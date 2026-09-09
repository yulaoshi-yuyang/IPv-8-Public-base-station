//! ipv8-ws-node — Cloudflare WebSocket 桥节点（外网定向测试用，外加测试件）
//!
//! 把原生 AEAD 隧道帧（Phase 6 双套件）逐条装进 WebSocket 二进制消息：
//! 外网对端经 `wss://<域名>` → Cloudflare 边缘 → tunnel 连接器 → 本进程
//! → 引擎。免费版 Cloudflare 不透传原始 gRPC/QUIC，但 WS 是 HTTP/1.1
//! Upgrade、完整支持；IPv8+ 帧自带 AEAD，边缘只当哑管道，零信任面不扩大。
//!
//! 用法：
//!   serve   --listen 127.0.0.1:9001 --ca-seed <64hex> --addr <32hex> --peer <32hex> --seed <64hex> [--suite chacha|aes]
//!   connect --url wss://host[:port] --ca-seed <64hex> --addr <32hex> --peer <32hex> --seed <64hex> [--suite chacha|aes]
//!   relay   --listen 127.0.0.1:9001 --ca-seed <64hex>   # ADR-026 级 3：双向多会话中继
//!
//! relay 模式（无需 --addr/--peer/--seed，只信 CA）：客户端连上后先报
//! 身份帧 `RPT0 ‖ addr(16B) ‖ cert(120B)`，中继用 CA 验签（地址/公钥/
//! 有效期绑定）才登记 `addr → 会话`；此后每条 WS 二进制消息 =
//! `dst(16B 明文路由头) ‖ 隧道帧(帧头+AEAD 密文)`，中继按 dst 查表整条
//! 搬运。隧道帧的目的地址在密文内、中继看不到（零信任），明文路由头是
//! 这条传输链路的封套、不侵入隧道协议；篡改/错投 → 收端 AEAD 解密失败。
//! 与 spec §6.6 转发前 PathSig 三验同构的"先验身份后搬运"哲学。
//!
//! 测试材料（仅外加测试，禁用于生产）：CA/身份种子在两端以参数对齐，
//! 证书由 provision() 本地自签，握手仍是完整的证书认证 + AEAD 流程。
//! connect 模式握手后发 3 个带序号的 ping，校验 echo 逐字节还原。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use ipv8_codec::IPv8Address;
use ipv8_tunnel::auth::{provision, Cert, CertAuthority, NO_EXPIRY};
use ipv8_tunnel::crypto::CipherSuite;
use ipv8_tunnel::{Engine, State, TrustAnchor};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

fn arg_value(argv: &[String], flag: &str) -> Option<String> {
    argv.iter()
        .position(|a| a == flag)
        .and_then(|i| argv.get(i + 1))
        .filter(|v| !v.starts_with("--"))
        .cloned()
}

fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

#[derive(Clone)]
struct Cfg {
    ca_seed: [u8; 32],
    host_addr: IPv8Address,
    peer_addr: IPv8Address,
    ed_seed: [u8; 32],
    suite: CipherSuite,
}

fn parse_cfg(argv: &[String]) -> Result<Cfg, String> {
    let ca_seed = parse_hex32(&arg_value(argv, "--ca-seed").ok_or("缺 --ca-seed <64hex>")?)
        .ok_or("--ca-seed 须为 64 位十六进制")?;
    let host_addr =
        IPv8Address::from_canonical_str(&arg_value(argv, "--addr").ok_or("缺 --addr <32hex>")?)
            .map_err(|_| "--addr 非法".to_string())?;
    let peer_addr =
        IPv8Address::from_canonical_str(&arg_value(argv, "--peer").ok_or("缺 --peer <32hex>")?)
            .map_err(|_| "--peer 非法".to_string())?;
    let ed_seed = parse_hex32(&arg_value(argv, "--seed").ok_or("缺 --seed <64hex>")?)
        .ok_or("--seed 须为 64 位十六进制")?;
    let suite = match arg_value(argv, "--suite").as_deref() {
        None | Some("chacha") => CipherSuite::ChaCha20Poly1305,
        Some("aes") => CipherSuite::Aes256Gcm,
        Some(other) => return Err(format!("--suite 未知: {other}（可用 chacha|aes）")),
    };
    Ok(Cfg { ca_seed, host_addr, peer_addr, ed_seed, suite })
}

/// 构造认证引擎：本地 CA 自签证书 + 信任锚 = 同一 CA 公钥（测试拓扑）
fn build_engine(cfg: &Cfg) -> Engine {
    let ca = CertAuthority::from_seed(cfg.ca_seed);
    let trust = TrustAnchor::from_bytes(ca.public_key()).expect("CA 公钥必合法");
    let host = provision(&ca, cfg.host_addr, cfg.ed_seed, NO_EXPIRY);
    let mut eng = Engine::authenticated(host, trust, cfg.host_addr, cfg.peer_addr);
    eng.set_cipher_suite(cfg.suite);
    eng
}

fn suite_name(s: CipherSuite) -> &'static str {
    match s {
        CipherSuite::ChaCha20Poly1305 => "ChaCha20-Poly1305",
        CipherSuite::Aes256Gcm => "AES-256-GCM",
    }
}

/// 帧收流辅助：读一条二进制消息，喂引擎，可选回发响应帧；返回是否收到消息
async fn pump<S, R>(
    tx: &mut S,
    rx: &mut R,
    eng: &mut Engine,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>
where
    S: futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
    R: futures_util::Stream<
            Item = Result<Message, tokio_tungstenite::tungstenite::Error>,
        > + Unpin,
{
    match rx.next().await {
        Some(Ok(Message::Binary(b))) => {
            if let Some(resp) = eng.handle_frame(&b) {
                tx.send(Message::Binary(resp)).await?;
            }
            Ok(true)
        }
        Some(Ok(Message::Close(_))) | None => Ok(false),
        Some(Ok(Message::Ping(p))) => {
            tx.send(Message::Pong(p)).await?;
            Ok(true)
        }
        Some(Ok(_)) => Ok(true), // Pong/Text/Frame：测试桥忽略
        Some(Err(e)) => Err(e.into()),
    }
}

// ---------------- serve：等外网对端穿隧道进来（本侧为握手 responder） ----------------

async fn serve(cfg: Cfg, listen: SocketAddr) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    let listener = tokio::net::TcpListener::bind(listen).await?;
    println!(
        "[ws-node] serve 监听 {listen}（WS 明文回环，供 cloudflared 回源） 本机={} 预期对端={} 套件={}",
        cfg.host_addr.to_canonical_string(),
        cfg.peer_addr.to_canonical_string(),
        suite_name(cfg.suite)
    );
    loop {
        let (tcp, remote) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[ws-node] accept 失败: {e}");
                continue;
            }
        };
        let cfg = cfg.clone();
        tokio::spawn(async move {
            println!("[ws-node] 新会话（来自 {remote}，即 cloudflared 连接器）");
            if let Err(e) = session_serve(tcp, &cfg).await {
                eprintln!("[ws-node] 会话结束: {e}");
            }
        });
    }
}

async fn session_serve(
    tcp: tokio::net::TcpStream,
    cfg: &Cfg,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let ws = tokio_tungstenite::accept_async(tcp).await?;
    let (mut tx, mut rx) = ws.split();
    let mut eng = build_engine(cfg);
    let mut established_logged = false;
    while pump(&mut tx, &mut rx, &mut eng).await? {
        if !established_logged && eng.state() == State::Established {
            println!("[ws-node] 握手完成：对端证书验证通过，AEAD 密钥就绪");
            established_logged = true;
        }
        // 数据面：收到内层载荷 → 原样 echo 回去（外加测试判据由发起端校验）
        while let Some(payload) = eng.take_delivered() {
            let back = eng.seal_frame(&payload).expect("echo 载荷必然可密封（与入站同 MTU 路径）");
            tx.send(Message::Binary(back)).await?;
        }
    }
    println!("[ws-node] 对端关闭连接");
    Ok(())
}

// ---------------- connect：主动打出去（本侧为握手 initiator + ping 发起方） ----------------

async fn connect(cfg: Cfg, url: String) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!(
        "[ws-node] connect {url} 本机={} 对端={} 套件={}",
        cfg.host_addr.to_canonical_string(),
        cfg.peer_addr.to_canonical_string(),
        suite_name(cfg.suite)
    );
    let flow = async move {
        let (ws, resp) = tokio_tungstenite::connect_async(&url).await?;
        println!("[ws-node] WS 已连通（HTTP {}），边缘→隧道→本机链路建立", resp.status().as_u16());
        let (mut tx, mut rx) = ws.split();
        let mut eng = build_engine(&cfg);

        // 1) 证书认证握手（initiator 侧）
        let init = eng.start_auth_handshake();
        tx.send(Message::Binary(init)).await?;
        while eng.state() != State::Established {
            if !pump(&mut tx, &mut rx, &mut eng).await? {
                return Err("握手期间连接被关闭".into());
            }
            if let Some(err) = eng.last_auth_error() {
                return Err(format!("认证失败: {err}").into());
            }
        }
        println!("[ws-node] 握手完成：对端证书验证通过，AEAD 密钥就绪");

        // 2) 数据面：3 个带序号的 ping，校验 echo 逐字节还原 + 序号对应
        for i in 0u8..3 {
            let mut ping = vec![0x45, 0x00, 0x00, 0x1C, b'i', b'p', b'v', b'8'];
            ping.push(i);
            let frame = eng.seal_frame(&ping).map_err(|e| format!("密封失败: {e:?}"))?;
            tx.send(Message::Binary(frame)).await?;
            loop {
                if !pump(&mut tx, &mut rx, &mut eng).await? {
                    return Err("数据期间连接被关闭".into());
                }
                if let Some(got) = eng.take_delivered() {
                    if got != ping {
                        return Err(format!(
                            "echo 不匹配: 发 {}B [{}] 收 {}B [{}]",
                            ping.len(),
                            hex(&ping),
                            got.len(),
                            hex(&got)
                        )
                        .into());
                    }
                    println!("[ws-node] ping[{i}] {}B → echo 逐字节一致 ✓", got.len());
                    break;
                }
            }
        }
        let st = eng.stats();
        println!(
            "[ws-node] PASS：外网经 Cloudflare 边缘定向至本机，证书握手 + AEAD({}) 双向密封各 {} 帧，丢弃入站 {}",
            suite_name(cfg.suite), st.delivered_inbound, st.dropped_inbound
        );
        Ok(())
    }
    .await;
    flow
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(" ")
}

// ---------------- ADR-026 级 3：relay（双向多会话中继，零信任密文搬运） ----------------

/// 注册帧魔数 + 布局：`RPT0 ‖ addr(16B) ‖ cert(120B线格式=TBS56‖ca_sig64)`
const RPT_MAGIC: &[u8; 4] = b"RPT0";
const REG_FRAME_LEN: usize = 4 + 16 + 120;
const ADDR_WIRE: usize = 16;

/// 墙钟 epoch 秒（证书有效期校验）
fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 16 字节地址线格式 → IPv8Address（大端；reserved 非 0 = 非法）
fn addr_from_wire(b: &[u8]) -> Option<IPv8Address> {
    if b.len() != ADDR_WIRE || b[13..16] != [0u8; 3] {
        return None;
    }
    Some(IPv8Address::new(
        u32::from_be_bytes(b[0..4].try_into().ok()?),
        u32::from_be_bytes(b[4..8].try_into().ok()?),
        u16::from_be_bytes(b[8..10].try_into().ok()?),
        u16::from_be_bytes(b[10..12].try_into().ok()?),
        b[12],
    ))
}

/// 120B 证书线格式（TBS ‖ ca_sig）→ Cert。字段布局同 `Cert::to_wire`。
fn cert_from_wire(w: &[u8]) -> Option<Cert> {
    if w.len() != 120 {
        return None;
    }
    Some(Cert {
        addr: addr_from_wire(&w[0..16])?,
        verify_key: w[16..48].try_into().ok()?,
        not_after: u64::from_be_bytes(w[48..56].try_into().ok()?),
        ca_sig: w[56..120].try_into().ok()?,
    })
}

/// 中继路由表：已登记地址 → 会话出帧通道。
///
/// ★ 传输层封帧（本链路私有，不侵入 AEAD 隧道协议）：WS 二进制消息 =
/// `dst(16B 明文路由头) ‖ 隧道帧(10B 帧头 + AEAD 密文)`。隧道帧的 DstAddr
/// 在密文里，中继看不到（零信任），故发送方在帧外自带明文收件地址；
/// 中继只搬这一层，篡改帧内容 = 对端 AEAD 解密失败，错投 dst 同样解不开。
struct RelayHub {
    by_addr: Mutex<HashMap<IPv8Address, mpsc::UnboundedSender<Vec<u8>>>>,
    trust: TrustAnchor,
    forwarded: AtomicU64,
    noroute: AtomicU64,
    rejected: AtomicU64,
}

/// 明文路由头长度（消息体前 16B = 目的 IPv8+ 地址线格式）
pub const ROUTE_HDR_LEN: usize = ADDR_WIRE;

impl RelayHub {
    fn new(ca_pub: [u8; 32]) -> Self {
        Self {
            by_addr: Mutex::new(HashMap::new()),
            trust: TrustAnchor::from_bytes(ca_pub).expect("CA 公钥自生成必合法"),
            forwarded: AtomicU64::new(0),
            noroute: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
        }
    }

    /// 注册帧校验 + 登记（同地址重连 = 新会话顶替旧会话）。
    fn register(&self, frame: &[u8], tx: mpsc::UnboundedSender<Vec<u8>>) -> Option<IPv8Address> {
        if frame.len() != REG_FRAME_LEN || &frame[0..4] != RPT_MAGIC {
            self.rejected.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let addr = addr_from_wire(&frame[4..20])?;
        let cert = cert_from_wire(&frame[20..])?;
        // 三验：CA 签名有效 + 未过期 + 证书主体 == 自报地址（防"拿别人
        // 证书认领自己地址"——地址不一致的证书再合法也不能建立绑定）
        if cert.addr != addr || self.trust.verify(&cert, now_epoch()).is_err() {
            self.rejected.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        self.by_addr.lock().expect("hub").insert(addr, tx);
        println!(
            "[relay] 登记 {}（证书主体一致，verify_key={}..）",
            addr.to_canonical_string(),
            hex(&cert.verify_key[..4])
        );
        Some(addr)
    }

    /// 按外层明文路由头（消息前 16B = 目的地址）查表转发整条消息。
    /// 返回 false = 无法路由/载荷非法（计数）。帧体本身不解析——密文由
    /// 收端 AEAD 认证，中继既看不懂也不该懂（零信任哑管道）。
    fn route(&self, msg: &[u8]) -> bool {
        if msg.len() <= ROUTE_HDR_LEN {
            self.noroute.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        let Some(dst) = addr_from_wire(&msg[..ROUTE_HDR_LEN]) else {
            self.noroute.fetch_add(1, Ordering::Relaxed);
            return false;
        };
        let mut g = self.by_addr.lock().expect("hub");
        match g.get(&dst) {
            Some(s) if s.send(msg.to_vec()).is_ok() => {
                self.forwarded.fetch_add(1, Ordering::Relaxed);
                true
            }
            // 目标会话已死：摘除路由，交还 false（消息丢弃，对端超时重发/降级）
            Some(_) => {
                g.remove(&dst);
                self.noroute.fetch_add(1, Ordering::Relaxed);
                false
            }
            None => {
                self.noroute.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    fn unregister(&self, addr: &IPv8Address) {
        if let Some(s) = self.by_addr.lock().expect("hub").remove(addr) {
            // 仅当移除的仍是该会话（未被重连顶替）；顶替场景由新登记自然覆盖
            println!("[relay] 会话注销 {addr}（closed={}）", s.is_closed());
        }
    }
}

async fn relay(ca_seed: [u8; 32], listen: SocketAddr) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let ca = CertAuthority::from_seed(ca_seed);
    let hub = Arc::new(RelayHub::new(ca.public_key()));
    let listener = tokio::net::TcpListener::bind(listen).await?;
    println!("[relay] 中继监听 {listen}（WS 明文，供 cloudflared/直连）；信任锚 ca_pub={}..", hex(&ca.public_key()[..4]));
    let stats = hub.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(10));
        loop {
            tick.tick().await;
            println!(
                "[relay] stats registered={} forwarded={} noroute={} rejected={}",
                stats.by_addr.lock().expect("hub").len(),
                stats.forwarded.load(Ordering::Relaxed),
                stats.noroute.load(Ordering::Relaxed),
                stats.rejected.load(Ordering::Relaxed)
            );
        }
    });
    loop {
        let (tcp, remote) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[relay] accept 失败: {e}");
                continue;
            }
        };
        let hub = hub.clone();
        tokio::spawn(async move {
            if let Err(e) = relay_session(tcp, remote, hub).await {
                eprintln!("[relay] {remote} 会话结束: {e}");
            }
        });
    }
}

async fn relay_session(
    tcp: tokio::net::TcpStream,
    remote: SocketAddr,
    hub: Arc<RelayHub>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let ws = tokio_tungstenite::accept_async(tcp).await?;
    let (mut tx, mut rx) = ws.split();
    // 本会话出帧通道：route() 投 sender 侧，writer 任务持 receiver 搬进 WS。
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    // 1) 首帧必须注册：验证不过立即关闭（不喂任何数据进路由表）
    let first = tokio::time::timeout(Duration::from_secs(10), rx.next()).await
        .map_err(|_| "注册超时（首帧 10s 未到）")?
        .ok_or("连接在注册前关闭")??;
    let reg = match first {
        Message::Binary(b) => b,
        other => return Err(format!("首帧非二进制注册帧（{other}）").into()),
    };
    let Some(addr) = hub.register(&reg, out_tx) else {
        return Err("注册帧无效（魔数/长度/CA 验签/主体一致性）".into());
    };
    println!("[relay] {remote} 登记为 {}", addr.to_canonical_string());
    let writer = tokio::spawn(async move {
        while let Some(frame) = out_rx.recv().await {
            if tx.send(Message::Binary(frame)).await.is_err() {
                break; // WS 写端断开
            }
        }
    });
    // 2) 收帧循环：reader 不碰 sink（已 move 给 writer），只喂路由
    while let Some(msg) = rx.next().await {
        match msg? {
            Message::Binary(b) => {
                if !b.is_empty() {
                    hub.route(&b);
                }
            }
            Message::Close(_) => break,
            _ => {} // Ping/Pong/Text：tungstenite 内部自动 pong，其余忽略
        }
    }
    hub.unregister(&addr);
    let _ = writer.await;
    Ok(())
}

/// relay-node：接入中继的端点（注册 + 握手 + 发起/回显），级 3 的数据面。
/// 出帧统一封套 `dst(16B 路由头) ‖ 隧道帧`——dst 恒为对端地址（单会话
/// 拓扑；多路复用归上层编排）。
fn wrap(dst: &IPv8Address, frame: Vec<u8>) -> Vec<u8> {
    let mut m = dst.to_bytes().to_vec();
    m.extend_from_slice(&frame);
    m
}

async fn relay_node(
    cfg: Cfg,
    url: String,
    initiate: bool,
    until_ok: u32,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (ws, resp) = tokio::time::timeout(Duration::from_secs(20), tokio_tungstenite::connect_async(&url))
        .await
        .map_err(|_| "20s 内未能连上中继")??;
    println!("[relay-node] 已连上中继（HTTP {}），role={}", resp.status().as_u16(), if initiate { "initiator" } else { "echo" });
    let (mut tx, mut rx) = ws.split();
    // 1) 注册帧：RPT0 ‖ addr ‖ cert（证明"这个地址归我"，中继才肯转发）
    let ca = CertAuthority::from_seed(cfg.ca_seed);
    let ident = provision(&ca, cfg.host_addr, cfg.ed_seed, NO_EXPIRY);
    let mut reg = RPT_MAGIC.to_vec();
    reg.extend_from_slice(&cfg.host_addr.to_bytes());
    reg.extend_from_slice(&ident.cert.to_wire());
    tx.send(Message::Binary(reg)).await?;
    // 2) 引擎与既有 connect/serve 流程同款（证书握手 + AEAD 数据面）
    let mut eng = build_engine(&cfg);
    if initiate {
        let init = eng.start_auth_handshake();
        tx.send(Message::Binary(wrap(&cfg.peer_addr, init))).await?;
    }
    let mut established = !initiate;
    let mut ok_count = 0u32;
    let mut next_inject = tokio::time::Instant::now();
    let started = tokio::time::Instant::now();
    loop {
        let msg = match tokio::time::timeout(Duration::from_millis(500), rx.next()).await {
            Err(_elapsed) => None,
            Ok(None) => return Err("中继关闭了连接".into()),
            Ok(Some(Err(e))) => return Err(e.into()),
            Ok(Some(Ok(m))) => Some(m),
        };
        if let Some(m) = msg {
            match m {
                Message::Binary(b) => {
                    // 剥掉本链路路由头再喂引擎（引擎只见纯隧道帧）
                    if b.len() <= ROUTE_HDR_LEN {
                        continue;
                    }
                    if let Some(rframe) = eng.handle_frame(&b[ROUTE_HDR_LEN..]) {
                        tx.send(Message::Binary(wrap(&cfg.peer_addr, rframe))).await?;
                    }
                    while let Some(payload) = eng.take_delivered() {
                        if initiate {
                            // 校验回显结构（同 ipv8-node no-tun 判据）
                            let good = payload.len() >= 9
                                && &payload[..5] == b"IP8NT"
                                && payload[9..].iter().all(|&x| x == 0xA5);
                            if good {
                                ok_count += 1;
                                println!("[relay-node] ECHO_OK #{ok_count} ({}B byte-exact)", payload.len());
                                if ok_count >= until_ok {
                                    println!("[relay-node] PASS：跨中继双向密封 {ok_count} 帧一致");
                                    return Ok(());
                                }
                            } else {
                                return Err(format!("回显结构异常: {}B [{}]", payload.len(), hex(&payload[..payload.len().min(16)])).into());
                            }
                        } else {
                            // echo 侧：原样密封回给对端（AEAD 保证不助记投毒）
                            let back = eng.seal_frame(&payload).map_err(|e| format!("echo 密封失败: {e:?}"))?;
                            tx.send(Message::Binary(wrap(&cfg.peer_addr, back))).await?;
                        }
                    }
                    if !established && eng.state() == State::Established {
                        println!("[relay-node] 隧道 Established（经中继）");
                        established = true;
                    }
                }
                Message::Close(_) => return Err("中继侧连接关闭".into()),
                _ => {}
            }
        }
        // 发起方：Established 后每 2s 注入合成回显包
        if initiate
            && established
            && tokio::time::Instant::now() >= next_inject
        {
            next_inject = tokio::time::Instant::now() + Duration::from_secs(2);
            let mut payload = b"IP8NT".to_vec();
            payload.extend_from_slice(&ok_count.to_be_bytes());
            payload.resize(64, 0xA5);
            let frame = eng.seal_frame(&payload).map_err(|e| format!("注入密封失败: {e:?}"))?;
            tx.send(Message::Binary(wrap(&cfg.peer_addr, frame))).await?;
        }
        if initiate && tokio::time::Instant::now() >= started + Duration::from_secs(90) {
            return Err(format!("90s 超时：ECHO_OK={ok_count}/{until_ok}").into());
        }
    }
}


#[tokio::main]
async fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let Some(mode) = argv.first().cloned() else {
        eprintln!("用法: ipv8-ws-node serve|connect|relay|relay-node [参数见文件头注释]");
        std::process::exit(2);
    };
    // relay（中继本体）只需要 CA 种子；其余模式走全量 cfg 解析
    if mode == "relay" {
        let ca_seed = match arg_value(&argv, "--ca-seed")
            .as_deref()
            .and_then(parse_hex32)
        {
            Some(s) => s,
            None => {
                eprintln!("[relay] 需要 --ca-seed <64hex>");
                std::process::exit(2);
            }
        };
        let listen: SocketAddr = arg_value(&argv, "--listen")
            .unwrap_or_else(|| "127.0.0.1:9002".into())
            .parse()
            .unwrap_or_else(|_| {
                eprintln!("[relay] --listen 非法");
                std::process::exit(2);
            });
        let r = relay(ca_seed, listen).await;
        if let Err(e) = r {
            eprintln!("[relay] FAIL: {e}");
            std::process::exit(1);
        }
        return;
    }
    let cfg = match parse_cfg(&argv) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[ws-node] 参数错误: {e}");
            std::process::exit(2);
        }
    };
    let r = match mode.as_str() {
        "serve" => {
            let listen: SocketAddr = arg_value(&argv, "--listen")
                .unwrap_or_else(|| "127.0.0.1:9001".into())
                .parse()
                .unwrap_or_else(|_| {
                    eprintln!("[ws-node] --listen 非法");
                    std::process::exit(2);
                });
            connect_guard(serve(cfg, listen)).await
        }
        "connect" => {
            let url = match arg_value(&argv, "--url") {
                Some(u) => u,
                None => {
                    eprintln!("[ws-node] connect 需要 --url wss://…");
                    std::process::exit(2);
                }
            };
            tokio::time::timeout(Duration::from_secs(30), connect(cfg, url)).await
                .unwrap_or_else(|_| Err("30s 总超时".into()))
        }
        "relay-node" => {
            let url = match arg_value(&argv, "--url") {
                Some(u) => u,
                None => {
                    eprintln!("[relay-node] 需要 --url ws://中继地址");
                    std::process::exit(2);
                }
            };
            let initiate = argv.iter().any(|a| a == "--initiate");
            let until_ok = arg_value(&argv, "--until")
                .and_then(|s| s.parse().ok())
                .unwrap_or(3u32);
            relay_node(cfg, url, initiate, until_ok).await
        }
        other => {
            eprintln!("[ws-node] 未知模式: {other}");
            std::process::exit(2);
        }
    };
    if let Err(e) = r {
        eprintln!("[ws-node] FAIL: {e}");
        std::process::exit(1);
    }
}

/// serve 常驻不包超时；connect 自带 30s 截止
async fn connect_guard<T>(f: T) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    T: std::future::Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>>,
{
    f.await
}

#[cfg(test)]
mod relay_tests {
    use super::*;

    fn addr(n: u32) -> IPv8Address {
        IPv8Address::new(0xfb14, n, 1, 0, 1)
    }

    /// 中继消息封套：dst(16B 路由头) ‖ 帧体（帧体内容对路由透明）
    fn msg_for(dst: &IPv8Address) -> Vec<u8> {
        let mut m = dst.to_bytes().to_vec();
        m.extend_from_slice(&[0x80, 0x11, 0x22, 0x33]); // 任意图腾帧体
        m
    }

    fn reg_frame(ca: &CertAuthority, a: IPv8Address, seed: u8) -> Vec<u8> {
        let ident = provision(ca, a, [seed; 32], NO_EXPIRY);
        let mut r = RPT_MAGIC.to_vec();
        r.extend_from_slice(&a.to_bytes());
        r.extend_from_slice(&ident.cert.to_wire());
        r
    }

    #[test]
    fn wire_roundtrips() {
        let a = addr(7);
        assert_eq!(addr_from_wire(&a.to_bytes()), Some(a));
        // reserved 非 0 → 拒
        let mut bad = a.to_bytes();
        bad[14] = 1;
        assert_eq!(addr_from_wire(&bad), None);
        let ca = CertAuthority::from_seed([0xC4; 32]);
        let ident = provision(&ca, a, [0xA1; 32], NO_EXPIRY);
        assert_eq!(cert_from_wire(&ident.cert.to_wire()), Some(ident.cert));
        assert_eq!(cert_from_wire(&[0u8; 119]), None);
    }

    #[test]
    fn hub_register_and_route() {
        let ca = CertAuthority::from_seed([0xC4u8; 32]);
        let hub = RelayHub::new(ca.public_key());
        let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
        assert_eq!(hub.register(&reg_frame(&ca, addr(1), 0xA1), tx.clone()), Some(addr(1)));
        // 伪造注册（自签"证书"）→ CA 验签失败 → 拒
        let (tx2, _rx2) = mpsc::unbounded_channel();
        let mut forged = reg_frame(&ca, addr(2), 0xB2);
        forged[20..].fill(0); // 抹掉合法签名
        assert_eq!(hub.register(&forged, tx2), None);
        // 地址主体不一致（拿 1 的证书认领 2）→ 拒
        let (tx3, _rx3) = mpsc::unbounded_channel();
        let mut swap = reg_frame(&ca, addr(1), 0xA1);
        swap[4..20].copy_from_slice(&addr(2).to_bytes());
        assert_eq!(hub.register(&swap, tx3), None);

        // 路由：dst=已登记 → 投通道（整条消息原样）；未登记 → noroute 计数、返回 false
        assert!(hub.route(&msg_for(&addr(1))));
        let got = rx.try_recv().expect("应收到转发消息");
        assert_eq!(got, msg_for(&addr(1)));
        assert!(!hub.route(&msg_for(&addr(99))));
        assert!(!hub.route(&[0x08; 16])); // 只有路由头、无帧体
        assert!(!hub.route(&{
            let mut m = addr(9).to_bytes().to_vec(); // 非法地址（reserved 非 0）
            m[14] = 1;
            m.extend_from_slice(&[0x80]);
            m
        }));
        let h = hub.rejected.load(Ordering::Relaxed);
        assert!(h >= 2, "两次非法注册均须计数");
        assert!(hub.forwarded.load(Ordering::Relaxed) >= 1);
        assert!(hub.noroute.load(Ordering::Relaxed) >= 3);
    }

    #[tokio::test]
    async fn dead_session_evicted_on_send() {
        let ca = CertAuthority::from_seed([0xC4u8; 32]);
        let hub = RelayHub::new(ca.public_key());
        let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
        hub.register(&reg_frame(&ca, addr(5), 0xA5), tx);
        drop(rx); // 模拟会话死亡
        assert!(!hub.route(&msg_for(&addr(5))), "死会话投帧应失败");
        assert!(hub.by_addr.lock().unwrap().get(&addr(5)).is_none(), "应已摘除路由");
    }
}
