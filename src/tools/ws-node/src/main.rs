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
//!
//! 测试材料（仅外加测试，禁用于生产）：CA/身份种子在两端以参数对齐，
//! 证书由 provision() 本地自签，握手仍是完整的证书认证 + AEAD 流程。
//! connect 模式握手后发 3 个带序号的 ping，校验 echo 逐字节还原。

use std::net::SocketAddr;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use ipv8_codec::IPv8Address;
use ipv8_tunnel::auth::{provision, CertAuthority, NO_EXPIRY};
use ipv8_tunnel::crypto::CipherSuite;
use ipv8_tunnel::{Engine, State, TrustAnchor};
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

#[tokio::main]
async fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let Some(mode) = argv.first().cloned() else {
        eprintln!("用法: ipv8-ws-node serve|connect [参数见文件头注释]");
        std::process::exit(2);
    };
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
