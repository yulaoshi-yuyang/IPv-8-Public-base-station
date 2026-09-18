//! ipv8-node — Phase 1 通包验证守护进程（verification-only）
//!
//! 把三样东西粘成一条完整数据链路：
//!   wintun TUN（OS ↔ 引擎） ↔ ipv8-tunnel::Engine（封装/AEAD/握手） ↔ UDP（物理网络）
//!
//! 目的只有一个：复现 v9 Phase 1 验收——"两台 Hyper-V VM 通过 wintun
//! 收发第一个 IPv8+ 包"。用 `ping 100.64.x.y` 即可驱动 ICMP 进隧道。
//! 生产路径仍是 C# Host + gRPC（tunnel.proto）；本二进制不替代它。
//!
//! 运行前提：管理员权限；UDP 端口放行入站；Phase 1 验证用静态对端配置，
//! 不依赖云端 Resolver。身份密钥每次启动随机（连通性验证够用；
//! Phase 2 接 ZoneServer 证书 + --cert-cache 持久化：重启离线验签命中即免注册）。

mod rio;

use std::error::Error;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rio::{RioMode, RioPacket, UdpIo};

use ipv8_codec::IPv8Address;
use ipv8_compat::{process_inbound, process_outbound, Outcome as CompatOutcome};
use ipv8_fec::{FecRx, FecTx};
use ipv8_hook::{Action as HookAction, Direction as HookDirection, HookBus, HookConfig, PacketEvent};
use ipv8_tunnel::auth::{
    pop_sign, provision, register_pop_message, verify_key_from_seed, Cert, CertAuthority,
    HostIdentity, TrustAnchor, NO_EXPIRY,
};
use ipv8_tunnel::{
    crypto::CipherSuite, Engine, FallbackManager, FallbackOptions, Failure, FlowShards, Identity,
    Level, Path as FallbackPath, Resolved, ShardSink, ShardStats, State,
};

/// 墙钟 epoch 秒（认证握手的证书过期校验用）
fn now_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 验证拓扑固定单对端，FallbackManager 的 peer 键恒为 "peer"
const PEER_KEY: &str = "peer";

/// 弱凭据入口刷新的限速窗：同窗内至多改址一次（防持续伪造源地址长期抢占）
const ROAM_MIN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

/// 内层 IP 包的 DSCP（0 = 尽力而为，Phase 4 --fec 的 QoS 门控判据）。
///
/// 协议正确取法（spec FR-4 意图 = DSCP≠0，实现按 RFC 精确提取）：
/// - IPv4：DS 字段 = byte[1]，DSCP = 高 6 位 = `byte[1] >> 2`；
/// - IPv6：Traffic Class 8 位跨两字节——`byte[0] 低 4 位 ‖ byte[1] 高 4 位`，
///   DSCP = TC 高 6 位 = `(byte[0]&0x0F)<<2 | byte[1]>>6`。
///
/// 长度不足 / 非_IPV_ 版本 → None（调用方按未标记处理）。
fn inner_dscp(pkt: &[u8]) -> Option<u8> {
    match pkt.first()? >> 4 {
        4 if pkt.len() >= 2 => Some(pkt[1] >> 2),
        6 if pkt.len() >= 2 => Some(((pkt[0] & 0x0F) << 2) | (pkt[1] >> 6)),
        _ => None,
    }
}

/// 外层 UDP 包发往哪里（由调度状态机 [`Sched`] 决定）
#[derive(Clone, Debug, PartialEq, Eq)]
enum Transport {
    /// 隧道：封装 IPv8+ 帧后发往当前选定入口
    Tunnel(SocketAddr),
    /// 明文降级：内层 IP 包不加密直发
    PlainUdp(SocketAddr),
}

/// ---- Fallback 共享调度状态（v9 §11；状态机在 ipv8-tunnel::fallback）----
/// 生产路径的入口来自 Resolver；node 验证拓扑用 --peer-ip/--peer-port=主入口、
/// --alt-ip/--alt-port=备用入口 静态模拟。TCP 明文传输归 C# 宿主，
/// node 验证明文级时复用 UDP socket 直发原始 IP 包（首字节 0x45/0x60 区分）。
struct Sched {
    fb: FallbackManager,
    main: SocketAddr,
    alt: Option<SocketAddr>,
    /// 最近一次 next_path 决策（Established 时据此 record_success）
    current: FallbackPath,
    transport: Transport,
    /// 发起方当前握手尝试：(Init 帧, 起始秒, 目的)。None=未尝试/已放弃
    attempt: Option<(Vec<u8>, u64, SocketAddr)>,
    /// Established 已被主循环观察（record_success 只记一次）
    success_recorded: bool,
    /// 明文降级日志只打一次
    plain_reported: bool,
    /// Established 观察时刻与当时 delivered（首包超时判定基线）
    est_started: Option<u64>,
    est_delivered: u64,
    plain_tx: u64,
    plain_rx: u64,
    /// Phase 3 --migrate：最近一次「未认证帧触发的入口刷新」时刻（限速用）。
    /// 已认证帧（通过 AEAD）的刷新不受此限；此处只约束握手/分片路径的现学。
    last_unauth_roam: Option<std::time::Instant>,
    /// Phase 4 --mp：多路径竞速启用。入口刷新判定从「transport 目的 ≠ from」
    /// 收紧为「from ∉ {main, alt}」——两条路径地址都合法，不收紧会反复横跳
    /// （FR-2）。关闭时判定与 Phase 3 逐字节一致。
    mp: bool,
}

impl Sched {
    /// FR-2 入口集合：`--mp` 开 = {main, alt}（两路径都合法）；关 = 空集补集
    /// 语义（调用方仅以 `dest != from` 判定，与 Phase 3 一致）。
    fn in_entry_set(&self, from: SocketAddr) -> bool {
        self.mp && (self.main == from || self.alt == Some(from))
    }

    /// 强凭据（AEAD 认证帧）入口刷新：无限速。返回 true 表示确有变化。
    ///
    /// N-6：强纠正成功时重置弱凭据限速窗——否则刚被 AEAD 帧纠正回真对端，
    /// 10s 窗口内的一个伪造弱帧又能把入口改走一次（短暂振荡）。
    fn strong_refresh(&mut self, from: SocketAddr) -> bool {
        let need = matches!(self.transport, Transport::Tunnel(dest) if dest != from)
            && !self.in_entry_set(from);
        if !need {
            return false;
        }
        self.main = from;
        self.transport = Transport::Tunnel(from);
        self.last_unauth_roam = Some(std::time::Instant::now());
        if let Some((f, t0, _)) = self.attempt.clone() {
            self.attempt = Some((f, t0, from));
        }
        true
    }

    /// 弱凭据（未认证帧）入口刷新决策。返回 Some(日志消息)=允许刷新；
    /// None=拒绝（入口未变，或限速窗口内）。调用方在锁外打印，避免
    /// 持锁 stdout 阻塞并发收发路径。
    ///
    /// - 首次现学（握手引导）：仅当 `allow_first_frame`（即启用了
    ///   --learn-peer 的引擎前调用点）时免限速，这是 --learn-peer 既有语义；
    ///   引擎后的弱凭据路径即使 learned==false 也不享受免限速（N-5：
    ///   否则仅开 --migrate 的明文模式发起方，生命周期内任意时刻收到一个
    ///   74B 伪造 Init 即可一次性把出站入口导向攻击者）。
    /// - 其余漫游现学：限速 [`ROAM_MIN_INTERVAL`] 一次，防止持续伪造
    ///   源地址长期抢占入口；真正的对端漫游会立即有「AEAD 认证帧」
    ///   走 [`Sched::strong_refresh`] 免限速通道纠正。
    fn unauth_refresh(
        &mut self,
        from: SocketAddr,
        learned: &mut bool,
        allow_first_frame: bool,
    ) -> Option<String> {
        let need_update = match self.transport {
            Transport::Tunnel(dest) => dest != from && !self.in_entry_set(from),
            Transport::PlainUdp(_) => true,
        };
        if !need_update {
            *learned = true;
            return None;
        }
        let msg = if allow_first_frame && !*learned {
            format!("[learn-peer] 入口 → {from}（按合法首帧源地址）")
        } else {
            // 漫游现学（含未启用 --learn-peer 时的首帧）：一律限速
            let now = std::time::Instant::now();
            if let Some(t) = self.last_unauth_roam {
                if now.duration_since(t) < ROAM_MIN_INTERVAL {
                    return None;
                }
            }
            self.last_unauth_roam = Some(now);
            format!("[migration] 漫游现学（限速，未认证帧）：隧道入口 → {from}")
        };
        self.main = from;
        self.transport = Transport::Tunnel(from);
        if let Some((f, t0, _)) = self.attempt.clone() {
            self.attempt = Some((f, t0, from));
        }
        *learned = true;
        Some(msg)
    }
}

/// Phase 3 连接迁移：探测到达 `peer` 时本机使用的出口 IP。
///
/// 用一个临时 UDP socket `bind(0.0.0.0:0)` + `connect(peer)` 让 OS 路由表
/// 决定出口地址（不发包、不改变主 socket 状态）。网络切换（WiFi↔4G）后
/// 返回值随之变化，是触发迁移的唯一信号。
fn detect_local_addr(peer: SocketAddr) -> Option<IpAddr> {
    let bind: SocketAddr = if peer.is_ipv4() {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
    };
    let s = std::net::UdpSocket::bind(bind).ok()?;
    s.connect(peer).ok()?;
    s.local_addr().ok().map(|sa| sa.ip())
}

/// Phase 3 迁移安全：判断引擎对一帧的处理结果是否构成「强漫游凭据」。
///
/// 强凭据 = 第三方离线无法伪造的来源证明，持有它可**立即免限速**刷新隧道入口：
/// - Data 帧成功解密出 `delivered`（已通过 AEAD 验证）；
/// - AuthInit（帧 type=4）让引擎产出 `resp`（证书三验通过才会产出）。
///
/// 注意：明文 HandshakeInit（type=0）产出的 `resp` 只是**弱凭据**——
/// accept_init 不认证发起方身份（长度正确即接受），任意外部主机都能构造
/// 74 字节伪造 Init。弱凭据只能走 [`Plane::maybe_learn_unauthenticated`]
/// 的 10s 限速通道，不得免限速抢占入口（R2 N-1）。
fn is_strong_roam_credential(raw: &[u8], has_resp: bool, has_delivered: bool) -> bool {
    // delivered 永远是 AEAD 解密产物
    if has_delivered {
        return true;
    }
    // resp 必须来自认证握手帧：帧头 Ver=0x01, Type=AuthInit(4)
    has_resp && raw.len() >= 2 && raw[0] == 0x01 && raw[1] == 0x04
}

/// 解析 64 位十六进制种子（CA/Ed25519 种子）
fn parse_seed(s: &str) -> Result<[u8; 32], String> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("种子必须是 64 个十六进制字符".to_string());
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string())?;
    }
    Ok(out)
}

const TUNNEL_TYPE: &str = "IPv8Plus Tunnel";

/// ADR-026 级 2：打洞"敲门"包。仅作撞活 NAT 映射之用，不含语义；
/// 收侧在进引擎解析前静默吸收（不污染 dropped 计数判据）。
const PUNCH_KNOCK: &[u8] = b"IP8PUNCH";

/// Data 面分片生命周期（--shards>1 时启用）。主循环负责在 Established /
/// 重协商点换片；TUN 读线程经 `seal` 投递出站，UDP 收线程经 `feed` 喂入站。
/// 锁序约束：允许 engine → hub，禁止在持 hub 时取 engine 锁。
#[derive(Default)]
struct ShardHub {
    shards: Option<FlowShards>,
    /// 已退役分片的累计计数（重协商换片后 [stats] 单调性不因换片倒退）
    off: ShardStats,
}

impl ShardHub {
    /// 出站批量投递：分片活跃返回 true（帧由各 worker 经装填时锁定的
    /// 当前 transport 出口异步发出；重协商/降级换片时 dest 随之更新）
    fn seal(&self, batch: &[Vec<u8>]) -> bool {
        match &self.shards {
            Some(sh) => {
                for b in batch {
                    if sh.seal_dispatch(b).is_err() {
                        return false; // 分片已停摆：回落单点路径
                    }
                }
                true
            }
            None => false,
        }
    }

    /// 入站投递：Data 帧且分片活跃返回 true（本帧已被分片接管）
    fn feed(&self, frame: &[u8]) -> bool {
        match &self.shards {
            Some(sh) => sh.handle_inbound(frame),
            None => false,
        }
    }

    /// 现役 + 退役累计的聚合视图（stats 打印与首包超时判据共用）
    fn stats(&self) -> ShardStats {
        let cur = self
            .shards
            .as_ref()
            .map(|s| s.stats())
            .unwrap_or(ShardStats { sealed: 0, delivered: 0, dropped: 0, fragments_sent: 0, fragments_reassembled: 0 });
        ShardStats {
            sealed: self.off.sealed + cur.sealed,
            delivered: self.off.delivered + cur.delivered,
            dropped: self.off.dropped + cur.dropped,
            fragments_sent: self.off.fragments_sent + cur.fragments_sent,
            fragments_reassembled: self.off.fragments_reassembled + cur.fragments_reassembled,
        }
    }

    /// 装填新分片（调用方先 shutdown 旧分片；本方法只做替换）
    fn install(&mut self, s: FlowShards) {
        self.shards = Some(s);
    }

    /// 活跃分片数（stats 行展示；0 = 单点路径）
    fn active(&self) -> usize {
        self.shards.as_ref().map(|s| s.len()).unwrap_or(0)
    }

    /// 拆下当前分片并把其计数并入退役累计（shutdown 由调用方在锁外执行）
    fn retire(&mut self) -> Option<FlowShards> {
        let old = self.shards.take();
        if let Some(s) = &old {
            let st = s.stats();
            self.off.sealed += st.sealed;
            self.off.delivered += st.delivered;
            self.off.dropped += st.dropped;
            self.off.fragments_sent += st.fragments_sent;
            self.off.fragments_reassembled += st.fragments_reassembled;
        }
        old
    }
}

#[derive(Debug)]
struct Config {
    self_addr: IPv8Address,
    peer_addr: IPv8Address,
    peer_ip: IpAddr, // IPv4 或 IPv6 字面量（跨网验证：对端可能在 v6 公网）
    /// 大内网/CGNAT 侧专用：首帧到达后把发送目的地「现学」为包的真实源地址，
    /// 覆盖启动时配置的 --peer-ip（对端公网映射地址预知不到）。
    learn_peer: bool,
    /// 无网卡模式：跳过 wintun（不加载驱动、不建适配器、不需要管理员），
    /// 用合成载荷包驱动隧道（发起方定时发 → 应答方逐字节回显 → 发起方比对）。
    /// 跨真实网络验证 AEAD/分片/握手时用——安全软件拦截驱动创建环境下的正路。
    no_tun: bool,
    /// --no-tun 合成载荷字节数（默认 64；> 引擎 mtu 即驱动 IPv8+ 分片路径）
    nt_size: usize,
    tun_ip: Ipv4Addr,
    netmask: Ipv4Addr, // 默认 /10 = CGNAT 空间（spec §7.9 / ADR-015）
    /// TUN IPv6 地址（方案 A：ULA 段，如 fd14::1/64）。None = 不给 TUN 配 v6，
    /// v6 流量走物理网卡不进隧道（与现有 v4 零回归对称）。
    tun_ipv6: Option<Ipv6Addr>,
    udp_port: u16,
    peer_port: u16,
    /// 备用隧道入口（--alt-ip/--alt-port）：主入口握手失败后 FallbackManager 级联至此。
    /// 未配置时只有主入口一个候选。
    alt: Option<(IpAddr, u16)>,
    /// 是否启用 Fallback 分级降级驱动（v9 §11）。关闭时保持 Phase 1/2 的
    /// "Init 每 2s 无限重发"行为，逐字节不变（零回归）。
    fallback: bool,
    /// 引擎侧 IPv8+ 包分片上限（含 40B 头；v9 默认 1432 = 1500-68）
    mtu: usize,
    /// wintun 接口 MTU（OS 交给我们的内层 IP 包最大整包尺寸）。默认 = mtu；
    /// 调大后超引擎上限的整包会走 IPv8+ 分片路径（-Fragment 验证用）
    tun_mtu: usize,
    dll_path: PathBuf,
    /// 是否主动发起握手（双端同时主动会互相拒绝对端的 Init → 死锁，
    /// 拓扑上必须一方 --initiate、一方被动）
    initiate: bool,
    /// 证书认证握手模式（Phase 2）。验证专用：--ca-seed 两端共享即等效
    /// 预置信任锚 + 本地预配证书；生产路径证书必须由 ZoneServer 签发。
    auth: bool,
    ca_seed: Option<[u8; 32]>,
    ed_seed: Option<[u8; 32]>,
    /// ZoneServer gRPC endpoint（真机注册路径：--zone http://host:port）。
    /// 与 --ca-seed 二选一；提供时节点证书/信任锚全部来自网络。
    zone: Option<String>,
    /// 证书缓存文件（v9 §10 生产语义）：注册成功后写入；重启时先离线验签
    /// （CA 签名 + 未过期 + 地址/公钥匹配本机），命中即免注册（ZoneServer
    /// 对重复注册返回 AlreadyRegistered，不缓存则每次重启必挂）。
    cert_cache: Option<PathBuf>,
    /// 网卡名：同机双实例联调时必须区分；跨 VM 部署可保持默认
    adapter_name: String,
    /// 主机侧地址前缀（默认 100.64.0.0/10 即 CGNAT；
    /// 同机联调可用 10.2xx.0.0/24 等与本机路由不冲突的段）
    tun_prefix: u8,
    /// ADR-026 级 2：Resolver 地址（--resolver http://host:port）。
    /// 提供时节点向 Resolver 登记并周期会合，取回对端候选地址打洞。
    resolver: Option<String>,
    /// 启用打洞编排（必须配 --resolver 与 --ed-seed）。
    /// --peer-ip 变成占位（决定 socket 绑定族：候选是 v6 就填任意 v6）。
    punch: bool,
    /// ADR-024 用户态性能线：Data 面流级分片 worker 数（--shards N，默认 1 = 单点
    /// 零回归）。Established 后自动拆分，同流同 worker 保 nonce 唯一。
    /// 仅真实 TUN 路径生效；--no-tun 回显验证件恒用单点引擎。
    /// 两端必须一致（部署配置，同 ADR-025 套件哲学）。
    shards: usize,
    /// 外部判决钩子监听地址（--hook，缺省关闭；裸 --hook = 127.0.0.1:45810）
    hook: Option<SocketAddr>,
    /// 钩子判决等待超时毫秒（--hook-timeout，默认 50）
    hook_timeout_ms: u64,
    /// 超时/无判决者时的默认动作（--hook-policy accept|drop，默认 accept）
    hook_default_drop: bool,
    /// 暴露给外部程序的包前缀字节数（--hook-payload，默认 128）
    hook_payload: usize,
    /// AEAD 套件（--cipher chacha|aes，默认 chacha；ADR-025：两端部署配置必须一致）
    cipher: CipherSuite,
    /// Registered I/O 数据面（--rio on|auto|off，默认 auto=能力探测逐级回退）
    rio_mode: RioMode,
    /// Phase 3 兼容性处理（--compat）：TTL 扣减、MSS 钳制、ICMP 差错回注
    compat: bool,
    /// 手动指定 MSS 钳制值（--mss-clamp，0 或缺省 = 自动按 effective_mtu 计算）
    mss_clamp: Option<u16>,
    /// Phase 3 连接迁移（--migrate）：检测本机出口 IP 变化，探测触发对端
    /// 现学新地址，隧道密钥/状态不变（WiFi↔4G 不断连）
    migrate: bool,
    /// Phase 4 --mp：多路径竞速。Data/FecRecovery 帧同时发 main+alt 两路径，
    /// 包级先到者赢（AEAD 重放窗口去重）。要求 alt 已配置、与 fallback 互斥。
    mp: bool,
    /// Phase 4 --fec：前向纠错。每 K 个 QoS 标记（DSCP≠0）的 Data 帧发 1 个
    /// XOR 恢复帧，单帧丢失免重传重建。
    fec: bool,
    /// --fec-k：FEC 组大小（2..=16，默认 4；开销 = 1/K）
    fec_k: usize,
    /// Phase 8 --l2：局域网 L2 传输（ipv8proto.sys 0xFB14 裸帧）
    l2: bool,
}

fn usage() -> ! {
    eprintln!(
        "用法: ipv8-node --self <32hex> --peer-addr <32hex> --peer-ip <IPv4|IPv6> [--initiate] \
         [--tun-ip 100.64.0.1] [--tun-prefix 100] [--udp-port 45700] [--peer-port <udp_port>] \
         [--adapter-name IPv8Plus] [--mtu 1432] [--tun-mtu <mtu>=--mtu] [--dll <path>]\n\
         \x20\x20 (--mtu = IPv8+ 分片上限；--tun-mtu 调大 = 整包进 TUN 走分片路径)\n\
         [--learn-peer]\n\
         \x20\x20 # 大内网对端专用：本端被动等对端首帧，把目的地现学为其真实源地址\n\
         \x20\x20 # （对端在 NAT 后预知不到公网映射地址；--peer-ip 传本端自己的地址占位定族）\n\
         [--no-tun [--nt-size 64]]\n\
         \x20\x20 # 零驱动模式：不加载 wintun、不建网卡（安全软件拦驱动的环境可跑）。\n\
         \x20\x20 # 发起方每 5s 注入合成包，应答方逐字节回显，验证真实网络上的隧道核心\n\
         [--auth --ed-seed <64hex> (--zone http://host:port | --ca-seed <64hex>)]\n\
         \x20\x20 # Phase 2 认证：--zone=向 ZoneServer 注册取证（真机路径），--ca-seed=预配（验证用）\n\
         \x20\x20 # --cert-cache <file>（配 --zone）：证书持久化，重启命中缓存免注册\n\
         [--fallback [--alt-ip <IPv4|IPv6> --alt-port <u16>]]\n\
         \x20\x20 # v9 §11 分级降级驱动：主入口超时→级联备用入口→明文 UDP；--alt 为备用入口\n\
         [--resolver http://host:port --punch --ed-seed <64hex>]\n\
         \x20\x20 # ADR-026 级 2 打洞：向 Resolver 登记+会合，取对端 observed 候选撞洞\n\
         \x20\x20 # （--peer-ip 占位定绑定族；应答方自动现学回程地址）\n\
         [--shards N]\n\
         \x20\x20 # ADR-024 用户态性能线：Data 面流级分片 worker 数（1..=64，默认 1=单点）。\n\
         \x20\x20 # Established 后自动拆分并行加解密；两端必须取相同 N（错配=丢包非错交付）\n\
         [--cipher chacha|aes]\n\
         \x20\x20 # ADR-025 AEAD 套件（默认 chacha20-poly1305；aes=aes-256-gcm，硬件 AES 机器更快）\n\
         \x20\x20 # 部署配置两端必须一致（不协商；不匹配的帧被拒），首帧前可改\n\
         [--rio on|auto|off]\n\
         \x20\x20 # Phase 2 Registered I/O 极速数据面（默认 auto：能力探测，失败自动回退 std）\n\
         [--hook [127.0.0.1:45810] --hook-timeout 50 --hook-policy accept|drop --hook-payload 128]\n\
         \x20\x20 # 外部判决钩子：把每个内层包以 NDJSON 推给本机程序判决 accept/drop。\n\
         \x20\x20 # 默认 fail-open；观察者可只录像不判决。协议见 docs/architecture.md §4\n\
         [--compat [--mss-clamp <mss>]]\n\
         \x20\x20 # Phase 3 兼容性（默认关闭=零回归）：TTL 扣减（traceroute 可见）、\n\
         \x20\x20 # DF 大包回 ICMP 需要分片、TCP SYN/SYN-ACK MSS 自动钳制到隧道 MTU、\n\
         \x20\x20 # 组播/广播逐字节透传（不扣 TTL，避免 mDNS/SSDP 黑洞）\n\
         \x20\x20 # --mss-clamp 直接指定最终 MSS 值（缺省=自动：v4 1352/v6 1332）\n\
         [--migrate]\n\
         \x20\x20 # Phase 3 连接迁移：检测本机出口 IP 变化（WiFi↔4G），\n\
         \x20\x20 # 自动探测；入口刷新只接受 AEAD 认证帧。两端都必须开启。\n\
         \x20\x20 # 安全提示：明文握手模式保留未认证重协商语义，安全敏感\n\
         \x20\x20 # 部署请与 --auth 同用（--auth 下伪造 Init 不产生任何刷新）\n\
         [--mp [--fec [--fec-k 4]]]\n\
         \x20\x20 # Phase 4 多路径竞速：Data/恢复帧同时发主+备两入口，包级先到者赢，\n\
         \x20\x20 # 丢包率 p→p²；要求 --alt-ip/--alt-port，与 --fallback 互斥。\n\
         \x20\x20 # --fec 前向纠错：每 K 个 DSCP≠0（低延迟标记）的 Data 帧发 1 个 XOR\n\
         \x20\x20 # 恢复帧，单帧丢失免重传。两端建议同开（仅一端开 --fec 时恢复帧被\n\
         \x20\x20 # 对端丢弃，功能退化为纯双发）。--fec-k 组大小 2..=16（默认 4=25% 开销）\n\
         [--l2]\n\
         \x20\x20 # Phase 8 局域网 L2 传输：经 ipv8proto.sys 0xFB14 裸帧收发，\n\
         \x20\x20 # 同子网零路由/零 NAT 开销；两端都需驱动 v0.11+ bound 同网卡\n\
         \x20\x20 # --peer-ip 不再需要（L2 直接用 MAC 通信），但仍需填一个 IP 占位\n\
         拓扑: 恰好一端 --initiate（主动），另一端被动等待 Init\n\
         示例(A 机主动): ipv8-node --self fb140000000000010001000000010000 \\\n\
         \x20\x20 --peer-addr fb140000000000010001000000020000 --peer-ip 192.168.1.12 --tun-ip 100.64.0.1 --initiate\n\
         示例(B 机被动): ipv8-node --self fb140000000000010001000000020000 \\\n\
         \x20\x20 --peer-addr fb140000000000010001000000010000 --peer-ip 192.168.1.11 --tun-ip 100.64.0.2"
    );
    std::process::exit(2);
}

fn parse_args() -> Result<Config, String> {
    parse_args_from(&std::env::args().skip(1).collect::<Vec<String>>())
}

/// argv 可注入（TR-5.1：非法/边界组合 parse 单测；生产入口 [`parse_args`]）
fn parse_args_from(argv: &[String]) -> Result<Config, String> {
    let argv: Vec<String> = argv.to_vec();
    // 取 --flag value 的 value；值粘连参数名或缺值时视为未提供
    let get = |flag: &str| -> Option<String> {
        argv.iter()
            .position(|a| a == flag)
            .and_then(|i| argv.get(i + 1))
            .filter(|v| !v.starts_with("--"))
            .cloned()
    };
    let req = |flag: &str| -> Result<String, String> {
        get(flag).ok_or_else(|| format!("缺少 {flag}"))
    };

    let self_addr = IPv8Address::from_canonical_str(&req("--self")?)
        .map_err(|e| format!("--self: {e}"))?;
    let peer_addr = IPv8Address::from_canonical_str(&req("--peer-addr")?)
        .map_err(|e| format!("--peer-addr: {e}"))?;
    let peer_ip = IpAddr::from_str(&req("--peer-ip")?).map_err(|e| format!("--peer-ip: {e}"))?;
    let learn_peer = argv.iter().any(|a| a == "--learn-peer");
    let no_tun = argv.iter().any(|a| a == "--no-tun");
    let nt_size = match get("--nt-size") {
        Some(s) => s.parse().map_err(|_| "--nt-size 非数字".to_string())?,
        None => 64usize,
    };
    let tun_ip = match get("--tun-ip") {
        Some(s) => Ipv4Addr::from_str(&s).map_err(|e| format!("--tun-ip: {e}"))?,
        None => Ipv4Addr::new(100, 64, 0, 1),
    };
    let udp_port = match get("--udp-port") {
        Some(s) => s.parse().map_err(|_| "--udp-port 非数字".to_string())?,
        None => 45_700,
    };
    // 对端端口默认等于本地端口；同机双实例时用 --peer-port 区分
    let peer_port = match get("--peer-port") {
        Some(s) => s.parse().map_err(|_| "--peer-port 非数字".to_string())?,
        None => udp_port,
    };
    let adapter_name = get("--adapter-name").unwrap_or_else(|| "IPv8Plus".to_string());
    let tun_prefix = match get("--tun-prefix") {
        Some(s) => s.parse().map_err(|_| "--tun-prefix 非 0-255 数字".to_string())?,
        None => 100u8, // CGNAT 第一段（ADR-015）
    };
    let mtu = match get("--mtu") {
        Some(s) => {
            let v: usize = s.parse().map_err(|_| "--mtu 非数字".to_string())?;
            // 下界 1280（IPv6 最小链路 MTU，且 mtu-40 需留得出 MSS）；
            // 上界 65535（ICMPv4 MTU 字段为 16 位，超出即截断）
            if !(1280..=65535).contains(&v) {
                return Err("--mtu 必须在 1280..=65535 之间".to_string());
            }
            v
        }
        None => 1432usize,
    };
    let tun_mtu = match get("--tun-mtu") {
        Some(s) => s.parse().map_err(|_| "--tun-mtu 非数字".to_string())?,
        None => mtu,
    };
    let alt = match (get("--alt-ip"), get("--alt-port")) {
        (Some(ip), Some(p)) => Some((
            IpAddr::from_str(&ip).map_err(|e| format!("--alt-ip: {e}"))?,
            p.parse().map_err(|_| "--alt-port 非数字".to_string())?,
        )),
        (None, None) => None,
        _ => return Err("--alt-ip 与 --alt-port 必须成对提供".to_string()),
    };
    let fallback = argv.iter().any(|a| a == "--fallback");
    let dll_path = match get("--dll") {
        Some(s) => PathBuf::from(s),
        None => {
            let exe_dir = std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|d| d.join("wintun.dll")));
            match exe_dir {
                Some(p) if p.exists() => p,
                // --no-tun 全程不加载 wintun，缺 dll 合法（零驱动模式的立身之本）
                _ if argv.iter().any(|a| a == "--no-tun") => PathBuf::from("(unused-no-tun)"),
                _ => {
                    return Err("找不到 wintun.dll：用 --dll 指定或放到 exe 同目录".to_string())
                }
            }
        }
    };

    let initiate = argv.iter().any(|a| a == "--initiate");
    let auth = argv.iter().any(|a| a == "--auth");
    let ca_seed = match get("--ca-seed") {
        Some(s) => Some(parse_seed(&s).map_err(|e| format!("--ca-seed: {e}"))?),
        None => None,
    };
    let ed_seed = match get("--ed-seed") {
        Some(s) => Some(parse_seed(&s).map_err(|e| format!("--ed-seed: {e}"))?),
        None => None,
    };
    let zone = get("--zone");
    let cert_cache = get("--cert-cache").map(PathBuf::from);
    let resolver = get("--resolver");
    let punch = argv.iter().any(|a| a == "--punch");
    let shards = match get("--shards") {
        Some(s) => {
            let v: usize = s.parse().map_err(|_| "--shards 非数字".to_string())?;
            if v == 0 || v > 64 {
                return Err(format!("--shards 必须在 1..=64，收到 {v}"));
            }
            v
        }
        None => 1,
    };
    if punch {
        if resolver.is_none() {
            return Err("--punch 需要 --resolver <url>（会合信令走 Resolver）".to_string());
        }
        if ed_seed.is_none() {
            return Err("--punch 需要 --ed-seed（登记/会合 PoP 用节点私钥）".to_string());
        }
    }
    if cert_cache.is_some() && zone.is_none() {
        return Err("--cert-cache 仅在 --zone 注册路径下有意义".to_string());
    }
    if auth && ed_seed.is_none() {
        return Err("--auth 必须提供 --ed-seed（节点签名私钥种子）".to_string());
    }
    if auth && zone.is_none() && ca_seed.is_none() {
        return Err("--auth 需要 --zone <url>（真机注册取证）或 --ca-seed（预配验证）".to_string());
    }

    // 前缀 100 → CGNAT /10（ADR-015 默认）；其他前缀按 /24 处理（同机联调段）
    let netmask = if tun_prefix == 100 {
        Ipv4Addr::new(255, 192, 0, 0)
    } else {
        Ipv4Addr::new(255, 255, 255, 0)
    };

    // ---- 外部判决钩子（ipv8-hook）----
    // 裸 --hook 用默认环回地址；--hook 127.0.0.1:9000 自定义
    let hook = if let Some(pos) = argv.iter().position(|a| a == "--hook") {
        let addr = argv
            .get(pos + 1)
            .filter(|v| !v.starts_with("--"))
            .map(|s| SocketAddr::from_str(s).map_err(|e| format!("--hook: {e}")))
            .transpose()?
            .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], ipv8_hook::DEFAULT_PORT)));
        if !addr.ip().is_loopback() {
            return Err("--hook 仅允许绑定环回地址（127.0.0.1 / ::1）".to_string());
        }
        Some(addr)
    } else {
        None
    };
    let hook_timeout_ms = match get("--hook-timeout") {
        Some(s) => s.parse().map_err(|_| "--hook-timeout 非数字".to_string())?,
        None => 50,
    };
    let hook_default_drop = match get("--hook-policy") {
        Some(s) if s.eq_ignore_ascii_case("drop") => true,
        Some(s) if s.eq_ignore_ascii_case("accept") => false,
        Some(s) => return Err(format!("--hook-policy 只接受 accept|drop，收到 {s}")),
        None => false,
    };
    let hook_payload = match get("--hook-payload") {
        Some(s) => s.parse().map_err(|_| "--hook-payload 非数字".to_string())?,
        None => 128,
    };
    let cipher = match get("--cipher").as_deref() {
        Some(s) if s.eq_ignore_ascii_case("chacha") || s == "chacha20-poly1305" => {
            CipherSuite::ChaCha20Poly1305
        }
        Some(s) if s.eq_ignore_ascii_case("aes") || s.eq_ignore_ascii_case("aes-256-gcm") => {
            CipherSuite::Aes256Gcm
        }
        Some(s) => return Err(format!("--cipher 只接受 chacha|aes，收到 {s}")),
        None => CipherSuite::ChaCha20Poly1305, // 默认套件，零回归
    };
    let rio_mode = match get("--rio").as_deref() {
        Some(s) if s.eq_ignore_ascii_case("on") => RioMode::On,
        Some(s) if s.eq_ignore_ascii_case("auto") => RioMode::Auto,
        Some(s) if s.eq_ignore_ascii_case("off") => RioMode::Off,
        Some(s) => return Err(format!("--rio 只接受 on|auto|off，收到 {s}")),
        None => RioMode::Auto,
    };
    // Phase 3 兼容性开关（默认关闭 = 零回归）
    let compat = argv.iter().any(|a| a == "--compat");
    let mss_clamp = match get("--mss-clamp") {
        Some(s) => {
            let v: u16 = s.parse().map_err(|_| "--mss-clamp 非数字".to_string())?;
            if v == 0 { None } else { Some(v) }
        }
        None => None,
    };
    let migrate = argv.iter().any(|a| a == "--migrate");

    // ---- Phase 4：多路径竞速 + FEC ----
    let mp = argv.iter().any(|a| a == "--mp");
    let fec = argv.iter().any(|a| a == "--fec");
    let fec_k = match get("--fec-k") {
        Some(s) => s.parse().map_err(|_| "--fec-k 非数字".to_string())?,
        None => 4,
    };
    if mp && alt.is_none() {
        return Err("--mp 需要 --alt-ip/--alt-port（备用入口即第二路径目的地）".to_string());
    }
    if mp && fallback {
        return Err("--mp 与 --fallback 互斥（alt 入口角色冲突：备用入口 vs 级联候选，v1 不做组合）".to_string());
    }
    if !(ipv8_fec::FEC_MIN_K..=ipv8_fec::FEC_MAX_K).contains(&fec_k) {
        return Err(format!(
            "--fec-k 必须在 {}..={}，收到 {fec_k}",
            ipv8_fec::FEC_MIN_K,
            ipv8_fec::FEC_MAX_K
        ));
    }

    Ok(Config {
        self_addr,
        peer_addr,
        peer_ip,
        learn_peer,
        no_tun,
        nt_size,
        tun_ip,
        netmask,
        udp_port,
        peer_port,
        alt,
        fallback,
        mtu,
        tun_mtu,
        dll_path,
        initiate,
        auth,
        ca_seed,
        ed_seed,
        zone,
        cert_cache,
        adapter_name,
        tun_prefix,
        resolver,
        punch,
        shards,
        hook,
        hook_timeout_ms,
        hook_default_drop,
        hook_payload,
        cipher,
        rio_mode,
        compat,
        mss_clamp,
        migrate,
        mp,
        fec,
        fec_k,
        l2: argv.iter().any(|a| a == "--l2"),
    })
}

/// 证书缓存文件布局（仅公开材料，CA 签名自证完整性；私钥仍走 --ed-seed）：
/// `MAGIC(4) ‖ version(1) ‖ ca_pub(32) ‖ cert(120)`
/// cert 体 = addr(16) ‖ verify_key(32) ‖ not_after(8) ‖ ca_sig(64)
const CACHE_MAGIC: &[u8; 4] = b"IP8C";
const CACHE_VERSION: u8 = 1;
const CA_PUB_LEN: usize = 32;
const CERT_BODY_LEN: usize = 16 + 32 + 8 + 64; // 120 B
const CACHE_LEN: usize = 4 + 1 + CA_PUB_LEN + CERT_BODY_LEN; // 157 B

fn cert_to_bytes(cert: &Cert) -> Vec<u8> {
    let mut b = Vec::with_capacity(CERT_BODY_LEN);
    b.extend_from_slice(&cert.addr.to_bytes());
    b.extend_from_slice(&cert.verify_key);
    b.extend_from_slice(&cert.not_after.to_be_bytes());
    b.extend_from_slice(&cert.ca_sig);
    b
}

fn cert_from_bytes(b: &[u8]) -> Option<Cert> {
    if b.len() != CERT_BODY_LEN {
        return None;
    }
    let addr_bytes: [u8; 16] = b[0..16].try_into().ok()?;
    Some(Cert {
        addr: IPv8Address::from_wire(&addr_bytes)?,
        verify_key: b[16..48].try_into().ok()?,
        not_after: u64::from_be_bytes(b[48..56].try_into().ok()?),
        ca_sig: b[56..120].try_into().ok()?,
    })
}

/// 读缓存并离线三验：文件结构合法 + CA 签名有效且未过期 + 证书主体 == 本机
/// （地址与公钥都对得上本地 seed）。任何一环不过 → None（回退注册路径）——
/// 缓存只是快路径，损坏/过期/拷错机器的文件一律静默作废。
fn load_cert_cache(
    path: &Path,
    self_addr: IPv8Address,
    ed_seed: [u8; 32],
    now: u64,
) -> Option<(HostIdentity, TrustAnchor)> {
    let raw = std::fs::read(path).ok()?;
    if raw.len() != CACHE_LEN || &raw[0..4] != CACHE_MAGIC || raw[4] != CACHE_VERSION {
        return None;
    }
    let ca_pub: [u8; CA_PUB_LEN] = raw[5..5 + CA_PUB_LEN].try_into().ok()?;
    let cert = cert_from_bytes(&raw[5 + CA_PUB_LEN..])?;
    let trust = TrustAnchor::from_bytes(ca_pub).ok()?;
    if trust.verify(&cert, now).is_err() {
        return None; // CA 签名坏 / 已过期
    }
    if cert.addr != self_addr || cert.verify_key != verify_key_from_seed(ed_seed) {
        return None; // 缓存属于别的身份（拷错机器/换 --ed-seed）
    }
    Some((HostIdentity::with_cert(self_addr, ed_seed, cert), trust))
}

/// 真机注册路径（带证书持久化）：
/// 1) 缓存命中（离线验签 + 未过期 + 主体匹配）→ 直接复用，ZoneServer 不可达也能起；
/// 2) 未命中 → 取锚 → PoP 注册（同密钥重注册 = 续期放行）→ 写回缓存。
///
/// CA 私钥全程只在服务端；节点学到的证书与锚都来自网络。
async fn enroll_via_zone(
    zone_url: &str,
    self_addr: IPv8Address,
    ed_seed: [u8; 32],
    cache_path: Option<&Path>,
) -> Result<(HostIdentity, TrustAnchor), Box<dyn Error>> {
    use ipv8_zoneserver::grpc::pb::{
        zone_server_client::ZoneServerClient, GetTrustAnchorRequest, RegisterRequest,
    };
    let ed_pub = verify_key_from_seed(ed_seed);
    let now = now_epoch_secs();
    if let Some(p) = cache_path {
        if let Some(pair) = load_cert_cache(p, self_addr, ed_seed, now) {
            println!(
                "[ipv8-node] [cert-cache] HIT file={} not_after={} skip-register",
                p.display(),
                pair.0.cert.not_after
            );
            return Ok(pair);
        }
        println!("[ipv8-node] [cert-cache] MISS -> register");
    }
    let mut c = ZoneServerClient::connect(zone_url.to_string()).await?;
    let anchor = c
        .get_trust_anchor(GetTrustAnchorRequest {})
        .await?
        .into_inner()
        .ca_pub;
    let anchor: [u8; 32] = anchor.try_into().map_err(|_| "CA 公钥长度非 32")?;
    let addr_text = self_addr.to_canonical_string();
    let proof = pop_sign(ed_seed, &register_pop_message(&addr_text, &ed_pub));
    let r = c
        .register(RegisterRequest {
            addr_text,
            ed_pub: ed_pub.to_vec(),
            proof: proof.to_vec(),
            label: "ipv8-node".to_string(),
        })
        .await?
        .into_inner();
    let cert = Cert {
        addr: self_addr,
        verify_key: r.verify_key.try_into().map_err(|_| "证书公钥长度错误")?,
        not_after: r.not_after,
        ca_sig: r.ca_sig.try_into().map_err(|_| "证书签名长度错误")?,
    };
    let trust = TrustAnchor::from_bytes(anchor)?;
    if let Some(p) = cache_path {
        let mut raw = Vec::with_capacity(CACHE_LEN);
        raw.extend_from_slice(CACHE_MAGIC);
        raw.push(CACHE_VERSION);
        raw.extend_from_slice(&anchor);
        raw.extend_from_slice(&cert_to_bytes(&cert));
        debug_assert_eq!(raw.len(), CACHE_LEN);
        if let Err(e) = std::fs::write(p, &raw) {
            tracing::warn!(error = %e, "[ipv8-node] 证书缓存写入失败（不影响本次运行）");
        } else {
            println!("[ipv8-node] 证书已缓存至 {}（重启命中则免注册）", p.display());
        }
    }
    Ok((HostIdentity::with_cert(self_addr, ed_seed, cert), trust))
}

#[tokio::main]
async fn main() {
    // 结构化日志：tracing 输出走 stderr，cross-verify 脚本读的 [stats]/Established
    // 等行留在 stdout 不受影响；级别可用 RUST_LOG 环境变量覆盖（默认 info）。
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")))
        .with_writer(std::io::stderr)
        .init();
    let cfg = match parse_args() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("参数错误: {e}");
            usage();
        }
    };
    match run(cfg).await {
        Ok(()) => println!("\n[ipv8-node] 正常退出"),
        Err(e) => {
            // Debug 形态输出错误链（wintun crate 的 OsError 变体会带 Win32
            // 错误码与函数名）——现场排障全靠这一行，别退回 Display。
            tracing::error!(error = %format!("{e:?}"), "[ipv8-node] 致命错误");
            tracing::error!("提示: 需要管理员权限；UDP 入站端口需在防火墙放行");
            std::process::exit(1);
        }
    }
}

async fn run(cfg: Config) -> Result<(), Box<dyn Error>> {
    // 配置一致性：tun-ip 首段必须落在 --tun-prefix 声明的 /8 内，
    // 否则 netmask 推导与实际地址矛盾（典型手滑：忘了改 --tun-ip）
    if cfg.tun_ip.octets()[0] != cfg.tun_prefix {
        return Err(format!(
            "配置矛盾: --tun-ip {} 首段 != --tun-prefix {}",
            cfg.tun_ip, cfg.tun_prefix
        )
        .into());
    }
    println!(
        "[ipv8-node] self={} peer={} peer_ip={}:{} tun={}/{} adapter={} mtu={}",
        cfg.self_addr.to_canonical_string(),
        cfg.peer_addr.to_canonical_string(),
        cfg.peer_ip,
        cfg.peer_port,
        cfg.tun_ip,
        cfg.netmask,
        cfg.adapter_name,
        cfg.mtu
    );

    // ---- wintun：TUN 设备 + 单一双工 Session（官方 udp-echo 示例模式：
    // 一个 start_session，读写线程各持同一 Session 的 Arc 克隆）----
    // --no-tun：整个驱动路径跳过（不 load dll / 不建适配器 / 不提权也能跑）。
    // 隧道核心（AEAD/握手/分片）与真实 UDP 完全保留，载荷改由合成包驱动。
    let session: Option<Arc<wintun::Session>> = if cfg.no_tun {
        println!("[ipv8-node] 模式: --no-tun（零驱动：不加载 wintun、不建网卡、不用管理员）");
        None
    } else {
        let wintun = unsafe { wintun::load_from_path(&cfg.dll_path) }?;
        let adapter = wintun::Adapter::open(&wintun, &cfg.adapter_name).or_else(|_| {
            wintun::Adapter::create(&wintun, &cfg.adapter_name, TUNNEL_TYPE, None).map_err(|e| {
                // wintun crate 吞掉了 GetLastError——这里补抓：建卡失败的根因
                // （5=权限不够 / 0xE000020B=驱动被安全策略拒绝 / 110=设备被禁用）
                // 全在这个码里，现场排障就靠它。
                let code = io::Error::last_os_error()
                    .raw_os_error()
                    .map(|c| format!("Win32 {c} (0x{c:X})"))
                    .unwrap_or_else(|| "无错误码".to_string());
                format!("{e} [{code}]")
            })
        })?;
        adapter.set_address(cfg.tun_ip)?;
        adapter.set_netmask(cfg.netmask)?;
        adapter.set_mtu(cfg.tun_mtu)?;
        Some(Arc::new(adapter.start_session(wintun::MAX_RING_CAPACITY)?))
    };

    // ---- 隧道引擎（三模式）----
    // --zone 优先：证书与信任锚来自运行中的 ZoneServer（真机路径）；
    // 仅 --ca-seed 时为预配快速路径（离线验证用，CA 私钥本不该在节点侧）。
    let engine = Arc::new(Mutex::new(if cfg.auth {
        let (host, trust) = match (&cfg.zone, cfg.ca_seed) {
            (Some(url), _) => {
                println!("[ipv8-node] 模式: 认证握手（真机路径：向 {url} 注册取证）");
                enroll_via_zone(
                    url,
                    cfg.self_addr,
                    cfg.ed_seed.expect("parse 已校验"),
                    cfg.cert_cache.as_deref(),
                )
                .await?
            }
            (None, Some(ca)) => {
                println!("[ipv8-node] 模式: 认证握手（预配 CA 种子，仅验证用途）");
                let ca = CertAuthority::from_seed(ca);
                let trust =
                    TrustAnchor::from_bytes(ca.public_key()).expect("CA 公钥自生成必合法");
                let host =
                    provision(&ca, cfg.self_addr, cfg.ed_seed.expect("parse 已校验"), NO_EXPIRY);
                (host, trust)
            }
            _ => return Err("--auth 需要 --zone 或 --ca-seed".into()),
        };
        Engine::authenticated(host, trust, cfg.self_addr, cfg.peer_addr)
    } else {
        Engine::new(Identity::generate(), cfg.self_addr, cfg.peer_addr)
    }));
    // 引擎分片上限 = cfg.mtu（v9: 1432）；TUN 接口 MTU = cfg.tun_mtu（默认相同；
    // -Fragment 验证时调大，使整包进 TUN 后由 IPv8+ 层分片）
    engine.lock().expect("engine").set_mtu(cfg.mtu);
    // ADR-025：握手建钥前应用部署套件（晚了会被引擎忽略；两端必须一致）
    engine.lock().expect("engine").set_cipher_suite(cfg.cipher);
    println!(
        "[ipv8-node] AEAD 套件: {}",
        match cfg.cipher {
            CipherSuite::ChaCha20Poly1305 => "chacha20-poly1305",
            CipherSuite::Aes256Gcm => "aes-256-gcm",
        }
    );

    // ---- ADR-026 流级分片中枢：Established 后由主循环装填（--shards 1..=64，
    // 默认 1 = 永不启用零回归；--no-tun 回显验证件恒单点）----
    let hub: Arc<Mutex<ShardHub>> = Arc::new(Mutex::new(ShardHub::default()));
    let has_tun = session.is_some();

    // ---- UDP 外层（一个 socket 同时收发；send_to/recv_from 均 &self 可跨线程）----
    // 绑定族跟随 --peer-ip：v6 对端绑 :: （std 对未指定 v6 地址默认双栈，
    // 现学到 v4 映射源地址后仍可从同一 socket 回发）。
    let bind_addr: SocketAddr = match cfg.peer_ip {
        IpAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, cfg.udp_port)),
        IpAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, cfg.udp_port)),
    };
    // Phase 2：UdpIo 按 --rio 选 RIO 批量数据面或标准 std（auto 失败自动回退）。
    // Phase 8：--l2 直接走 ipv8proto.sys 0xFB14 裸帧。
    // 三种模式同构：send_to/recv 语义一致，打洞/分片/握手各线程无感知。
    let mode = if cfg.l2 { rio::RioMode::L2 } else { cfg.rio_mode };
    let udp = UdpIo::bind(bind_addr, mode)?;
    let peer = SocketAddr::new(cfg.peer_ip, cfg.peer_port);
    println!("[ipv8-node] UDP 绑定 {bind_addr}，对端初始 {peer}");

    // ---- Fallback 共享调度状态 ----
    // Transport / Sched 定义见模块顶部（限速决策方法在其上，供单测覆盖）。
    let entry_addr = |entry: &str, fallback_to: SocketAddr| -> SocketAddr {
        entry.parse().unwrap_or(fallback_to)
    };
    let sched = Arc::new(Mutex::new(Sched {
        fb: FallbackManager::new(FallbackOptions::default()),
        main: peer,
        alt: cfg.alt.map(|(ip, p)| SocketAddr::new(ip, p)),
        current: FallbackPath::Tunnel { entry: String::new() },
        transport: Transport::Tunnel(peer),
        attempt: None,
        success_recorded: false,
        plain_reported: false,
        est_started: None,
        est_delivered: 0,
        plain_tx: 0,
        plain_rx: 0,
        last_unauth_roam: None,
        mp: cfg.mp,
    }));
    // 喂入口拓扑：主入口 + 可选备用入口，ipv8_capable=true（node 验证恒为隧道候选）
    {
        let mut sc = sched.lock().expect("sched");
        let alt_list: Vec<String> = sc.alt.as_ref().map(|a| vec![a.to_string()]).unwrap_or_default();
        sc.fb.note_resolved(
            PEER_KEY,
            Resolved {
                tunnel_entry: Some(format!("{}:{}", cfg.peer_ip, cfg.peer_port)),
                alt_entries: alt_list,
                ipv8_capable: true,
                last_good_entry: None,
            },
        );
    }

    // ---- ADR-026 级 2：打洞编排（--punch + --resolver）----
    // 每轮：登记（首轮，取服务端所见 observed 回显）→ 会合拿对端候选
    // （Resolver 把"它看到的对端源地址"排首位）→ 向候选连发敲门包撞活
    // 双方 NAT 映射；发起方在隧道未建立时把 Init 目标改指首选候选，
    // 之后握手由既有主循环幂等重发驱动，应答方 --learn-peer 现学回位。
    // 20s 周期 = 心跳刷新 observed（服务端窗口 90s，1:4.5 安全比）。
    if cfg.punch {
        let url = cfg.resolver.clone().expect("parse 已校验");
        let ed = cfg.ed_seed.expect("parse 已校验");
        let (sock2, engine2, sched2) = (udp.clone(), engine.clone(), sched.clone());
        let (sa, pa, port) = (cfg.self_addr, cfg.peer_addr, cfg.udp_port);
        let initiate2 = cfg.initiate;
        let ed_pub = verify_key_from_seed(ed);
        let addr_text = sa.to_canonical_string();
        let peer_text = pa.to_canonical_string();
        println!("[ipv8-node] 模式: PUNCH（ADR-026 级 2 打洞，Resolver={url}）");
        tokio::spawn(async move {
            use ipv8_resolver::grpc::pb::resolver_client::ResolverClient;
            use ipv8_resolver::grpc::pb::{RegisterRequest, RendezvousRequest};
            use ipv8_resolver::{register_pop_message, rendezvous_pop_message};
            let mut registered = false;
            loop {
                match ResolverClient::connect(url.clone()).await {
                    Err(e) => println!("[punch] 连接 Resolver {url} 失败: {e}（30s 后重试）"),
                    Ok(mut c) => {
                        if !registered {
                            let proof = pop_sign(ed, &register_pop_message(&addr_text, &ed_pub));
                            let req = RegisterRequest {
                                name: String::new(),
                                addr_text: addr_text.clone(),
                                ed_pub: ed_pub.to_vec(),
                                proof: proof.to_vec(),
                                // 打洞模式下没有可预登记的入口——真实映射由服务端 observed 观察
                                tunnel_entry: format!("0.0.0.0:{port}"),
                                alt_entries: vec![],
                                mtu: 0,
                                ttl: 120,
                                ipv8_capable: true,
                            };
                            match c.register(req).await {
                                Ok(r) => {
                                    let o = r.into_inner();
                                    println!(
                                        "[punch] 已登记 Resolver，本端公网映射 observed={}",
                                        if o.observed_addr.is_empty() { "(不可观察)" } else { &o.observed_addr }
                                    );
                                    registered = true;
                                }
                                Err(e) => println!("[punch] 登记失败: {e:?}"),
                            }
                        }
                        let proof = pop_sign(ed, &rendezvous_pop_message(&addr_text, &peer_text));
                        let req = RendezvousRequest {
                            addr_text: addr_text.clone(),
                            proof: proof.to_vec(),
                            peer_addr_text: peer_text.clone(),
                            local_candidates: vec![],
                        };
                        match c.rendezvous(req).await {
                            Ok(r) => {
                                let out = r.into_inner();
                                if !out.peer_candidates.is_empty() {
                                    println!("[punch] 对端候选（observed 优先）: {:?}", out.peer_candidates);
                                    // 只用首选候选（服务端权威观察）；失败下轮自动换
                                    if let Some(dest) = out
                                        .peer_candidates
                                        .iter()
                                        .filter_map(|c| c.parse::<SocketAddr>().ok())
                                        // 双栈适配：socket 绑在 v6（占位 --peer-ip 为 v6）
                                        // 而候选是 v4 时，Windows 需显式 v4-mapped 才可发
                                        // （Ipv6Addr::from(Ipv4Addr) = ::a.b.c.d 即映射形）
                                        .map(|a| match (sock2.local_addr().ok(), a) {
                                            (Some(l), SocketAddr::V4(v4)) if l.is_ipv6() => {
                                                let o = v4.ip().octets();
                                                let mapped = Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff,
                                                    u16::from_be_bytes([o[0], o[1]]),
                                                    u16::from_be_bytes([o[2], o[3]]));
                                                SocketAddr::new(IpAddr::V6(mapped), a.port())
                                            }
                                            _ => a,
                                        })
                                        .next()
                                    {
                                        for _ in 0..3 {
                                            let _ = sock2.send_to(PUNCH_KNOCK, dest);
                                        }
                                        if initiate2 {
                                            let est = {
                                                let g = engine2.lock().expect("engine");
                                                g.stats().state == State::Established
                                            };
                                            if !est {
                                                let mut sc = sched2.lock().expect("sched");
                                                sc.transport = Transport::Tunnel(dest);
                                                if let Some((f, t0, _)) = sc.attempt.clone() {
                                                    sc.attempt = Some((f, t0, dest));
                                                }
                                            }
                                        }
                                    }
                                } else {
                                    println!("[punch] 会合成功但对端无候选（等对端上线）");
                                }
                            }
                            Err(e) => println!("[punch] 会合失败: {}（对端未登记/签名域错？）", e.code()),
                        }
                    }
                }
                tokio::time::sleep(Duration::from_secs(20)).await;
            }
        });
    }

    // 角色：仅主动方发起握手；被动方等对端 Init（双方同时主动会互相
    // 拒绝对端的 Init 而永久死锁）。
    // - fallback 关：Phase 1 行为，Init 每 tick 幂等重发，不限时。
    // - fallback 开：主循环按 FallbackManager 分级超时→重试→入口级联→明文。
    if cfg.initiate {
        if cfg.fallback {
            println!("[ipv8-node] 模式: Fallback 驱动（主入口 {}，备用 {:?}）", peer, cfg.alt);
        } else {
            let f = {
                let mut g = engine.lock().expect("engine");
                if cfg.auth {
                    g.start_auth_handshake()
                } else {
                    g.start_handshake()
                }
            };
            // 首发包失败不再直接崩：多为「本机无该族出口」（v6 未启用 → WSAENETUNREACH）。
            // Init 每 tick 幂等重发兜底，这里只报一次清晰诊断后继续跑。
            if let Err(e) = udp.send_to(&f, peer) {
                tracing::warn!(error = %e, target = %peer, "[ipv8-node] 首发失败：常见原因是本机没有到该地址的网络出口（如目标为 IPv6 但本机 v6 未启用），测试命令: ping -6 <对端v6>");
            } else {
                println!("[ipv8-node] {} 已发出 ({}B)，等待 Established...", if cfg.auth { "AuthInit" } else { "HandshakeInit" }, f.len());
            }
            sched.lock().expect("sched").attempt = Some((f, now_epoch_secs(), peer));
        }
    } else {
        println!("[ipv8-node] 被动模式：等待对端 {}...", if cfg.auth { "AuthInit" } else { "HandshakeInit" });
    }

    // ---- 外部判决钩子（--hook；仅环回，默认关闭）----
    let hook_bus: Option<Arc<HookBus>> = cfg.hook.map(|addr| {
        let hcfg = HookConfig {
            listen: addr,
            timeout: Duration::from_millis(cfg.hook_timeout_ms),
            default_action: if cfg.hook_default_drop {
                HookAction::Drop
            } else {
                HookAction::Accept
            },
            payload_prefix: cfg.hook_payload,
            ..HookConfig::default()
        };
        match HookBus::start(hcfg) {
            Ok(b) => {
                println!(
                    "[hook] 外部判决钩子监听 {}（默认 {}，超时 {}ms，包前缀 {}B）",
                    addr,
                    if cfg.hook_default_drop { "drop（fail-close）" } else { "accept（fail-open）" },
                    cfg.hook_timeout_ms,
                    cfg.hook_payload
                );
                b
            }
            Err(e) => {
                eprintln!("[hook] 监听 {addr} 失败: {e}");
                std::process::exit(1);
            }
        }
    });

    // ---- 数据面共享上下文（Plane）----
    // 入站帧处理与 TUN 出站批处理只写一份：std 双线程模式（--rio off / auto
    // 回退）与 RIO 单事件循环（--rio on / auto 命中）走完全相同的业务逻辑，
    // 两种模式的差异只在「谁把字节取回来、谁把帧发出去」。
    let echo_ok = Arc::new(AtomicU32::new(0));
    let echo_bad = Arc::new(AtomicU32::new(0));

    /// Phase 4 FEC 收发状态机对（--fec 关闭时 Plane.fec = None，零开销）
    struct FecNode {
        tx: Mutex<FecTx>,
        rx: Mutex<FecRx>,
    }

    struct Plane {
        engine: Arc<Mutex<Engine>>,
        udp: UdpIo,
        session: Option<Arc<wintun::Session>>,
        sched: Arc<Mutex<Sched>>,
        hub: Arc<Mutex<ShardHub>>,
        hook: Option<Arc<HookBus>>,
        plain_demux: bool,
        learn: bool,
        is_initiator: bool,
        echo_ok: Arc<AtomicU32>,
        echo_bad: Arc<AtomicU32>,
        /// Phase 3：是否启用兼容处理（TTL/MSS/ICMP）
        compat: bool,
        /// Phase 3：隧道有效 MTU = mtu - 40（IPv8+ 基础头）
        effective_mtu: usize,
        /// Phase 3：本机 TUN 地址（ICMP 差错报文源地址）
        tun_ip: Ipv4Addr,
        /// Phase 3：手动 MSS 钳制值（None = 自动）
        mss_clamp: Option<u16>,
        /// Phase 3：连接迁移（允许从新地址的探测/合法帧持续现学入口）
        migrate: bool,
        /// Phase 4 --mp：数据面双发第二目的地（备用入口）。None = 单路径
        mp_alt: Option<SocketAddr>,
        /// Phase 4 --fec：FEC 收发状态机对；None = 关闭（Type=6 由引擎静默丢）
        fec: Option<Arc<FecNode>>,
    }

    impl Plane {
        /// Phase 3：把 ICMP 差错报文写回本地 TUN（不进隧道）
        fn inject_icmp(&self, icmp_pkt: &[u8]) {
            let Some(s) = &self.session else { return };
            match s.allocate_send_packet(icmp_pkt.len() as u16) {
                Ok(mut p) => {
                    p.bytes_mut().copy_from_slice(icmp_pkt);
                    s.send_packet(p);
                }
                Err(e) => tracing::warn!(error = %e, "[compat] ICMP 回注 allocate 失败"),
            }
        }

        /// 把隧道入口（发送目标）立即刷新为 `from`（强凭据通道，无限速）。
        /// 返回 true 表示确有变化（日志由调用方在锁外打印）。
        /// 决策逻辑见 [`Sched::strong_refresh`]（N-6 限速窗重置在其内）。
        fn apply_transport_refresh(&self, from: SocketAddr) -> bool {
            self.sched.lock().expect("sched").strong_refresh(from)
        }

        /// 未认证帧路径的入口刷新（握手首帧现学 / 分片活跃期漫游 / 明文握手
        /// resp）。决策逻辑（含 N-5 首帧免限速门控、10s 限速）见
        /// [`Sched::unauth_refresh`]；返回日志消息（None=未刷新）由调用方
        /// 在锁外打印。
        fn maybe_learn_unauthenticated(
            &self,
            from: SocketAddr,
            learned: &mut bool,
            allow_first_frame: bool,
        ) -> Option<String> {
            self.sched
                .lock()
                .expect("sched")
                .unauth_refresh(from, learned, allow_first_frame)
        }

        /// 处理一个入站 UDP 数据报（已从内核取回）。
        /// `learned` 是「大内网入口现学」一次性标志，随接收侧线程走
        /// （std 收线程与 RIO 事件循环各持一份，语义等价）。
        fn handle_inbound(&self, raw: &[u8], from: SocketAddr, learned: &mut bool) {
            let n = raw.len();
            // 打洞敲门包：只用于撞活 NAT 映射，静默吸收——
            // 不进引擎（否则污染 dropped 判据）、不回包、**绝不改隧道入口**。
            // （F-5：敲门包无认证，任何外部主机都能伪造 8 字节固定载荷；
            //  漫游入口刷新只接受「通过 AEAD 验证的帧」，见 handle_inbound 后半段。）
            if raw == PUNCH_KNOCK {
                return;
            }
            // ---- Phase 4 --fec：恢复帧分流 + Data 帧缓存（FR-5）----
            // 必须在 hub/引擎之前：两者都不消费 Type=6（引擎静默丢），不先分流
            // 则恢复帧永远进不了 FecRx。Data 帧 observe 以 AEAD 计数器为键，
            // --mp 双发重复帧覆盖值无副作用。fec=None 时整块跳过（零回归）。
            if let Some(fec) = &self.fec {
                if raw.len() >= 2 && raw[0] == 0x01 {
                    if raw[1] == 6 {
                        let recon = fec.rx.lock().expect("fec-rx").accept_recovery(raw);
                        match recon {
                            Ok(Some(recon)) => {
                                // 重建 Data 帧走完整入站链路：hub/引擎重放窗口
                                // 兜底（晚于原件到达 → Replay 拒绝，无害）
                                self.handle_inbound(&recon, from, learned);
                            }
                            Ok(None) => {} // 全在席 / 缺≥2 放弃 / 重复组
                            Err(e) => {
                                tracing::debug!(error = %e, "[fec] 恢复帧拒绝");
                            }
                        }
                        return;
                    }
                    if raw[1] == 2 {
                        let _ = fec.rx.lock().expect("fec-rx").observe_data(raw);
                    }
                }
            }
            // 明文降级入包：非隧道帧（Ver 字节≠0x01）→ 直接注入 TUN。
            // 仅在 -Fallback 验证下启用，避免改变既有模式丢弃语义。
            if self.plain_demux && (n < 10 || raw[0] != 0x01) {
                let ipv4 = matches!(raw.first(), Some(v) if v >> 4 == 4);
                let ipv6 = matches!(raw.first(), Some(v) if v >> 4 == 6);
                if ipv4 || ipv6 {
                    // 外部判决钩子（入站），与隧道解密包同一套策略
                    let allow = self
                        .hook
                        .as_ref()
                        .map(|h| {
                            let v = h.evaluate(&PacketEvent {
                                direction: HookDirection::In,
                                packet: raw,
                            });
                            if !v.delay.is_zero() {
                                std::thread::sleep(v.delay);
                            }
                            v.accepted()
                        })
                        .unwrap_or(true);
                    if !allow {
                        return;
                    }
                    // 明文包只有真 TUN 才有处可写；--no-tun 下计数丢弃。
                    match &self.session {
                        Some(s) => match s.allocate_send_packet(n as u16) {
                            Ok(mut p) => {
                                p.bytes_mut().copy_from_slice(raw);
                                s.send_packet(p);
                                self.sched.lock().expect("sched").plain_rx += 1;
                            }
                            Err(e) => tracing::warn!(error = %e, "[tun] plain allocate"),
                        },
                        None => {
                            self.sched.lock().expect("sched").plain_rx += 1;
                        }
                    }
                    return;
                }
            }
            // 大内网侧现学入口（必须在 handle_frame_at 之前：被动方对首帧会
            // 产出握手响应，resp 发往当前 transport——不先学就回错地址）。
            // 仅隧道帧触发（Ver==0x01）。Established 后 --migrate 的漫游现学
            // 在 helper 内限速；真正的对端漫游随后会用 AEAD 认证帧免限速纠正。
            if self.learn && n >= 1 && raw[0] == 0x01 && (!*learned || self.migrate) {
                if let Some(msg) =
                    self.maybe_learn_unauthenticated(from, learned, true)
                {
                    println!("{msg}");
                }
            }
            let (resp, delivered) = {
                // ADR-026：分片活跃时 Data 帧由 workers 接管
                // （同余路由免解密定片）；握手/控制帧仍走引擎状态机。
                if self.hub.lock().expect("hub").feed(raw) {
                    return;
                }
                let mut g = self.engine.lock().expect("engine");
                let r = g.handle_frame_at(raw, now_epoch_secs());
                (r, g.take_delivered())
            };
            // F-5/N-1 连接迁移：入口刷新按凭据强度分两级。
            // 强凭据（delivered=AEAD Data，或 AuthInit 三验通过的 resp）→
            // 立即免限速；明文 HandshakeInit 的 resp 不认证发起方（弱凭据），
            // 与未认证现学共用 10s 限速，第三方无法以 74B 伪造包抢占入口。
            // 必须在 resp 发送前完成：漫游握手响应要回到新地址。
            if self.migrate && (resp.is_some() || delivered.is_some()) {
                let strong =
                    is_strong_roam_credential(raw, resp.is_some(), delivered.is_some());
                let changed = if strong {
                    self.apply_transport_refresh(from)
                } else {
                    // N-5：引擎后弱凭据路径的首帧免限速仅在 --learn-peer
                    // 启用时保留；否则（如仅 --migrate 的发起方）一律限速，
                    // 74B 伪造 Init 无法在生命周期内免费抢占一次入口。
                    self.maybe_learn_unauthenticated(from, learned, self.learn)
                        .is_some()
                };
                if changed {
                    let kind = if strong {
                        "对端漫游（AEAD 认证帧）"
                    } else {
                        "漫游现学（限速，未认证帧）"
                    };
                    println!("[migration] {kind}：隧道入口 → {from}");
                }
            }
            // 握手响应帧 → 直接回 UDP
            if let Some(frame) = resp {
                let dest = match self.sched.lock().expect("sched").transport {
                    Transport::Tunnel(d) | Transport::PlainUdp(d) => d,
                };
                let _ = self.udp.send_to(&frame, dest);
            }
            // 拆出的内层包 → 先过外部判决钩子（入站），再写回 TUN/回显。
            if let Some(mut tun_pkt) = delivered {
                // Phase 3：入站 MSS 钳制（仅 SYN-ACK），确保对端 MSS 也适配隧道。
                // mss_clamp 为显式最终值；None 时按 effective_mtu 自动换算（F-4）。
                if self.compat {
                    process_inbound(&mut tun_pkt, self.effective_mtu, self.mss_clamp);
                }
                let allow = self
                    .hook
                    .as_ref()
                    .map(|h| {
                        let v = h.evaluate(&PacketEvent {
                            direction: HookDirection::In,
                            packet: &tun_pkt,
                        });
                        if !v.delay.is_zero() {
                            std::thread::sleep(v.delay);
                        }
                        v.accepted()
                    })
                    .unwrap_or(true);
                if !allow {
                    return;
                }
                match &self.session {
                    Some(s) => {
                        match s.allocate_send_packet(tun_pkt.len() as u16) {
                            Ok(mut p) => {
                                p.bytes_mut().copy_from_slice(&tun_pkt);
                                s.send_packet(p);
                            }
                            Err(e) => tracing::warn!(error = %e, "[tun] allocate_send_packet"),
                        }
                    }
                    // --no-tun 应答方：把合成包原样密封回给来包地址。
                    // 用 seal_frames（多帧）：大载荷回显同样走分片路径。
                    None if !self.is_initiator => {
                        let backs = {
                            let mut g = self.engine.lock().expect("engine");
                            g.seal_frames(&tun_pkt).ok()
                        };
                        if let Some(frames) = backs {
                            for f in frames {
                                let _ = self.udp.send_to(&f, from);
                            }
                        }
                    }
                    // --no-tun 发起方：校验回显结构（magic + 长度 + 填充）。
                    None => {
                        let good = tun_pkt.len() >= 9
                            && &tun_pkt[..5] == b"IP8NT"
                            && tun_pkt[9..].iter().all(|&b| b == 0xA5);
                        if good {
                            let k = self.echo_ok.fetch_add(1, Ordering::Relaxed) + 1;
                            println!("[no-tun] ECHO_OK #{k} ({}B byte-exact)", tun_pkt.len());
                        } else {
                            self.echo_bad.fetch_add(1, Ordering::Relaxed);
                            println!("[no-tun] ECHO_BAD ({}B)", tun_pkt.len());
                        }
                    }
                }
            }
        }

        /// 处理一批 TUN 出站 IP 包：外部判决（出站）→ 批级 transport 决策 →
        /// 持锁一次批量密封 → 锁外统一发 UDP（v9 §8 铁律：engine 锁外不碰网络）。
        /// transport 按批读取一次；Fallback 级联切换的生效延迟上界
        /// = 一个批次（≤64 包），对秒级降级决策无影响。
        fn dispatch_tun_batch(&self, mut batch: Vec<Vec<u8>>) {
            // ---- 外部判决钩子（出站：程序 → TUN → 隧道）----
            // 无钩子时 hook=None，本分支编译后零成本；有钩子时按包判决，
            // 流缓存命中的包在总线内部零 IPC。判决丢弃的包直接从批次移除。
            if let Some(h) = &self.hook {
                batch.retain(|bytes| {
                    let v = h.evaluate(&PacketEvent {
                        direction: HookDirection::Out,
                        packet: bytes,
                    });
                    if !v.delay.is_zero() {
                        std::thread::sleep(v.delay);
                    }
                    v.accepted()
                });
                if batch.is_empty() {
                    return;
                }
            }

            // ---- Phase 3 兼容性处理（出站）----
            // TTL 扣减 / DF 大包 ICMP / MSS 钳制。--compat 关闭时零开销。
            if self.compat {
                // PMTU 阈值恒为 effective_mtu；mss_clamp 是最终 MSS 值（不再扣减），
                // 二者互不污染（F-4）。
                // TUN 当前只配置 IPv4 地址，故 v6 传 None：v6 差错不生成、
                // 包直接丢弃（绝不从 :: 发非法 ICMPv6，F-2）。
                // 未来给 TUN 配置 v6 地址后，把 Some(addr) 传入即可启用。
                batch.retain_mut(|bytes| {
                    match process_outbound(
                        bytes,
                        self.effective_mtu,
                        self.mss_clamp,
                        self.tun_ip,
                        None,
                    ) {
                        CompatOutcome::Forward => true,
                        CompatOutcome::InjectIcmp(icmp) => {
                            self.inject_icmp(&icmp);
                            false
                        }
                        CompatOutcome::Drop => false,
                    }
                });
                if batch.is_empty() {
                    return;
                }
            }

            let transport = self.sched.lock().expect("sched").transport.clone();
            match transport {
                // 超 MTU 的内层包 → IPv8+ 分片为多帧，逐帧交 UDP（v9 §8/§7.8）
                Transport::Tunnel(dest) => {
                    // ADR-026：分片活跃 → 批投给 workers（同流同片，锁外并行
                    // 封装，帧经出口线程异步发出）；未活跃 → 原单点批量路径。
                    // （Phase 4：分片活跃期多路径复制/FEC 同步暂停——spec 决议）
                    let used_shards = {
                        let hb = self.hub.lock().expect("hub");
                        hb.seal(&batch)
                    };
                    if used_shards {
                        return;
                    }
                    // Phase 4 --mp：第二目的地（备用入口）。send 错误仅计数不阻断，
                    // 备用路径不可达不影响主路径（FR-1）
                    let mp_alt = self.mp_alt;
                    let mut out: Vec<Vec<u8>> = Vec::new();
                    {
                        let mut g = self.engine.lock().expect("engine");
                        for bytes in &batch {
                            // Phase 4 --fec：QoS 门控在密封前判一次（每包一次），
                            // 同一内层包密封出的全部分片继承标记（FR-4）
                            let marked =
                                self.fec.is_some() && inner_dscp(bytes).is_some_and(|d| d != 0);
                            match g.seal_frames(bytes) {
                                Ok(frames) => {
                                    if marked {
                                        if let Some(fec) = &self.fec {
                                            let mut tx = fec.tx.lock().expect("fec-tx");
                                            for frame in &frames {
                                                // 恢复帧头 KeyID 沿用成员帧头（当前密钥代）
                                                let mut kid = [0u8; 8];
                                                kid.copy_from_slice(&frame[2..10]);
                                                match tx.push(frame, kid) {
                                                    Ok(Some(rec)) => out.push(rec),
                                                    Ok(None) => {}
                                                    Err(e) => tracing::warn!(
                                                        error = %e,
                                                        "[fec] 入组失败（帧不入组）"
                                                    ),
                                                }
                                            }
                                        }
                                    }
                                    out.extend(frames);
                                }
                                Err(e) => tracing::warn!(error = %format!("{e:?}"), dropped = bytes.len(), "[tun→wire] 未封装，丢弃"),
                            }
                        }
                    } // 先还 engine 锁，再碰网络
                    for frame in &out {
                        if let Err(e) = self.udp.send_to(frame, dest) {
                            tracing::warn!(error = %e, "[udp] send 失败");
                        }
                        if let Some(alt) = mp_alt {
                            if let Err(e) = self.udp.send_to(frame, alt) {
                                tracing::warn!(error = %e, target = %alt, "[udp] 备用路径 send 失败");
                            }
                        }
                    }
                }
                // 明文级：内层 IP 包原样直发（v9 §11 末两级）
                Transport::PlainUdp(dest) => {
                    let mut sent = 0u64;
                    for bytes in &batch {
                        if self.udp.send_to(bytes, dest).is_ok() {
                            sent += 1;
                        }
                    }
                    if sent > 0 {
                        self.sched.lock().expect("sched").plain_tx += sent;
                    }
                }
            }
        }
    }

    let plane = Arc::new(Plane {
        engine: engine.clone(),
        udp: udp.clone(),
        session: session.clone(),
        sched: sched.clone(),
        hub: hub.clone(),
        hook: hook_bus.clone(),
        plain_demux: cfg.fallback,
        // punch 应答方自动现学：发起方的 Init 会从"服务端所见本端映射"
        // 到达——与配置的占位 --peer-ip 不同源，不现学则握手响应回错地址
        // （learn-peer 的既有语义正为此设计）。
        learn: cfg.learn_peer || (cfg.punch && !cfg.initiate),
        is_initiator: cfg.initiate,
        echo_ok: echo_ok.clone(),
        echo_bad: echo_bad.clone(),
        compat: cfg.compat,
        effective_mtu: cfg.mtu.saturating_sub(40),
        tun_ip: cfg.tun_ip,
        mss_clamp: cfg.mss_clamp,
        migrate: cfg.migrate,
        mp_alt: if cfg.mp {
            Some(cfg.alt.expect("parse 已校验 --mp 必配 alt").into())
        } else {
            None
        },
        fec: if cfg.fec {
            Some(Arc::new(FecNode {
                tx: Mutex::new(
                    FecTx::new(cfg.fec_k).expect("fec_k 已在 parse 校验 2..=16"),
                ),
                rx: Mutex::new(FecRx::new(ipv8_fec::DEFAULT_RX_CACHE)),
            }))
        } else {
            None
        },
    });

    /// 单批 TUN 排空上界：wintun 官方 C API 只有单包 Receive/Send，
    /// 真正省的是每包一次 engine/sched 互斥锁与逐包 send 的调用开销。
    const TUN_BATCH_CAP: usize = 64;

    // --no-tun 发起方：Established 后周期注入合成包（两种 I/O 模式都保留；
    // 该线程只发不收）。载荷 = magic(5) ‖ seq(4) ‖ 填充(0xA5…)；
    // 应答方逐字节回显，本端结构校验。
    if session.is_none() && cfg.initiate {
        let engine = engine.clone();
        let sock = udp.clone();
        let size = cfg.nt_size.max(16);
        let peer_for_inject = peer;
        std::thread::spawn(move || {
            let mut seq = 0u32;
            let mut next_send = std::time::Instant::now();
            loop {
                std::thread::sleep(Duration::from_millis(200));
                let established = {
                    let g = engine.lock().expect("engine");
                    g.stats().state == State::Established
                };
                if !established || std::time::Instant::now() < next_send {
                    continue;
                }
                next_send = std::time::Instant::now() + Duration::from_secs(5);
                let mut payload = b"IP8NT".to_vec();
                payload.extend_from_slice(&seq.to_be_bytes());
                payload.resize(size, 0xA5);
                seq = seq.wrapping_add(1);
                match engine.lock().expect("engine").seal_frames(&payload) {
                    Ok(frames) => {
                        for f in frames {
                            if let Err(e) = sock.send_to(&f, peer_for_inject) {
                                tracing::warn!(error = %e, "[no-tun] send 失败");
                            }
                        }
                    }
                    Err(e) => tracing::warn!(error = %format!("{e:?}"), "[no-tun] 注入密封失败"),
                }
            }
        });
    }

    if let Some(rt) = udp.as_rio() {
        // ---- RIO 极速数据面：单一事件循环替换 std 模式的 TUN 收线程 + UDP 收线程 ----
        // 唤醒模型（空闲零烧 CPU，有包亚微秒接力）：
        //   排空一轮 TUN ring + RIO CQ → 任一侧有活则忙轮询（自适应），
        //   连续两轮全空才 arm_notify + WaitForMultipleObjects(CQ 事件, TUN 事件)。
        // RIO 收割唯一消费者铁律：CQ 的 dequeue/repost 只在此线程发生；
        // 其他线程（打洞/握手/注入/shard 出口）只调用 RIOSend。
        let rt = rt.clone();
        let plane = plane.clone();
        let rio_session = session.clone();
        std::thread::spawn(move || {
            // wintun 读等待事件：ring 非空 signaled，排空后自动 unsignal。
            // 取失败不致命：降级为本线程只跑 UDP 侧（--no-tun 本就 None）。
            let tun_event = match &rio_session {
                Some(s) => match s.get_read_wait_event() {
                    Ok(h) => Some(h),
                    Err(e) => {
                        tracing::warn!(error = %e, "[rio] 取不到 TUN 等待事件，仅跑 UDP 侧");
                        None
                    }
                },
                None => None,
            };
            let mut learned = false;
            let mut packets: Vec<RioPacket> = Vec::with_capacity(64);

            // 单轮排空：TUN 侧非阻塞收一批 + RIO CQ 收割入站帧。
            // 返回 (本轮是否干过活, 是否发生致命错)。致命错包括
            // TUN 坏 / CQ 损坏 / repost 失败——外层据此结束循环。
            let mut drain = |packets: &mut Vec<RioPacket>| -> (bool, bool) {
                let mut worked = false;
                let mut fatal = false;
                if let Some(s) = &rio_session {
                    let mut batch: Vec<Vec<u8>> = Vec::new();
                    // 事件循环里不做阻塞首包等待——首包由 wintun 事件唤醒，
                    // 进来直接非阻塞排空即可。
                    while batch.len() < TUN_BATCH_CAP {
                        match s.try_receive() {
                            Ok(Some(pkt)) => {
                                batch.push(pkt.bytes().to_vec()); // ★ 拷贝出 ring
                                drop(pkt); // ★ 立即归还（v9 §8 铁律）
                            }
                            Ok(None) => break,
                            Err(e) => {
                                tracing::warn!(error = %e, "[tun] try_receive 结束");
                                fatal = true;
                                break;
                            }
                        }
                    }
                    if !batch.is_empty() {
                        worked = true;
                        plane.dispatch_tun_batch(batch);
                    }
                }
                packets.clear();
                if let Err(e) = rt.dequeue(packets) {
                    tracing::warn!(error = %e, "[rio] CQ 收割失败，事件循环退出");
                    return (worked, true);
                }
                if !packets.is_empty() {
                    worked = true;
                }
                // 入站处理：packet_data 是注册缓冲内的零拷贝借用。
                for pkt in packets.iter() {
                    let raw = rt.packet_data(pkt);
                    plane.handle_inbound(raw, pkt.from, &mut learned);
                }
                // 全部处理完统一归还接收槽（立即重新投递，保持 RQ 常满）。
                for pkt in packets.iter() {
                    if let Err(e) = rt.repost_recv(pkt.slot) {
                        tracing::warn!(error = %e, slot = pkt.slot, "[rio] 接收槽重投失败，事件循环退出");
                        fatal = true;
                        break;
                    }
                }
                (worked, fatal)
            };

            'event_loop: loop {
                let (worked, fatal) = drain(&mut packets);
                if fatal {
                    break 'event_loop;
                }
                if worked {
                    // 自适应忙轮询：连续两轮两侧全空才去阻塞。
                    // dequeue/try_receive 都是用户态 ring 读取，空排空成本极低，
                    // 换来突发期间 0 系统调用、0 唤醒延迟的接力。
                    let mut idle_rounds = 0u32;
                    'spin: loop {
                        let (w, fatal) = drain(&mut packets);
                        if fatal {
                            break 'event_loop;
                        }
                        if w {
                            idle_rounds = 0;
                        } else {
                            idle_rounds += 1;
                            if idle_rounds >= 2 {
                                break 'spin;
                            }
                        }
                    }
                }
                // 先武装通知再等（RIO 契约）；武装与等待之间到达的完成也会
                // 触发事件信号，不会漏醒；wintun 事件同理（非空即 signaled）。
                if let Err(e) = rt.arm_notify() {
                    tracing::warn!(error = %e, "[rio] RIONotify 失败，事件循环退出");
                    break 'event_loop;
                }
                if let Err(e) = rt.wait_io(tun_event) {
                    tracing::warn!(error = %e, "[rio] 事件等待结束");
                    break 'event_loop;
                }
            }
            eprintln!("[rio] 事件循环已退出（数据面停止：进程仍在但不再收发隧道数据）");
        });
    } else if let Some(l2) = udp.as_l2() {
        // ---- Phase 8 L2 数据面：ipv8proto.sys 0xFB14 裸帧 ----
        // 收线程走 L2Io::recv()，塞占位 SocketAddr 给 Plane；
        // 发送路径完全复用（UdpIo::send_to 在 L2 分支已走 send_to_mac）。
        let plane = plane.clone();
        let l2 = l2.clone();
        std::thread::spawn(move || {
            let mut learned = false;
            loop {
                match l2.recv() {
                    Ok((payload, src_mac)) => {
                        let from = SocketAddr::from(([0, 0, 0, 0], 0));
                        plane.handle_inbound(&payload, from, &mut learned);
                        // 首次收到帧时，把对端 MAC 记住，后续直接单播
                        if l2.peer_mac().is_none() {
                            l2.set_peer_mac(src_mac);
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "[l2] recv 重试中…");
                        // L2 收阻塞，微秒级重试
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
            }
        });
    } else {
        // ---- std 数据面（--rio off，或 auto 探测失败回退）：行为与 Phase 1 一字不差 ----

        // TUN 读线程（v9 §8 铁律：独立 std::thread + 拷贝即 drop）：
        // 阻塞等到第一包后，非阻塞排空环形缓冲，组批交 Plane 统一处理。
        if let Some(session) = plane.session.clone() {
            let plane = plane.clone();
            std::thread::spawn(move || loop {
                let mut batch: Vec<Vec<u8>> = Vec::new();
                match session.receive_blocking() {
                    Ok(pkt) => {
                        batch.push(pkt.bytes().to_vec()); // ★ 拷贝出环形缓冲区
                        drop(pkt); // ★ 立即归还
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "[tun] receive 结束");
                        break;
                    }
                }
                while batch.len() < TUN_BATCH_CAP {
                    match session.try_receive() {
                        Ok(Some(pkt)) => {
                            batch.push(pkt.bytes().to_vec());
                            drop(pkt);
                        }
                        Ok(None) => break, // 环空：交还阻塞等待
                        Err(e) => {
                            tracing::warn!(error = %e, "[tun] try_receive 结束");
                            return;
                        }
                    }
                }
                plane.dispatch_tun_batch(batch);
            });
        }

        // UDP 收线程：recv_from 阻塞取包，交 Plane 统一拆壳/写回 TUN。
        let sock = udp
            .as_std()
            .expect("进入 std 分支即证明 UdpIo::Std")
            .clone();
        let plane = plane.clone();
        std::thread::spawn(move || {
            let mut buf = vec![0u8; 65507]; // 单个 UDP 载荷上限
            let mut learned = false;
            loop {
                match sock.recv_from(&mut buf) {
                    Ok((n, from)) => plane.handle_inbound(&buf[..n], from, &mut learned),
                    Err(ref e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::Interrupted
                                | io::ErrorKind::ConnectionReset
                                | io::ErrorKind::ConnectionRefused
                        ) =>
                    {
                        // Windows 特有：对未绑定端口发包后收 ICMP 不可达，
                        // 会武装套接字错误让下一次 recv 报 10054（ConnectionReset）。
                        // 这是瞬态错误，继续收包，绝不退出线程。
                        continue;
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "[udp] recv 结束");
                        break;
                    }
                }
            }
        });
    }

    // ---- 主任务：Fallback 调度 + Established 后周期打印统计，Ctrl+C 退出 ----
    let mut ticker = tokio::time::interval(Duration::from_secs(2));
    // Phase 3：连接迁移检测（5s 一次；临时 socket 探测，开销可忽略）
    let mut migrator = tokio::time::interval(Duration::from_secs(5));
    let mut last_local: Option<IpAddr> = None;
    let mut established_reported = false;
    loop {
        tokio::select! {
            // Phase 3 连接迁移：本机出口 IP 变化 → 探测撞活新路径，
            // 对端（--learn-peer/--migrate）从探测包现学新源地址；
            // 未建隧道时 Init 的 2s 重发自然沿新路径继续，无需重置状态机。
            _ = migrator.tick(), if cfg.migrate => {
                let dest = match sched.lock().expect("sched").transport.clone() {
                    Transport::Tunnel(d) => d,
                    Transport::PlainUdp(d) => d,
                };
                if let Some(cur) = detect_local_addr(dest) {
                    if let Some(prev) = last_local {
                        if prev != cur {
                            println!("[migration] 本机出口变化: {prev} → {cur}，发送漫游探测（隧道状态保持）");
                            // 连发探测包：撞活新路径上的 NAT 映射并让对端现学。
                            for _ in 0..3 {
                                let _ = udp.send_to(PUNCH_KNOCK, dest);
                            }
                        }
                    }
                    last_local = Some(cur);
                }
            }
            _ = ticker.tick() => {
                let now = now_epoch_secs();
                let (st, eng_sharded) = {
                    let g = engine.lock().expect("engine");
                    (g.stats(), g.is_sharded())
                };

                // ---- ADR-026 分片生命周期（必须取 sched 锁之前处理：退役
                // join worker 时，分片出口线程可能正持 sched 发包）----
                if cfg.shards > 1 && has_tun {
                    let hb_active = hub.lock().expect("hub").active() > 0;
                    if hb_active && !eng_sharded {
                        // 隧道已重协商（引擎换密钥并解冻）→ 旧分片作废退役
                        let old = hub.lock().expect("hub").retire();
                        if let Some(s) = old {
                            println!("[shards] 隧道重协商 → 旧 {} 分片退役（下 tick 按新密钥重组）", s.len());
                            s.shutdown();
                        }
                    } else if st.state == State::Established && !hb_active && !eng_sharded {
                        if let Ok((shards, la, pa, mtu)) =
                            engine.lock().expect("engine").split_shards(cfg.shards)
                        {
                            let (sock2, sched2) = (udp.clone(), sched.clone());
                            let frames: ShardSink = Arc::new(move |f: Vec<u8>| {
                                let dest = match sched2.lock().expect("sched").transport {
                                    Transport::Tunnel(d) | Transport::PlainUdp(d) => d,
                                };
                                if let Err(e) = sock2.send_to(&f, dest) {
                                    tracing::warn!(error = %e, "[shard→udp] send 失败");
                                }
                            });
                            let session2 = session.clone();
                            let delivered: ShardSink = Arc::new(move |pkt: Vec<u8>| {
                                let Some(sess) = &session2 else { return };
                                match sess.allocate_send_packet(pkt.len() as u16) {
                                    Ok(mut p) => {
                                        p.bytes_mut().copy_from_slice(&pkt);
                                        sess.send_packet(p);
                                    }
                                    Err(e) => tracing::warn!(error = %e, "[shard→tun] allocate_send_packet"),
                                }
                            });
                            let sh = FlowShards::new(shards, la, pa, mtu, frames, delivered);
                            println!(
                                "[shards] ADR-026 流级分片启用: {} workers（同流同片；两端 --shards 必须一致）",
                                sh.len()
                            );
                            hub.lock().expect("hub").install(sh);
                        }
                    }
                }

                let mut sc = sched.lock().expect("sched");
                let fb_on = cfg.fallback;

                if st.state == State::Established {
                    // 统计口径：分片活跃时用聚合计数（单点引擎数据面已冻结）
                    let (sealed, deliv, dropped, f_sent, f_re, nsh) = {
                        let hb = hub.lock().expect("hub");
                        match hb.active() {
                            0 => (
                                st.sealed_outbound,
                                st.delivered_inbound,
                                st.dropped_inbound,
                                st.fragments_sent,
                                st.fragments_reassembled,
                                0usize,
                            ),
                            _ => {
                                let s = hb.stats();
                                (
                                    s.sealed,
                                    s.delivered,
                                    s.dropped,
                                    s.fragments_sent,
                                    s.fragments_reassembled,
                                    hb.active(),
                                )
                            }
                        }
                    };
                    // 锁内只做簿记与快照，stdout 打印全部移到锁外——
                    // stdout 可能阻塞（管道/控制台），持锁打印会拖慢并发的
                    // 收发路径对 sched 锁的竞争（R3 指出，2s 一拍冷路径）。
                    let (plain_tx, plain_rx, first_pkt_timeout) = {
                        // 隧道成功：记一次（清降级缓存、备用入口提正、记 last_good）
                        if fb_on && !sc.success_recorded {
                            let cur = sc.current.clone();
                            sc.fb.record_success(PEER_KEY, &cur);
                            // 数据面必须锁到**实际握手成功**的入口：级联场景下
                            // current/transport 还停在降级前的决策，不锁会往死端口发数据
                            if let Some((_, _, dest)) = sc.attempt.take() {
                                sc.transport = Transport::Tunnel(dest);
                            }
                            sc.success_recorded = true;
                            sc.est_started = Some(now);
                            sc.est_delivered = deliv;
                        }
                        // 首包超时判定（v9 §11：隧道已建但数据不通 → 不浪费重试，
                        // 直接降级）：已发包但超时窗口内 delivered 无增长 → 重置。
                        // （record_success 刚发生时 est_delivered==deliv，恒不触发）
                        let timeout_secs = sc.fb.first_packet_timeout().as_secs();
                        let timed_out = fb_on
                            && sealed > 0
                            && deliv == sc.est_delivered
                            && sc
                                .est_started
                                .is_some_and(|t0| now.saturating_sub(t0) >= timeout_secs);
                        if timed_out {
                            sc.fb.record_failure(PEER_KEY, Failure::FirstPacketTimeout, now);
                            sc.success_recorded = false;
                            sc.est_started = None;
                        }
                        (sc.plain_tx, sc.plain_rx, timed_out)
                    };
                    drop(sc); // 锁序：engine 与 sched 不同时持有；打印期间不持锁
                    if !established_reported {
                        println!(
                            "[ipv8-node] ✅ 隧道 Established（epoch={}）。等待内层 IP 流量进隧道（ping 目标见验证脚本）。",
                            st.send_epoch.unwrap_or(0)
                        );
                        established_reported = true;
                    } else {
                        println!(
                            "[stats] epoch={} sealed={} delivered={} dropped={} frags_sent={} frags_reassembled={} plain_tx={} plain_rx={} echo_ok={} echo_bad={} shards={}",
                            st.send_epoch.unwrap_or(0),
                            sealed,
                            deliv,
                            dropped,
                            f_sent,
                            f_re,
                            plain_tx,
                            plain_rx,
                            echo_ok.load(Ordering::Relaxed),
                            echo_bad.load(Ordering::Relaxed),
                            nsh
                        );
                    }
                    if let Some(h) = &hook_bus {
                        let s = h.stats_snapshot();
                        println!(
                            "[hook] seen={} decided={} cached={} fallback={} accepted={} dropped={}",
                            s["seen"], s["decided"], s["cached"], s["fallback"], s["accepted"], s["dropped"]
                        );
                    }
                    if first_pkt_timeout {
                        println!("[fallback] 首包超时（隧道半开）→ reset + record_failure，走表降级");
                        engine.lock().expect("engine").reset();
                    }
                    continue;
                }
                established_reported = false;

                if !fb_on {
                    // ---- Phase 1 行为（无 fallback）：Init 每 tick 幂等重发 ----
                    if st.state == State::Initiating {
                        if let Some((f, _, dest)) = &sc.attempt {
                            let _ = udp.send_to(f, *dest);
                        }
                    }
                    continue;
                }

                // ---- Fallback 驱动 ----
                match st.state {
                    State::Idle => {
                        if !cfg.initiate {
                            continue; // 被动方永远等对端 Init，无发起预算
                        }
                        // 每次重开尝试都要换全新临时密钥：abandon 保证从 Idle 起步
                        let path = sc.fb.next_path(PEER_KEY, now);
                        sc.current = path.clone();
                        sc.success_recorded = false;
                        sc.est_started = None;
                        let dest = match &path {
                            FallbackPath::Tunnel { entry } => entry_addr(entry, sc.main),
                            FallbackPath::PlainTcp | FallbackPath::PlainUdp => sc.main,
                        };
                        sc.transport = match &path {
                            FallbackPath::Tunnel { .. } => Transport::Tunnel(dest),
                            _ => Transport::PlainUdp(dest),
                        };
                        match &path {
                            FallbackPath::Tunnel { entry } => {
                                let f = {
                                    drop(sc); // engine 锁与 sched 锁不同时持有
                                    let mut g = engine.lock().expect("engine");
                                    g.abandon_handshake();
                                    if cfg.auth { g.start_auth_handshake() } else { g.start_handshake() }
                                };
                                sc = sched.lock().expect("sched");
                                let to = sc.fb.handshake_timeout(PEER_KEY);
                                println!("[fallback] 隧道尝试 entry={entry} → {dest}（超时 {}s）", to.as_secs());
                                let _ = udp.send_to(&f, dest);
                                sc.attempt = Some((f, now, dest));
                            }
                            plain => {
                                if !sc.plain_reported {
                                    println!("[fallback] 隧道入口全部失败 → 降级 {plain:?}（明文；降级缓存到期后自动回试隧道）");
                                    sc.plain_reported = true;
                                }
                            }
                        }
                    }
                    State::Initiating | State::Responding => {
                        if let Some((f, started, dest)) = sc.attempt.clone() {
                            let to = sc.fb.handshake_timeout(PEER_KEY);
                            if now.saturating_sub(started) >= to.as_secs() {
                                let lvl = sc.fb.level_of(PEER_KEY);
                                sc.fb.record_failure(PEER_KEY, Failure::HandshakeTimeout, now);
                                println!("[fallback] entry 握手超时（{to:?}）→ record_failure，级别 {lvl:?}→{:?}",
                                    sc.fb.level_of(PEER_KEY).unwrap_or(lvl.unwrap_or(Level::MainTunnel)));
                                drop(sc);
                                engine.lock().expect("engine").abandon_handshake();
                                sc = sched.lock().expect("sched");
                                sc.attempt = None;
                            } else {
                                let _ = udp.send_to(&f, dest); // 预算内重发同一 Init（幂等）
                            }
                        }
                    }
                    State::Established => {} // 上方已处理
                }
            }
            _ = tokio::signal::ctrl_c() => {
                println!("\n[ipv8-node] 收到 Ctrl+C，退出（TUN 网卡保留，重启即复用）");
                break;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(n: u32) -> IPv8Address {
        IPv8Address::with_region(n as u64, 1, 0, 0x0100, 0)
    }

    fn cache_file(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("ipv8-certcache-test-{name}.bin"));
        p
    }

    fn write_cache(path: &Path, ca_pub: [u8; 32], cert: &Cert) {
        let mut raw = Vec::new();
        raw.extend_from_slice(CACHE_MAGIC);
        raw.push(CACHE_VERSION);
        raw.extend_from_slice(&ca_pub);
        raw.extend_from_slice(&cert_to_bytes(cert));
        std::fs::write(path, raw).unwrap();
    }

    #[test]
    fn cert_bytes_roundtrip() {
        let ca = CertAuthority::from_seed([0xC4u8; 32]);
        let cert = ca.issue(addr(7), [0xAB; 32], 1234567890);
        let back = cert_from_bytes(&cert_to_bytes(&cert)).expect("往返必须成功");
        assert_eq!(back, cert);
    }

    #[test]
    fn cache_hit_then_tamper_miss() {
        let ca = CertAuthority::from_seed([0xC4u8; 32]);
        let seed = [0xA1u8; 32];
        let vk = verify_key_from_seed(seed);
        let cert = ca.issue(addr(7), vk, 5_000);
        let path = cache_file("hit");
        write_cache(&path, ca.public_key(), &cert);

        // 命中：签名有效 + 未过期 + 主体匹配
        let (host, _trust) = load_cert_cache(&path, addr(7), seed, 4_999).expect("应命中");
        assert_eq!(host.cert, cert);
        // 过期 → 未命中
        assert!(load_cert_cache(&path, addr(7), seed, 5_001).is_none());
        // 篡改签名 → 未命中
        let mut raw = std::fs::read(&path).unwrap();
        let n = raw.len();
        raw[n - 1] ^= 0x01;
        std::fs::write(&path, &raw).unwrap();
        assert!(load_cert_cache(&path, addr(7), seed, 4_999).is_none());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn cache_identity_mismatch_rejected() {
        let ca = CertAuthority::from_seed([0xC4u8; 32]);
        let seed = [0xA1u8; 32];
        let cert = ca.issue(addr(7), verify_key_from_seed(seed), 5_000);
        let path = cache_file("ident");
        write_cache(&path, ca.public_key(), &cert);

        // 换本机 ed-seed（公钥对不上证书）→ 作废
        assert!(load_cert_cache(&path, addr(7), [0xB2u8; 32], 4_999).is_none());
        // 换本机地址（拷错机器）→ 作废
        assert!(load_cert_cache(&path, addr(8), seed, 4_999).is_none());
        // 缓存被其他 CA 签发 → 验签失败
        let rogue = CertAuthority::from_seed([0x99u8; 32]);
        let forged = rogue.issue(addr(7), verify_key_from_seed(seed), 5_000);
        write_cache(&path, ca.public_key(), &forged); // 锚仍写真 CA → 签名对不上
        assert!(load_cert_cache(&path, addr(7), seed, 4_999).is_none());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn migration_addr_detection_stable_for_same_target() {
        // 向本机回环地址探测：两次结果必须一致（模拟"网络未切换"）
        let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 45799);
        let a = detect_local_addr(target).expect("回环探测应成功");
        let b = detect_local_addr(target).expect("回环探测应成功");
        assert_eq!(a, b, "同一目标的出口地址在无切换时必须稳定");
        assert!(a.is_loopback(), "回环目标的出口应为回环地址，实际 {a}");
    }

    #[test]
    fn migration_addr_detection_detects_change() {
        // 不同目标（回环 v4 vs 一个不可路由的 v4 段）应给出不同或至少能被
        // 比较的结果——核心验证探测函数在目标变化时不崩溃且返回 Some。
        let lo = detect_local_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 45799));
        assert!(lo.is_some());
        // 0.0.0.0 目标：connect 通常失败/无路由 → None 或 unspecified，函数必须安全
        let _ = detect_local_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 45799));
    }

    /// 构造隧道帧头：Ver=0x01, Type, 8B key_id
    fn tunnel_frame(ftype: u8) -> Vec<u8> {
        let mut f = vec![0x01, ftype];
        f.extend_from_slice(&[0u8; 8]);
        f
    }

    #[test]
    fn roam_credential_delivered_is_strong_even_for_garbage_frame() {
        // delivered 只可能来自 AEAD 解密成功，即使帧头异常也按强凭据对待
        // （实践中 garbage 帧不可能产生 delivered，此为防御性契约）
        assert!(is_strong_roam_credential(&[0xff, 0x00], false, true));
    }

    #[test]
    fn roam_credential_auth_init_resp_is_strong() {
        // AuthInit(type=4) 三验通过才有 resp → 强凭据
        let f = tunnel_frame(4);
        assert!(is_strong_roam_credential(&f, true, false));
    }

    #[test]
    fn roam_credential_plaintext_init_resp_is_weak() {
        // N-1 回归：明文 HandshakeInit(type=0) 的 resp 不认证发起方，
        // 74 字节即可伪造，必须判为弱凭据（走 10s 限速，不得免限速）
        let f = tunnel_frame(0);
        assert!(!is_strong_roam_credential(&f, true, false));
    }

    #[test]
    fn roam_credential_handshake_resp_frame_is_weak() {
        // HandshakeResp(type=1) 帧本身不会在本端产出 resp（返回 None）；
        // 即使误报 has_resp 也不得视为强凭据
        let f = tunnel_frame(1);
        assert!(!is_strong_roam_credential(&f, true, false));
        assert!(!is_strong_roam_credential(&f, false, false));
    }

    #[test]
    fn roam_credential_data_without_outcome_is_weak() {
        // Data(type=2) 未解密成功（无 delivered、无 resp）→ 无凭据
        let f = tunnel_frame(2);
        assert!(!is_strong_roam_credential(&f, false, false));
    }

    #[test]
    fn roam_credential_short_and_garbage_frames_are_weak() {
        assert!(!is_strong_roam_credential(&[], true, false));
        assert!(!is_strong_roam_credential(&[0x01], true, false));
        assert!(!is_strong_roam_credential(&[0x00, 0x04], true, false)); // Ver 错
    }

    // ---- Sched 迁移限速状态机（R3 N-2 补强：限速/一次性路径此前仅靠推理）----

    /// 构造一个隧道入口指向 `dest` 的最小 Sched（fb 仅参与簿记，测试不触发）
    fn roam_sched(dest: SocketAddr) -> Sched {
        Sched {
            fb: FallbackManager::new(FallbackOptions::default()),
            main: dest,
            alt: None,
            current: FallbackPath::Tunnel { entry: String::new() },
            transport: Transport::Tunnel(dest),
            attempt: None,
            success_recorded: false,
            plain_reported: false,
            est_started: None,
            est_delivered: 0,
            plain_tx: 0,
            plain_rx: 0,
            last_unauth_roam: None,
            mp: false,
        }
    }

    #[test]
    fn unauth_first_frame_learns_immediately_under_learn_peer() {
        // --learn-peer 引导语义：首帧现学免限速，入口/主入口/attempt 联动
        let a: SocketAddr = "10.0.0.1:100".parse().unwrap();
        let b: SocketAddr = "10.0.0.2:200".parse().unwrap();
        let mut sc = roam_sched(a);
        sc.attempt = Some((vec![1, 2], 5, a));
        let mut learned = false;
        let msg = sc.unauth_refresh(b, &mut learned, true).expect("首帧必须放行");
        assert!(msg.starts_with("[learn-peer]"), "实际 {msg}");
        assert_eq!(sc.transport, Transport::Tunnel(b));
        assert_eq!(sc.main, b);
        assert_eq!(sc.attempt.unwrap().2, b, "握手尝试目的地必须随入口联动");
        assert!(learned);
    }

    #[test]
    fn unauth_roam_rate_limited_within_window() {
        let a: SocketAddr = "10.0.0.1:100".parse().unwrap();
        let b: SocketAddr = "10.0.0.2:200".parse().unwrap();
        let mut sc = roam_sched(a);
        let mut learned = true;
        sc.last_unauth_roam = Some(std::time::Instant::now());
        assert!(
            sc.unauth_refresh(b, &mut learned, false).is_none(),
            "限速窗口内的漫游现学必须拒绝"
        );
        assert_eq!(sc.transport, Transport::Tunnel(a), "入口不得被改走");
        assert!(learned, "拒绝路径也要保持已学标志");
    }

    #[test]
    fn unauth_roam_allowed_after_window_with_reset() {
        let a: SocketAddr = "10.0.0.1:100".parse().unwrap();
        let b: SocketAddr = "10.0.0.2:200".parse().unwrap();
        let mut sc = roam_sched(a);
        let mut learned = true;
        sc.last_unauth_roam = Some(std::time::Instant::now() - ROAM_MIN_INTERVAL);
        let msg = sc.unauth_refresh(b, &mut learned, false).expect("窗口外必须放行");
        assert!(msg.starts_with("[migration]"), "实际 {msg}");
        assert_eq!(sc.transport, Transport::Tunnel(b));
        // 放行即重置窗口起点
        assert!(sc.last_unauth_roam.is_some());
    }

    #[test]
    fn unauth_no_first_frame_privilege_without_learn_peer() {
        // N-5 回归：仅 --migrate（无 --learn-peer）时，learned==false 也不享受
        // 首帧免限速——74B 伪造 Init 在窗口内无法免费抢占一次入口
        let a: SocketAddr = "10.0.0.1:100".parse().unwrap();
        let b: SocketAddr = "10.0.0.2:200".parse().unwrap();
        let mut sc = roam_sched(a);
        sc.last_unauth_roam = Some(std::time::Instant::now());
        let mut learned = false;
        assert!(sc.unauth_refresh(b, &mut learned, false).is_none());
        assert_eq!(sc.transport, Transport::Tunnel(a));
        // 窗口外放行，但走的是限速文案而非 learn-peer 文案
        sc.last_unauth_roam = Some(std::time::Instant::now() - ROAM_MIN_INTERVAL);
        let msg = sc.unauth_refresh(b, &mut learned, false).expect("窗口外放行");
        assert!(msg.starts_with("[migration]"), "不得冒充 learn-peer 引导：{msg}");
    }

    #[test]
    fn unauth_same_address_no_op_marks_learned() {
        let a: SocketAddr = "10.0.0.1:100".parse().unwrap();
        let mut sc = roam_sched(a);
        let mut learned = false;
        assert!(sc.unauth_refresh(a, &mut learned, true).is_none());
        assert!(learned, "同址空转也要置已学，避免反复判定");
    }

    // ---- Phase 4：QoS 门控 + 多路径入口集合（AC-5 / TR-3.1 门控侧）----

    /// TR-5.1 基础 argv（--dll 占位避免测试环境找 wintun.dll）
    fn p4_argv(extra: &[&str]) -> Vec<String> {
        let mut v: Vec<String> = [
            "--self",
            "fb140000000000010001000000010000",
            "--peer-addr",
            "fb140000000000010001000000020000",
            "--peer-ip",
            "192.168.1.12",
            "--dll",
            "(test)",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        v.extend(extra.iter().map(|s| s.to_string()));
        v
    }

    #[test]
    fn p4_parse_defaults_off() {
        let c = parse_args_from(&p4_argv(&[])).expect("最小参数必须可解析");
        assert!(!c.mp && !c.fec);
        assert_eq!(c.fec_k, 4, "默认组大小 4");
    }

    #[test]
    fn p4_parse_mp_requires_alt() {
        assert!(parse_args_from(&p4_argv(&["--mp"])).is_err());
        // 配齐 alt 即可
        let c = parse_args_from(&p4_argv(&[
            "--mp",
            "--alt-ip",
            "192.168.1.13",
            "--alt-port",
            "45701",
        ]))
        .expect("mp+alt 合法");
        assert!(c.mp);
    }

    #[test]
    fn p4_parse_mp_fallback_mutex() {
        assert!(parse_args_from(&p4_argv(&[
            "--mp",
            "--fallback",
            "--alt-ip",
            "192.168.1.13",
            "--alt-port",
            "45701",
        ]))
        .is_err());
    }

    #[test]
    fn p4_parse_fec_k_bounds() {
        assert!(parse_args_from(&p4_argv(&["--fec", "--fec-k", "1"])).is_err());
        assert!(parse_args_from(&p4_argv(&["--fec", "--fec-k", "17"])).is_err());
        assert!(parse_args_from(&p4_argv(&["--fec", "--fec-k", "abc"])).is_err());
        assert!(parse_args_from(&p4_argv(&["--fec", "--fec-k", "16"]))
            .expect("上界合法")
            .fec_k
            == 16);
        assert!(parse_args_from(&p4_argv(&["--fec", "--fec-k", "2"]))
            .expect("下界合法")
            .fec_k
            == 2);
    }

    #[test]
    fn inner_dscp_v4_v6_and_garbage() {
        // IPv4：EF = 46 → byte[1] = 46<<2 = 184；DSCP=0 → byte[1] 低 2 位任意
        assert_eq!(inner_dscp(&[0x45, 184]), Some(46));
        assert_eq!(inner_dscp(&[0x45, 0x03]), Some(0), "低 2 位 ECN 不算 DSCP");
        // IPv6：TC 8 位跨字节——byte0 低 4b=TC[7..4]，byte1 高 2b=TC[3..2]。
        // EF=46=0b101110 → byte0=0x6|0xB=0x6B，byte1=0b10<<6|FL=0x80
        assert_eq!(inner_dscp(&[0x6B, 0x80]), Some(46));
        assert_eq!(inner_dscp(&[0x60, 0x00]), Some(0));
        // 畸形：短包 / 非 IP 版本
        assert_eq!(inner_dscp(&[0x45]), None);
        assert_eq!(inner_dscp(&[]), None);
        assert_eq!(inner_dscp(&[0x30, 0x00]), None);
    }

    /// AC-5：--mp 开时两路径交替到达不触发入口刷新（transport 稳定）
    #[test]
    fn mp_entry_set_blocks_flip_flop() {
        let main: SocketAddr = "10.0.0.1:100".parse().unwrap();
        let alt: SocketAddr = "10.0.0.2:200".parse().unwrap();
        let mut sc = roam_sched(main);
        sc.mp = true;
        sc.alt = Some(alt);
        // 强凭据从 alt 到达：from ∈ 集合 → 不刷新
        assert!(!sc.strong_refresh(alt));
        assert_eq!(sc.transport, Transport::Tunnel(main));
        let mut learned = true;
        assert!(sc.unauth_refresh(alt, &mut learned, false).is_none());
        assert_eq!(sc.transport, Transport::Tunnel(main));
        // main ↔ alt 交替多轮，transport 恒定
        for _ in 0..3 {
            assert!(!sc.strong_refresh(alt) && !sc.strong_refresh(main));
        }
        assert_eq!(sc.transport, Transport::Tunnel(main));
        // 真网络切换（新地址 ∉ {main, alt}）→ 照常刷新（Phase 3 两级凭据仍工作）
        let roam: SocketAddr = "10.0.0.3:300".parse().unwrap();
        assert!(sc.strong_refresh(roam), "集合外地址必须触发迁移");
        assert_eq!(sc.transport, Transport::Tunnel(roam));
    }

    /// TR-4.2 对照：--mp 关闭时刷新行为与 Phase 3 逐字节一致
    #[test]
    fn mp_off_keeps_phase3_behavior() {
        let main: SocketAddr = "10.0.0.1:100".parse().unwrap();
        let alt: SocketAddr = "10.0.0.2:200".parse().unwrap();
        let mut sc = roam_sched(main);
        sc.alt = Some(alt); // fallback 场景 alt 已配置但 mp 关
        // mp 关：in_entry_set 恒 false → dest != from 即刷新（与 Phase 3 一致）
        assert!(sc.strong_refresh(alt));
        assert_eq!(sc.transport, Transport::Tunnel(alt));
    }

    #[test]
    fn strong_refresh_unlimited_and_resets_weak_window() {
        // N-6 回归：强凭据纠正免限速，且成功后重置弱凭据限速窗
        let a: SocketAddr = "10.0.0.1:100".parse().unwrap();
        let b: SocketAddr = "10.0.0.2:200".parse().unwrap();
        let c: SocketAddr = "10.0.0.3:300".parse().unwrap();
        let mut sc = roam_sched(a);
        sc.last_unauth_roam = Some(std::time::Instant::now());
        assert!(sc.strong_refresh(b), "强凭据刷新不受弱凭据限速窗约束");
        assert_eq!(sc.transport, Transport::Tunnel(b));
        // 刚被强凭据纠正，窗口内伪造弱帧不得再改址（防振荡）
        let mut learned = true;
        assert!(sc.unauth_refresh(c, &mut learned, false).is_none());
    }

    #[test]
    fn strong_refresh_no_change_is_pure_noop() {
        let a: SocketAddr = "10.0.0.1:100".parse().unwrap();
        let mut sc = roam_sched(a);
        assert!(!sc.strong_refresh(a), "同址刷新必须返回 false");
        assert!(sc.last_unauth_roam.is_none(), "空转不得重置弱凭据限速窗");
    }

    #[test]
    fn plain_udp_transport_always_treated_as_needing_update() {
        // 明文降级路径无「隧道入口」概念：任意来源都视为待更新（走限速）
        let a: SocketAddr = "10.0.0.1:100".parse().unwrap();
        let mut sc = roam_sched(a);
        sc.transport = Transport::PlainUdp(a);
        let mut learned = true;
        let msg = sc.unauth_refresh(a, &mut learned, false).expect("必须放行");
        assert!(msg.starts_with("[migration]"));
        assert_eq!(sc.transport, Transport::Tunnel(a), "放行即转回隧道模式");
    }
}