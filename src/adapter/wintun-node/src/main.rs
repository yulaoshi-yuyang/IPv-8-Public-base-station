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

use std::error::Error;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ipv8_codec::IPv8Address;
use ipv8_tunnel::auth::{
    pop_sign, provision, register_pop_message, verify_key_from_seed, Cert, CertAuthority,
    HostIdentity, TrustAnchor, NO_EXPIRY,
};
use ipv8_tunnel::{
    Engine, FallbackManager, FallbackOptions, Failure, FlowShards, Identity, Level,
    Path as FallbackPath, Resolved, ShardSink, ShardStats, State,
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
    /// ADR-026 性能线：Data 面流级分片 worker 数（--shards N，默认 1 = 单点
    /// 零回归）。Established 后自动拆分，同流同 worker 保 nonce 唯一。
    /// 仅真实 TUN 路径生效；--no-tun 回显验证件恒用单点引擎。
    /// 两端必须一致（部署配置，同 ADR-025 套件哲学）。
    shards: usize,
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
         \x20\x20 # ADR-026 性能线：Data 面流级分片 worker 数（1..=64，默认 1=单点）。\n\
         \x20\x20 # Established 后自动拆分并行加解密；两端必须取相同 N（错配=丢包非错交付）\n\
         拓扑: 恰好一端 --initiate（主动），另一端被动等待 Init\n\
         示例(A 机主动): ipv8-node --self 0000fb14000000010001000001000000 \\\n\
         \x20\x20 --peer-addr 0000fb14000000020001000001000000 --peer-ip 192.168.1.12 --tun-ip 100.64.0.1 --initiate\n\
         示例(B 机被动): ipv8-node --self 0000fb14000000020001000001000000 \\\n\
         \x20\x20 --peer-addr 0000fb14000000010001000001000000 --peer-ip 192.168.1.11 --tun-ip 100.64.0.2"
    );
    std::process::exit(2);
}

fn parse_args() -> Result<Config, String> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
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
        Some(s) => s.parse().map_err(|_| "--mtu 非数字".to_string())?,
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
    // 手工还原线格式字段（大端），Reserved 非 0 视为损坏
    if addr_bytes[13..16] != [0u8; 3] {
        return None;
    }
    Some(Cert {
        addr: IPv8Address::new(
            u32::from_be_bytes(addr_bytes[0..4].try_into().ok()?),
            u32::from_be_bytes(addr_bytes[4..8].try_into().ok()?),
            u16::from_be_bytes(addr_bytes[8..10].try_into().ok()?),
            u16::from_be_bytes(addr_bytes[10..12].try_into().ok()?),
            addr_bytes[12],
        ),
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
            eprintln!("[ipv8-node] 警告: 证书缓存写入失败（不影响本次运行）: {e}");
        } else {
            println!("[ipv8-node] 证书已缓存至 {}（重启命中则免注册）", p.display());
        }
    }
    Ok((HostIdentity::with_cert(self_addr, ed_seed, cert), trust))
}

#[tokio::main]
async fn main() {
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
            eprintln!("[ipv8-node] 致命错误: {e:?}");
            eprintln!("提示: 需要管理员权限；UDP 入站端口需在防火墙放行");
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
    let sock = Arc::new(UdpSocket::bind(bind_addr)?);
    let peer = SocketAddr::new(cfg.peer_ip, cfg.peer_port);
    println!("[ipv8-node] UDP 绑定 {bind_addr}，对端初始 {peer}");

    // ---- Fallback 共享调度状态（v9 §11；状态机在 ipv8-tunnel::fallback）----
    // 生产路径的入口来自 Resolver；node 验证拓扑用 --peer-ip/--peer-port=主入口、
    // --alt-ip/--alt-port=备用入口 静态模拟。TCP 明文传输归 C# 宿主，
    // node 验证明文级时复用 UDP socket 直发原始 IP 包（首字节 0x45/0x60 区分）。
    #[derive(Clone, PartialEq, Eq)]
    enum Transport {
        /// 隧道：封装 IPv8+ 帧后发往当前选定入口
        Tunnel(SocketAddr),
        /// 明文降级：内层 IP 包不加密直发
        PlainUdp(SocketAddr),
    }

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
    }

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
        let (sock2, engine2, sched2) = (sock.clone(), engine.clone(), sched.clone());
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
            if let Err(e) = sock.send_to(&f, peer) {
                eprintln!(
                    "[ipv8-node] ⚠ 首发 {peer} 失败: {e}\n\
                     \x20\x20 常见原因: 本机没有到该地址的网络出口（如目标为 IPv6 但本机 v6 未启用）。\n\
                     \x20\x20 测试命令: ping -6 <对端v6>；不通则先修 v6 或改用 IPv4 直连拓扑。"
                );
            } else {
                println!("[ipv8-node] {} 已发出 ({}B)，等待 Established...", if cfg.auth { "AuthInit" } else { "HandshakeInit" }, f.len());
            }
            sched.lock().expect("sched").attempt = Some((f, now_epoch_secs(), peer));
        }
    } else {
        println!("[ipv8-node] 被动模式：等待对端 {}...", if cfg.auth { "AuthInit" } else { "HandshakeInit" });
    }

    // ---- 数据面驱动线程：正常模式 = TUN 读线程（v9 §8 铁律：独立 std::thread
    // + 拷贝即 drop）；--no-tun 发起方 = 合成包注入（Established 后每 5s 一发）----
    let echo_ok = Arc::new(AtomicU32::new(0));
    let echo_bad = Arc::new(AtomicU32::new(0));
    if let Some(session) = session.clone() {
        let engine = engine.clone();
        let sock = sock.clone();
        let sched = sched.clone();
        let hub = hub.clone();
        // 用户态批处理（"wintun 批量优化"的正确落地形态）：
        // wintun 官方 C API（0.14.x）只有单包 ReceivePacket/SendPacket，
        // 不存在 StartBatch/EndBatch；真正可省的是**每包一次** engine/sched
        // 互斥锁与逐包 send 的调用开销。策略：阻塞等到第一包后，非阻塞
        // 排空环形缓冲（最多 TUN_BATCH_CAP 包），持锁一次批量 seal，
        // 释放锁后再统一发 UDP —— 锁外不做任何 engine 操作。
        // 注：transport 按批读取一次；Fallback 级联切换的生效延迟上界
        // = 一个批次（≤64 包），对秒级降级决策无影响。
        const TUN_BATCH_CAP: usize = 64;
        std::thread::spawn(move || loop {
            // ---- 1) 收一批（首包阻塞，后续非阻塞排空）----
            let mut batch: Vec<Vec<u8>> = Vec::new();
            match session.receive_blocking() {
                Ok(pkt) => {
                    batch.push(pkt.bytes().to_vec()); // ★ 拷贝出环形缓冲区
                    drop(pkt); // ★ 立即归还
                }
                Err(e) => {
                    eprintln!("[tun] receive 结束: {e}");
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
                        eprintln!("[tun] try_receive 结束: {e}");
                        return;
                    }
                }
            }

            // ---- 2) 批级决策 + 持锁一次批量处理 ----
            let transport = sched.lock().expect("sched").transport.clone();
            match transport {
                // 超 MTU 的内层包 → IPv8+ 分片为多帧，逐帧交 UDP（v9 §8/§7.8）
                Transport::Tunnel(dest) => {
                    // ADR-026：分片活跃 → 批投给 workers（同流同片，锁外并行
                    // 封装，帧经出口线程异步发出）；未活跃 → 原单点批量路径。
                    let used_shards = {
                        let hb = hub.lock().expect("hub");
                        hb.seal(&batch)
                    };
                    if used_shards {
                        continue;
                    }
                    let mut out: Vec<Vec<u8>> = Vec::new();
                    {
                        let mut g = engine.lock().expect("engine");
                        for bytes in &batch {
                            match g.seal_frames(bytes) {
                                Ok(frames) => out.extend(frames),
                                Err(e) => eprintln!(
                                    "[tun→wire] 未封装（{e:?}），丢弃 {}B",
                                    bytes.len()
                                ),
                            }
                        }
                    } // 先还 engine 锁，再碰网络
                    for frame in &out {
                        if let Err(e) = sock.send_to(frame, dest) {
                            eprintln!("[udp] send 失败: {e}");
                        }
                    }
                }
                // 明文级：内层 IP 包原样直发（v9 §11 末两级）
                Transport::PlainUdp(dest) => {
                    let mut sent = 0u64;
                    for bytes in &batch {
                        if sock.send_to(bytes, dest).is_ok() {
                            sent += 1;
                        }
                    }
                    if sent > 0 {
                        sched.lock().expect("sched").plain_tx += sent;
                    }
                }
            }
        });
    } else if cfg.initiate {
        // --no-tun 发起方：Established 后周期注入合成包
        // 载荷 = magic(5) ‖ seq(4) ‖ 填充(0xA5…)；应答方逐字节回显，本端结构校验。
        let engine = engine.clone();
        let sock = sock.clone();
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
                                eprintln!("[no-tun] send 失败: {e}");
                            }
                        }
                    }
                    Err(e) => eprintln!("[no-tun] 注入密封失败: {e:?}"),
                }
            }
        });
    }

    // ---- UDP 收线程：拆壳 + 写回 TUN ----
    {
        let engine = engine.clone();
        let sock = sock.clone();
        let session = session.clone();
        let sched = sched.clone();
        let hub = hub.clone();
        let plain_demux = cfg.fallback;
        let learn = cfg.learn_peer || (cfg.punch && !cfg.initiate); // punch 应答方自动现学：
    // 发起方的 Init 会从"服务端所见本端映射"到达——与配置的占位 --peer-ip
    // 不同源，不现学则握手响应回错地址（learn-peer 的既有语义正为此设计）。
        let is_initiator = cfg.initiate;
        let echo_ok = echo_ok.clone();
        let echo_bad = echo_bad.clone();
        std::thread::spawn(move || {
            let mut buf = vec![0u8; 65507]; // 单个 UDP 载荷上限
            let mut learned = false;
            loop {
                match sock.recv_from(&mut buf) {
                    Ok((n, from)) => {
                        let raw = &buf[..n];
                        // 打洞敲门包：只用于撞活 NAT 映射，静默吸收——
                        // 不进引擎（否则污染 dropped 判据）、不回包。
                        if raw == PUNCH_KNOCK {
                            continue;
                        }
                        // 明文降级入包：非隧道帧（Ver 字节≠0x01）→ 直接注入 TUN。
                        // 仅在 -Fallback 验证下启用，避免改变既有模式丢弃语义。
                        if plain_demux && (n < 10 || raw[0] != 0x01) {
                            let ipv4 = matches!(raw.first(), Some(v) if v >> 4 == 4);
                            let ipv6 = matches!(raw.first(), Some(v) if v >> 4 == 6);
                            if ipv4 || ipv6 {
                                // 明文包只有真 TUN 才有处可写；--no-tun 下计数丢弃。
                                match &session {
                                    Some(s) => match s.allocate_send_packet(n as u16) {
                                        Ok(mut p) => {
                                            p.bytes_mut().copy_from_slice(raw);
                                            s.send_packet(p);
                                            sched.lock().expect("sched").plain_rx += 1;
                                        }
                                        Err(e) => eprintln!("[tun] plain allocate: {e}"),
                                    },
                                    None => {
                                        sched.lock().expect("sched").plain_rx += 1;
                                    }
                                }
                                continue;
                            }
                        }
                        // 大内网侧现学入口（必须在 handle_frame_at 之前：被动方对首帧会
                        // 产出握手响应，resp 发往当前 transport——不先学就回错地址）。
                        // 仅隧道帧触发（Ver==0x01）；垃圾包即使污染 transport 也无安全
                        // 影响——AEAD 三验保证只有合法对端能 Established，对端持续重发
                        // Init 时下一帧即被纠正。Established 后 attempt 已带真实入口。
                        if learn && !learned && n >= 1 && raw[0] == 0x01 {
                            let mut sc = sched.lock().expect("sched");
                            if let Transport::Tunnel(dest) = sc.transport {
                                if dest != from {
                                    println!("[learn-peer] 入口 {dest} → {from}（按合法首帧源地址）");
                                }
                            }
                            sc.main = from;
                            sc.transport = Transport::Tunnel(from);
                            if let Some((f, t0, _)) = sc.attempt.clone() {
                                sc.attempt = Some((f, t0, from));
                            }
                            learned = true;
                        }
                        let (resp, delivered) = {
                            // ADR-026：分片活跃时 Data 帧由 workers 接管
                            // （同余路由免解密定片）；握手/控制帧仍走引擎状态机。
                            if hub.lock().expect("hub").feed(raw) {
                                continue;
                            }
                            let mut g = engine.lock().expect("engine");
                            let r = g.handle_frame_at(raw, now_epoch_secs());
                            (r, g.take_delivered())
                        };
                        // 握手响应帧 → 直接回 UDP
                        if let Some(frame) = resp {
                            let dest = match sched.lock().expect("sched").transport {
                                Transport::Tunnel(d) | Transport::PlainUdp(d) => d,
                            };
                            let _ = sock.send_to(&frame, dest);
                        }
                        // 拆出的内层包 → 有 TUN 网卡则写回；无网卡模式做回显/校验。
                        if let Some(tun_pkt) = delivered {
                            match &session {
                                Some(s) => {
                                    match s.allocate_send_packet(tun_pkt.len() as u16) {
                                        Ok(mut p) => {
                                            p.bytes_mut().copy_from_slice(&tun_pkt);
                                            s.send_packet(p);
                                        }
                                        Err(e) => eprintln!("[tun] allocate_send_packet: {e}"),
                                    }
                                }
                                // --no-tun 应答方：把合成包原样密封回给来包地址。
                                // 用 seal_frames（多帧）：大载荷回显同样走分片路径。
                                None if !is_initiator => {
                                    let backs = {
                                        let mut g = engine.lock().expect("engine");
                                        g.seal_frames(&tun_pkt).ok()
                                    };
                                    if let Some(frames) = backs {
                                        for f in frames {
                                            let _ = sock.send_to(&f, from);
                                        }
                                    }
                                }
                                // --no-tun 发起方：校验回显结构（magic + 长度 + 填充）。
                                None => {
                                    let good = tun_pkt.len() >= 9
                                        && &tun_pkt[..5] == b"IP8NT"
                                        && tun_pkt[9..].iter().all(|&b| b == 0xA5);
                                    if good {
                                        let n = echo_ok.fetch_add(1, Ordering::Relaxed) + 1;
                                        println!("[no-tun] ECHO_OK #{n} ({}B byte-exact)", tun_pkt.len());
                                    } else {
                                        echo_bad.fetch_add(1, Ordering::Relaxed);
                                        println!("[no-tun] ECHO_BAD ({}B)", tun_pkt.len());
                                    }
                                }
                            }
                        }
                    }
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
                        eprintln!("[udp] recv 结束: {e}");
                        break;
                    }
                }
            }
        });
    }

    // ---- 主任务：Fallback 调度 + Established 后周期打印统计，Ctrl+C 退出 ----
    let mut ticker = tokio::time::interval(Duration::from_secs(2));
    let mut established_reported = false;
    loop {
        tokio::select! {
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
                            let (sock2, sched2) = (sock.clone(), sched.clone());
                            let frames: ShardSink = Arc::new(move |f: Vec<u8>| {
                                let dest = match sched2.lock().expect("sched").transport {
                                    Transport::Tunnel(d) | Transport::PlainUdp(d) => d,
                                };
                                if let Err(e) = sock2.send_to(&f, dest) {
                                    eprintln!("[shard→udp] send 失败: {e}");
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
                                    Err(e) => eprintln!("[shard→tun] allocate_send_packet: {e}"),
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
                            sc.plain_tx,
                            sc.plain_rx,
                            echo_ok.load(Ordering::Relaxed),
                            echo_bad.load(Ordering::Relaxed),
                            nsh
                        );
                    }
                    // 首包超时（v9 §11：隧道已建但数据不通 → 不浪费重试，直接降级）：
                    // 已发包但 3s 内 delivered 无增长 → 拆死隧道重排路径
                    if fb_on && sealed > 0 && deliv == sc.est_delivered {
                        if let Some(t0) = sc.est_started {
                            if now.saturating_sub(t0) >= sc.fb.first_packet_timeout().as_secs() {
                                println!("[fallback] 首包超时（隧道半开）→ reset + record_failure，走表降级");
                                sc.fb.record_failure(PEER_KEY, Failure::FirstPacketTimeout, now);
                                sc.success_recorded = false;
                                sc.est_started = None;
                                drop(sc); // 锁序：engine 与 sched 不同时持有
                                engine.lock().expect("engine").reset();
                            }
                        }
                    }
                    continue;
                }
                established_reported = false;

                if !fb_on {
                    // ---- Phase 1 行为（无 fallback）：Init 每 tick 幂等重发 ----
                    if st.state == State::Initiating {
                        if let Some((f, _, dest)) = &sc.attempt {
                            let _ = sock.send_to(f, *dest);
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
                                let _ = sock.send_to(&f, dest);
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
                                let _ = sock.send_to(&f, dest); // 预算内重发同一 Init（幂等）
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
        IPv8Address::new(0xfb14, n, 1, 0, 1)
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
}