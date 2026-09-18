//! # ipv8-resolver
//!
//! IPv8+ 地址解析服务核心逻辑（v9 Phase 3 云端）。分层与 zoneserver 一致：
//! 本模块是**零 IO 纯逻辑**（HashMap + 注入时钟），gRPC 网络层在
//! [`grpc`]，二者可独立测试。
//!
//! 职责（v9 §Resolver 最小版本）：节点登记"我的 IPv8+ 地址 ↔ 隧道入口"，
//! 查询方一次 RPC 原子拿回 {入口 IP, ipv8_capable, mtu, alt_ips, ttl}。
//! Fallback 状态机的 `Resolved` 输入、多跳的下一跳物理解析都吃这个输出。
//!
//! 隐私（ADR-007）：查询匿名（不要求调用方凭据）、响应只含路由必需字段、
//! 服务端不记查询日志、TTL 驱动客户端缓存以减少查询频率。
//!
//! 持久化（ADR-010）：内存实现，`trait Store` 已抽象；SQLite/PG 按触发
//! 条件后置，不进本轮验收。

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use smallvec::SmallVec;

use ed25519_dalek::{Signature, VerifyingKey};
use ipv8_codec::IPv8Address;

pub mod grpc;
pub mod sqlite_store;
pub mod dht_store;
pub mod cached_store;

/// 登记记录（一个 IPv8+ 地址的可达性事实）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeRecord {
    /// 主隧道入口 "ip:port"
    pub tunnel_entry: String,
    /// 备用入口列表（Fallback 的级联候选，v9 alt_ips 语义）
    /// SmallVec：90%+ 节点为空 → 栈上零分配，clone 0ns vs Vec ~40ns
    pub alt_entries: SmallVec<[String; 4]>,
    /// 是否支持 IPv8+（否则查询方直接降级——v9 ipv8_capable 源头）
    pub ipv8_capable: bool,
    /// 建议 MTU（0 = 未声明，响应时填协议默认）
    pub mtu: u32,
    /// 登记时刻 + TTL = 过期判定（reaper 清理，缓存语义）
    pub registered_at: Instant,
    pub ttl: Duration,
    /// ADR-026：服务端在最近一次 Register/Rendezvous 连接上"看到"的源地址
    /// （NAT 映射后的公网 "ip:port"）+ 观察时刻。STUN 的观察值；带独立
    /// 新鲜度窗口（映射会漂移，见 [`OBSERVED_MAX_AGE`]）。
    pub observed: Option<(String, Instant)>,
    /// ADR-026：节点在 Rendezvous 时自报的候选（LAN 地址等，仅信息性——
    /// 自报可能伪冒，权威候选是 observed；数量/长度在入口处消毒）。
    pub local_candidates: SmallVec<[String; 4]>,
}

impl NodeRecord {
    pub fn is_expired(&self, now: Instant) -> bool {
        add_secs(self.registered_at, self.ttl) <= now
    }

    /// observed 是否在新鲜度窗口内（超窗 = NAT 映射可能已漂移，不再作候选）
    pub fn fresh_observed(&self, now: Instant) -> Option<&str> {
        self.observed
            .as_ref()
            .filter(|(_, t)| now.saturating_duration_since(*t) <= OBSERVED_MAX_AGE)
            .map(|(a, _)| a.as_str())
    }
}

/// 默认 TTL：5 分钟（与 v9 降级缓存同量级；服务端在 [1s, 24h] 内裁剪）
pub const DEFAULT_TTL: Duration = Duration::from_secs(300);
/// 服务端 TTL 上限（自托管小机器防内存膨胀）
pub const MAX_TTL: Duration = Duration::from_secs(24 * 3600);
/// 未声明 MTU 时响应协议默认值（v9 1500-68）
pub const DEFAULT_MTU: u32 = 1432;
/// ADR-026：observed 地址新鲜度窗口。UDP NAT 映射的典型空闲超时是
/// 30s~2min（保守值），取 90s——超窗的 observed 不再作为打洞候选，
/// 节点须再打一次 Register/Rendezvous 刷新（心跳语义由调用方驱动）。
pub const OBSERVED_MAX_AGE: Duration = Duration::from_secs(90);
/// Rendezvous 会合窗口：两次调用（A→B、B→A）须在此间隔内互相看见，
/// 否则视为对端没在线，返回无候选（打洞不成，退回直连/中继判断）。
pub const RENDEZVOUS_WINDOW: Duration = OBSERVED_MAX_AGE;
/// 自报候选消毒：条数上限 / 单条字节上限（防存储放大与注入）
pub const MAX_LOCAL_CANDIDATES: usize = 8;
pub const MAX_CANDIDATE_LEN: usize = 64;

/// 登记条目（公钥是重登记授权判定与 PoP 验证的材料）。
/// 存储细节类型：外部 Store 实现会触碰它。
#[derive(Debug, Clone)]
pub struct Entry {
    pub ed_pub: [u8; 32],
    pub rec: NodeRecord,
}

/// 共享指针包装的 Entry（Store::get 返回类型，Arc clone ~5ns）
pub type ArcEntry = Arc<Entry>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveError {
    /// 目标地址文本非法（canonical 32hex）
    BadAddress,
    /// 无登记或已过期（与"从未登记"不可区分——ADR-007 防探测枚举）
    NotFound,
    /// PoP 验签失败（不持有登记私钥，或消息域/地址不匹配）
    BadProof,
    /// 同名重登记但公钥不同（迁移身份必须先在 ZoneServer 走 rotate）
    KeyConflict { addr: IPv8Address },
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadAddress => write!(f, "目标地址文本非法"),
            Self::NotFound => write!(f, "未登记或已过期"),
            Self::BadProof => write!(f, "登记 PoP 验证失败"),
            Self::KeyConflict { addr } => write!(f, "地址 {addr} 已绑定其他公钥"),
        }
    }
}

impl std::error::Error for ResolveError {}

/// PoP 域分隔（与注册 ipv8plus-register / 轮换 ipv8plus-rotate / 路由
/// ipv8plus-routetrace 并列，签名跨服务不可挪用）
pub const RESOLVE_DOMAIN: &[u8] = b"ipv8plus-resolve";
/// ADR-026 会合 PoP 域（登记签名不可挪用来发起会合，反之亦然）
pub const RENDEZVOUS_DOMAIN: &[u8] = b"ipv8plus-rendezvous";

/// 登记 PoP 消息体：`domain ‖ addr_text ‖ ed_pub`
pub fn register_pop_message(addr_text: &str, ed_pub: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(RESOLVE_DOMAIN.len() + addr_text.len() + ed_pub.len());
    m.extend_from_slice(RESOLVE_DOMAIN);
    m.extend_from_slice(addr_text.as_bytes());
    m.extend_from_slice(ed_pub);
    m
}

/// 会合 PoP 消息体：`domain ‖ addr_text ‖ peer_addr_text`
/// （绑定 peer：一次签名不能换目标反复复用）
pub fn rendezvous_pop_message(addr_text: &str, peer_text: &str) -> Vec<u8> {
    let mut m = Vec::with_capacity(RENDEZVOUS_DOMAIN.len() + addr_text.len() + peer_text.len());
    m.extend_from_slice(RENDEZVOUS_DOMAIN);
    m.extend_from_slice(addr_text.as_bytes());
    m.extend_from_slice(peer_text.as_bytes());
    m
}

/// 解析输出（= resolver.proto ResolveResponse 的领域形态，网络层逐字段映射）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub tunnel_entry: String,
    pub alt_entries: SmallVec<[String; 4]>,
    pub ipv8_capable: bool,
    pub mtu: u32,
    pub ttl: Duration,
}

/// 会合输出（= resolver.proto RendezvousResponse 的领域形态）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RendezvousOutcome {
    /// 对端候选："对端新鲜 observed"（首位，权威）∪ "对端自报候选"
    pub peer_candidates: Vec<String>,
    /// 服务端所见本端源地址（诊断回显；None = 本次连接不可观察）
    pub self_observed: Option<String>,
    /// 候选有效期（= observed 新鲜度窗口，调用方据此决定重报心跳节奏）
    pub ttl: Duration,
}

/// Instant + Duration 的饱和加法。`registered_at + ttl` 在客户端请求
/// ttl 逼近 86400s（MAX_TTL 钳位）且进程长跑时不会溢出 panic。
fn add_secs(base: Instant, d: Duration) -> Instant {
    base.checked_add(d).unwrap_or(base)
}

/// 自报候选消毒：条数截断、长度截断、仅保留可见 ASCII——
/// 这些串最终会出现在对端进程的解析输出里，入口必须收紧。
fn sanitize_candidates(list: &[String]) -> SmallVec<[String; 4]> {
    list.iter()
        .take(MAX_LOCAL_CANDIDATES)
        .filter_map(|s| {
            let t: String = s.chars().take(MAX_CANDIDATE_LEN).filter(|c| !c.is_control()).collect();
            (!t.is_empty()).then_some(t)
        })
        .collect()
}

/// 存储抽象（ADR-010：trait 先行、实现按触发条件后置）。
/// 注意：故意不加 `Default` supertrait——SQLite/DHT 等实现
/// 需要路径/网络参数才能构造，走 `with_store` 入口即可。
///
/// `get` 返回 `Arc<Entry>`：缓存命中时 Arc clone 仅 ~5ns
/// （原子引用计数 +1），避免 Entry 深拷贝的 ~200ns 开销。
/// 写入仍按值接受 Entry，各实现内部自行包装 Arc。
pub trait Store {
    fn get(&self, addr: &IPv8Address) -> Option<Arc<Entry>>;
    fn insert(&mut self, addr: IPv8Address, e: Entry);
    /// 返回清理条数
    fn sweep_expired(&mut self, now: Instant) -> usize;
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// 默认存储：单 zone 内存表（自托管单机形态）
#[derive(Default)]
pub struct MemStore {
    by_addr: HashMap<IPv8Address, Arc<Entry>>,
}

impl Store for MemStore {
    fn get(&self, addr: &IPv8Address) -> Option<Arc<Entry>> {
        self.by_addr.get(addr).cloned()
    }
    fn insert(&mut self, addr: IPv8Address, e: Entry) {
        self.by_addr.insert(addr, Arc::new(e));
    }
    fn sweep_expired(&mut self, now: Instant) -> usize {
        let before = self.by_addr.len();
        self.by_addr.retain(|_, e| !e.rec.is_expired(now));
        before - self.by_addr.len()
    }
    fn len(&self) -> usize {
        self.by_addr.len()
    }
}

/// [`ResolverService::register`] 的输入（gRPC RegisterRequest 的领域形态）。
#[derive(Debug, Clone)]
pub struct RegisterSpec<'a> {
    pub addr_text: &'a str,
    pub ed_pub: &'a [u8],
    /// PoP：ed_pub 私钥对 [`register_pop_message`] 的签名（首次登记必需）
    pub proof: &'a [u8],
    /// 主隧道入口 "ip:port"
    pub tunnel_entry: &'a str,
    pub alt_entries: Vec<String>,
    pub ipv8_capable: bool,
    /// 建议 MTU（0 = 响应时填协议默认）
    pub mtu: u32,
    /// 请求 TTL 秒（0 = 默认 300；服务端裁剪到 [1, 86400]）
    pub ttl_secs: u64,
    /// ADR-026：服务端在该次登记连接上观察到的源地址（"ip:port"，
    /// tonic ConnectInfo 提取）。None = 不可观察（如测试直调），此时
    /// 保留旧值不清空。
    pub observed: Option<&'a str>,
}

/// 登记输出：生效 TTL + 服务端所见本端源地址（proto RegisterResponse 对应）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterOutcome {
    pub ttl: Duration,
    pub observed: Option<String>,
}

/// 解析服务（泛型存储便于将来换持久化后端不动逻辑/网络层）
pub struct ResolverService<S: Store = MemStore> {
    store: S,
}

impl Default for ResolverService<MemStore> {
    fn default() -> Self {
        Self::new()
    }
}

impl ResolverService<MemStore> {
    /// 默认内存存储构造（重启丢失；自测 / 无持久化部署用）
    pub fn new() -> Self {
        Self { store: MemStore::default() }
    }
}

impl<S: Store> ResolverService<S> {
    /// 自定义存储构造（SQLite/PG 等持久化后端入口，ADR-010）
    pub fn with_store(store: S) -> Self {
        Self { store }
    }

    /// 登记/更新隧道入口。
    ///
    /// - 首次登记：要求 `proof` = ed_pub 对应私钥对 [`register_pop_message`]
    ///   的 Ed25519 签名（PoP：防止替他人地址登记入口）；
    /// - 重登记：同地址同公钥 → 更新入口刷新 TTL（私钥持有者自证，
    ///   免再签）；同地址换公钥 → `KeyConflict`（身份迁移须走 ZoneServer
    ///   轮换，解析层不旁路）；
    /// - `ttl_secs` 服务端裁剪到 `[1, 86400]`，0 = 默认 300。
    pub fn register(&mut self, spec: &RegisterSpec<'_>, now: Instant) -> Result<RegisterOutcome, ResolveError> {
        let addr = IPv8Address::from_canonical_str(spec.addr_text).map_err(|_| ResolveError::BadAddress)?;
        if spec.ed_pub.len() != 32 {
            return Err(ResolveError::BadProof);
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(spec.ed_pub);
        let vk = VerifyingKey::from_bytes(&pk).map_err(|_| ResolveError::BadProof)?;

        let existing = self.store.get(&addr);
        match existing.as_ref() {
            Some(e) if e.ed_pub == pk => { /* 重登记：持有者已证，免 PoP */ }
            Some(e) if e.rec.is_expired(now) => {
                // 已过期：允许新身份重新登记，但必须重新自证
                let sig = Self::parse_sig(spec.proof)?;
                vk.verify_strict(&register_pop_message(spec.addr_text, spec.ed_pub), &sig)
                    .map_err(|_| ResolveError::BadProof)?;
            }
            Some(_) => return Err(ResolveError::KeyConflict { addr }),
            None => {
                let sig = Self::parse_sig(spec.proof)?;
                vk.verify_strict(&register_pop_message(spec.addr_text, spec.ed_pub), &sig)
                    .map_err(|_| ResolveError::BadProof)?;
            }
        }

        let ttl = if spec.ttl_secs == 0 {
            DEFAULT_TTL
        } else {
            Duration::from_secs(spec.ttl_secs.clamp(1, MAX_TTL.as_secs()))
        };
        // ADR-026：observed 处理——本次连接可观察则刷新；不可观察
        // （None，如测试直调/代理终结连接）时，**同身份**重登记保留旧值，
        // **新身份**接管则清空（旧映射属于上一个持有者，不能继承）。
        let (observed, local_candidates) = match (spec.observed, existing.as_ref()) {
            (Some(o), _) => (Some((o.to_string(), now)), SmallVec::new()),
            (None, Some(e)) if e.ed_pub == pk => (e.rec.observed.clone(), e.rec.local_candidates.clone()),
            (None, _) => (None, SmallVec::new()),
        };
        self.store.insert(
            addr,
            Entry {
                ed_pub: pk,
                rec: NodeRecord {
                    tunnel_entry: spec.tunnel_entry.to_string(),
                    alt_entries: spec.alt_entries.clone().into(),
                    ipv8_capable: spec.ipv8_capable,
                    mtu: spec.mtu,
                    registered_at: now,
                    ttl,
                    observed,
                    local_candidates,
                },
            },
        );
        let observed_out = self
            .store
            .get(&addr)
            .and_then(|e| e.rec.observed.as_ref().map(|(a, _)| a.clone()));
        Ok(RegisterOutcome { ttl, observed: observed_out })
    }

    /// 原子解析。NotFound 同时覆盖"未登记"与"已过期"——查询方无法探测
    /// 曾经存在过的地址（ADR-007 最小披露）。
    pub fn resolve(&self, target_text: &str, now: Instant) -> Result<Resolved, ResolveError> {
        let addr = IPv8Address::from_canonical_str(target_text)
            .map_err(|_| ResolveError::BadAddress)?;
        let e = self.store.get(&addr).ok_or(ResolveError::NotFound)?;
        if e.rec.is_expired(now) {
            return Err(ResolveError::NotFound);
        }
        Ok(Resolved {
            tunnel_entry: e.rec.tunnel_entry.clone(),
            alt_entries: e.rec.alt_entries.clone(),
            ipv8_capable: e.rec.ipv8_capable,
            mtu: if e.rec.mtu == 0 { DEFAULT_MTU } else { e.rec.mtu },
            ttl: e.rec.ttl,
        })
    }

    /// 清理过期条目（gRPC 层周期性调用；返回值 = 清理条数）
    pub fn sweep_expired(&mut self, now: Instant) -> usize {
        self.store.sweep_expired(now)
    }

    /// ADR-026 级 2：打洞会合（STUN 观察 + 信令交换）。
    ///
    /// 语义（本方法 = 一次"我方上线报到 + 索取对端地址"）：
    /// 1. 本端必须已登记且未过期；PoP 用**存储的公钥**验证（域
    ///    [`RENDEZVOUS_DOMAIN`]、消息绑定 peer）——自报 addr_text+坏签名
    ///    不能冒用他人身份会合；
    /// 2. 刷新本端 observed（服务端所见源地址）与自报候选（消毒后存储）
    ///    ——observed 新鲜本身即"近期在线且该 NAT 映射存活"的证据；
    /// 3. 返回对端候选 = 对端新鲜 observed（权威，服务端所见）∪ 对端自报
    ///    候选（信息性）。对端未登记/过期 → NotFound（与 resolve 同语义）。
    ///
    /// 打洞时序：A 调（拿到 B 候选）→ B 调（拿到 A 候选）→ 双方同时向
    /// 对方候选发包撞洞。窗口判据用 observed 新鲜度（90s）近似"对方
    /// 刚打过招呼"，不额外维护会合时间戳——原型够用，误判的代价只是
    /// 白撞一次洞（AEAD 三验兜底，伪冒候选解不开帧）。
    pub fn rendezvous(
        &mut self,
        addr_text: &str,
        peer_text: &str,
        proof: &[u8],
        local_candidates: &[String],
        observed: Option<&str>,
        now: Instant,
    ) -> Result<RendezvousOutcome, ResolveError> {
        let addr = IPv8Address::from_canonical_str(addr_text).map_err(|_| ResolveError::BadAddress)?;
        let peer = IPv8Address::from_canonical_str(peer_text).map_err(|_| ResolveError::BadAddress)?;

        // 1) 本端身份：已登记 + PoP 用存储公钥验（不采信请求里的任何公钥）
        let me = self.store.get(&addr).ok_or(ResolveError::NotFound)?;
        if me.rec.is_expired(now) {
            return Err(ResolveError::NotFound);
        }
        let vk = VerifyingKey::from_bytes(&me.ed_pub).map_err(|_| ResolveError::BadProof)?;
        let sig = Self::parse_sig(proof)?;
        vk.verify_strict(&rendezvous_pop_message(addr_text, peer_text), &sig)
            .map_err(|_| ResolveError::BadProof)?;

        // 2) 刷新本端条目（observed + 消毒后的自报候选），TTL/入口不动
        let mut rec = me.rec.clone();
        if let Some(o) = observed {
            rec.observed = Some((o.to_string(), now));
        }
        rec.local_candidates = sanitize_candidates(local_candidates);
        self.store.insert(addr, Entry { ed_pub: me.ed_pub, rec });

        // 3) 对端候选（优先级 = 打洞可用性）：
        //    a. 组合候选：对端 observed 的**公网 IP** + 对端登记的 entry **端口**。
        //       observed 来自 TCP 连接（临时映射端口打 UDP 必不中），但 IP 是
        //       权威观察值；NAT 对出站常保留"同 IP 可入"的语义（cone 类成立，
        //       symmetric 不成立 → 退回级 3 中继，ADR-026 已预告）。
        //    b. observed 原样（对端 entry 无端口/解析不出时的兜底）。
        //    c. 对端自报候选（信息性，可能伪冒，AEAD 三验兜底）。
        let pe = self.store.get(&peer).ok_or(ResolveError::NotFound)?;
        if pe.rec.is_expired(now) {
            return Err(ResolveError::NotFound);
        }
        let mut candidates: Vec<String> = Vec::new();
        if let Some(o) = pe.rec.fresh_observed(now) {
            // observed = "ip:port"（取 rsplit_once 前段 IP）；entry 取末段端口
            let combo = match (o.rsplit_once(':'), pe.rec.tunnel_entry.rsplit_once(':')) {
                (Some((o_ip, _)), Some((_, e_port))) if !e_port.is_empty() =>
                    Some(format!("{o_ip}:{e_port}")),
                _ => None,
            };
            if let Some(c) = combo {
                candidates.push(c);
            }
            if !candidates.iter().any(|c| c == o) {
                candidates.push(o.to_string());
            }
        }
        for c in &pe.rec.local_candidates {
            // 上限：组合 + observed 原样（最多 2 条权威）+ MAX_LOCAL_CANDIDATES 条自报
            if candidates.len() > 1 + MAX_LOCAL_CANDIDATES {
                break;
            }
            if !candidates.contains(c) {
                candidates.push(c.clone());
            }
        }
        Ok(RendezvousOutcome {
            peer_candidates: candidates,
            self_observed: observed.map(|o| o.to_string()),
            ttl: OBSERVED_MAX_AGE,
        })
    }

    /// 登记条目数（观测用）
    pub fn len(&self) -> usize {
        self.store.len()
    }

    pub fn is_empty(&self) -> bool {
        self.store.len() == 0
    }

    fn parse_sig(proof: &[u8]) -> Result<Signature, ResolveError> {
        let arr: [u8; 64] = proof.try_into().map_err(|_| ResolveError::BadProof)?;
        Ok(Signature::from_bytes(&arr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;

    fn text(n: u32) -> String {
        IPv8Address::with_region(n as u64, 1, 0, 0x0100, 0).to_canonical_string()
    }

    struct Node {
        sk: ed25519_dalek::SigningKey,
    }

    impl Node {
        fn new(seed: u8) -> Self {
            Self { sk: ed25519_dalek::SigningKey::from_bytes(&[seed; 32]) }
        }
        fn pub_bytes(&self) -> Vec<u8> {
            self.sk.verifying_key().to_bytes().to_vec()
        }
        fn proof(&self, addr_text: &str) -> Vec<u8> {
            self.sk.sign(&register_pop_message(addr_text, &self.pub_bytes())).to_bytes().to_vec()
        }
        fn rz_proof(&self, addr_text: &str, peer_text: &str) -> Vec<u8> {
            self.sk
                .sign(&rendezvous_pop_message(addr_text, peer_text))
                .to_bytes()
                .to_vec()
        }
    }

    fn at(secs: u64) -> Instant {
        Instant::now() + Duration::from_secs(secs)
    }

    #[allow(clippy::too_many_arguments)]
    fn full(
        s: &mut ResolverService,
        t: &str,
        n: &Node,
        proof: &[u8],
        entry: &str,
        alts: Vec<String>,
        cap: bool,
        mtu: u32,
        ttl: u64,
        now: Instant,
    ) -> Result<RegisterOutcome, ResolveError> {
        let pb = n.pub_bytes();
        s.register(
            &RegisterSpec {
                addr_text: t,
                ed_pub: &pb,
                proof,
                tunnel_entry: entry,
                alt_entries: alts,
                ipv8_capable: cap,
                mtu,
                ttl_secs: ttl,
                observed: None,
            },
            now,
        )
    }

    /// 常规登记（默认入口/能力真/MTU 未声明/带合法 PoP）
    fn reg(s: &mut ResolverService, t: &str, n: &Node, ttl: u64, now: Instant) -> Result<RegisterOutcome, ResolveError> {
        let proof = n.proof(t);
        full(s, t, n, &proof, "10.0.0.1:45700", vec![], true, 0, ttl, now)
    }

    #[test]
    fn register_then_resolve_atomic_fields() {
        let mut s = ResolverService::new();
        let n = Node::new(0xA1);
        let t = text(1);
        reg(&mut s, &t, &n, 0, Instant::now()).unwrap();
        let r = s.resolve(&t, Instant::now()).unwrap();
        assert_eq!(r.tunnel_entry, "10.0.0.1:45700");
        assert!(r.ipv8_capable);
        assert_eq!(r.mtu, DEFAULT_MTU); // 未声明 → 协议默认
        assert_eq!(r.ttl, DEFAULT_TTL);
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn first_registration_requires_pop() {
        let mut s = ResolverService::new();
        let t = text(1);
        let n = Node::new(0xA1);
        // 无 PoP（冒注他人地址的入口）→ 拒
        let bad = [0u8; 64];
        assert_eq!(
            full(&mut s, &t, &n, &bad, "1.2.3.4:1", vec![], true, 0, 0, Instant::now()).err(),
            Some(ResolveError::BadProof)
        );
        assert!(s.is_empty());
    }

    #[test]
    fn same_key_re_register_updates_entry_without_pop() {
        let mut s = ResolverService::new();
        let t = text(1);
        let n = Node::new(0xA1);
        reg(&mut s, &t, &n, 0, Instant::now()).unwrap();
        // 更新入口：同公钥免再签（持有者身份已建立）
        full(&mut s, &t, &n, &[], "10.0.0.9:9999", vec!["10.0.0.8:8".into()], true, 1400, 600, Instant::now()).unwrap();
        let r = s.resolve(&t, Instant::now()).unwrap();
        assert_eq!(r.tunnel_entry, "10.0.0.9:9999");
        assert_eq!(r.alt_entries.to_vec(), vec!["10.0.0.8:8".to_string()]);
        assert_eq!(r.mtu, 1400);
        assert_eq!(r.ttl, Duration::from_secs(600));
    }

    #[test]
    fn key_change_rejected_as_conflict() {
        let mut s = ResolverService::new();
        let t = text(1);
        let (n1, n2) = (Node::new(0xA1), Node::new(0xB2));
        reg(&mut s, &t, &n1, 0, Instant::now()).unwrap();
        // 换公钥登记 = 身份迁移，必须先在 ZoneServer 轮换，这里拒
        assert_eq!(reg(&mut s, &t, &n2, 0, Instant::now()).err(), Some(ResolveError::KeyConflict { addr: IPv8Address::from_canonical_str(&t).unwrap() }));
        // 原登记不受影响
        assert_eq!(s.resolve(&t, Instant::now()).unwrap().tunnel_entry, "10.0.0.1:45700");
    }

    #[test]
    fn expired_entry_resolves_not_found_and_new_key_can_takeover() {
        let mut s = ResolverService::new();
        let t = text(1);
        let n1 = Node::new(0xA1);
        reg(&mut s, &t, &n1, 100, at(0)).unwrap();
        let n2 = Node::new(0xB2);
        // 未过期：换公钥被拒（不泄露"它活着"）
        assert_eq!(reg(&mut s, &t, &n2, 0, at(50)).err(), Some(ResolveError::KeyConflict { addr: IPv8Address::from_canonical_str(&t).unwrap() }));
        // 过期后：新身份凭 PoP 接管；旧查询方只看到 NotFound
        assert_eq!(s.resolve(&t, at(200)).err(), Some(ResolveError::NotFound));
        let p2 = n2.proof(&t);
        full(&mut s, &t, &n2, &p2, "10.0.0.2:45701", vec![], true, 0, 0, at(200)).unwrap();
        assert_eq!(s.resolve(&t, at(201)).unwrap().tunnel_entry, "10.0.0.2:45701");
    }

    #[test]
    fn bad_address_text_rejected_on_both_paths() {
        let mut s = ResolverService::new();
        assert_eq!(reg(&mut s, "not-hex", &Node::new(1), 0, Instant::now()).err(), Some(ResolveError::BadAddress));
        assert_eq!(s.resolve("zz", Instant::now()).err(), Some(ResolveError::BadAddress));
    }

    #[test]
    fn ttl_clamped_to_server_bounds() {
        let mut s = ResolverService::new();
        let t = text(1);
        let n = Node::new(0xA1);
        let got = full(&mut s, &t, &n, &n.proof(&t), "e:1", vec![], true, 0, 999_999_999, Instant::now()).unwrap();
        assert_eq!(got.ttl, MAX_TTL);
        let t2 = text(2);
        let got2 = full(&mut s, &t2, &n, &n.proof(&t2), "e:1", vec![], true, 0, 0, Instant::now()).unwrap();
        assert_eq!(got2.ttl, DEFAULT_TTL);
    }

    #[test]
    fn sweep_expired_reclaims_only_dead_entries() {
        let mut s = ResolverService::new();
        let (t1, t2) = (text(1), text(2));
        let n = Node::new(0xA1);
        reg(&mut s, &t1, &n, 100, at(0)).unwrap();
        reg(&mut s, &t2, &n, 10_000, at(0)).unwrap();
        assert_eq!(s.sweep_expired(at(200)), 1, "t1 过期清理，t2 保留");
        assert_eq!(s.len(), 1);
        assert!(s.resolve(&t2, at(200)).is_ok());
    }

    #[test]
    fn resolve_is_read_only_no_side_effect() {
        let mut s = ResolverService::new();
        let t = text(1);
        let n = Node::new(0xA1);
        reg(&mut s, &t, &n, 0, Instant::now()).unwrap();
        let before = s.len();
        for _ in 0..5 {
            s.resolve(&t, Instant::now()).unwrap();
        }
        assert_eq!(s.len(), before, "查询不得写库（ADR-007 不记查询痕迹）");
    }

    #[test]
    fn proof_domain_separation() {
        // 注册 PoP（ipv8plus-register 域）不能挪用到解析登记
        let mut s = ResolverService::new();
        let t = text(1);
        let n = Node::new(0xA1);
        let zone_msg = {
            // 手工构造 ZoneServer 注册域的消息体（域不同 → 签名不可互用）
            let mut m = Vec::new();
            m.extend_from_slice(b"ipv8plus-register");
            m.extend_from_slice(t.as_bytes());
            m.extend_from_slice(&n.pub_bytes());
            m
        };
        let stolen = n.sk.sign(&zone_msg).to_bytes().to_vec();
        assert_eq!(
            full(&mut s, &t, &n, &stolen, "e:1", vec![], true, 0, 0, Instant::now()).err(),
            Some(ResolveError::BadProof)
        );
    }

    #[test]
    fn multiple_addresses_isolated() {
        let mut s = ResolverService::new();
        let (t1, t2) = (text(1), text(2));
        let n = Node::new(0xA1); // 同一设备两个地址场景
        let p1 = n.proof(&t1);
        let p2 = n.proof(&t2);
        full(&mut s, &t1, &n, &p1, "e1:1", vec![], true, 0, 0, Instant::now()).unwrap();
        full(&mut s, &t2, &n, &p2, "e2:2", vec![], false, 0, 0, Instant::now()).unwrap();
        assert_eq!(s.resolve(&t1, Instant::now()).unwrap().tunnel_entry, "e1:1");
        let r2 = s.resolve(&t2, Instant::now()).unwrap();
        assert!(!r2.ipv8_capable, "能力声明按条目独立");
    }

    // —— ADR-026：会合（observed + Rendezvous）——

    #[test]
    fn register_observed_echo_and_refresh() {
        let mut s = ResolverService::new();
        let t = text(1);
        let n = Node::new(0xA1);
        let pb = n.pub_bytes();
        let o1 = s
            .register(
                &RegisterSpec {
                    addr_text: &t,
                    ed_pub: &pb,
                    proof: &n.proof(&t),
                    tunnel_entry: "e:1",
                    alt_entries: vec![],
                    ipv8_capable: true,
                    mtu: 0,
                    ttl_secs: 0,
                    observed: Some("203.0.113.7:40000"),
                },
                Instant::now(),
            )
            .unwrap();
        assert_eq!(o1.observed.as_deref(), Some("203.0.113.7:40000"));
        // 同身份重登记且本次不可观察 → 保留旧 observed（不清空）
        let o2 = full(&mut s, &t, &n, &n.proof(&t), "e:2", vec![], true, 0, 0, Instant::now()).unwrap();
        assert_eq!(o2.observed.as_deref(), Some("203.0.113.7:40000"), "同身份重登记应保留 observed");
        // 可观察时新值覆盖旧值
        let o3 = s
            .register(
                &RegisterSpec {
                    addr_text: &t,
                    ed_pub: &pb,
                    proof: &[],
                    tunnel_entry: "e:2",
                    alt_entries: vec![],
                    ipv8_capable: true,
                    mtu: 0,
                    ttl_secs: 0,
                    observed: Some("203.0.113.9:40001"),
                },
                Instant::now(),
            )
            .unwrap();
        assert_eq!(o3.observed.as_deref(), Some("203.0.113.9:40001"));
    }

    #[test]
    fn rendezvous_happy_path_swaps_candidates() {
        let mut s = ResolverService::new();
        let (ta, tb) = (text(1), text(2));
        let (na, nb) = (Node::new(0xA1), Node::new(0xB2));
        reg(&mut s, &ta, &na, 0, Instant::now()).unwrap();
        reg(&mut s, &tb, &nb, 0, Instant::now()).unwrap();
        // A 先到：B 还没有 observed（刚登记、无自报）→ 候选仅自报（此处为 none）
        let ra = s
            .rendezvous(
                &ta,
                &tb,
                &na.rz_proof(&ta, &tb),
                &["10.1.1.1:45700".into()],
                Some("198.51.100.1:5000"),
                Instant::now(),
            )
            .unwrap();
        assert_eq!(ra.self_observed.as_deref(), Some("198.51.100.1:5000"));
        // B 后到：拿到 A 的候选 = 组合（observed IP + A 登记端口，权威首选）
        // + A observed 原样 + A 自报候选
        let rb = s
            .rendezvous(&tb, &ta, &nb.rz_proof(&tb, &ta), &[], Some("198.51.100.2:6000"), Instant::now())
            .unwrap();
        assert_eq!(rb.peer_candidates[0], "198.51.100.1:45700", "组合候选（observed IP+登记端口）应排首位");
        assert!(rb.peer_candidates.contains(&"198.51.100.1:5000".to_string()), "observed 原样应保留兜底");
        assert!(rb.peer_candidates.contains(&"10.1.1.1:45700".to_string()), "自报候选应附带");
        // A 再打一次心跳式会合，也能看到 B 的 observed 了
        let ra2 = s
            .rendezvous(&ta, &tb, &na.rz_proof(&ta, &tb), &["10.1.1.1:45700".into()], Some("198.51.100.1:5000"), Instant::now())
            .unwrap();
        assert!(ra2.peer_candidates.contains(&"198.51.100.2:45700".to_string()));
    }

    #[test]
    fn rendezvous_rejects_bad_identity() {
        let mut s = ResolverService::new();
        let (ta, tb) = (text(1), text(2));
        let (na, nb) = (Node::new(0xA1), Node::new(0xB2));
        reg(&mut s, &ta, &na, 0, Instant::now()).unwrap();
        reg(&mut s, &tb, &nb, 0, Instant::now()).unwrap();
        // 未登记地址发起会合 → NotFound（不区分"不存在/过期"）
        assert_eq!(
            s.rendezvous(&text(404), &ta, &[], &[], Some("x:1"), Instant::now()).err(),
            Some(ResolveError::NotFound)
        );
        // 冒用他人 addr + 自己签的 proof → 验签失败（存储公钥不认）
        let fake = Node::new(0xEE);
        assert_eq!(
            s.rendezvous(&ta, &tb, &fake.rz_proof(&ta, &tb), &[], Some("x:1"), Instant::now()).err(),
            Some(ResolveError::BadProof)
        );
        // 登记域签名挪用到会合 → 拒（域分隔）
        assert_eq!(
            s.rendezvous(&ta, &tb, &na.proof(&ta), &[], Some("x:1"), Instant::now()).err(),
            Some(ResolveError::BadProof)
        );
        // 把会合签名换 peer 复用 → 拒（peer 绑定进消息体）
        let stolen = na.rz_proof(&ta, &text(3));
        assert_eq!(
            s.rendezvous(&ta, &tb, &stolen, &[], Some("x:1"), Instant::now()).err(),
            Some(ResolveError::BadProof)
        );
        // 对端未登记 → NotFound
        assert_eq!(
            s.rendezvous(&ta, &text(555), &na.rz_proof(&ta, text(555).as_str()), &[], Some("x:1"), Instant::now()).err(),
            Some(ResolveError::NotFound)
        );
    }

    #[test]
    fn rendezvous_stale_observed_excluded() {
        let mut s = ResolverService::new();
        let (ta, tb) = (text(1), text(2));
        let (na, nb) = (Node::new(0xA1), Node::new(0xB2));
        reg(&mut s, &ta, &na, 0, at(0)).unwrap();
        reg(&mut s, &tb, &nb, 0, at(0)).unwrap();
        // B 在 t=0 留下 observed（含自报）
        s.rendezvous(
            &tb,
            &ta,
            &nb.rz_proof(&tb, &ta),
            &["10.2.2.2:45700".into()],
            Some("198.51.100.2:6000"),
            at(0),
        )
        .unwrap();
        // A 在窗口内会合 → 拿到 B observed + 自报
        let in_win = s
            .rendezvous(&ta, &tb, &na.rz_proof(&ta, &tb), &[], Some("198.51.100.1:5000"), at(80))
            .unwrap();
        assert!(in_win.peer_candidates.contains(&"198.51.100.2:6000".to_string()));
        // 超窗后再会合 → observed 出清，只剩自报候选（信息性保留）
        let late = s
            .rendezvous(&ta, &tb, &na.rz_proof(&ta, &tb), &[], Some("198.51.100.1:5000"), at(200))
            .unwrap();
        assert!(!late.peer_candidates.contains(&"198.51.100.2:6000".to_string()), "过期 observed 不得作候选");
        assert!(late.peer_candidates.contains(&"10.2.2.2:45700".to_string()));
    }

    #[test]
    fn rendezvous_sanitizes_reported_candidates() {
        let mut s = ResolverService::new();
        let (ta, tb) = (text(1), text(2));
        let (na, nb) = (Node::new(0xA1), Node::new(0xB2));
        reg(&mut s, &ta, &na, 0, Instant::now()).unwrap();
        reg(&mut s, &tb, &nb, 0, Instant::now()).unwrap();
        let mut junk: Vec<String> = (0..20).map(|i| format!("10.0.0.{i}:1")).collect();
        junk.push("x".repeat(300)); // 超长 → 截断
        junk.push("bad\r\nline".into()); // 控制字符 → 剥除
        s.rendezvous(&ta, &tb, &na.rz_proof(&ta, &tb), &junk, Some("o:1"), Instant::now())
            .unwrap();
        let out = s
            .rendezvous(&tb, &ta, &nb.rz_proof(&tb, &ta), &[], Some("o:2"), Instant::now())
            .unwrap();
        // 首位是组合候选（observed "o:1" 的 IP 段 "o" + 登记 entry 端口）：
        // reg 默认 entry "10.0.0.1:45700" → 首选 "o:45700"，observed 原样兜底
        assert_eq!(out.peer_candidates[0], "o:45700");
        assert!(out.peer_candidates.contains(&"o:1".to_string()));
        // 其余自报 ≤ MAX_LOCAL_CANDIDATES（总长 = 权威 2 + 自报 8）
        assert!(out.peer_candidates.len() <= 2 + MAX_LOCAL_CANDIDATES);
        assert!(out.peer_candidates.iter().all(|c| c.len() <= MAX_CANDIDATE_LEN && !c.contains('\r') && !c.contains('\n')));
    }
}
