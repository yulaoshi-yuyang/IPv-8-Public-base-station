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
use std::time::{Duration, Instant};

use ed25519_dalek::{Signature, VerifyingKey};
use ipv8_codec::IPv8Address;

pub mod grpc;

/// 登记记录（一个 IPv8+ 地址的可达性事实）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeRecord {
    /// 主隧道入口 "ip:port"
    pub tunnel_entry: String,
    /// 备用入口列表（Fallback 的级联候选，v9 alt_ips 语义）
    pub alt_entries: Vec<String>,
    /// 是否支持 IPv8+（否则查询方直接降级——v9 ipv8_capable 源头）
    pub ipv8_capable: bool,
    /// 建议 MTU（0 = 未声明，响应时填协议默认）
    pub mtu: u32,
    /// 登记时刻 + TTL = 过期判定（reaper 清理，缓存语义）
    pub registered_at: Instant,
    pub ttl: Duration,
}

impl NodeRecord {
    pub fn is_expired(&self, now: Instant) -> bool {
        self.registered_at + self.ttl <= now
    }
}

/// 默认 TTL：5 分钟（与 v9 降级缓存同量级；服务端在 [1s, 24h] 内裁剪）
pub const DEFAULT_TTL: Duration = Duration::from_secs(300);
/// 服务端 TTL 上限（自托管小机器防内存膨胀）
pub const MAX_TTL: Duration = Duration::from_secs(24 * 3600);
/// 未声明 MTU 时响应协议默认值（v9 1500-68）
pub const DEFAULT_MTU: u32 = 1432;

/// 登记条目（公钥是重登记授权判定与 PoP 验证的材料）。
/// 存储细节类型：外部 Store 实现会触碰它。
#[derive(Debug, Clone)]
pub struct Entry {
    pub ed_pub: [u8; 32],
    pub rec: NodeRecord,
}

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

/// 登记 PoP 消息体：`domain ‖ addr_text ‖ ed_pub`
pub fn register_pop_message(addr_text: &str, ed_pub: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(RESOLVE_DOMAIN.len() + addr_text.len() + ed_pub.len());
    m.extend_from_slice(RESOLVE_DOMAIN);
    m.extend_from_slice(addr_text.as_bytes());
    m.extend_from_slice(ed_pub);
    m
}

/// 解析输出（= resolver.proto ResolveResponse 的领域形态，网络层逐字段映射）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub tunnel_entry: String,
    pub alt_entries: Vec<String>,
    pub ipv8_capable: bool,
    pub mtu: u32,
    pub ttl: Duration,
}

/// 内存版存储（ADR-010：trait 先行、实现按触发条件后置）。
pub trait Store: Default {
    fn get(&self, addr: &IPv8Address) -> Option<&Entry>;
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
    by_addr: HashMap<IPv8Address, Entry>,
}

impl Store for MemStore {
    fn get(&self, addr: &IPv8Address) -> Option<&Entry> {
        self.by_addr.get(addr)
    }
    fn insert(&mut self, addr: IPv8Address, e: Entry) {
        self.by_addr.insert(addr, e);
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
}

/// 解析服务（泛型存储便于将来换持久化后端不动逻辑/网络层）
pub struct ResolverService<S: Store = MemStore> {
    store: S,
}

impl<S: Store> Default for ResolverService<S> {
    fn default() -> Self {
        Self { store: S::default() }
    }
}

impl ResolverService<MemStore> {
    /// 默认内存存储构造
    pub fn new() -> Self {
        Self { store: MemStore::default() }
    }
}

impl<S: Store> ResolverService<S> {
    /// 自定义存储构造（将来 SQLite/PG 后端入口，ADR-010）
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
    pub fn register(&mut self, spec: &RegisterSpec<'_>, now: Instant) -> Result<Duration, ResolveError> {
        let addr = IPv8Address::from_canonical_str(spec.addr_text).map_err(|_| ResolveError::BadAddress)?;
        if spec.ed_pub.len() != 32 {
            return Err(ResolveError::BadProof);
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(spec.ed_pub);
        let vk = VerifyingKey::from_bytes(&pk).map_err(|_| ResolveError::BadProof)?;

        let existing = self.store.get(&addr).cloned();
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
        self.store.insert(
            addr,
            Entry {
                ed_pub: pk,
                rec: NodeRecord {
                    tunnel_entry: spec.tunnel_entry.to_string(),
                    alt_entries: spec.alt_entries.clone(),
                    ipv8_capable: spec.ipv8_capable,
                    mtu: spec.mtu,
                    registered_at: now,
                    ttl,
                },
            },
        );
        Ok(ttl)
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
        IPv8Address::new(64500, n, 1, 0, 1).to_canonical_string()
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
    ) -> Result<Duration, ResolveError> {
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
            },
            now,
        )
    }

    /// 常规登记（默认入口/能力真/MTU 未声明/带合法 PoP）
    fn reg(s: &mut ResolverService, t: &str, n: &Node, ttl: u64, now: Instant) -> Result<Duration, ResolveError> {
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
        assert_eq!(r.alt_entries, vec!["10.0.0.8:8".to_string()]);
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
        assert_eq!(got, MAX_TTL);
        let t2 = text(2);
        let got2 = full(&mut s, &t2, &n, &n.proof(&t2), "e:1", vec![], true, 0, 0, Instant::now()).unwrap();
        assert_eq!(got2, DEFAULT_TTL);
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
}
