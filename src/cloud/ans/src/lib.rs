//! # ipv8-ans — ANS 智能体命名服务核心（零 IO）
//!
//! v9 Phase 4 / ADR-022（ANS 以 Rust 实现）/ ADR-023（AgentCard 数据模型
//! 与 ANS↔Resolver↔ZoneServer 边界）。本模块只回答三件事：
//!
//! 1. **直接寻址**：name → {addr, tunnel_entry, card 摘要}（哈希表）；
//! 2. **能力寻址**：{精确标签集} → 候选（覆盖 + qos + 剩余 TTL 打分排序）；
//! 3. **任务寻址**：TaskDescription → 能力寻址取未租候选 → top-N 分片 +
//!    租约（防并发双订；回报/超时回收）。
//!
//! 信任边界（ADR-023 §1）：ANS **不发证书**，addr↔公钥 绑定用本地信任锚
//! 对随附证书离线三验（复用 `ipv8_routing::cert_binding_ok`，与握手/多跳
//! 同源）；登记另需**持有证明 PoP**（域 `ipv8plus-ans-register`）证明注册者
//! 持有该公钥，并用 **CardSig**（域 `ipv8plus-agentcard`，§6.7）把卡片哈希
//! 绑定到智能体自身密钥。能力标签格式与包内 SemanticTag 头同源（§6.8）。
//!
//! 持久化：`trait Store` 抽象，内存实现；SQLite/PG 按 ADR-010 触发条件后置。

use std::collections::HashMap;

use ed25519_dalek::{Signature, VerifyingKey};
use ipv8_codec::{agent_card_message, AgentCardSummary, IPv8Address, SemanticTags};
use sha2::{Digest, Sha256};

pub mod grpc;

#[cfg(test)]
pub mod tests_util;
#[cfg(test)]
mod vector_tests;

/// ANS 域分隔：登记 PoP（防与注册/轮换/路由/卡片签名互挪）
pub const ANS_REGISTER_DOMAIN: &[u8] = b"ipv8plus-ans-register";

/// 卡片格式版本（spec §6.7）
pub const CARD_VERSION: u8 = 1;
/// 租约上限秒（防 timeout_ms 过大长期占用）
pub const MAX_LEASE_SECS: u64 = 3600;

/// 能力标签（§6.8）解析/校验复用 codec 单一权威，此处再导出别名给 grpc 层
pub fn validate_tags(tags: &[String]) -> Result<(), AnsError> {
    let refs: Vec<&str> = tags.iter().map(String::as_str).collect();
    // encode 会校验非空/数量/字符/总长，但我们要的是"仅校验"：encode 成功即合法
    SemanticTags::encode(&refs).map(|_| ()).map_err(|_| AnsError::BadTags)
}

/// 登记 PoP 消息体：`domain ‖ name ‖ addr_text ‖ card_hash(16)`
pub fn ans_register_pop_message(name: &str, addr_text: &str, card_hash: &[u8; 16]) -> Vec<u8> {
    let mut m = Vec::with_capacity(ANS_REGISTER_DOMAIN.len() + name.len() + addr_text.len() + 16);
    m.extend_from_slice(ANS_REGISTER_DOMAIN);
    m.extend_from_slice(name.as_bytes());
    m.extend_from_slice(addr_text.as_bytes());
    m.extend_from_slice(card_hash);
    m
}

/// ANS 侧全量卡片（ADR-023 §2）；`card_hash = SHA-256(canonical_bytes)[0..16]`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentCard {
    pub version: u8,
    /// 全名，须以配置的命名空间根结尾（ADR-021 零硬编码）
    pub name: String,
    pub addr: IPv8Address,
    /// 能力标签（§6.8 词汇），登记时校验
    pub capabilities: Vec<String>,
    /// 可选端点（"ip:port" 文本），供 ResolveName 透传
    pub endpoints: Vec<String>,
    /// 建议 QoS 等级（0-15），能力寻址过滤用
    pub qos_hint: u8,
    /// 有效期 epoch 秒（<= 登记时刻即拒；到期经 reaper 清理）
    pub not_after: u64,
    /// 隧道入口（读模型，权威仍属 Resolver，ADR-023 §1）
    pub tunnel_entry: String,
}

impl AgentCard {
    /// 规范字节：定序 + 长度前缀，字段一一编码；哈希与 CardSig 的输入基准。
    /// 长度前缀用 u8（≤255），超限视为非法卡片。
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AnsError> {
        let mut b = Vec::new();
        b.push(self.version);
        b.extend_from_slice(&self.addr.to_bytes());
        push_u8_str(&mut b, &self.name)?;
        push_u8_str(&mut b, &self.tunnel_entry)?;
        if self.qos_hint > 15 {
            return Err(AnsError::BadCard);
        }
        b.push(self.qos_hint);
        b.extend_from_slice(&self.not_after.to_be_bytes());
        push_u8_strs(&mut b, &self.capabilities)?;
        push_u8_strs(&mut b, &self.endpoints)?;
        Ok(b)
    }

    /// 卡片哈希 = SHA-256(规范字节) 前 16 字节（spec §6.7 CardHash）。
    pub fn card_hash(&self) -> Result<[u8; 16], AnsError> {
        let digest = Sha256::digest(self.canonical_bytes()?);
        let mut h = [0u8; 16];
        h.copy_from_slice(&digest[..16]);
        Ok(h)
    }

    /// 由卡片 + 公钥 + 签名还原包内摘要（§6.7 结构）。
    pub fn summary(&self, agent_pubkey: [u8; 32], card_sig: [u8; 64]) -> Result<AgentCardSummary, AnsError> {
        Ok(AgentCardSummary {
            version: self.version,
            card_hash: self.card_hash()?,
            not_after: self.not_after,
            agent_pubkey,
            card_sig,
        })
    }
}

fn push_u8_str(b: &mut Vec<u8>, s: &str) -> Result<(), AnsError> {
    if s.len() > u8::MAX as usize {
        return Err(AnsError::BadCard);
    }
    b.push(s.len() as u8);
    b.extend_from_slice(s.as_bytes());
    Ok(())
}

fn push_u8_strs(b: &mut Vec<u8>, v: &[String]) -> Result<(), AnsError> {
    if v.len() > u8::MAX as usize {
        return Err(AnsError::BadCard);
    }
    b.push(v.len() as u8);
    for s in v {
        push_u8_str(b, s)?;
    }
    Ok(())
}

/// 登记后的存储条目（ANS 侧记录；含当前租约）。
#[derive(Debug, Clone)]
pub struct StoredAgent {
    /// 证书绑定的智能体公钥（cert.verify_key，摘要 agent_pubkey 同源）
    pub ed_pub: [u8; 32],
    pub name: String,
    pub card: AgentCard,
    pub summary: AgentCardSummary,
    /// (plan_id, 租约到期秒)；None = 空闲
    pub lease: Option<(u64, u64)>,
}

impl StoredAgent {
    fn is_leased(&self, now: u64) -> bool {
        self.lease.is_some_and(|(_, exp)| exp > now)
    }
    fn is_expired(&self, now: u64) -> bool {
        self.card.not_after <= now
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnsError {
    /// 名称未以配置根结尾 / 空标签部分 / 超 255
    BadName,
    /// 地址文本非法
    BadAddress,
    /// 能力标签不合 §6.8
    BadTags,
    /// 卡片结构/字段越界，或 CardSig 与哈希不符
    BadCard,
    /// 登记 PoP 验签失败
    BadProof,
    /// 证书与信任锚/有效期不符（addr↔pubkey 绑定不成立）
    BadCert,
    /// 地址已绑定其他公钥（身份迁移须走 ZoneServer 轮换）
    KeyConflict,
    /// 名称已被其他**存活**地址占用
    NameConflict,
    /// 未知或已过期（两者不可区分，ADR-007 防枚举）
    NotFound,
    /// 任务候选不足 min_count
    Insufficient { wanted: usize, got: usize },
}

impl std::fmt::Display for AnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadName => write!(f, "名称不合法（须以命名空间根结尾且 ≤255）"),
            Self::BadAddress => write!(f, "地址文本非法"),
            Self::BadTags => write!(f, "能力标签不合 §6.8"),
            Self::BadCard => write!(f, "卡片结构非法或 CardSig 不匹配哈希"),
            Self::BadProof => write!(f, "登记 PoP 验签失败"),
            Self::BadCert => write!(f, "证书不满足信任锚/有效期"),
            Self::KeyConflict => write!(f, "地址已绑定其他公钥"),
            Self::NameConflict => write!(f, "名称已被占用"),
            Self::NotFound => write!(f, "未登记或已过期"),
            Self::Insufficient { wanted, got } => {
                write!(f, "候选不足：需 {wanted}，得 {got}")
            }
        }
    }
}

impl std::error::Error for AnsError {}

/// [`AnsService::register`] 输入（证书 + 卡片 + 两份签名材料）。
#[derive(Debug, Clone)]
pub struct RegisterSpec<'a> {
    pub addr_text: &'a str,
    /// 120B 证书线格式（ZoneServer 签发；addr↔pubkey 绑定证明）
    pub cert_wire: &'a [u8],
    pub card: &'a AgentCard,
    /// CardSig：agent 对 [`agent_card_message`] 的签名
    pub card_sig: &'a [u8; 64],
    /// PoP：agent 对 [`ans_register_pop_message`] 的签名
    pub pop: &'a [u8],
}

/// 能力/名字查询返回（ADR-023 §1 的读模型；含摘要供目的地重算哈希）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedAgent {
    pub name: String,
    pub addr: IPv8Address,
    pub tunnel_entry: String,
    pub capabilities: Vec<String>,
    pub endpoints: Vec<String>,
    pub qos_hint: u8,
    pub not_after: u64,
    pub summary: AgentCardSummary,
}

/// 任务描述（ADR-023 §3，最小结构化匹配，无语义推理）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskDescription {
    /// 必须被覆盖的能力标签集
    pub required_caps: Vec<String>,
    /// 需要的并发 agent 数（1..=）
    pub min_count: usize,
    /// 候选 qos_hint 下限
    pub qos_level: u8,
    /// 租约时长（毫秒，服务端裁剪到 ≤3600s）
    pub timeout_ms: u64,
}

/// 一条分片指派
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assignment {
    pub addr: IPv8Address,
    pub shard_id: usize,
    pub lease_expiry: u64,
}

/// 任务计划输出
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub plan_id: u64,
    pub assignments: Vec<Assignment>,
    pub created_at: u64,
}

/// 存储抽象（将来 SQLite/PG 后端入口，ADR-010）
pub trait Store: Default {
    fn put(&mut self, addr: IPv8Address, agent: StoredAgent);
    fn get(&self, addr: IPv8Address) -> Option<&StoredAgent>;
    fn get_mut(&mut self, addr: IPv8Address) -> Option<&mut StoredAgent>;
    fn addr_of_name(&self, name: &str) -> Option<IPv8Address>;
    /// 摘除地址条目，连带清理其 name 索引
    fn remove(&mut self, addr: IPv8Address) -> Option<StoredAgent>;
    fn addrs(&self) -> Vec<IPv8Address>;
}

/// 默认内存存储
#[derive(Default)]
pub struct MemStore {
    by_addr: HashMap<IPv8Address, StoredAgent>,
    by_name: HashMap<String, IPv8Address>,
}

impl Store for MemStore {
    fn put(&mut self, addr: IPv8Address, agent: StoredAgent) {
        self.by_name.insert(agent.name.clone(), addr);
        self.by_addr.insert(addr, agent);
    }
    fn get(&self, addr: IPv8Address) -> Option<&StoredAgent> {
        self.by_addr.get(&addr)
    }
    fn get_mut(&mut self, addr: IPv8Address) -> Option<&mut StoredAgent> {
        self.by_addr.get_mut(&addr)
    }
    fn addr_of_name(&self, name: &str) -> Option<IPv8Address> {
        self.by_name.get(name).copied()
    }
    fn remove(&mut self, addr: IPv8Address) -> Option<StoredAgent> {
        if let Some(a) = self.by_addr.remove(&addr) {
            self.by_name.remove(&a.name);
            Some(a)
        } else {
            None
        }
    }
    fn addrs(&self) -> Vec<IPv8Address> {
        self.by_addr.keys().copied().collect()
    }
}

/// ANS 服务（泛型存储）
pub struct AnsService<S: Store = MemStore> {
    store: S,
    /// 本地信任锚公钥（验 addr↔pubkey 绑定）
    anchor_pub: [u8; 32],
    /// 命名空间根（ADR-021 配置化，如 ".ipv8.net"；空 = 不校验后缀）
    namespace_root: String,
    next_plan_id: u64,
}

impl AnsService<MemStore> {
    /// 便捷构造：默认内存存储
    pub fn new(anchor_pub: [u8; 32], namespace_root: impl Into<String>) -> Self {
        Self { store: MemStore::default(), anchor_pub, namespace_root: namespace_root.into(), next_plan_id: 1 }
    }
}

impl<S: Store> AnsService<S> {
    pub fn with_store(store: S, anchor_pub: [u8; 32], namespace_root: impl Into<String>) -> Self {
        Self { store, anchor_pub, namespace_root: namespace_root.into(), next_plan_id: 1 }
    }

    /// 校验名称：空/超 255/不以根结尾（根非空时）即 BadName
    fn check_name(&self, name: &str) -> Result<(), AnsError> {
        if name.is_empty() || name.len() > u8::MAX as usize {
            return Err(AnsError::BadName);
        }
        if !self.namespace_root.is_empty() && !name.ends_with(&self.namespace_root) {
            // 还须有非空前缀标签（仅根不行）
            return Err(AnsError::BadName);
        }
        if name == self.namespace_root {
            return Err(AnsError::BadName);
        }
        Ok(())
    }

    /// 登记 / 更新一个智能体。返回卡片哈希（供上层回显绑定）。
    ///
    /// 三道验证顺序：证书绑定 → CardSig（哈希一致）→ PoP（持有者）。
    /// 同地址同公钥 = 更新（覆盖卡片，保留租约判定按新 not_after）；换公钥 = KeyConflict。
    pub fn register(&mut self, spec: &RegisterSpec<'_>, now: u64) -> Result<[u8; 16], AnsError> {
        let addr = IPv8Address::from_canonical_str(spec.addr_text).map_err(|_| AnsError::BadAddress)?;
        self.check_name(&spec.card.name)?;
        // 卡片自洽：版本/地址
        if spec.card.version != CARD_VERSION || spec.card.addr != addr {
            return Err(AnsError::BadCard);
        }
        if spec.card.not_after <= now {
            return Err(AnsError::BadCard); // 登记的卡片已过期
        }
        validate_tags(&spec.card.capabilities)?;
        let card_hash = spec.card.card_hash()?;

        // ① 证书：addr↔pubkey 由信任锚证明（复用 routing，与握手/多跳同一 120B 编码）
        let pubkey = ipv8_routing::cert_pubkey_from_wire(spec.cert_wire).ok_or(AnsError::BadCert)?;
        if !ipv8_routing::cert_binding_ok(&self.anchor_pub, spec.cert_wire, &addr, &pubkey, now) {
            return Err(AnsError::BadCert);
        }

        // ② CardSig：对 (version‖hash‖not_after‖pubkey) 的签名，绑定卡片哈希到该密钥
        let msg = agent_card_message(spec.card.version, &card_hash, spec.card.not_after, &pubkey);
        let vk = VerifyingKey::from_bytes(&pubkey).map_err(|_| AnsError::BadCard)?;
        let sig = Signature::from_bytes(spec.card_sig);
        vk.verify_strict(&msg, &sig).map_err(|_| AnsError::BadCard)?;

        // ③ PoP：注册者持有该私钥
        let pop = Self::parse_sig(spec.pop)?;
        vk.verify_strict(&ans_register_pop_message(&spec.card.name, spec.addr_text, &card_hash), &pop)
            .map_err(|_| AnsError::BadProof)?;

        // 冲突判定
        if let Some(existing_addr) = self.store.addr_of_name(&spec.card.name) {
            if existing_addr != addr {
                // 名称被别的存活地址占用才算冲突；过期占位先清
                let taken = self
                    .store
                    .get(existing_addr)
                    .map(|a| !a.is_expired(now))
                    .unwrap_or(false);
                if taken {
                    return Err(AnsError::NameConflict);
                }
                self.store.remove(existing_addr);
            }
        }
        if let Some(cur) = self.store.get(addr) {
            if cur.ed_pub != pubkey {
                return Err(AnsError::KeyConflict);
            }
        }

        let summary = spec.card.summary(pubkey, *spec.card_sig)?;
        // 更新保留既有租约（同身份刷新不夺约）；新登记无租约
        let lease = self.store.get(addr).and_then(|a| a.lease);
        self.store.put(
            addr,
            StoredAgent { ed_pub: pubkey, name: spec.card.name.clone(), card: spec.card.clone(), summary, lease },
        );
        Ok(card_hash)
    }

    /// 直接寻址：name → 读模型。过期/未知统一 NotFound（防枚举）。
    pub fn resolve_name(&self, name: &str, now: u64) -> Result<ResolvedAgent, AnsError> {
        let addr = self.store.addr_of_name(name).ok_or(AnsError::NotFound)?;
        self.resolve_addr(addr, now)
    }

    /// 按地址取读模型（内部复用）。
    pub fn resolve_addr(&self, addr: IPv8Address, now: u64) -> Result<ResolvedAgent, AnsError> {
        let a = self.store.get(addr).ok_or(AnsError::NotFound)?;
        if a.is_expired(now) {
            return Err(AnsError::NotFound);
        }
        Ok(to_resolved(a))
    }

    /// 能力寻址：候选 = 覆盖 required_caps 且 qos_hint>=min_qos 且未过期未租；
    /// 排序 (qos_hint 降, 剩余 TTL 降, addr 升) —— 与 C# 侧镜像一致（ADR-023 §3）。
    ///
    /// `exclude_leased=true`（默认）排除已租 agent；发现型查询可传 false。
    pub fn search_capability(
        &self,
        required_caps: &[String],
        min_qos: u8,
        exclude_leased: bool,
        now: u64,
    ) -> Vec<ResolvedAgent> {
        validate_tags(required_caps).ok(); // 宽松：非法词集只会导致无候选，不 panic
        let mut out: Vec<ResolvedAgent> = self
            .store
            .addrs()
            .into_iter()
            .filter_map(|a| self.store.get(a))
            .filter(|a| !a.is_expired(now) && (!exclude_leased || !a.is_leased(now)))
            .filter(|a| covers(&a.card.capabilities, required_caps) && a.card.qos_hint >= min_qos)
            .map(to_resolved)
            .collect();
        out.sort_by(|x, y| {
            y.qos_hint
                .cmp(&x.qos_hint)
                .then(y.not_after.cmp(&x.not_after))
                .then_with(|| x.addr.to_canonical_string().cmp(&y.addr.to_canonical_string()))
        });
        out
    }

    /// 任务寻址：能力寻址取候选 → top-min_count 分片 + 起租（防并发双订）。
    pub fn plan_task(&mut self, task: &TaskDescription, now: u64) -> Result<Plan, AnsError> {
        validate_tags(&task.required_caps)?;
        if task.min_count == 0 {
            return Err(AnsError::Insufficient { wanted: 0, got: 0 });
        }
        let lease_secs = (task.timeout_ms.saturating_add(999) / 1000).clamp(1, MAX_LEASE_SECS);
        let candidates = self.search_capability(&task.required_caps, task.qos_level, true, now);
        if candidates.len() < task.min_count {
            return Err(AnsError::Insufficient { wanted: task.min_count, got: candidates.len() });
        }
        let plan_id = self.next_plan_id;
        self.next_plan_id += 1;
        let mut assignments = Vec::with_capacity(task.min_count);
        for (i, c) in candidates.iter().take(task.min_count).enumerate() {
            let expiry = now.saturating_add(lease_secs);
            if let Some(agent) = self.store.get_mut(c.addr) {
                agent.lease = Some((plan_id, expiry));
            }
            assignments.push(Assignment { addr: c.addr, shard_id: i, lease_expiry: expiry });
        }
        Ok(Plan { plan_id, assignments, created_at: now })
    }

    /// 回报完成：释放该 plan 对该 agent 的租约。plan/agent 不匹配或无租约 → NotFound。
    pub fn report_done(&mut self, plan_id: u64, addr: IPv8Address, now: u64) -> Result<(), AnsError> {
        let a = self.store.get_mut(addr).ok_or(AnsError::NotFound)?;
        match a.lease {
            Some((pid, _)) if pid == plan_id => {
                a.lease = None;
                let _ = now;
                Ok(())
            }
            _ => Err(AnsError::NotFound),
        }
    }

    /// 回收：清过期租约 + 摘过期卡片。返回 (释放租约数, 摘除卡片数)。
    pub fn reap(&mut self, now: u64) -> (usize, usize) {
        let mut released = 0;
        let mut expired_cards = Vec::new();
        for addr in self.store.addrs() {
            if let Some(a) = self.store.get_mut(addr) {
                if let Some((_, exp)) = a.lease {
                    if exp <= now {
                        a.lease = None;
                        released += 1;
                    }
                }
                if a.is_expired(now) {
                    expired_cards.push(addr);
                }
            }
        }
        let expired_n = expired_cards.len();
        for addr in expired_cards {
            self.store.remove(addr);
        }
        (released, expired_n)
    }

    /// 存活卡片数（观测）
    pub fn len(&self) -> usize {
        self.store.addrs().len()
    }
    pub fn is_empty(&self) -> bool {
        self.store.addrs().is_empty()
    }

    fn parse_sig(s: &[u8]) -> Result<Signature, AnsError> {
        let arr: [u8; 64] = s.try_into().map_err(|_| AnsError::BadProof)?;
        Ok(Signature::from_bytes(&arr))
    }
}

/// 覆盖判定：required ⊆ agent 能力集（精确标签）
fn covers(agent_caps: &[String], required: &[String]) -> bool {
    required.iter().all(|r| agent_caps.iter().any(|c| c == r))
}

fn to_resolved(a: &StoredAgent) -> ResolvedAgent {
    ResolvedAgent {
        name: a.name.clone(),
        addr: a.card.addr,
        tunnel_entry: a.card.tunnel_entry.clone(),
        capabilities: a.card.capabilities.clone(),
        endpoints: a.card.endpoints.clone(),
        qos_hint: a.card.qos_hint,
        not_after: a.card.not_after,
        summary: a.summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const CA_SEED: [u8; 32] = [0xC4u8; 32];
    const ROOT: &str = ".ipv8.net";
    const NOW: u64 = 2_000_000_000;
    /// 永久（远未来）
    const FOREVER: u64 = u64::MAX - 1;

    fn addr(n: u32) -> IPv8Address {
        IPv8Address::with_region(n as u64, 1, 0, 0x0100, 0)
    }
    fn text(n: u32) -> String {
        addr(n).to_canonical_string()
    }

    /// CA 公钥（信任锚）
    fn anchor() -> [u8; 32] {
        SigningKey::from_bytes(&CA_SEED).verifying_key().to_bytes()
    }

    /// 造 120B 证书线格式：TBS = addr16 ‖ pub32 ‖ not_after8，CA 签名附尾
    fn make_cert_wire(ca: &SigningKey, a: IPv8Address, pubkey: &[u8; 32], not_after: u64) -> Vec<u8> {
        let mut tbs = Vec::with_capacity(56);
        tbs.extend_from_slice(&a.to_bytes());
        tbs.extend_from_slice(pubkey);
        tbs.extend_from_slice(&not_after.to_be_bytes());
        let sig = ca.sign(&tbs).to_bytes();
        let mut w = tbs;
        w.extend_from_slice(&sig);
        w
    }

    struct Agent {
        sk: SigningKey,
        a: IPv8Address,
        name: String,
        caps: Vec<String>,
        qos: u8,
    }

    impl Agent {
        fn new(seed: u8, n: u32, name: &str, caps: &[&str], qos: u8) -> Self {
            Self {
                sk: SigningKey::from_bytes(&[seed; 32]),
                a: addr(n),
                name: format!("{name}{ROOT}"),
                caps: caps.iter().map(|s| s.to_string()).collect(),
                qos,
            }
        }
        fn pubkey(&self) -> [u8; 32] {
            self.sk.verifying_key().to_bytes()
        }
        fn card(&self, not_after: u64) -> AgentCard {
            AgentCard {
                version: CARD_VERSION,
                name: self.name.clone(),
                addr: self.a,
                capabilities: self.caps.clone(),
                endpoints: vec![format!("10.0.0.{}:45700", self.a.region_lo)],
                qos_hint: self.qos,
                not_after,
                tunnel_entry: format!("192.0.2.{}:45700", self.a.region_lo),
            }
        }
    }

    /// 完整登记一份 spec：证书 + CardSig + PoP，全部现签
    struct Kit {
        card: AgentCard,
        cert: Vec<u8>,
        card_sig: [u8; 64],
        pop: Vec<u8>,
        hash: [u8; 16],
    }

    fn kit(ca: &SigningKey, ag: &Agent, not_after: u64) -> Kit {
        let card = ag.card(not_after);
        let hash = card.card_hash().unwrap();
        let pk = ag.pubkey();
        let cert = make_cert_wire(ca, ag.a, &pk, not_after);
        let card_sig = ag.sk.sign(&agent_card_message(card.version, &hash, not_after, &pk)).to_bytes();
        let pop = ag.sk.sign(&ans_register_pop_message(&card.name, &text_of(ag.a), &hash)).to_bytes().to_vec();
        Kit { card, cert, card_sig, pop, hash }
    }
    fn text_of(a: IPv8Address) -> String {
        a.to_canonical_string()
    }

    fn spec_of<'a>(k: &'a Kit, addr_text: &'a str) -> RegisterSpec<'a> {
        RegisterSpec {
            addr_text,
            cert_wire: &k.cert,
            card: &k.card,
            card_sig: &k.card_sig,
            pop: &k.pop,
        }
    }

    fn svc() -> AnsService {
        AnsService::new(anchor(), ROOT)
    }

    // —— 规范字节 / 哈希 ——

    #[test]
    fn canonical_bytes_are_deterministic_and_field_sensitive() {
        let ag = Agent::new(0xA1, 1, "ocr", &["ocr"], 5);
        let b1 = ag.card(FOREVER).canonical_bytes().unwrap();
        assert_eq!(b1, ag.card(FOREVER).canonical_bytes().unwrap(), "同输入必须同字节");
        // qos / not_after / 能力 / 端点 任一变化 → 字节变
        let mut c2 = ag.card(FOREVER);
        c2.qos_hint = 6;
        assert_ne!(c2.canonical_bytes().unwrap(), b1);
        let mut c3 = ag.card(FOREVER);
        c3.not_after -= 1;
        assert_ne!(c3.canonical_bytes().unwrap(), b1);
        let mut c4 = ag.card(FOREVER);
        c4.capabilities.push("extra".into());
        assert_ne!(c4.canonical_bytes().unwrap(), b1);
    }

    #[test]
    fn card_hash_is_16_prefix_of_sha256() {
        let ag = Agent::new(0xA1, 1, "ocr", &["ocr"], 5);
        let bytes = ag.card(FOREVER).canonical_bytes().unwrap();
        let digest = Sha256::digest(&bytes);
        let want: [u8; 16] = digest[..16].try_into().unwrap();
        assert_eq!(ag.card(FOREVER).card_hash().unwrap(), want);
    }

    #[test]
    fn summary_matches_card_fields() {
        let ca = SigningKey::from_bytes(&CA_SEED);
        let ag = Agent::new(0xA1, 1, "ocr", &["ocr"], 5);
        let k = kit(&ca, &ag, FOREVER);
        assert_eq!(k.hash, k.card.card_hash().unwrap());
        let s = k.card.summary(ag.pubkey(), k.card_sig).unwrap();
        assert_eq!(s.card_hash, k.hash);
        assert_eq!(s.agent_pubkey, ag.pubkey());
        assert_eq!(s.not_after, FOREVER);
        assert_eq!(s.version, CARD_VERSION);
    }

    // —— 登记三验 ——

    #[test]
    fn register_valid_returns_hash() {
        let ca = SigningKey::from_bytes(&CA_SEED);
        let mut s = svc();
        let ag = Agent::new(0xA1, 1, "ocr", &["ocr"], 5);
        let k = kit(&ca, &ag, FOREVER);
        let t = text(1);
        assert_eq!(s.register(&spec_of(&k, &t), NOW).unwrap(), k.hash);
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn register_rejects_expired_cert() {
        let ca = SigningKey::from_bytes(&CA_SEED);
        let mut s = svc();
        // 卡片 not_after 有效，但**证书线格式**的 not_after < now → BadCert
        // （register 先过卡片自洽校验，故须分离两者才能命中证书有效期分支）
        let ag = Agent::new(0xA1, 1, "ocr", &["ocr"], 5);
        let card = ag.card(FOREVER);
        let hash = card.card_hash().unwrap();
        let pk = ag.pubkey();
        let cert = make_cert_wire(&ca, ag.a, &pk, NOW - 1); // 证书过期
        let card_sig = ag.sk.sign(&agent_card_message(card.version, &hash, FOREVER, &pk)).to_bytes();
        let pop = ag.sk.sign(&ans_register_pop_message(&card.name, &text(1), &hash)).to_bytes().to_vec();
        let spec = RegisterSpec { addr_text: &text(1), cert_wire: &cert, card: &card, card_sig: &card_sig, pop: &pop };
        assert_eq!(s.register(&spec, NOW).err(), Some(AnsError::BadCert));
    }

    #[test]
    fn register_rejects_rogue_ca() {
        let mut s = svc();
        let ag = Agent::new(0xA1, 1, "ocr", &["ocr"], 5);
        let rogue = SigningKey::from_bytes(&[0x99u8; 32]);
        let card = ag.card(FOREVER);
        let hash = card.card_hash().unwrap();
        let cert = make_cert_wire(&rogue, ag.a, &ag.pubkey(), FOREVER);
        let pk = ag.pubkey();
        let card_sig = ag.sk.sign(&agent_card_message(card.version, &hash, FOREVER, &pk)).to_bytes();
        let pop = ag.sk.sign(&ans_register_pop_message(&card.name, &text(1), &hash)).to_bytes();
        let spec = RegisterSpec { addr_text: &text(1), cert_wire: &cert, card: &card, card_sig: &card_sig, pop: &pop };
        assert_eq!(s.register(&spec, NOW).err(), Some(AnsError::BadCert));
    }

    #[test]
    fn register_rejects_tampered_cardsig() {
        let ca = SigningKey::from_bytes(&CA_SEED);
        let mut s = svc();
        let ag = Agent::new(0xA1, 1, "ocr", &["ocr"], 5);
        let mut k = kit(&ca, &ag, FOREVER);
        k.card_sig[0] ^= 0x01;
        let t = text(1);
        assert_eq!(s.register(&spec_of(&k, &t), NOW).err(), Some(AnsError::BadCard));
    }

    #[test]
    fn register_rejects_card_sig_from_wrong_key() {
        // 证书声明 victim 公钥 V，但 CardSig 用 attacker 密钥签 → CardSig 验签
        // 先失败（BadCard）。攻击者没有 victim 私钥就无法伪造过 CardSig，更到不了
        // PoP —— CardSig 已把"卡片哈希"绑定到"证书公钥"，这就是它的防冒充价值。
        let ca = SigningKey::from_bytes(&CA_SEED);
        let mut s = svc();
        let victim = Agent::new(0xA1, 1, "ocr", &["ocr"], 5);
        let attacker = Agent::new(0xE7, 1, "ocr", &["ocr"], 5); // 同地址不同密钥
        let card = victim.card(FOREVER);
        let hash = card.card_hash().unwrap();
        let cert = make_cert_wire(&ca, victim.a, &victim.pubkey(), FOREVER);
        let bad_sig = attacker.sk.sign(&agent_card_message(card.version, &hash, FOREVER, &victim.pubkey()));
        let pop = attacker.sk.sign(&ans_register_pop_message(&card.name, &text(1), &hash));
        let (bs, bp) = (bad_sig.to_bytes(), pop.to_bytes().to_vec());
        let spec = RegisterSpec { addr_text: &text(1), cert_wire: &cert, card: &card, card_sig: &bs, pop: &bp };
        assert_eq!(s.register(&spec, NOW).err(), Some(AnsError::BadCard), "错密钥 CardSig 必须先被拒");
    }

    #[test]
    fn register_rejects_bad_pop() {
        let ca = SigningKey::from_bytes(&CA_SEED);
        let mut s = svc();
        let ag = Agent::new(0xA1, 1, "ocr", &["ocr"], 5);
        let mut k = kit(&ca, &ag, FOREVER);
        k.pop = vec![0u8; 64];
        let t = text(1);
        assert_eq!(s.register(&spec_of(&k, &t), NOW).err(), Some(AnsError::BadProof));
    }

    #[test]
    fn register_rejects_pop_from_other_domain() {
        // 把 ANS PoP 域换成 register 域签名 → 验不过（域分隔）
        let ca = SigningKey::from_bytes(&CA_SEED);
        let mut s = svc();
        let ag = Agent::new(0xA1, 1, "ocr", &["ocr"], 5);
        let card = ag.card(FOREVER);
        let hash = card.card_hash().unwrap();
        let mut msg = Vec::new();
        msg.extend_from_slice(b"ipv8plus-register"); // 错误域
        msg.extend_from_slice(card.name.as_bytes());
        msg.extend_from_slice(text(1).as_bytes());
        msg.extend_from_slice(&hash);
        let pop = ag.sk.sign(&msg).to_bytes().to_vec();
        let k = Kit { card, cert: make_cert_wire(&ca, ag.a, &ag.pubkey(), FOREVER), card_sig: ag.sk.sign(&agent_card_message(CARD_VERSION, &hash, FOREVER, &ag.pubkey())).to_bytes(), pop, hash };
        let t = text(1);
        assert_eq!(s.register(&spec_of(&k, &t), NOW).err(), Some(AnsError::BadProof));
    }

    #[test]
    fn register_rejects_bad_card_fields() {
        let ca = SigningKey::from_bytes(&CA_SEED);
        let mut s = svc();
        // 版本不符
        let ag = Agent::new(0xA1, 1, "ocr", &["ocr"], 5);
        let mut k = kit(&ca, &ag, FOREVER);
        k.card.version = 99;
        let t = text(1);
        assert_eq!(s.register(&spec_of(&k, &t), NOW).err(), Some(AnsError::BadCard));
        // addr 不符
        let mut k2 = kit(&ca, &ag, FOREVER);
        k2.card.addr = addr(2);
        assert_eq!(s.register(&spec_of(&k2, &t), NOW).err(), Some(AnsError::BadCard));
        // not_after 已到期
        let mut k3 = kit(&ca, &ag, NOW);
        k3.card_sig = ag.sk.sign(&agent_card_message(CARD_VERSION, &k3.hash, NOW, &ag.pubkey())).to_bytes();
        let p = ag.sk.sign(&ans_register_pop_message(&ag.name, &text(1), &k3.hash)).to_bytes().to_vec();
        k3.pop = p;
        assert_eq!(s.register(&spec_of(&k3, &t), NOW).err(), Some(AnsError::BadCard));
    }

    #[test]
    fn register_rejects_bad_tags() {
        let ca = SigningKey::from_bytes(&CA_SEED);
        let mut s = svc();
        let ag = Agent::new(0xA1, 1, "ocr", &["OCR-BAD"], 5); // 大写非法
        let card = ag.card(FOREVER);
        let hash = card.card_hash().unwrap();
        let k = Kit {
            card,
            cert: make_cert_wire(&ca, ag.a, &ag.pubkey(), FOREVER),
            card_sig: ag.sk.sign(&agent_card_message(CARD_VERSION, &hash, FOREVER, &ag.pubkey())).to_bytes(),
            pop: ag.sk.sign(&ans_register_pop_message(&ag.name, &text(1), &hash)).to_bytes().to_vec(),
            hash,
        };
        let t = text(1);
        assert_eq!(s.register(&spec_of(&k, &t), NOW).err(), Some(AnsError::BadTags));
    }

    #[test]
    fn register_rejects_bad_name() {
        let ca = SigningKey::from_bytes(&CA_SEED);
        let mut s = svc();
        let ag = Agent::new(0xA1, 1, "ocr", &["ocr"], 5);
        let mut k = kit(&ca, &ag, FOREVER);
        k.card.name = "not-rooted.example".into(); // 不以 .ipv8.net 结尾
        // 名字进 PoP，需重签
        k.pop = ag.sk.sign(&ans_register_pop_message(&k.card.name, &text(1), &k.hash)).to_bytes().to_vec();
        let t = text(1);
        assert_eq!(s.register(&spec_of(&k, &t), NOW).err(), Some(AnsError::BadName));
    }

    #[test]
    fn register_rejects_bad_address_text() {
        let ca = SigningKey::from_bytes(&CA_SEED);
        let mut s = svc();
        let ag = Agent::new(0xA1, 1, "ocr", &["ocr"], 5);
        let k = kit(&ca, &ag, FOREVER);
        assert_eq!(s.register(&spec_of(&k, "not-hex"), NOW).err(), Some(AnsError::BadAddress));
    }

    #[test]
    fn same_key_re_register_updates_and_keeps_lease() {
        let ca = SigningKey::from_bytes(&CA_SEED);
        let mut s = svc();
        let ag = Agent::new(0xA1, 1, "ocr", &["ocr"], 5);
        let t = text(1);
        s.register(&spec_of(&kit(&ca, &ag, FOREVER), &t), NOW).unwrap();
        // 制造租约
        let plan = s.plan_task(&task(&["ocr"], 1, 0, 10_000), NOW).unwrap();
        s.register(&spec_of(&kit(&ca, &ag, FOREVER), &t), NOW + 5).unwrap();
        let r = s.resolve_addr(ag.a, NOW + 5).unwrap();
        // 更新后仍可解析，且 plan 未被夺约破坏（report_done 仍认得旧 plan_id）
        s.report_done(plan.plan_id, r.addr, NOW + 6).unwrap();
    }

    #[test]
    fn different_key_same_addr_is_conflict() {
        let ca = SigningKey::from_bytes(&CA_SEED);
        let mut s = svc();
        let t = text(1);
        s.register(&spec_of(&kit(&ca, &Agent::new(0xA1, 1, "ocr", &["ocr"], 5), FOREVER), &t), NOW).unwrap();
        // 换密钥（seed 0xB2）同地址登记 → KeyConflict
        let ag2 = Agent::new(0xB2, 1, "ocr2", &["ocr"], 5);
        assert_eq!(s.register(&spec_of(&kit(&ca, &ag2, FOREVER), &t), NOW).err(), Some(AnsError::KeyConflict));
    }

    #[test]
    fn name_conflict_across_live_addrs() {
        let ca = SigningKey::from_bytes(&CA_SEED);
        let mut s = svc();
        let a1 = Agent::new(0xA1, 1, "shared", &["ocr"], 5);
        let a2 = Agent::new(0xB2, 2, "shared", &["ocr"], 5);
        s.register(&spec_of(&kit(&ca, &a1, FOREVER), &text(1)), NOW).unwrap();
        assert_eq!(
            s.register(&spec_of(&kit(&ca, &a2, FOREVER), &text(2)), NOW).err(),
            Some(AnsError::NameConflict)
        );
    }

    #[test]
    fn expired_name_slot_reclaimed_on_rebind() {
        let ca = SigningKey::from_bytes(&CA_SEED);
        let mut s = svc();
        let a1 = Agent::new(0xA1, 1, "shared", &["ocr"], 5);
        s.register(&spec_of(&kit(&ca, &a1, FOREVER), &text(1)), NOW).unwrap();
        // a1 过期占位；a2 用同名不同地址，且先手动让 a1 过期
        let a2 = Agent::new(0xB2, 2, "shared", &["ocr"], 5);
        s.register(&spec_of(&kit(&ca, &a2, FOREVER), &text(2)), NOW).unwrap_err();
        // 让 a1 过期后重登记 a2 应成功（同名可被回收）
        s.register(&spec_of(&kit(&ca, &a1, NOW + 10), &text(1)), NOW).unwrap();
        // a1 not_after = NOW+10，在 NOW+20 已过期
        let _ = s.reap(NOW + 20);
        assert!(s.register(&spec_of(&kit(&ca, &a2, FOREVER), &text(2)), NOW + 20).is_ok());
    }

    // —— 直接寻址 ——

    #[test]
    fn resolve_name_returns_readmodel() {
        let ca = SigningKey::from_bytes(&CA_SEED);
        let mut s = svc();
        let ag = Agent::new(0xA1, 1, "ocr", &["ocr"], 5);
        s.register(&spec_of(&kit(&ca, &ag, FOREVER), &text(1)), NOW).unwrap();
        let r = s.resolve_name(&ag.name, NOW).unwrap();
        assert_eq!(r.addr, ag.a);
        assert_eq!(r.tunnel_entry, ag.card(FOREVER).tunnel_entry);
        assert_eq!(r.capabilities, vec!["ocr".to_string()]);
        assert_eq!(r.qos_hint, 5);
        assert_eq!(r.summary.agent_pubkey, ag.pubkey());
        assert_eq!(r.summary.card_hash, ag.card(FOREVER).card_hash().unwrap());
    }

    #[test]
    fn resolve_unknown_and_expired_are_indistinguishable() {
        let ca = SigningKey::from_bytes(&CA_SEED);
        let mut s = svc();
        let ag = Agent::new(0xA1, 1, "ocr", &["ocr"], 5);
        s.register(&spec_of(&kit(&ca, &ag, NOW + 100), &text(1)), NOW).unwrap();
        let unknown = s.resolve_name("ghost.ipv8.net", NOW).err();
        let expired = s.resolve_name(&ag.name, NOW + 101).err();
        assert_eq!(unknown, Some(AnsError::NotFound));
        assert_eq!(expired, Some(AnsError::NotFound), "过期与不存在必须不可区分");
    }

    // —— 能力寻址 ——

    fn caps(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }
    fn task(req: &[&str], min: usize, qos: u8, ms: u64) -> TaskDescription {
        TaskDescription { required_caps: caps(req), min_count: min, qos_level: qos, timeout_ms: ms }
    }

    #[test]
    fn capability_requires_full_cover() {
        let ca = SigningKey::from_bytes(&CA_SEED);
        let mut s = svc();
        s.register(&spec_of(&kit(&ca, &Agent::new(0xA1, 1, "multi", &["ocr", "tts"], 5), FOREVER), &text(1)), NOW).unwrap();
        // 只要求 {ocr,tts} 命中；{ocr,vision} 不命中（缺 vision）
        assert_eq!(s.search_capability(&caps(&["ocr", "tts"]), 0, true, NOW).len(), 1);
        assert_eq!(s.search_capability(&caps(&["ocr", "vision"]), 0, true, NOW).len(), 0);
        // 子集也命中：只要 agent 覆盖 required
        assert_eq!(s.search_capability(&caps(&["ocr"]), 0, true, NOW).len(), 1);
    }

    #[test]
    fn capability_qos_floor_filters() {
        let ca = SigningKey::from_bytes(&CA_SEED);
        let mut s = svc();
        s.register(&spec_of(&kit(&ca, &Agent::new(0xA1, 1, "lo", &["ocr"], 2), FOREVER), &text(1)), NOW).unwrap();
        s.register(&spec_of(&kit(&ca, &Agent::new(0xB2, 2, "hi", &["ocr"], 9), FOREVER), &text(2)), NOW).unwrap();
        let all = s.search_capability(&caps(&["ocr"]), 0, true, NOW);
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].qos_hint, 9, "高 qos 先");
        let hi = s.search_capability(&caps(&["ocr"]), 5, true, NOW);
        assert_eq!(hi.len(), 1);
        assert_eq!(hi[0].qos_hint, 9);
    }

    #[test]
    fn capability_orders_by_qos_then_ttl_then_addr() {
        let ca = SigningKey::from_bytes(&CA_SEED);
        let mut s = svc();
        // 同 qos，不同 TTL：TTL 大者先
        s.register(&spec_of(&kit(&ca, &Agent::new(0xA1, 3, "a", &["x"], 5), NOW + 100), &text(3)), NOW).unwrap();
        s.register(&spec_of(&kit(&ca, &Agent::new(0xB2, 1, "b", &["x"], 5), FOREVER), &text(1)), NOW).unwrap();
        let r = s.search_capability(&caps(&["x"]), 0, true, NOW);
        assert_eq!(r[0].name, "b.ipv8.net", "TTL 更长优先");
    }

    #[test]
    fn capability_excludes_leased_by_default() {
        let ca = SigningKey::from_bytes(&CA_SEED);
        let mut s = svc();
        s.register(&spec_of(&kit(&ca, &Agent::new(0xA1, 1, "a", &["ocr"], 5), FOREVER), &text(1)), NOW).unwrap();
        s.register(&spec_of(&kit(&ca, &Agent::new(0xB2, 2, "b", &["ocr"], 5), FOREVER), &text(2)), NOW).unwrap();
        let plan = s.plan_task(&task(&["ocr"], 1, 0, 10_000), NOW).unwrap();
        assert_eq!(plan.assignments.len(), 1);
        assert_eq!(s.search_capability(&caps(&["ocr"]), 0, true, NOW).len(), 1, "被租者排除");
        assert_eq!(s.search_capability(&caps(&["ocr"]), 0, false, NOW).len(), 2, "发现型不排除");
    }

    // —— 任务寻址 ——

    #[test]
    fn plan_task_fans_out_and_leases() {
        let ca = SigningKey::from_bytes(&CA_SEED);
        let mut s = svc();
        for (seed, n) in [(0xA1u8, 1u32), (0xB2, 2), (0xC3, 3)] {
            s.register(&spec_of(&kit(&ca, &Agent::new(seed, n, &format!("a{n}"), &["ocr"], 5), FOREVER), &text(n)), NOW).unwrap();
        }
        let p = s.plan_task(&task(&["ocr"], 2, 0, 30_000), NOW).unwrap();
        assert_eq!(p.assignments.len(), 2);
        assert_eq!(p.assignments[0].shard_id, 0);
        assert_eq!(p.assignments[1].shard_id, 1);
        // 租约 30s
        assert_eq!(p.assignments[0].lease_expiry, NOW + 30);
        // 两个被选者现在都不可再被规划
        assert_eq!(s.search_capability(&caps(&["ocr"]), 0, true, NOW).len(), 1);
    }

    #[test]
    fn plan_task_insufficient_keeps_state_untouched() {
        let ca = SigningKey::from_bytes(&CA_SEED);
        let mut s = svc();
        s.register(&spec_of(&kit(&ca, &Agent::new(0xA1, 1, "a", &["ocr"], 5), FOREVER), &text(1)), NOW).unwrap();
        let before = s.search_capability(&caps(&["ocr"]), 0, true, NOW).len();
        // 要 2 个，只有 1 个 → 失败且不建租约
        let e = s.plan_task(&task(&["ocr"], 2, 0, 30_000), NOW).err();
        assert_eq!(e, Some(AnsError::Insufficient { wanted: 2, got: 1 }));
        assert_eq!(s.search_capability(&caps(&["ocr"]), 0, true, NOW).len(), before);
    }

    #[test]
    fn plan_task_min_count_zero_rejected() {
        let mut s = svc();
        assert_eq!(s.plan_task(&task(&["ocr"], 0, 0, 1000), NOW).err(), Some(AnsError::Insufficient { wanted: 0, got: 0 }));
    }

    #[test]
    fn plan_task_lease_clamped_to_max() {
        let ca = SigningKey::from_bytes(&CA_SEED);
        let mut s = svc();
        s.register(&spec_of(&kit(&ca, &Agent::new(0xA1, 1, "a", &["ocr"], 5), FOREVER), &text(1)), NOW).unwrap();
        let p = s.plan_task(&task(&["ocr"], 1, 0, u64::MAX), NOW).unwrap();
        assert_eq!(p.assignments[0].lease_expiry, NOW + MAX_LEASE_SECS, "timeout 裁剪到 1h");
    }

    #[test]
    fn report_done_releases_lease() {
        let ca = SigningKey::from_bytes(&CA_SEED);
        let mut s = svc();
        let ag = Agent::new(0xA1, 1, "a", &["ocr"], 5);
        s.register(&spec_of(&kit(&ca, &ag, FOREVER), &text(1)), NOW).unwrap();
        let p = s.plan_task(&task(&["ocr"], 1, 0, 30_000), NOW).unwrap();
        assert_eq!(s.search_capability(&caps(&["ocr"]), 0, true, NOW).len(), 0);
        s.report_done(p.plan_id, ag.a, NOW).unwrap();
        assert_eq!(s.search_capability(&caps(&["ocr"]), 0, true, NOW).len(), 1, "回报后重获可用");
    }

    #[test]
    fn report_done_wrong_plan_or_unknown_rejected() {
        let ca = SigningKey::from_bytes(&CA_SEED);
        let mut s = svc();
        let ag = Agent::new(0xA1, 1, "a", &["ocr"], 5);
        s.register(&spec_of(&kit(&ca, &ag, FOREVER), &text(1)), NOW).unwrap();
        let p = s.plan_task(&task(&["ocr"], 1, 0, 30_000), NOW).unwrap();
        assert_eq!(s.report_done(p.plan_id + 999, ag.a, NOW).err(), Some(AnsError::NotFound), "错 plan");
        assert_eq!(s.report_done(p.plan_id, addr(77), NOW).err(), Some(AnsError::NotFound), "未知 addr");
        // 释放后再回报 → NotFound（无租约）
        s.report_done(p.plan_id, ag.a, NOW).unwrap();
        assert_eq!(s.report_done(p.plan_id, ag.a, NOW).err(), Some(AnsError::NotFound));
    }

    #[test]
    fn reap_releases_expired_leases_and_cards() {
        let ca = SigningKey::from_bytes(&CA_SEED);
        let mut s = svc();
        s.register(&spec_of(&kit(&ca, &Agent::new(0xA1, 1, "a", &["ocr"], 5), FOREVER), &text(1)), NOW).unwrap();
        let lease_ag = addr(1);
        s.plan_task(&task(&["ocr"], 1, 0, 5_000), NOW).unwrap(); // NOW+5 到期
        s.register(&spec_of(&kit(&ca, &Agent::new(0xB2, 2, "b", &["ocr"], 5), NOW + 100), &text(2)), NOW).unwrap();
        let (rel, exp) = s.reap(NOW + 6);
        assert_eq!(rel, 1, "a 租约 NOW+5 到期被释放");
        assert_eq!(exp, 0, "b 卡片 NOW+100 未过期");
        assert!(s.resolve_addr(lease_ag, NOW + 6).is_ok());
        let (rel2, exp2) = s.reap(NOW + 200);
        assert_eq!(rel2, 0);
        assert_eq!(exp2, 1, "b 卡片过期被摘除");
        assert_eq!(s.resolve_name("b.ipv8.net", NOW + 200).err(), Some(AnsError::NotFound));
    }

    // —— 覆盖/工具 ——

    #[test]
    fn covers_predicate_semantics() {
        assert!(covers(&caps(&["a", "b"]), &caps(&["a"])));
        assert!(covers(&caps(&["a", "b"]), &caps(&[])));
        assert!(!covers(&caps(&["a"]), &caps(&["a", "b"])));
        assert!(!covers(&caps(&["a", "b"]), &caps(&["c"])));
    }

    #[test]
    fn validate_tags_gate() {
        assert!(validate_tags(&caps(&["ocr", "image-gen"])).is_ok());
        assert!(validate_tags(&caps(&["OCR"])).is_err());
        assert!(validate_tags(&[]).is_err(), "空集非法");
    }

    #[test]
    fn ans_register_pop_message_layout() {
        let m = ans_register_pop_message("n.ipv8.net", "deadbeef", &[7u8; 16]);
        assert!(m.starts_with(ANS_REGISTER_DOMAIN));
        assert!(m.windows(10).any(|w| w == b"n.ipv8.net"));
        assert_eq!(&m[m.len() - 16..], &[7u8; 16]);
    }

    #[test]
    fn empty_service_observations() {
        let s = svc();
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
        assert_eq!(s.resolve_name("x.ipv8.net", NOW).err(), Some(AnsError::NotFound));
    }
}
