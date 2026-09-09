//! 扩展头载荷布局（protocol-spec §6.5 QoSReservation / §6.6 RouteTrace /
//! §6.7 AgentCard / §6.8 SemanticTag）。
//!
//! 纯编解码：结构合法性的严格校验在此，密码学验证（PathSig/CardSig/
//! 全文哈希）在 `ipv8-routing` 与 `ipv8-ans`（签名消息体的权威构造在
//! 本模块，保证签名与线上字节逐位一致）。载荷总长均满足 8 字节对齐，
//! 可直接放进 [`ExtensionHeader`]。

use crate::header::{IPv8Address, ExtType, AGENT_CARD_DOMAIN, ROUTE_TRACE_DOMAIN};

/// 布局层错误
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutError {
    /// 载荷长度与该头定义不符（§6.5 = 8B；§6.6 = 104+16N；§6.7 = 128B）
    BadLen,
    /// TokenBucketRate 超出 24 bit 可表达范围（§6.5 字节 0-2）
    RateTooLarge,
    /// HopCount=0 非法（§6.6 MUST 丢弃）
    EmptyHops,
    /// HopCount 协议上限 64（§6.6）
    TooManyHops,
    /// 能力标签为空（§6.8 至少 1 个）
    EmptyTags,
    /// 能力标签超 32 个（§6.8）
    TooManyTags,
    /// 单个标签不合法：空/超 48B/含非法字符/首尾连字符/非 UTF-8（§6.8）
    BadTag,
    /// 标签列表总载荷超 1536 字节（§6.8）
    TagsTooLong,
}

impl std::fmt::Display for LayoutError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadLen => write!(f, "扩展头载荷长度不符"),
            Self::RateTooLarge => write!(f, "TokenBucketRate 超 24 bit"),
            Self::EmptyHops => write!(f, "HopCount=0 非法"),
            Self::TooManyHops => write!(f, "HopCount 超协议上限 64"),
            Self::EmptyTags => write!(f, "能力标签列表为空"),
            Self::TooManyTags => write!(f, "能力标签超 32 个上限"),
            Self::BadTag => write!(f, "能力标签不合 §6.8 字符/长度规则"),
            Self::TagsTooLong => write!(f, "能力标签载荷总长超 1536 字节"),
        }
    }
}

impl std::error::Error for LayoutError {}

/// §6.5 QoSReservation：速率承诺（提示语义，中间节点只读）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QosReservation {
    /// TokenBucketRate，单位 KiB/s，24 bit；0 = 仅优先级提示无承诺
    pub rate_kibs: u32,
    /// BurstSize，16 bit；0 时速率承诺不生效
    pub burst_size: u16,
    /// 建议转发队列类（0-15），与 Flags QoS Level 独立
    pub queue_hint: u8,
}

impl QosReservation {
    /// 载荷字节偏移（spec §6.5）：rate 0-2 | burst 3-4 | hint 5 | rsv 6-7
    pub const PAYLOAD_LEN: usize = 8;

    pub fn to_payload(&self) -> Result<Vec<u8>, LayoutError> {
        if self.rate_kibs >= 1 << 24 {
            return Err(LayoutError::RateTooLarge);
        }
        let mut p = vec![0u8; Self::PAYLOAD_LEN];
        p[0..3].copy_from_slice(&self.rate_kibs.to_be_bytes()[1..4]); // 取低 24 bit
        p[3..5].copy_from_slice(&self.burst_size.to_be_bytes());
        p[5] = self.queue_hint;
        // p[6..8] 保留位：发送置 0（§2.2）
        Ok(p)
    }

    /// 接收方 MUST 忽略保留位（§2.2）：不校验 p[6..8]。
    pub fn from_payload(p: &[u8]) -> Result<Self, LayoutError> {
        if p.len() != Self::PAYLOAD_LEN {
            return Err(LayoutError::BadLen);
        }
        Ok(Self {
            rate_kibs: u32::from_be_bytes([0, p[0], p[1], p[2]]),
            burst_size: u16::from_be_bytes([p[3], p[4]]),
            queue_hint: p[5],
        })
    }
}

/// §6.6 RouteTrace：源路由 + 路径单次签名（ADR-019 决议）。
///
/// 载荷 = SrcPubKey(32) ‖ PathSig(64) ‖ HopCount(1) ‖ InitHopLimit(1) ‖
/// Rsv(6) ‖ 跳列表(16×N)。InitHopLimit 是签名覆盖的明文副本——基头
/// HopLimit 逐跳递减，中转以 `InitHopLimit − (下标+1) == 当前值` 校验。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteTrace {
    /// 源点 Ed25519 公钥（Phase 2 证书 verify_key；与 SrcAddr 的绑定
    /// 由证书经信任锚证明）
    pub src_pubkey: [u8; 32],
    /// PathSig：对 [`route_trace_message`] 的 Ed25519 签名
    pub path_sig: [u8; 64],
    /// 源点发出时刻的 HopLimit（spec §6.6 签名字段的明文副本）
    pub init_hop_limit: u8,
    /// NextHopList：第 i 项 = 从源点起第 i+1 跳地址；末项 MUST == DstAddr。
    /// 1..=64 项。
    pub hops: Vec<IPv8Address>,
}

impl RouteTrace {
    /// 固定头长度 = SrcPubKey(32) + PathSig(64) + HopCount(1) +
    /// InitHopLimit(1) + Rsv(6) = 104
    pub const HEADER_LEN: usize = 32 + 64 + 8; // 104
    const HOPCOUNT_IDX: usize = 32 + 64; // 96
    const INITHL_IDX: usize = 97;

    pub fn to_payload(&self) -> Result<Vec<u8>, LayoutError> {
        if self.hops.is_empty() {
            return Err(LayoutError::EmptyHops);
        }
        if self.hops.len() > 64 {
            return Err(LayoutError::TooManyHops);
        }
        let mut p = Vec::with_capacity(Self::HEADER_LEN + 16 * self.hops.len());
        p.extend_from_slice(&self.src_pubkey);
        p.extend_from_slice(&self.path_sig);
        p.push(self.hops.len() as u8);
        p.push(self.init_hop_limit);
        p.extend_from_slice(&[0u8; 6]); // 保留位发送置 0（§2.2）
        for h in &self.hops {
            p.extend_from_slice(&h.to_bytes());
        }
        Ok(p)
    }

    /// 严格长度：必须等于 104 + 16×HopCount（防截短/加长攻击）；
    /// 保留位（InitHopLimit 后的 6 字节）接收方忽略。
    pub fn from_payload(p: &[u8]) -> Result<Self, LayoutError> {
        if p.len() < Self::HEADER_LEN {
            return Err(LayoutError::BadLen);
        }
        let n = p[Self::HOPCOUNT_IDX] as usize;
        if n == 0 {
            return Err(LayoutError::EmptyHops);
        }
        if n > 64 {
            return Err(LayoutError::TooManyHops);
        }
        if p.len() != Self::HEADER_LEN + 16 * n {
            return Err(LayoutError::BadLen);
        }
        let mut hops = Vec::with_capacity(n);
        for i in 0..n {
            let b = &p[Self::HEADER_LEN + 16 * i..Self::HEADER_LEN + 16 * (i + 1)];
            hops.push(addr_from_wire(b));
        }
        Ok(Self {
            src_pubkey: p[0..32].try_into().expect("长度已校验"),
            path_sig: p[32..96].try_into().expect("长度已校验"),
            init_hop_limit: p[Self::INITHL_IDX],
            hops,
        })
    }
}

/// [`route_trace_message`] 的签名输入（spec §6.6 消息体的全部被签要素）。
#[derive(Debug, Clone, Copy)]
pub struct TraceSigInput<'a> {
    pub src_addr: &'a IPv8Address,
    pub dst_addr: &'a IPv8Address,
    pub min_compat_ver: u8,
    pub flags: u16,
    pub payload_len: u16,
    pub init_hop_limit: u8,
    pub src_pubkey: &'a [u8; 32],
    pub hops: &'a [IPv8Address],
}

/// PathSig 的权威消息体（spec §6.6）：
/// `domain ‖ SrcPubKey ‖ 基头字节0-6 ‖ SrcAddr ‖ DstAddr ‖ HopCount ‖ NextHopList`
///
/// 基头字节 0-6 = Version‖MinCompat(8) ‖ Flags(16) ‖ PayloadLen(16) ‖
/// InitHopLimit(8) ‖ NextHdr(8=RouteTrace 钉死)。注意消息体里的
/// HopLimit 字节用 **InitHopLimit**（签名时刻值），与 RouteTrace 明文副本
/// 同值——验证方从副本重建，不读逐跳递减的基头字节。
pub fn route_trace_message(i: &TraceSigInput<'_>) -> Vec<u8> {
    let mut m = Vec::with_capacity(
        ROUTE_TRACE_DOMAIN.len() + 32 + 7 + 16 + 16 + 1 + 16 * i.hops.len(),
    );
    m.extend_from_slice(ROUTE_TRACE_DOMAIN);
    m.extend_from_slice(i.src_pubkey);
    m.push((crate::header::VERSION << 4) | (i.min_compat_ver & 0x0F));
    m.extend_from_slice(&i.flags.to_be_bytes());
    m.extend_from_slice(&i.payload_len.to_be_bytes());
    m.push(i.init_hop_limit);
    m.push(ExtType::RouteTrace.wire()); // NextHdr 钉死 5：链首约束进签名
    m.extend_from_slice(&i.src_addr.to_bytes());
    m.extend_from_slice(&i.dst_addr.to_bytes());
    m.push(i.hops.len() as u8);
    for h in i.hops {
        m.extend_from_slice(&h.to_bytes());
    }
    m
}

/// 16 字节线格式 → 地址（Reserved 接收忽略，§3.1/§2.2）
fn addr_from_wire(b: &[u8]) -> IPv8Address {
    IPv8Address::new(
        u32::from_be_bytes(b[0..4].try_into().unwrap()),
        u32::from_be_bytes(b[4..8].try_into().unwrap()),
        u16::from_be_bytes(b[8..10].try_into().unwrap()),
        u16::from_be_bytes(b[10..12].try_into().unwrap()),
        b[12],
    )
}

/// §6.7 AgentCard（类型 4）：摘要进包 + ANS 拉全文（ADR-023）。
///
/// 载荷定长 128 字节：Version(1) ‖ Rsv(7) ‖ CardHash(16) ‖ NotAfter(8) ‖
/// AgentPubKey(32) ‖ CardSig(64)。CardSig 由**智能体自身密钥**签发——
/// 它是唯一把 CardHash 绑定到该 agent 的手段，缺签名的哈希可被换成
/// 受害卡片的合法值实现冒充投递（spec §6.7 规范理由）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentCardSummary {
    /// 卡片格式版本（当前 = 1）
    pub version: u8,
    /// SHA-256(全文规范字节)[0..16]（哈希计算在 ANS，布局层不引依赖）
    pub card_hash: [u8; 16],
    /// 卡片有效期 epoch 秒；0 = 已过期哨兵（接收方按过期处理）
    pub not_after: u64,
    /// 智能体 Ed25519 公钥（ANS 注册同一密钥）
    pub agent_pubkey: [u8; 32],
    /// 对 [`agent_card_message`] 的 Ed25519 签名
    pub card_sig: [u8; 64],
}

impl AgentCardSummary {
    pub const PAYLOAD_LEN: usize = 128; // ExtLen = 16

    pub fn to_payload(&self) -> Vec<u8> {
        let mut p = Vec::with_capacity(Self::PAYLOAD_LEN);
        p.push(self.version);
        p.extend_from_slice(&[0u8; 7]); // 保留位发送置 0（§2.2）
        p.extend_from_slice(&self.card_hash);
        p.extend_from_slice(&self.not_after.to_be_bytes());
        p.extend_from_slice(&self.agent_pubkey);
        p.extend_from_slice(&self.card_sig);
        p
    }

    /// 严格长度 128；保留位（1-7）接收忽略。
    pub fn from_payload(p: &[u8]) -> Result<Self, LayoutError> {
        if p.len() != Self::PAYLOAD_LEN {
            return Err(LayoutError::BadLen);
        }
        Ok(Self {
            version: p[0],
            card_hash: p[8..24].try_into().expect("长度已验"),
            not_after: u64::from_be_bytes(p[24..32].try_into().expect("长度已验")),
            agent_pubkey: p[32..64].try_into().expect("长度已验"),
            card_sig: p[64..128].try_into().expect("长度已验"),
        })
    }
}

/// CardSig 的权威消息体（spec §6.7）：
/// `domain ‖ Version(8) ‖ CardHash(128) ‖ NotAfter(64) ‖ AgentPubKey(256)`
pub fn agent_card_message(
    version: u8,
    card_hash: &[u8; 16],
    not_after: u64,
    agent_pubkey: &[u8; 32],
) -> Vec<u8> {
    let mut m = Vec::with_capacity(AGENT_CARD_DOMAIN.len() + 1 + 16 + 8 + 32);
    m.extend_from_slice(AGENT_CARD_DOMAIN);
    m.push(version);
    m.extend_from_slice(card_hash);
    m.extend_from_slice(&not_after.to_be_bytes());
    m.extend_from_slice(agent_pubkey);
    m
}

/// §6.8 SemanticTag（类型 2）：能力标签列表编解码。
///
/// 载荷 = UTF-8 标签以单个 US(0x1F) 分隔。本模块是格式唯一权威：
/// ANS 注册校验与包内解析共用，杜绝两套词汇漂移。
/// 接收侧对畸形载荷的处置是**忽略本头内容不丢包**（§6.8/§6.2），
/// 故 `parse` 返回 Err 时调用方丢内容、不丢包。
pub struct SemanticTags;

impl SemanticTags {
    /// 单标签字节上限（§6.8）
    pub const MAX_TAG_LEN: usize = 48;
    /// 标签数上限（§6.8）
    pub const MAX_TAGS: usize = 32;
    /// 载荷总长上限（§6.8）
    pub const MAX_PAYLOAD: usize = 1536;
    /// 分隔符 U+001F（UTF-8 单字节）
    const SEP: u8 = 0x1F;

    /// 编码并校验每个标签（发送侧严格：不合法直接拒发）
    pub fn encode(tags: &[&str]) -> Result<Vec<u8>, LayoutError> {
        if tags.is_empty() {
            return Err(LayoutError::EmptyTags);
        }
        if tags.len() > Self::MAX_TAGS {
            return Err(LayoutError::TooManyTags);
        }
        for t in tags {
            Self::check_tag(t)?;
        }
        let mut p = tags.join("\u{1f}").into_bytes();
        if p.len() > Self::MAX_PAYLOAD {
            return Err(LayoutError::TagsTooLong);
        }
        // ExtensionHeader 要求 8B 对齐：0 填充由头长度字段隐含，
        // 解析以 US 计数为准——此处补齐到 8 的倍数（填充不参与标签集）
        while !p.len().is_multiple_of(8) {
            p.push(0);
        }
        Ok(p)
    }

    /// 解码并逐个校验；任何不合法 → Err（调用方忽略内容保包）
    pub fn decode(p: &[u8]) -> Result<Vec<String>, LayoutError> {
        if p.is_empty() || p.len() > Self::MAX_PAYLOAD {
            return Err(if p.is_empty() { LayoutError::EmptyTags } else { LayoutError::TagsTooLong });
        }
        // 去除尾部的 8 字节对齐零填充：有效载荷 = 至最后一个 US 段结束；
        // 更稳的规则：按 US 切分后，末段允许被 \0 填充尾巴污染，先剥尾零
        let trimmed = trim_pad(p);
        let parts: Vec<&[u8]> = trimmed.split(|b| *b == Self::SEP).collect();
        if parts.len() > Self::MAX_TAGS {
            return Err(LayoutError::TooManyTags);
        }
        let mut out = Vec::with_capacity(parts.len());
        for part in parts {
            let s = std::str::from_utf8(part).map_err(|_| LayoutError::BadTag)?;
            Self::check_tag(s)?;
            out.push(s.to_string());
        }
        Ok(out)
    }

    /// §6.8 单标签规则：1..=48B、小写 a-z0-9-、不以 '-' 开头/结尾
    fn check_tag(t: &str) -> Result<(), LayoutError> {
        let b = t.as_bytes();
        if b.is_empty() || b.len() > Self::MAX_TAG_LEN {
            return Err(LayoutError::BadTag);
        }
        if b[0] == b'-' || b[b.len() - 1] == b'-' {
            return Err(LayoutError::BadTag);
        }
        if !b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-') {
            return Err(LayoutError::BadTag);
        }
        Ok(())
    }
}

/// 剥离编码尾部的对齐零填充（US 分隔的标签内容不含 0x00，安全）
fn trim_pad(p: &[u8]) -> &[u8] {
    let mut end = p.len();
    while end > 0 && p[end - 1] == 0 {
        end -= 1;
    }
    &p[..end]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::{ExtensionHeader, IPv8Header};

    fn addr(n: u32) -> IPv8Address {
        IPv8Address::new(0xfb14, n, 1, 0x2a, 1)
    }

    #[test]
    fn qos_roundtrip_and_offsets() {
        let q = QosReservation { rate_kibs: 0x12_3456, burst_size: 0xABCD, queue_hint: 7 };
        let p = q.to_payload().unwrap();
        assert_eq!(p.len(), QosReservation::PAYLOAD_LEN);
        // spec §6.5 偏移表逐字节锁定
        assert_eq!(&p[0..3], &[0x12, 0x34, 0x56]);
        assert_eq!(&p[3..5], &[0xAB, 0xCD]);
        assert_eq!(p[5], 7);
        assert_eq!(&p[6..8], &[0, 0], "保留位发送置 0");
        assert_eq!(QosReservation::from_payload(&p).unwrap(), q);
    }

    #[test]
    fn qos_rate_overflow_rejected() {
        let q = QosReservation { rate_kibs: 1 << 24, burst_size: 0, queue_hint: 0 };
        assert_eq!(q.to_payload().err(), Some(LayoutError::RateTooLarge));
    }

    #[test]
    fn qos_reserved_bits_ignored_on_receive() {
        let mut p = vec![0u8; 8];
        p[6] = 0xFF; // §2.2：保留位非零不得丢包
        let q = QosReservation::from_payload(&p).unwrap();
        assert_eq!(q.rate_kibs, 0);
    }

    #[test]
    fn routetrace_roundtrip_payload_multiple_of_8() {
        let rt = RouteTrace {
            src_pubkey: [0xA1; 32],
            path_sig: [0xB2; 64],
            init_hop_limit: 64,
            hops: vec![addr(2), addr(3), addr(4)],
        };
        let p = rt.to_payload().unwrap();
        assert_eq!(p.len(), 104 + 48);
        assert_eq!(p.len() % 8, 0, "ExtLen 单位 8B 必须整除");
        assert_eq!(p[RouteTrace::HOPCOUNT_IDX], 3, "HopCount 偏移 96");
        assert_eq!(p[RouteTrace::INITHL_IDX], 64, "InitHopLimit 偏移 97");
        assert_eq!(RouteTrace::from_payload(&p).unwrap(), rt);
        // 载荷可被 ExtensionHeader 接纳（链式编解码复用现有通道）
        assert!(ExtensionHeader::new(ExtType::RouteTrace, p.clone()).is_some());
    }

    #[test]
    fn routetrace_strict_length_checks() {
        let rt = RouteTrace {
            src_pubkey: [0u8; 32],
            path_sig: [0u8; 64],
            init_hop_limit: 64,
            hops: vec![addr(9)],
        };
        let mut p = rt.to_payload().unwrap();
        p.truncate(104 + 16 - 1); // 截短 1 字节 → 拒
        assert_eq!(RouteTrace::from_payload(&p).err(), Some(LayoutError::BadLen));
        p = rt.to_payload().unwrap();
        p.extend_from_slice(&[0u8; 16]); // 加长一跳 → 拒
        assert_eq!(RouteTrace::from_payload(&p).err(), Some(LayoutError::BadLen));
    }

    #[test]
    fn routetrace_hop_bounds() {
        let empty = RouteTrace {
            src_pubkey: [0; 32],
            path_sig: [0; 64],
            init_hop_limit: 64,
            hops: vec![],
        };
        assert_eq!(empty.to_payload().err(), Some(LayoutError::EmptyHops));
        let many = RouteTrace {
            src_pubkey: [0; 32],
            path_sig: [0; 64],
            init_hop_limit: 64,
            hops: (0..65).map(|i| addr(i + 1)).collect(),
        };
        assert_eq!(many.to_payload().err(), Some(LayoutError::TooManyHops));
    }

    #[test]
    fn routetrace_survives_full_wire_roundtrip() {
        // 定稿布局必须能穿过既有 encode/decode 链式通道（§6.2 零改动兼容）
        let rt = RouteTrace {
            src_pubkey: [0xC3; 32],
            path_sig: [0xD7; 64],
            init_hop_limit: 64,
            hops: vec![addr(20), addr(30)],
        };
        let mut hdr = IPv8Header::new(addr(1), addr(30), 8);
        hdr.attach_ext_headers(vec![
            ExtensionHeader::new(ExtType::RouteTrace, rt.to_payload().unwrap()).unwrap(),
            ExtensionHeader::new(ExtType::IdentityToken, vec![0xEE; 8]).unwrap(),
        ]);
        let pkt = crate::encode(&hdr, b"payload!").unwrap();
        assert_eq!(pkt[6], ExtType::RouteTrace.wire(), "RouteTrace 必须居链首");
        let d = crate::decode(&pkt).unwrap();
        assert_eq!(d.header, hdr);
        let back = RouteTrace::from_payload(&d.header.ext_headers[0].payload).unwrap();
        assert_eq!(back, rt);
    }

    #[test]
    fn signed_message_covers_all_frozen_fields() {
        // spec §6.6：任一被签要素变化必须使消息体改变（防改写/防延展）
        let (a, b, c, d) = (addr(1), addr(2), addr(3), addr(4));
        let pk = [0xA1u8; 32];
        let hops = [c, d];
        let base_in = TraceSigInput {
            src_addr: &a,
            dst_addr: &b,
            min_compat_ver: 0,
            flags: 0x40,
            payload_len: 16,
            init_hop_limit: 64,
            src_pubkey: &pk,
            hops: &hops,
        };
        let base = route_trace_message(&base_in);
        assert!(base.starts_with(b"ipv8plus-routetrace"), "域分隔前缀");
        // 域之后立刻是 SrcPubKey：公钥替换攻击改变消息体
        let evil = [0xB2u8; 32];
        assert_ne!(route_trace_message(&TraceSigInput { src_pubkey: &evil, ..base_in }), base);
        // MinCompatVer / Flags / PayloadLen / InitHopLimit 逐字段敏感
        assert_ne!(route_trace_message(&TraceSigInput { min_compat_ver: 1, ..base_in }), base);
        assert_ne!(route_trace_message(&TraceSigInput { flags: 0x41, ..base_in }), base);
        assert_ne!(route_trace_message(&TraceSigInput { payload_len: 17, ..base_in }), base);
        assert_ne!(route_trace_message(&TraceSigInput { init_hop_limit: 63, ..base_in }), base);
        // 地址/列表变化同样敏感（NextHdr 恒 5 由构造函数钉死，无需变异测试）
        assert_ne!(
            route_trace_message(&TraceSigInput { src_addr: &b, dst_addr: &a, ..base_in }),
            base,
            "src/dst 互换未检出"
        );
        let rev = [d, c];
        assert_ne!(route_trace_message(&TraceSigInput { hops: &rev[..], ..base_in }), base, "跳序篡改未检出");
        assert_ne!(route_trace_message(&TraceSigInput { hops: &hops[..1], ..base_in }), base, "截短一跳未检出");
    }

    // —— §6.7 AgentCard ——

    fn card() -> AgentCardSummary {
        AgentCardSummary {
            version: 1,
            card_hash: [0xA5; 16],
            not_after: 0x0102_0304_0506_0708,
            agent_pubkey: [0xB4; 32],
            card_sig: [0xC7; 64],
        }
    }

    #[test]
    fn agentcard_roundtrip_and_offsets() {
        let c = card();
        let p = c.to_payload();
        assert_eq!(p.len(), AgentCardSummary::PAYLOAD_LEN);
        assert!(p.len().is_multiple_of(8)); // ExtLen=16 整除
        // spec §6.7 偏移表逐字节锁定
        assert_eq!(p[0], 1);
        assert_eq!(&p[1..8], &[0u8; 7], "保留位发送置 0");
        assert_eq!(&p[8..24], &[0xA5; 16]);
        assert_eq!(&p[24..32], &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        assert_eq!(&p[32..64], &[0xB4; 32]);
        assert_eq!(&p[64..128], &[0xC7; 64]);
        assert_eq!(AgentCardSummary::from_payload(&p).unwrap(), c);
    }

    #[test]
    fn agentcard_strict_length() {
        let p = card().to_payload();
        assert_eq!(AgentCardSummary::from_payload(&p[..127]).err(), Some(LayoutError::BadLen));
        let mut long = p.clone();
        long.extend_from_slice(&[0u8; 8]); // 多一个 ExtLen 单位也拒（定长头）
        assert_eq!(AgentCardSummary::from_payload(&long).err(), Some(LayoutError::BadLen));
    }

    #[test]
    fn agentcard_reserved_ignored_on_receive() {
        let mut p = card().to_payload();
        p[3] = 0xFF; // §2.2：保留位非零不得丢包
        assert_eq!(AgentCardSummary::from_payload(&p).unwrap(), card());
    }

    #[test]
    fn agentcard_message_domain_and_sensitivity() {
        let c = card();
        let base = agent_card_message(c.version, &c.card_hash, c.not_after, &c.agent_pubkey);
        assert!(base.starts_with(b"ipv8plus-agentcard"), "域分隔前缀");
        // 四个被签要素逐一敏感（CardSig 的防冒充语义：哈希/密钥/期限都不能换）
        assert_ne!(agent_card_message(2, &c.card_hash, c.not_after, &c.agent_pubkey), base);
        assert_ne!(agent_card_message(c.version, &[0x00; 16], c.not_after, &c.agent_pubkey), base);
        assert_ne!(agent_card_message(c.version, &c.card_hash, c.not_after - 1, &c.agent_pubkey), base);
        assert_ne!(agent_card_message(c.version, &c.card_hash, c.not_after, &[0x99; 32]), base);
    }

    // —— §6.8 SemanticTag ——

    #[test]
    fn semantictags_roundtrip_and_padding() {
        let tags = vec!["ocr", "image-gen", "v2-api"];
        let p = SemanticTags::encode(&tags).unwrap();
        assert!(p.len().is_multiple_of(8), "8B 对齐才能进 ExtensionHeader");
        assert_eq!(&p[..8], b"ocr\x1fimag", "US 单字节分隔");
        assert_eq!(SemanticTags::decode(&p).unwrap(), tags);
        // 恰好对齐的载荷也正常（无填充）
        let t8 = vec!["abcdefgh"];
        let p8 = SemanticTags::encode(&t8).unwrap();
        assert_eq!(p8.len(), 8);
        assert_eq!(SemanticTags::decode(&p8).unwrap(), t8);
    }

    #[test]
    fn semantictags_reject_bad_chars_and_shape() {
        // 大写 / 首尾连字符 / 空标签 / 非法字符 / 超 48B
        for bad in ["OCR", "-lead", "trail-", "", "has space", "标", &"x".repeat(49)] {
            assert_eq!(
                SemanticTags::encode(&[bad]).err(),
                Some(LayoutError::BadTag),
                "标签 {bad:?} 必须被拒"
            );
        }
        // 数字与连字符中置合法
        assert!(SemanticTags::encode(&["a1-b2"]).is_ok());
    }

    #[test]
    fn semantictags_bounds() {
        let many: Vec<&str> = (0..33).map(|i| if i % 2 == 0 { "aa" } else { "bb" }).collect();
        // 33 个 → 超限（去重后仍按个数计）
        assert_eq!(SemanticTags::encode(&many).err(), Some(LayoutError::TooManyTags));
        let empty: Vec<&str> = vec![];
        assert_eq!(SemanticTags::encode(&empty).err(), Some(LayoutError::EmptyTags));
        // 32 个 48B 标签 = 1568+31 > 1536 → 总长拒
        let big = "x".repeat(48);
        let manybig: Vec<&str> = (0..32).map(|_| big.as_str()).collect();
        assert_eq!(SemanticTags::encode(&manybig).err(), Some(LayoutError::TagsTooLong));
    }

    #[test]
    fn semantictags_decode_rejects_garbage_keeps_packet_semantics() {
        // 非 UTF-8 载荷 → decode Err（调用方忽略内容不丢包，§6.8）
        let bad = [0xFFu8; 8];
        assert!(SemanticTags::decode(&bad).is_err());
        // 空载荷 → EmptyTags
        assert_eq!(SemanticTags::decode(&[]).err(), Some(LayoutError::EmptyTags));
    }

    #[test]
    fn agentcard_and_semantictags_survive_wire_chain() {
        // 定稿布局穿过既有 encode/decode 链式通道（§6.2 零改动兼容）
        let c = card();
        let tags = SemanticTags::encode(&["ocr", "summarize"]).unwrap();
        let mut hdr = IPv8Header::new(addr(1), addr(2), 8);
        hdr.attach_ext_headers(vec![
            ExtensionHeader::new(ExtType::AgentCard, c.to_payload()).unwrap(),
            ExtensionHeader::new(ExtType::SemanticTag, tags).unwrap(),
        ]);
        let pkt = crate::encode(&hdr, b"payload!").unwrap();
        let d = crate::decode(&pkt).unwrap();
        assert_eq!(d.header, hdr);
        assert_eq!(AgentCardSummary::from_payload(&d.header.ext_headers[0].payload).unwrap(), c);
        assert_eq!(
            SemanticTags::decode(&d.header.ext_headers[1].payload).unwrap(),
            vec!["ocr".to_string(), "summarize".to_string()]
        );
    }
}
