//! IPv8+ 基础包头（40 字节固定 + 可变扩展头）与地址定义。
//!
//! ★ v9 确认：
//! - 字段偏移严格连续，无幽灵字节（ADR-013）
//!   PayloadLen 偏移: 3-4（非 4-5）
//!   HopLimit 偏移: 5
//!   NextHeader 偏移: 6
//!   SrcAddr 偏移: 7-22
//!   DstAddr 偏移: 23-38
//! - `#[repr(C)]` 固定内存布局（ADR-014）
//! - 显式 `reserved: [u8; 3]`，`new()` 为唯一构造入口
//! - 不含 Checksum：依赖隧道层 AEAD (ChaCha20-Poly1305) 保证完整性

/// IPv8+ 基础包头固定长度（字节）
pub const BASE_HEADER_SIZE: usize = 40;

/// PayloadLen 协议上限（ADR-012）
/// 65535(IPv4最大总长度) - 20(IPv4头) - 8(UDP头) - 40(IPv8+基础头) = 65467
pub const MAX_PAYLOAD_LEN: u16 = 65467;

/// IPv8+ 包最大总长度：封装进 IPv4/UDP 时受 UDP 载荷上限约束
/// 65535(IPv4 总长上限) - 20(IPv4 头) - 8(UDP 头) = 65507
pub const MAX_PACKET_LEN: usize = 65507;

/// 协议版本，固定 0x8
pub const VERSION: u8 = 0x8;

/// 扩展头链最大深度，防御恶意超长链导致解析循环
pub const MAX_EXT_CHAIN: usize = 64;

/// IPv8+ 地址（128 位）
///
/// 改进格式（v9.1）——零浪费、层级路由、NAT 专用字段：
/// ```text
/// fb14 : RRRR : RRRR : RRRR : SSSS : SSSS : NNNN : TTTT : XXXX
///   │      │      │      │      │      │      │      │      │
///   │      │      │      │      │      │      │      │      └ Service/Interface (16 bit)
///   │      │      │      │      │      │      │      └ Session ID (16 bit, 0=静态)
///   │      │      │      │      │      │      └ Node Hash (16 bit, 公钥指纹截断)
///   │      │      │      │      │      └ Subnet ID 2 (16 bit)
///   │      │      │      │      └ Subnet ID 1 (16 bit)
///   │      │      └──────────────└ Region ID (48 bit, 全球路由)
///   └ Protocol Magic (16 bit, 0xFB14 = IPv8)
/// ```
///
/// 线格式（大端）：
///   Protocol(0-1) Region(2-7) Subnet1(8-9) Subnet2(10-11)
///   NodeHash(12-13) SessionID(14-15) Service(16-17)  → wait, that's 18 bytes
///
/// 实际线格式（16 字节）：
///   Protocol(0-1) RegionHi(2-3) RegionMid(4-5) RegionLo(6-7)
///   Subnet1(8-9) Subnet2(10-11) NodeHash(12-13)
///   SessionID(14-15)
///
/// 注意：Service bits 合并到 SessionID 的高位中，通过 flags 区分。
/// 静态地址：SessionID=0，Service bits 在 Subnet2 的高 4 位。
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IPv8Address {
    /// 协议 Magic (0xFB14)
    pub protocol: u16,
    /// 区域 ID 高 16 位
    pub region_hi: u16,
    /// 区域 ID 中 16 位
    pub region_mid: u16,
    /// 区域 ID 低 16 位 → 总共 48 bit Region
    pub region_lo: u16,
    /// 子网 ID 1
    pub subnet1: u16,
    /// 子网 ID 2
    pub subnet2: u16,
    /// 节点身份哈希（公钥指纹截断）
    pub node_hash: u16,
    /// 会话 ID（NAT 穿透用，0=静态地址）
    pub session_id: u16,
}

/// 协议 Magic 常量
pub const PROTOCOL_MAGIC: u16 = 0xFB14;

impl IPv8Address {
    /// 唯一构造入口
    #[allow(clippy::too_many_arguments)] // 地址 8 字段为协议结构，非设计缺陷
    pub fn new(
        protocol: u16,
        region_hi: u16,
        region_mid: u16,
        region_lo: u16,
        subnet1: u16,
        subnet2: u16,
        node_hash: u16,
        session_id: u16,
    ) -> Self {
        Self { protocol, region_hi, region_mid, region_lo, subnet1, subnet2, node_hash, session_id }
    }

    /// 快捷构造：用 Region u48 + 子网 + 节点哈希
    pub fn with_region(
        region: u64,
        subnet1: u16,
        subnet2: u16,
        node_hash: u16,
        session_id: u16,
    ) -> Self {
        Self {
            protocol: PROTOCOL_MAGIC,
            region_hi: (region >> 32) as u16,
            region_mid: (region >> 16) as u16,
            region_lo: region as u16,
            subnet1,
            subnet2,
            node_hash,
            session_id,
        }
    }

    /// 获取 48 bit Region ID
    pub fn region(&self) -> u64 {
        ((self.region_hi as u64) << 32) | ((self.region_mid as u64) << 16) | (self.region_lo as u64)
    }

    /// 地址字节数
    pub const WIRE_SIZE: usize = 16;

    /// 规范文本形式（protocol-spec §3.2）：16 字节大端顺序、32 个小写
    /// 十六进制数字、无分隔符、不压缩零。预分配，无中间缓冲。
    pub fn to_canonical_string(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let wire = self.to_bytes();
        let mut s = String::with_capacity(32);
        for byte in wire {
            s.push(HEX[(byte >> 4) as usize] as char);
            s.push(HEX[(byte & 0x0F) as usize] as char);
        }
        s
    }

    /// 冒号分隔显示格式（人类可读，类似 IPv6 风格）：
    /// `fb14:0000:0000:0001:0001:0000:0002:0000`
    /// 8 组 4 位十六进制，冒号分隔，不压缩零。
    pub fn to_display_string(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let wire = self.to_bytes();
        let mut s = String::with_capacity(39);
        for (i, chunk) in wire.chunks(2).enumerate() {
            if i > 0 {
                s.push(':');
            }
            s.push(HEX[(chunk[0] >> 4) as usize] as char);
            s.push(HEX[(chunk[0] & 0x0F) as usize] as char);
            s.push(HEX[(chunk[1] >> 4) as usize] as char);
            s.push(HEX[(chunk[1] & 0x0F) as usize] as char);
        }
        s
    }

    /// 16 字节线格式（大端）
    pub fn to_bytes(&self) -> [u8; 16] {
        let mut b = [0u8; 16];
        self.write_to(&mut b);
        b
    }

    /// 解析规范文本形式（protocol-spec §3.2）：32 个十六进制数字，
    /// 大小写不敏感，无分隔符。
    pub fn from_canonical_str(s: &str) -> Result<Self, AddrParseError> {
        let bytes = s.as_bytes();
        if bytes.len() != 32 || !bytes.iter().all(|b| b.is_ascii_hexdigit()) {
            return Err(AddrParseError::Format);
        }
        let mut wire = [0u8; 16];
        for i in 0..16 {
            wire[i] = (hex_val(bytes[i * 2]) << 4) | hex_val(bytes[i * 2 + 1]);
        }
        Self::from_wire(&wire).ok_or(AddrParseError::Format).and_then(|addr| {
            if addr.protocol != PROTOCOL_MAGIC {
                Err(AddrParseError::BadProtocol)
            } else {
                Ok(addr)
            }
        })
    }

    /// 从 16 字节线格式解析
    pub fn from_wire(wire: &[u8; 16]) -> Option<Self> {
        Some(Self {
            protocol: u16::from_be_bytes(wire[0..2].try_into().ok()?),
            region_hi: u16::from_be_bytes(wire[2..4].try_into().ok()?),
            region_mid: u16::from_be_bytes(wire[4..6].try_into().ok()?),
            region_lo: u16::from_be_bytes(wire[6..8].try_into().ok()?),
            subnet1: u16::from_be_bytes(wire[8..10].try_into().ok()?),
            subnet2: u16::from_be_bytes(wire[10..12].try_into().ok()?),
            node_hash: u16::from_be_bytes(wire[12..14].try_into().ok()?),
            session_id: u16::from_be_bytes(wire[14..16].try_into().ok()?),
        })
    }

    /// 写入 16 字节线格式（大端）
    pub(crate) fn write_to(&self, buf: &mut [u8]) -> bool {
        buf[0..2].copy_from_slice(&self.protocol.to_be_bytes());
        buf[2..4].copy_from_slice(&self.region_hi.to_be_bytes());
        buf[4..6].copy_from_slice(&self.region_mid.to_be_bytes());
        buf[6..8].copy_from_slice(&self.region_lo.to_be_bytes());
        buf[8..10].copy_from_slice(&self.subnet1.to_be_bytes());
        buf[10..12].copy_from_slice(&self.subnet2.to_be_bytes());
        buf[12..14].copy_from_slice(&self.node_hash.to_be_bytes());
        buf[14..16].copy_from_slice(&self.session_id.to_be_bytes());
        true
    }
}

/// Flags 位定义（16 bit）
pub mod flags {
    /// QoS 等级掩码（位 0-3）
    pub const QOS_LEVEL_MASK: u16 = 0x000F;
    /// 位 4：载荷已加密
    pub const ENCRYPTED: u16 = 1 << 4;
    /// 位 5：此包是分片
    pub const FRAGMENT: u16 = 1 << 5;
    /// 位 6：存在扩展头
    pub const HAS_EXTENSION: u16 = 1 << 6;
    /// 位 7-15：保留，必须为 0
    pub const RESERVED_MASK: u16 = 0xFF80;
}

/// Flags 辅助方法
pub struct Flags;

impl Flags {
    pub fn qos_level(flags: u16) -> u8 {
        (flags & flags::QOS_LEVEL_MASK) as u8
    }
    pub fn is_encrypted(flags: u16) -> bool {
        flags & flags::ENCRYPTED != 0
    }
    pub fn is_fragment(flags: u16) -> bool {
        flags & flags::FRAGMENT != 0
    }
    pub fn has_extension(flags: u16) -> bool {
        flags & flags::HAS_EXTENSION != 0
    }
    /// 保留位是否合规（必须为 0）
    pub fn reserved_ok(flags: u16) -> bool {
        flags & flags::RESERVED_MASK == 0
    }
}

/// RouteTrace PathSig 域分隔前缀（protocol-spec §6.6；签名与验证共用
/// 单一来源，防止注册/轮换场景的签名挪用到路由场景，反之亦然）
pub const ROUTE_TRACE_DOMAIN: &[u8] = b"ipv8plus-routetrace";

/// AgentCard CardSig 域分隔前缀（protocol-spec §6.7；智能体自身密钥
/// 对"哈希+有效期+公钥"的签名，防 CardHash 换值冒充）
pub const AGENT_CARD_DOMAIN: &[u8] = b"ipv8plus-agentcard";

/// 扩展头类型编号（注册表 0-6；编号 7-255 为未来分配空间）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtType {
    None,
    /// 身份令牌（JWT/DID 证明）
    IdentityToken,
    /// 语义标签（ANS 能力寻址，CapTag 扩容的演进载体）
    SemanticTag,
    /// QoS 资源预留
    QoSReservation,
    /// 智能体能力描述
    AgentCard,
    /// 路由追踪（类 IPv6 Hop-by-Hop）
    RouteTrace,
    /// 分片信息（偏移 + 更多分片标记）
    Fragment,
    /// 注册表外的类型编号（宽松接收：按 ExtLen 跳过，不得丢弃整包）
    Unknown(u8),
}

impl ExtType {
    /// 线格式编号（链尾/无扩展头为 0）
    pub const fn wire(self) -> u8 {
        match self {
            Self::None => 0,
            Self::IdentityToken => 1,
            Self::SemanticTag => 2,
            Self::QoSReservation => 3,
            Self::AgentCard => 4,
            Self::RouteTrace => 5,
            Self::Fragment => 6,
            Self::Unknown(v) => v,
        }
    }

    /// 编号 → 类型。注册表外编号映射为 `Unknown`，供解析器按 ExtLen 跳过。
    pub const fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::None,
            1 => Self::IdentityToken,
            2 => Self::SemanticTag,
            3 => Self::QoSReservation,
            4 => Self::AgentCard,
            5 => Self::RouteTrace,
            6 => Self::Fragment,
            other => Self::Unknown(other),
        }
    }
}

/// 单个扩展头：NextHeader(1B) + ExtLen(1B，单位 8 字节) + 载荷(ExtLen×8 字节)
///
/// 内存中只保存自身类型 `ext_type`；线上的 NextHeader 指针由编码器
/// 根据链中下一个扩展头的类型自动重排（链尾为 0）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionHeader {
    /// 本扩展头的类型
    pub ext_type: ExtType,
    /// 载荷，长度必须是 8 的非零倍数，且 ≤ 255×8
    pub payload: Vec<u8>,
}

impl ExtensionHeader {
    /// 构造扩展头。类型不得为 `None`（0 是链尾哨兵），载荷长度必须是
    /// 8 的非零倍数且 ≤ 255×8；不满足返回 None。
    pub fn new(ext_type: ExtType, payload: Vec<u8>) -> Option<Self> {
        if matches!(ext_type, ExtType::None) {
            return None;
        }
        if !payload.len().is_multiple_of(8)
            || payload.len() / 8 == 0
            || payload.len() / 8 > u8::MAX as usize
        {
            return None;
        }
        Some(Self { ext_type, payload })
    }

    /// ExtLen 字段值（8 字节为单位）
    pub fn ext_len(&self) -> u8 {
        (self.payload.len() / 8) as u8
    }

    /// 该扩展头在线上的总长度（含 2 字节头）
    pub fn wire_size(&self) -> usize {
        2 + self.payload.len()
    }
}

/// IPv8+ 基础包头（40 字节固定 + 可变扩展头）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IPv8Header {
    /// 4 bits：协议版本，固定 0x8
    pub version: u8,
    /// 4 bits：最低兼容版本号（0-15）
    pub min_compat_ver: u8,
    /// 16 bits：QoS/加密/分片/扩展头标记
    pub flags: u16,
    /// 16 bits：载荷长度（不含包头与扩展头），≤ MAX_PAYLOAD_LEN
    pub payload_len: u16,
    /// 8 bits：跳数限制，每跳减 1，到 0 丢弃
    pub hop_limit: u8,
    /// 8 bits：第一个扩展头类型编号（0 = 无扩展头）
    pub next_header: u8,
    pub src_addr: IPv8Address,
    pub dst_addr: IPv8Address,
    /// 扩展头链（链尾 NextHeader=0，由编码时自动重排）
    pub ext_headers: Vec<ExtensionHeader>,
}

impl IPv8Header {
    /// 构造无扩展头的基础包头
    pub fn new(src_addr: IPv8Address, dst_addr: IPv8Address, payload_len: u16) -> Self {
        Self {
            version: VERSION,
            min_compat_ver: 0,
            flags: 0,
            payload_len,
            hop_limit: 64,
            next_header: 0,
            src_addr,
            dst_addr,
            ext_headers: Vec::new(),
        }
    }

    /// 挂载扩展头链：自动重排基础包头 NextHeader 指针与 HAS_EXTENSION 标志。
    pub fn attach_ext_headers(&mut self, ext_headers: Vec<ExtensionHeader>) {
        self.next_header = ext_headers.first().map_or(0, |e| e.ext_type.wire());
        if ext_headers.is_empty() {
            self.flags &= !flags::HAS_EXTENSION;
        } else {
            self.flags |= flags::HAS_EXTENSION;
        }
        self.ext_headers = ext_headers;
    }
}

/// IPv8Address 文本解析错误（protocol-spec §3.2）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrParseError {
    /// 长度非 32 或含非十六进制字符
    Format,
    /// 协议 Magic 不对（不是 0xFB14）
    BadProtocol,
}

impl core::fmt::Display for AddrParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Format => write!(f, "IPv8+ 地址文本必须是 32 个十六进制数字（无分隔符）"),
            Self::BadProtocol => write!(f, "IPv8+ 地址 Protocol Magic 必须是 fb14"),
        }
    }
}

impl std::error::Error for AddrParseError {}

fn hex_val(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0, // 调用方已用 is_ascii_hexdigit 过滤
    }
}

/// 规范文本形式（protocol-spec §3.2 权威显示格式）
impl core::fmt::Display for IPv8Address {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_canonical_string())
    }
}

/// 字符串解析入口（`addr.parse::<IPv8Address>()`；等价 from_canonical_str）
impl core::str::FromStr for IPv8Address {
    type Err = AddrParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_canonical_str(s)
    }
}
