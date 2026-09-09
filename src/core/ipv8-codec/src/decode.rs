//! IPv8+ 包头解码：线格式字节 → 内存结构。
//!
//! 校验策略（对齐 protocol-spec 定稿条款）：
//! - **normative**：字节序全大端；Version 高 4 位；偏移严格连续。
//! - **宽松接收（Robustness Principle）**：
//!   - 注册表外的扩展头类型 → 按 ExtLen 跳过继续解析（`ExtType::Unknown`），
//!     不得丢弃整包 —— 这是 CapTag/SemanticTag 向后兼容演进的前提；
//!   - Flags 保留位、字节 39 填充、地址 Reserved 24 位 → 接收方**忽略**，
//!     不强制为 0（发送方置 0），避免严格校验实现与未来字段扩展互相打死。
//! - **硬性拒绝**：长度不足、版本错误、PayloadLen 越界、链截断、ExtLen=0、
//!   链回路、数量超限。

use crate::header::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// 字节数不足 BASE_HEADER_SIZE
    TooShort(usize),
    BadVersion(u8),
    /// PayloadLen 超过协议上限 65467
    PayloadTooLong(u16),
    /// 声明的 PayloadLen 超过缓冲区剩余可用字节
    PayloadBeyondBuffer { need: usize, have: usize },
    /// 总包长超过 65507（IPv4/UDP 载荷上限）
    PacketTooLong,
    /// 扩展头链截断
    ExtHeaderTruncated,
    /// 扩展头数量超过上限
    TooManyExtHeaders,
    /// ExtLen 为 0（规范要求 8 字节的正整数倍）
    ExtLenZero,
    /// 扩展头链环（NextHeader 指针形成回路）
    ExtChainCycle,
    /// 有扩展头但未置 HAS_EXTENSION 标志（X 位是链存在性权威声明）
    FlagMismatch,
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooShort(n) => write!(f, "包长 {n} 字节，不足基础包头 {BASE_HEADER_SIZE} 字节"),
            Self::BadVersion(v) => write!(f, "非法协议版本 {v:#x}（必须为 0x8）"),
            Self::PayloadTooLong(n) => write!(f, "PayloadLen {n} 超过协议上限 {MAX_PAYLOAD_LEN}"),
            Self::PayloadBeyondBuffer { need, have } => {
                write!(f, "声明载荷 {need} 字节，缓冲区仅剩 {have} 字节")
            }
            Self::PacketTooLong => write!(f, "IPv8+ 包总长超过 {MAX_PACKET_LEN}"),
            Self::ExtHeaderTruncated => write!(f, "扩展头链被截断"),
            Self::TooManyExtHeaders => write!(f, "扩展头数量超过上限 {MAX_EXT_CHAIN}"),
            Self::ExtLenZero => write!(f, "扩展头 ExtLen 不得为 0"),
            Self::ExtChainCycle => write!(f, "扩展头链存在回路"),
            Self::FlagMismatch => write!(f, "HAS_EXTENSION 标志与扩展头链不一致"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// 解码结果：包头 + 载荷切片（零拷贝借用输入缓冲）
#[derive(Debug, PartialEq, Eq)]
pub struct Decoded<'a> {
    pub header: IPv8Header,
    pub payload: &'a [u8],
}

/// 从字节流解码 IPv8+ 包头与载荷。
pub fn decode(buf: &[u8]) -> Result<Decoded<'_>, DecodeError> {
    if buf.len() < BASE_HEADER_SIZE {
        return Err(DecodeError::TooShort(buf.len()));
    }

    // 字节 0：Version(高 4) | MinCompatVer(低 4)
    let version = buf[0] >> 4;
    let min_compat_ver = buf[0] & 0x0F;
    if version != VERSION {
        return Err(DecodeError::BadVersion(version));
    }

    // 字节 1-2：Flags（大端）。保留位接收方忽略，不做强制校验。
    let flags = u16::from_be_bytes([buf[1], buf[2]]);

    // 字节 3-4：PayloadLen（大端，偏移 3-4，非 4-5）
    let payload_len = u16::from_be_bytes([buf[3], buf[4]]);
    if payload_len > MAX_PAYLOAD_LEN {
        return Err(DecodeError::PayloadTooLong(payload_len));
    }

    let hop_limit = buf[5];
    let next_header = buf[6];

    // 字节 7-22 / 23-38：地址。Reserved 字节接收方忽略并清零。
    let src_addr = read_addr(&buf[7..23]);
    let dst_addr = read_addr(&buf[23..39]);

    // 字节 39：对齐填充，接收方忽略（不做校验）

    // 扩展头链
    let has_ext_flag = flags & flags::HAS_EXTENSION != 0;
    let mut cursor = BASE_HEADER_SIZE;
    let mut ext_headers: Vec<ExtensionHeader> = Vec::new();

    if next_header != 0 {
        // 有链：逐个解析。未知类型按 ExtLen 跳过但保留占位，保证载荷偏移正确。
        let mut cur_type = next_header;
        let mut idx = 0usize;
        // 已出现编号表（≤64 项线性查找），防御回路；不用位图以避免 u128 移位溢出
        let mut seen: Vec<u8> = Vec::new();
        loop {
            let ty = ExtType::from_u8(cur_type);
            if seen.contains(&cur_type) {
                return Err(DecodeError::ExtChainCycle);
            }
            seen.push(cur_type);

            if cursor + 2 > buf.len() {
                return Err(DecodeError::ExtHeaderTruncated);
            }
            let ptr_next = buf[cursor];
            let ext_len = buf[cursor + 1];
            if ext_len == 0 {
                return Err(DecodeError::ExtLenZero);
            }
            let plen = ext_len as usize * 8;
            if cursor + 2 + plen > buf.len() {
                return Err(DecodeError::ExtHeaderTruncated);
            }
            let payload = buf[cursor + 2..cursor + 2 + plen].to_vec();
            ext_headers.push(ExtensionHeader { ext_type: ty, payload });

            idx += 1;
            if idx > MAX_EXT_CHAIN {
                return Err(DecodeError::TooManyExtHeaders);
            }

            cursor += 2 + plen;
            if ptr_next == 0 {
                break; // 链尾
            }
            cur_type = ptr_next;
        }
    }

    // HAS_EXTENSION 标志与链一致性（X 位是链存在性的权威声明）
    if has_ext_flag != !ext_headers.is_empty() {
        return Err(DecodeError::FlagMismatch);
    }

    // 载荷
    if cursor + payload_len as usize > buf.len() {
        return Err(DecodeError::PayloadBeyondBuffer {
            need: payload_len as usize,
            have: buf.len() - cursor,
        });
    }
    let payload = &buf[cursor..cursor + payload_len as usize];

    // IPv8+ 部分总长硬约束（超出 IPv4/UDP 载荷上限的包不可能合法到达本端）
    if cursor + payload_len as usize > MAX_PACKET_LEN {
        return Err(DecodeError::PacketTooLong);
    }

    Ok(Decoded {
        header: IPv8Header {
            version,
            min_compat_ver,
            flags,
            payload_len,
            hop_limit,
            next_header,
            src_addr,
            dst_addr,
            ext_headers,
        },
        payload,
    })
}

fn read_addr(b: &[u8]) -> IPv8Address {
    // Reserved 24 位：接收方忽略（不校验非零），内存中统一置 0
    IPv8Address {
        asn: u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
        host_id: u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
        device_id: u16::from_be_bytes([b[8], b[9]]),
        cap_tag: u16::from_be_bytes([b[10], b[11]]),
        sec_level: b[12],
        reserved: [0; 3],
    }
}
