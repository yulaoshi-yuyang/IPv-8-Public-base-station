//! IPv8+ 包头编码：内存结构 → 线格式字节。

use crate::header::*;

/// 编码结果：包头占用字节数（40 + 扩展头链）。
/// 线格式总包 = encode_header 输出 + payload。
pub fn encode_header(hdr: &IPv8Header, out: &mut Vec<u8>) -> Result<usize, EncodeError> {
    if hdr.version != VERSION {
        return Err(EncodeError::BadVersion(hdr.version));
    }
    if hdr.min_compat_ver > 15 {
        return Err(EncodeError::FieldOverflow("min_compat_ver"));
    }
    if !Flags::reserved_ok(hdr.flags) {
        return Err(EncodeError::ReservedBits);
    }
    if hdr.payload_len > MAX_PAYLOAD_LEN {
        return Err(EncodeError::PayloadTooLong(hdr.payload_len));
    }
    if hdr.ext_headers.len() > MAX_EXT_CHAIN {
        return Err(EncodeError::TooManyExtHeaders(hdr.ext_headers.len()));
    }

    // 扩展头链总长
    let ext_total: usize = hdr.ext_headers.iter().map(|e| e.wire_size()).sum();
    if BASE_HEADER_SIZE + ext_total + hdr.payload_len as usize > MAX_PACKET_LEN {
        return Err(EncodeError::PacketTooLong);
    }

    // next_header 一致性：无扩展头时必须为 0，有扩展头时必须等于首个类型
    let first_nh = hdr.ext_headers.first().map_or(0, |e| e.ext_type.wire());
    if hdr.next_header != first_nh {
        return Err(EncodeError::NextHeaderMismatch { expect: first_nh, got: hdr.next_header });
    }
    // HAS_EXTENSION 标志一致性
    let has_ext_flag = hdr.flags & flags::HAS_EXTENSION != 0;
    if has_ext_flag != !hdr.ext_headers.is_empty() {
        return Err(EncodeError::FlagMismatch("HAS_EXTENSION"));
    }

    let start = out.len();
    out.resize(start + BASE_HEADER_SIZE, 0);
    let b = &mut out[start..start + BASE_HEADER_SIZE];

    // 字节 0：Version(高 4) | MinCompatVer(低 4)
    b[0] = (hdr.version << 4) | (hdr.min_compat_ver & 0x0F);
    // 字节 1-2：Flags（大端）
    b[1..3].copy_from_slice(&hdr.flags.to_be_bytes());
    // 字节 3-4：PayloadLen（大端）
    b[3..5].copy_from_slice(&hdr.payload_len.to_be_bytes());
    // 字节 5：HopLimit
    b[5] = hdr.hop_limit;
    // 字节 6：NextHeader
    b[6] = hdr.next_header;
    // 字节 7-22 / 23-38：地址
    if !hdr.src_addr.write_to(&mut b[7..23]) || !hdr.dst_addr.write_to(&mut b[23..39]) {
        return Err(EncodeError::AddressReserved);
    }
    // 字节 39：32 位对齐填充，必须为 0（b[39] 已由 resize 置 0）

    // 扩展头链：编码时自动重排每个头的 NextHeader 指针
    for (i, ext) in hdr.ext_headers.iter().enumerate() {
        let next_ptr = hdr.ext_headers.get(i + 1).map_or(0, |n| n.ext_type.wire());
        out.push(next_ptr);
        out.push(ext.ext_len());
        out.extend_from_slice(&ext.payload);
    }

    Ok(out.len() - start)
}

/// 便捷函数：编码包头 + 载荷为完整 IPv8+ 包
pub fn encode(hdr: &IPv8Header, payload: &[u8]) -> Result<Vec<u8>, EncodeError> {
    if payload.len() != hdr.payload_len as usize {
        return Err(EncodeError::PayloadLengthMismatch {
            header: hdr.payload_len as usize,
            actual: payload.len(),
        });
    }
    let mut out = Vec::with_capacity(BASE_HEADER_SIZE + payload.len());
    encode_header(hdr, &mut out)?;
    out.extend_from_slice(payload);
    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodeError {
    BadVersion(u8),
    FieldOverflow(&'static str),
    /// Flags 位 7-15 非零
    ReservedBits,
    PayloadTooLong(u16),
    /// 包头 PayloadLen 与实际载荷长度不一致
    PayloadLengthMismatch { header: usize, actual: usize },
    TooManyExtHeaders(usize),
    /// 40 + 扩展头 + 载荷超过 65507
    PacketTooLong,
    NextHeaderMismatch { expect: u8, got: u8 },
    FlagMismatch(&'static str),
    /// 地址 reserved 3 字节非零
    AddressReserved,
}

impl core::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadVersion(v) => write!(f, "非法协议版本 {v:#x}（必须为 0x8）"),
            Self::FieldOverflow(name) => write!(f, "字段 {name} 溢出"),
            Self::ReservedBits => write!(f, "Flags 保留位必须为 0"),
            Self::PayloadTooLong(n) => write!(f, "PayloadLen {n} 超过协议上限 {MAX_PAYLOAD_LEN}"),
            Self::PayloadLengthMismatch { header, actual } => {
                write!(f, "包头 PayloadLen({header}) 与实际载荷长度({actual})不一致")
            }
            Self::TooManyExtHeaders(n) => write!(f, "扩展头数量 {n} 超过上限 {MAX_EXT_CHAIN}"),
            Self::PacketTooLong => write!(f, "IPv8+ 包总长超过 {MAX_PACKET_LEN}"),
            Self::NextHeaderMismatch { expect, got } => {
                write!(f, "NextHeader 应为 {expect}，实际 {got}")
            }
            Self::FlagMismatch(name) => write!(f, "标志位 {name} 与扩展头链不一致"),
            Self::AddressReserved => write!(f, "IPv8Address.reserved 必须全 0（请用 IPv8Address::new）"),
        }
    }
}

impl std::error::Error for EncodeError {}
