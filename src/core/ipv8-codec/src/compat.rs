//! IPv4/IPv6 兼容模式（protocol-spec §7.9）：
//! Overlay 模式下 IPv8+ Payload 承载原始 IP 包（IPv4 或 IPv6），
//! 隧道外层再做 IPv4/UDP 封装。本模块提供载荷侧的传输族识别，
//! 供 ipv8-tunnel 的封装器选择外层协议。

/// 载荷承载的内层传输族
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InnerProto {
    IPv4,
    IPv6,
    /// 非 IP 载荷（如协议自身控制消息）
    Other,
}

/// 从载荷首字节（IP Version 高 4 位）识别内层协议族。
/// 返回 None 表示载荷为空，无法判定。
pub fn classify(payload: &[u8]) -> Option<InnerProto> {
    let v = payload.first()? >> 4;
    Some(match v {
        4 => InnerProto::IPv4,
        6 => InnerProto::IPv6,
        _ => InnerProto::Other,
    })
}

/// 内层 IP 头最小长度：IPv4 20B / IPv6 40B，用于隧道层快速合法性检查
pub fn min_inner_header_len(proto: InnerProto) -> usize {
    match proto {
        InnerProto::IPv4 => 20,
        InnerProto::IPv6 => 40,
        InnerProto::Other => 0,
    }
}
