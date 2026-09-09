//! QoSReservation 报文构造（v9 `ipv8-qos/reservation.rs`，spec §6.5）。
//!
//! 本轮只**产出**（发送方标注速率承诺），不实现承诺的消费端——
//! 中间节点对未实现承诺语义的本头 MUST 只读或忽略（§6.5）。
//! 权威编解码在 `ipv8-codec::layouts`，本模块只提供构造糖。

use ipv8_codec::{ExtType, ExtensionHeader, QosReservation};

/// 构造携带速率承诺的扩展头（链中任意位置均可；与 QoS Level 独立）。
///
/// `rate_kibs=0` 表示"仅优先级提示无承诺"（spec §6.5），此时通常根本
/// 不需要本头——返回 Some 让调用方显式决策，不隐式吞掉。
pub fn reservation_header(
    rate_kibs: u32,
    burst_size: u16,
    queue_hint: u8,
) -> Option<ExtensionHeader> {
    let r = QosReservation { rate_kibs, burst_size, queue_hint };
    ExtensionHeader::new(ExtType::QoSReservation, r.to_payload().ok()?)
}

/// 从扩展头还原速率承诺（非 QoSReservation 类型返回 None）。
pub fn parse_reservation(ext: &ExtensionHeader) -> Option<QosReservation> {
    if ext.ext_type != ExtType::QoSReservation {
        return None;
    }
    QosReservation::from_payload(&ext.payload).ok()
}
