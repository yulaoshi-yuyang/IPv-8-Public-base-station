//! # ipv8-qos
//!
//! IPv8+ QoS 引擎（v9 Phase 3）：
//!
//! - [`classifier`]：基头 QoS Level（4 bit）→ 4 级调度类
//! - [`scheduler`]：严格优先队列（类内 FIFO，不做带宽保证）
//! - [`reservation`]：QoSReservation 报文构造（spec §6.5，本轮只产出不消费）
//!
//! 接入形态：上层（node 转发队列 / C# Host）在 enqueue 时调 classifier、
//! 出队经 scheduler；本 crate 不持有 IO，纯数据变换，可独立测试。

pub mod classifier;
pub mod reservation;
pub mod scheduler;

pub use classifier::{classify_base_header, class_of_level, qos_level_of_base_header, NUM_CLASSES};
pub use reservation::{parse_reservation, reservation_header};
pub use scheduler::PriorityScheduler;

#[cfg(test)]
mod tests {
    use super::*;
    use ipv8_codec::{encode, ExtType, ExtensionHeader, IPv8Address, IPv8Header, QosReservation, flags};

    fn hdr_with_level(level: u16) -> Vec<u8> {
        let a = IPv8Address::new(1, 2, 1, 0, 1);
        let mut h = IPv8Header::new(a, a, 4);
        h.flags = level | flags::ENCRYPTED;
        encode(&h, b"dat!").unwrap()
    }

    #[test]
    fn level_maps_to_quarter_class() {
        // spec §5：0-15 线性映射 4 级
        assert_eq!(class_of_level(0), 0);
        assert_eq!(class_of_level(3), 0);
        assert_eq!(class_of_level(4), 1);
        assert_eq!(class_of_level(7), 1);
        assert_eq!(class_of_level(8), 2);
        assert_eq!(class_of_level(11), 2);
        assert_eq!(class_of_level(12), 3);
        assert_eq!(class_of_level(15), 3);
    }

    #[test]
    fn level_extracted_from_wire_header() {
        for level in [0u16, 1, 5, 9, 15] {
            let pkt = hdr_with_level(level);
            assert_eq!(qos_level_of_base_header(&pkt), Some(level as u8));
            assert_eq!(classify_base_header(&pkt), class_of_level(level as u8));
        }
    }

    #[test]
    fn malformed_header_classifies_best_effort() {
        assert_eq!(qos_level_of_base_header(&[0u8; 39]), None);
        assert_eq!(classify_base_header(&[0u8; 39]), 0); // 归最低类而非 panic
    }

    #[test]
    fn higher_class_preempts_regardless_of_arrival_order() {
        let mut s = PriorityScheduler::<u32>::new(16);
        // 低优先来 3 个，高优后来 2 个：出队必须高优先出
        s.push(0, 101);
        s.push(0, 102);
        s.push(1, 201);
        s.push(3, 301);
        s.push(3, 302);
        assert_eq!(s.take_next(), Some(301));
        assert_eq!(s.take_next(), Some(302));
        assert_eq!(s.take_next(), Some(201));
        assert_eq!(s.take_next(), Some(101));
        assert_eq!(s.take_next(), Some(102));
        assert!(s.is_empty());
    }

    #[test]
    fn same_class_is_fifo() {
        let mut s = PriorityScheduler::<u32>::new(16);
        for i in 0..5 {
            s.push(2, i);
        }
        for i in 0..5 {
            assert_eq!(s.take_next(), Some(i));
        }
    }

    #[test]
    fn bounded_queue_drops_and_reports() {
        let mut s = PriorityScheduler::<u32>::new(2);
        assert_eq!(s.push(0, 1), None);
        assert_eq!(s.push(0, 2), None);
        assert_eq!(s.push(0, 3), Some(3), "满类溢出交还调用方");
        assert_eq!(s.push(3, 9), None, "其他类不受影响");
        assert_eq!(s.dropped(), 1);
        assert_eq!(s.class_len(0), 2);
        assert_eq!(s.len(), 3);
    }

    #[test]
    fn reservation_roundtrips_through_ext_header() {
        let ext = reservation_header(0x12_3456, 4096, 7).expect("合法构造");
        assert_eq!(ext.ext_type, ExtType::QoSReservation);
        assert_eq!(ext.ext_len(), 1); // 8 字节恰一个 ExtLen 单位（spec §6.5）
        let r = parse_reservation(&ext).unwrap();
        assert_eq!(
            r,
            QosReservation { rate_kibs: 0x12_3456, burst_size: 4096, queue_hint: 7 }
        );
        // 非 QoS 头解析为 None
        let other = ExtensionHeader::new(ExtType::IdentityToken, vec![0u8; 8]).unwrap();
        assert!(parse_reservation(&other).is_none());
    }

    #[test]
    fn oversize_rate_yields_no_header() {
        assert!(reservation_header(1 << 24, 0, 0).is_none(), "24bit 超限不得产出畸形头");
    }
}
