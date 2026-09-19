//! 回执帧载荷线格式（v1，固定 100 字节）。
//!
//! ```text
//! 偏移 长度  字段
//! 0    1     version=1
//! 1    1     slots 有效数（1=仅 main；2=main+alt；union 槽恒有效）
//! 2    2     保留 0
//! 4    4     报告序号 u32 BE
//! 8    8     本端发送时刻 us（相对时钟，仅做回显/RTT）
//! 16   8     LSR：对端最近报告的 send_ts（0=无）
//! 24   4     DLSR：本端收到对端报告到现在的延迟 us（u32::MAX=无）
//! 28   32*3  三个计数槽：main(28) / alt(60) / union(92)
//!              每槽 32B = u64 expected ‖ u64 seen ‖ u64 dup ‖ u32 resets ‖ u32 age_ms
//! ```

use crate::window::PathCounters;

pub const REPORT_VERSION: u8 = 1;
pub const REPORT_LEN: usize = 124;
pub const SLOT_MAIN: usize = 0;
pub const SLOT_ALT: usize = 1;
pub const SLOT_UNION: usize = 2;
pub const SLOT_COUNT: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Report {
    pub seq: u32,
    pub send_ts_us: u64,
    pub lsr_us: u64,
    pub dlsr_us: u32,
    /// 有效路径槽数（1 或 2）；union 不占此数
    pub slots_valid: u8,
    pub slots: [PathCounters; SLOT_COUNT],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportError {
    /// 长度不是固定 100B
    BadLen(usize),
    /// 版本不匹配
    BadVersion(u8),
}

fn put_u64(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_be_bytes());
}
fn put_u32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_be_bytes());
}
fn get_u64(b: &[u8], off: usize) -> u64 {
    u64::from_be_bytes(b[off..off + 8].try_into().unwrap())
}
fn get_u32(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes(b[off..off + 4].try_into().unwrap())
}

fn put_slot(b: &mut [u8], base: usize, s: &PathCounters) {
    put_u64(b, base, s.expected);
    put_u64(b, base + 8, s.seen);
    put_u64(b, base + 16, s.dup);
    put_u32(b, base + 24, s.resets);
    put_u32(b, base + 28, s.last_recv_age_ms);
}

fn get_slot(b: &[u8], base: usize) -> PathCounters {
    PathCounters {
        expected: get_u64(b, base),
        seen: get_u64(b, base + 8),
        dup: get_u64(b, base + 16),
        resets: get_u32(b, base + 24),
        last_recv_age_ms: get_u32(b, base + 28),
    }
}

/// 编码为固定 100B
pub fn encode(r: &Report) -> [u8; REPORT_LEN] {
    let mut b = [0u8; REPORT_LEN];
    b[0] = REPORT_VERSION;
    b[1] = r.slots_valid.clamp(1, 2);
    put_u32(&mut b, 4, r.seq);
    put_u64(&mut b, 8, r.send_ts_us);
    put_u64(&mut b, 16, r.lsr_us);
    put_u32(&mut b, 24, r.dlsr_us);
    put_slot(&mut b, 28, &r.slots[SLOT_MAIN]);
        put_slot(&mut b, 60, &r.slots[SLOT_ALT]);
        put_slot(&mut b, 92, &r.slots[SLOT_UNION]);
    b
}

/// 解析固定 124B；slots_valid 容错（非 1/2 一律钳到 1）
pub fn decode(b: &[u8]) -> Result<Report, ReportError> {
    if b.len() != REPORT_LEN {
        return Err(ReportError::BadLen(b.len()));
    }
    if b[0] != REPORT_VERSION {
        return Err(ReportError::BadVersion(b[0]));
    }
    Ok(Report {
        seq: get_u32(b, 4),
        send_ts_us: get_u64(b, 8),
        lsr_us: get_u64(b, 16),
        dlsr_us: get_u32(b, 24),
        slots_valid: b[1].clamp(1, 2),
        slots: [get_slot(b, 28), get_slot(b, 60), get_slot(b, 92)],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_all_fields() {
        let r = Report {
            seq: 0xdead_beef,
            send_ts_us: 12_345_678,
            lsr_us: 1_000,
            dlsr_us: 3_000,
            slots_valid: 2,
            slots: [
                PathCounters { expected: 100, seen: 99, dup: 1, resets: 2, last_recv_age_ms: 5 },
                PathCounters { expected: 0, seen: 0, dup: 0, resets: 0, last_recv_age_ms: u32::MAX },
                PathCounters { expected: 100, seen: 100, dup: 1, resets: 2, last_recv_age_ms: 5 },
            ],
        };
        let b = encode(&r);
        assert_eq!(b.len(), REPORT_LEN);
        assert_eq!(decode(&b).unwrap(), r);
    }

    #[test]
    fn rejects_bad_len_and_version() {
        assert!(matches!(decode(&[0u8; 123]), Err(ReportError::BadLen(123))));
        let mut b = encode(&Report {
            seq: 1,
            send_ts_us: 0,
            lsr_us: 0,
            dlsr_us: u32::MAX,
            slots_valid: 1,
            slots: Default::default(),
        });
        b[0] = 9;
        assert!(matches!(decode(&b), Err(ReportError::BadVersion(9))));
    }

    #[test]
    fn slots_valid_clamped() {
        let mut r = Report {
            seq: 0,
            send_ts_us: 0,
            lsr_us: 0,
            dlsr_us: u32::MAX,
            slots_valid: 7,
            slots: Default::default(),
        };
        assert_eq!(encode(&r)[1], 2);
        r.slots_valid = 0;
        assert_eq!(encode(&r)[1], 1);
    }
}
