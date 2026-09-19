//! RTCP 式单向延迟（LSR/DLSR）跟踪：时间戳只回显不解释绝对值，
//! RTT 完全在本机时钟内做差，跨机时钟无需同步。
//!
//! ```text
//! A t0 发报告 → B t1 收到：B 记 (peer_lsr=t0, peer_recv=t1)
//! B t2 发报告：回显 lsr=t0, dlsr=t2-t1
//! A t3 收到：RTT = t3 - lsr - dlsr
//! ```

use crate::report::Report;

#[derive(Debug, Clone, Default)]
pub struct RttTracker {
    /// 对端最近一份报告的发送时刻（待回显；0=尚无）
    peer_send_ts: u64,
    peer_recv_us: Option<u64>,
    rtt_us: Option<u64>,
}

impl RttTracker {
    /// 收到对端报告：登记回显材料，并用其回显的本机时间戳更新本机 RTT
    pub fn on_peer_report(&mut self, now_us: u64, r: &Report) {
        self.peer_send_ts = r.send_ts_us;
        self.peer_recv_us = Some(now_us);
        if r.lsr_us != 0 {
            let dlsr = if r.dlsr_us == u32::MAX { 0 } else { r.dlsr_us as u64 };
            let total = r.lsr_us.saturating_add(dlsr);
            if now_us >= total {
                self.rtt_us = Some(now_us - total);
            }
        }
    }

    /// 本端发报告时填充的回显字段（lsr, dlsr）
    pub fn echo(&self, now_us: u64) -> (u64, u32) {
        let dlsr = match self.peer_recv_us {
            Some(t) if now_us >= t => (now_us - t).min(u32::MAX as u64 - 1) as u32,
            _ => u32::MAX,
        };
        (self.peer_send_ts, dlsr)
    }

    pub fn rtt_us(&self) -> Option<u64> {
        self.rtt_us
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::window::PathCounters;

    fn rep(ts: u64, lsr: u64, dlsr: u32) -> Report {
        Report {
            seq: 0,
            send_ts_us: ts,
            lsr_us: lsr,
            dlsr_us: dlsr,
            slots_valid: 1,
            slots: [PathCounters::default(); 3],
        }
    }

    #[test]
    fn rtt_one_round_exchange() {
        // B 侧：收到 A(t0=1000) 报告时 now=5000；t2=8000 发报告
        let mut b = RttTracker::default();
        b.on_peer_report(5_000, &rep(1_000, 0, u32::MAX));
        assert_eq!(b.echo(8_000), (1_000, 3_000));
        // A 侧 t3=12000：RTT = 12000-1000-3000 = 8000
        let mut a = RttTracker::default();
        a.on_peer_report(12_000, &rep(8_000, 1_000, 3_000));
        assert_eq!(a.rtt_us(), Some(8_000));
    }

    #[test]
    fn no_echo_no_rtt() {
        let mut a = RttTracker::default();
        a.on_peer_report(1_000, &rep(900, 0, u32::MAX));
        assert_eq!(a.rtt_us(), None);
        assert_eq!(a.echo(2_000), (900, 1_000));
    }
}
