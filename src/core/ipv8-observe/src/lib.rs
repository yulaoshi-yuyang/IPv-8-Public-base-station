//! 观测底座（ADR-0002）：隧道数据面质量信号的唯一生产者。
//!
//! 是什么 / 输入 / 输出
//! - 是什么：纯函数零依赖 crate。入站 Data 帧经稀疏滑动窗统计计数器缺口，
//!   周期性编码成 124B 回执帧（FrameType=7，由 node 层 AEAD 密封后发出）；
//!   对端报告经 RTCP 式回显产出 RTT，并驱动两个滞回策略与 ADR-0003 拥塞控制：
//!   --mp alt 熔断、FEC 自适应门控、--cc 延迟主导丢包兜底限速。
//! - 输入：①`observe_inbound` 喂原始入站 Data 帧（密文即可，计数器明文在帧尾），
//!   带路径归属；②`ingest_report` 喂对端回执字节；全部时刻由调用方注入
//!   （ms 用于年龄/周期，us 用于 RTT；相对时钟即可，跨机只回显不比绝对值）。
//! - 输出：`maybe_build_report` 周期产出回执字节；`alt_disabled`/`fec_enabled`
//!   给出站策略；`cc_rate_bps` 给出站限速；`rtt_us`/`path_counters` 供观测。

mod cc;
mod policy;
mod report;
mod rtt;
mod window;

pub use cc::{CcConfig, CongestionController};
pub use policy::{Breaker, BreakerConfig, FecGate, GateConfig};
pub use report::{decode as decode_report, encode as encode_report, Report, ReportError, REPORT_LEN};
pub use rtt::RttTracker;
pub use window::{frame_meta, PathCounters, PathState, DATA_MIN_FRAME};

use window::SaWindows;

/// 物理路径归属（按 node 层入站 SocketAddr 归类后传入）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathId {
    Main = 0,
    Alt = 1,
}

/// 底座配置（策略子配置见 BreakerConfig/GateConfig）
#[derive(Debug, Clone)]
pub struct ObserveConfig {
    /// 回执生成周期（ms），默认 200
    pub report_interval_ms: u64,
    /// --mp 双路径时 true；false 时 alt 槽无效、熔断永不触发
    pub dual_path: bool,
    pub breaker: BreakerConfig,
    pub gate: GateConfig,
    /// ADR-0003 --cc：拥塞控制配置；None = 关闭（出站直通，零开销）
    pub cc: Option<CcConfig>,
}

impl Default for ObserveConfig {
    fn default() -> Self {
        Self {
            report_interval_ms: 200,
            dual_path: false,
            breaker: BreakerConfig::default(),
            gate: GateConfig::default(),
            cc: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ObserveNode {
    cfg: ObserveConfig,
    /// 本端入向观测（对端→本端方向）
    rx: [PathState; 2],
    /// 双路径并集（mp 双发同帧只算一次到达）
    rx_union: SaWindows,
    rtt: RttTracker,
    seq: u32,
    last_report_ms: Option<u64>,
    /// 对端上一份报告的快照（做区间差值）
    peer_prev: Option<[PathCounters; report::SLOT_COUNT]>,
    /// 最近一次推进策略的 union (期望差, 到达差)，诊断用
    last_dunion: (u64, u64),
    breaker: Breaker,
    gate: FecGate,
    /// ADR-0003 --cc：拥塞控制器；None = 关闭
    cc: Option<CongestionController>,
}

impl ObserveNode {
    pub fn new(cfg: ObserveConfig) -> Self {
        let breaker = Breaker::new(cfg.breaker);
        let gate = FecGate::new(cfg.gate);
        let cc = cfg.cc.map(CongestionController::new);
        Self {
            cfg,
            rx: [PathState::new(), PathState::new()],
            rx_union: SaWindows::default(),
            rtt: RttTracker::default(),
            seq: 0,
            last_report_ms: None,
            peer_prev: None,
            last_dunion: (0, 0),
            breaker,
            gate,
            cc,
        }
    }

    /// 喂入一个原始入站 Data 帧（在解密/分流之前即可调用）
    pub fn observe_inbound(&mut self, now_ms: u64, path: PathId, frame: &[u8]) -> bool {
        let accepted = self.rx[path as usize].observe_data(now_ms, frame);
        if accepted {
            if let Some((key, counter)) = window::frame_meta(frame) {
                self.rx_union.observe(key, counter);
            }
        }
        accepted
    }

    /// 周期到达时产出回执帧载荷（124B）；未到周期返回 None
    pub fn maybe_build_report(&mut self, now_ms: u64, now_us: u64) -> Option<[u8; REPORT_LEN]> {
        if let Some(last) = self.last_report_ms {
            if now_ms.saturating_sub(last) < self.cfg.report_interval_ms {
                return None;
            }
        }
        let main = self.rx[0].counters(now_ms);
        let alt = self.rx[1].counters(now_ms);
        let (e, s, d, r) = self.rx_union.totals();
        // 并集年龄取两路径最新者（无对端时为 u32::MAX）
        let union_age = main.last_recv_age_ms.min(alt.last_recv_age_ms);
        let union = PathCounters {
            expected: e,
            seen: s,
            dup: d,
            resets: r,
            last_recv_age_ms: union_age,
        };
        let slots_valid = if self.cfg.dual_path { 2 } else { 1 };
        let (lsr_us, dlsr_us) = self.rtt.echo(now_us);
        let report = Report {
            seq: self.seq,
            send_ts_us: now_us,
            lsr_us,
            dlsr_us,
            slots_valid,
            slots: [main, alt, union],
        };
        self.seq = self.seq.wrapping_add(1);
        self.last_report_ms = Some(now_ms);
        Some(report::encode(&report))
    }

    /// 摄入对端回执（解密后的 124B 载荷）。首份只建基线不推进策略。
    pub fn ingest_report(&mut self, now_ms: u64, now_us: u64, bytes: &[u8]) -> Result<(), ReportError> {
        let r = report::decode(bytes)?;
        self.rtt.on_peer_report(now_us, &r);
        if let Some(prev) = self.peer_prev {
            let delta = |cur: &PathCounters, old: &PathCounters| {
                (
                    cur.expected.wrapping_sub(old.expected),
                    cur.seen.wrapping_sub(old.seen),
                )
            };
            let dmain = delta(&r.slots[report::SLOT_MAIN], &prev[report::SLOT_MAIN]);
            let dunion = delta(&r.slots[report::SLOT_UNION], &prev[report::SLOT_UNION]);
            if self.cfg.dual_path {
                self.breaker.update(
                    &r.slots[report::SLOT_MAIN],
                    &r.slots[report::SLOT_ALT],
                );
            }
            self.gate.update(dunion);
            self.last_dunion = dunion;
            // ADR-0003：CC 与门控同源（dunion 丢包‰）+ RTT 回显，同一函数顺手推进
            if let Some(cc) = &mut self.cc {
                cc.update(dunion, self.rtt.rtt_us(), now_ms);
            }
            // 显式标记 dmain 属设计口径（main 活性在 breaker 内按年龄判），防未用警告
            let _ = dmain;
        }
        self.peer_prev = Some(r.slots);
        Ok(())
    }

    /// 出站是否应停发 alt（--mp 熔断中）。非双路径配置恒为 false。
    pub fn alt_disabled(&self) -> bool {
        self.cfg.dual_path && self.breaker.alt_disabled()
    }

    /// 出站是否应加 FEC（自适应门控开）
    pub fn fec_enabled(&self) -> bool {
        self.gate.enabled()
    }

    /// 诊断：最近一份对端报告的 union 期望/到达差与门控态（真机验收查信号链）
    pub fn last_union_delta(&self) -> ((u64, u64), bool) {
        (self.last_dunion, self.gate.enabled())
    }

    pub fn rtt_us(&self) -> Option<u64> {
        self.rtt.rtt_us()
    }

    /// ADR-0003 --cc：当前限速 bit/s；None = 未启用（出站直通）
    pub fn cc_rate_bps(&self) -> Option<u64> {
        self.cc.as_ref().map(CongestionController::rate_bps)
    }

    /// 本端入向某路径的累计计数（诊断/测试用）
    pub fn path_counters(&self, now_ms: u64, path: PathId) -> PathCounters {
        self.rx[path as usize].counters(now_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造 74B Data 帧（计数器在明文段后 offset=50；body[6]=0 无扩展头）
    fn data_frame(counter: u64) -> Vec<u8> {
        let mut f = vec![0u8; DATA_MIN_FRAME];
        f[0] = 1;
        f[1] = 2;
        let off = window::FRAME_HEADER_LEN + window::BASE_HEADER_SIZE;
        f[off..off + 8].copy_from_slice(&counter.to_be_bytes());
        f
    }

    fn dual() -> ObserveConfig {
        ObserveConfig { dual_path: true, ..Default::default() }
    }

    #[test]
    fn report_rhythm_and_payload() {
        let mut n = ObserveNode::new(dual());
        assert!(n.maybe_build_report(0, 0).is_some()); // 首份立即发
        assert!(n.maybe_build_report(199, 199_000).is_none());
        let b = n.maybe_build_report(200, 200_000).expect("200ms 到点");
        assert_eq!(b.len(), REPORT_LEN);
        assert_eq!(b[1], 2); // dual → slots_valid=2
    }

    #[test]
    fn alt_blackout_trips_breaker_then_recovery_clears() {
        // B（观测侧）：main 收全，alt 全丢；周期出报告喂给 A（决策侧）
        let mut b = ObserveNode::new(dual());
        let mut a = ObserveNode::new(dual());
        let mut now = 0u64;

        // 基线报告（0 计数）
        let r0 = b.maybe_build_report(now, now * 1000).unwrap();
        a.ingest_report(now, now * 1000, &r0).unwrap();

        // 3 个窗：main 1..300，alt 无
        for w in 1..=3u64 {
            now = w * 200;
            for c in (w - 1) * 100 + 1..=w * 100 {
                b.observe_inbound(now, PathId::Main, &data_frame(c));
            }
            let rep = b.maybe_build_report(now, now * 1000).unwrap();
            a.ingest_report(now, now * 1000, &rep).unwrap();
        }
        assert!(a.alt_disabled(), "main 活 alt 死透 3 窗必须熔断");

        // 恢复：main+alt 都收全 5 窗（计数器续 301..800）
        for w in 4..=8u64 {
            now = w * 200;
            for c in (w - 1) * 100 + 1..=w * 100 {
                let f = data_frame(c);
                b.observe_inbound(now, PathId::Main, &f);
                b.observe_inbound(now, PathId::Alt, &f);
            }
            let rep = b.maybe_build_report(now, now * 1000).unwrap();
            a.ingest_report(now, now * 1000, &rep).unwrap();
        }
        assert!(!a.alt_disabled(), "5 连高质量窗必须恢复双发");
    }

    #[test]
    fn cc_none_passes_through_cc_some_advances() {
        // --cc 关：cc_rate_bps=None
        let a_off = ObserveNode::new(ObserveConfig::default());
        assert_eq!(a_off.cc_rate_bps(), None);

        // --cc 开（ceil=8Mbps）：起步=ceil/4=2M
        let cfg = ObserveConfig { cc: Some(CcConfig::new(8_000_000)), ..Default::default() };
        let mut a_on = ObserveNode::new(cfg);
        assert_eq!(a_on.cc_rate_bps(), Some(2_000_000));

        // B 端构造报告：首份基线 + 两份零丢包区间 → 加性增两次
        let mut b = ObserveNode::new(ObserveConfig::default());
        let r0 = b.maybe_build_report(0, 0).unwrap();
        a_on.ingest_report(0, 0, &r0).unwrap();
        for w in 1..=2u64 {
            let now = w * 200;
            for c in (w - 1) * 100 + 1..=w * 100 {
                b.observe_inbound(now, PathId::Main, &data_frame(c));
            }
            let rep = b.maybe_build_report(now, now * 1000).unwrap();
            a_on.ingest_report(now, now * 1000, &rep).unwrap();
        }
        assert_eq!(a_on.cc_rate_bps(), Some(4_000_000), "两份好窗 +ceil/8×2");
    }

    #[test]
    fn fec_gate_uses_union_loss() {
        let mut b = ObserveNode::new(dual());
        let mut a = ObserveNode::new(dual());
        let now = 0u64;
        let r0 = b.maybe_build_report(now, now * 1000).unwrap();
        a.ingest_report(now, now * 1000, &r0).unwrap();
        // 双发同帧两边都收到 → union 无丢包：即使 main 槽 accounting 双份，门控不开
        for w in 1..=3u64 {
            let now = w * 200;
            for c in (w - 1) * 100 + 1..=w * 100 {
                let f = data_frame(c);
                b.observe_inbound(now, PathId::Main, &f);
                b.observe_inbound(now, PathId::Alt, &f);
            }
            let rep = b.maybe_build_report(now, now * 1000).unwrap();
            a.ingest_report(now, now * 1000, &rep).unwrap();
        }
        assert!(!a.fec_enabled());
        // union 30% 丢包（单路受损），2 窗开启
        for w in 4..=5u64 {
            let now = w * 200;
            for c in (w - 1) * 100 + 1..=w * 100 {
                if c % 10 < 7 {
                    b.observe_inbound(now, PathId::Main, &data_frame(c));
                }
            }
            let rep = b.maybe_build_report(now, now * 1000).unwrap();
            a.ingest_report(now, now * 1000, &rep).unwrap();
        }
        assert!(a.fec_enabled());
    }

    #[test]
    fn single_path_never_breaks() {
        let n = ObserveNode::new(ObserveConfig::default());
        assert!(!n.alt_disabled());
    }
}
