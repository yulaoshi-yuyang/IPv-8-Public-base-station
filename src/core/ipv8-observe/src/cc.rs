//! ADR-0003 拥塞控制：延迟主导 + 丢包兜底，保护性限速（--cc 默认关闭）。
//!
//! 定位：防跨公网自饿/打爆对端队列（守 RTT 预算），不抢满带宽。
//! 与 Breaker/FecGate 同风格：纯函数状态机，时钟与计数由调用方注入。

/// 拥塞控制配置（ceil_bps 必填，其余旋钮由 [`CcConfig::new`] 填默认）
#[derive(Debug, Clone, Copy)]
pub struct CcConfig {
    /// 速率天花板 bit/s（来自 --cc-ceil）
    pub ceil_bps: u64,
    /// 速率地板 bit/s，默认 max(ceil/16, 64kbps)
    pub floor_bps: u64,
    /// RTT 膨胀阈值（per-mille）：RTT ≥ min_rtt × (1000+本值)/1000 判膨胀
    pub rtt_infl_permille: u32,
    /// 丢包率兜底阈值（per-mille）：RTT 信号缺失或失真时的最终防线
    pub loss_on_permille: u32,
    /// 乘性降分子/分母（默认 7/10）
    pub decrease_num: u64,
    pub decrease_den: u64,
    /// 加性增步长分母：每好窗 +ceil/本值（默认 8）
    pub increase_div: u64,
    /// 区间最小期望样本数，不足则冻结（同 GateConfig 口径）
    pub min_expected: u64,
    /// min_rtt 基线过期（ms）：基线超期未刷新则重置（链路切换后防旧基线锚死）
    pub min_rtt_expiry_ms: u64,
}

impl CcConfig {
    pub fn new(ceil_bps: u64) -> Self {
        Self {
            ceil_bps,
            floor_bps: (ceil_bps / 16).max(64_000),
            rtt_infl_permille: 250,
            loss_on_permille: 30,
            decrease_num: 7,
            decrease_den: 10,
            increase_div: 8,
            min_expected: 32,
            min_rtt_expiry_ms: 10_000,
        }
    }
}

/// 拥塞控制器：起步 ceil/4，对端回执累积推进（累积到 min_expected 评估一次）。
/// 降：RTT 膨胀或丢包率超阈 → 乘性 ×7/10（不低于 floor）；
/// 增：好窗 → 加性 +ceil/8（不超 ceil）。
#[derive(Debug, Clone)]
pub struct CongestionController {
    cfg: CcConfig,
    rate_bps: u64,
    /// (min_rtt_us, 建立/最近刷新时刻 ms)
    min_rtt: Option<(u64, u64)>,
    /// 样本累积器 (期望, 唯一到达)：累积到 min_expected 才评估一次。
    /// 单份报告窗固定 200ms，低帧率下 expected 远小于 min_expected，
    /// 逐份评估会恒冻结在起步值（低 ceil 场景功能失效）。
    acc: (u64, u64),
    /// 累积窗内最小 RTT（us）
    acc_rtt: Option<u64>,
}

impl CongestionController {
    pub fn new(cfg: CcConfig) -> Self {
        Self {
            cfg,
            rate_bps: cfg.ceil_bps / 4,
            min_rtt: None,
            acc: (0, 0),
            acc_rtt: None,
        }
    }

    /// 每份对端报告推进一次；delta=(期望差, 唯一到达差)（union 槽口径）。
    /// rtt_us=None（对端回执尚未往返）时只判丢包。
    /// 累积口径：多份报告累积到 min_expected 再评估一次（低帧率防冻结）；
    /// 高帧率下首份即达标，行为与逐份评估等价（无回归）。
    pub fn update(&mut self, delta: (u64, u64), rtt_us: Option<u64>, now_ms: u64) {
        self.acc.0 = self.acc.0.saturating_add(delta.0);
        self.acc.1 = self.acc.1.saturating_add(delta.1);
        if let Some(r) = rtt_us {
            self.acc_rtt = Some(self.acc_rtt.map_or(r, |b| b.min(r)));
        }
        if self.acc.0 < self.cfg.min_expected {
            return; // 样本仍不足：速率与基线全冻结，保持现状
        }
        let (expected, seen) = self.acc;
        let rtt_us = self.acc_rtt;
        self.acc = (0, 0);
        self.acc_rtt = None;
        // min_rtt 基线：更低样本即时刷新；超期未刷新则重置为当前值
        let inflated = match rtt_us {
            Some(rtt) => {
                let base = match self.min_rtt {
                    Some((base, ts))
                        if rtt >= base
                            && now_ms.saturating_sub(ts) <= self.cfg.min_rtt_expiry_ms =>
                    {
                        base
                    }
                    _ => {
                        self.min_rtt = Some((rtt, now_ms));
                        rtt
                    }
                };
                // 整数比较防浮点：rtt/base ≥ (1000+infl)/1000
                u128::from(rtt) * 1000
                    >= u128::from(base) * u128::from(1000 + self.cfg.rtt_infl_permille)
            }
            None => false,
        };
        let lost = expected.saturating_sub(seen).min(expected);
        let loss_pm = lost.saturating_mul(1000) / expected;
        if inflated || loss_pm >= u64::from(self.cfg.loss_on_permille) {
            self.rate_bps =
                (self.rate_bps * self.cfg.decrease_num / self.cfg.decrease_den).max(self.cfg.floor_bps);
        } else {
            self.rate_bps =
                (self.rate_bps + self.cfg.ceil_bps / self.cfg.increase_div).min(self.cfg.ceil_bps);
        }
    }

    /// 当前限速 bit/s
    pub fn rate_bps(&self) -> u64 {
        self.rate_bps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ceil=8Mbps：起步 2M，步长 1M，地板 500k
    fn cc() -> CongestionController {
        CongestionController::new(CcConfig::new(8_000_000))
    }

    #[test]
    fn rtt_inflation_decreases() {
        let mut c = cc();
        // 建立基线 100ms（零丢包好窗）
        c.update((100, 100), Some(100_000), 0);
        assert_eq!(c.rate_bps(), 3_000_000, "首窗建基线后加性增");
        // 30% 膨胀（≥25% 阈值）→ ×0.7
        c.update((100, 100), Some(130_000), 200);
        assert_eq!(c.rate_bps(), 2_100_000);
        // 24% 膨胀（未达阈值）→ 增
        c.update((100, 100), Some(124_000), 400);
        assert_eq!(c.rate_bps(), 3_100_000);
    }

    #[test]
    fn loss_decreases_when_rtt_normal() {
        let mut c = cc();
        c.update((100, 100), Some(100_000), 0);
        // RTT 贴基线不膨胀，但丢包 4% ≥ 30‰ → 降
        c.update((100, 96), Some(100_000), 200);
        assert_eq!(c.rate_bps(), 2_100_000, "丢包兜底独立于 RTT 生效");
        // 2.9%（未达 30‰）→ 增
        c.update((1000, 971), Some(100_000), 400);
        assert_eq!(c.rate_bps(), 3_100_000);
    }

    #[test]
    fn additive_increase_capped_at_ceil() {
        let mut c = cc();
        for i in 0..20 {
            c.update((100, 100), Some(100_000), i * 200);
        }
        assert_eq!(c.rate_bps(), 8_000_000, "加性增不超 ceil");
    }

    #[test]
    fn decrease_clamped_at_floor() {
        let mut c = cc();
        for i in 0..30 {
            c.update((100, 90), Some(200_000), i * 200); // 膨胀+丢包双触发
        }
        assert_eq!(c.rate_bps(), 500_000, "乘性降不低 floor=max(ceil/16,64k)");
    }

    #[test]
    fn freeze_on_small_sample() {
        let mut c = cc();
        c.update((100, 100), Some(100_000), 0);
        let before = c.rate_bps();
        // 样本 10 < 32：即使丢包 90%+RTT 膨胀也冻结
        c.update((10, 1), Some(900_000), 200);
        assert_eq!(c.rate_bps(), before);
    }

    #[test]
    fn min_rtt_expiry_resets_baseline() {
        let mut c = cc();
        c.update((100, 100), Some(100_000), 0); // 基线 100ms@t0 → 3M
        // t=5s（未过期）rtt=120ms：+20% 未达阈值 → 增
        c.update((100, 100), Some(120_000), 5_000);
        assert_eq!(c.rate_bps(), 4_000_000);
        // t=11s（距基线建立超 10s）rtt=200ms：基线过期重置为 200ms，不判膨胀 → 增
        c.update((100, 100), Some(200_000), 11_000);
        assert_eq!(c.rate_bps(), 5_000_000, "旧基线锚死被过期重置防住");
        // t=11.2s rtt=200ms 贴新基线 → 增
        c.update((100, 100), Some(200_000), 11_200);
        assert_eq!(c.rate_bps(), 6_000_000);
        // 新基线下 260ms（+30%）→ 降
        c.update((100, 100), Some(260_000), 11_400);
        assert_eq!(c.rate_bps(), 4_200_000);
    }

    #[test]
    fn rtt_none_only_loss_judges() {
        let mut c = cc();
        // 无 RTT 信号（对端回执未往返）：零丢包 → 增
        c.update((100, 100), None, 0);
        assert_eq!(c.rate_bps(), 3_000_000);
        // 丢包高 → 降
        c.update((100, 90), None, 200);
        assert_eq!(c.rate_bps(), 2_100_000);
    }

    #[test]
    fn accumulates_low_rate_samples_then_acts() {
        // 低帧率场景：每份报告 expected=4（远小于 min_expected=32），
        // 逐份评估会恒冻结；累积到 32 才推进一次。
        let mut c = cc(); // ceil 8M，起步 2M，步长 1M
        let start = c.rate_bps();
        for i in 0..7 {
            c.update((4, 4), Some(100_000), i * 200);
        }
        assert_eq!(c.rate_bps(), start, "累计 28 (<32) 仍冻结");
        c.update((4, 4), Some(100_000), 7 * 200);
        assert_eq!(c.rate_bps(), start + 1_000_000, "累计 32 达标后 +ceil/8");
    }

    #[test]
    fn accumulates_low_rate_then_decrease_on_loss() {
        let mut c = cc();
        let start = c.rate_bps();
        // 4 份各 (8,8) 无丢，累计 32 → 好窗增一次
        for i in 0..4 {
            c.update((8, 8), Some(100_000), i * 200);
        }
        assert_eq!(c.rate_bps(), start + 1_000_000);
        // 累积窗内 (32,24)：丢 8/32 = 250‰ ≥ 30‰ → 乘性降
        for i in 0..4 {
            c.update((8, 6), Some(100_000), 800 + i * 200);
        }
        assert_eq!(c.rate_bps(), 2_100_000);
    }
}
