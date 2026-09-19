//! 两个滞回策略，均为纯函数状态机（时钟与计数由调用方注入）。
//!
//! 不对称原则（log 2026-09-19 对抗评审）：误熔断=丢冗余保护（高代价），
//! 该熔未熔=白耗一份带宽（低代价），阈值显著偏向不熔断；恢复门槛严于触发。

use crate::window::PathCounters;

/// --mp alt 路径熔断配置
#[derive(Debug, Clone, Copy)]
pub struct BreakerConfig {
    /// alt 收包年龄超此值=死透
    pub dead_age_ms: u32,
    /// alt 收包年龄小于此值=存活
    pub alive_age_ms: u32,
    /// closed→open：连续 N 个报告窗"main 活且 alt 死透"
    pub trigger_windows: u32,
    /// open→closed：连续 M 个报告窗 alt 高质量（M 严于 N）
    pub recover_windows: u32,
    /// 恢复窗 alt 收包/期望比下限（per-mille）
    pub recover_ratio_permille: u32,
    /// 恢复窗最小期望样本数（样本不足判中性）
    pub min_expected: u64,
}

impl Default for BreakerConfig {
    fn default() -> Self {
        // 报告周期 200ms：3 坏窗≈0.6s+死亡年龄 1s 才触发；恢复需 5 好窗≈1s
        Self {
            dead_age_ms: 1_000,
            alive_age_ms: 600,
            trigger_windows: 3,
            recover_windows: 5,
            recover_ratio_permille: 500,
            min_expected: 32,
        }
    }
}

enum AltVerdict {
    Dead,
    Good,
    Neutral,
}

/// alt 路径熔断滞回机
#[derive(Debug, Clone)]
pub struct Breaker {
    cfg: BreakerConfig,
    open: bool,
    bad_run: u32,
    good_run: u32,
}

impl Default for Breaker {
    fn default() -> Self {
        Self::new(BreakerConfig::default())
    }
}

impl Breaker {
    pub fn new(cfg: BreakerConfig) -> Self {
        Self { cfg, open: false, bad_run: 0, good_run: 0 }
    }

    fn classify(
        &self,
        main: &PathCounters,
        alt: &PathCounters,
        alt_delta: (u64, u64),
    ) -> AltVerdict {
        let main_alive = main.last_recv_age_ms <= self.cfg.alive_age_ms;
        let alt_dead = alt.last_recv_age_ms > self.cfg.dead_age_ms;
        let alt_alive = alt.last_recv_age_ms <= self.cfg.alive_age_ms;
        let (de, ds) = alt_delta;
        let ratio_ok =
            de >= self.cfg.min_expected && ds.saturating_mul(1000) >= de * u64::from(self.cfg.recover_ratio_permille);
        if main_alive && alt_dead {
            AltVerdict::Dead
        } else if alt_alive && ratio_ok {
            AltVerdict::Good
        } else {
            AltVerdict::Neutral
        }
    }

    /// 每份对端报告推进一次。`alt_delta`=(期望差, 到达差)，对端视角=本端发送质量
    pub fn update(&mut self, main: &PathCounters, alt: &PathCounters, alt_delta: (u64, u64)) {
        match self.classify(main, alt, alt_delta) {
            AltVerdict::Dead => {
                self.good_run = 0;
                if !self.open {
                    self.bad_run += 1;
                    if self.bad_run >= self.cfg.trigger_windows {
                        self.open = true;
                    }
                }
            }
            AltVerdict::Good => {
                self.bad_run = 0;
                if self.open {
                    self.good_run += 1;
                    if self.good_run >= self.cfg.recover_windows {
                        self.open = false;
                    }
                }
            }
            // 中性：open 态不恢复（证据不足）；closed 态不熔断
            AltVerdict::Neutral => {
                self.good_run = 0;
                if !self.open {
                    self.bad_run = 0;
                }
            }
        }
    }

    /// true=本端出站应停发 alt（熔断中）
    pub fn alt_disabled(&self) -> bool {
        self.open
    }
}

/// FEC 自适应门控配置
#[derive(Debug, Clone, Copy)]
pub struct GateConfig {
    /// 并集丢包率 ≥ 此值（per-mille）计高
    pub on_loss_permille: u32,
    /// 丢包率 ≤ 此值计低
    pub off_loss_permille: u32,
    pub on_windows: u32,
    pub off_windows: u32,
    /// 区间最小期望样本数，不足则冻结
    pub min_expected: u64,
}

impl Default for GateConfig {
    fn default() -> Self {
        Self {
            on_loss_permille: 30,
            off_loss_permille: 5,
            on_windows: 2,
            off_windows: 5,
            min_expected: 32,
        }
    }
}

/// FEC 启停滞回门（初始关闭）
#[derive(Debug, Clone)]
pub struct FecGate {
    cfg: GateConfig,
    on: bool,
    high_run: u32,
    low_run: u32,
}

impl Default for FecGate {
    fn default() -> Self {
        Self::new(GateConfig::default())
    }
}

impl FecGate {
    pub fn new(cfg: GateConfig) -> Self {
        Self { cfg, on: false, high_run: 0, low_run: 0 }
    }

    /// 每份对端报告的 union 槽推进；delta=(期望差, 唯一到达差)
    pub fn update(&mut self, delta: (u64, u64)) {
        let (expected, seen) = delta;
        if expected < self.cfg.min_expected {
            return; // 样本不足：两边计数冻结，保持现状
        }
        let lost = expected.saturating_sub(seen).min(expected);
        let permille = (lost.saturating_mul(1000) / expected) as u32;
        if !self.on {
            if permille >= self.cfg.on_loss_permille {
                self.high_run += 1;
                self.low_run = 0;
                if self.high_run >= self.cfg.on_windows {
                    self.on = true;
                }
            } else {
                self.high_run = 0;
            }
        } else if permille <= self.cfg.off_loss_permille {
            self.low_run += 1;
            self.high_run = 0;
            if self.low_run >= self.cfg.off_windows {
                self.on = false;
            }
        } else {
            self.low_run = 0;
        }
    }

    /// true=本端出站应加 FEC
    pub fn enabled(&self) -> bool {
        self.on
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pc(age: u32) -> PathCounters {
        PathCounters { last_recv_age_ms: age, ..Default::default() }
    }

    #[test]
    fn breaker_three_dead_then_five_good() {
        let mut b = Breaker::default();
        let live = pc(100);
        let dead = pc(u32::MAX);
        // 未连满 3 次不熔断
        b.update(&live, &dead, (100, 0));
        b.update(&live, &dead, (100, 0));
        assert!(!b.alt_disabled());
        b.update(&live, &dead, (100, 0));
        assert!(b.alt_disabled());
        // open 后好窗不足 5 不恢复；插入中性清零
        let good = pc(100);
        for _ in 0..4 {
            b.update(&live, &good, (100, 100));
        }
        assert!(b.alt_disabled());
        b.update(&live, &pc(800), (100, 50)); // 中性
        b.update(&live, &good, (100, 100)); // good_run=1（清零后重数）
        assert!(b.alt_disabled());
        for _ in 0..3 {
            b.update(&live, &good, (100, 100));
        }
        assert!(b.alt_disabled()); // 累计 4，仍不恢复
        b.update(&live, &good, (100, 100)); // 第 5 连好窗
        assert!(!b.alt_disabled());
    }

    #[test]
    fn breaker_never_fires_when_main_also_dead() {
        // 双断=链路整体问题，不是 alt 单路径故障，保持双发
        let mut b = Breaker::default();
        for _ in 0..10 {
            b.update(&pc(u32::MAX), &pc(u32::MAX), (0, 0));
        }
        assert!(!b.alt_disabled());
    }

    #[test]
    fn gate_hysteresis() {
        let mut g = FecGate::default();
        // 30% 丢包，2 窗开
        g.update((100, 70));
        assert!(!g.enabled());
        g.update((100, 70));
        assert!(g.enabled());
        // 20% 居中保持
        for _ in 0..10 {
            g.update((100, 80));
        }
        assert!(g.enabled());
        // ≤5‰ 需要 5 连窗关
        for _ in 0..4 {
            g.update((100, 100));
        }
        assert!(g.enabled());
        g.update((100, 80)); // 中断清零
        for _ in 0..4 {
            g.update((100, 100));
        }
        assert!(g.enabled());
        g.update((100, 100));
        assert!(!g.enabled());
        // 样本不足冻结
        g.update((10, 1));
        assert!(!g.enabled());
    }
}
