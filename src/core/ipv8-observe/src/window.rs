//! Data 帧计数器接收观测：稀疏滑动窗 + 跨密钥代（SA）累计统计。
//!
//! 计数器是 Data 帧尾的明文 AEAD nonce，无需解密即可提取。每个 SA（帧头 KeyID）
//! 一个窗口；窗口口径对齐 tunnel `RxWindow`（128 宽位图），累计量单调递增供
//! 回执按周期做差值：`expected`=计数器跨度（丢包分母），`seen`=唯一到达帧数。

/// 稀疏位图宽度：top..=top-127（与 tunnel RxWindow 同宽）
pub(crate) const WINDOW_BITS: u64 = 128;

/// 计数器跨度超过此值视为计数器重置/异常路径，缺口不可信，只计本帧。
pub(crate) const JUMP_GUARD: u64 = 4096;

/// 保留的最大 SA 窗口数（密钥轮换后旧窗口留账，超出丢最旧）
const MAX_SAS: usize = 8;

/// 帧长下限：帧头(10)+明文基础头(40)+计数器(8)+tag(16)
pub const DATA_MIN_FRAME: usize = 74;
pub(crate) const FRAME_HEADER_LEN: usize = 10;
pub(crate) const TUNNEL_VERSION: u8 = 0x01;
pub(crate) const DATA_FRAME_TYPE: u8 = 2;
/// 计数器距帧尾的偏移：len-24..len-16
const COUNTER_FROM_END: usize = 24;

/// 单路径（或并集）截至某时刻的累计计数（u64 累计，对端做 wrapping 差值）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathCounters {
    /// 计数器跨度累计（首帧计 1）——丢包率分母
    pub expected: u64,
    /// 唯一到达帧数（补洞也计）
    pub seen: u64,
    /// 重复帧/窗外迟到帧
    pub dup: u64,
    /// 计数器重置/异常跳跃次数
    pub resets: u32,
    /// 最后一帧距快照时刻的毫秒年龄；`u32::MAX` = 从未收到
    pub last_recv_age_ms: u32,
}

impl Default for PathCounters {
    fn default() -> Self {
        Self {
            expected: 0,
            seen: 0,
            dup: 0,
            resets: 0,
            last_recv_age_ms: u32::MAX,
        }
    }
}

/// 从线帧提取 (KeyID, counter)；非 Data/过短/版本不符返回 None。
pub(crate) fn frame_meta(frame: &[u8]) -> Option<(u64, u64)> {
    if frame.len() < DATA_MIN_FRAME
        || frame[0] != TUNNEL_VERSION
        || frame[1] != DATA_FRAME_TYPE
    {
        return None;
    }
    let mut k = [0u8; 8];
    k.copy_from_slice(&frame[2..FRAME_HEADER_LEN]);
    let tail = frame.len() - COUNTER_FROM_END;
    let mut c = [0u8; 8];
    c.copy_from_slice(&frame[tail..tail + 8]);
    Some((u64::from_be_bytes(k), u64::from_be_bytes(c)))
}

#[derive(Debug, Clone)]
struct CounterWindow {
    top: u64,
    /// bit0=top，bit k=top-k
    mask: u128,
    expected: u64,
    seen: u64,
    dup: u64,
    resets: u32,
}

impl CounterWindow {
    fn first(c: u64) -> Self {
        Self { top: c, mask: 1, expected: 1, seen: 1, dup: 0, resets: 0 }
    }

    fn observe(&mut self, c: u64) {
        if c > self.top {
            let delta = c - self.top;
            if delta > JUMP_GUARD {
                // 重置/异常：旧账不再相关，缺口不进 expected
                self.top = c;
                self.mask = 1;
                self.expected = self.expected.saturating_add(1);
                self.seen = self.seen.saturating_add(1);
                self.resets = self.resets.saturating_add(1);
            } else {
                self.mask = if delta >= WINDOW_BITS {
                    0
                } else {
                    self.mask << (delta as u32)
                };
                self.mask |= 1;
                self.expected = self.expected.saturating_add(delta);
                self.seen = self.seen.saturating_add(1);
                self.top = c;
            }
        } else {
            let back = self.top - c;
            if back >= WINDOW_BITS {
                self.dup = self.dup.saturating_add(1);
            } else {
                let bit = 1u128 << back;
                if self.mask & bit != 0 {
                    self.dup = self.dup.saturating_add(1);
                } else {
                    self.mask |= bit;
                    self.seen = self.seen.saturating_add(1);
                }
            }
        }
    }

    fn totals(&self) -> (u64, u64, u64, u32) {
        (self.expected, self.seen, self.dup, self.resets)
    }
}

/// 一组按 KeyID 分窗的计数器（单路径或双路径并集共用此结构）。
#[derive(Debug, Clone, Default)]
pub(crate) struct SaWindows {
    entries: Vec<(u64, CounterWindow)>,
}

impl SaWindows {
    pub(crate) fn observe(&mut self, key: u64, counter: u64) {
        match self.entries.iter().position(|(k, _)| *k == key) {
            Some(i) => self.entries[i].1.observe(counter),
            None => {
                self.entries.push((key, CounterWindow::first(counter)));
                if self.entries.len() > MAX_SAS {
                    self.entries.remove(0);
                }
            }
        }
    }

    /// 汇总所有 SA 的累计计数（不含年龄，年龄由 PathState/调用方给）
    pub(crate) fn totals(&self) -> (u64, u64, u64, u32) {
        let mut e = 0u64;
        let mut s = 0u64;
        let mut d = 0u64;
        let mut r = 0u32;
        for (_, w) in &self.entries {
            let (we, ws, wd, wr) = w.totals();
            e = e.saturating_add(we);
            s = s.saturating_add(ws);
            d = d.saturating_add(wd);
            r = r.saturating_add(wr);
        }
        (e, s, d, r)
    }
}

/// 单条物理路径（main/alt）的接收观测状态。
#[derive(Debug, Clone, Default)]
pub struct PathState {
    pub(crate) sas: SaWindows,
    last_recv_ms: Option<u64>,
    /// 原始 Data 到达帧数（含重复，诊断用）
    pub raw_frames: u64,
}

impl PathState {
    pub fn new() -> Self {
        Self::default()
    }

    /// 喂入一个原始入站帧（密文即可，计数器在明文帧尾）。
    /// 非 Data/过短返回 false，不产生计数。
    pub fn observe_data(&mut self, now_ms: u64, frame: &[u8]) -> bool {
        let Some((key, counter)) = frame_meta(frame) else {
            return false;
        };
        self.sas.observe(key, counter);
        self.last_recv_ms = Some(now_ms);
        self.raw_frames = self.raw_frames.saturating_add(1);
        true
    }

    /// 累计计数快照（年龄按调用方时钟计算）
    pub fn counters(&self, now_ms: u64) -> PathCounters {
        let (expected, seen, dup, resets) = self.sas.totals();
        let last_recv_age_ms = match self.last_recv_ms {
            Some(t) if now_ms >= t => (now_ms - t).min(u32::MAX as u64) as u32,
            _ => u32::MAX,
        };
        PathCounters { expected, seen, dup, resets, last_recv_age_ms }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(counter: u64, key: u64) -> Vec<u8> {
        let mut f = vec![0u8; DATA_MIN_FRAME];
        f[0] = TUNNEL_VERSION;
        f[1] = DATA_FRAME_TYPE;
        f[2..10].copy_from_slice(&key.to_be_bytes());
        let tail = f.len() - COUNTER_FROM_END;
        f[tail..tail + 8].copy_from_slice(&counter.to_be_bytes());
        f
    }

    #[test]
    fn ordered_sequence_no_loss() {
        let mut p = PathState::new();
        for c in 1..=100u64 {
            assert!(p.observe_data(0, &frame(c, 1)));
        }
        let s = p.counters(1_000);
        assert_eq!((s.expected, s.seen, s.dup, s.resets), (100, 100, 0, 0));
        assert_eq!(s.last_recv_age_ms, 1_000);
    }

    #[test]
    fn gaps_count_as_expected_not_seen() {
        let mut p = PathState::new();
        for c in (1..=10u64).filter(|c| *c != 5) {
            p.observe_data(0, &frame(c, 1));
        }
        let s = p.counters(0);
        assert_eq!(s.expected, 10);
        assert_eq!(s.seen, 9);
    }

    #[test]
    fn reorder_fills_gap() {
        let mut p = PathState::new();
        for c in [1u64, 2, 3, 4, 6, 7] {
            p.observe_data(0, &frame(c, 1));
        }
        assert_eq!(p.counters(0).seen, 6);
        // 迟到补洞：seen+1，expected 不动
        p.observe_data(0, &frame(5, 1));
        let s = p.counters(0);
        assert_eq!((s.expected, s.seen), (7, 7));
    }

    #[test]
    fn duplicates_and_old_frames_count_dup() {
        let mut p = PathState::new();
        for c in 1..=10u64 {
            p.observe_data(0, &frame(c, 1));
        }
        p.observe_data(0, &frame(10, 1)); // 窗内重复
        p.observe_data(0, &frame(1, 1)); // 窗内重复
        p.observe_data(0, &frame(1, 1));
        assert_eq!(p.counters(0).dup, 3);
        // 窗外旧帧
        for c in 200..=260u64 {
            p.observe_data(0, &frame(c, 1));
        }
        p.observe_data(0, &frame(10, 1));
        assert_eq!(p.counters(0).dup, 4);
    }

    #[test]
    fn big_jump_is_reset_not_loss() {
        let mut w = SaWindows::default();
        for c in 1..=10u64 {
            w.observe(1, c);
        }
        w.observe(1, 5000);
        let (e, s, _d, r) = w.totals();
        assert_eq!((e, s, r), (11, 11, 1));
    }

    #[test]
    fn multiple_sas_are_separate() {
        let mut p = PathState::new();
        p.observe_data(0, &frame(1, 100));
        p.observe_data(0, &frame(1, 200));
        p.observe_data(0, &frame(2, 100));
        p.observe_data(0, &frame(2, 200));
        let s = p.counters(0);
        assert_eq!((s.expected, s.seen), (4, 4));
    }

    #[test]
    fn rejects_non_data_and_short() {
        let mut p = PathState::new();
        let mut bad = frame(1, 1);
        bad[1] = 6;
        assert!(!p.observe_data(0, &bad));
        assert!(!p.observe_data(0, &[0u8; 73]));
        let s = p.counters(0);
        assert_eq!((s.expected, s.seen, p.raw_frames), (0, 0, 0));
        assert_eq!(s.last_recv_age_ms, u32::MAX);
    }
}
