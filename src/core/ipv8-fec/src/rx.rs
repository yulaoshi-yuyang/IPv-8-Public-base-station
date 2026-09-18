//! FEC 接收侧状态机（spec FR-5）。
//!
//! 用法：node 层把到达的 Data 帧喂 [`FecRx::observe_data`]（以 AEAD 计数器
//! 为键缓存，环形上限防膨胀）；Type=6 帧喂 [`FecRx::accept_recovery`]：
//! 按恢复帧携带的成员表比对缓存——缺 1 帧 XOR 重建、缺 ≥2 放弃（K 选 1）。
//! 重建帧经 node 层走正常 decapsulate，AEAD 校验兜底正确性。
//!
//! `--mp` 双发下同一恢复帧到达两次 → 按 group_seq 去重（MAX_SEEN_GROUPS）。

use std::collections::{HashMap, VecDeque};

use crate::{data_counter, xor_into, FecError, DATA_MIN_FRAME, FRAME_HEADER_SIZE,
            MAX_SEEN_GROUPS, RECOVERY_FIXED_BODY};

/// 隧道版本 / Data 帧类型判别值（frame.rs 本地副本，零依赖）
const TUNNEL_VERSION: u8 = 0x01;
const DATA_FRAME_TYPE: u8 = 2;
const FEC_FRAME_TYPE: u8 = 6;

/// 接收侧状态机：Data 帧缓存 + 恢复帧重建
pub struct FecRx {
    /// 成员缓存：AEAD 计数器 → 完整 Data 帧
    cache: HashMap<u64, Vec<u8>>,
    /// 到达序（环形淘汰用；同计数器重复帧不重复入队）
    order: VecDeque<u64>,
    limit: usize,
    /// 已处理恢复帧组序号（去重；环形上限 MAX_SEEN_GROUPS）
    seen_groups: VecDeque<u64>,
    /// 成功重建帧数
    pub recovered: u64,
    /// 缺 ≥2 帧放弃的组数
    pub abandoned: u64,
    /// 重复恢复帧数（--mp 双发去重）
    pub dup_recovery: u64,
}

impl FecRx {
    /// limit=0 视为用默认值（防御调用方误配，不 panic）
    pub fn new(limit: usize) -> Self {
        Self {
            cache: HashMap::new(),
            order: VecDeque::new(),
            limit: if limit == 0 { crate::DEFAULT_RX_CACHE } else { limit },
            seen_groups: VecDeque::new(),
            recovered: 0,
            abandoned: 0,
            dup_recovery: 0,
        }
    }

    /// 当前缓存帧数（观测用）
    pub fn cached(&self) -> usize {
        self.cache.len()
    }

    /// 收到一个 Data 帧（完整帧）→ 以计数器为键缓存。
    /// 重复计数器（--mp 双发/重排）覆盖值、不重复占淘汰位。
    /// 帧长不足仅报错，调用方忽略即可（不影响隧道主链路）。
    pub fn observe_data(&mut self, frame: &[u8]) -> Result<(), FecError> {
        if frame.len() < DATA_MIN_FRAME {
            return Err(FecError::TooShort(frame.len()));
        }
        let counter = data_counter(frame)?;
        // 同计数器重复帧（--mp 双发/重排）：覆盖值、不重复占淘汰位
        match self.cache.entry(counter) {
            std::collections::hash_map::Entry::Occupied(mut e) => {
                e.insert(frame.to_vec());
                return Ok(());
            }
            std::collections::hash_map::Entry::Vacant(e) => {
                e.insert(frame.to_vec());
            }
        }
        self.order.push_back(counter);
        while self.cache.len() > self.limit {
            if let Some(oldest) = self.order.pop_front() {
                // order 与 cache 键一一对应（重复不入队），直接移除即可
                self.cache.remove(&oldest);
            }
        }
        Ok(())
    }

    /// 收到一个 FecRecovery 帧（完整帧，含 10B 帧头）。
    /// 返回 `Some(重建的完整 Data 帧)`（恰缺 1 帧时）；其余情况 `Ok(None)`。
    pub fn accept_recovery(&mut self, frame: &[u8]) -> Result<Option<Vec<u8>>, FecError> {
        // —— 结构校验（全边界，绝不 panic）——
        let fixed_end = FRAME_HEADER_SIZE + RECOVERY_FIXED_BODY;
        if frame.len() < fixed_end {
            return Err(FecError::BodyTooShort { need: fixed_end, got: frame.len() });
        }
        if frame[0] != TUNNEL_VERSION || frame[1] != FEC_FRAME_TYPE {
            return Err(FecError::SanityCheck);
        }
        let group_seq = u64::from_be_bytes(frame[10..18].try_into().unwrap());
        let k = frame[18] as usize;
        if !(crate::FEC_MIN_K..=crate::FEC_MAX_K).contains(&k) {
            return Err(FecError::BadK(k));
        }
        let table_end = fixed_end + k * 10;
        if frame.len() < table_end {
            return Err(FecError::BodyTooShort { need: table_end, got: frame.len() });
        }

        // —— 组去重（--mp 双发同帧）——
        if self.seen_groups.contains(&group_seq) {
            self.dup_recovery += 1;
            return Ok(None);
        }

        // —— 成员表 ——
        let mut counters = Vec::with_capacity(k);
        let mut lens = Vec::with_capacity(k);
        for i in 0..k {
            let co = FRAME_HEADER_SIZE + RECOVERY_FIXED_BODY + i * 8;
            counters.push(u64::from_be_bytes(frame[co..co + 8].try_into().unwrap()));
        }
        for i in 0..k {
            let lo = fixed_end + k * 8 + i * 2;
            lens.push(u16::from_be_bytes(frame[lo..lo + 2].try_into().unwrap()) as usize);
        }
        let xor_len = frame.len() - table_end;
        let max_len = *lens.iter().max().unwrap_or(&0);
        if xor_len != max_len {
            return Err(FecError::XorLenMismatch { expect: max_len, got: xor_len });
        }
        for l in &lens {
            if *l < DATA_MIN_FRAME {
                return Err(FecError::BadMemberLen(*l));
            }
        }

        self.seen_groups.push_back(group_seq);
        while self.seen_groups.len() > MAX_SEEN_GROUPS {
            self.seen_groups.pop_front();
        }

        // —— 在席/缺失判定 ——
        let mut missing: Option<usize> = None;
        let mut missing_count = 0usize;
        for (i, c) in counters.iter().enumerate() {
            if !self.cache.contains_key(c) {
                missing_count += 1;
                if missing_count > 1 {
                    break;
                }
                missing = Some(i);
            }
        }
        match missing_count {
            // 全在席：恢复帧冗余（双发竞速常态），无需重建
            0 => Ok(None),
            // 缺 ≥2：XOR 只能救 1
            n if n > 1 => {
                self.abandoned += 1;
                Ok(None)
            }
            // 恰缺 1：XOR 重建（missing 必为 Some，防御性兜底拒绝）
            1 => {
                let Some(mi) = missing else {
                    return Err(FecError::SanityCheck);
                };
                let mut recon = frame[table_end..].to_vec();
                for (i, c) in counters.iter().enumerate() {
                    if i != mi {
                        if let Some(m) = self.cache.get(c) {
                            xor_into(&mut recon, m);
                        }
                    }
                }
                // 截到缺失成员声明的帧长（XOR 零填充尾部去除）
                let want = lens[mi];
                if recon.len() < want {
                    // xor 段不可能短于 max(len) ≥ want；防御性拒绝
                    return Err(FecError::XorLenMismatch { expect: want, got: recon.len() });
                }
                recon.truncate(want);
                // 自检：版本/类型/计数器一致性（防篡改/错配；AEAD 仍兜底）
                if recon[0] != TUNNEL_VERSION
                    || recon[1] != DATA_FRAME_TYPE
                    || data_counter(&recon)? != counters[mi]
                {
                    return Err(FecError::SanityCheck);
                }
                self.recovered += 1;
                Ok(Some(recon))
            }
            // 理论不可达（missing_count 只能 0/1/≥2），防御性穷尽
            _ => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::synth_data_frame;

    /// 把 K 个成员喂 TX 产出一个恢复帧 + 返回成员帧
    fn make_group(k: usize, base_counter: u64) -> (Vec<Vec<u8>>, Vec<u8>) {
        let mut tx = crate::FecTx::new(k).unwrap();
        let mut members = Vec::new();
        let mut rec = None;
        for i in 0..k as u64 {
            let f = synth_data_frame(base_counter + i, (i as u8) * 7 + 1, 40 + (i as usize % 3) * 8);
            members.push(f.clone());
            if let Some(r) = tx.push(&f, [0xAA; 8]).unwrap() {
                rec = Some(r);
            }
        }
        (members, rec.expect("组满必产出"))
    }

    /// AC-1 矩阵：K=4 组，任意位置丢 1 帧 → 逐字节重建
    #[test]
    fn recovers_each_missing_position() {
        for drop_pos in 0..4usize {
            let (members, rec) = make_group(4, 900);
            let dropped = members[drop_pos].clone();
            let mut rx = FecRx::new(0);
            for (i, m) in members.iter().enumerate() {
                if i != drop_pos {
                    rx.observe_data(m).unwrap();
                }
            }
            let recon = rx.accept_recovery(&rec)
                .expect("缺 1 必须成功重建")
                .expect("产出重建帧");
            assert_eq!(recon, dropped, "丢第 {drop_pos} 帧重建逐字节不一致");
            assert_eq!(rx.recovered, 1);
            assert_eq!(rx.abandoned, 0);
        }
    }

    /// AC-1 扩展：K=2/8/16 与长短帧混合（max 帧丢失场景）
    #[test]
    fn recovers_across_k_and_mixed_lengths() {
        for k in [2usize, 8, 16] {
            let mut tx = crate::FecTx::new(k).unwrap();
            let mut members = Vec::new();
            let mut rec = None;
            for i in 0..k as u64 {
                // 长度交替 74 / 138，最短在最前、最长在最后
                let f = synth_data_frame(500 + i, i as u8 * 3, 40 + (i as usize % 2) * 64);
                members.push(f.clone());
                if let Some(r) = tx.push(&f, [0xBB; 8]).unwrap() {
                    rec = Some(r);
                }
            }
            let rec = rec.unwrap();
            // 丢最长帧（xor 边界场景）
            let mut rx = FecRx::new(0);
            for (i, m) in members.iter().enumerate() {
                if i != k - 1 {
                    rx.observe_data(m).unwrap();
                }
            }
            let recon = rx.accept_recovery(&rec).unwrap().unwrap();
            assert_eq!(recon, members[k - 1], "K={k} 丢最长帧重建失败");
            // 丢最短帧
            let mut rx2 = FecRx::new(0);
            for (i, m) in members.iter().enumerate() {
                if i != 0 {
                    rx2.observe_data(m).unwrap();
                }
            }
            let recon2 = rx2.accept_recovery(&rec).unwrap().unwrap();
            assert_eq!(recon2, members[0], "K={k} 丢最短帧重建失败");
        }
    }

    /// AC-3 库侧：QoS 门控由调用方实现——只喂标记帧，未标记帧不出现在成员表
    #[test]
    fn group_members_only_marked_frames() {
        let mut tx = crate::FecTx::new(4).unwrap();
        let mut rec = None;
        // counter 700..706：标记 = 奇数或 i>=4（即 701,703,704,705 入组；700,702 未标记不喂）
        let mut fed = Vec::new();
        for i in 0..6u64 {
            let marked = i % 2 != 0 || i >= 4;
            if !marked {
                continue;
            }
            let f = synth_data_frame(700 + i, 1, 40);
            fed.push(700 + i);
            if let Some(r) = tx.push(&f, [0xCC; 8]).unwrap() {
                rec = Some(r);
            }
        }
        let rec = rec.expect("凑满 K=4 标记帧必产出");
        assert_eq!(fed, vec![701u64, 703, 704, 705]);
        // 成员表 = 仅被标记的 4 帧；xor 段长度 = max 成员帧长
        for (i, c) in fed.iter().enumerate() {
            let off = 22 + i * 8;
            assert_eq!(u64::from_be_bytes(rec[off..off + 8].try_into().unwrap()), *c);
        }
    }

    #[test]
    fn observe_rejects_short() {
        let mut rx = FecRx::new(0);
        assert!(matches!(
            rx.observe_data(&[0u8; DATA_MIN_FRAME - 1]),
            Err(FecError::TooShort(_))
        ));
    }

    #[test]
    fn accept_rejects_malformed() {
        let mut rx = FecRx::new(0);
        // 截断（不足固定段 22B）
        assert!(matches!(
            rx.accept_recovery(&[0u8; 20]),
            Err(FecError::BodyTooShort { .. })
        ));
        // 错误版本/类型（长度足够，头字段不对）
        let mut bad = vec![0x01, 0x02];
        bad.resize(22, 0);
        assert!(matches!(rx.accept_recovery(&bad), Err(FecError::SanityCheck)));
        let mut bad2 = vec![0x02, 0x06];
        bad2.resize(22, 0);
        assert!(matches!(rx.accept_recovery(&bad2), Err(FecError::SanityCheck)));
        // k=0 / k=17（帧头 10B + 固定段完整，k 越界先于成员表长度检查）
        let mut badk = vec![0x01, 0x06];
        badk.extend_from_slice(&[0xAA; 8]); // KeyID
        badk.extend_from_slice(&[0u8; 8]); // group_seq
        badk.push(0); // k=0
        badk.extend_from_slice(&[0, 0, 0]);
        assert_eq!(badk.len(), 22);
        assert!(matches!(rx.accept_recovery(&badk), Err(FecError::BadK(0))));
        badk[18] = 17;
        assert!(matches!(rx.accept_recovery(&badk), Err(FecError::BadK(17))));
        // 成员表截断（k=4 但帧体只含 2 个 counter 的位置）
        let mut trunc = vec![0x01, 0x06];
        trunc.extend_from_slice(&[0xAA; 8]); // KeyID
        trunc.extend_from_slice(&[0u8; 8]); // group_seq
        trunc.push(4); // k
        trunc.extend_from_slice(&[0, 0, 0]); // 保留
        trunc.extend_from_slice(&[0u8; 16]); // 仅 2 个 counter 的空间
        assert!(matches!(
            rx.accept_recovery(&trunc),
            Err(FecError::BodyTooShort { .. })
        ));
    }

    #[test]
    fn duplicate_group_dedup() {
        let (members, rec) = make_group(4, 100);
        let mut rx = FecRx::new(0);
        for m in &members {
            rx.observe_data(m).unwrap();
        }
        assert!(rx.accept_recovery(&rec).unwrap().is_none()); // 全在席
        assert!(rx.accept_recovery(&rec).unwrap().is_none());
        assert_eq!(rx.dup_recovery, 1);
    }

    #[test]
    fn missing_two_abandons() {
        let (members, rec) = make_group(4, 200);
        let mut rx = FecRx::new(0);
        for (i, m) in members.iter().enumerate() {
            if i != 0 && i != 2 {
                rx.observe_data(m).unwrap();
            }
        }
        assert!(rx.accept_recovery(&rec).unwrap().is_none());
        assert_eq!(rx.abandoned, 1);
        // 状态可续：下一组正常服务（新 tx 实例 group_seq 撞 0，patch 成 5 走真实路径）
        let (m2, mut r2) = make_group(4, 300);
        for m in &m2 {
            rx.observe_data(m).unwrap();
        }
        rx.observe_data(&m2[1]).unwrap(); // 同计数器重复帧无害（覆盖值）
        r2[10..18].copy_from_slice(&5u64.to_be_bytes());
        assert!(rx.accept_recovery(&r2).unwrap().is_none());
        assert_eq!(rx.abandoned, 1, "后续组不受污染");
    }

    #[test]
    fn cache_ring_evicts_oldest() {
        let mut rx = FecRx::new(4);
        for i in 0..6u64 {
            rx.observe_data(&synth_data_frame(i, 1, 40)).unwrap();
            assert!(rx.cached() <= 4);
        }
        // 计数器 0/1 已被环形淘汰：单靠它们无法恢复（缺 2 放弃）；
        // 计数器 4/5 仍在缓存：对应组可恢复
        let mut tx = crate::FecTx::new(2).unwrap();
        let f4 = synth_data_frame(4, 9, 40);
        let f5 = synth_data_frame(5, 9, 40);
        let rec = tx.push(&f4, [0xAA; 8]).unwrap();
        assert!(rec.is_none());
        let rec = tx.push(&f5, [0xAA; 8]).unwrap().unwrap();
        assert!(rx.accept_recovery(&rec).unwrap().is_none(), "4/5 仍在缓存");
        let f0 = synth_data_frame(0, 9, 40);
        let f1 = synth_data_frame(1, 9, 40);
        let mut tx2 = crate::FecTx::new(2).unwrap();
        tx2.push(&f0, [0xAA; 8]).unwrap();
        let mut rec01 = tx2.push(&f1, [0xAA; 8]).unwrap().unwrap();
        // tx2 是新实例、group_seq 从 0 起，与上组撞号——手工改成 77 避开去重
        rec01[10..18].copy_from_slice(&77u64.to_be_bytes());
        assert!(rx.accept_recovery(&rec01).unwrap().is_none(), "0/1 已淘汰放弃");
        assert_eq!(rx.abandoned, 1);
    }

    #[test]
    fn xor_len_mismatch_rejected() {
        let (members, mut rec) = make_group(2, 400);
        rec.pop(); // 截掉 1 字节 xor 段
        let mut rx = FecRx::new(0);
        for m in &members {
            rx.observe_data(m).unwrap();
        }
        rx.observe_data(&members[0]).unwrap();
        assert!(matches!(
            rx.accept_recovery(&rec),
            Err(FecError::XorLenMismatch { .. })
        ));
    }
}
