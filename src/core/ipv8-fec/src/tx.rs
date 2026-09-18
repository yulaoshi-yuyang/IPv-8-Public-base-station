//! FEC 发送侧组窗状态机（spec FR-4 / FR-3 帧格式）。
//!
//! 用法：node 层在密封后、发送前把**被 QoS 标记**的 Data 帧逐个
//! [`FecTx::push`]；每凑满 K 帧产出 1 个完整 FecRecovery 帧（含 10B 帧头），
//! 与成员 Data 帧一并交给发送。未满 K 的尾部残留自动滚动进下一组
//! （滑动分组，帧永不丢弃，只延迟到组满）。
//!
//! QoS 门控不在本库：调用方只喂标记帧（TR-1.3）。

use crate::{data_counter, xor_into, FecError, DATA_MIN_FRAME, FEC_MAX_K, FEC_MIN_K,
            FRAME_HEADER_SIZE, RECOVERY_FIXED_BODY};

/// 隧道版本字节（ipv8-tunnel `TUNNEL_VERSION` 本地副本，零依赖）
const TUNNEL_VERSION: u8 = 0x01;
/// FrameType::FecRecovery 判别值
pub(crate) const FEC_FRAME_TYPE: u8 = 6;

/// 发送侧组窗：连续 K 个标记 Data 帧 → 1 个 XOR 恢复帧
pub struct FecTx {
    k: usize,
    /// 下一个恢复帧的组序号（产出后 +1，u64 回绕无害）
    group_seq: u64,
    /// 当前组 XOR 累加器（长度 = 组内最大帧长，短帧右侧零填充）
    acc: Vec<u8>,
    /// 当前组成员 AEAD 计数器（成员标识）
    counters: Vec<u64>,
    /// 当前组成员原始帧长
    lens: Vec<u16>,
}

impl FecTx {
    /// k 超出 2..=16 报 [`FecError::BadK`]
    pub fn new(k: usize) -> Result<Self, FecError> {
        if !(FEC_MIN_K..=FEC_MAX_K).contains(&k) {
            return Err(FecError::BadK(k));
        }
        Ok(Self {
            k,
            group_seq: 0,
            acc: Vec::new(),
            counters: Vec::with_capacity(k),
            lens: Vec::with_capacity(k),
        })
    }

    /// 当前组已收集帧数（测试/观测用）
    pub fn pending(&self) -> usize {
        self.counters.len()
    }

    /// 组大小
    pub fn k(&self) -> usize {
        self.k
    }

    /// 喂入一个已密封 Data 帧（完整帧，含 10B 帧头）。
    /// 组满 K 时返回 `Some(完整 FecRecovery 帧)` 并开启下一组。
    ///
    /// `key_id` 取当前密钥代（恢复帧头仅作路径一致性标记，spec FR-3）。
    pub fn push(
        &mut self,
        frame: &[u8],
        key_id: [u8; 8],
    ) -> Result<Option<Vec<u8>>, FecError> {
        if frame.len() < DATA_MIN_FRAME {
            return Err(FecError::TooShort(frame.len()));
        }
        let counter = data_counter(frame)?;
        // 累加器扩到新最大帧长（旧内容左侧不动、右侧语义为零填充已满足）
        if frame.len() > self.acc.len() {
            self.acc.resize(frame.len(), 0);
        }
        xor_into(&mut self.acc, frame);
        self.counters.push(counter);
        // 帧长上界受 MTU 约束 < 65535，u16 恒可容纳；防御钳制不 panic
        self.lens.push(u16::try_from(frame.len()).unwrap_or(u16::MAX));

        if self.counters.len() < self.k {
            return Ok(None);
        }
        let out = self.encode_recovery(key_id);
        self.group_seq = self.group_seq.wrapping_add(1);
        self.acc.clear();
        self.counters.clear();
        self.lens.clear();
        Ok(Some(out))
    }

    /// 编码恢复帧（FR-3 帧体布局，长度恒可整除、无截断路径）
    fn encode_recovery(&self, key_id: [u8; 8]) -> Vec<u8> {
        let k = self.counters.len();
        let mut f = Vec::with_capacity(
            FRAME_HEADER_SIZE + RECOVERY_FIXED_BODY + k * 10 + self.acc.len(),
        );
        // 帧头：Ver ‖ Type ‖ KeyID
        f.push(TUNNEL_VERSION);
        f.push(FEC_FRAME_TYPE);
        f.extend_from_slice(&key_id);
        // 固定段：group_seq ‖ k ‖ 保留(3B,0)
        f.extend_from_slice(&self.group_seq.to_be_bytes());
        f.push(k as u8);
        f.extend_from_slice(&[0u8; 3]);
        // 成员表：counter[k] ‖ len[k]
        for c in &self.counters {
            f.extend_from_slice(&c.to_be_bytes());
        }
        for l in &self.lens {
            f.extend_from_slice(&l.to_be_bytes());
        }
        // xor 段（长度 = 组内最大帧长）
        f.extend_from_slice(&self.acc);
        debug_assert_eq!(f.len(),
            FRAME_HEADER_SIZE + RECOVERY_FIXED_BODY + k * 10 + self.acc.len());
        f
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{data_counter, RECOVERY_FIXED_BODY};

    fn key() -> [u8; 8] {
        [0xAA; 8]
    }

    #[test]
    fn new_rejects_bad_k() {
        assert!(matches!(FecTx::new(1), Err(FecError::BadK(1))));
        assert!(matches!(FecTx::new(17), Err(FecError::BadK(17))));
        assert!(FecTx::new(2).is_ok());
        assert!(FecTx::new(16).is_ok());
    }

    #[test]
    fn push_rejects_short_frame() {
        let mut tx = FecTx::new(2).unwrap();
        assert!(matches!(
            tx.push(&[0u8; DATA_MIN_FRAME - 1], key()),
            Err(FecError::TooShort(_))
        ));
    }

    #[test]
    fn group_fills_at_exactly_k() {
        let mut tx = FecTx::new(4).unwrap();
        for i in 0..3u64 {
            let f = crate::tests::synth_data_frame(i, i as u8, 40);
            assert_eq!(tx.pending(), i as usize);
            assert!(tx.push(&f, key()).unwrap().is_none());
        }
        let f = crate::tests::synth_data_frame(3, 3, 40);
        let rec = tx.push(&f, key()).unwrap().expect("第 4 帧应产出恢复帧");
        assert_eq!(tx.pending(), 0, "产出后组应清空");
        // 帧头：Ver=1, Type=6, KeyID
        assert_eq!(rec[0], 0x01);
        assert_eq!(rec[1], FEC_FRAME_TYPE);
        assert_eq!(&rec[2..10], &key());
        // 固定段：group_seq=0(10..18) ‖ k=4(18) ‖ 保留 3B(19..22)
        assert_eq!(&rec[10..18], &0u64.to_be_bytes());
        assert_eq!(rec[18], 4);
        assert_eq!(&rec[19..22], &[0, 0, 0]);
        // 恢复帧总长 = 10 + 12 + 4*10 + max成员帧长(74)
        assert_eq!(rec.len(), FRAME_HEADER_SIZE + RECOVERY_FIXED_BODY + 40 + 74);
    }

    #[test]
    fn sliding_group_carries_over() {
        // K=2：喂 3 帧 → 第 2 帧产出组0，第 3 帧残留进组1
        let mut tx = FecTx::new(2).unwrap();
        for i in 0..3u64 {
            let f = crate::tests::synth_data_frame(i, i as u8, 40);
            let out = tx.push(&f, key()).unwrap();
            assert_eq!(out.is_some(), i == 1);
        }
        assert_eq!(tx.pending(), 1);
        // 补第 4 帧 → 组1 产出，group_seq=1
        let f = crate::tests::synth_data_frame(3, 0, 40);
        let rec = tx.push(&f, key()).unwrap().unwrap();
        assert_eq!(u64::from_be_bytes([rec[10], rec[11], rec[12], rec[13], rec[14], rec[15], rec[16], rec[17]]), 1);
    }

    #[test]
    fn recovery_carries_member_counters_and_xor() {
        // 3 个 74B 帧 + 1 个 90B 帧（max=90）
        let mut members = Vec::new();
        for i in 0..4u64 {
            members.push(crate::tests::synth_data_frame(
                0x1000 + i,
                (i as u8) * 0x11,
                40 + i as usize * 16,
            ));
        }
        let max_len = members.iter().map(|m| m.len()).max().unwrap();
        let mut tx = FecTx::new(4).unwrap();
        let mut rec = None;
        for m in &members {
            if let Some(r) = tx.push(m, key()).unwrap() {
                rec = Some(r);
            }
        }
        let rec = rec.unwrap();
        // 成员表
        for (i, m) in members.iter().enumerate() {
            let off = 22 + i * 8;
            let c = u64::from_be_bytes(rec[off..off + 8].try_into().unwrap());
            assert_eq!(c, data_counter(m).unwrap(), "成员 {i} 计数器");
            let loff = 22 + 4 * 8 + i * 2;
            let l = u16::from_be_bytes(rec[loff..loff + 2].try_into().unwrap());
            assert_eq!(l as usize, m.len(), "成员 {i} 帧长");
        }
        // xor 段 = 各成员按位异或（短帧右侧零填充）
        let xor_start = 22 + 4 * 10;
        assert_eq!(rec.len() - xor_start, max_len);
        let mut expect = vec![0u8; max_len];
        for m in &members {
            for (b, mb) in expect.iter_mut().zip(m.iter()) {
                *b ^= mb;
            }
        }
        assert_eq!(&rec[xor_start..], &expect[..]);
    }
}
