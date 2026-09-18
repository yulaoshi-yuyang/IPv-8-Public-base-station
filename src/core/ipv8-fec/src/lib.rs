//! IPv8+ 隧道前向纠错（Phase 4，`.trae/specs/phase4-multipath-fec/spec.md` FR-3/4/5）。
//!
//! 设计要点（spec §Background 的代码事实）：
//! - Data 帧体 = IPv8+ 明文段 ‖ **计数器 8B（明文）** ‖ 密文‖tag(16B)——
//!   计数器恒在**帧尾倒数 24..16 字节**，不解密即可提取 → 免费作组成员标识。
//! - 恢复帧（Type=6）本身不加密不认证：K 选 1 的 XOR 无机密性需求，
//!   任何篡改使重建帧 AEAD 解密失败被引擎丢弃——攻击者最多妨碍恢复（DoS），
//!   无法注入数据。正确性由被恢复帧的 AEAD 兜底。
//! - K 选 1：组内丢 ≥2 帧放弃恢复（XOR 只能救 1）。
//!
//! 铁律（与 ipv8-compat 同款）：零依赖纯函数、全边界检查、绝不 panic、
//! 默认关闭（不带 `--fec` 时本 crate 不被构造、Type=6 帧由引擎按 Rekey
//! 同款静默丢弃）。

mod rx;
mod tx;

pub use rx::FecRx;
pub use tx::FecTx;

/// 隧道帧头长度（ipv8-tunnel/src/frame.rs `FRAME_HEADER_SIZE` 的本地副本；
/// 本 crate 零依赖，不引 ipv8-tunnel）
pub const FRAME_HEADER_SIZE: usize = 10;

/// Data 帧最短长度：帧头(10) + 明文段至少含基础头(40) + 计数器(8) + tag(16)
/// （与 ipv8-tunnel `MIN_DATA_BODY` + 帧头一致 = 74；计数器提取只需 34，
/// 这里取完整下限更保守）
pub const DATA_MIN_FRAME: usize = 74;

/// 组大小上下限（FR-3/FR-4：k 为 u8，2..=16）
pub const FEC_MIN_K: usize = 2;
pub const FEC_MAX_K: usize = 16;

/// 接收侧成员帧缓存默认上限（帧数；~1.5KB/帧典型 ≈ 384KB 内存上界）
pub const DEFAULT_RX_CACHE: usize = 256;

/// 已处理恢复帧组序号去重缓存上限（--mp 双发同帧去重；上限 128 线性扫可忽略）
pub const MAX_SEEN_GROUPS: usize = 128;

/// 计数器在帧体内的偏移：从帧尾倒数——`len-24..len-16`（FR-3）
pub const COUNTER_FROM_END: usize = 24;

/// 恢复帧体（不含 10B 帧头）固定段长度：group_seq(8) + k(1) + 保留(3)
pub const RECOVERY_FIXED_BODY: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FecError {
    /// 帧长不足以提取计数器/成员
    TooShort(usize),
    /// 组大小 k 非法（2..=16 之外）
    BadK(usize),
    /// 恢复帧体截断（固定段/成员表不完整）
    BodyTooShort { need: usize, got: usize },
    /// xor 段长度与成员最大帧长不一致
    XorLenMismatch { expect: usize, got: usize },
    /// 成员帧长非法（< 最短帧）
    BadMemberLen(usize),
    /// 重建帧未通过自检（版本/类型/计数器一致性）——疑似篡改
    SanityCheck,
}

impl core::fmt::Display for FecError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooShort(n) => write!(f, "帧长 {n} 不足以提取计数器"),
            Self::BadK(k) => write!(f, "组大小 {k} 超出 2..=16"),
            Self::BodyTooShort { need, got } => write!(f, "恢复帧体 {got} 字节不足固定段+成员表 {need}"),
            Self::XorLenMismatch { expect, got } => write!(f, "xor 段 {got} 字节 ≠ 成员最大帧长 {expect}"),
            Self::BadMemberLen(n) => write!(f, "成员帧长 {n} 非法"),
            Self::SanityCheck => write!(f, "重建帧自检失败（疑似篡改）"),
        }
    }
}

impl std::error::Error for FecError {}

/// 从隧道 Data 帧提取 8B AEAD 计数器（帧尾倒数 24..16，大端）。
/// 布局恒定：plain ‖ counter(8B) ‖ ct‖tag(16B)，与明文段长度无关。
pub fn data_counter(frame: &[u8]) -> Result<u64, FecError> {
    if frame.len() < DATA_MIN_FRAME {
        return Err(FecError::TooShort(frame.len()));
    }
    let tail = frame.len() - COUNTER_FROM_END;
    let mut b = [0u8; 8];
    b.copy_from_slice(&frame[tail..tail + 8]);
    Ok(u64::from_be_bytes(b))
}

/// `acc[i] ^= other[i]`（other.len() ≤ acc.len()；调用方保证，此处仍防越界）
pub(crate) fn xor_into(acc: &mut [u8], other: &[u8]) {
    let n = acc.len().min(other.len());
    for (a, o) in acc[..n].iter_mut().zip(other[..n].iter()) {
        *a ^= o;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一个自洽的合成 Data 帧：10B 头(Type=2) + plain(40B) + counter(8B) + tag(16B)
    pub(crate) fn synth_data_frame(counter: u64, body_seed: u8, total_plain: usize) -> Vec<u8> {
        let mut f = vec![0x01u8, 0x02];
        f.extend_from_slice(&[0xABu8; 8]); // KeyID
        f.resize(FRAME_HEADER_SIZE + total_plain, body_seed);
        f.extend_from_slice(&counter.to_be_bytes());
        f.extend_from_slice(&[0x77u8; 16]); // tag
        f
    }

    #[test]
    fn counter_extraction_roundtrip() {
        let f = synth_data_frame(0x0102_0304_0506_0708, 1, 40);
        assert_eq!(data_counter(&f).unwrap(), 0x0102_0304_0506_0708);
        // 明文段加长后计数器仍在尾部
        let f2 = synth_data_frame(42, 9, 100);
        assert_eq!(data_counter(&f2).unwrap(), 42);
    }

    #[test]
    fn counter_extraction_rejects_short() {
        assert!(matches!(
            data_counter(&[0u8; DATA_MIN_FRAME - 1]),
            Err(FecError::TooShort(_))
        ));
    }

    #[test]
    fn xor_into_saturates_at_shorter_operand() {
        let mut acc = [1u8; 4];
        xor_into(&mut acc, &[0xff, 0xff]);
        assert_eq!(acc, [0xfe, 0xfe, 1, 1]);
    }

    /// AC-8：FEC 纯函数单帧摊销计时。release 下阈值 <200ns/帧（NFR-2）；
    /// 输入帧预构造循环复用（push 不修改输入），计时不含 Vec 分配。
    /// debug 模式只打印不硬断言（数值放大 ~50×，无参考意义）。
    #[test]
    fn tx_rx_amortized_timing() {
        const N: usize = 200_000;
        let frames: Vec<Vec<u8>> =
            (0..4096usize).map(|i| synth_data_frame(i as u64, 1, 1200)).collect();

        // ---- TX：push 摊销（每 K 帧 1 次 XOR + 1 次恢复帧编码）----
        let mut tx = FecTx::new(4).unwrap();
        let kid = [0u8; 8];
        for f in &frames[..64] {
            let _ = tx.push(f, kid);
        }
        let t0 = std::time::Instant::now();
        for i in 0..N {
            let _ = tx.push(&frames[i & 4095], kid);
        }
        let tx_ns = t0.elapsed().as_nanos() as f64 / N as f64;

        // ---- RX：计数器提取摊销（NFR-2 的 100ns 阈值语义 = 纯提取，
        //      不含 observe 的帧缓存拷贝——那是 FR-5 重建的必需成本，单列打印）----
        let t1 = std::time::Instant::now();
        let mut sink = 0u64;
        for i in 0..N {
            sink = sink.wrapping_add(data_counter(&frames[i & 4095]).unwrap_or(0));
        }
        let rx_ns = t1.elapsed().as_nanos() as f64 / N as f64;

        // observe 摊销（含 1200B 缓存拷贝 + HashMap）：仅打印作内存成本参考
        let mut rx = FecRx::new(4096);
        for f in &frames {
            let _ = rx.observe_data(f);
        }
        let t2 = std::time::Instant::now();
        for i in 0..N {
            let _ = rx.observe_data(&frames[i & 4095]);
        }
        let obs_ns = t2.elapsed().as_nanos() as f64 / N as f64;

        println!("[fec-timing] FecTx.push 摊销 = {tx_ns:.0} ns/帧（K=4，1200B）");
        println!("[fec-timing] FecRx 计数器提取摊销 = {rx_ns:.0} ns/帧");
        println!("[fec-timing] FecRx.observe_data 摊销 = {obs_ns:.0} ns/帧（含 1200B 缓存拷贝，参考）");
        let _ = sink;
        if cfg!(not(debug_assertions)) {
            assert!(tx_ns < 200.0, "AC-8：TX 摊销 {tx_ns:.0}ns ≥ 200ns");
            assert!(rx_ns < 100.0, "RX 计数提取 {rx_ns:.0}ns ≥ 100ns");
        }
    }
}
