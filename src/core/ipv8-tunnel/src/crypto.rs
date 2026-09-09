//! 密码学核心：X25519 共享密钥 + ChaCha20-Poly1305 AEAD + HKDF 逐代派生。
//!
//! 设计要点（ADR-005）：
//! - **密钥代（epoch）单调递增**，隧道帧 KeyID 字段就是 8 字节 epoch。
//!   双方由握手得到的共享 DH 种子独立派生每一代密钥，无需为轮换额外传密钥。
//! - 方向分离：发起方 send = HKDF(dh,dir0‖epoch) / recv = HKDF(dh,dir1‖epoch)，
//!   响应方相反。保证 A.send == B.recv 且两向密钥互不冲突。
//! - 轮换：每 `ROTATE_BYTES`(1GB) 或 `ROTATE_SECS`(1h)，发送方 epoch+1。
//!   接收方接受 {最新代, 最新代-1} —— v9 的 60s 宽限期在此以"落后一代"
//!   表达：延迟包只能来自上一代（更旧代直接拒绝）。
//! - **AAD 绑定完整明文 IPv8+ 头**（基础头 + 扩展头链）：改载荷或改头
//!   （篡改 CapTag/SecLevel/DstAddr）都导致 AEAD 失败（protocol-spec §10.2）。
//! - Nonce = 4B 零 ‖ 8B 方向内计数器；**发送侧**计数器严格递增 → nonce 唯一；
//!   **接收侧**用 IPsec 式滑动窗口防重放：容忍乱序（UDP 重排/IPv8+ 分片
//!   天然乱序），拒绝精确重复与窗外观测。

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use chacha20poly1305::{
    aead::{Aead, Error as AeadError, KeyInit, Payload},
    ChaCha20Poly1305, Nonce as AeadNonce,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::frame::FrameError;

/// AEAD 密码套件（ADR-025）。数值写入隧道帧 KeyID[0]：
/// 0 = ChaCha20-Poly1305（默认，与 Phase 1-4 线上格式逐字节兼容），
/// 1 = AES-256-GCM（AES-NI 加速路径）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CipherSuite {
    #[default]
    ChaCha20Poly1305,
    Aes256Gcm,
}

impl CipherSuite {
    pub const fn byte(self) -> u8 {
        match self {
            Self::ChaCha20Poly1305 => 0,
            Self::Aes256Gcm => 1,
        }
    }

    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::ChaCha20Poly1305),
            1 => Some(Self::Aes256Gcm),
            _ => None,
        }
    }
}

/// 当前 epoch 派生出的活动密码器（enum dispatch，避免 dyn）。
/// AES-GCM 内部结构远大于 ChaCha，装箱压平 enum 尺寸（clippy::large_enum_variant）。
enum Cipher {
    ChaCha(ChaCha20Poly1305),
    Aes(Box<aes_gcm::Aes256Gcm>),
}

impl Cipher {
    fn encrypt(&self, nonce: &AeadNonce, p: Payload<'_, '_>) -> Result<Vec<u8>, AeadError> {
        match self {
            Self::ChaCha(c) => c.encrypt(nonce, p),
            Self::Aes(c) => c.encrypt(nonce, p),
        }
    }
    fn decrypt(&self, nonce: &AeadNonce, p: Payload<'_, '_>) -> Result<Vec<u8>, AeadError> {
        match self {
            Self::ChaCha(c) => c.decrypt(nonce, p),
            Self::Aes(c) => c.decrypt(nonce, p),
        }
    }
}

/// 密钥轮换阈值：1 GB
pub const ROTATE_BYTES: u64 = 1_073_741_824;
/// 密钥轮换阈值：1 小时
pub const ROTATE_SECS: u64 = 3600;
/// 宽限期等价：接收方最多容忍落后当前代 1 个 epoch
pub const GRACE_EPOCHS: u64 = 1;

/// 节点静态身份密钥对。x25519-dalek 的 StaticSecret 不暴露密钥字节
/// （防误用泄露），因此本类型自持 32 字节种子；持久化时保存种子即可。
/// （Phase 1 仅用于识别对端；证书绑定见 Phase 2）
pub struct Identity {
    seed: [u8; 32],
    public: PublicKey,
}

impl Identity {
    /// 生成新身份（OS CSPRNG）
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut seed);
        Self::from_seed(seed)
    }

    /// 从 32 字节种子构造（测试/持久化恢复场景）
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let public = PublicKey::from(&StaticSecret::from(seed));
        Self { seed, public }
    }

    /// 从 32 字节种子构造（`from_seed` 的历史别名）
    pub fn from_bytes(seed: [u8; 32]) -> Self {
        Self::from_seed(seed)
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        *self.public.as_bytes()
    }

    /// 本端种子（仅供调用方安全存储；除持久化外不应使用）
    pub fn seed(&self) -> [u8; 32] {
        self.seed
    }

    pub fn dh(&self, peer_pub: &[u8; 32]) -> [u8; 32] {
        StaticSecret::from(self.seed)
            .diffie_hellman(&PublicKey::from(*peer_pub))
            .to_bytes()
    }
}

/// HKDF-SHA256，单次输出 32 字节（RFC 5869 extract+expand）
fn hkdf(ikm: &[u8; 32], info: &[u8]) -> [u8; 32] {
    let prk = {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(b"ipv8plus-tunnel-v1")
            .expect("HMAC accepts any key length");
        mac.update(ikm);
        mac.finalize().into_bytes()
    };
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(&prk).expect("HMAC accepts any key length");
    mac.update(info);
    let t = mac.finalize().into_bytes();
    let mut okm = [0u8; 32];
    okm.copy_from_slice(&t);
    okm
}

/// 由 (dh, suite, epoch, 本端是否发起方, 发送方向) 派生 AEAD 密钥。
/// 方向位约定：发起方 send=0/recv=1；响应方 send=1/recv=0。
/// suite 进 HKDF info（域分离）：同一 DH/epoch 在不同套件下派生不同密钥，
/// 跨套件密文不可能被误解密为明文（ADR-025）。
fn cipher_for(
    dh: &[u8; 32],
    suite: CipherSuite,
    epoch: u64,
    is_initiator: bool,
    sending: bool,
) -> Cipher {
    let dir_bit: u8 = match (is_initiator, sending) {
        (true, true) | (false, false) => 0,
        (true, false) | (false, true) => 1,
    };
    let mut info = [0u8; 11];
    info[0] = dir_bit;
    info[1..9].copy_from_slice(&epoch.to_be_bytes());
    info[9] = b'K';
    info[10] = suite.byte();
    let key = hkdf(dh, &info);
    match suite {
        CipherSuite::ChaCha20Poly1305 => Cipher::ChaCha(ChaCha20Poly1305::new((&key).into())),
        CipherSuite::Aes256Gcm => Cipher::Aes(Box::new(aes_gcm::Aes256Gcm::new((&key).into()))),
    }
}

fn nonce_for(counter: u64) -> AeadNonce {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_be_bytes());
    AeadNonce::clone_from_slice(&n)
}

/// 一条已建立隧道的密钥状态
pub struct TunnelKeys {
    dh: [u8; 32],
    is_initiator: bool,
    /// 本隧道协商使用的 AEAD 套件（ADR-025；默认 ChaCha20 = 零回归）
    suite: CipherSuite,
    send_epoch: u64,
    epoch_created: Instant,
    epoch_bytes: u64,
    tx_counter: u64,
    /// 流级分片编号（ADR-026 性能线；0 = 非分片，与历史行为一致）
    shard: u64,
    /// epoch 推进步幅 = 分片总数（默认 1：逐代 +1，Phase 1-5 零回归）。
    /// 分片 k 的 epoch 序列 ≡ k (mod stride)，接收端凭 `epoch % stride`
    /// 无解密路由到对应分片 SA——线格式（KeyID/计数器/nonce）不变。
    stride: u64,
    /// 各 epoch 的接收滑动窗口（仅保留最近 GRACE_EPOCHS+1 代）
    rx: BTreeMap<u64, RxWindow>,
}

/// 接收重放窗口（IPsec 式）：`top` = 已接受的最大计数器，`mask` 第 k 位
/// 表示 `top - k` 是否已见。容忍 ≤64 的乱序（UDP/分片），拒精确重复与窗外旧包。
/// 计数器从 1 起（seal 先 ++），top=0 表示尚无可信基准。
#[derive(Debug, Clone, Copy, Default)]
pub struct RxWindow {
    top: u64,
    mask: u128,
}

/// 窗口宽度（位）
const RX_WINDOW: u32 = 127;

impl RxWindow {
    /// 若 counter 可接受（未重复且不完全在窗外）返回 true 并标记之。
    fn accept(&mut self, counter: u64) -> bool {
        if counter == 0 {
            return false;
        }
        if self.top == 0 || counter > self.top {
            let shift = counter - self.top;
            self.mask = if shift >= RX_WINDOW as u64 {
                1 // 新顶超出整窗，旧位全部作废
            } else {
                (self.mask << shift) | 1
            };
            self.top = counter;
            true
        } else {
            let back = self.top - counter; // 1..=
            if back >= RX_WINDOW as u64 {
                false // 太旧，窗外（保守拒）
            } else {
                let bit = 1u128 << back;
                if self.mask & bit != 0 {
                    false // 精确重复
                } else {
                    self.mask |= bit;
                    true
                }
            }
        }
    }
}

impl Clone for TunnelKeys {
    fn clone(&self) -> Self {
        Self {
            dh: self.dh,
            is_initiator: self.is_initiator,
            suite: self.suite,
            send_epoch: self.send_epoch,
            epoch_created: self.epoch_created,
            epoch_bytes: self.epoch_bytes,
            tx_counter: self.tx_counter,
            shard: self.shard,
            stride: self.stride,
            rx: self.rx.clone(),
        }
    }
}

impl TunnelKeys {
    /// 握手完成后用共享 DH 初始化；epoch 从 0 开始，套件默认 ChaCha20（零回归）
    pub fn new(dh: [u8; 32], is_initiator: bool) -> Self {
        Self {
            dh,
            is_initiator,
            suite: CipherSuite::default(),
            send_epoch: 0,
            epoch_created: Instant::now(),
            epoch_bytes: 0,
            tx_counter: 0,
            shard: 0,
            stride: 1,
            rx: BTreeMap::new(),
        }
    }

    /// 指定套件的构造（部署配置，ADR-025：两端必须人工一致，不做协商）
    pub fn with_suite(dh: [u8; 32], is_initiator: bool, suite: CipherSuite) -> Self {
        let mut k = Self::new(dh, is_initiator);
        k.suite = suite;
        k
    }

    /// 流级分片 SA 构造（ADR-026 性能线）：本实例只处理 `epoch ≡ shard
    /// (mod stride)` 的帧，轮换时 epoch += stride。同一隧道的 N 个分片
    /// 各持一个实例，跨线程无锁并发（每片内部仍是单线程计数器语义）。
    /// 两端的 (shard, stride) 配置必须人工一致——不一致在 `open` 处
    /// `ShardMismatch` 拒收，绝不误解密。
    pub fn with_shard(dh: [u8; 32], is_initiator: bool, suite: CipherSuite, shard: u64, stride: u64) -> Self {
        assert!(stride >= 1 && shard < stride, "分片配置要求 shard < stride 且 stride ≥ 1");
        let mut k = Self::with_suite(dh, is_initiator, suite);
        // epoch 0 恒属于分片 0；其余分片从自己的第一个同余代起算
        k.shard = shard;
        k.stride = stride;
        k.send_epoch = shard; // shard ∈ [1, stride) 时首个合法 epoch
        k
    }

    /// 本实例的分片号（非分片模式恒 0）
    pub fn shard(&self) -> u64 {
        self.shard
    }

    /// 本实例所属分片总数（非分片模式恒 1）
    pub fn stride(&self) -> u64 {
        self.stride
    }

    /// 从本 SA 派生同隧道的第 `shard` 个分片 SA（ADR-026 流级多核）：
    /// 继承 dh / 套件 / 方向位，只换同余类起点。不导出任何密钥材料。
    pub fn derive_shard(&self, shard: u64, stride: u64) -> Self {
        assert!(stride >= 1 && shard < stride, "分片配置要求 shard < stride 且 stride ≥ 1");
        let mut k = self.clone();
        k.shard = shard;
        k.stride = stride;
        k.send_epoch = shard; // 本分片的第一个合法代（≡ shard mod stride）
        k.epoch_created = Instant::now();
        k.epoch_bytes = 0;
        k.tx_counter = 0;
        k.rx = BTreeMap::new();
        k
    }

    /// 本端使用的套件
    pub fn suite(&self) -> CipherSuite {
        self.suite
    }

    /// 修改本端套件。仅允许在**首帧使用前**调用——
    /// 用于 Engine 在握手完成后应用部署配置（ADR-025：两端人工一致，不协商）。
    /// 已发过帧返回 false（防止半程改套件导致密钥链分裂）。
    /// 判定用「epoch 仍在构造初值 + 计数器 0 + 接收窗空」，分片实例
    /// （初值 send_epoch = shard，ADR-026）同样适用。
    pub fn set_suite(&mut self, suite: CipherSuite) -> bool {
        if self.send_epoch != self.shard || self.tx_counter != 0 || !self.rx.is_empty() {
            return false;
        }
        self.suite = suite;
        true
    }

    /// 帧头 KeyID 线格式：`suite(1) ‖ epoch 高 7 字节`。
    /// epoch 永远 < 2^56（轮换阈值下不可能触顶），故默认套件的 KeyID[0]=0
    /// 与 Phase 1-4 的 epoch 大端 8 字节**逐字节相同**——向后兼容是构造性成立。
    pub fn frame_key_id(&self, epoch: u64) -> [u8; 8] {
        let mut k = epoch.to_be_bytes();
        k[0] = self.suite.byte();
        k
    }

    /// 当前发送密钥代（写入帧头 KeyID）
    pub fn current_epoch(&self) -> u64 {
        self.send_epoch
    }

    /// 加密载荷。返回 (**帧头 KeyID 8B**, 帧体 = 计数器(8B) ‖ 密文‖tag)。
    /// `aad` 必须是完整明文 IPv8+ 头字节。
    pub fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> ([u8; 8], Vec<u8>) {
        if self.epoch_bytes >= ROTATE_BYTES
            || self.epoch_created.elapsed() >= Duration::from_secs(ROTATE_SECS)
        {
            self.advance_epoch();
        }
        self.tx_counter += 1;
        let cipher = cipher_for(&self.dh, self.suite, self.send_epoch, self.is_initiator, true);
        let ct = cipher
            .encrypt(&nonce_for(self.tx_counter), Payload { msg: plaintext, aad })
            .expect("AEAD encrypt cannot fail for inbounds size");
        let mut body = Vec::with_capacity(8 + ct.len());
        body.extend_from_slice(&self.tx_counter.to_be_bytes());
        body.extend_from_slice(&ct);
        self.epoch_bytes += body.len() as u64;
        (self.frame_key_id(self.send_epoch), body)
    }

    /// 解密。`aad` 为完整明文 IPv8+ 头；`key_id` 为帧头 8B（suite‖epoch）。
    /// **密钥派生只信本地配置的 suite**（帧内 suite 字节不采信——防对端
    /// 降级）；帧内 suite ≠ 本端 → `SuiteMismatch`（配置漂移诊断）。
    /// 重放判定用滑动窗口：乱序可容忍，精确重复/窗外旧包拒绝。
    pub fn open(&mut self, key_id: &[u8; 8], body: &[u8], aad: &[u8]) -> Result<Vec<u8>, FrameError> {
        let remote_suite = CipherSuite::from_byte(key_id[0]).ok_or(FrameError::UnknownKeyId)?;
        if remote_suite != self.suite {
            return Err(FrameError::SuiteMismatch {
                expected: self.suite,
                got: remote_suite,
            });
        }
        // KeyID 线格式 = suite(1) ‖ epoch 低 7 字节：掩掉首字节还原 epoch。
        // 默认套件下 key_id[0]==0，掩码是恒等 → 与 Phase 1-4 的 8B 大端逐字节一致。
        let epoch = u64::from_be_bytes(*key_id) & 0x00FF_FFFF_FFFF_FFFF;
        // 流级分片路由（ADR-026）：epoch ≡ shard (mod stride)。非本片同余类
        // 的帧直接拒收（配置漂移诊断），绝不跨片解密。stride=1 恒通过。
        if epoch % self.stride != self.shard {
            return Err(FrameError::ShardMismatch { epoch, shard: self.shard, stride: self.stride });
        }
        if body.len() < 8 {
            return Err(FrameError::BodyTooShort);
        }
        let counter = u64::from_be_bytes(body[..8].try_into().unwrap());
        let ct = &body[8..];

        // epoch 宽限窗口：不得比已见最新代旧超过 GRACE_EPOCHS **代**
        // （分片模式下相邻代相差 stride 个 epoch，宽限须按代换算）
        let max_seen = self.rx.keys().next_back().copied().unwrap_or(epoch);
        let newest = max_seen.max(epoch);
        if newest > epoch.saturating_add(GRACE_EPOCHS.saturating_mul(self.stride)) {
            return Err(FrameError::StaleEpoch { epoch, newest });
        }

        let cipher = cipher_for(&self.dh, self.suite, epoch, self.is_initiator, false);
        let win = self.rx.entry(epoch).or_default();
        // 先验密码学完整性，通过才占重放位（篡改包不得污染窗口）
        match cipher.decrypt(&nonce_for(counter), Payload { msg: ct, aad }) {
            Ok(pt) => {
                if !win.accept(counter) {
                    self.prune(newest);
                    return Err(FrameError::Replay);
                }
                self.prune(newest);
                Ok(pt)
            }
            Err(_) => Err(FrameError::DecryptFailed),
        }
    }

    /// 轮换后重建（对端经 Rekey 帧提供新临时公钥 → 新 DH）
    pub fn rekey(&mut self, new_dh: [u8; 32]) {
        self.dh = new_dh;
        self.advance_epoch();
        self.rx.clear();
    }

    fn prune(&mut self, newest: u64) {
        let floor = newest.saturating_sub(GRACE_EPOCHS.saturating_mul(self.stride));
        let keep = self.rx.split_off(&floor);
        self.rx = keep;
    }

    fn advance_epoch(&mut self) {
        // 步幅 = 分片总数（默认 1）：各分片始终停留在自己的同余类内轮换
        self.send_epoch += self.stride;
        self.epoch_created = Instant::now();
        self.epoch_bytes = 0;
        self.tx_counter = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (TunnelKeys, TunnelKeys) {
        let a = Identity::from_seed([1u8; 32]);
        let b = Identity::from_seed([2u8; 32]);
        let dh_a = a.dh(&b.public_bytes());
        let dh_b = b.dh(&a.public_bytes());
        assert_eq!(dh_a, dh_b, "DH 必须对称");
        (TunnelKeys::new(dh_a, true), TunnelKeys::new(dh_b, false))
    }

    fn aes_pair() -> (TunnelKeys, TunnelKeys) {
        let a = Identity::from_seed([1u8; 32]);
        let b = Identity::from_seed([2u8; 32]);
        let dh_a = a.dh(&b.public_bytes());
        let dh_b = b.dh(&a.public_bytes());
        (
            TunnelKeys::with_suite(dh_a, true, CipherSuite::Aes256Gcm),
            TunnelKeys::with_suite(dh_b, false, CipherSuite::Aes256Gcm),
        )
    }

    const AAD: &[u8] = b"fake-ipv8-header-40-bytes-padding!!xxxxxxxx";

    #[test]
    fn identity_dh_symmetric() {
        let id = Identity::generate();
        assert_eq!(id.public_bytes().len(), 32);
        assert_eq!(Identity::from_seed(id.seed()).public_bytes(), id.public_bytes());
    }

    #[test]
    fn default_keyid_is_backward_compatible() {
        // 默认套件下 KeyID[0] 必须为 0 → 与 Phase 1-4 的纯 epoch 大端逐字节相同
        let (mut a, _b) = pair();
        let (kid, _) = a.seal(AAD, b"x");
        assert_eq!(kid[0], 0);
        assert_eq!(kid, a.current_epoch().to_be_bytes());
    }

    #[test]
    fn seal_open_roundtrip() {
        let (mut a, mut b) = pair();
        let pt = b"hello tunnel";
        let (kid, body) = a.seal(AAD, pt);
        assert_eq!(b.open(&kid, &body, AAD).unwrap(), pt);
    }

    #[test]
    fn aes_seal_open_roundtrip() {
        let (mut a, mut b) = aes_pair();
        let pt = b"hello aes-gcm";
        let (kid, body) = a.seal(AAD, pt);
        assert_eq!(kid[0], 1, "AES 帧 KeyID[0] 必须为 1");
        assert_eq!(b.open(&kid, &body, AAD).unwrap(), pt);
    }

    #[test]
    fn cross_suite_keys_diverge() {
        // HKDF info 绑 suite：同 DH/epoch 两套件派生不同密钥 → 跨套件密文互不可解
        let (mut a_chacha, mut b_chacha) = pair();
        let (_a2, mut b_aes) = aes_pair();
        let (kid, body) = a_chacha.seal(AAD, b"x");
        // b_aes 配置 AES 收 ChaCha 帧 → SuiteMismatch（不采信对端，配置为准）
        assert!(matches!(
            b_aes.open(&kid, &body, AAD),
            Err(FrameError::SuiteMismatch { .. })
        ));
        // 同一帧喂给"配置 ChaCha 但密钥派生走 AES info"不存在路径——
        // b_chacha 正常解（自证方向信息没坏）
        assert!(b_chacha.open(&kid, &body, AAD).is_ok());
    }

    #[test]
    fn tampered_payload_fails() {
        let (mut a, mut b) = pair();
        let (kid, mut body) = a.seal(AAD, b"secret data");
        let last = body.len() - 1;
        body[last] ^= 0x01;
        assert_eq!(b.open(&kid, &body, AAD), Err(FrameError::DecryptFailed));
    }

    #[test]
    fn tampered_header_aad_fails() {
        // 中间节点改写 DstAddr（头是 AAD）必须导致解密失败
        let (mut a, mut b) = pair();
        let (kid, body) = a.seal(AAD, b"secret data");
        let mut bad_aad = AAD.to_vec();
        bad_aad[23] ^= 0x80;
        assert_eq!(b.open(&kid, &body, &bad_aad), Err(FrameError::DecryptFailed));
    }

    #[test]
    fn direction_keys_are_separated() {
        let (mut a, mut b) = pair();
        let (kid, body) = a.seal(AAD, b"x");
        assert!(a.open(&kid, &body, AAD).is_err(), "发起方 recv 密钥解不开自己 send 的帧");
        assert!(b.open(&kid, &body, AAD).is_ok());
    }

    #[test]
    fn replay_rejected() {
        let (mut a, mut b) = pair();
        let (kid, body) = a.seal(AAD, b"once");
        assert!(b.open(&kid, &body, AAD).is_ok());
        assert_eq!(b.open(&kid, &body, AAD), Err(FrameError::Replay));
    }

    #[test]
    fn out_of_order_within_window_ok_duplicate_rejected() {
        let (mut a, mut b) = pair();
        let (k1, b1) = a.seal(AAD, b"1");
        let (k2, b2) = a.seal(AAD, b"2");
        assert!(b.open(&k1, &b1, AAD).is_ok());
        assert!(b.open(&k2, &b2, AAD).is_ok());

        // 乱序：计数器 2 先到、1 后到 → 窗内接受（UDP/分片正常行为）
        let (mut a2, mut b2r) = pair();
        let (s1k, s1) = a2.seal(AAD, b"1");
        let (s2k, s2) = a2.seal(AAD, b"2");
        assert!(b2r.open(&s2k, &s2, AAD).is_ok());
        assert_eq!(b2r.open(&s1k, &s1, AAD).unwrap(), b"1", "窗内旧计数器乱序应接受");
        // 但精确重复（同 counter 再投）仍拒
        assert_eq!(b2r.open(&s1k, &s1, AAD), Err(FrameError::Replay));
    }

    #[test]
    fn bytes_rotation_advances_epoch() {
        let (mut a, mut b) = pair();
        assert_eq!(a.current_epoch(), 0);
        a.epoch_bytes = ROTATE_BYTES;
        let (kid, body) = a.seal(AAD, b"x");
        assert_eq!(a.current_epoch(), 1, "达到字节阈值应轮换");
        assert_eq!(kid, a.frame_key_id(1));
        assert_eq!(b.open(&kid, &body, AAD).unwrap(), b"x");
        // 宽限期：上一代（epoch 0）的迟到帧仍可解
        let (late_kid, late_body) = {
            let keep = (a.send_epoch, a.tx_counter);
            a.send_epoch = 0;
            a.tx_counter = 0;
            let out = a.seal(AAD, b"late");
            a.send_epoch = keep.0;
            a.tx_counter = keep.1;
            out
        };
        assert_eq!(b.open(&late_kid, &late_body, AAD).unwrap(), b"late");
    }

    #[test]
    fn stale_epoch_rejected() {
        let (mut a, mut b) = pair();
        a.send_epoch = 5;
        let (fresh_kid, fresh) = a.seal(AAD, b"x");
        assert!(b.open(&fresh_kid, &fresh, AAD).is_ok());
        let (old_kid, old) = {
            let keep = (a.send_epoch, a.tx_counter);
            a.send_epoch = 3;
            a.tx_counter = 0;
            let out = a.seal(AAD, b"x");
            a.send_epoch = keep.0;
            a.tx_counter = keep.1;
            out
        };
        assert!(matches!(
            b.open(&old_kid, &old, AAD),
            Err(FrameError::StaleEpoch { epoch: 3, newest: 5 })
        ));
    }

    #[test]
    fn rekey_resets_chain() {
        let (mut a, mut b) = pair();
        let (k0, body0) = a.seal(AAD, b"pre");
        assert!(b.open(&k0, &body0, AAD).is_ok());
        a.rekey([9u8; 32]);
        b.rekey([9u8; 32]);
        assert_eq!(a.current_epoch(), 1);
        let (k1, body1) = a.seal(AAD, b"post");
        assert_eq!(a.current_epoch(), 1);
        assert_eq!(b.open(&k1, &body1, AAD).unwrap(), b"post");
        assert!(b.open(&k0, &body0, AAD).is_err(), "旧 DH 的帧在新链上彻底失效");
    }
}
