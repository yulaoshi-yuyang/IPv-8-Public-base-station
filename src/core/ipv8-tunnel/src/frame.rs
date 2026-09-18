//! 隧道帧格式（docs/tunnel-protocol.md §帧布局 的权威实现）。
//!
//! ```text
//! 0        1        2                             10
//! +--------+--------+------------------------------+
//! | Ver(1) | Type(1)|      KeyID(8, 大端)           |
//! +--------+--------+------------------------------+
//! ```
//!
//! - Ver  固定 0x01
//! - Type 0=HandshakeInit 1=HandshakeResp 2=Data 3=Rekey
//! - KeyID = suite(1B, ADR-025；0=ChaCha20 默认) ‖ epoch（大端）。默认套件下
//!   与"纯 epoch 大端 8B"逐字节相同（epoch 恒 < 2^56），向后兼容是构造性的。
//!
//! Data 帧体 = IPv8+ 完整包（头明文 + 载荷密文||tag，见 encapsulate）。

use ipv8_codec::{DecodeError, BASE_HEADER_SIZE};
use sha2::{Digest, Sha256};

use crate::crypto::CipherSuite;

pub const TUNNEL_VERSION: u8 = 0x01;
pub const FRAME_HEADER_SIZE: usize = 10;
pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    HandshakeInit = 0,
    HandshakeResp = 1,
    Data = 2,
    Rekey = 3,
    /// 证书认证握手 Init（帧体 = AUTH_BUNDLE_LEN 认证束）
    AuthInit = 4,
    /// 证书认证握手 Resp（帧体 = AUTH_BUNDLE_LEN 认证束）
    AuthResp = 5,
    /// FEC XOR 恢复帧（Phase 4，帧体见 ipv8-fec crate；引擎不处理，node 层分流）
    FecRecovery = 6,
}

impl FrameType {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::HandshakeInit),
            1 => Some(Self::HandshakeResp),
            2 => Some(Self::Data),
            3 => Some(Self::Rekey),
            4 => Some(Self::AuthInit),
            5 => Some(Self::AuthResp),
            6 => Some(Self::FecRecovery),
            _ => None,
        }
    }
}

/// 帧头解析结果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHead {
    pub frame_type: FrameType,
    pub key_id: [u8; 8],
}

/// 计算密钥代标识：SHA-256(pubkey) 前 8 字节
pub fn compute_key_id(peer_pub: &[u8; 32]) -> [u8; 8] {
    let digest = Sha256::digest(peer_pub);
    let mut id = [0u8; 8];
    id.copy_from_slice(&digest[..8]);
    id
}

/// 解析帧头（不透明字节 → 结构化）。
pub fn parse_head(frame: &[u8]) -> Result<FrameHead, FrameError> {
    if frame.len() < FRAME_HEADER_SIZE {
        return Err(FrameError::TooShort(frame.len()));
    }
    if frame[0] != TUNNEL_VERSION {
        return Err(FrameError::BadVersion(frame[0]));
    }
    let frame_type =
        FrameType::from_u8(frame[1]).ok_or(FrameError::BadType(frame[1]))?;
    let mut key_id = [0u8; 8];
    key_id.copy_from_slice(&frame[2..10]);
    Ok(FrameHead { frame_type, key_id })
}

/// 写入帧头
pub fn write_head(frame: &mut Vec<u8>, frame_type: FrameType, key_id: &[u8; 8]) {
    frame.push(TUNNEL_VERSION);
    frame.push(frame_type as u8);
    frame.extend_from_slice(key_id);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    TooShort(usize),
    BadVersion(u8),
    BadType(u8),
    /// 期望 Data 帧，收到其他类型
    NotData(FrameType),
    /// Data 帧体不足最小长度（IPv8 头 + nonce + tag）
    BodyTooShort,
    /// AAD 与 IPv8+ 包头绑定校验失败（载荷解密失败）
    DecryptFailed,
    /// 载荷长度与包头 PayloadLen 不一致
    PayloadLenMismatch,
    /// 重放：收到的 nonce 计数器不大于已见最大值
    Replay,
    /// 帧的密钥代落后于当前代超过宽限期
    StaleEpoch { epoch: u64, newest: u64 },
    /// nonce 计数器无法匹配任何密钥代（含宽限期）
    UnknownKeyId,
    /// 握手帧长度不合法
    BadHandshakeLen,
    /// 帧内密码套件与本端配置不符（部署漂移诊断；ADR-025）
    SuiteMismatch { expected: CipherSuite, got: CipherSuite },
    /// 帧的 epoch 不属于本分片 SA（epoch ≢ shard mod stride；ADR-024 用户态性能线：流级分片）
    ShardMismatch { epoch: u64, shard: u64, stride: u64 },
    /// 认证握手失败（伪造证书/过期/transcript 签名无效）
    AuthFailed,
    /// 解码 IPv8+ 头失败
    Header(DecodeError),
}

impl core::fmt::Display for FrameError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooShort(n) => write!(f, "帧长 {n} 不足帧头 {FRAME_HEADER_SIZE}"),
            Self::BadVersion(v) => write!(f, "隧道版本 {v:#x} 不匹配"),
            Self::BadType(t) => write!(f, "未知帧类型 {t}"),
            Self::NotData(t) => write!(f, "期望 Data 帧，收到类型 {:?}", t),
            Self::BodyTooShort => write!(f, "Data 帧体过短"),
            Self::DecryptFailed => write!(f, "AEAD 解密失败（AAD 绑定或完整性校验不通过）"),
            Self::PayloadLenMismatch => write!(f, "载荷长度与包头 PayloadLen 不一致"),
            Self::Replay => write!(f, "重放帧被丢弃"),
            Self::StaleEpoch { epoch, newest } => {
                write!(f, "密钥代 {epoch} 落后于最新代 {newest}，超出宽限期")
            }
            Self::UnknownKeyId => write!(f, "未知密钥代 KeyID"),
            Self::BadHandshakeLen => write!(f, "握手帧长度不合法"),
            Self::SuiteMismatch { expected, got } => {
                write!(f, "对端帧套件 {got:?} 与本端配置 {expected:?} 不符")
            }
            Self::ShardMismatch { epoch, shard, stride } => {
                write!(f, "帧 epoch {epoch} 不属于分片 {shard}（步幅 {stride}）")
            }
            Self::AuthFailed => write!(f, "认证握手失败"),
            Self::Header(e) => write!(f, "IPv8+ 头解析失败: {e}"),
        }
    }
}

impl std::error::Error for FrameError {}

impl From<DecodeError> for FrameError {
    fn from(e: DecodeError) -> Self {
        Self::Header(e)
    }
}

/// Data 帧体长度下限：明文基础头(40) + 计数器(8) + AEAD tag(16)
/// （载荷可以为空；nonce 不再单独传输，计数器即 nonce 材料）
pub const MIN_DATA_BODY: usize = BASE_HEADER_SIZE + 8 + TAG_SIZE;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn head_roundtrip() {
        let key_id = compute_key_id(&[7u8; 32]);
        let mut v = Vec::new();
        write_head(&mut v, FrameType::Data, &key_id);
        assert_eq!(v.len(), FRAME_HEADER_SIZE);
        let h = parse_head(&v).unwrap();
        assert_eq!(h.frame_type, FrameType::Data);
        assert_eq!(h.key_id, key_id);
    }

    #[test]
    fn key_id_is_hash_prefix() {
        let a = compute_key_id(&[1u8; 32]);
        let b = compute_key_id(&[2u8; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn rejects_bad_frames() {
        assert_eq!(parse_head(&[0u8; 9]), Err(FrameError::TooShort(9)));
        assert_eq!(
            parse_head(&[0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Err(FrameError::BadVersion(2))
        );
        assert_eq!(
            parse_head(&[0x01, 9, 0, 0, 0, 0, 0, 0, 0, 0]),
            Err(FrameError::BadType(9))
        );
    }

    #[test]
    fn parse_head_type6_roundtrip() {
        // Phase 4：FecRecovery=6 解析往返；0-5 帧既有断言不受影响
        let mut f = Vec::new();
        write_head(&mut f, FrameType::FecRecovery, &[0x11; 8]);
        assert_eq!(f[1], 6);
        let h = parse_head(&f).expect("Type=6 必须可解析");
        assert_eq!(h.frame_type, FrameType::FecRecovery);
        assert_eq!(h.key_id, [0x11; 8]);
        // 越界类型仍拒绝
        let mut bad = f;
        bad[1] = 7;
        assert!(matches!(parse_head(&bad), Err(FrameError::BadType(7))));
    }
}
