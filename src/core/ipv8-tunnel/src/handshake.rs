//! X25519 隧道握手（Phase 1 明文握手，证书绑定 Phase 2 接入 ZoneServer）。
//!
//! 消息格式（握手帧体，明文传输 —— 提供的是密钥协商，身份认证在 Phase 2）：
//! - HandshakeInit : ephemeral_pub(32) ‖ initiator_static_pub(32)
//! - HandshakeResp : ephemeral_pub(32) ‖ responder_static_pub(32)
//!
//! 共享密钥 = 双方临时私钥的交叉 DH（eph_a × eph_b），标准一次性 ECDH；
//! 静态密钥仅在消息中携带供 Phase 2 签名认证。

use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::crypto::{Identity, TunnelKeys};
use crate::frame::{FrameError, FrameType};

pub const HANDSHAKE_BODY_LEN: usize = 64;

/// 发起方生成握手请求：(临时公钥‖静态公钥, 待用的临时私钥上下文)
/// 本端状态保存在 `HandshakeState`，等待响应帧完成配对。
pub fn create_init(identity: &Identity) -> (Vec<u8>, PendingHandshake) {
    let eph = EphemeralSecret::random_from_rng(rand_core::OsRng);
    let eph_pub = PublicKey::from(&eph);
    let mut body = Vec::with_capacity(HANDSHAKE_BODY_LEN);
    body.extend_from_slice(eph_pub.as_bytes());
    body.extend_from_slice(&identity.public_bytes());
    (body, PendingHandshake { local_eph: eph, local_static: identity.public_bytes() })
}

/// 响应方处理握手请求，返回 (响应帧体, 会话密钥)。请求非法则 Err。
/// 共享密钥 = 本端临时私钥 × 对端临时公钥（双方同值），
/// 静态密钥 Phase 2 用于签名认证该协商过程。
pub fn accept_init(identity: &Identity, body: &[u8]) -> Result<(Vec<u8>, TunnelKeys), FrameError> {
    let (peer_eph, peer_static) = split_handshake(body)?;
    let _ = (peer_static, identity); // Phase 2: 静态密钥验签 + ZoneServer 注册表交叉验证
    let eph = EphemeralSecret::random_from_rng(rand_core::OsRng);
    let eph_pub = PublicKey::from(&eph);
    let shared = eph.diffie_hellman(&peer_eph);
    let mut resp = Vec::with_capacity(HANDSHAKE_BODY_LEN);
    resp.extend_from_slice(eph_pub.as_bytes());
    resp.extend_from_slice(&identity.public_bytes());
    Ok((resp, TunnelKeys::new(*shared.as_bytes(), false)))
}

/// 发起方处理握手响应，返回会话密钥。
pub fn finish_init(pending: PendingHandshake, body: &[u8]) -> Result<TunnelKeys, FrameError> {
    let (peer_eph, _peer_static) = split_handshake(body)?;
    let shared = pending.local_eph.diffie_hellman(&peer_eph);
    Ok(TunnelKeys::new(*shared.as_bytes(), true))
}

/// 发起方侧保存的等待状态
pub struct PendingHandshake {
    local_eph: EphemeralSecret,
    #[allow(dead_code)] // Phase 2: 回显校验与证书绑定
    local_static: [u8; 32],
}

fn split_handshake(body: &[u8]) -> Result<(PublicKey, [u8; 32]), FrameError> {
    if body.len() != HANDSHAKE_BODY_LEN {
        return Err(FrameError::BadHandshakeLen);
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&body[..32]);
    let mut st = [0u8; 32];
    st.copy_from_slice(&body[32..]);
    Ok((PublicKey::from(pk), st))
}

/// 判定帧类型是否握手类（明文两条 + 认证两条；供 Engine 路由）
pub fn is_handshake(t: FrameType) -> bool {
    matches!(
        t,
        FrameType::HandshakeInit
            | FrameType::HandshakeResp
            | FrameType::AuthInit
            | FrameType::AuthResp
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{parse_head, write_head, FRAME_HEADER_SIZE};

    const AAD: &[u8] = b"fake-ipv8-header-40-bytes-padding!!xxxxxxxx";

    #[test]
    fn full_handshake_establishes_shared_keys() {
        let alice = Identity::from_bytes([1u8; 32]);
        let bob = Identity::from_bytes([2u8; 32]);

        let (init_body, pending) = create_init(&alice);
        let (resp_body, mut bob_keys) = accept_init(&bob, &init_body).unwrap();
        let mut alice_keys = finish_init(pending, &resp_body).unwrap();

        // A→B 再 B→A 双向验证
        let (kid, ct) = alice_keys.seal(AAD, b"ping");
        assert_eq!(bob_keys.open(&kid, &ct, AAD).unwrap(), b"ping");
        let (kid2, ct2) = bob_keys.seal(AAD, b"pong");
        assert_eq!(alice_keys.open(&kid2, &ct2, AAD).unwrap(), b"pong");
    }

    #[test]
    fn handshake_frames_wrap_with_head() {
        let alice = Identity::from_bytes([3u8; 32]);
        let (init_body, _p) = create_init(&alice);
        let mut frame = Vec::new();
        write_head(&mut frame, FrameType::HandshakeInit, &[0u8; 8]);
        frame.extend_from_slice(&init_body);
        let h = parse_head(&frame).unwrap();
        assert_eq!(h.frame_type, FrameType::HandshakeInit);
        assert_eq!(frame.len(), FRAME_HEADER_SIZE + HANDSHAKE_BODY_LEN);
    }

    #[test]
    fn bad_handshake_len_rejected() {
        let bob = Identity::from_bytes([4u8; 32]);
        assert_eq!(accept_init(&bob, &[0u8; 63]).err(), Some(FrameError::BadHandshakeLen));
        assert_eq!(accept_init(&bob, &[0u8; 65]).err(), Some(FrameError::BadHandshakeLen));
    }

    #[test]
    fn mitm_cannot_derive_keys() {
        // 无认证握手可被中间人换包 → 双方密钥不一致，通信失败。
        // 这正是 Phase 2 必须用 ZoneServer 证书绑定静态密钥的证据。
        let alice = Identity::from_bytes([5u8; 32]);
        let bob = Identity::from_bytes([6u8; 32]);
        let mallory = Identity::from_bytes([7u8; 32]);

        let (init_body, pending) = create_init(&alice);
        let (evil_body, _evil_pending) = create_init(&mallory);
        let mut hijacked = init_body.clone();
        hijacked[..32].copy_from_slice(&evil_body[..32]); // Mallory 替换临时公钥

        let (resp_body, mut bob_keys) = accept_init(&bob, &hijacked).unwrap();
        let mut alice_keys = finish_init(pending, &resp_body).unwrap();

        let (kid, ct) = alice_keys.seal(AAD, b"hello");
        assert!(bob_keys.open(&kid, &ct, AAD).is_err());
    }
}
