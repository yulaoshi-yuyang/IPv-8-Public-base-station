//! 隧道封装/拆壳（v9 §9 的 Phase 1 实现，对应 spec §5.1 / §10.2 的 AAD 绑定）。
//!
//! 数据面切分（与 protocol-spec 一致）：
//! - **明文段** = IPv8+ 基础头(40B) + 扩展头链 —— 外层与中间节点需要
//!   DstAddr/HopLimit/链结构，必须明文（spec §5.1：扩展头链始终明文）。
//! - **加密段** = 载荷（原始 IP 包）——套件见 ADR-025（默认 ChaCha20-Poly1305）。
//! - **AAD** = 完整明文段字节 —— 任何对基础头/扩展头的篡改（如改
//!   DstAddr、CapTag）都会使 AEAD 失败（spec §10.2 端到端字段清单）。
//! - KeyID(帧头 8B) = suite(1B) ‖ epoch（大端），接收方据此选密钥代；
//!   套件字节仅做配置漂移诊断，密钥派生只信本端配置（防降级，ADR-025）。
//! - 帧体 = 明文段 ‖ 计数器(8B) ‖ 密文‖tag(16B)。
//!
//! 外层 IPv4/UDP 由 OS 协议栈经 wintun 完成，本模块不构造外层头。

use ipv8_codec::{decode as decode_ipv8, BASE_HEADER_SIZE};

use crate::crypto::TunnelKeys;
use crate::frame::{parse_head, write_head, FrameError, FrameType, MIN_DATA_BODY, FRAME_HEADER_SIZE};

/// 封装一个完整 IPv8+ 包为隧道 Data 帧。
pub fn encapsulate(keys: &mut TunnelKeys, ipv8_packet: &[u8]) -> Result<Vec<u8>, FrameError> {
    // 用解码器定位明文段/加密段边界（同时校验包自洽性）
    let d = decode_ipv8(ipv8_packet).map_err(FrameError::Header)?;
    let plain_len = ipv8_packet.len() - d.payload.len();
    let (plain, secret) = ipv8_packet.split_at(plain_len);

    let (key_id, cipher_body) = keys.seal(plain, secret);
    let mut frame = Vec::with_capacity(FRAME_HEADER_SIZE + plain_len + cipher_body.len());
    write_head(&mut frame, FrameType::Data, &key_id);
    frame.extend_from_slice(plain);
    frame.extend_from_slice(&cipher_body);
    Ok(frame)
}

/// 拆一个隧道 Data 帧，返回还原后的完整 IPv8+ 包（可直接写回 TUN）。
pub fn decapsulate(keys: &mut TunnelKeys, frame: &[u8]) -> Result<Vec<u8>, FrameError> {
    let head = parse_head(frame)?;
    if head.frame_type != FrameType::Data {
        return Err(FrameError::NotData(head.frame_type));
    }
    let body = &frame[FRAME_HEADER_SIZE..];
    if body.len() < MIN_DATA_BODY {
        return Err(FrameError::BodyTooShort);
    }
    // 明文段边界由包头自描述：解码器返回的 payload 借用切片的起点偏移
    // 即"基础头 + 扩展头"总长（此时尾部计数器/密文被误当作载荷，只取偏移）。
    let d = decode_ipv8(body).map_err(FrameError::Header)?;
    let plain_len = (d.payload.as_ptr() as usize) - (body.as_ptr() as usize);
    if plain_len < BASE_HEADER_SIZE || body.len() - plain_len < 8 {
        return Err(FrameError::BodyTooShort);
    }
    let (plain, rest) = body.split_at(plain_len);
    let secret = keys.open(&head.key_id, rest, plain)?;

    let mut pkt = Vec::with_capacity(plain_len + secret.len());
    pkt.extend_from_slice(plain);
    pkt.extend_from_slice(&secret);
    Ok(pkt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipv8_codec::{encode, ExtType, ExtensionHeader, IPv8Address, IPv8Header, MAX_PAYLOAD_LEN};
    use x25519_dalek::{PublicKey, StaticSecret};

    fn keys_pair() -> (TunnelKeys, TunnelKeys) {
        let sa = StaticSecret::from([1u8; 32]);
        let sb = StaticSecret::from([2u8; 32]);
        let pa = PublicKey::from(&sa);
        let pb = PublicKey::from(&sb);
        let da = sa.diffie_hellman(&pb);
        let db = sb.diffie_hellman(&pa);
        (TunnelKeys::new(*da.as_bytes(), true), TunnelKeys::new(*db.as_bytes(), false))
    }

    fn sample_packet() -> Vec<u8> {
        let src = IPv8Address::new(10, 20, 1, 0x1234, 3);
        let dst = IPv8Address::new(10, 21, 2, 0xFFFF, 1);
        let inner = [0x45u8, 0x00, 0x00, 0x14]; // 假 IPv4 头前缀
        let hdr = IPv8Header::new(src, dst, inner.len() as u16);
        encode(&hdr, &inner).unwrap()
    }

    #[test]
    fn encap_decap_roundtrip() {
        let (mut a, mut b) = keys_pair();
        let pkt = sample_packet();
        let frame = encapsulate(&mut a, &pkt).unwrap();
        let out = decapsulate(&mut b, &frame).unwrap();
        assert_eq!(out, pkt);
    }

    #[test]
    fn ext_headers_stay_plaintext() {
        // spec §5.1：扩展头链在隧道帧中必须明文可见（外层/中间节点要能解析链）
        let (mut a, mut b) = keys_pair();
        let src = IPv8Address::new(1, 2, 3, 4, 5);
        let mut hdr = IPv8Header::new(src, src, 4);
        hdr.attach_ext_headers(vec![ExtensionHeader::new(ExtType::SemanticTag, vec![0x5A; 16]).unwrap()]);
        let pkt = encode(&hdr, b"data").unwrap();
        let frame = encapsulate(&mut a, &pkt).unwrap();
        // 明文段 = 40B 基础头 + 扩展头链，原样出现在帧体起始处
        let plain_len = pkt.len() - 4; // payload "data" 是加密段
        assert_eq!(&frame[FRAME_HEADER_SIZE..FRAME_HEADER_SIZE + plain_len], &pkt[..plain_len]);
        assert_eq!(decapsulate(&mut b, &frame).unwrap(), pkt);
    }

    #[test]
    fn base_header_tamper_breaks_aead() {
        let (mut a, mut b) = keys_pair();
        let pkt = sample_packet();
        let mut frame = encapsulate(&mut a, &pkt).unwrap();
        // DstAddr 首字节：帧头(10) + 头内偏移(23) = 33
        frame[33] ^= 0x01;
        assert!(matches!(decapsulate(&mut b, &frame), Err(FrameError::DecryptFailed)), "改明文头破坏 AAD 绑定");
    }

    #[test]
    fn ext_header_tamper_breaks_aead() {
        let (mut a, mut b) = keys_pair();
        let src = IPv8Address::new(1, 2, 3, 4, 5);
        let mut hdr = IPv8Header::new(src, src, 4);
        hdr.attach_ext_headers(vec![ExtensionHeader::new(ExtType::IdentityToken, vec![0xAA; 8]).unwrap()]);
        let pkt = encode(&hdr, b"data").unwrap();
        let mut frame = encapsulate(&mut a, &pkt).unwrap();
        let last_ext_byte = FRAME_HEADER_SIZE + 40 + 2 + 8 - 1; // 链内最后一个载荷字节
        frame[last_ext_byte] ^= 0x01;
        assert!(decapsulate(&mut b, &frame).is_err(), "扩展头被改必须失败");
    }

    #[test]
    fn payload_tamper_detected() {
        let (mut a, mut b) = keys_pair();
        let pkt = sample_packet();
        let mut frame = encapsulate(&mut a, &pkt).unwrap();
        let last = frame.len() - 1;
        frame[last] ^= 0x80;
        assert!(decapsulate(&mut b, &frame).is_err());
    }

    #[test]
    fn oversized_payload_encodes() {
        let (mut a, mut b) = keys_pair();
        let src = IPv8Address::new(1, 1, 0, 0, 0);
        let payload = vec![0u8; 60_000]; // 超 MTU，验证协议上限内的封装路径
        let hdr = IPv8Header::new(src, src, payload.len() as u16);
        let pkt = encode(&hdr, &payload).unwrap();
        let frame = encapsulate(&mut a, &pkt).unwrap();
        assert_eq!(decapsulate(&mut b, &frame).unwrap(), pkt);
        assert!(payload.len() <= MAX_PAYLOAD_LEN as usize);
    }
}
