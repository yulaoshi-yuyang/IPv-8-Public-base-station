//! Phase 3 多跳转发端到端验证（CI 可跑，无需 wintun/UAC）。
//!
//! 拓扑：A ↔(隧道1)↔ R ↔(隧道2)↔ B，两条隧道各自独立认证握手
//! （Phase 2 路径），R 与 B 启用转发验证（Phase 3 / ADR-019）。
//! 外层用**真实 UDP socket**，数据面走 seal_multihop → 中转验证转发 →
//! seal_prebuilt → 目的地三验交付，与 ipv8-node 的多隧道编排逐帧一致。
//! 这是 v9 "隧道内多跳路由 + QoS 标记" 验收的进程内等价物。

use std::net::UdpSocket;

use ed25519_dalek::{Signer, SigningKey};
use ipv8_codec::{encode, flags, ExtType, ExtensionHeader, IPv8Address, IPv8Header};
use ipv8_routing::{build_route_trace, PathSpec};
use ipv8_tunnel::auth::{provision, CertAuthority, TrustAnchor, NO_EXPIRY};
use ipv8_tunnel::{Engine, State};

fn addr(n: u32) -> IPv8Address {
    IPv8Address::new(64500, n, 1, 0, 1)
}

const NOW: u64 = 1_700_000_000;
const CA_SEED: [u8; 32] = [0xC4u8; 32];
/// 源点 A 的签名种子（helper 构造包与引擎身份必须一致）
const A_SEED: [u8; 32] = [0xA1u8; 32];

struct Anchors {
    ca: CertAuthority,
    trust: TrustAnchor,
    anchor: [u8; 32],
}

fn anchors() -> Anchors {
    let ca = CertAuthority::from_seed(CA_SEED);
    let trust = TrustAnchor::from_bytes(ca.public_key()).unwrap();
    let anchor = ca.public_key();
    Anchors { ca, trust, anchor }
}

/// A 地址的证书线格式（与 A_SEED 身份一致，供手工构造包附 IdentityToken）
fn a_cert_wire() -> Vec<u8> {
    provision(&CertAuthority::from_seed(CA_SEED), addr(1), A_SEED, NO_EXPIRY)
        .cert
        .to_wire()
}

/// 认证握手（经真实 UDP），双向 Established。initiator 主动发 Init。
fn auth_handshake(
    init_sock: &UdpSocket,
    init_engine: &mut Engine,
    init_peer: std::net::SocketAddr,
    resp_sock: &UdpSocket,
    resp_engine: &mut Engine,
) {
    let init = init_engine.start_auth_handshake();
    init_sock.send_to(&init, init_peer).unwrap();
    let mut buf = [0u8; 4096];
    let (n, from) = resp_sock.recv_from(&mut buf).unwrap();
    let resp = resp_engine.handle_frame_at(&buf[..n], NOW).unwrap();
    resp_sock.send_to(&resp, from).unwrap();
    let (n2, _) = init_sock.recv_from(&mut buf).unwrap();
    assert!(init_engine.handle_frame_at(&buf[..n2], NOW).is_none());
    assert_eq!(init_engine.state(), State::Established);
    assert_eq!(resp_engine.state(), State::Established);
}

/// 排空 socket 上的可读帧喂给 engine（内部切非阻塞后还原；握手依赖阻塞 recv）。
fn pump(sock: &UdpSocket, engine: &mut Engine) {
    sock.set_nonblocking(true).unwrap();
    let mut buf = [0u8; 65536];
    loop {
        match sock.recv_from(&mut buf) {
            Ok((n, _from)) => engine.handle_frame_at(&buf[..n], NOW),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => {
                sock.set_nonblocking(false).unwrap();
                panic!("recv: {e}");
            }
        };
    }
    sock.set_nonblocking(false).unwrap();
}

/// 手工构造多跳明文包（可控 QoS/HopLimit，篡改测试与 QoS 搬运测试用）。
/// 签名种子与证书均为 A_SEED/addr(1)——与测试里的 A 引擎身份一致。
fn multihop_pkt(
    dst: IPv8Address,
    hops: &[IPv8Address],
    init_hl: u8,
    qos_level: u16,
    inner: &[u8],
) -> Vec<u8> {
    let sk = SigningKey::from_bytes(&A_SEED);
    let ed = sk.verifying_key().to_bytes();
    let final_flags = flags::HAS_EXTENSION | qos_level;
    let trace = build_route_trace(
        &PathSpec {
            src_addr: addr(1),
            dst_addr: dst,
            min_compat_ver: 0,
            flags: final_flags,
            payload_len: inner.len() as u16,
            init_hop_limit: init_hl,
            hops,
            src_pubkey: &ed,
        },
        |m| sk.sign(m).to_bytes(),
    )
    .unwrap();
    let mut hdr = IPv8Header::new(addr(1), dst, inner.len() as u16);
    hdr.hop_limit = init_hl;
    hdr.flags = final_flags;
    hdr.attach_ext_headers(vec![
        ExtensionHeader::new(ExtType::RouteTrace, trace.to_payload().unwrap()).unwrap(),
        ExtensionHeader::new(ExtType::IdentityToken, a_cert_wire()).unwrap(),
    ]);
    encode(&hdr, inner).unwrap()
}

/// 建四引擎 + 两条 Established 隧道。返回可变引用不方便，直接内联在测试里。
/// 本函数只造引擎，socket/握手留给调用方。
struct Nodes {
    a: Engine,
    r_a: Engine,
    r_b: Engine,
    b: Engine,
    anchor: [u8; 32],
}

fn nodes(an: &Anchors, enable_fwd: bool) -> Nodes {
    let host_a = provision(&an.ca, addr(1), A_SEED, NO_EXPIRY);
    let host_r1 = provision(&an.ca, addr(2), [0xB0u8; 32], NO_EXPIRY);
    let host_r2 = provision(&an.ca, addr(2), [0xB0u8; 32], NO_EXPIRY);
    let host_b = provision(&an.ca, addr(3), [0xC3u8; 32], NO_EXPIRY);
    let a = Engine::authenticated(host_a, an.trust.clone(), addr(1), addr(2));
    let mut r_a = Engine::authenticated(host_r1, an.trust.clone(), addr(2), addr(1));
    let r_b = Engine::authenticated(host_r2, an.trust.clone(), addr(2), addr(3));
    let mut b = Engine::authenticated(host_b, an.trust.clone(), addr(3), addr(2));
    if enable_fwd {
        r_a.enable_forwarding(an.anchor);
        b.enable_forwarding(an.anchor);
    }
    Nodes { a, r_a, r_b, b, anchor: an.anchor }
}

#[test]
fn multihop_udp_relay_a_to_r_to_b_delivers() {
    let an = anchors();
    let a_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let ra_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let rb_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let b_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let ra_addr = ra_sock.local_addr().unwrap();
    let b_addr = b_sock.local_addr().unwrap();

    let mut n = nodes(&an, true);
    auth_handshake(&a_sock, &mut n.a, ra_addr, &ra_sock, &mut n.r_a);
    auth_handshake(&rb_sock, &mut n.r_b, b_addr, &b_sock, &mut n.b);

    // 源点用生产 API：seal_multihop 自动签路径 + 附 A 自身证书
    let inner = vec![0x45u8, 0x00, 0x00, 0x1C, b'p', b'i', b'n', b'g'];
    let frames = n.a.seal_multihop(&inner, addr(3), &[addr(2), addr(3)], 64).unwrap();
    assert_eq!(frames.len(), 1);
    for f in &frames {
        a_sock.send_to(f, ra_addr).unwrap();
    }

    // R：验证→减跳→排队，然后经面向 B 的隧道续程
    pump(&ra_sock, &mut n.r_a);
    assert_eq!(n.r_a.take_delivered(), None, "中转不交付本机");
    assert_eq!(n.r_a.stats().forwarded, 1, "合法多跳包应放行: {:?}", n.r_a.stats());
    let (_next, fwd_pkt) = n.r_a.take_forward_packet().unwrap();
    let frame = n.r_b.seal_prebuilt(&fwd_pkt).unwrap();
    rb_sock.send_to(&frame, b_addr).unwrap();

    // B：三验（PathSig + A 证书 + 跳位）后交付
    pump(&b_sock, &mut n.b);
    assert_eq!(n.b.take_delivered().as_deref(), Some(&inner[..]));
    assert_eq!(n.b.stats().fwd_rejected, 0);
    assert_eq!(n.b.stats().dropped_inbound, 0);
    let _ = n.anchor;
}

#[test]
fn multihop_udp_tampered_path_is_dropped_at_relay() {
    let an = anchors();
    let a_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let ra_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let ra_addr = ra_sock.local_addr().unwrap();

    let mut n = nodes(&an, true);
    auth_handshake(&a_sock, &mut n.a, ra_addr, &ra_sock, &mut n.r_a);

    let inner = vec![0x45u8, 0x00, 0x00, 0x14, b'x'];
    let mut pkt = multihop_pkt(addr(3), &[addr(2), addr(3)], 64, 0, &inner);
    // RouteTrace 载荷起点 = 基头 40 + 头框架 2；hops[0] 在其 +104；翻 host_id 末字节
    pkt[40 + 2 + 104 + 7] ^= 0x07;
    let frame = n.a.seal_prebuilt(&pkt).unwrap();
    a_sock.send_to(&frame, ra_addr).unwrap();

    pump(&ra_sock, &mut n.r_a);
    assert_eq!(n.r_a.stats().forwarded, 0, "篡改路径不得转发");
    assert_eq!(n.r_a.stats().fwd_rejected, 1);
    assert!(n.r_a.take_forward_packet().is_none());
}

#[test]
fn relay_without_enable_forwarding_drops() {
    let an = anchors();
    let a_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let ra_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let ra_addr = ra_sock.local_addr().unwrap();

    let mut n = nodes(&an, false); // 不启用转发
    auth_handshake(&a_sock, &mut n.a, ra_addr, &ra_sock, &mut n.r_a);

    let inner = vec![0x45u8, 0x00, 0x00, 0x14];
    let pkt = multihop_pkt(addr(3), &[addr(2), addr(3)], 64, 0, &inner);
    let frame = n.a.seal_prebuilt(&pkt).unwrap();
    a_sock.send_to(&frame, ra_addr).unwrap();

    pump(&ra_sock, &mut n.r_a);
    assert_eq!(n.r_a.stats().forwarded, 0);
    assert_eq!(n.r_a.stats().fwd_rejected, 1, "未启用转发的引擎一律拒收多跳包");
    assert_eq!(n.r_a.take_delivered(), None, "也不得交付本机");
}

#[test]
fn qos_level_survives_multihop_wire() {
    // v9 验收 "QoS 标记"：QoS Level 进基头 flags（签名前）后被转发链端到端
    // 完整搬运，中转读取分类但不改写（端到端不可变字段）。
    use ipv8_qos::classify_base_header;
    let an = anchors();
    let a_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let ra_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let rb_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let b_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let ra_addr = ra_sock.local_addr().unwrap();
    let b_addr = b_sock.local_addr().unwrap();

    let mut n = nodes(&an, true);
    auth_handshake(&a_sock, &mut n.a, ra_addr, &ra_sock, &mut n.r_a);
    auth_handshake(&rb_sock, &mut n.r_b, b_addr, &b_sock, &mut n.b);

    let inner = vec![0x45u8, 0x00, 0x00, 0x14, b'q'];
    let pkt = multihop_pkt(addr(3), &[addr(2), addr(3)], 64, 13, &inner); // QoS=13 → 类3
    let frame = n.a.seal_prebuilt(&pkt).unwrap();
    a_sock.send_to(&frame, ra_addr).unwrap();

    pump(&ra_sock, &mut n.r_a);
    assert_eq!(n.r_a.stats().forwarded, 1, "带 QoS 标记的合法多跳包应放行: {:?}", n.r_a.stats());
    let (_next, fwd_pkt) = n.r_a.take_forward_packet().unwrap();
    assert_eq!(classify_base_header(&fwd_pkt), 3, "R 看到的 QoS 类应为 3（level 13）");
    let f2 = n.r_b.seal_prebuilt(&fwd_pkt).unwrap();
    rb_sock.send_to(&f2, b_addr).unwrap();

    pump(&b_sock, &mut n.b);
    assert_eq!(n.b.take_delivered().as_deref(), Some(&inner[..]));
    assert_eq!(n.b.stats().fwd_rejected, 0, "QoS 标记不得破坏端到端验签");
}

/// §6.7 AgentCard 头随包进隧道：链是 AAD 覆盖的明文段，必须原样往返，
/// 且任何对头字节的篡改都被 AEAD 检出（隧道完整性与 ANS 哈希绑定的合流）。
#[test]
fn agentcard_header_survives_tunnel_aead() {
    use ipv8_codec::{encode, AgentCardSummary, ExtType, ExtensionHeader, IPv8Header, flags};
    use ipv8_tunnel::crypto::TunnelKeys;
    use ipv8_tunnel::{decapsulate, encapsulate};

    let summary = AgentCardSummary {
        version: 1,
        card_hash: [0xA5; 16],
        not_after: 4_000_000_000,
        agent_pubkey: [0xB4; 32],
        card_sig: [0xC7; 64],
    };
    let mut hdr = IPv8Header::new(addr(1), addr(2), 8);
    hdr.flags = flags::HAS_EXTENSION;
    hdr.attach_ext_headers(vec![ExtensionHeader::new(ExtType::AgentCard, summary.to_payload()).unwrap()]);
    let pkt = encode(&hdr, b"agentpay").unwrap();

    // 同 DH、initiator 互补的一对密钥（与隧道数据面同构）
    let mut tx = TunnelKeys::new([9u8; 32], true);
    let mut rx = TunnelKeys::new([9u8; 32], false);
    let frame = encapsulate(&mut tx, &pkt).unwrap();
    assert_eq!(decapsulate(&mut rx, &frame).unwrap(), pkt, "AgentCard 头必须原样往返");

    // 篡改 AgentPubKey 中段（帧头10 + 基头40 + 扩展框架2 + ver1+rsv7 + hash16 + not8）
    let mut evil = frame.clone();
    evil[10 + 40 + 2 + 32] ^= 0x01;
    assert!(decapsulate(&mut rx, &evil).is_err(), "改公钥字节必须破 AEAD");
    // 篡改 version 字节同样检出
    let mut evil2 = frame.clone();
    evil2[10 + 40 + 2] ^= 0x80;
    assert!(decapsulate(&mut rx, &evil2).is_err());
}
