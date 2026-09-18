//! 畸形包不 panic 属性测试（unwrap 治理的验证闭环）
//!
//! 背景：core 生产代码的 unwrap/expect 经逐条核查，全部位于"长度守卫先行
//! 拒绝"的路径上（from_payload 先查 len、unpack_bundle 先查定长、open 先查
//! body≥8……）。目测论证会随代码演化失效，这里用确定性 PRNG 把数据面入口反
//! 复喂畸形输入：任何 panic（unwrap 失败即 panic）都会让本测试变红。
//!
//! 种子固定 + 结构断言防"全在门口被拒导致零覆盖"：失败可复现、可回灌回归。

use ipv8_codec::{
    decode, encode, flags, AgentCardSummary, ExtensionHeader, ExtType, FragmentInfo, IPv8Address,
    IPv8Header, QosReservation, Reassembler, RouteTrace, SemanticTags, BASE_HEADER_SIZE,
    MAX_PAYLOAD_LEN,
};
use ipv8_tunnel::{
    auth::{auth_accept, CertAuthority, TrustAnchor},
    Engine, HostIdentity, Identity, NO_EXPIRY,
};

/// splitmix64：不引新依赖的确定性 PRNG（测试自身可复现）。
struct Rng(u64);
impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn byte(&mut self) -> u8 {
        (self.next_u64() >> 24) as u8
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }
    /// 畸形字节流：纯随机 + 结构偏置（合法版本 nibble、NextHeader 小值域），
    /// 提高穿过第一道守卫、打到深层解析/重组/转发代码的命中密度。
    fn fuzz_packet(&mut self) -> Vec<u8> {
        let mode = self.below(8);
        let len = match mode {
            0 => self.below(64) as usize,                             // 碎片
            1 => BASE_HEADER_SIZE,                                    // 恰基头
            2..=4 => 40 + self.below(300) as usize,                   // 头部+短扩展区
            5 => 40 + self.below(MAX_PAYLOAD_LEN as u64) as usize,    // 大载荷
            _ => self.below(1472) as usize,                           // MTU 级
        };
        let mut v: Vec<u8> = (0..len).map(|_| self.byte()).collect();
        if mode >= 2 {
            if self.below(2) == 0 {
                if let Some(b0) = v.first_mut() {
                    *b0 = (*b0 & 0x0F) | 0x80; // 合法 Version=8 高 nibble
                }
            }
            if v.len() > 6 {
                v[6] = (self.below(16)) as u8; // NextHeader 小值域（常撞链首 5）
            }
        }
        v
    }
}

fn addr(n: u32) -> IPv8Address {
    IPv8Address::with_region(n as u64, 1, 0, 1, 0)
}

/// 1) 解码 + 布局层入口：任意字节喂进去必须返回 Err/Ok，禁止 panic。
#[test]
fn fuzz_decode_and_layouts_never_panic() {
    let mut rng = Rng(0xDEAD_BEEF_CAFE_0001);
    for _ in 0..20_000u64 {
        let buf = rng.fuzz_packet();
        let _ = decode(&buf);
        // 布局层：对端可控扩展载荷直接进 from_payload/parse
        let mut sub: Vec<u8> = buf.clone();
        if sub.len() < 160 {
            sub.resize(160, rng.byte());
        }
        let _ = RouteTrace::from_payload(&sub);
        let _ = AgentCardSummary::from_payload(&sub);
        let _ = QosReservation::from_payload(&sub);
        let _ = SemanticTags::decode(&sub);
        let ext = ExtensionHeader {
            ext_type: ExtType::from_u8(buf.first().copied().unwrap_or(0)),
            payload: sub,
        };
        let _ = FragmentInfo::parse(&ext);
    }
}

/// 2) 重组器（Group/chunks 簿记 unwrap 密集区）：先造结构合法的分片包，
///    再位级篡改制造"decode 能过但语义畸形"的序列，确保深入簿记分支。
#[test]
fn fuzz_reassembler_never_panic() {
    let mut rng = Rng(0x0BAD_C0DE_5EED_0002);
    let mut r = Reassembler::new();
    let mut fed = 0u64;
    let mut inserted = 0u64;
    for _ in 0..30_000u64 {
        let payload: Vec<u8> = (0..rng.below(64)).map(|_| rng.byte()).collect();
        let mut hdr = IPv8Header::new(
            addr(1 + rng.below(3) as u32),
            addr(9),
            payload.len() as u16,
        );
        hdr.flags |= flags::FRAGMENT | flags::HAS_EXTENSION;
        let mut fp = [0u8; 8];
        fp[0..4].copy_from_slice(&(rng.next_u64() as u32).to_be_bytes());
        let off = (rng.below(8192)) as u16; // offset 边界值域
        let more = rng.below(3) as u16; // more 位 + 脏位组合
        fp[4..6].copy_from_slice(&(((off & 0x1FFF) << 3) | more).to_be_bytes());
        hdr.attach_ext_headers(vec![ExtensionHeader {
            ext_type: ExtType::Fragment,
            payload: fp.to_vec(),
        }]);
        let Ok(mut pkt) = encode(&hdr, &payload) else { continue };
        for _ in 0..rng.below(3) {
            let i = rng.below(pkt.len() as u64) as usize;
            pkt[i] ^= 1 << rng.below(8);
        }
        fed += 1;
        if let Ok(d) = decode(&pkt) {
            let _ = r.insert(&d.header, d.payload);
            inserted += 1;
        }
        if rng.below(512) == 0 {
            r.reap();
            let _ = r.active_groups();
        }
    }
    assert!(fed > 1000, "fuzz 生成异常: fed={fed}");
    assert!(
        inserted * 2 > fed,
        "decode 通过率过低（重组簿记未被覆盖）: inserted={inserted} fed={fed}"
    );
}

/// 3) 引擎状态机：Established 解密路径 + 转发 route_decision 路径，
///    随机帧与"合法头+随机 NextHeader/扩展链"的包全部禁止 panic。
#[test]
fn fuzz_engine_handle_frame_never_panic() {
    let mut rng = Rng(0xFEED_FACE_1234_0003);
    let mut alice = Engine::new(Identity::from_seed([1u8; 32]), addr(1), addr(2));
    let mut bob = Engine::new(Identity::from_seed([2u8; 32]), addr(2), addr(1));
    let init = alice.start_handshake();
    let resp = bob.handle_frame(&init).expect("合法 Init 应有响应");
    alice.handle_frame(&resp); // 双方 Established

    // 认证 + 转发引擎（直接索引 ext[0] 与 cert_binding_ok 所在路径）
    let ca = CertAuthority::from_seed([9u8; 32]);
    let ed_seed = [3u8; 32];
    let verify_key = ipv8_tunnel::auth::verify_key_from_seed(ed_seed);
    let host = HostIdentity::with_cert(addr(3), ed_seed, ca.issue(addr(3), verify_key, NO_EXPIRY));
    let trust = TrustAnchor::from_bytes(ca.public_key()).expect("真锚");
    let mut fwd = Engine::authenticated(host, trust, addr(3), addr(4));
    fwd.enable_forwarding(ca.public_key());

    for _ in 0..20_000u64 {
        let buf = rng.fuzz_packet();
        let _ = bob.handle_frame_at(&buf, 12345);
        let _ = fwd.handle_frame_at(&buf, 12345);
        // 结构合法但字段随机的 IPv8+ 明文包：直穿 decode→route_decision
        if rng.below(4) == 0 {
            let payload: Vec<u8> = (0..rng.below(80)).map(|_| rng.byte()).collect();
            let mut hdr = IPv8Header::new(addr(1), addr(3), payload.len() as u16);
            hdr.next_header = rng.below(16) as u8;
            hdr.hop_limit = rng.below(8) as u8;
            let exts: Vec<ExtensionHeader> = (0..rng.below(3))
                .map(|_| ExtensionHeader {
                    ext_type: ExtType::from_u8(rng.below(16) as u8),
                    payload: (0..rng.below(24)).map(|_| rng.byte() & 0xF8).collect(), // 8 对齐偏置
                })
                .collect();
            if !exts.is_empty() {
                hdr.attach_ext_headers(exts);
            }
            if let Ok(pkt) = encode(&hdr, &payload) {
                let _ = fwd.handle_frame_at(&pkt, 12345);
            }
        }
        // 偶发合法数据面帧，保持 Established 解密路径活跃
        if rng.below(64) == 0 {
            if let Ok(f) = alice.seal_frame(b"ping") {
                let _ = bob.handle_frame(&f);
            }
        }
    }
}

/// 4) 认证束解析：随机束（含定长 216B）必须走 Err 分支，禁止 panic。
#[test]
fn fuzz_auth_bundle_never_panic() {
    let mut rng = Rng(0xABCD_0123_DEAD_0004);
    let ca = CertAuthority::from_seed([7u8; 32]);
    let trust = TrustAnchor::from_bytes(ca.public_key()).expect("真锚");
    let ed_seed = [5u8; 32];
    let verify_key = ipv8_tunnel::auth::verify_key_from_seed(ed_seed);
    let host = HostIdentity::with_cert(addr(5), ed_seed, ca.issue(addr(5), verify_key, NO_EXPIRY));
    for _ in 0..5_000u64 {
        let len = match rng.below(3) {
            0 => ipv8_tunnel::AUTH_BUNDLE_LEN,
            1 => rng.below(300) as usize,
            _ => ipv8_tunnel::AUTH_BUNDLE_LEN + rng.below(8) as usize,
        };
        let bundle: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        let _ = auth_accept(&host, &trust, &bundle, Some(addr(6)), 999_999_999);
    }
}
