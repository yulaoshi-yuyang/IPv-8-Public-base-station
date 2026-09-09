//! ipv8-codec 测试套件：
//! 1. 固定线格式夹具（钉死 40 字节布局与字段偏移）
//! 2. 往返一致性（含扩展头链自动重排）
//! 3. 严格校验（畸形包全部拒绝、不 panic）
//! 4. 截断性质测试（LCG 伪随机，零依赖）

use ipv8_codec::*;

fn addr_full() -> IPv8Address {
    IPv8Address::new(0x0102_0304, 0x0A0B_0C0D, 0x1122, 0x3344, 0x02)
}

fn addr_min() -> IPv8Address {
    IPv8Address::new(0, 1, 0, 0, 0)
}

/// ★ 协议契约测试：钉死 40 字节线格式，任何布局改动都会让此测试红
#[test]
fn wire_format_fixture() {
    let mut hdr = IPv8Header::new(addr_full(), addr_min(), 4);
    hdr.hop_limit = 64;
    let pkt = encode(&hdr, &[0xDE, 0xAD, 0xBE, 0xEF]).unwrap();

    assert_eq!(pkt.len(), 44); // 40 头 + 4 载荷
    #[rustfmt::skip]
    let expect: [u8; 40] = [
        0x80, 0x00, 0x00,             // Version|MinCompat, Flags 高, Flags 低
        0x00, 0x04,                   // PayloadLen @3-4
        0x40,                         // HopLimit @5
        0x00,                         // NextHeader @6
        // SrcAddr @7-22
        0x01, 0x02, 0x03, 0x04, 0x0A, 0x0B, 0x0C, 0x0D, 0x11, 0x22, 0x33, 0x44, 0x02, 0x00, 0x00, 0x00,
        // DstAddr @23-38（asn=0, host_id=1 大端 → 字节 27-30）
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,                         // 对齐填充 @39
    ];
    assert_eq!(&pkt[..40], &expect[..]);
    assert_eq!(&pkt[40..], &[0xDE, 0xAD, 0xBE, 0xEF]);
}

#[test]
fn roundtrip_no_ext() {
    let hdr = IPv8Header::new(addr_full(), addr_min(), 3);
    let pkt = encode(&hdr, b"abc").unwrap();
    let d = decode(&pkt).unwrap();
    assert_eq!(d.header, hdr);
    assert_eq!(d.payload, b"abc");
}

#[test]
fn roundtrip_ext_chain_reordered() {
    let mut hdr = IPv8Header::new(addr_full(), addr_min(), 2);
    hdr.attach_ext_headers(vec![
        ExtensionHeader::new(ExtType::IdentityToken, vec![0xAA; 16]).unwrap(),
        ExtensionHeader::new(ExtType::Fragment, vec![0xBB; 8]).unwrap(),
    ]);
    let pkt = encode(&hdr, b"hi").unwrap();
    let d = decode(&pkt).unwrap();
    assert_eq!(d.header, hdr);
    assert_eq!(d.header.ext_headers.len(), 2);
    // 链指针：基础头 NextHeader=1(Identity)，第一环指向 6(Fragment)，尾环=0
    assert_eq!(d.header.next_header, ExtType::IdentityToken.wire());
    assert_eq!(pkt[40], 6, "IdentityToken 环内指针应指向 Fragment");
    assert_eq!(d.payload, b"hi");
}

#[test]
fn flags_helpers() {
    let f: u16 = 0x50; // QoS=0, E=1(bit4=16) | F(bit5=32) → 0x30; 用显式位
    assert!(Flags::is_encrypted(flags::ENCRYPTED));
    assert!(Flags::is_fragment(flags::FRAGMENT));
    assert!(Flags::has_extension(flags::HAS_EXTENSION));
    assert_eq!(Flags::qos_level(0x0D), 13);
    assert!(!Flags::reserved_ok(f | 0x0080));
    assert!(Flags::reserved_ok(flags::ENCRYPTED | flags::FRAGMENT | 7));
}

#[test]
fn payload_len_constraint() {
    // 上限内合法：65467
    let hdr = IPv8Header::new(addr_min(), addr_min(), MAX_PAYLOAD_LEN);
    let payload = vec![0u8; MAX_PAYLOAD_LEN as usize];
    let pkt = encode(&hdr, &payload).unwrap();
    assert_eq!(pkt.len(), 40 + 65467);
    let d = decode(&pkt).unwrap();
    assert_eq!(d.header.payload_len, MAX_PAYLOAD_LEN);

    // 超限拒绝（65468 < 65536，可被 u16 表达）
    let bad = IPv8Header::new(addr_min(), addr_min(), MAX_PAYLOAD_LEN + 1);
    assert_eq!(
        encode_header(&bad, &mut Vec::new()),
        Err(EncodeError::PayloadTooLong(65468))
    );
}

#[test]
fn encode_rejects_inconsistency() {
    // PayloadLen 与实际载荷不符
    let hdr = IPv8Header::new(addr_min(), addr_min(), 10);
    assert!(matches!(
        encode(&hdr, b"short"),
        Err(EncodeError::PayloadLengthMismatch { .. })
    ));

    // Flags 保留位非零
    let mut bad = IPv8Header::new(addr_min(), addr_min(), 0);
    bad.flags = 0x0080;
    assert_eq!(encode_header(&bad, &mut Vec::new()), Err(EncodeError::ReservedBits));

    // NextHeader 与扩展头链不符（手工制造不一致）
    let mut stale = IPv8Header::new(addr_min(), addr_min(), 0);
    stale.attach_ext_headers(vec![ExtensionHeader::new(ExtType::AgentCard, vec![1; 8]).unwrap()]);
    stale.next_header = 0; // 篡改指针
    assert!(matches!(
        encode_header(&stale, &mut Vec::new()),
        Err(EncodeError::NextHeaderMismatch { .. })
    ));
}

#[test]
fn decode_rejects_malformed() {
    // 太短
    assert_eq!(decode(&[0u8; 39]), Err(DecodeError::TooShort(39)));

    // 版本错误
    let mut pkt = encode(&IPv8Header::new(addr_min(), addr_min(), 0), &[]).unwrap();
    pkt[0] = 0x60; // Version=6
    assert_eq!(decode(&pkt), Err(DecodeError::BadVersion(6)));

    // 地址 reserved 非零 → 接收方忽略（不丢包），内存中清零
    let mut pkt = encode(&IPv8Header::new(addr_min(), addr_min(), 0), &[]).unwrap();
    pkt[20] = 0xFF; // SrcAddr 的 Reserved 第 2 字节
    let d = decode(&pkt).unwrap();
    assert_eq!(d.header.src_addr.reserved, [0; 3]);

    // 填充字节非零 → 接收方忽略
    let mut pkt = encode(&IPv8Header::new(addr_min(), addr_min(), 0), &[]).unwrap();
    pkt[39] = 0x01;
    assert!(decode(&pkt).is_ok());

    // Flags 保留位非零 → 接收方忽略
    let mut pkt = encode(&IPv8Header::new(addr_min(), addr_min(), 0), &[]).unwrap();
    pkt[1] |= 0xFF; // 高 8 位保留位
    assert!(decode(&pkt).is_ok());

    // 声明载荷超过缓冲区（直接构造 40 字节头，不带载荷）
    let mut pkt = Vec::new();
    encode_header(&IPv8Header::new(addr_min(), addr_min(), 100), &mut pkt).unwrap();
    assert_eq!(
        decode(&pkt),
        Err(DecodeError::PayloadBeyondBuffer { need: 100, have: 0 })
    );

    // 未知扩展头类型（编号 200 ≥128，同时覆盖移位溢出回归）→ 按 ExtLen 跳过继续解析
    let mut pkt = encode(&IPv8Header::new(addr_min(), addr_min(), 2), b"ok").unwrap();
    pkt[6] = 200; // NextHeader = 未注册编号
    pkt[2] |= 0x40; // HAS_EXTENSION
    pkt.splice(40..40, [0u8, 2u8]); // 插入 [NextPtr=0, ExtLen=2] → 16 字节未知载荷
    pkt.splice(42..42, std::iter::repeat_n(0xAB, 16));
    let d = decode(&pkt).unwrap();
    assert_eq!(d.header.ext_headers.len(), 1);
    assert_eq!(d.header.ext_headers[0].ext_type, ExtType::Unknown(200));
    assert_eq!(d.payload, b"ok", "未知头被跳过后载荷偏移必须正确");
    // 未知头可重编码（wire() 保留原编号）
    let re = encode(&d.header, d.payload).unwrap();
    assert_eq!(re, pkt);

    // 扩展头链回路：Identity → Identity
    let mut hdr = IPv8Header::new(addr_min(), addr_min(), 0);
    hdr.attach_ext_headers(vec![ExtensionHeader::new(ExtType::IdentityToken, vec![0; 8]).unwrap()]);
    let mut pkt = encode(&hdr, &[]).unwrap();
    pkt[40] = 1; // 把链尾指针改成指回 IdentityToken
    assert_eq!(decode(&pkt), Err(DecodeError::ExtChainCycle));

    // ExtLen=0 非法
    let mut pkt2 = encode(&hdr, &[]).unwrap();
    pkt2[41] = 0;
    assert_eq!(decode(&pkt2), Err(DecodeError::ExtLenZero));

    // 有扩展头但未置 HAS_EXTENSION 标志
    let mut pkt3 = encode(&hdr, &[]).unwrap();
    pkt3[2] &= !0x40;
    assert_eq!(decode(&pkt3), Err(DecodeError::FlagMismatch));
}

#[test]
fn version_negotiation() {
    let mut hdr = IPv8Header::new(addr_min(), addr_min(), 0);
    assert_eq!(negotiate_local(&hdr), Negotiation::Degrade { their_min_compat: 0 });
    hdr.min_compat_ver = 8;
    assert_eq!(negotiate_local(&hdr), Negotiation::Full);
    hdr.min_compat_ver = 9;
    assert_eq!(
        negotiate_local(&hdr),
        Negotiation::Incompatible { their_min_compat: 9, local: 8 }
    );
}

#[test]
fn address_canonical_text() {
    // spec §3.2：16 字节大端、32 个小写十六进制、不压缩零
    let a = IPv8Address::new(0x0102_0304, 0x0A0B_0C0D, 0x1122, 0x3344, 0x02);
    // asn(8) host(8) dev(4) cap(4) sec(2) reserved(6) = 32 位
    assert_eq!(a.to_canonical_string(), "010203040a0b0c0d1122334402000000");
    let zero = IPv8Address::new(0, 0, 0, 0, 0);
    assert_eq!(zero.to_canonical_string(), "0".repeat(32));

    // 往返 + 大小写不敏感
    let back = IPv8Address::from_canonical_str("010203040A0B0C0D1122334402000000").unwrap();
    assert_eq!(back, a);

    // 非法输入
    assert_eq!(IPv8Address::from_canonical_str("0102"), Err(AddrParseError::Format));
    assert_eq!(
        IPv8Address::from_canonical_str(&format!("{}g00000", "0".repeat(25))),
        Err(AddrParseError::Format)
    );
    assert_eq!(
        IPv8Address::from_canonical_str("010203040a0b0c0d1122334402ff0000"),
        Err(AddrParseError::ReservedNonZero)
    );
}

#[test]
fn compat_classification() {
    assert_eq!(classify(&[0x45, 0, 0, 0]), Some(InnerProto::IPv4));
    assert_eq!(classify(&[0x60, 0, 0, 0]), Some(InnerProto::IPv6));
    assert_eq!(classify(&[0x00]), Some(InnerProto::Other));
    assert_eq!(classify(&[]), None);
}

/// 性质测试：LCG 伪随机合法包头 → 编码 → 解码 → 一致（1000 轮）
#[test]
fn property_roundtrip_random() {
    let mut state: u64 = 0x1234_5678_9ABC_DEF0;
    let mut next = move || {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (state >> 33) as u32
    };
    for _ in 0..1000 {
        let src = IPv8Address::new(next(), next(), next() as u16, next() as u16, next() as u8);
        let dst = IPv8Address::new(next(), next(), next() as u16, next() as u16, next() as u8);
        let plen = (next() % 1392) as u16; // 一个 MTU 内的典型载荷
        let mut hdr = IPv8Header::new(src, dst, plen);
        hdr.flags = (next() % 16) as u16
            | if next() % 2 == 0 { flags::ENCRYPTED } else { 0 }
            | if next() % 3 == 0 { flags::FRAGMENT } else { 0 };
        hdr.hop_limit = next() as u8;
        if next() % 4 == 0 {
            let types = [ExtType::IdentityToken, ExtType::SemanticTag, ExtType::AgentCard];
            let n = 1 + (next() % 3) as usize;
            let exts: Vec<_> = types[..n.min(types.len())]
                .iter()
                .map(|t| ExtensionHeader::new(*t, vec![next() as u8; 8]).unwrap())
                .collect();
            hdr.attach_ext_headers(exts);
        }
        let payload: Vec<u8> = (0..plen as usize).map(|_| next() as u8).collect();
        let pkt = encode(&hdr, &payload).unwrap();
        let d = decode(&pkt).unwrap();
        assert_eq!(d.header, hdr, "往返不一致: {hdr:?}");
        assert_eq!(d.payload, &payload[..]);
    }
}

/// 性质测试：任意截断/损坏的字节流喂给 decode 不得 panic
#[test]
fn property_decode_never_panics() {
    let good = {
        let mut hdr = IPv8Header::new(addr_full(), addr_min(), 8);
        hdr.attach_ext_headers(vec![ExtensionHeader::new(ExtType::RouteTrace, vec![7; 24]).unwrap()]);
        encode(&hdr, b"payload!").unwrap()
    };
    // 所有前缀截断
    for i in 0..good.len() {
        let _ = decode(&good[..i]);
    }
    // 单字节翻转
    for i in 0..good.len() {
        for bit in 0..8 {
            let mut corrupted = good.clone();
            corrupted[i] ^= 1 << bit;
            let _ = decode(&corrupted); // 允许 Ok 或 Err，不许 panic
        }
    }
}
