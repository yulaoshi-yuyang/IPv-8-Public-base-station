//! RouteTrace 构建与验证（spec §6.6，ADR-019 决议）。
//!
//! 信任模型：源点用 Ed25519 私钥（Phase 2 证书体系）对"冻结基头字段 +
//! 初始 HopLimit + 完整路径"签一次名；中转/目的地用随包携带的 SrcPubKey
//! 验签，并用本地信任锚验证 `SrcAddr ↔ SrcPubKey` 的证书绑定——两件事
//! 都过才承认路径合法。HopLimit 逐跳可变（§10.2），签名钉的是 RouteTrace
//! 内的明文副本 InitHopLimit；中转以 `InitHopLimit − k == 当前 HopLimit`
//! （k = 本机在列表中的下标，与 IP 语义一致：目的地不减）自证跳数预算
//! 未被拉伸/压缩。

use ed25519_dalek::{Signature, VerifyingKey};
use ipv8_codec::{route_trace_message, IPv8Address, RouteTrace};

/// 验证失败类别（§6.6 MUST 丢弃路径上的每种情形）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceError {
    /// HopCount=0 / 超上限 / 载荷长与声明不符
    BadTrace,
    /// PathSig 对 SrcPubKey 验签失败（冻结字段或路径被篡改）
    BadPathSig,
    /// SrcAddr ↔ SrcPubKey 的证书绑定无效（冒充源点）
    BadCertBinding,
    /// 本机地址不在列表的合法跳位上，或 HopLimit 与跳位不一致
    NotOnPath,
}

/// 本节点对多跳流量的转发策略（由 Engine 在装配时确定）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TracePolicy {
    /// Phase 1/2 行为：只收 DstAddr==本机，永不转发（零回归默认）
    NoForward,
    /// 多跳中转：本机在路径中时验证并转发（需信任锚做证书绑定验证）
    Relay,
}

/// 验证决策（转发路径的三种归宿）
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// 本机是目的地：交付载荷
    Deliver,
    /// 本机是第 k 跳中转：把包发往该地址（外层物理地址由调用方解析）
    ForwardTo {
        /// 列表中的下一跳 IPv8+ 地址
        next: IPv8Address,
        /// 下一跳在列表中的下标（0 基，即 hops[k+1]）
        hop_index: usize,
    },
}

/// 从编码后的基头取冻结字节 0-6（Version‖MinCompat | Flags | PayloadLen |
/// HopLimit | NextHdr）。RouteTrace 包要求链首：`head[6] == 5`，不符即拒
/// （防链重排绕签名，spec §6.6）。
pub fn frozen_head(base40: &[u8]) -> Option<[u8; 7]> {
    if base40.len() < 7 || base40[6] != 5 {
        return None;
    }
    Some([base40[0], base40[1], base40[2], base40[3], base40[4], base40[5], base40[6]])
}

/// [`build_route_trace`] 的输入（源点建路径所需的全部要素）。
#[derive(Debug, Clone, Copy)]
pub struct PathSpec<'a> {
    pub src_addr: IPv8Address,
    pub dst_addr: IPv8Address,
    pub min_compat_ver: u8,
    /// 基头 flags 的**最终值**（含 E/X 等位——签名在基头定型后计算）
    pub flags: u16,
    pub payload_len: u16,
    /// 发出时刻 HopLimit（RouteTrace 明文副本 + 签名覆盖）
    pub init_hop_limit: u8,
    /// 不含源点的完整路径，末项 MUST == dst_addr（spec §6.6）
    pub hops: &'a [IPv8Address],
    /// 源点 Ed25519 公钥（进消息体防延展；证书体系中的 verify_key）
    pub src_pubkey: &'a [u8; 32],
}

/// 源点构建 RouteTrace 载荷（含 PathSig）。
///
/// `sign` 对 [`route_trace_message`] 的输出签名——密钥持有形态由调用方
/// 决定（种子/签名器对象均可），本 crate 因此不需要接触私钥存储。
pub fn build_route_trace(
    spec: &PathSpec<'_>,
    sign: impl FnOnce(&[u8]) -> [u8; 64],
) -> Result<RouteTrace, TraceError> {
    let PathSpec { src_addr, dst_addr, min_compat_ver, flags, payload_len, init_hop_limit, hops, src_pubkey } =
        *spec;
    if hops.is_empty() || hops.len() > 64 {
        return Err(TraceError::BadTrace);
    }
    if *hops.last().expect("非空已验") != dst_addr {
        return Err(TraceError::NotOnPath);
    }
    let msg = route_trace_message(&ipv8_codec::TraceSigInput {
        src_addr: &src_addr,
        dst_addr: &dst_addr,
        min_compat_ver,
        flags,
        payload_len,
        init_hop_limit,
        src_pubkey,
        hops,
    });
    Ok(RouteTrace {
        src_pubkey: *src_pubkey,
        path_sig: sign(&msg),
        init_hop_limit,
        hops: hops.to_vec(),
    })
}

/// 从 120B 证书线格式提取其中的 Ed25519 公钥（TBS 偏移 16..48）。
/// 长度非法返回 None；**不验签**——仅"取出证书声明的 pubkey"，供调用方
/// 配合 [`cert_binding_ok`] 使用（ANS 登记据此把 CardSig/PoP 的验证密钥
/// 锚定到证书声明的 addr↔pubkey，避免调用方自带 pubkey 造成的绑定错位）。
pub fn cert_pubkey_from_wire(cert_wire: &[u8]) -> Option<[u8; 32]> {
    if cert_wire.len() != 120 {
        return None;
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&cert_wire[16..48]);
    Some(pk)
}

/// 证书绑定验证：`cert(addr ‖ pubkey ‖ not_after ‖ ca_sig)` 由锚公钥验签，
/// 且主体必须恰好是被验证的 (addr, pubkey)。
///
/// 证书线格式 120 字节（ipv8-tunnel::auth::Cert 同一编码：TBS = addr16 ‖
/// pub32 ‖ not_after8 共 56B，CA 签名 64B 附尾）。独立实现以维持
/// codec ← routing 的依赖方向（见 lib.rs 注释）。`now` 为调用方墙钟秒。
pub fn cert_binding_ok(
    anchor_pub: &[u8; 32],
    cert_wire: &[u8],
    addr: &IPv8Address,
    pubkey: &[u8; 32],
    now: u64,
) -> bool {
    if cert_wire.len() != 120 {
        return false;
    }
    let (tbs, sig) = cert_wire.split_at(56);
    if tbs[0..16] != addr.to_bytes()[..] || tbs[16..48] != *pubkey {
        return false;
    }
    let Ok(ca) = VerifyingKey::from_bytes(anchor_pub) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(sig) else {
        return false;
    };
    if ca.verify_strict(tbs, &sig).is_err() {
        return false;
    }
    let not_after = u64::from_be_bytes(tbs[48..56].try_into().expect("56B 切片"));
    now <= not_after
}

/// [`verify_for_next_hop`] 的输入（中转/目的地验证所需全部材料）。
#[derive(Debug, Clone, Copy)]
pub struct VerifyInput<'a> {
    /// 本机地址（定位自己在路径中的跳位）
    pub local_addr: IPv8Address,
    pub trace: &'a RouteTrace,
    /// 接收基头字节 0-6（[`frozen_head`] 提取；NextHdr 已校验为链首 5）
    pub head7: &'a [u8; 7],
    pub src_addr: IPv8Address,
    pub dst_addr: IPv8Address,
    /// 此刻基头 HopLimit（每经过一个转发节点减 1）
    pub current_hop_limit: u8,
    /// 源证书线格式 120B（IdentityToken 头携带，spec §6.6）
    pub cert_wire: &'a [u8],
    /// 本节点信任锚公钥
    pub anchor_pub: &'a [u8; 32],
    /// 墙钟秒（证书有效期检查）
    pub now: u64,
}

/// 中转/目的地统一入口：验证 RouteTrace 并给出决策（§10.3：任一步失败
/// 调用方 MUST 丢弃并计数）。
pub fn verify_for_next_hop(v: &VerifyInput<'_>) -> Result<Decision, TraceError> {
    let trace = v.trace;
    let head7 = v.head7;

    // 1) 冻结字段 + 路径摘要 → 验 PathSig（对随包 SrcPubKey）
    let msg = route_trace_message(&ipv8_codec::TraceSigInput {
        src_addr: &v.src_addr,
        dst_addr: &v.dst_addr,
        min_compat_ver: head7[0] & 0x0F, // Version 高 4 位固定 0x8，覆盖字节 0 整体
        flags: u16::from_be_bytes([head7[1], head7[2]]),
        payload_len: u16::from_be_bytes([head7[3], head7[4]]),
        init_hop_limit: trace.init_hop_limit,
        src_pubkey: &trace.src_pubkey,
        hops: &trace.hops,
    });
    let pk = VerifyingKey::from_bytes(&trace.src_pubkey).map_err(|_| TraceError::BadCertBinding)?;
    let sig = Signature::from_bytes(&trace.path_sig);
    pk.verify_strict(&msg, &sig).map_err(|_| TraceError::BadPathSig)?;

    // 2) SrcAddr ↔ SrcPubKey 证书绑定（含有效期）
    if !cert_binding_ok(v.anchor_pub, v.cert_wire, &v.src_addr, &trace.src_pubkey, v.now) {
        return Err(TraceError::BadCertBinding);
    }

    // 3) 本机跳位与 HopLimit 递减一致（k = hops 下标；目的地 k=n-1 不再减，
    //    与 IP 语义一致——spec §6.6）
    let k = trace
        .hops
        .iter()
        .position(|h| *h == v.local_addr)
        .ok_or(TraceError::NotOnPath)?;
    if k > usize::from(trace.init_hop_limit)
        || trace.init_hop_limit - k as u8 != v.current_hop_limit
    {
        return Err(TraceError::NotOnPath);
    }
    if k + 1 == trace.hops.len() {
        Ok(Decision::Deliver) // 本机 = 末项 = 目的地（hops.last()==dst）
    } else {
        Ok(Decision::ForwardTo { next: trace.hops[k + 1], hop_index: k + 1 })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use ipv8_codec::ROUTE_TRACE_DOMAIN;

    fn a(n: u32) -> IPv8Address {
        IPv8Address::new(0xfb14, n, 1, 0, 1)
    }

    /// 造 120B 证书线格式：ca_seed 给 (addr,pub,not_after) 签名
    fn make_cert(ca_seed: &[u8; 32], addr: IPv8Address, pub_key: &[u8; 32], not_after: u64) -> Vec<u8> {
        let ca = SigningKey::from_bytes(ca_seed);
        let mut tbs = Vec::with_capacity(56);
        tbs.extend_from_slice(&addr.to_bytes());
        tbs.extend_from_slice(pub_key);
        tbs.extend_from_slice(&not_after.to_be_bytes());
        let sig = ca.sign(&tbs);
        let mut w = tbs;
        w.extend_from_slice(&sig.to_bytes());
        w
    }

    /// 冻结基头字节 0-6（与 build/verify 的消息体重建严格对应）
    fn head7(min_compat: u8, flags: u16, plen: u16, cur_hl: u8) -> [u8; 7] {
        let f = flags.to_be_bytes();
        let p = plen.to_be_bytes();
        [0x80 | (min_compat & 0x0F), f[0], f[1], p[0], p[1], cur_hl, 5]
    }

    const CA: &[u8; 32] = &[0xC4u8; 32];
    const SRC_SEED: &[u8; 32] = &[0xA1u8; 32];

    /// 与 SRC_SEED 对应的公钥（spec 用）
    fn src_pub() -> [u8; 32] {
        SigningKey::from_bytes(SRC_SEED).verifying_key().to_bytes()
    }

    /// 默认签名器（持 SRC_SEED 的节点）
    fn sign_src(msg: &[u8]) -> [u8; 64] {
        SigningKey::from_bytes(SRC_SEED).sign(msg).to_bytes()
    }

    struct Setup {
        src: IPv8Address,
        dst: IPv8Address,
        relay: IPv8Address,
        trace: RouteTrace,
        cert: Vec<u8>,
        anchor: [u8; 32],
    }

    impl Setup {
        /// 常规验证输入（now=1，证书未过期）；特殊用例经字段覆写派生
        fn vi<'a>(&'a self, local: IPv8Address, h: &'a [u8; 7], cur: u8) -> VerifyInput<'a> {
            VerifyInput {
                local_addr: local,
                trace: &self.trace,
                head7: h,
                src_addr: self.src,
                dst_addr: self.dst,
                current_hop_limit: cur,
                cert_wire: &self.cert,
                anchor_pub: &self.anchor,
                now: 1,
            }
        }
    }

    /// 源点建一条 A→R→B 的路径（init HopLimit=64，未过期证书）
    fn setup() -> Setup {
        let (src, relay, dst) = (a(1), a(2), a(3));
        let hops = vec![relay, dst];
        let trace = build_route_trace(
            &PathSpec {
                src_addr: src,
                dst_addr: dst,
                min_compat_ver: 0,
                flags: 0x40,
                payload_len: 8,
                init_hop_limit: 64,
                hops: &hops,
                src_pubkey: &src_pub(),
            },
            sign_src,
        )
        .unwrap();
        let cert = make_cert(CA, src, &trace.src_pubkey, 10_000);
        // 锚 = CA **公钥**（种子只是测试里的签名私钥来源）
        let anchor = SigningKey::from_bytes(CA).verifying_key().to_bytes();
        Setup { src, dst, relay, trace, cert, anchor }
    }

    fn spec<'a>(src: IPv8Address, dst: IPv8Address, hops: &'a [IPv8Address]) -> PathSpec<'a> {
        static ZERO32: [u8; 32] = [0u8; 32];
        PathSpec {
            src_addr: src,
            dst_addr: dst,
            min_compat_ver: 0,
            flags: 0x40,
            payload_len: 8,
            init_hop_limit: 64,
            hops,
            // 拒签用例在触到 pubkey 前就返回 Err，取静态零占位即可
            src_pubkey: &ZERO32,
        }
    }

    fn build(s: &PathSpec<'_>) -> Result<RouteTrace, TraceError> {
        build_route_trace(s, sign_src)
    }

    #[test]
    fn build_rejects_empty_and_oversized_path() {
        assert_eq!(build(&spec(a(1), a(3), &[])).err(), Some(TraceError::BadTrace));
        let many: Vec<_> = (0..65).map(|i| a(i + 100)).collect();
        assert_eq!(
            build(&spec(a(1), *many.last().unwrap(), &many)).err(),
            Some(TraceError::BadTrace)
        );
    }

    #[test]
    fn build_requires_path_end_at_dst() {
        // 路径末项不是 dst = 目的不可达，拒签
        assert_eq!(build(&spec(a(1), a(3), &[a(2)])).err(), Some(TraceError::NotOnPath));
    }

    #[test]
    fn destination_verifies_and_delivers() {
        let s = setup();
        // 目的地在 hops[1]（k=1）：current = 64−1 = 63（交付路径不再减）
        let h = head7(0, 0x40, 8, 63);
        assert_eq!(verify_for_next_hop(&s.vi(s.dst, &h, 63)), Ok(Decision::Deliver));
    }

    #[test]
    fn relay_forwards_to_next_hop() {
        let s = setup();
        // 中转在 hops[0]（k=0）：current = 64−0 = 64（源点发出未自减）
        let h = head7(0, 0x40, 8, 64);
        assert_eq!(
            verify_for_next_hop(&s.vi(s.relay, &h, 64)),
            Ok(Decision::ForwardTo { next: s.dst, hop_index: 1 })
        );
    }

    #[test]
    fn tamper_flags_breaks_path_sig() {
        let s = setup();
        let h = head7(0, 0x41, 8, 63); // Flags 低 4bit QoS 被中间节点改
        assert_eq!(
            verify_for_next_hop(&s.vi(s.dst, &h, 63)).err(),
            Some(TraceError::BadPathSig)
        );
    }

    #[test]
    fn tamper_payload_len_breaks_sig() {
        let s = setup();
        let h = head7(0, 0x40, 9, 63); // PayloadLen 篡改
        assert_eq!(
            verify_for_next_hop(&s.vi(s.dst, &h, 63)).err(),
            Some(TraceError::BadPathSig)
        );
    }

    #[test]
    fn tamper_mincompat_breaks_sig() {
        let s = setup();
        let h = head7(1, 0x40, 8, 63); // MinCompatVer 篡改
        assert_eq!(
            verify_for_next_hop(&s.vi(s.dst, &h, 63)).err(),
            Some(TraceError::BadPathSig)
        );
    }

    #[test]
    fn swap_dst_breaks_sig() {
        let s = setup();
        let h = head7(0, 0x40, 8, 63);
        let mut v = s.vi(s.dst, &h, 63);
        v.dst_addr = a(9); // 声称别的目的地（DstAddr 改写攻击）
        assert_eq!(verify_for_next_hop(&v).err(), Some(TraceError::BadPathSig));
    }

    #[test]
    fn swap_src_addr_breaks_sig() {
        let s = setup();
        let h = head7(0, 0x40, 8, 63);
        let mut v = s.vi(s.dst, &h, 63);
        v.src_addr = a(9); // 冒充别的源点
        assert_eq!(verify_for_next_hop(&v).err(), Some(TraceError::BadPathSig));
    }

    #[test]
    fn pubkey_swap_not_extension() {
        // 替换 SrcPubKey（配一份自证新公钥的假证书）：PathSig 对新公钥必失败
        let s = setup();
        let evil = SigningKey::from_bytes(&[0xE7u8; 32]);
        let mut forged = s.trace.clone();
        forged.src_pubkey = evil.verifying_key().to_bytes();
        let fcert = make_cert(CA, s.src, &forged.src_pubkey, 10_000);
        let h = head7(0, 0x40, 8, 63);
        let mut v = s.vi(s.dst, &h, 63);
        v.trace = &forged;
        v.cert_wire = &fcert;
        assert_eq!(
            verify_for_next_hop(&v).err(),
            Some(TraceError::BadPathSig),
            "SrcPubKey 入签：换公钥即破坏签名"
        );
    }

    #[test]
    fn missing_or_expired_cert_binding_rejected() {
        let s = setup();
        let h = head7(0, 0x40, 8, 63);
        let empty = [];
        let mut v = s.vi(s.dst, &h, 63);
        v.cert_wire = &empty; // 无证书 → 长度不符
        assert_eq!(verify_for_next_hop(&v).err(), Some(TraceError::BadCertBinding));
        let mut v = s.vi(s.dst, &h, 63);
        v.now = 10_001; // 过期
        assert_eq!(verify_for_next_hop(&v).err(), Some(TraceError::BadCertBinding));
    }

    #[test]
    fn rogue_anchor_rejected() {
        let s = setup();
        let h = head7(0, 0x40, 8, 63);
        // 证书由 CA 签，但验证方用的是另一个**合法**锚 → CA 签名验不过
        let bogus = SigningKey::from_bytes(&[0x99u8; 32]).verifying_key().to_bytes();
        let mut v = s.vi(s.dst, &h, 63);
        v.anchor_pub = &bogus;
        assert_eq!(verify_for_next_hop(&v).err(), Some(TraceError::BadCertBinding));
    }

    #[test]
    fn hoplimit_stretch_and_shrink_rejected() {
        let s = setup();
        // 目的地 k=1 的合法 current = 63。提前送到（偏大）或伪造跳数（偏小）都拒
        for cur in [64u8, 62u8, 0u8, 1u8] {
            let h = head7(0, 0x40, 8, cur);
            assert_eq!(
                verify_for_next_hop(&s.vi(s.dst, &h, cur)).err(),
                Some(TraceError::NotOnPath),
                "current={cur} 与 init−k=63 不一致应被拒"
            );
        }
    }

    #[test]
    fn node_not_on_path_rejected() {
        let s = setup();
        let h = head7(0, 0x40, 8, 63);
        // 本机 a(7) 根本不在 hops=[a2,a3] 里
        assert_eq!(
            verify_for_next_hop(&s.vi(a(7), &h, 63)).err(),
            Some(TraceError::NotOnPath)
        );
    }

    #[test]
    fn frozen_head_enforces_chain_first() {
        // 基头字节 6（NextHdr）非 5 → 拒绝（RouteTrace 不在链首即绕签名）
        assert!(frozen_head(&[0x80, 0, 0x40, 0, 8, 64, 5]).is_some());
        assert_eq!(frozen_head(&[0x80, 0, 0x40, 0, 8, 64, 0]), None); // 无扩展头
        assert_eq!(frozen_head(&[0x80, 0, 0x40, 0, 8, 64, 6]), None); // 链首是 Fragment
        assert_eq!(frozen_head(&[0x80, 0, 0x40]), None); // 过短
    }

    #[test]
    fn message_has_domain_and_pubkey_prefix() {
        // 域分隔 + SrcPubKey 紧随其后（防跨协议签名挪用的结构证据）
        let pk = [0xA1u8; 32];
        let m = route_trace_message(&ipv8_codec::TraceSigInput {
            src_addr: &a(1),
            dst_addr: &a(3),
            min_compat_ver: 0,
            flags: 0x40,
            payload_len: 8,
            init_hop_limit: 64,
            src_pubkey: &pk,
            hops: &[a(2), a(3)],
        });
        assert!(m.starts_with(ROUTE_TRACE_DOMAIN));
        assert_eq!(&m[ROUTE_TRACE_DOMAIN.len()..ROUTE_TRACE_DOMAIN.len() + 32], &pk);
    }
}
