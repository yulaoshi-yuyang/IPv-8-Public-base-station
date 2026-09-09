//! 证书认证握手（Phase 2，ADR-005 收口）。
//!
//! 背景：Phase 1 的 X25519 握手只提供密钥协商、不认证身份，`handshake.rs` 里的
//! MITM 测试正是这一缺口的活证据（中间人换临时公钥，双方密钥不一致却无人察觉）。
//! 本模块在不改动 Phase-1 已验收路径的前提下，提供 SigMA 式两条认证握手：
//!
//! ```text
//! Init  (I→R): ephI ‖ edI ‖ addrI ‖ notAfterI ‖ caSigI ‖ hsSigI
//! Resp  (R→I): ephR ‖ edR ‖ addrR ‖ notAfterR ‖ caSigR ‖ hsSigR
//!   hsSigX = Ed25519_sign(skX, DOMAIN ‖ role ‖ ephX ‖ edX ‖ addrX ‖ notAfterX ‖ ephPeer)
//! ```
//!
//! - `caSigX`：CA 对 `addrX ‖ edX ‖ notAfterX` 的签名（证书，绑定"哪个地址拥有哪把 Ed25519 公钥"）。
//! - 接收方三验：① CA 公钥验证书签名 ② 证书未过期 ③ 用证书里的 ed 公钥验 transcript 签名。
//! - 角色字节 'I'/'R' 区分两条消息，防反射攻击；Resp 的 transcript 绑定 Init 的真实
//!   eph，故中间人替换 Init 会被发起方检出。
//! - 会话密钥仍是 `X(eph_self_secret, eph_peer_pub)`，认证层与协商层解耦。
//!
//! 时钟以 `now: u64`（epoch 秒）注入，测试确定性、无 SystemTime 依赖。

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use ipv8_codec::IPv8Address;
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::crypto::TunnelKeys;
use crate::frame::FrameError;

/// 握手域分隔常量（transcript 前缀，防跨协议签名复用）
const DOMAIN: &[u8] = b"ipv8plus-handshake/v2";
/// Init/Resp 认证束定长：eph32 ‖ ed32 ‖ addr16 ‖ notAfter8 ‖ caSig64 ‖ hsSig64
pub const AUTH_BUNDLE_LEN: usize = 32 + 32 + 16 + 8 + 64 + 64;
/// 证书永久有效哨兵
pub const NO_EXPIRY: u64 = u64::MAX;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    /// 认证束长度不符
    BadBundleLen,
    /// CA 对证书的签名无效（伪造/篡改证书）
    BadCertSignature,
    /// 证书已过期
    Expired { not_after: u64, now: u64 },
    /// Ed25519 公钥字节非法
    BadVerifyKey,
    /// transcript 签名无效（身份未认证 / 中间人替换临时密钥）
    BadHandshakeSignature,
    /// 对端证书地址与期望的 peer 不符（合法 CA 下的错误身份）
    PeerMismatch { expected: IPv8Address, got: IPv8Address },
    /// 地址字节非法（含 Reserved 非零）
    BadAddress,
}

impl core::fmt::Display for AuthError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadBundleLen => write!(f, "认证束长度应为 {AUTH_BUNDLE_LEN}"),
            Self::BadCertSignature => write!(f, "证书 CA 签名校验失败"),
            Self::Expired { not_after, now } => {
                write!(f, "证书已过期: not_after={not_after} < now={now}")
            }
            Self::BadVerifyKey => write!(f, "非法 Ed25519 公钥"),
            Self::BadHandshakeSignature => write!(f, "握手 transcript 签名无效（身份未认证）"),
            Self::PeerMismatch { expected, got } => write!(
                f,
                "对端证书地址 {got} 与期望 {expected} 不符"
            ),
            Self::BadAddress => write!(f, "非法 IPv8+ 地址"),
        }
    }
}

impl std::error::Error for AuthError {}

/// 证书：把"IPv8+ 地址"绑定到"Ed25519 公钥"，由 CA 签名。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cert {
    pub addr: IPv8Address,
    pub verify_key: [u8; 32],
    pub not_after: u64,
    pub ca_sig: [u8; 64],
}

impl Cert {
    /// 证书待签体（TBS）= addr ‖ verify_key ‖ not_after
    fn tbs(&self) -> Vec<u8> {
        let mut t = Vec::with_capacity(56);
        t.extend_from_slice(&self.addr.to_bytes());
        t.extend_from_slice(&self.verify_key);
        t.extend_from_slice(&self.not_after.to_be_bytes());
        t
    }

    /// 120 字节线格式：TBS(56) ‖ ca_sig(64)。
    /// spec §6.6 规定多跳包用 IdentityToken 头携带源证书，中转/目的地
    /// 用本地信任锚离线验证——`ipv8-routing::cert_binding_ok` 消费本编码。
    pub fn to_wire(&self) -> Vec<u8> {
        let mut w = self.tbs();
        w.extend_from_slice(&self.ca_sig);
        w
    }
}

/// 证书签发机构（持有 Ed25519 私钥）。生产环境即 ZoneServer 的 CA。
pub struct CertAuthority {
    signing: SigningKey,
}

impl CertAuthority {
    pub fn generate() -> Self {
        Self { signing: SigningKey::generate(&mut rand_core::OsRng) }
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self { signing: SigningKey::from_bytes(&seed) }
    }

    /// CA 公钥（供各节点构造 TrustAnchor）
    pub fn public_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// 为 (addr, verify_key) 签发改书。`not_after` 用 [`NO_EXPIRY`] 表示不过期。
    pub fn issue(&self, addr: IPv8Address, verify_key: [u8; 32], not_after: u64) -> Cert {
        let mut cert = Cert { addr, verify_key, not_after, ca_sig: [0u8; 64] };
        cert.ca_sig = self.signing.sign(&cert.tbs()).to_bytes();
        cert
    }
}

/// 信任锚：节点预置的 CA 公钥（自托管即换此公钥，ADR-021）。
#[derive(Clone)]
pub struct TrustAnchor {
    ca_pub: VerifyingKey,
}

impl TrustAnchor {
    pub fn from_bytes(b: [u8; 32]) -> Result<Self, AuthError> {
        VerifyingKey::from_bytes(&b).map(|ca_pub| Self { ca_pub }).map_err(|_| AuthError::BadVerifyKey)
    }

    /// 锚公钥（32B）：传给 ipv8-routing 做证书绑定验证
    pub fn anchor_bytes(&self) -> [u8; 32] {
        self.ca_pub.to_bytes()
    }

    /// 验证证书：CA 签名 + 未过期。
    pub fn verify(&self, cert: &Cert, now: u64) -> Result<(), AuthError> {
        let sig = Signature::from_bytes(&cert.ca_sig);
        self.ca_pub
            .verify_strict(&cert.tbs(), &sig)
            .map_err(|_| AuthError::BadCertSignature)?;
        if now > cert.not_after {
            return Err(AuthError::Expired { not_after: cert.not_after, now });
        }
        Ok(())
    }
}

/// 节点握手身份：Ed25519 签名密钥 + CA 为其地址签发的证书。
#[derive(Clone)]
pub struct HostIdentity {
    pub addr: IPv8Address,
    signing: SigningKey,
    pub cert: Cert,
}

impl HostIdentity {
    pub fn public_ed_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// 用本身份私钥对任意消息签名（多跳 RouteTrace PathSig 的签名入口；
    /// spec §6.6 有域分隔，不会与握手/注册签名混淆）
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.signing.sign(msg).to_bytes()
    }

    /// 用外部（ZoneServer）签发的证书构造身份。节点不需要 CA 私钥——这是
    /// 真机路径：`cert.verify_key` 必须与 `ed_seed` 对应的公钥一致，否则握手
    /// transcript 签名与证书公钥对不上，auth_accept 阶段即失败。
    pub fn with_cert(addr: IPv8Address, ed_seed: [u8; 32], cert: Cert) -> Self {
        Self { addr, signing: SigningKey::from_bytes(&ed_seed), cert }
    }
}

/// 从 Ed25519 私钥种子派生公钥（注册时上送 ZoneServer，私钥永不出本机）。
pub fn verify_key_from_seed(ed_seed: [u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(&ed_seed).verifying_key().to_bytes()
}

/// 注册 PoP 域分隔常量（客户端签名 / 服务端验签共用，单一来源）
pub const REGISTER_DOMAIN: &[u8] = b"ipv8plus-register";
/// 密钥轮换 PoP 域分隔常量（域不同 → 注册签名不可挪用到轮换，反之亦然）
pub const ROTATE_DOMAIN: &[u8] = b"ipv8plus-rotate";

/// PoP 消息体：domain ‖ addr_text ‖ ed_pub
///
/// addr 必须参与：否则一份注册 PoP 可被挪用到其它地址的注册/轮换请求上。
pub fn pop_message(domain: &[u8], addr_text: &str, ed_pub: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(domain.len() + addr_text.len() + ed_pub.len());
    m.extend_from_slice(domain);
    m.extend_from_slice(addr_text.as_bytes());
    m.extend_from_slice(ed_pub);
    m
}

/// 注册 PoP 消息体（domain = REGISTER_DOMAIN）
pub fn register_pop_message(addr_text: &str, ed_pub: &[u8]) -> Vec<u8> {
    pop_message(REGISTER_DOMAIN, addr_text, ed_pub)
}

/// 轮换 PoP 消息体（domain = ROTATE_DOMAIN）
pub fn rotate_pop_message(addr_text: &str, new_ed_pub: &[u8]) -> Vec<u8> {
    pop_message(ROTATE_DOMAIN, addr_text, new_ed_pub)
}

/// 用 Ed 私钥种子对消息签 PoP（注册/轮换请求的持有证明）
pub fn pop_sign(ed_seed: [u8; 32], msg: &[u8]) -> [u8; 64] {
    SigningKey::from_bytes(&ed_seed).sign(msg).to_bytes()
}

/// 用 CA 派生并签发一个节点身份。仅测试/内嵌 CA 场景使用（需要 CA 私钥）；
/// 生产节点走 [`HostIdentity::with_cert`] + ZoneServer 签发。
pub fn provision(ca: &CertAuthority, addr: IPv8Address, ed_seed: [u8; 32], not_after: u64) -> HostIdentity {
    let signing = SigningKey::from_bytes(&ed_seed);
    let cert = ca.issue(addr, signing.verifying_key().to_bytes(), not_after);
    HostIdentity { addr, signing, cert }
}

/// 序列认证束为定长线格式。
fn pack_bundle(
    eph: &[u8; 32],
    ed: &[u8; 32],
    addr: &IPv8Address,
    not_after: u64,
    ca_sig: &[u8; 64],
    hs_sig: &[u8; 64],
) -> Vec<u8> {
    let mut b = Vec::with_capacity(AUTH_BUNDLE_LEN);
    b.extend_from_slice(eph);
    b.extend_from_slice(ed);
    b.extend_from_slice(&addr.to_bytes());
    b.extend_from_slice(&not_after.to_be_bytes());
    b.extend_from_slice(ca_sig);
    b.extend_from_slice(hs_sig);
    b
}

/// 反序列化后的认证束（具名结构，避免六元组类型过复杂）
struct Bundle {
    eph: [u8; 32],
    ed: [u8; 32],
    addr: IPv8Address,
    not_after: u64,
    ca_sig: [u8; 64],
    hs_sig: [u8; 64],
}

/// 反序列化认证束。
fn unpack_bundle(bytes: &[u8]) -> Result<Bundle, AuthError> {
    if bytes.len() != AUTH_BUNDLE_LEN {
        return Err(AuthError::BadBundleLen);
    }
    let mut eph = [0u8; 32];
    eph.copy_from_slice(&bytes[0..32]);
    let mut ed = [0u8; 32];
    ed.copy_from_slice(&bytes[32..64]);
    let addr =
        IPv8Address::from_canonical_str(&hex(&bytes[64..80])).map_err(|_| AuthError::BadAddress)?;
    let not_after = u64::from_be_bytes(bytes[80..88].try_into().unwrap());
    let mut ca_sig = [0u8; 64];
    ca_sig.copy_from_slice(&bytes[88..152]);
    let mut hs_sig = [0u8; 64];
    hs_sig.copy_from_slice(&bytes[152..216]);
    Ok(Bundle { eph, ed, addr, not_after, ca_sig, hs_sig })
}

fn hex(b: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push(H[(x >> 4) as usize] as char);
        s.push(H[(x & 0x0F) as usize] as char);
    }
    s
}

/// transcript = DOMAIN ‖ role ‖ eph_self ‖ ed_self ‖ addr_self ‖ not_after_self ‖ eph_peer
fn transcript(
    role: u8,
    eph_self: &[u8; 32],
    ed_self: &[u8; 32],
    addr_self: &IPv8Address,
    not_after_self: u64,
    eph_peer: &[u8; 32],
) -> Vec<u8> {
    let mut t = Vec::with_capacity(DOMAIN.len() + 1 + 32 + 32 + 16 + 8 + 32);
    t.extend_from_slice(DOMAIN);
    t.push(role);
    t.extend_from_slice(eph_self);
    t.extend_from_slice(ed_self);
    t.extend_from_slice(&addr_self.to_bytes());
    t.extend_from_slice(&not_after_self.to_be_bytes());
    t.extend_from_slice(eph_peer);
    t
}

fn verify_strict(ed: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> Result<(), AuthError> {
    let vk = VerifyingKey::from_bytes(ed).map_err(|_| AuthError::BadVerifyKey)?;
    vk.verify_strict(msg, &Signature::from_bytes(sig))
        .map_err(|_| AuthError::BadHandshakeSignature)
}

/// 发起方持有待完成状态：临时私钥 + 其公钥（验 Resp 时作为 eph_peer 回绑）
pub struct AuthPending {
    eph: EphemeralSecret,
    eph_pub: [u8; 32],
}

/// 发起方产出 Init 认证束。
///
/// 此时尚不知道对端临时公钥 → transcript 的 eph_peer 用全零占位；
/// Resp 会把 Init 的真实 eph 绑进去，形成双向绑定。
pub fn auth_init(host: &HostIdentity) -> (Vec<u8>, AuthPending) {
    let eph = EphemeralSecret::random_from_rng(rand_core::OsRng);
    let eph_pub: [u8; 32] = *PublicKey::from(&eph).as_bytes();
    let ed = host.public_ed_key();
    let ts = transcript(b'I', &eph_pub, &ed, &host.addr, host.cert.not_after, &[0u8; 32]);
    let hs_sig = host.signing.sign(&ts).to_bytes();
    let bundle =
        pack_bundle(&eph_pub, &ed, &host.addr, host.cert.not_after, &host.cert.ca_sig, &hs_sig);
    (bundle, AuthPending { eph, eph_pub })
}

/// 响应方验证 Init 并产出 Resp 认证束 + 会话密钥。
///
/// `expected_peer`：若为 Some(addr)，要求对端证书地址与之相符（堵"合法 CA 但
/// 对话对象非预期"错配；Resolver 已解析目标时由 Engine 传入）。None = 不校验。
pub fn auth_accept(
    host: &HostIdentity,
    trust: &TrustAnchor,
    init_bundle: &[u8],
    expected_peer: Option<IPv8Address>,
    now: u64,
) -> Result<(Vec<u8>, TunnelKeys), AuthError> {
    let b = unpack_bundle(init_bundle)?;
    // ① 证书（addr 取自束内声明，与公钥一起由 CA 签名保护）
    let cert_i = Cert { addr: b.addr, verify_key: b.ed, not_after: b.not_after, ca_sig: b.ca_sig };
    trust.verify(&cert_i, now)?;
    // ② 对端身份绑定：证书合法但不是要对话的人 → 拒绝
    if let Some(exp) = expected_peer {
        if b.addr != exp {
            return Err(AuthError::PeerMismatch { expected: exp, got: b.addr });
        }
    }
    // ③ transcript 签名：只有持有该地址对应 Ed 私钥者能签
    let ts_i = transcript(b'I', &b.eph, &b.ed, &b.addr, b.not_after, &[0u8; 32]);
    verify_strict(&b.ed, &ts_i, &b.hs_sig)?;

    let eph_r = EphemeralSecret::random_from_rng(rand_core::OsRng);
    let eph_r_pub: [u8; 32] = *PublicKey::from(&eph_r).as_bytes();
    let ed_r = host.public_ed_key();
    let ts_r = transcript(b'R', &eph_r_pub, &ed_r, &host.addr, host.cert.not_after, &b.eph);
    let hs_sig_r = host.signing.sign(&ts_r).to_bytes();
    let resp =
        pack_bundle(&eph_r_pub, &ed_r, &host.addr, host.cert.not_after, &host.cert.ca_sig, &hs_sig_r);

    let shared = eph_r.diffie_hellman(&PublicKey::from(b.eph));
    Ok((resp, TunnelKeys::new(*shared.as_bytes(), false)))
}

/// 发起方验证 Resp + 建立会话密钥。
///
/// `expected_peer`：要求对端证书地址与之相符（同 auth_accept，None = 不校验）。
/// 若中间人替换了 Init 的 eph，Resp 绑定的 eph_peer 与 `pending.eph_pub` 不符，
/// 签名验证失败 → MITM 检出。
pub fn auth_finish_init(
    pending: AuthPending,
    trust: &TrustAnchor,
    expected_peer: Option<IPv8Address>,
    resp_bundle: &[u8],
    now: u64,
) -> Result<TunnelKeys, AuthError> {
    let b = unpack_bundle(resp_bundle)?;
    let cert_r = Cert { addr: b.addr, verify_key: b.ed, not_after: b.not_after, ca_sig: b.ca_sig };
    trust.verify(&cert_r, now)?;
    if let Some(exp) = expected_peer {
        if b.addr != exp {
            return Err(AuthError::PeerMismatch { expected: exp, got: b.addr });
        }
    }
    let ts_r = transcript(b'R', &b.eph, &b.ed, &b.addr, b.not_after, &pending.eph_pub);
    verify_strict(&b.ed, &ts_r, &b.hs_sig)?;
    let shared = pending.eph.diffie_hellman(&PublicKey::from(b.eph));
    Ok(TunnelKeys::new(*shared.as_bytes(), true))
}

/// 认证握手失败统一并入帧错误，供 Engine/gRPC 层复用
impl From<AuthError> for FrameError {
    fn from(_: AuthError) -> Self {
        FrameError::AuthFailed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(n: u32) -> IPv8Address {
        IPv8Address::new(64500, n, 1, 0, 1)
    }

    fn setup() -> (TrustAnchor, HostIdentity, HostIdentity) {
        let ca = CertAuthority::from_seed([0xC4u8; 32]);
        let trust = TrustAnchor::from_bytes(ca.public_key()).unwrap();
        let alice = provision(&ca, addr(1), [0xA1u8; 32], NO_EXPIRY);
        let bob = provision(&ca, addr(2), [0xB0u8; 32], NO_EXPIRY);
        (trust, alice, bob)
    }

    const AAD: &[u8] = b"fake-ipv8-header-40-bytes-padding!!xxxxxxxx";

    #[test]
    fn authenticated_handshake_establishes_and_exchanges() {
        let (trust, alice, bob) = setup();
        let now = 1_700_000_000u64;

        let (init, pending) = auth_init(&alice);
        assert_eq!(init.len(), AUTH_BUNDLE_LEN);
        // 双方都绑定"预期对端地址"：Bob 期望 Alice(1)，Alice 期望 Bob(2)
        let (resp, mut bob_keys) =
            auth_accept(&bob, &trust, &init, Some(addr(1)), now).unwrap();
        let mut alice_keys =
            auth_finish_init(pending, &trust, Some(addr(2)), &resp, now).unwrap();

        let (kid, ct) = alice_keys.seal(AAD, b"secret");
        assert_eq!(bob_keys.open(&kid, &ct, AAD).unwrap(), b"secret");
        // 反向
        let (kid2, ct2) = bob_keys.seal(AAD, b"reply");
        assert_eq!(alice_keys.open(&kid2, &ct2, AAD).unwrap(), b"reply");
    }

    #[test]
    fn peer_mismatch_rejected() {
        // 共享 CA 下唯一残余攻击面：对话对象证书合法、签名合法，
        // 但不是我们约定要连接的那个地址（Resolver 被投毒/串号）。
        // expected_peer 绑定必须在此拦下。
        let (trust, alice, bob) = setup();
        let now = 1_700_000_000u64;
        let (init, _pending) = auth_init(&alice); // Alice 证书 addr=addr(1)，合法
        // Bob 期望连的是 addr(99)，实际来的是合法的 addr(1) → 身份错配
        assert_eq!(
            auth_accept(&bob, &trust, &init, Some(addr(99)), now).err(),
            Some(AuthError::PeerMismatch { expected: addr(99), got: addr(1) }),
            "合法证书但不是预期对端 → PeerMismatch"
        );
        // 不绑定（None）则放行到正常密钥建立——校验是显式开关
        assert!(auth_accept(&bob, &trust, &init, None, now).is_ok());
    }

    #[test]
    fn mitm_is_now_detected() {
        // 对照 handshake.rs 里"MITM 成功"的旧世界：认证后换 Init 的临时公钥，
        // 会破坏 Alice 绑定真 eph 的 transcript 签名 → Bob 在 accept 阶段即拒绝。
        let (trust, alice, bob) = setup();
        let rogue_ca = CertAuthority::from_seed([0xC4u8; 32]); // 同 CA → Mallory 证书合法
        let mallory = provision(&rogue_ca, addr(3), [0x5Au8; 32], NO_EXPIRY);
        let now = 1_700_000_000u64;

        let (mut init, _pending) = auth_init(&alice);
        let (evil_init, _p2) = auth_init(&mallory);
        init[0..32].copy_from_slice(&evil_init[0..32]); // 只换 eph，其余仍是 Alice 的

        assert_eq!(
            auth_accept(&bob, &trust, &init, Some(addr(1)), now).err(),
            Some(AuthError::BadHandshakeSignature),
            "临时密钥被换 → Alice 的 transcript 签名对不上 → MITM 在 accept 即检出"
        );
    }

    #[test]
    fn forged_cert_rejected() {
        let (trust, _alice, bob) = setup();
        // Mallory 用另一把 CA 私钥冒充 addr(2)
        let rogue_ca = CertAuthority::from_seed([0xFFu8; 32]);
        let fake = provision(&rogue_ca, addr(2), [0x11u8; 32], NO_EXPIRY);
        let (init, _pending) = auth_init(&fake);
        assert_eq!(
            auth_accept(&bob, &trust, &init, None, 1).err(),
            Some(AuthError::BadCertSignature),
            "非信任锚签发的证书被拒"
        );
    }

    #[test]
    fn tampered_cert_binding_rejected() {
        // 真 CA 签的证书，但事后把 addr 改成别人的 → CA 签名不再匹配
        let (trust, alice, bob) = setup();
        let (mut init, _p) = auth_init(&alice);
        // addr 位于 bytes[64..80]：篡改成 addr(2) 冒充 Bob
        let forged = addr(2).to_bytes();
        init[64..80].copy_from_slice(&forged);
        assert_eq!(
            auth_accept(&bob, &trust, &init, None, 1).err(),
            Some(AuthError::BadCertSignature),
            "改绑定关系必然破坏 CA 签名"
        );
    }

    #[test]
    fn expired_cert_rejected() {
        let ca = CertAuthority::from_seed([0xC4u8; 32]);
        let trust = TrustAnchor::from_bytes(ca.public_key()).unwrap();
        let alice = provision(&ca, addr(1), [0xA1u8; 32], 100); // not_after=100
        let bob = provision(&ca, addr(2), [0xB0u8; 32], NO_EXPIRY);
        let (init, _p) = auth_init(&alice);
        assert!(matches!(
            auth_accept(&bob, &trust, &init, None, 101).err(),
            Some(AuthError::Expired { not_after: 100, now: 101 })
        ));
        // 未过期时刻仍可用
        assert!(auth_accept(&bob, &trust, &init, None, 100).is_ok());
    }

    #[test]
    fn bundle_length_enforced() {
        let (trust, alice, bob) = setup();
        let short = alice.addr.to_bytes().to_vec();
        assert_eq!(
            auth_accept(&bob, &trust, &short, None, 1).err(),
            Some(AuthError::BadBundleLen)
        );
    }

    #[test]
    fn unknown_ca_anchor_rejects_everything() {
        let ca = CertAuthority::from_seed([0xC4u8; 32]);
        let alice = provision(&ca, addr(1), [0xA1u8; 32], NO_EXPIRY);
        let bob = provision(&ca, addr(2), [0xB0u8; 32], NO_EXPIRY);
        let stranger = TrustAnchor::from_bytes(CertAuthority::from_seed([0x99u8; 32]).public_key()).unwrap();
        let (init, _p) = auth_init(&alice);
        assert_eq!(
            auth_accept(&bob, &stranger, &init, None, 1).err(),
            Some(AuthError::BadCertSignature)
        );
    }
}
