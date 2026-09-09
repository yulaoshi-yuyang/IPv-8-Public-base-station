//! ZoneServer 最小实现（Phase 2 先行的纯逻辑层，无网络/无 DB）。
//!
//! 职责（v9 §5 cloud/IPv8Plus.ZoneServer 的等价 Rust 核心）：
//! - **PoP 注册**：节点上送 Ed25519 公钥 + 对该密钥签的 proof，验通过才发证书
//!   → 防止冒注他人公钥；
//! - **证书签发**：复用 ipv8-tunnel::auth 的 `Cert`/`CertAuthority` 格式，
//!   与握手三验天然互认（addr ‖ verify_key ‖ not_after 的 CA 签名）；
//! - **JWT（HS256）**：sub=addr_text，含 iat/exp；`verify_token` 校验签名与过期；
//! - **密钥轮换**：需 JWT 且需新密钥 PoP（防 JWT 被盗后换公钥）。
//!
//! 本层刻意保持无 IO / 无时钟：`now` 一律由调用方注入（gRPC 层用系统时钟，
//! 测试用固定值），与 ipv8-tunnel 的 auth/keys 设计一致。
//!
//! gRPC 接线见 [`grpc`]（tonic 服务 + 生成好的 client stub 供节点侧复用）。

pub mod grpc;

use std::collections::HashMap;

use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hmac::{Hmac, Mac};
use ipv8_codec::IPv8Address;
use ipv8_tunnel::auth::{register_pop_message, rotate_pop_message, Cert, CertAuthority};
use sha2::Sha256;

/// 默认证书有效期：90 天
pub const DEFAULT_VALIDITY_SECS: u64 = 90 * 24 * 3600;
/// 默认 JWT 有效期：24 小时
pub const DEFAULT_TOKEN_TTL_SECS: u64 = 24 * 3600;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZoneError {
    /// 地址文本非法
    BadAddress,
    /// 公钥/签名字节长度不符
    BadKeyLength,
    /// PoP 签名无效（非该密钥持有者，或域/内容不匹配）
    BadProof,
    /// 地址已被占用（重复注册需走 RotateKey）
    AlreadyRegistered { addr: IPv8Address },
    /// 未注册的地址
    NotRegistered { addr: IPv8Address },
    /// JWT 签名无效 / 格式错误
    BadToken,
    /// JWT 过期
    TokenExpired { exp: u64, now: u64 },
    /// 轮换时 JWT 的 sub 与注册记录不符
    TokenMismatch,
}

impl core::fmt::Display for ZoneError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadAddress => write!(f, "地址文本必须是 32 个十六进制数字"),
            Self::BadKeyLength => write!(f, "公钥需 32 字节、签名需 64 字节"),
            Self::BadProof => write!(f, "PoP 签名验证失败（非该密钥持有者或内容不符）"),
            Self::AlreadyRegistered { addr } => write!(f, "地址 {addr} 已注册"),
            Self::NotRegistered { addr } => write!(f, "地址 {addr} 未注册"),
            Self::BadToken => write!(f, "JWT 签名/格式无效"),
            Self::TokenExpired { exp, now } => write!(f, "JWT 已过期: exp={exp} now={now}"),
            Self::TokenMismatch => write!(f, "JWT 的 sub 与该地址注册记录不符"),
        }
    }
}

impl std::error::Error for ZoneError {}

/// 注册成功的返回包
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issued {
    pub cert: Cert,
    pub jwt: String,
}

#[derive(Clone)]
struct Record {
    verify_key: [u8; 32],
}

/// 服务端（持 CA 私钥 + JWT 密钥）。单进程内存存储 = Phase 2 最小版；
/// 持久化/多租户属 Phase 3（v9 ADR-010 SQLite→PG）。
pub struct ZoneServer {
    ca: CertAuthority,
    jwt_key: [u8; 32],
    records: HashMap<IPv8Address, Record>,
}

impl ZoneServer {
    /// 从固定种子构造（测试/内网部署可复现）。生产用 [`Self::generate`]。
    pub fn from_seeds(ca_seed: [u8; 32], jwt_key: [u8; 32]) -> Self {
        Self { ca: CertAuthority::from_seed(ca_seed), jwt_key, records: HashMap::new() }
    }

    pub fn generate() -> Self {
        let mut ca = [0u8; 32];
        let mut jk = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut ca);
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut jk);
        Self::from_seeds(ca, jk)
    }

    /// 信任锚 = CA 公钥（节点握手验证书用）
    pub fn trust_anchor(&self) -> [u8; 32] {
        self.ca.public_key()
    }

    pub fn is_registered(&self, addr: IPv8Address) -> bool {
        self.records.contains_key(&addr)
    }

    /// 注册 PoP 消息体（委托 auth 层共享实现，与节点侧签名逐字节一致）
    fn register_msg(addr_text: &str, ed_pub: &[u8]) -> Vec<u8> {
        register_pop_message(addr_text, ed_pub)
    }

    /// 轮换 PoP 消息体（domain 与注册不同 → 两场景签名不可互用；addr 参与 → 不可跨地址挪用）
    fn rotate_msg(addr_text: &str, new_ed_pub: &[u8]) -> Vec<u8> {
        rotate_pop_message(addr_text, new_ed_pub)
    }

    /// 用已注册密钥对消息体签名（客户端辅助；服务端只验）
    pub fn pop_sign(ed_signing: &SigningKey, msg: &[u8]) -> [u8; 64] {
        ed_signing.sign(msg).to_bytes()
    }

    /// 注册：验证 PoP → 签发证书 → 颁发 JWT。
    pub fn register(
        &mut self,
        addr_text: &str,
        ed_pub: &[u8],
        proof: &[u8],
        ttl_secs: u64,
        now: u64,
    ) -> Result<Issued, ZoneError> {
        let addr = IPv8Address::from_canonical_str(addr_text).map_err(|_| ZoneError::BadAddress)?;
        let vk = Self::parse_pub(ed_pub)?;
        let sig = Self::parse_sig(proof)?;
        // PoP：证明持有 ed_pub 对应私钥
        vk.verify_strict(&Self::register_msg(addr_text, ed_pub), &sig)
            .map_err(|_| ZoneError::BadProof)?;
        if let Some(rec) = self.records.get(&addr) {
            // PoP 本身即持有者证明：**同一密钥**的重注册视为证书续期放行
            // （节点重启时证书已过 90 天而 JWT 只剩 24h 效期，不留此路径
            // 将永远无法恢复）。换密钥仍必须走 rotate_key 的 JWT+新 PoP
            // 双因子，这里照旧拒绝——注册接口不构成密钥替换通道。
            if rec.verify_key != vk.to_bytes() {
                return Err(ZoneError::AlreadyRegistered { addr });
            }
        }
        let not_after = now.saturating_add(ttl_secs);
        let cert = self.ca.issue(addr, vk.to_bytes(), not_after);
        self.records.insert(addr, Record { verify_key: vk.to_bytes() });
        let jwt = self.issue_jwt(addr_text, now, DEFAULT_TOKEN_TTL_SECS)?;
        Ok(Issued { cert, jwt })
    }

    /// 密钥轮换：JWT 有效 且 sub==addr 且 新密钥 PoP 有效 → 重签证书。
    pub fn rotate_key(
        &mut self,
        jwt: &str,
        addr_text: &str,
        new_ed_pub: &[u8],
        proof: &[u8],
        ttl_secs: u64,
        now: u64,
    ) -> Result<Issued, ZoneError> {
        let sub = self.verify_token(jwt, now)?;
        if sub != addr_text {
            return Err(ZoneError::TokenMismatch);
        }
        let addr = IPv8Address::from_canonical_str(addr_text).map_err(|_| ZoneError::BadAddress)?;
        let vk = Self::parse_pub(new_ed_pub)?;
        let sig = Self::parse_sig(proof)?;
        vk.verify_strict(&Self::rotate_msg(addr_text, new_ed_pub), &sig)
            .map_err(|_| ZoneError::BadProof)?;
        let rec = self
            .records
            .get_mut(&addr)
            .ok_or(ZoneError::NotRegistered { addr })?;
        let not_after = now.saturating_add(ttl_secs);
        let cert = self.ca.issue(addr, vk.to_bytes(), not_after);
        rec.verify_key = vk.to_bytes(); // 旧公钥即刻作废
        Ok(Issued { cert, jwt: jwt.to_string() })
    }

    fn parse_pub(b: &[u8]) -> Result<VerifyingKey, ZoneError> {
        let arr: [u8; 32] = b.try_into().map_err(|_| ZoneError::BadKeyLength)?;
        VerifyingKey::from_bytes(&arr).map_err(|_| ZoneError::BadKeyLength)
    }

    fn parse_sig(b: &[u8]) -> Result<Signature, ZoneError> {
        let arr: [u8; 64] = b.try_into().map_err(|_| ZoneError::BadKeyLength)?;
        Ok(Signature::from_bytes(&arr))
    }

    // ============================ JWT (HS256) ============================

    fn b64(data: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
    }

    fn unb64(s: &str) -> Option<Vec<u8>> {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).ok()
    }

    fn hmac256(key: &[u8], msg: &[u8]) -> [u8; 32] {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
            .expect("HMAC accepts any key length");
        mac.update(msg);
        mac.finalize().into_bytes().into()
    }

    /// 签发 HS256 JWT：header {"alg":"HS256","typ":"JWT"}，payload {"sub","iat","exp"}
    pub fn issue_jwt(
        &self,
        addr_text: &str,
        now: u64,
        ttl_secs: u64,
    ) -> Result<String, ZoneError> {
        #[derive(serde::Serialize)]
        struct Claims<'a> {
            sub: &'a str,
            iat: u64,
            exp: u64,
        }
        let header = Self::b64(br#"{"alg":"HS256","typ":"JWT"}"#);
        let payload_json = serde_json::to_vec(&Claims {
            sub: addr_text,
            iat: now,
            exp: now.saturating_add(ttl_secs),
        })
        .map_err(|_| ZoneError::BadToken)?;
        let payload = Self::b64(&payload_json);
        let signing_input = format!("{header}.{payload}");
        let sig = Self::b64(&Self::hmac256(&self.jwt_key, signing_input.as_bytes()));
        Ok(format!("{signing_input}.{sig}"))
    }

    /// 校验 JWT，返回 sub（= addr_text）。
    pub fn verify_token(&self, jwt: &str, now: u64) -> Result<String, ZoneError> {
        self.verify_token_claims(jwt, now).map(|(sub, _exp)| sub)
    }

    /// 校验 JWT，返回 (sub, exp)。gRPC VerifyToken 回显 exp 用。
    pub fn verify_token_claims(&self, jwt: &str, now: u64) -> Result<(String, u64), ZoneError> {
        let mut parts = jwt.split('.');
        let (Some(h), Some(p), Some(s), None) = (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(ZoneError::BadToken);
        };
        let expect = Self::b64(&Self::hmac256(&self.jwt_key, format!("{h}.{p}").as_bytes()));
        if !ct_eq(expect.as_bytes(), s.as_bytes()) {
            return Err(ZoneError::BadToken);
        }
        let json = Self::unb64(p).ok_or(ZoneError::BadToken)?;
        let v: serde_json::Value = serde_json::from_slice(&json).map_err(|_| ZoneError::BadToken)?;
        let exp = v.get("exp").and_then(|x| x.as_u64()).ok_or(ZoneError::BadToken)?;
        if now > exp {
            return Err(ZoneError::TokenExpired { exp, now });
        }
        let sub = v
            .get("sub")
            .and_then(|x| x.as_str())
            .ok_or(ZoneError::BadToken)?
            .to_string();
        Ok((sub, exp))
    }
}

/// 定长比较（防时序侧信道）
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    const NOW: u64 = 1_700_000_000;
    fn seed(n: u8) -> [u8; 32] {
        [n; 32]
    }
    fn addr_text(n: u32) -> String {
        IPv8Address::new(64500, n, 1, 0, 1).to_canonical_string()
    }

    fn reg_pop(sk: &SigningKey, text: &str) -> ([u8; 32], [u8; 64]) {
        let msg = ZoneServer::register_msg(text, &sk.verifying_key().to_bytes());
        (sk.verifying_key().to_bytes(), sk.sign(&msg).to_bytes())
    }

    #[test]
    fn register_issues_cert_verifiable_by_trust_anchor() {
        let mut z = ZoneServer::from_seeds(seed(0xC4), seed(0x2A));
        let sk = SigningKey::from_bytes(&seed(0xA1));
        let text = addr_text(1);
        let (ed, proof) = reg_pop(&sk, &text);
        let issued = z.register(&text, &ed, &proof, DEFAULT_VALIDITY_SECS, NOW).unwrap();

        // 签发的证书必须能通过客户端信任锚三验的前两验（CA 签名 + 有效期）
        let anchor = ipv8_tunnel::auth::TrustAnchor::from_bytes(z.trust_anchor()).unwrap();
        assert!(anchor.verify(&issued.cert, NOW).is_ok());
        assert_eq!(issued.cert.addr.to_canonical_string(), text);
        assert_eq!(issued.cert.verify_key, ed);
        // JWT 可验且 sub 正确
        assert_eq!(z.verify_token(&issued.jwt, NOW + 60).unwrap(), text);
    }

    #[test]
    fn bad_pop_rejected() {
        let mut z = ZoneServer::from_seeds(seed(0xC4), seed(0x2A));
        let sk = SigningKey::from_bytes(&seed(0xA1));
        let text = addr_text(1);
        let (ed, _proof) = reg_pop(&sk, &text);
        // 用别的密钥签 proof → PoP 对不上公钥
        let attacker = SigningKey::from_bytes(&seed(0x66));
        let bad = attacker.sign(&ZoneServer::register_msg(&text, &ed)).to_bytes();
        assert_eq!(z.register(&text, &ed, &bad[..], 900, NOW).err(), Some(ZoneError::BadProof));

        // 域错配：拿注册签名当轮换用（domain 不同）也应失败
        let (ed2, proof2) = reg_pop(&sk, &text);
        z.register(&text, &ed2, &proof2, 900, NOW).unwrap();
        let rot_msg = ZoneServer::rotate_msg(&text, &ed2);
        let misuse = sk.sign(&rot_msg).to_bytes(); // 合法签名但针对 rotate 域 → 注册域校验应拒绝
        assert_eq!(
            z.register(&addr_text(2), &ed2, &misuse[..], 900, NOW).err(),
            Some(ZoneError::BadProof)
        );
    }

    #[test]
    fn duplicate_register_rejected() {
        let mut z = ZoneServer::from_seeds(seed(0xC4), seed(0x2A));
        let sk = SigningKey::from_bytes(&seed(0xA1));
        let text = addr_text(1);
        let (ed, proof) = reg_pop(&sk, &text);
        z.register(&text, &ed, &proof, 900, NOW).unwrap();
        // 换密钥重注册：即便 PoP 有效也拒绝（密钥替换必须走 rotate_key 双因子）
        let sk2 = SigningKey::from_bytes(&seed(0xDD));
        let (ed2, proof2) = reg_pop(&sk2, &text);
        assert_eq!(
            z.register(&text, &ed2, &proof2, 900, NOW + 1).err(),
            Some(ZoneError::AlreadyRegistered { addr: IPv8Address::from_canonical_str(&text).unwrap() })
        );
    }

    #[test]
    fn same_key_reregister_renews_cert() {
        // 节点重启 + 证书过期后的恢复路径：同密钥 PoP 重注册 = 续期
        let mut z = ZoneServer::from_seeds(seed(0xC4), seed(0x2A));
        let sk = SigningKey::from_bytes(&seed(0xA1));
        let text = addr_text(1);
        let (ed, proof) = reg_pop(&sk, &text);
        let old = z.register(&text, &ed, &proof, 900, NOW).unwrap();
        let later = NOW + 901; // 旧证书已过期
        let fresh = z.register(&text, &ed, &proof, 900, later).unwrap();
        assert_eq!(fresh.cert.verify_key, old.cert.verify_key);
        assert!(fresh.cert.not_after > old.cert.not_after);
        let anchor = ipv8_tunnel::auth::TrustAnchor::from_bytes(z.trust_anchor()).unwrap();
        assert!(anchor.verify(&fresh.cert, later).is_ok());
        assert!(anchor.verify(&old.cert, later).is_err(), "旧证书过期后须不可用");
    }

    #[test]
    fn rotate_requires_valid_token_and_new_pop() {
        let mut z = ZoneServer::from_seeds(seed(0xC4), seed(0x2A));
        let sk = SigningKey::from_bytes(&seed(0xA1));
        let text = addr_text(1);
        let (ed, proof) = reg_pop(&sk, &text);
        let issued = z.register(&text, &ed, &proof, 900, NOW).unwrap();

        // 1) 无 JWT → 拒
        assert_eq!(z.verify_token("garbage", NOW).err(), Some(ZoneError::BadToken));

        // 2) 过期 JWT → 拒
        assert!(matches!(
            z.verify_token(&issued.jwt, NOW + DEFAULT_TOKEN_TTL_SECS + 1).err(),
            Some(ZoneError::TokenExpired { .. })
        ));

        // 3) 合法 JWT + 新密钥 PoP → 重签，旧公钥作废
        let sk2 = SigningKey::from_bytes(&seed(0xB2));
        let (ed2, proof2) = {
            let msg = ZoneServer::rotate_msg(&text, &sk2.verifying_key().to_bytes());
            (sk2.verifying_key().to_bytes(), sk2.sign(&msg).to_bytes())
        };
        let r2 = z
            .rotate_key(&issued.jwt, &text, &ed2, &proof2, 900, NOW + 10)
            .unwrap();
        assert_eq!(r2.cert.verify_key, ed2);

        // 4) 有 JWT 但 PoP 是旧密钥签的（没有新私钥证明）→ 拒
        let (ed3, proof3) = {
            let attacker_sk = SigningKey::from_bytes(&seed(0x99));
            let msg = ZoneServer::rotate_msg(&text, &sk.verifying_key().to_bytes());
            (sk.verifying_key().to_bytes(), attacker_sk.sign(&msg).to_bytes())
        };
        assert_eq!(
            z.rotate_key(&issued.jwt, &text, &ed3, &proof3, 900, NOW + 20).err(),
            Some(ZoneError::BadProof)
        );

        // 5) 用 A 的 JWT 换 B 的密钥：addr 不符（sub 不匹配 / rotate PoP 未注册）
        let b_text = addr_text(2);
        let b_sk = SigningKey::from_bytes(&seed(0xBB));
        let (b_ed, b_proof) = reg_pop(&b_sk, &b_text);
        z.register(&b_text, &b_ed, &b_proof, 900, NOW).unwrap();
        let (x_ed, x_proof) = {
            let msg = ZoneServer::rotate_msg(&b_text, &b_sk.verifying_key().to_bytes());
            (b_sk.verifying_key().to_bytes(), b_sk.sign(&msg).to_bytes())
        };
        assert_eq!(
            z.rotate_key(&issued.jwt, &b_text, &x_ed, &x_proof, 900, NOW + 5).err(),
            Some(ZoneError::TokenMismatch)
        );
    }

    #[test]
    fn tampered_jwt_rejected() {
        let mut z = ZoneServer::from_seeds(seed(0xC4), seed(0x2A));
        let sk = SigningKey::from_bytes(&seed(0xA1));
        let text = addr_text(1);
        let (ed, proof) = reg_pop(&sk, &text);
        let issued = z.register(&text, &ed, &proof, 900, NOW).unwrap();
        // 篡改 payload：sub 换成别人的地址
        let parts: Vec<&str> = issued.jwt.split('.').collect();
        let evil_claims = format!(r#"{{"sub":"{}","iat":{},"exp":{}}}"#, addr_text(42), NOW, NOW + 9999);
        let evil_payload =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(evil_claims.as_bytes());
        let forged = format!("{}.{}.{}", parts[0], evil_payload, parts[2]);
        assert_eq!(z.verify_token(&forged, NOW).err(), Some(ZoneError::BadToken));
    }

    #[test]
    fn bad_address_text_rejected() {
        let mut z = ZoneServer::from_seeds(seed(0xC4), seed(0x2A));
        let sk = SigningKey::from_bytes(&seed(0xA1));
        let (ed, proof) = {
            let msg = ZoneServer::register_msg("nothex", &sk.verifying_key().to_bytes());
            (sk.verifying_key().to_bytes(), sk.sign(&msg).to_bytes())
        };
        assert_eq!(z.register("nothex", &ed, &proof, 900, NOW).err(), Some(ZoneError::BadAddress));
    }

    #[test]
    fn wrong_key_length_rejected() {
        let mut z = ZoneServer::from_seeds(seed(0xC4), seed(0x2A));
        let text = addr_text(1);
        assert_eq!(
            z.register(&text, &[0u8; 31], &[0u8; 64], 900, NOW).err(),
            Some(ZoneError::BadKeyLength)
        );
        let sk = SigningKey::from_bytes(&seed(0xA1));
        let ed = sk.verifying_key().to_bytes();
        assert_eq!(
            z.register(&text, &ed, &[0u8; 63], 900, NOW).err(),
            Some(ZoneError::BadKeyLength)
        );
    }

    /// 全链路：ZoneServer 签发的证书 + 信任锚 直接进入认证握手数据面
    #[test]
    fn issued_cert_works_in_authenticated_handshake() {
        use ipv8_tunnel::auth::{verify_key_from_seed, HostIdentity, TrustAnchor, NO_EXPIRY};
        use ipv8_tunnel::Engine;

        let mut z = ZoneServer::from_seeds(seed(0xC4), seed(0x2A));
        let anchor = TrustAnchor::from_bytes(z.trust_anchor()).unwrap();

        // 两个节点各自生成密钥 → 向 ZoneServer 注册拿证书（不持有 CA 私钥）
        let mut setup = |n: u32, priv_seed: u8| -> HostIdentity {
            let sk = SigningKey::from_bytes(&seed(priv_seed));
            let text = addr_text(n);
            let ed = verify_key_from_seed(sk.to_bytes());
            let msg = ZoneServer::register_msg(&text, &ed);
            let proof = sk.sign(&msg).to_bytes();
            let issued = z.register(&text, &ed, &proof, NO_EXPIRY, NOW).unwrap();
            HostIdentity::with_cert(IPv8Address::from_canonical_str(&text).unwrap(), sk.to_bytes(), issued.cert)
        };
        let host_a = setup(1, 0xA1);
        let host_b = setup(2, 0xB0);

        let mut alice = Engine::authenticated(host_a, anchor.clone(), addr_text(1).parse().unwrap(), addr_text(2).parse().unwrap());
        let mut bob = Engine::authenticated(host_b, anchor, addr_text(2).parse().unwrap(), addr_text(1).parse().unwrap());
        let init = alice.start_auth_handshake();
        let resp = bob.handle_frame_at(&init, NOW).expect("ZoneServer 签发的证书应被信任锚接受");
        alice.handle_frame_at(&resp, NOW);
        assert_eq!(alice.state(), ipv8_tunnel::State::Established);
        assert_eq!(bob.state(), ipv8_tunnel::State::Established);
    }
}
