//! 测试脚手架（仅 cfg(test)）：手工造证书/CardSig/PoP 的公共夹具。
//! lib 单测与 grpc e2e 共用，保证两侧验证材料同一构造路径。
#![allow(dead_code)]

use ed25519_dalek::{Signer, SigningKey};
use ipv8_codec::{agent_card_message, IPv8Address};

use crate::{
    ans_register_pop_message, AgentCard, AnsService, RegisterSpec, CARD_VERSION,
};

pub const CA_SEED: [u8; 32] = [0xC4u8; 32];
pub const ROOT: &str = ".ipv8.net";
pub const NOW: u64 = 2_000_000_000;
/// 永久（远未来）
pub const FOREVER: u64 = u64::MAX - 1;

pub fn far_future() -> u64 {
    FOREVER
}

pub fn addr(n: u32) -> IPv8Address {
    IPv8Address::with_region(n as u64, 1, 0, 0x0100, 0)
}
pub fn text(n: u32) -> String {
    addr(n).to_canonical_string()
}
pub fn addr_text(n: u32) -> String {
    text(n)
}

pub fn ca() -> SigningKey {
    SigningKey::from_bytes(&CA_SEED)
}

/// CA 公钥（信任锚）
pub fn anchor() -> [u8; 32] {
    ca().verifying_key().to_bytes()
}

/// 造 120B 证书线格式：TBS = addr16 ‖ pub32 ‖ not_after8，CA 签名附尾
pub fn make_cert_wire(
    ca: &SigningKey,
    a: IPv8Address,
    pubkey: &[u8; 32],
    not_after: u64,
) -> Vec<u8> {
    let mut tbs = Vec::with_capacity(56);
    tbs.extend_from_slice(&a.to_bytes());
    tbs.extend_from_slice(pubkey);
    tbs.extend_from_slice(&not_after.to_be_bytes());
    let sig = ca.sign(&tbs).to_bytes();
    let mut w = tbs;
    w.extend_from_slice(&sig);
    w
}

pub struct Agent {
    pub sk: SigningKey,
    pub a: IPv8Address,
    /// 完整名（含根）
    pub name: String,
    pub caps: Vec<String>,
    pub qos: u8,
}

impl Agent {
    pub fn new(seed: u8, n: u32, short: &str, caps: &[&str], qos: u8) -> Self {
        Self {
            sk: SigningKey::from_bytes(&[seed; 32]),
            a: addr(n),
            name: format!("{short}{ROOT}"),
            caps: caps.iter().map(|s| s.to_string()).collect(),
            qos,
        }
    }
    pub fn pubkey(&self) -> [u8; 32] {
        self.sk.verifying_key().to_bytes()
    }
    pub fn name(&self) -> String {
        self.name.clone()
    }
    pub fn card(&self, not_after: u64) -> AgentCard {
        AgentCard {
            version: CARD_VERSION,
            name: self.name.clone(),
            addr: self.a,
            capabilities: self.caps.clone(),
            endpoints: vec![format!("10.0.0.{}:45700", self.a.region_lo)],
            qos_hint: self.qos,
            not_after,
            tunnel_entry: format!("192.0.2.{}:45700", self.a.region_lo),
        }
    }
}

/// 完整登记材料包：证书 + CardSig + PoP 全现签
pub struct Kit {
    pub card: AgentCard,
    pub cert: Vec<u8>,
    pub card_sig: [u8; 64],
    pub pop: Vec<u8>,
    pub hash: [u8; 16],
}

pub fn kit(ca: &SigningKey, ag: &Agent, not_after: u64) -> Kit {
    let card = ag.card(not_after);
    let hash = card.card_hash().unwrap();
    let pk = ag.pubkey();
    let cert = make_cert_wire(ca, ag.a, &pk, not_after);
    let card_sig = ag.sk.sign(&agent_card_message(card.version, &hash, not_after, &pk)).to_bytes();
    let pop = ag
        .sk
        .sign(&ans_register_pop_message(&card.name, &text_of(ag.a), &hash))
        .to_bytes()
        .to_vec();
    Kit { card, cert, card_sig, pop, hash }
}

pub fn text_of(a: IPv8Address) -> String {
    a.to_canonical_string()
}

pub fn spec_of<'a>(k: &'a Kit, addr_text: &'a str) -> RegisterSpec<'a> {
    RegisterSpec {
        addr_text,
        cert_wire: &k.cert,
        card: &k.card,
        card_sig: &k.card_sig,
        pop: &k.pop,
    }
}

pub fn svc() -> AnsService {
    AnsService::new(anchor(), ROOT)
}

pub fn caps(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

pub fn task(req: &[&str], min: usize, qos: u8, ms: u64) -> crate::TaskDescription {
    crate::TaskDescription {
        required_caps: caps(req),
        min_count: min,
        qos_level: qos,
        timeout_ms: ms,
    }
}
