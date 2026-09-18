//! IPv8+ 二层邻居发现（Phase 5B，spec §3）。
//!
//! EtherType 0xFB14 以太网帧 payload 上的签名 HELLO/ACK 协议：
//!
//! ```text
//! "IP8N"(4) | ver=1(1) | type(1: HELLO=1/ACK=2) | flags(2,保留0)
//! | addr(16 IPv8) | ts_secs(8 BE) | nonce(8 BE) | pubkey(32) | sig(64)
//! ```
//!
//! 共 136B 定长；签名域为前 72B（"IP8N" 魔数自带域分隔）。签名/验签经
//! [`SignatureOps`] trait 注入，本 crate **零依赖**；上层（ping8）用
//! ed25519-dalek 实现。
//!
//! 安全模型：
//! - 时间窗 ±300s 拒绝；每公钥最近 64 个 nonce 环形去重（HELLO/ACK 各自防重放）。
//! - 已授权公钥的 HELLO → 自动回 ACK；未知公钥 → 人工授权（NeedsConsent）。
//! - ACK 必须回显本端 30s 内发出 HELLO 的 nonce，发起方才把对端入表
//!   （发起即信任意图；被动方必须显式同意）。
//! - 邻居记录主键为公钥；同公钥换 mac/addr 自动刷新。
//!
//! 铁律（与 ipv8-fec/ipv8-compat 同款）：零依赖、全边界检查、绝不 panic。

#![forbid(unsafe_code)]

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;

// ── 线格式常量 ───────────────────────────────────────────────────

/// 报文魔数 "IP8N"（首字节 0x49，与高 4 位 0x8 的 IPv8 数据包天然不冲突）
pub const MAGIC: [u8; 4] = *b"IP8N";
/// 协议版本
pub const VERSION: u8 = 1;
/// HELLO（广播）
pub const MSG_HELLO: u8 = 1;
/// ACK（单播回 HELLO 源）
pub const MSG_ACK: u8 = 2;

/// 报文总长（定长）
pub const MSG_LEN: usize = 136;
/// Ed25519 公钥长
pub const PUBKEY_LEN: usize = 32;
/// Ed25519 签名长
pub const SIG_LEN: usize = 64;
/// IPv8 地址长
pub const ADDR_LEN: usize = 16;
/// MAC 长
pub const MAC_LEN: usize = 6;
/// nonce 长
pub const NONCE_LEN: usize = 8;

/// 签名域长度：报文前 72B（魔数/版本/类型/flags/addr/ts/nonce/pubkey）
pub const SIGNED_LEN: usize = 72;

/// 时间窗：±300 秒
pub const TS_WINDOW_SECS: i64 = 300;
/// 每公钥 nonce 环形去重容量
pub const NONCE_RING: usize = 64;
/// 本端待确认 HELLO nonce 的存活时间（秒）
pub const PENDING_TTL_SECS: i64 = 30;
/// 待确认集合硬上限（防异常不回 ACK 时无限增长）
pub const PENDING_MAX: usize = 1024;

// ── neighbors.bin 常量 ───────────────────────────────────────────

const STORE_MAGIC_1: [u8; 4] = *b"IP8N";
const STORE_MAGIC_2: [u8; 4] = *b"NBHR";
/// 邻居文件头：magic1(4)+magic2(4)+ver(1)+count(4 LE) = 13B
const STORE_HDR_LEN: usize = 13;
/// 单条记录：mac6+pad2+addr16+pubkey32+ts8 = 64B
pub const RECORD_LEN: usize = 64;
const STORE_VERSION: u8 = 1;

// ── 错误类型 ─────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NeighError {
    /// 报文长度不是 136B
    BadLength { expect: usize, got: usize },
    /// 魔数不是 "IP8N"
    BadMagic,
    /// 版本不支持
    BadVersion(u8),
    /// 类型不是 HELLO(1)/ACK(2)
    UnknownType(u8),
    /// 保留 flags 非 0
    BadFlags(u16),
    /// ts_secs 超出 i64（不可信输入）
    BadTimestamp,
    /// 签名验证失败（或 sig 被翻转）
    BadSignature,
    /// 时间戳超出 ±300s 窗口
    TimestampOutOfWindow { msg: i64, now: i64 },
    /// nonce 在最近 64 个之内（重放）
    Replay(u64),
    /// process_hello 收到非 HELLO
    UnexpectedType(u8),
    /// ACK 回显 nonce 不在本端待确认集合
    AckNonceMismatch(u64),
    /// neighbors.bin 长度不足
    StoreTooShort,
    /// neighbors.bin 魔数错误
    StoreMagic,
    /// neighbors.bin 版本不支持
    StoreVersion(u8),
    /// neighbors.bin 长度与 count 不一致
    StoreLength { expect: usize, got: usize },
    /// 文件 IO
    Io(String),
    /// 传输层错误（P8：MAC 解析 / trait 构造失败等）
    Transport(String),
}

impl fmt::Display for NeighError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NeighError::BadLength { expect, got } => {
                write!(f, "报文长度错误：期望 {expect}B，收到 {got}B")
            }
            NeighError::BadMagic => f.write_str("报文魔数不是 IP8N"),
            NeighError::BadVersion(v) => write!(f, "不支持的协议版本 {v}"),
            NeighError::UnknownType(t) => write!(f, "未知报文类型 {t}"),
            NeighError::BadFlags(x) => write!(f, "保留 flags 非 0：{x}"),
            NeighError::BadTimestamp => f.write_str("时间戳超出可表示范围"),
            NeighError::BadSignature => f.write_str("签名验证失败"),
            NeighError::TimestampOutOfWindow { msg, now } => write!(
                f,
                "时间戳超出 ±{TS_WINDOW_SECS}s 窗口（报文 {msg}，本机 {now}）"
            ),
            NeighError::Replay(n) => write!(f, "重放报文（nonce {n} 最近已见过）"),
            NeighError::UnexpectedType(t) => write!(f, "期望 HELLO，收到类型 {t}"),
            NeighError::AckNonceMismatch(n) => {
                write!(f, "ACK nonce {n} 不在本端 {PENDING_TTL_SECS}s 待确认集合")
            }
            NeighError::StoreTooShort => f.write_str("neighbors.bin 长度不足"),
            NeighError::StoreMagic => f.write_str("neighbors.bin 魔数错误"),
            NeighError::StoreVersion(v) => write!(f, "neighbors.bin 版本不支持：{v}"),
            NeighError::StoreLength { expect, got } => {
                write!(f, "neighbors.bin 长度与 count 不符：期望 {expect}，实际 {got}")
            }
            NeighError::Io(s) => write!(f, "文件读写失败：{s}"),
            NeighError::Transport(s) => write!(f, "传输层错误：{s}"),
        }
    }
}

impl std::error::Error for NeighError {}

impl From<io::Error> for NeighError {
    fn from(e: io::Error) -> Self {
        NeighError::Io(e.to_string())
    }
}

// ── 报文 ─────────────────────────────────────────────────────────

/// IP8N 邻居发现报文（136B 定长，全部数值字段大端）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeighborMessage {
    /// MSG_HELLO / MSG_ACK
    pub msg_type: u8,
    /// 保留（必须为 0）
    pub flags: u16,
    /// 发送方 16B IPv8 地址
    pub addr: [u8; ADDR_LEN],
    /// 发送方秒级时间戳
    pub ts_secs: i64,
    /// 随机 nonce；ACK 回显 HELLO 的 nonce
    pub nonce: u64,
    /// 发送方 Ed25519 公钥
    pub pubkey: [u8; PUBKEY_LEN],
    /// 前 72B 的 Ed25519 签名
    pub sig: [u8; SIG_LEN],
}

fn encode_parts(
    msg_type: u8,
    addr: &[u8; ADDR_LEN],
    ts_secs: i64,
    nonce: u64,
    pubkey: &[u8; PUBKEY_LEN],
    sig: &[u8; SIG_LEN],
) -> [u8; MSG_LEN] {
    let mut b = [0u8; MSG_LEN];
    b[0..4].copy_from_slice(&MAGIC);
    b[4] = VERSION;
    b[5] = msg_type;
    b[6..8].copy_from_slice(&0u16.to_be_bytes());
    b[8..24].copy_from_slice(addr);
    b[24..32].copy_from_slice(&(ts_secs as u64).to_be_bytes());
    b[32..40].copy_from_slice(&nonce.to_be_bytes());
    b[40..72].copy_from_slice(pubkey);
    b[72..136].copy_from_slice(sig);
    b
}

/// 严格解码；长度/魔数/版本/类型/flags/时间戳任一不合法即拒
pub fn decode(buf: &[u8]) -> Result<NeighborMessage, NeighError> {
    if buf.len() != MSG_LEN {
        return Err(NeighError::BadLength {
            expect: MSG_LEN,
            got: buf.len(),
        });
    }
    if buf[0..4] != MAGIC {
        return Err(NeighError::BadMagic);
    }
    let ver = buf[4];
    if ver != VERSION {
        return Err(NeighError::BadVersion(ver));
    }
    let msg_type = buf[5];
    if !matches!(msg_type, MSG_HELLO | MSG_ACK) {
        return Err(NeighError::UnknownType(msg_type));
    }
    let flags = u16::from_be_bytes([buf[6], buf[7]]);
    if flags != 0 {
        return Err(NeighError::BadFlags(flags));
    }
    let mut addr = [0u8; ADDR_LEN];
    addr.copy_from_slice(&buf[8..24]);
    let raw_ts = u64::from_be_bytes(buf[24..32].try_into().unwrap());
    let ts_secs = i64::try_from(raw_ts).map_err(|_| NeighError::BadTimestamp)?;
    let nonce = u64::from_be_bytes(buf[32..40].try_into().unwrap());
    let mut pubkey = [0u8; PUBKEY_LEN];
    pubkey.copy_from_slice(&buf[40..72]);
    let mut sig = [0u8; SIG_LEN];
    sig.copy_from_slice(&buf[72..136]);
    Ok(NeighborMessage {
        msg_type,
        flags,
        addr,
        ts_secs,
        nonce,
        pubkey,
        sig,
    })
}

impl NeighborMessage {
    /// 取签名域（前 72B）
    pub fn signing_domain(buf: &[u8]) -> &[u8] {
        &buf[..SIGNED_LEN.min(buf.len())]
    }

    /// 编码为 136B
    pub fn encode(&self) -> [u8; MSG_LEN] {
        encode_parts(
            self.msg_type,
            &self.addr,
            self.ts_secs,
            self.nonce,
            &self.pubkey,
            &self.sig,
        )
    }
}

/// 构造并签名一个报文（签名域前 72B）。`nonce`：HELLO 用新随机数，ACK 回显。
pub fn build_signed<S: SignatureOps + ?Sized>(
    signer: &S,
    msg_type: u8,
    addr: &[u8; ADDR_LEN],
    ts_secs: i64,
    nonce: u64,
    pubkey: &[u8; PUBKEY_LEN],
) -> [u8; MSG_LEN] {
    let unsigned = encode_parts(msg_type, addr, ts_secs, nonce, pubkey, &[0u8; SIG_LEN]);
    let sig = signer.sign(&unsigned[..SIGNED_LEN]);
    encode_parts(msg_type, addr, ts_secs, nonce, pubkey, &sig)
}

// ── 签名注入 ─────────────────────────────────────────────────────

/// Ed25519 签名操作注入点；上层用 ed25519-dalek 实现，本库零依赖
pub trait SignatureOps {
    /// 对签名域签名
    fn sign(&self, domain: &[u8]) -> [u8; SIG_LEN];
    /// 用公钥验签
    fn verify(&self, pubkey: &[u8; PUBKEY_LEN], domain: &[u8], sig: &[u8; SIG_LEN]) -> bool;
}

// ── 二层 payload 分类（与 IPv8 数据包区分）──────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadKind {
    /// IP8N 邻居发现报文（且长度为 136B）
    Neighbor,
    /// IPv8 数据包（首字节高 4 位为 0x8）
    Ipv8,
    /// 其它裸帧 payload
    Other,
}

/// 分类 0xFB14 帧 payload：IP8N（'I'=0x49 起始）/ IPv8（高 4 位 0x8）/ 其它
pub fn classify(payload: &[u8]) -> PayloadKind {
    if payload.len() >= 4 && payload[0..4] == MAGIC {
        // 长度也须是定长 136B 才算合法邻居报文
        if payload.len() == MSG_LEN {
            PayloadKind::Neighbor
        } else {
            PayloadKind::Other
        }
    } else if payload.first().map(|b| b >> 4) == Some(0x8) {
        PayloadKind::Ipv8
    } else {
        PayloadKind::Other
    }
}

/// 快速判定是否为邻居发现报文
pub fn is_neighbor_payload(payload: &[u8]) -> bool {
    classify(payload) == PayloadKind::Neighbor
}

// ── 邻居表 ───────────────────────────────────────────────────────

/// 已授权邻居（公钥为主键）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeighborRecord {
    /// 最近一次见到的二层源 MAC
    pub mac: [u8; MAC_LEN],
    /// IPv8 地址
    pub addr: [u8; ADDR_LEN],
    /// Ed25519 公钥（身份主键）
    pub pubkey: [u8; PUBKEY_LEN],
    /// 最近刷新时间（秒）
    pub ts: i64,
}

/// 内存邻居表 + neighbors.bin 线格式
/// ```text
/// "IP8N""NBHR"(8) | ver(1) | count(u32 LE) | record[]{mac6+pad2, addr16,
/// pubkey32, ts8 LE}  每条 64B
/// ```
#[derive(Debug, Clone, Default)]
pub struct NeighborStore {
    peers: Vec<NeighborRecord>,
}

impl NeighborStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.peers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &NeighborRecord> {
        self.peers.iter()
    }

    pub fn contains(&self, pubkey: &[u8; PUBKEY_LEN]) -> bool {
        self.peers.iter().any(|p| &p.pubkey == pubkey)
    }

    /// 授权/刷新：同公钥覆盖 mac/addr/ts；否则追加
    pub fn upsert(
        &mut self,
        mac: [u8; MAC_LEN],
        addr: [u8; ADDR_LEN],
        pubkey: [u8; PUBKEY_LEN],
        ts: i64,
    ) {
        match self.peers.iter_mut().find(|p| p.pubkey == pubkey) {
            Some(p) => {
                p.mac = mac;
                p.addr = addr;
                p.ts = ts;
            }
            None => self.peers.push(NeighborRecord {
                mac,
                addr,
                pubkey,
                ts,
            }),
        }
    }

    /// 按公钥精确移除
    pub fn remove_pubkey(&mut self, pubkey: &[u8; PUBKEY_LEN]) -> bool {
        let before = self.peers.len();
        self.peers.retain(|p| &p.pubkey != pubkey);
        self.peers.len() != before
    }

    /// 按公钥十六进前缀（至少 1 字节/2 hex 字符的等价值）移除，返回是否命中
    pub fn remove_pubkey_prefix(&mut self, prefix: &[u8]) -> bool {
        if prefix.is_empty() {
            return false;
        }
        let before = self.peers.len();
        self.peers.retain(|p| !p.pubkey.starts_with(prefix));
        self.peers.len() != before
    }

    /// 按 IPv8 地址移除
    pub fn remove_addr(&mut self, addr: &[u8; ADDR_LEN]) -> bool {
        let before = self.peers.len();
        self.peers.retain(|p| &p.addr != addr);
        self.peers.len() != before
    }

    /// 按 MAC 移除
    pub fn remove_mac(&mut self, mac: &[u8; MAC_LEN]) -> bool {
        let before = self.peers.len();
        self.peers.retain(|p| &p.mac != mac);
        self.peers.len() != before
    }

    /// 序列化为 neighbors.bin 字节
    pub fn encode_vec(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(STORE_HDR_LEN + self.peers.len() * RECORD_LEN);
        out.extend_from_slice(&STORE_MAGIC_1);
        out.extend_from_slice(&STORE_MAGIC_2);
        out.push(STORE_VERSION);
        let count = u32::try_from(self.peers.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&count.to_le_bytes());
        for p in &self.peers {
            let mut rec = [0u8; RECORD_LEN];
            rec[0..6].copy_from_slice(&p.mac);
            // 6..8 pad 保持 0
            rec[8..24].copy_from_slice(&p.addr);
            rec[24..56].copy_from_slice(&p.pubkey);
            rec[56..64].copy_from_slice(&(p.ts as u64).to_le_bytes());
            out.extend_from_slice(&rec);
        }
        out
    }

    /// 严格解析 neighbors.bin
    pub fn decode_slice(buf: &[u8]) -> Result<Self, NeighError> {
        if buf.len() < STORE_HDR_LEN {
            return Err(NeighError::StoreTooShort);
        }
        if buf[0..4] != STORE_MAGIC_1 || buf[4..8] != STORE_MAGIC_2 {
            return Err(NeighError::StoreMagic);
        }
        let ver = buf[8];
        if ver != STORE_VERSION {
            return Err(NeighError::StoreVersion(ver));
        }
        let count = u32::from_le_bytes([buf[9], buf[10], buf[11], buf[12]]) as usize;
        let expect = STORE_HDR_LEN + count * RECORD_LEN;
        if buf.len() != expect {
            return Err(NeighError::StoreLength {
                expect,
                got: buf.len(),
            });
        }
        let mut store = Self::new();
        for i in 0..count {
            let base = STORE_HDR_LEN + i * RECORD_LEN;
            let rec = &buf[base..base + RECORD_LEN];
            let mut mac = [0u8; MAC_LEN];
            mac.copy_from_slice(&rec[0..6]);
            let mut addr = [0u8; ADDR_LEN];
            addr.copy_from_slice(&rec[8..24]);
            let mut pubkey = [0u8; PUBKEY_LEN];
            pubkey.copy_from_slice(&rec[24..56]);
            let ts = i64::from_le_bytes(rec[56..64].try_into().unwrap());
            // 文件主键去重（异常重复时后者覆盖）
            store.upsert(mac, addr, pubkey, ts);
        }
        Ok(store)
    }

    /// 落盘（整文件原子性由调用方保证；此处一次性 write_all）
    pub fn save_path(&self, path: &Path) -> Result<(), NeighError> {
        let bytes = self.encode_vec();
        let mut f = File::create(path)?;
        f.write_all(&bytes)?;
        Ok(())
    }

    /// 从磁盘加载；文件不存在视为空表
    pub fn load_path(path: &Path) -> Result<Self, NeighError> {
        if !path.exists() {
            return Ok(Self::new());
        }
        let mut f = File::open(path)?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)?;
        Self::decode_slice(&buf)
    }

    /// 写入任意 writer
    pub fn write_to<W: Write>(&self, w: &mut W) -> Result<(), NeighError> {
        w.write_all(&self.encode_vec())?;
        Ok(())
    }

    /// 从任意 reader 读取
    pub fn read_from<R: Read>(r: &mut R) -> Result<Self, NeighError> {
        let mut buf = Vec::new();
        r.read_to_end(&mut buf)?;
        Self::decode_slice(&buf)
    }
}

// ── 协议状态机 ───────────────────────────────────────────────────

/// HELLO 处理决策
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelloDecision {
    /// 已授权邻居：直接回 ACK（报文附带，便于构造应答）
    AutoAck(NeighborMessage),
    /// 未知公钥：交上层弹 Y/N；同意后调 approve_consent
    NeedsConsent(NeighborMessage),
    /// 拒收（坏签名/重放/超窗/类型错）
    Reject(NeighError),
}

/// HELLO/ACK 处理状态机：验签、时间窗、nonce 防重放、待确认集合
pub struct NeighborProcessor<S: SignatureOps> {
    signer: S,
    local_addr: [u8; ADDR_LEN],
    local_pubkey: [u8; PUBKEY_LEN],
    store: NeighborStore,
    /// 对端公钥 → 最近 64 个已见 nonce（HELLO/ACK 共用同一去重环）
    seen: HashMap<[u8; PUBKEY_LEN], VecDeque<u64>>,
    /// 本端已发 HELLO 的待确认 (nonce, 发出时刻秒)
    pending: VecDeque<(u64, i64)>,
}

impl<S: SignatureOps> NeighborProcessor<S> {
    pub fn new(
        signer: S,
        local_addr: [u8; ADDR_LEN],
        local_pubkey: [u8; PUBKEY_LEN],
        store: NeighborStore,
    ) -> Self {
        Self {
            signer,
            local_addr,
            local_pubkey,
            store,
            seen: HashMap::new(),
            pending: VecDeque::new(),
        }
    }

    pub fn store(&self) -> &NeighborStore {
        &self.store
    }

    pub fn store_mut(&mut self) -> &mut NeighborStore {
        &mut self.store
    }

    pub fn local_addr(&self) -> &[u8; ADDR_LEN] {
        &self.local_addr
    }

    pub fn local_pubkey(&self) -> &[u8; PUBKEY_LEN] {
        &self.local_pubkey
    }

    /// 登记本端发出的 HELLO nonce（ACK 回来时据此自动入表）
    pub fn record_hello_sent(&mut self, nonce: u64, now: i64) {
        self.prune_pending(now);
        if self.pending.len() >= PENDING_MAX {
            self.pending.pop_front();
        }
        self.pending.push_back((nonce, now));
    }

    fn prune_pending(&mut self, now: i64) {
        self.pending
            .retain(|(_, ts)| now.saturating_sub(*ts) <= PENDING_TTL_SECS);
    }

    /// 构造签名 HELLO/ACK
    pub fn build_message(&self, msg_type: u8, nonce: u64, now: i64) -> [u8; MSG_LEN] {
        build_signed(
            &self.signer,
            msg_type,
            &self.local_addr,
            now,
            nonce,
            &self.local_pubkey,
        )
    }

    /// 构造广播 HELLO（同时登记待确认 nonce）
    pub fn build_hello(&mut self, nonce: u64, now: i64) -> [u8; MSG_LEN] {
        self.record_hello_sent(nonce, now);
        self.build_message(MSG_HELLO, nonce, now)
    }

    /// 构造回给指定 HELLO 的单播 ACK（回显其 nonce）
    pub fn build_ack(&self, hello: &NeighborMessage, now: i64) -> [u8; MSG_LEN] {
        self.build_message(MSG_ACK, hello.nonce, now)
    }

    /// 公共校验：解码/类型/签名/时间窗/nonce 去重
    fn verify_frame(
        &mut self,
        frame: &[u8],
        expect_type: u8,
        now: i64,
    ) -> Result<NeighborMessage, NeighError> {
        let msg = decode(frame)?;
        if msg.msg_type != expect_type {
            return Err(NeighError::UnexpectedType(msg.msg_type));
        }
        if !self
            .signer
            .verify(&msg.pubkey, &frame[..SIGNED_LEN], &msg.sig)
        {
            return Err(NeighError::BadSignature);
        }
        let delta = msg.ts_secs.saturating_sub(now).abs();
        if delta > TS_WINDOW_SECS {
            return Err(NeighError::TimestampOutOfWindow {
                msg: msg.ts_secs,
                now,
            });
        }
        let ring = self
            .seen
            .entry(msg.pubkey)
            .or_insert_with(|| VecDeque::with_capacity(NONCE_RING));
        if ring.contains(&msg.nonce) {
            return Err(NeighError::Replay(msg.nonce));
        }
        if ring.len() >= NONCE_RING {
            ring.pop_front();
        }
        ring.push_back(msg.nonce);
        Ok(msg)
    }

    /// 处理收到的 HELLO。
    /// - 已授权公钥 → AutoAck（刷新邻居表）
    /// - 未知公钥 → NeedsConsent（上层 Y/N；同意调 approve_consent）
    /// - 坏签名/重放/超窗 → Reject
    pub fn process_hello(
        &mut self,
        frame: &[u8],
        src_mac: [u8; MAC_LEN],
        now: i64,
    ) -> HelloDecision {
        let msg = match self.verify_frame(frame, MSG_HELLO, now) {
            Ok(m) => m,
            Err(e) => return HelloDecision::Reject(e),
        };
        if self.store.contains(&msg.pubkey) {
            self.store
                .upsert(src_mac, msg.addr, msg.pubkey, now);
            HelloDecision::AutoAck(msg)
        } else {
            HelloDecision::NeedsConsent(msg)
        }
    }

    /// 人工同意后调用：授权入表（公钥主键，刷新 mac/addr/ts）
    pub fn approve_consent(
        &mut self,
        hello: &NeighborMessage,
        src_mac: [u8; MAC_LEN],
        now: i64,
    ) {
        self.store
            .upsert(src_mac, hello.addr, hello.pubkey, now);
    }

    /// 处理收到的 ACK：验签/窗口/去重后，nonce 必须在本端 30s 待确认集合；
    /// 命中即把对端永久入表（公钥主键刷新），待确认条目一次性消费。
    pub fn process_ack(
        &mut self,
        frame: &[u8],
        src_mac: [u8; MAC_LEN],
        now: i64,
    ) -> Result<NeighborRecord, NeighError> {
        let msg = self.verify_frame(frame, MSG_ACK, now)?;
        self.prune_pending(now);
        let pos = self
            .pending
            .iter()
            .position(|(n, _)| *n == msg.nonce)
            .ok_or(NeighError::AckNonceMismatch(msg.nonce))?;
        self.pending.remove(pos);
        self.store
            .upsert(src_mac, msg.addr, msg.pubkey, now);
        Ok(NeighborRecord {
            mac: src_mac,
            addr: msg.addr,
            pubkey: msg.pubkey,
            ts: now,
        })
    }
}

// ── 传输层抽象（P8：让 neigh 库脱离 UDP 硬编码，可跑在 L2/UDP 自动切换）──────

/// 以太网 MAC 地址（6 字节）
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    pub const BROADCAST: MacAddr = MacAddr([0xFF; 6]);
    pub const ZERO: MacAddr = MacAddr([0; 6]);

    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(":")
    }

    pub fn parse(s: &str) -> Result<Self, NeighError> {
        let bytes: Vec<&str> = s.split(':').collect();
        if bytes.len() != 6 {
            return Err(NeighError::Transport(format!(
                "MAC 格式应为 aa:bb:cc:dd:ee:ff，got: {s}"
            )));
        }
        let mut mac = [0u8; 6];
        for (i, b) in bytes.iter().enumerate() {
            mac[i] = u8::from_str_radix(b, 16).map_err(|_| {
                NeighError::Transport(format!("MAC 第 {i} 段无效: {b}"))
            })?;
        }
        Ok(MacAddr(mac))
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// 传输层错误
#[derive(Debug)]
pub enum TransportError {
    Io(String),
    Driver(String),
    Parse(String),
    Timeout,
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::Io(e) => write!(f, "IO 错误: {e}"),
            TransportError::Driver(e) => write!(f, "驱动错误: {e}"),
            TransportError::Parse(e) => write!(f, "解析错误: {e}"),
            TransportError::Timeout => write!(f, "超时"),
        }
    }
}

/// 邻居发现传输层抽象
///
/// 同一份 IP8N 状态机可跑在 UDP 45802 或 L2 0xFB14，auto 模式自动选择。
pub trait NeighborTransport: Send {
    /// 收一个 IP8N 报文（阻塞），返回 (报文字节, 源 MAC)
    fn recv(&mut self) -> Result<(Vec<u8>, MacAddr), TransportError>;

    /// 发一个 IP8N 报文，dst=BROADCAST 为广播，否则单播
    fn send(&mut self, pkt: &[u8], dst: MacAddr) -> Result<(), TransportError>;

    /// 本机 MAC 地址
    fn local_mac(&self) -> MacAddr;

    /// 传输层名称（"l2" / "udp"），用于日志
    fn name(&self) -> &'static str;

    /// 关闭底层连接（可选，默认空实现）
    fn close(&mut self) {}
}

// ── 测试（含确定性 mock 签名，crate 本身零依赖）─────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// 确定性 mock Ed25519：无安全性，但对 domain/pubkey 单比特翻转敏感，
    /// 足以驱动验签/状态机测试。签名可仅由公钥验证（mock 无私钥运算）。
    #[derive(Clone)]
    struct MockSigner {
        sk: [u8; 32],
    }

    impl MockSigner {
        fn new(seed: u8) -> Self {
            let mut sk = [0u8; 32];
            for (i, b) in sk.iter_mut().enumerate() {
                *b = seed.wrapping_add((i as u8).wrapping_mul(31)).rotate_left(1);
            }
            Self { sk }
        }
        fn pubkey(&self) -> [u8; 32] {
            let mut p = [0u8; 32];
            for (i, b) in p.iter_mut().enumerate() {
                *b = self.sk[i].rotate_left(3) ^ self.sk[(i + 17) % 32] ^ 0x5A;
            }
            p
        }
    }

    fn mock_mix(pk: &[u8; 32], domain: &[u8]) -> [u8; 64] {
        // round 1：domain 每字节按公钥派生系数累加进 64B 状态
        let mut s = [0u8; 64];
        for (i, &b) in domain.iter().enumerate() {
            let k = pk[(i.wrapping_mul(7)) % 32] | 1;
            let slot = i % 64;
            s[slot] = s[slot].wrapping_add(b.wrapping_mul(k));
        }
        // round 2：槽间混合，保证单比特变化扩散且依赖全部公钥字节
        let mut out = [0u8; 64];
        for j in 0..64 {
            out[j] = s[j]
                .rotate_left(3)
                ^ s[(j + 29) % 64]
                ^ pk[j % 32]
                ^ pk[(j * 3 + 5) % 32];
        }
        out
    }

    impl SignatureOps for MockSigner {
        fn sign(&self, domain: &[u8]) -> [u8; 64] {
            mock_mix(&self.pubkey(), domain)
        }
        fn verify(
            &self,
            pubkey: &[u8; 32],
            domain: &[u8],
            sig: &[u8; 64],
        ) -> bool {
            &mock_mix(pubkey, domain) == sig
        }
    }

    fn addr_of(seed: u8) -> [u8; 16] {
        let mut a = [0u8; 16];
        a[0] = 0x80;
        a[15] = seed;
        a
    }

    fn make_node(seed: u8) -> (MockSigner, [u8; 16], [u8; 32]) {
        let s = MockSigner::new(seed);
        (s.clone(), addr_of(seed), s.pubkey())
    }

    const T0: i64 = 1_700_000_000;
    const MAC_A: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    const MAC_B: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];

    // 1
    #[test]
    fn hello_roundtrip_encode_decode() {
        let (s, addr, pk) = make_node(1);
        let frame = build_signed(&s, MSG_HELLO, &addr, T0, 0x1122_3344_5566_7788, &pk);
        assert_eq!(frame.len(), MSG_LEN);
        assert_eq!(&frame[0..4], b"IP8N");
        let m = decode(&frame).unwrap();
        assert_eq!(m.msg_type, MSG_HELLO);
        assert_eq!(m.flags, 0);
        assert_eq!(m.addr, addr);
        assert_eq!(m.ts_secs, T0);
        assert_eq!(m.nonce, 0x1122_3344_5566_7788);
        assert_eq!(m.pubkey, pk);
        assert_eq!(m.sig, frame[72..136]);
        assert_eq!(m.encode(), frame);
    }

    // 2
    #[test]
    fn rejects_truncated_and_oversized() {
        let (s, addr, pk) = make_node(2);
        let frame = build_signed(&s, MSG_HELLO, &addr, T0, 1, &pk);
        assert!(matches!(
            decode(&frame[..135]),
            Err(NeighError::BadLength { expect: MSG_LEN, got: 135 })
        ));
        let mut long = frame.to_vec();
        long.push(0);
        assert!(matches!(
            decode(&long),
            Err(NeighError::BadLength { expect: MSG_LEN, got: 137 })
        ));
        assert!(matches!(decode(&[]), Err(NeighError::BadLength { .. })));
    }

    // 3
    #[test]
    fn rejects_bad_magic() {
        let (s, addr, pk) = make_node(3);
        let mut frame = build_signed(&s, MSG_HELLO, &addr, T0, 1, &pk);
        frame[0] ^= 0x01;
        assert!(matches!(decode(&frame), Err(NeighError::BadMagic)));
    }

    // 4
    #[test]
    fn rejects_bad_version() {
        let (s, addr, pk) = make_node(4);
        let mut frame = build_signed(&s, MSG_HELLO, &addr, T0, 1, &pk);
        frame[4] = 9;
        assert!(matches!(decode(&frame), Err(NeighError::BadVersion(9))));
    }

    // 5
    #[test]
    fn rejects_unknown_type_and_flags() {
        let (s, addr, pk) = make_node(5);
        let frame = build_signed(&s, 99, &addr, T0, 1, &pk);
        assert!(matches!(decode(&frame), Err(NeighError::UnknownType(99))));
        let mut frame2 = build_signed(&s, MSG_HELLO, &addr, T0, 1, &pk);
        frame2[7] = 1;
        assert!(matches!(decode(&frame2), Err(NeighError::BadFlags(1))));
    }

    // 6
    #[test]
    fn valid_hello_is_needs_consent_for_unknown() {
        let (sa, addra, pka) = make_node(0x10);
        let (sb, addrb, pkb) = make_node(0x20);
        let mut a = NeighborProcessor::new(sa, addra, pka, NeighborStore::new());
        let hello_b = build_signed(&sb, MSG_HELLO, &addrb, T0, 1234, &pkb);
        match a.process_hello(&hello_b, MAC_B, T0) {
            HelloDecision::NeedsConsent(m) => {
                assert_eq!(m.pubkey, pkb);
                assert_eq!(m.nonce, 1234);
            }
            other => panic!("期望 NeedsConsent，实际 {other:?}"),
        }
    }

    // 7
    #[test]
    fn rejects_bad_signature_field() {
        let (sa, addra, _) = make_node(0x10);
        let (sb, addrb, pkb) = make_node(0x21);
        let mut a = NeighborProcessor::new(sa, addra, {
            let mut p = [0u8; 32];
            p[0] = 0xAA;
            p
        }, NeighborStore::new());
        let mut hello = build_signed(&sb, MSG_HELLO, &addrb, T0, 1, &pkb);
        hello[100] ^= 0x01; // 翻转签名字节
        assert!(matches!(
            a.process_hello(&hello, MAC_B, T0),
            HelloDecision::Reject(NeighError::BadSignature)
        ));
    }

    // 8
    #[test]
    fn rejects_tampered_signed_domain() {
        let (sa, addra, pka) = make_node(0x10);
        let (sb, addrb, pkb) = make_node(0x22);
        let mut a = NeighborProcessor::new(sa, addra, pka, NeighborStore::new());
        let mut hello = build_signed(&sb, MSG_HELLO, &addrb, T0, 7, &pkb);
        hello[20] ^= 0x01; // 翻转 addr 中 1 位（在签名域前 72B 内）
        assert!(matches!(
            a.process_hello(&hello, MAC_B, T0),
            HelloDecision::Reject(NeighError::BadSignature)
        ));
    }

    // 9
    #[test]
    fn rejects_wrong_pubkey_verification() {
        let (sa, addra, pka) = make_node(0x10);
        let (sb, addrb, _) = make_node(0x23);
        // B 用自己的公钥签名，但报文里塞 C 的公钥
        let pk_c = MockSigner::new(0x99).pubkey();
        let mut a = NeighborProcessor::new(sa, addra, pka, NeighborStore::new());
        let hello = build_signed(&sb, MSG_HELLO, &addrb, T0, 1, &pk_c);
        assert!(matches!(
            a.process_hello(&hello, MAC_B, T0),
            HelloDecision::Reject(NeighError::BadSignature)
        ));
    }

    // 10
    #[test]
    fn rejects_timestamp_out_of_window() {
        let (sa, addra, pka) = make_node(0x10);
        let (sb, addrb, pkb) = make_node(0x24);
        let mut a = NeighborProcessor::new(sa, addra, pka, NeighborStore::new());
        let old = build_signed(&sb, MSG_HELLO, &addrb, T0 - 301, 1, &pkb);
        assert!(matches!(
            a.process_hello(&old, MAC_B, T0),
            HelloDecision::Reject(NeighError::TimestampOutOfWindow { .. })
        ));
        let future = build_signed(&sb, MSG_HELLO, &addrb, T0 + 301, 2, &pkb);
        assert!(matches!(
            a.process_hello(&future, MAC_B, T0),
            HelloDecision::Reject(NeighError::TimestampOutOfWindow { .. })
        ));
    }

    // 11
    #[test]
    fn timestamp_boundary_accepted() {
        let (sa, addra, pka) = make_node(0x10);
        let (sb, addrb, pkb) = make_node(0x25);
        let mut a = NeighborProcessor::new(sa, addra, pka, NeighborStore::new());
        let h1 = build_signed(&sb, MSG_HELLO, &addrb, T0 - 300, 1, &pkb);
        assert!(matches!(
            a.process_hello(&h1, MAC_B, T0),
            HelloDecision::NeedsConsent(_)
        ));
        let h2 = build_signed(&sb, MSG_HELLO, &addrb, T0 + 300, 2, &pkb);
        assert!(matches!(
            a.process_hello(&h2, MAC_B, T0),
            HelloDecision::NeedsConsent(_)
        ));
    }

    // 12
    #[test]
    fn rejects_replayed_nonce() {
        let (sa, addra, pka) = make_node(0x10);
        let (sb, addrb, pkb) = make_node(0x26);
        let mut a = NeighborProcessor::new(sa, addra, pka, NeighborStore::new());
        let h = build_signed(&sb, MSG_HELLO, &addrb, T0, 55, &pkb);
        assert!(matches!(
            a.process_hello(&h, MAC_B, T0),
            HelloDecision::NeedsConsent(_)
        ));
        // 完全相同的第二帧（同 nonce）→ 重放
        assert!(matches!(
            a.process_hello(&h, MAC_B, T0),
            HelloDecision::Reject(NeighError::Replay(55))
        ));
    }

    // 13
    #[test]
    fn nonce_ring_keeps_exactly_64() {
        let (sa, addra, pka) = make_node(0x10);
        let (sb, addrb, pkb) = make_node(0x27);
        let mut a = NeighborProcessor::new(sa, addra, pka, NeighborStore::new());
        // 64 个不同 nonce 占满环
        for n in 1..=64u64 {
            let h = build_signed(&sb, MSG_HELLO, &addrb, T0, n, &pkb);
            assert!(matches!(
                a.process_hello(&h, MAC_B, T0),
                HelloDecision::NeedsConsent(_)
            ));
        }
        // 第 65 个把 nonce=1 挤出环（环内现为 2..=65）
        let h65 = build_signed(&sb, MSG_HELLO, &addrb, T0, 65, &pkb);
        assert!(matches!(
            a.process_hello(&h65, MAC_B, T0),
            HelloDecision::NeedsConsent(_)
        ));
        // nonce=2 仍在环内 → 重放（先验，避免后续帧再挤出它）
        let h2 = build_signed(&sb, MSG_HELLO, &addrb, T0, 2, &pkb);
        assert!(matches!(
            a.process_hello(&h2, MAC_B, T0),
            HelloDecision::Reject(NeighError::Replay(2))
        ));
        // nonce=1 已被挤出 → 不再识别为重放
        let h1_again = build_signed(&sb, MSG_HELLO, &addrb, T0, 1, &pkb);
        assert!(matches!(
            a.process_hello(&h1_again, MAC_B, T0),
            HelloDecision::NeedsConsent(_)
        ));
    }

    // 14
    #[test]
    fn known_neighbor_gets_auto_ack_and_refresh() {
        let (sa, addra, pka) = make_node(0x10);
        let (sb, addrb, pkb) = make_node(0x28);
        let mut store = NeighborStore::new();
        store.upsert(MAC_B, addrb, pkb, T0 - 10);
        let mut a = NeighborProcessor::new(sa, addra, pka, store);
        let h = build_signed(&sb, MSG_HELLO, &addrb, T0, 900, &pkb);
        match a.process_hello(&h, MAC_B, T0) {
            HelloDecision::AutoAck(m) => {
                assert_eq!(m.pubkey, pkb);
                // ACK 回显 nonce
                let ack = a.build_ack(&m, T0);
                let am = decode(&ack).unwrap();
                assert_eq!(am.msg_type, MSG_ACK);
                assert_eq!(am.nonce, 900);
            }
            other => panic!("期望 AutoAck，实际 {other:?}"),
        }
        assert_eq!(a.store().iter().next().unwrap().ts, T0);
    }

    // 15
    #[test]
    fn consent_then_ack_full_handshake() {
        let (sa, addra, pka) = make_node(0x10);
        let (sb, addrb, pkb) = make_node(0x29);
        // B 被动方：收到 A 的 HELLO，授权后回 ACK
        let mut store_b = NeighborProcessor::new(sb.clone(), addrb, pkb, NeighborStore::new());
        // A 主动方：发 HELLO（登记 pending nonce）
        let mut node_a = NeighborProcessor::new(sa.clone(), addra, pka, NeighborStore::new());
        let nonce = 0xABCD;
        let hello_a = node_a.build_hello(nonce, T0);

        // B 收到 → NeedsConsent → 人工同意 → 入表 + 回 ACK
        match store_b.process_hello(&hello_a, MAC_A, T0) {
            HelloDecision::NeedsConsent(m) => {
                store_b.approve_consent(&m, MAC_A, T0);
                let ack = store_b.build_ack(&m, T0);
                // A 收到 ACK → 自动入表
                let rec = node_a.process_ack(&ack, MAC_B, T0).unwrap();
                assert_eq!(rec.pubkey, pkb);
                assert_eq!(rec.mac, MAC_B);
            }
            other => panic!("期望 NeedsConsent，实际 {other:?}"),
        }
        assert!(node_a.store().contains(&pkb));
        assert!(store_b.store().contains(&pka));
    }

    // 16
    #[test]
    fn ack_with_unknown_nonce_rejected() {
        let (sa, addra, pka) = make_node(0x10);
        let (sb, addrb, pkb) = make_node(0x30);
        let mut a = NeighborProcessor::new(sa, addra, pka, NeighborStore::new());
        // A 从未发过 nonce=42 的 HELLO
        let ack = build_signed(&sb, MSG_ACK, &addrb, T0, 42, &pkb);
        assert!(matches!(
            a.process_ack(&ack, MAC_B, T0),
            Err(NeighError::AckNonceMismatch(42))
        ));
        assert!(!a.store().contains(&pkb));
    }

    // 17
    #[test]
    fn ack_pending_expires_after_30s() {
        // 30s 边界仍有效
        let (sa, addra, pka) = make_node(0x10);
        let (sb, addrb, pkb) = make_node(0x31);
        let mut a = NeighborProcessor::new(sa, addra, pka, NeighborStore::new());
        let _ = a.build_hello(77, T0);
        let ack30 = build_signed(&sb, MSG_ACK, &addrb, T0 + 30, 77, &pkb);
        assert!(a.process_ack(&ack30, MAC_B, T0 + 30).is_ok());

        // 31s 后 pending 过期 → 失配拒（换一对新身份避免 nonce 环干扰）
        let (sd, addrd, pkd) = make_node(0x40);
        let (se, addre, pke) = make_node(0x41);
        let mut d = NeighborProcessor::new(sd, addrd, pkd, NeighborStore::new());
        let _ = d.build_hello(79, T0);
        let ack_late = build_signed(&se, MSG_ACK, &addre, T0 + 31, 79, &pke);
        assert!(matches!(
            d.process_ack(&ack_late, MAC_B, T0 + 31),
            Err(NeighError::AckNonceMismatch(79))
        ));
        assert!(!d.store().contains(&pke));
    }

    // 18
    #[test]
    fn duplicate_ack_consumed_once() {
        let (sa, addra, pka) = make_node(0x10);
        let (sb, addrb, pkb) = make_node(0x33);
        let mut a = NeighborProcessor::new(sa, addra, pka, NeighborStore::new());
        let _ = a.build_hello(5, T0);
        let ack = build_signed(&sb, MSG_ACK, &addrb, T0, 5, &pkb);
        assert!(a.process_ack(&ack, MAC_B, T0).is_ok());
        // 第二次：pending 已消费（同时 nonce 环也已记录）
        assert!(a.process_ack(&ack, MAC_B, T0).is_err());
    }

    // 19
    #[test]
    fn store_save_load_roundtrip() {
        let mut st = NeighborStore::new();
        st.upsert([1; 6], [2; 16], [3; 32], T0);
        st.upsert([4; 6], [5; 16], [6; 32], T0 + 9);
        let bytes = st.encode_vec();
        assert_eq!(bytes.len(), STORE_HDR_LEN + 2 * RECORD_LEN);
        assert_eq!(&bytes[0..8], b"IP8NNBHR");
        assert_eq!(bytes[8], STORE_VERSION);
        assert_eq!(u32::from_le_bytes(bytes[9..13].try_into().unwrap()), 2);
        let back = NeighborStore::decode_slice(&bytes).unwrap();
        assert_eq!(back.len(), 2);
        let v: Vec<_> = back.iter().cloned().collect();
        assert_eq!(v[0], NeighborRecord {
            mac: [1; 6],
            addr: [2; 16],
            pubkey: [3; 32],
            ts: T0
        });
        assert_eq!(v[1].ts, T0 + 9);
    }

    // 20
    #[test]
    fn store_upsert_same_pubkey_refreshes() {
        let mut st = NeighborStore::new();
        st.upsert([1; 6], [2; 16], [9; 32], 100);
        st.upsert([7; 6], [8; 16], [9; 32], 200);
        assert_eq!(st.len(), 1);
        let p = st.iter().next().unwrap();
        assert_eq!(p.mac, [7; 6]);
        assert_eq!(p.addr, [8; 16]);
        assert_eq!(p.ts, 200);
    }

    // 21
    #[test]
    fn store_remove_by_all_keys() {
        let mut st = NeighborStore::new();
        st.upsert([1; 6], [2; 16], [3; 32], 1);
        st.upsert([4; 6], [5; 16], [6; 32], 2);
        assert!(st.remove_pubkey(&[3; 32]));
        assert!(!st.remove_pubkey(&[3; 32]));
        assert!(st.remove_addr(&[5; 16]));
        assert!(st.is_empty());

        st.upsert([0xAA; 6], [0xBB; 16], [0xCC; 32], 3);
        assert!(!st.remove_pubkey_prefix(&[0xCB]));
        assert!(st.remove_pubkey_prefix(&[0xCC]));
        assert!(!st.remove_pubkey_prefix(&[]));

        st.upsert([0x11; 6], [0x22; 16], [0x33; 32], 4);
        assert!(st.remove_mac(&[0x11; 6]));
        assert!(st.is_empty());
    }

    // 22
    #[test]
    fn store_rejects_bad_file() {
        assert!(matches!(
            NeighborStore::decode_slice(&[0u8; 4]),
            Err(NeighError::StoreTooShort)
        ));
        let mut bad = vec![0u8; STORE_HDR_LEN];
        bad[0..4].copy_from_slice(b"XXXX");
        bad[4..8].copy_from_slice(b"NBHR");
        assert!(matches!(
            NeighborStore::decode_slice(&bad),
            Err(NeighError::StoreMagic)
        ));
        let mut badver = vec![0u8; STORE_HDR_LEN];
        badver[0..4].copy_from_slice(b"IP8N");
        badver[4..8].copy_from_slice(b"NBHR");
        badver[8] = 9;
        assert!(matches!(
            NeighborStore::decode_slice(&badver),
            Err(NeighError::StoreVersion(9))
        ));
        let mut badlen = vec![0u8; STORE_HDR_LEN];
        badlen[0..4].copy_from_slice(b"IP8N");
        badlen[4..8].copy_from_slice(b"NBHR");
        badlen[8] = 1;
        badlen[9..13].copy_from_slice(&1u32.to_le_bytes());
        // count=1 但没有 64B 记录体
        assert!(matches!(
            NeighborStore::decode_slice(&badlen),
            Err(NeighError::StoreLength { expect: 77, got: 13 })
        ));
    }

    // 23
    #[test]
    fn classifies_neighbor_vs_ipv8_vs_other() {
        let (s, addr, pk) = make_node(0x55);
        let hello = build_signed(&s, MSG_HELLO, &addr, T0, 1, &pk);
        assert_eq!(classify(&hello), PayloadKind::Neighbor);
        assert!(is_neighbor_payload(&hello));
        // IPv8 数据包：首字节高 4 位 0x8
        assert_eq!(classify(&[0x80, 1, 2, 3, 4]), PayloadKind::Ipv8);
        assert_eq!(classify(&[0x8F]), PayloadKind::Ipv8);
        // l2 ping 文本帧
        assert_eq!(classify(b"IPV8-L2-PING"), PayloadKind::Other);
        // IP8N 魔数但长度不是 136 → 其它（不冒充邻居报文）
        assert_eq!(classify(b"IP8NXX"), PayloadKind::Other);
        assert_eq!(classify(&[]), PayloadKind::Other);
    }
}
