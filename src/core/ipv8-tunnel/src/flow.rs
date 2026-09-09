//! 流级分片数据面（ADR-024 用户态性能线：多核扩展）。
//!
//! 背景：Phase 5 实测单线程引擎是吞吐瓶颈（AES 后 7.5 Gbps/核）。本模块把
//! **Data 面**拆成 N 个互不共享密钥状态的 worker 线程；握手/降级等控制面
//! 仍归原 [`Engine`]（其单点数据面经 [`Engine::split_shards`] 移交后冻结）。
//!
//! 分片正确性的两根支柱（均在 [`crate::crypto::TunnelKeys`] 层实现）：
//! - **发送侧**：内层 IP 五元组哈希 → 分片 k → 该流全部帧由 k 的 SA 封装。
//!   同流同 worker → 计数器严格递增 → nonce 唯一，无需跨线程协调。
//! - **接收侧**：分片 k 的 SA 轮换步幅 = N（epoch ≡ k mod N），因此帧头
//!   KeyID 的 epoch 同余类**免解密**即可路由到对应 worker；跨片帧直接
//!   `ShardMismatch` 拒收，绝不串片解密。
//!
//! 限制（与单点 Engine 的差异，接入方必须知晓）：
//! - 仅端点投递语义（decode → 分片重组 → delivered）。**多跳转发**（fwd /
//!   RouteTrace 链）不走本路径，需要转发的节点保持单 Engine。
//! - 两端 (N, 套件) 必须人工一致（同 ADR-025 部署配置哲学）；不一致表现为
//!   跨片拒收 + dropped 计数，可诊断。
//! - 帧到达顺序不再全局单调（各片独立计数器）：IPv8+ 分片组按 frag 同余类
//!   路由，组内仍同源同序；重组器容忍乱序不受影响。

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use ipv8_codec::{
    decode as decode_ipv8, flags, fragment_packet, encode, IPv8Address, IPv8Header, Reassembler,
};

use crate::crypto::TunnelKeys;
use crate::engine::EngineError;
use crate::encapsulate::{decapsulate, encapsulate};
use crate::frame::{parse_head, FrameType};

/// 出站投递目标（隧道帧 → 交 UDP）；入站投递目标（内层 IP 包 → 交 TUN）。
/// 均要求可跨线程共享（worker 各持一份克隆）。
pub type Sink = Arc<dyn Fn(Vec<u8>) + Send + Sync + 'static>;

/// 分片数据面聚合计数（跨 worker 原子累加，单调不减）
#[derive(Debug, Default)]
pub struct ShardCounters {
    pub sealed: AtomicU64,
    pub delivered: AtomicU64,
    pub dropped: AtomicU64,
    pub fragments_sent: AtomicU64,
    pub fragments_reassembled: AtomicU64,
}

/// 计数快照
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ShardStats {
    pub sealed: u64,
    pub delivered: u64,
    pub dropped: u64,
    pub fragments_sent: u64,
    pub fragments_reassembled: u64,
}

enum Task {
    /// 发送：内层 IP 包 → 本片 SA 封装（含 MTU 分片）→ frames sink
    Seal(Vec<u8>),
    /// 接收：已按同余类路由到本片的完整隧道帧 → 拆壳交付
    Data(Vec<u8>),
    Shutdown,
}

/// 一个隧道 Data 面的 N-worker 分片器。方法均为非阻塞投递（channel send）。
pub struct FlowShards {
    n: usize,
    tx: Vec<Sender<Task>>,
    handles: Mutex<Vec<JoinHandle<()>>>,
    counters: Arc<ShardCounters>,
    ok: Arc<AtomicBool>,
}

impl FlowShards {
    /// 显式指定 sink 的构造（生产路径；node 用它把帧引向 UDP socket / TUN）。
    /// 分片 SA 通常来自 [`Engine::split_shards`]；地址/MTU 一并按引擎配置传入。
    pub fn new(
        shards: Vec<TunnelKeys>,
        local_addr: IPv8Address,
        peer_addr: IPv8Address,
        mtu: usize,
        frames: Sink,
        delivered: Sink,
    ) -> Self {
        assert!(!shards.is_empty(), "至少一个分片");
        let n = shards.len();
        let counters = Arc::new(ShardCounters::default());
        let ok = Arc::new(AtomicBool::new(true));
        let mut tx = Vec::with_capacity(n);
        let mut handles = Vec::with_capacity(n);
        for keys in shards.into_iter() {
            let (s, r) = channel::<Task>();
            tx.push(s);
            let (counters, ok, frames, delivered) =
                (counters.clone(), ok.clone(), frames.clone(), delivered.clone());
            let h = thread::Builder::new()
                .name(format!("ipv8-shard-{}", keys.shard()))
                .spawn(move || {
                    worker_loop(
                        WorkerCtx { keys, local_addr, peer_addr, mtu, frames, delivered, counters, ok },
                        r,
                    )
                })
                .expect("spawn shard worker");
            handles.push(h);
        }
        Self { n, tx, handles: Mutex::new(handles), counters, ok }
    }

    /// 分片数
    pub fn len(&self) -> usize {
        self.n
    }

    /// FlowShards 恒非空（构造校验过）；clippy 要求配对提供 is_empty
    pub fn is_empty(&self) -> bool {
        false
    }

    /// 出站：按五元组哈希选择分片投递封装任务。
    pub fn seal_dispatch(&self, inner_ip: &[u8]) -> Result<(), EngineError> {
        if !self.ok.load(Ordering::Relaxed) {
            return Err(EngineError::NotEstablished);
        }
        let k = (hash_flow(inner_ip) as usize) % self.n;
        self.tx[k]
            .send(Task::Seal(inner_ip.to_vec()))
            .map_err(|_| EngineError::NotEstablished)
    }

    /// 入站：解析 Data 帧的 epoch 同余类路由到对应分片。非 Data 帧或
    /// 解析失败返回 false（调用方交控制面处理/丢弃计数）。
    pub fn handle_inbound(&self, frame: &[u8]) -> bool {
        if !self.ok.load(Ordering::Relaxed) {
            return false;
        }
        let head = match parse_head(frame) {
            Ok(h) => h,
            Err(_) => return false,
        };
        if head.frame_type != FrameType::Data {
            return false;
        }
        // epoch 低 56 位在 key_id[1..8]（suite 字节不参与同余路由）
        let mut e = [0u8; 8];
        e[1..].copy_from_slice(&head.key_id[1..]);
        let epoch = u64::from_be_bytes(e);
        let k = (epoch % self.n as u64) as usize;
        if self.tx[k].send(Task::Data(frame.to_vec())).is_err() {
            self.counters.dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        true
    }

    /// 计数快照
    pub fn stats(&self) -> ShardStats {
        ShardStats {
            sealed: self.counters.sealed.load(Ordering::Relaxed),
            delivered: self.counters.delivered.load(Ordering::Relaxed),
            dropped: self.counters.dropped.load(Ordering::Relaxed),
            fragments_sent: self.counters.fragments_sent.load(Ordering::Relaxed),
            fragments_reassembled: self.counters.fragments_reassembled.load(Ordering::Relaxed),
        }
    }

    /// 关停全部 worker 并 join（幂等）。
    pub fn shutdown(&self) {
        if !self.ok.swap(false, Ordering::SeqCst) {
            return;
        }
        for s in &self.tx {
            let _ = s.send(Task::Shutdown);
        }
        let mut handles = self.handles.lock().expect("shard handles");
        for h in handles.drain(..) {
            let _ = h.join();
        }
    }
}

impl Drop for FlowShards {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// worker 线程的完整上下文（一次构造、move 进线程）
struct WorkerCtx {
    keys: TunnelKeys,
    local_addr: IPv8Address,
    peer_addr: IPv8Address,
    mtu: usize,
    frames: Sink,
    delivered: Sink,
    counters: Arc<ShardCounters>,
    ok: Arc<AtomicBool>,
}

fn worker_loop(ctx: WorkerCtx, rx: Receiver<Task>) {
    let WorkerCtx { mut keys, local_addr, peer_addr, mtu, frames, delivered, counters, ok } = ctx;
    let mut reasm = Reassembler::new();
    let mut frag_id: u32 = keys.shard() as u32; // 各片 ID 空间以片号起跳，避免混组歧义
    loop {
        let first = match rx.recv() {
            Ok(t) => t,
            Err(_) => return, // sender 全部释放（FlowShards drop）
        };
        // 批量排空：摊薄唤醒成本（对齐 node TUN 批处理策略，上限 64）
        let mut batch = Vec::with_capacity(32);
        batch.push(first);
        while let Ok(t) = rx.try_recv() {
            batch.push(t);
            if batch.len() >= 64 {
                break;
            }
        }
        for t in batch {
            match t {
                Task::Shutdown => return,
                Task::Seal(inner) => {
                    if !ok.load(Ordering::Relaxed) {
                        continue;
                    }
                    let hdr = IPv8Header::new(local_addr, peer_addr, inner.len() as u16);
                    let whole = match encode(&hdr, &inner) {
                        Ok(w) => w,
                        Err(_) => {
                            counters.dropped.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                    };
                    let pkts = match fragment_packet(&whole, mtu, frag_id) {
                        Ok(p) => p,
                        Err(_) => {
                            counters.dropped.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                    };
                    frag_id = frag_id.wrapping_add(1);
                    let n = pkts.len() as u64;
                    let mut failed = false;
                    for p in &pkts {
                        match encapsulate(&mut keys, p) {
                            Ok(f) => (frames)(f),
                            Err(_) => {
                                failed = true;
                                break;
                            }
                        }
                    }
                    if failed {
                        counters.dropped.fetch_add(1, Ordering::Relaxed);
                    } else {
                        counters.sealed.fetch_add(n, Ordering::Relaxed);
                        counters.fragments_sent.fetch_add(n.saturating_sub(1), Ordering::Relaxed);
                    }
                }
                Task::Data(frame) => {
                    let pkt = match decapsulate(&mut keys, &frame) {
                        Ok(p) => p,
                        Err(_) => {
                            counters.dropped.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                    };
                    match decode_ipv8(&pkt) {
                        Ok(d) => {
                            // 端点语义与 Engine 对齐：多跳包（链首 RouteTrace）在
                            // 未启用转发的路径上一律拒收——分片 worker 无 PathSig
                            // 验签能力，绝不"看似到达"地交付未验多跳载荷。
                            let multihop =
                                d.header.next_header == ipv8_codec::ExtType::RouteTrace.wire();
                            if multihop {
                                counters.dropped.fetch_add(1, Ordering::Relaxed);
                                continue;
                            }
                            if d.header.flags & flags::FRAGMENT != 0 {
                                match reasm.insert(&d.header, d.payload) {
                                    Ok(Some(reassembled)) => {
                                        counters.fragments_reassembled.fetch_add(1, Ordering::Relaxed);
                                        match decode_ipv8(&reassembled) {
                                            Ok(rd) => {
                                                counters.delivered.fetch_add(1, Ordering::Relaxed);
                                                (delivered)(rd.payload.to_vec());
                                            }
                                            Err(_) => { counters.dropped.fetch_add(1, Ordering::Relaxed); }
                                        }
                                    }
                                    Ok(None) => {} // 组未齐：等待更多片
                                    Err(_) => { counters.dropped.fetch_add(1, Ordering::Relaxed); }
                                }
                            } else {
                                counters.delivered.fetch_add(1, Ordering::Relaxed);
                                (delivered)(d.payload.to_vec());
                            }
                        }
                        Err(_) => {
                            counters.dropped.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
        }
    }
}

/// 内层 IP 五元组流哈希（FNV-1a，IPv4/IPv6）。非 IP / 截断回退 0，行为确定。
pub fn hash_flow(inner_ip: &[u8]) -> u32 {
    let mut buf = [0u8; 40];
    let mut len = 0usize;
    macro_rules! push {
        ($b:expr) => {{
            for &x in $b {
                if len < buf.len() {
                    buf[len] = x;
                    len += 1;
                }
            }
        }};
    }
    if !inner_ip.is_empty() {
        match inner_ip[0] >> 4 {
            4 if inner_ip.len() >= 20 => {
                push!(&inner_ip[12..20]); // src(4)+dst(4)
                let proto = inner_ip[9];
                let ihl = ((inner_ip[0] & 0x0F) as usize) * 4;
                let ihl = if (6..=60).contains(&ihl) && inner_ip.len() >= ihl { ihl } else { 20 };
                if (proto == 6 || proto == 17) && inner_ip.len() >= ihl + 4 {
                    push!(&inner_ip[ihl..ihl + 4]); // sport+dport
                }
                push!(&[proto]);
            }
            6 if inner_ip.len() >= 40 => {
                push!(&inner_ip[8..40]); // src(16)+dst(16)
                let nh = inner_ip[6];
                if (nh == 6 || nh == 17) && inner_ip.len() >= 44 {
                    push!(&inner_ip[40..44]); // sport+dport
                }
                push!(&[nh]);
            }
            _ => push!(&inner_ip[..inner_ip.len().min(16)]),
        }
    }
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in &buf[..len] {
        h ^= b as u64;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    ((h >> 32) ^ h) as u32 // 高低位混合，取 32 位
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::CipherSuite;
    use crate::engine::Engine;
    use crate::engine::State;
    use crate::Identity;

    fn engine_pair() -> (Engine, Engine) {
        let alice = Engine::new(
            Identity::from_bytes([1u8; 32]),
            IPv8Address::new(1, 1, 0, 0, 0),
            IPv8Address::new(1, 2, 0, 0, 0),
        );
        let bob = Engine::new(
            Identity::from_bytes([2u8; 32]),
            IPv8Address::new(1, 2, 0, 0, 0),
            IPv8Address::new(1, 1, 0, 0, 0),
        );
        (alice, bob)
    }

    type Collector = Arc<Mutex<Vec<Vec<u8>>>>;

    fn collector() -> (Sink, Collector) {
        let out: Collector = Arc::new(Mutex::new(Vec::new()));
        let o = out.clone();
        (Arc::new(move |v: Vec<u8>| o.lock().unwrap().push(v)), out)
    }

    /// 握手建立后两端各拆 N 片；返回两侧 FlowShards + 各自帧出口 + B 侧交付收集器
    fn shard_pair(
        n: usize,
        suite: CipherSuite,
    ) -> (FlowShards, FlowShards, Collector, Collector, Collector) {
        let (mut alice, mut bob) = engine_pair();
        alice.set_cipher_suite(suite);
        bob.set_cipher_suite(suite);
        let init = alice.start_handshake();
        let resp = bob.handle_frame(&init).expect("Bob 应回 Resp");
        alice.handle_frame(&resp);
        assert_eq!(alice.state(), State::Established);
        assert_eq!(bob.state(), State::Established);
        let (a_shards, al, ap, mtu) = alice.split_shards(n).unwrap();
        let (b_shards, bl, bp, _) = bob.split_shards(n).unwrap();
        let (a_frames, a_out) = collector();
        let (b_frames, b_out) = collector();
        let (b_deliv, b_delivered) = collector();
        let noop: Sink = Arc::new(|_| {});
        let ash = FlowShards::new(a_shards, al, ap, mtu, a_frames, noop);
        let bsh = FlowShards::new(b_shards, bl, bp, mtu, b_frames, b_deliv);
        (ash, bsh, a_out, b_out, b_delivered)
    }

    /// 每条 i 独立五元组流（src 末字节 = i）→ 打散到各分片
    fn ping(i: u8) -> Vec<u8> {
        vec![
            0x45, 0, 0, 0x18, 0, 0, 0, 0, 64, 6, 0, 0, // IPv4 固定头（proto=6, ihl=20）
            10, 0, 0, i, 10, 0, 0, 2, // src(末字节=流号) / dst
            0x30, 39, 0x1f, 0x90, // sport=12345 dport=8080
        ]
    }

    /// drain A→B 帧并喂入 B 侧（单向）
    fn feed(dst: &FlowShards, src_out: &Collector) {
        let frames: Vec<Vec<u8>> = {
            let mut q = src_out.lock().unwrap();
            std::mem::take(&mut *q)
        };
        for f in frames {
            assert!(dst.handle_inbound(&f), "Data 帧必须被分片器接管");
        }
    }

    /// 轮询收集器直到收满 want 包（2s 上限，worker 异步）
    fn wait_delivered(col: &Collector, want: usize) {
        for _ in 0..200 {
            if col.lock().unwrap().len() >= want {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    #[test]
    fn split_shards_requires_established() {
        let (mut alice, _bob) = engine_pair();
        assert!(alice.split_shards(4).is_err(), "未建立不得拆分");
        assert!(alice.split_shards(0).is_err(), "零分片不得拆分");
    }

    #[test]
    fn shards_roundtrip_multiple_flows() {
        for n in [1usize, 2, 4, 7] {
            let (ash, bsh, a_out, b_out, delivered) = shard_pair(n, CipherSuite::ChaCha20Poly1305);
            for i in 0..64u8 {
                ash.seal_dispatch(&ping(i)).unwrap();
            }
            for _ in 0..8 {
                feed(&bsh, &a_out);
                wait_delivered(&delivered, 64);
                if delivered.lock().unwrap().len() >= 64 {
                    break;
                }
            }
            let got: Vec<Vec<u8>> = delivered.lock().unwrap().clone();
            assert_eq!(got.len(), 64, "n={n} 全部流必须拆壳交付");
            for i in 0..64u8 {
                assert!(got.contains(&ping(i)), "n={n} 流 {i} 载荷必须逐字节一致");
            }
            let sa = ash.stats();
            let sb = bsh.stats();
            assert_eq!(sa.sealed, 64, "n={n} 发送侧计数");
            assert_eq!(sb.dropped, 0, "n={n} 不得有任何丢弃: {sb:?}");
            assert_eq!(sb.delivered, 64);
            let _ = b_out;
        }
    }

    #[test]
    fn shard_suite_aes_roundtrip() {
        let (ash, bsh, a_out, _b_out, delivered) = shard_pair(4, CipherSuite::Aes256Gcm);
        for i in 0..32u8 {
            ash.seal_dispatch(&ping(i)).unwrap();
        }
        for _ in 0..8 {
            feed(&bsh, &a_out);
            wait_delivered(&delivered, 32);
            if delivered.lock().unwrap().len() >= 32 {
                break;
            }
        }
        assert_eq!(delivered.lock().unwrap().len(), 32, "AES 套件分片往返");
        assert_eq!(bsh.stats().dropped, 0);
    }

    #[test]
    fn misaligned_shard_counts_fail_safe_not_corrupting() {
        // A 端 4 片、B 端 2 片（错配 = 部署事故，不保证语义，只保证安全）：
        // 同余路由把 A 的多片折进 B 的单片；密钥/窗口按 epoch 隔离，
        // 解通的载荷仍逐字节合法，解不通计入 dropped。底线 = **绝不产出
        // 未发送过的载荷**（无损坏交付），失败模式是可诊断的丢弃而非错数据。
        let (ash, bsh, a_out, _b_out, delivered) = {
            let (mut alice, mut bob) = engine_pair();
            let resp = bob.handle_frame(&alice.start_handshake()).unwrap();
            alice.handle_frame(&resp);
            let (a_shards, al, ap, mtu) = alice.split_shards(4).unwrap();
            let (b_shards, bl, bp, _) = bob.split_shards(2).unwrap();
            let (a_frames, a_out) = collector();
            let (b_frames, b_out) = collector();
            let (b_deliv, delivered) = collector();
            let ash = FlowShards::new(a_shards, al, ap, mtu, a_frames, Arc::new(|_| {}));
            let bsh = FlowShards::new(b_shards, bl, bp, mtu, b_frames, b_deliv);
            let _ = b_out;
            (ash, bsh, a_out, Collector::default(), delivered)
        };
        let sent: Vec<Vec<u8>> = (0..32u8).map(ping).collect();
        for p in &sent {
            ash.seal_dispatch(p).unwrap();
        }
        for _ in 0..4 {
            feed(&bsh, &a_out);
        }
        wait_delivered(&delivered, sent.len());
        std::thread::sleep(std::time::Duration::from_millis(100));
        let got = delivered.lock().unwrap();
        for g in got.iter() {
            assert!(sent.contains(g), "错配下不得产出未发送过的载荷（损坏交付）");
        }
    }

    #[test]
    fn hash_flow_stable_and_spread() {
        let h1 = hash_flow(&ping(1));
        let h2 = hash_flow(&ping(1));
        assert_eq!(h1, h2, "同流必须同哈希");
        assert_ne!(hash_flow(&ping(1)), hash_flow(&ping(2)), "不同流应当不同");
        let mut seen = std::collections::HashSet::new();
        for i in 0..64u8 {
            seen.insert(hash_flow(&ping(i)) % 8);
        }
        assert!(seen.len() >= 4, "64 流应打散到 ≥4 桶，实得 {:?}", seen.len());
    }

    #[test]
    fn big_packet_fragmentation_across_shards() {
        // 超 MTU 载荷 → 分片 → 对端重组交付（frag 组随流同片，同余类闭环）
        let (ash, bsh, a_out, _b_out, delivered) = shard_pair(3, CipherSuite::ChaCha20Poly1305);
        let mut big = ping(9);
        big.resize(4000, 0x5A);
        ash.seal_dispatch(&big).unwrap();
        for _ in 0..8 {
            feed(&bsh, &a_out);
            wait_delivered(&delivered, 1);
            if !delivered.lock().unwrap().is_empty() {
                break;
            }
        }
        let got = delivered.lock().unwrap();
        assert_eq!(got.len(), 1, "分片组必须重组为一次交付");
        assert_eq!(got[0], big, "重组载荷必须逐字节一致");
        assert_eq!(bsh.stats().dropped, 0, "重组不得有丢弃: {:?}", bsh.stats());
        assert!(ash.stats().fragments_sent >= 2, "应记录分片产出");
    }

    #[test]
    fn engine_single_path_frozen_after_split() {
        let (mut alice, mut bob) = engine_pair();
        let resp = bob.handle_frame(&alice.start_handshake()).unwrap();
        alice.handle_frame(&resp);
        assert_eq!(alice.state(), State::Established);
        alice.seal_frame(&ping(1)).unwrap(); // 未拆分前单点路径可用
        let _ = alice.split_shards(4).unwrap();
        assert!(alice.seal_frame(&ping(2)).is_err(), "拆分后单点 seal 必须冻结");
        assert!(alice.seal_frames(&ping(2)).is_err());
        assert!(alice.split_shards(2).is_err(), "不得重复拆分");
        assert!(alice.is_sharded());
        // 控制面保留：对端 fallback 重协商 → alice 收新 Init 重建隧道、冻结解除
        bob.reset();
        let init2 = bob.start_handshake();
        let resp2 = alice.handle_frame(&init2).expect("Established+新 Init 应替换并应答");
        bob.handle_frame(&resp2);
        assert_eq!(alice.state(), State::Established);
        assert!(!alice.is_sharded(), "重协商后冻结解除");
        alice.seal_frame(&ping(3)).unwrap(); // 单点数据面恢复
    }
}
