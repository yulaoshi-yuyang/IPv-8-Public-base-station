//! # ipv8-hook — 外部判决钩子总线
//!
//! 把数据包判决权交给**本机任意外部程序**（Python/Rust/Go……），对标 Linux
//! NFQUEUE，但无需任何内核组件。数据面（ipv8-node）在每个内层 IP 包上调用
//! [`HookBus::evaluate`]：
//!
//! 1. 流缓存命中 → 零 IPC 直接采用缓存判决；
//! 2. 无 decision 客户端 → 默认策略（默认放行）；
//! 3. 有 decision 客户端 → NDJSON 事件经环回 TCP 投递，等待 accept/drop，
//!    超时 / 客户端断线 / 队列拥塞一律立即回退，**绝不阻塞数据面**。
//!
//! 线协议见 [`protocol`]；IP 包解析见 [`ip`]；模块导览见本 crate 的 README。

pub mod ip;
pub mod protocol;

pub use protocol::{Action, ClientMode};

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine;
use serde_json::Value;

/// 默认监听端口（仅环回）
pub const DEFAULT_PORT: u16 = 45810;

/// 方向
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// 本机程序发出（TUN → 隧道）
    Out,
    /// 隧道收到 → 本机
    In,
}

impl Direction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Out => "out",
            Self::In => "in",
        }
    }
}

/// 待判决事件：数据面只给方向 + 原始内层包，元数据由总线解析
pub struct PacketEvent<'a> {
    pub direction: Direction,
    pub packet: &'a [u8],
}

/// 判决来源（统计/调试用）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerdictSource {
    /// decision 客户端实时判决
    Decider,
    /// 流缓存命中
    Cached,
    /// 没有判决者连接
    NoClient,
    /// 等待判决超时
    Timeout,
    /// 总线内部队列拥塞
    Backpressure,
    /// 判决者读取太慢，事件被挤出
    SlowDecider,
    /// 判决者中途断线
    DeciderGone,
}

impl VerdictSource {
    /// 是否来自实时判决/缓存（非回退）
    pub fn is_authoritative(self) -> bool {
        matches!(self, Self::Decider | Self::Cached)
    }
}

/// 最终判决
#[derive(Debug, Clone)]
pub struct Verdict {
    pub action: Action,
    /// 动作前延迟（外部要求整形时）
    pub delay: Duration,
    /// 自由标签
    pub tag: Option<String>,
    pub source: VerdictSource,
}

impl Verdict {
    pub fn accepted(&self) -> bool {
        self.action == Action::Accept
    }
}

/// 总线配置
#[derive(Debug, Clone)]
pub struct HookConfig {
    /// 监听地址（必须是环回）；端口 0 = 由系统分配（测试用）
    pub listen: std::net::SocketAddr,
    /// 单次判决等待超时（默认 50ms）
    pub timeout: Duration,
    /// 超时/无客户端/拥塞时的默认动作（默认 Accept = fail-open）
    pub default_action: Action,
    /// 暴露给客户端的包前缀字节数（默认 128）
    pub payload_prefix: usize,
    /// 客户端请求 ttl_ms 的上限钳制（默认 300s）
    pub flow_ttl_cap: Duration,
    /// 总线内部分发队列容量（满 → Backpressure 回退）
    pub dispatch_capacity: usize,
    /// 每个客户端的待写队列容量（满 → SlowDecider 回退/观察者丢弃）
    pub client_queue: usize,
}

impl Default for HookConfig {
    fn default() -> Self {
        Self {
            listen: std::net::SocketAddr::from(([127, 0, 0, 1], DEFAULT_PORT)),
            timeout: Duration::from_millis(50),
            default_action: Action::Accept,
            payload_prefix: 128,
            flow_ttl_cap: Duration::from_secs(300),
            dispatch_capacity: 2048,
            client_queue: 256,
        }
    }
}

/// 运行统计（全是原子计数，读取无锁）
#[derive(Debug, Default)]
pub struct HookStats {
    seen: AtomicU64,
    cached: AtomicU64,
    decided: AtomicU64,
    no_client: AtomicU64,
    timeout: AtomicU64,
    backpressure: AtomicU64,
    decider_gone: AtomicU64,
    accepted: AtomicU64,
    dropped: AtomicU64,
}

impl HookStats {
    pub fn snapshot(&self) -> HashMap<String, u64> {
        let pick = |a: &AtomicU64| a.load(Ordering::Relaxed);
        let fallback = pick(&self.no_client)
            + pick(&self.timeout)
            + pick(&self.backpressure)
            + pick(&self.decider_gone);
        HashMap::from([
            ("seen".into(), pick(&self.seen)),
            ("decided".into(), pick(&self.decided)),
            ("cached".into(), pick(&self.cached)),
            ("fallback".into(), fallback),
            ("accepted".into(), pick(&self.accepted)),
            ("dropped".into(), pick(&self.dropped)),
        ])
    }
}

/// 流缓存条目
struct CachedEntry {
    action: Action,
    delay: Duration,
    tag: Option<String>,
    expires: Instant,
}

// ---- 调度线程内部消息 ----

struct Dispatch {
    event_line: String,
    reply: Sender<VerdictResult>,
    deadline: Instant,
    flow: String,
}

struct VerdictResult {
    action: Action,
    delay_ms: u64,
    ttl_ms: u64,
    tag: Option<String>,
}

enum Msg {
    Dispatch(Dispatch),
    Hello {
        client_id: u64,
        mode: ClientMode,
        name: String,
        writer: SyncSender<String>,
    },
    ClientVerdict {
        client_id: u64,
        id: u64,
        result: VerdictResult,
    },
    GetStats {
        reply: Sender<Value>,
    },
    Disconnect {
        client_id: u64,
    },
}

struct ClientSlot {
    mode: ClientMode,
    #[allow(dead_code)]
    name: String,
    writer: SyncSender<String>,
}

struct Inner {
    cfg: HookConfig,
    stats: HookStats,
    /// event id 单调递增
    next_id: AtomicU64,
    /// 当前是否有 decision 客户端（热路径无锁快判）
    has_decider: AtomicBool,
    /// 流缓存
    flows: Mutex<HashMap<String, CachedEntry>>,
    /// 发往调度线程（有界通道，满则热路径立即回退）
    tx: SyncSender<Msg>,
}

/// 外部判决钩子总线。启动后监听环回端口，数据面调 [`evaluate`](Self::evaluate)。
pub struct HookBus {
    inner: Arc<Inner>,
    local_addr: std::net::SocketAddr,
}

impl HookBus {
    /// 绑定端口并启动所有后台线程。
    pub fn start(cfg: HookConfig) -> std::io::Result<Arc<Self>> {
        let listener = TcpListener::bind(cfg.listen)?;
        listener.set_nonblocking(false)?;
        let local_addr = listener.local_addr()?;

        let (tx, rx) = mpsc::sync_channel::<Msg>(cfg.dispatch_capacity);
        let inner = Arc::new(Inner {
            cfg: cfg.clone(),
            stats: HookStats::default(),
            next_id: AtomicU64::new(1),
            has_decider: AtomicBool::new(false),
            flows: Mutex::new(HashMap::new()),
            tx,
        });

        // 调度线程：拥有客户端注册表 + 待决表
        {
            let inner = Arc::clone(&inner);
            std::thread::Builder::new()
                .name("ipv8-hook-dispatch".into())
                .spawn(move || dispatch_loop(&inner, rx))
                .expect("spawn dispatch");
        }

        // 接受连接线程
        {
            let inner = Arc::clone(&inner);
            std::thread::Builder::new()
                .name("ipv8-hook-accept".into())
                .spawn(move || accept_loop(listener, inner))
                .expect("spawn accept");
        }

        Ok(Arc::new(Self { inner, local_addr }))
    }

    /// 实际监听地址（端口 0 时用于发现分配结果）
    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.local_addr
    }

    pub fn stats_snapshot(&self) -> HashMap<String, u64> {
        self.inner.stats.snapshot()
    }

    /// 数据面入口：评估一个内层包，返回最终判决。
    /// 该函数绝不传播错误——任何异常都回退默认动作，保证数据面可用。
    pub fn evaluate(&self, ev: &PacketEvent<'_>) -> Verdict {
        let inr = &self.inner;
        inr.stats.seen.fetch_add(1, Ordering::Relaxed);

        let info = ip::inspect(ev.packet);
        let flow = ip::flow_key(&info);

        // 1) 流缓存快路径
        {
            let mut flows = inr.flows.lock().expect("flow cache");
            if let Some(entry) = flows.get(&flow) {
                if entry.expires > Instant::now() {
                    inr.stats.cached.fetch_add(1, Ordering::Relaxed);
                    let v = Verdict {
                        action: entry.action,
                        delay: entry.delay,
                        tag: entry.tag.clone(),
                        source: VerdictSource::Cached,
                    };
                    self.count_outcome(&v);
                    return v;
                }
            }
            // 顺带惰性清理过期项，避免无外部消息时无限增长
            if flows.len() > 256 {
                flows.retain(|_, e| e.expires > Instant::now());
            }
        }

        // 2) 无判决者 → 默认策略（热路径不碰调度线程）
        if !inr.has_decider.load(Ordering::Relaxed) {
            inr.stats.no_client.fetch_add(1, Ordering::Relaxed);
            return self.fallback(VerdictSource::NoClient);
        }

        // 3) 构造事件
        let id = inr.next_id.fetch_add(1, Ordering::Relaxed);
        let prefix = &ev.packet[..ev.packet.len().min(inr.cfg.payload_prefix)];
        let event = protocol::EventMessage {
            ty: "event",
            id,
            ts_ms: now_ms(),
            direction: ev.direction.as_str(),
            flow: flow.clone(),
            ipver: info.ipver,
            proto: ip::proto_name(info.proto_num),
            proto_num: info.proto_num,
            src: info.src,
            dst: info.dst,
            sport: info.sport,
            dport: info.dport,
            size: ev.packet.len(),
            payload_b64: base64::engine::general_purpose::STANDARD.encode(prefix),
        };
        let event_line = serde_json::to_string(&event).unwrap_or_else(|_| String::from("{}"));

        let (reply_tx, reply_rx) = mpsc::channel::<VerdictResult>();
        let msg = Msg::Dispatch(Dispatch {
            event_line,
            reply: reply_tx,
            deadline: Instant::now() + inr.cfg.timeout,
            flow,
        });

        // 有界投递：调度线程跟不上就立刻回退，不等待、不堆积
        if inr.tx.try_send(msg).is_err() {
            inr.stats.backpressure.fetch_add(1, Ordering::Relaxed);
            return self.fallback(VerdictSource::Backpressure);
        }

        match reply_rx.recv_timeout(inr.cfg.timeout) {
            Ok(r) => {
                inr.stats.decided.fetch_add(1, Ordering::Relaxed);
                // 流缓存在调度线程收到判决时统一写入（flow key 归它管）
                let v = Verdict {
                    action: r.action,
                    delay: Duration::from_millis(r.delay_ms),
                    tag: r.tag,
                    source: VerdictSource::Decider,
                };
                self.count_outcome(&v);
                v
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                inr.stats.timeout.fetch_add(1, Ordering::Relaxed);
                self.fallback(VerdictSource::Timeout)
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                inr.stats.decider_gone.fetch_add(1, Ordering::Relaxed);
                self.fallback(VerdictSource::DeciderGone)
            }
        }
    }

    fn fallback(&self, source: VerdictSource) -> Verdict {
        let v = Verdict {
            action: self.inner.cfg.default_action,
            delay: Duration::ZERO,
            tag: None,
            source,
        };
        self.count_outcome(&v);
        v
    }

    fn count_outcome(&self, v: &Verdict) {
        match v.action {
            Action::Accept => &self.inner.stats.accepted,
            Action::Drop => &self.inner.stats.dropped,
        }
        .fetch_add(1, Ordering::Relaxed);
    }

    /// 请求一次调度线程维护的统计快照（含观察者数等）
    pub fn request_stats_json(&self) -> Option<Value> {
        let (tx, rx) = mpsc::channel();
        self.inner.tx.send(Msg::GetStats { reply: tx }).ok()?;
        rx.recv_timeout(Duration::from_millis(200)).ok()
    }
}

// ---- 线程实现 ----

fn accept_loop(listener: TcpListener, inner: Arc<Inner>) {
    let mut next_client_id: u64 = 1;
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let id = next_client_id;
                next_client_id += 1;
                let inner = Arc::clone(&inner);
                std::thread::Builder::new()
                    .name(format!("ipv8-hook-client-{id}"))
                    .spawn(move || client_thread(id, stream, inner))
                    .ok();
            }
            Err(_) => continue,
        }
    }
}

fn client_thread(id: u64, stream: TcpStream, inner: Arc<Inner>) {
    // 禁用 Nagle：判决是小包，低延迟优先
    let _ = stream.set_nodelay(true);
    let read_stream = match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let writer_stream = stream;

    // 写线程：SyncSender<String> → TcpStream
    let (write_tx, write_rx) = mpsc::sync_channel::<String>(inner.cfg.client_queue);
    std::thread::Builder::new()
        .name(format!("ipv8-hook-write-{id}"))
        .spawn(move || {
            let mut w = writer_stream;
            while let Ok(line) = write_rx.recv() {
                if w.write_all(line.as_bytes()).is_err() || w.write_all(b"\n").is_err() {
                    break;
                }
            }
        })
        .ok();

    // 读线程：逐行解析，首条必须是 hello
    let reader = BufReader::new(read_stream);
    let mut greeted = false;
    for line in reader.lines() {
        let Ok(line) = line else { break };
        let Ok(msg) = serde_json::from_str::<protocol::ClientMessage>(&line) else {
            continue;
        };
        match msg {
            protocol::ClientMessage::Hello { mode, name, version } => {
                if greeted {
                    continue; // 只认第一次 hello
                }
                greeted = true;
                let mode = mode.unwrap_or(ClientMode::Observer);
                let name = name.unwrap_or_else(|| format!("client-{id}"));
                if let Some(v) = version {
                    if v != protocol::PROTOCOL_VERSION {
                        let _ = write_tx.send(
                            serde_json::json!({
                                "type": "hello_ack", "ok": false,
                                "reason": format!("unsupported protocol version {v}, expected {}", protocol::PROTOCOL_VERSION),
                            }).to_string(),
                        );
                        break;
                    }
                }
                inner.tx.send(Msg::Hello {
                    client_id: id,
                    mode,
                    name,
                    writer: write_tx.clone(),
                }).ok();
            }
            protocol::ClientMessage::Verdict { id: vid, action, delay_ms, ttl_ms, tag } => {
                if !greeted {
                    continue;
                }
                inner.tx.send(Msg::ClientVerdict {
                    client_id: id,
                    id: vid,
                    result: VerdictResult {
                        action,
                        delay_ms: delay_ms.min(10_000), // 单包延迟上限 10s，防滥用
                        ttl_ms: ttl_ms.min(3_600_000), // 缓存上限 1h
                        tag,
                    },
                }).ok();
            }
            protocol::ClientMessage::Stats => {
                let (tx, rx) = mpsc::channel();
                if inner.tx.send(Msg::GetStats { reply: tx }).is_ok() {
                    if let Ok(v) = rx.recv_timeout(Duration::from_millis(200)) {
                        let _ = write_tx.send(v.to_string());
                    }
                }
            }
        }
    }

    // 连接结束（无论是否 hello 过）
    let _ = inner.tx.send(Msg::Disconnect { client_id: id });
}

/// 待决条目
struct Pending {
    reply: Sender<VerdictResult>,
    deadline: Instant,
    flow: String,
}

fn dispatch_loop(inner: &Arc<Inner>, rx: Receiver<Msg>) {
    let mut clients: HashMap<u64, ClientSlot> = HashMap::new();
    let mut decider: Option<u64> = None;
    let mut pending: HashMap<u64, Pending> = HashMap::new();

    while let Ok(msg) = rx.recv() {
        match msg {
            Msg::Hello { client_id, mode, name, writer } => {
                let assigned = if mode == ClientMode::Decision && decider.is_none() {
                    decider = Some(client_id);
                    inner.has_decider.store(true, Ordering::Relaxed);
                    ClientMode::Decision
                } else if mode == ClientMode::Decision {
                    // 判决位已占 → 降级观察者
                    ClientMode::Observer
                } else {
                    ClientMode::Observer
                };

                let ack = if assigned == ClientMode::Decision {
                    protocol::hello_ack_ok(ClientMode::Decision).to_string()
                } else if mode == ClientMode::Decision {
                    protocol::hello_ack_degrade(
                        ClientMode::Observer,
                        "decision slot occupied; downgraded to observer",
                    )
                    .to_string()
                } else {
                    protocol::hello_ack_ok(ClientMode::Observer).to_string()
                };
                let _ = writer.send(ack);

                clients.insert(
                    client_id,
                    ClientSlot {
                        mode: assigned,
                        name,
                        writer,
                    },
                );
            }

            Msg::Dispatch(Dispatch { event_line, reply, deadline, flow }) => {
                // 惰性清理超时待决（超时由 evaluate 侧计时，这里只防表膨胀）
                if pending.len() > 1024 {
                    let now = Instant::now();
                    pending.retain(|_, p| p.deadline > now);
                }

                let Some(d_id) = decider else {
                    // 竞态：evaluate 看到有判决者，但此刻恰好掉线 → 直接回退
                    let _ = reply.send(default_result(inner));
                    continue;
                };

                // 事件 id 从事件 JSON 提取，作为待决表 key 与判决对齐
                let event_id: u64 = serde_json::from_str::<Value>(&event_line)
                    .ok()
                    .and_then(|v| v.get("id").and_then(|x| x.as_u64()))
                    .unwrap_or(0);

                // 投给判决者（满 = 判决者太慢 → 立即回退）
                let Some(d_slot) = clients.get(&d_id) else {
                    let _ = reply.send(default_result(inner));
                    continue;
                };
                if d_slot.writer.try_send(event_line.clone()).is_err() {
                    inner.stats.backpressure.fetch_add(1, Ordering::Relaxed);
                    let _ = reply.send(default_result(inner));
                    continue;
                }
                pending.insert(
                    event_id,
                    Pending {
                        reply,
                        deadline,
                        flow,
                    },
                );

                // 副本给观察者（尽力而为，丢弃不影响判决）
                for (cid, slot) in clients.iter() {
                    if *cid == d_id || slot.mode != ClientMode::Observer {
                        continue;
                    }
                    let _ = slot.writer.try_send(event_line.clone());
                }
            }

            Msg::ClientVerdict { client_id, id, result } => {
                if decider != Some(client_id) {
                    continue; // 观察者的判决无效
                }
                if let Some(p) = pending.remove(&id) {
                    // ttl>0：缓存整流判决，TTL 内同 5 元组走零 IPC 快路径
                    if result.ttl_ms > 0 {
                        let ttl = Duration::from_millis(result.ttl_ms)
                            .min(inner.cfg.flow_ttl_cap);
                        let mut flows = inner.flows.lock().expect("flow cache");
                        flows.insert(
                            p.flow,
                            CachedEntry {
                                action: result.action,
                                delay: Duration::from_millis(result.delay_ms),
                                tag: result.tag.clone(),
                                expires: Instant::now() + ttl,
                            },
                        );
                    }
                    let _ = p.reply.send(result);
                }
            }

            Msg::GetStats { reply } => {
                let s = inner.stats.snapshot();
                let _ = reply.send(serde_json::json!({
                    "type": "stats",
                    "decided": s["decided"],
                    "cached": s["cached"],
                    "fallback": s["fallback"],
                    "accepted": s["accepted"],
                    "dropped": s["dropped"],
                    "observers": clients.values().filter(|c| c.mode == ClientMode::Observer).count(),
                    "decider": decider.and_then(|d| clients.get(&d)).map(|c| c.name.clone()),
                }));
            }

            Msg::Disconnect { client_id } => {
                clients.remove(&client_id);
                if decider == Some(client_id) {
                    decider = None;
                    inner.has_decider.store(false, Ordering::Relaxed);
                    // 所有在途判决立即按默认策略落地（不等超时）
                    for (_, p) in pending.drain() {
                        let _ = p.reply.send(default_result(inner));
                    }
                }
            }
        }
    }
}

fn default_result(inner: &Inner) -> VerdictResult {
    VerdictResult {
        action: inner.cfg.default_action,
        delay_ms: 0,
        ttl_ms: 0,
        tag: None,
    }
}

fn now_ms() -> u64 {
    use std::time::UNIX_EPOCH;
    std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
