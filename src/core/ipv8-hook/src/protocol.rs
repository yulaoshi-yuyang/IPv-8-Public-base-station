//! 外部判决钩子的 NDJSON 线协议消息定义。
//!
//! 所有消息都是**单行 JSON + `\n`**（NDJSON），任何语言用标准库
//! socket + json 即可实现客户端。协议版本见 [`PROTOCOL_VERSION`]。

use serde::{Deserialize, Serialize};

/// 线协议版本（hello 消息携带，不兼容时节点拒绝）
pub const PROTOCOL_VERSION: u32 = 1;

/// 节点服务名（hello_ack 中回传）
pub const SERVER_NAME: &str = "ipv8-hook/0.9";

/// 客户端身份模式
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClientMode {
    /// 判决者：收到事件，可回复 accept/drop。全局同时只允许一个。
    Decision,
    /// 观察者：只收事件副本，判决无效（录像/监测/调试用）。
    Observer,
}

/// 判决动作
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// 放行
    Accept,
    /// 丢弃
    Drop,
}

/// 客户端 → 节点的消息
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ClientMessage {
    /// 连接后第一条消息：声明身份
    Hello {
        #[serde(default)]
        mode: Option<ClientMode>,
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        version: Option<u32>,
    },
    /// 对某个事件的判决
    Verdict {
        id: u64,
        action: Action,
        /// 执行动作前延迟毫秒（整形/压测），缺省 0
        #[serde(default)]
        delay_ms: u64,
        /// 同流缓存毫秒：TTL 内同 5 元组不再询问，缺省 0 = 每包都问
        #[serde(default)]
        ttl_ms: u64,
        /// 自由标签（策略路由用，Phase 1 仅统计），缺省 null
        #[serde(default)]
        tag: Option<String>,
    },
    /// 请求一次统计快照
    Stats,
}

/// 节点 → 客户端：数据包事件（序列化为 NDJSON 行）
#[derive(Debug, Clone, Serialize)]
pub struct EventMessage {
    #[serde(rename = "type")]
    pub ty: &'static str,
    pub id: u64,
    pub ts_ms: u64,
    /// `out` = TUN→隧道（本机发出）；`in` = 隧道→TUN
    pub direction: &'static str,
    /// 方向无关的规范流标识
    pub flow: String,
    pub ipver: u8,
    /// "tcp"/"udp"/"icmp"/"icmpv6"/"other"
    pub proto: &'static str,
    /// IANA 协议号；无法解析为 0
    pub proto_num: u8,
    pub src: String,
    pub dst: String,
    pub sport: u16,
    pub dport: u16,
    /// 完整内层包字节数
    pub size: usize,
    /// 内层 IP 包前缀的 base64（长度由 --hook-payload 控制）
    pub payload_b64: String,
}

/// hello_ack（由总线按实际情况构造 JSON）
pub fn hello_ack_ok(mode: ClientMode) -> serde_json::Value {
    serde_json::json!({
        "type": "hello_ack",
        "ok": true,
        "mode": mode,
        "server": SERVER_NAME,
        "version": PROTOCOL_VERSION,
    })
}

/// hello 被拒绝/降级时的应答
pub fn hello_ack_degrade(assigned: ClientMode, reason: &str) -> serde_json::Value {
    serde_json::json!({
        "type": "hello_ack",
        "ok": false,
        "mode": assigned,
        "reason": reason,
        "server": SERVER_NAME,
        "version": PROTOCOL_VERSION,
    })
}
