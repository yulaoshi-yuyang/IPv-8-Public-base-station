//! # ipv8-codec
//!
//! IPv8+ 包头编解码（纯函数，零依赖）。
//!
//! - [`header`]：40 字节基础包头 + 扩展头定义 + `#[repr(C)]` 地址
//! - [`encode`]：内存结构 → 线格式
//! - [`decode`]：线格式 → 内存结构（严格校验）
//! - [`version`]：版本协商 + MinCompatVer 降级
//! - [`compat`]：IPv4/IPv6 兼容模式（载荷内层协议识别）
//! - [`fragment`]：MTU 分片与重组（spec §8.3）
//! - [`layouts`]：QoSReservation / RouteTrace / AgentCard / SemanticTag 布局（spec §6.5-§6.8）

pub mod compat;
pub mod decode;
pub mod encode;
pub mod fragment;
pub mod header;
pub mod layouts;
pub mod version;

pub use compat::{classify, InnerProto};
pub use decode::{decode, Decoded, DecodeError};
pub use encode::{encode, encode_header, EncodeError};
pub use fragment::{
    fragment_packet, FragmentError, FragmentInfo, Reassembler, ReassemblyError, DEFAULT_MTU,
    FRAG_EXT_WIRE, MAX_GROUP_BYTES, MAX_GROUPS, REASSEMBLY_TIMEOUT,
};
pub use header::*;
pub use layouts::{
    agent_card_message, route_trace_message, AgentCardSummary, LayoutError, QosReservation,
    RouteTrace, SemanticTags, TraceSigInput,
};
pub use version::{negotiate, negotiate_local, Negotiation};
