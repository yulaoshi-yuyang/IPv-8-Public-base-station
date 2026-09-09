//! # ipv8-routing
//!
//! IPv8+ 多跳路由决策层（protocol-spec §6.6 / ADR-019 决议：
//! **源路由 + 路径签名**）。
//!
//! - [`route_trace`]：RouteTrace 构建（源点签名）与验证（中转/目的地）
//! - [`static_route`]：`Router` 抽象 + 静态源路由实现
//! - [`cf`]：Chord 一致性哈希骨架（feature `chord`；不进本轮验收）
//!
//! 依赖方向铁律：本 crate 只依赖 ipv8-codec；隧道引擎（ipv8-tunnel）
//! 反过来引用本 crate 做转发决策。证书验证在此独立实现（120B 线格式 =
//! addr‖pub‖not_after‖ca_sig，与 ipv8-tunnel::auth 逐字节一致），
//! 避免 codec ← routing → tunnel 的循环。

pub mod cf;
pub mod route_trace;
pub mod static_route;

pub use route_trace::{
    build_route_trace, cert_binding_ok, cert_pubkey_from_wire, frozen_head, verify_for_next_hop,
    Decision, PathSpec, TraceError, TracePolicy, VerifyInput,
};
pub use static_route::{Router, StaticRouter};
