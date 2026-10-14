# ADR 0008 — FFI 仅 Phase 0 编解码验证使用，Phase 1 起冻结

> 是什么：C ABI（`ipv8-ffi`）只服务 Phase 0 编解码验证；Phase 1 起跨语言通信唯一通道为 gRPC，FFI 冻结。
> 证据来源：src/core/ipv8-ffi/Cargo.toml:3；src/core/ipv8-ffi/src/lib.rs:1-2；src/core/ipv8-ffi/include/ipv8.h:1-4；src/core/ipv8-grpc/src/lib.rs:3；shared/ipv8-proto/tunnel.proto:17。
> 抽取日期：2026-10-13（自代码注释抽取，债 1）。

## 背景

Rust 引擎与外部宿主之间需要一条跨语言通信通道。注释记载的口径是分两阶段：
Phase 0 用 C ABI 做编解码验证，Phase 1 切换到 gRPC(tonic) 契约通道。

## 决定了什么

1. `ipv8-ffi` 的 C ABI 导出**仅用于 Phase 0 编解码验证**（lib.rs:1）。
2. **Phase 1 起全部走 gRPC，此模块冻结**（lib.rs:2；ipv8.h:4 同口径：
   "Phase 1 起跨语言通信一律走 gRPC（tonic），本头文件冻结"）。
3. gRPC 桥（ipv8-grpc）是**跨语言通信唯一通道**（ipv8-grpc/src/lib.rs:3），
   Phase 1 起一切跨语言通信走 tunnel.proto 契约（tunnel.proto:17）。
4. 冻结前维护口径：ipv8.h 与 Rust 侧 ABI **手工保持同步**（ipv8.h:3）。

## 为什么（考虑过的替代方案）

代码注释未记载被否决的替代方案论证。注释可辨认的取舍只有阶段划分本身：
FFI 短暂服役于 Phase 0，gRPC 作为 Phase 1 的唯一承接通道。

## 什么条件下可以推翻

代码注释未记载。
