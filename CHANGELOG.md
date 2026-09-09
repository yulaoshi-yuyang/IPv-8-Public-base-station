# Changelog

所有显著的变更都会记录在此文件中。格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
并且本项目遵循 [语义化版本](https://semver.org/lang/zh-CN/) 规范。

## [Unreleased]

### 项目结构重构
- 将项目主体从 `Strata/` 子目录提升到根目录，消除多余嵌套层级
- 整理文档结构：工程化方案 PDF/TXT 归集到 `docs/references/`，spec 归属分析移入 `docs/`
- 更新 `README.md` 工程结构说明，补全目录清单

### 修复
- 修复 `NrptCleanupService` 脚本路径引用错误：原硬编码 `scripts/cleanup-nrpt.ps1` 与实际位置 `deploy/client/cleanup-nrpt.ps1` 不符
- 将 NRPT 清理脚本路径配置化，新增 `ClientOptions.NrptCleanupScriptPath`，支持相对/绝对路径
- 补全 `appsettings.json` 配置项：新增 `QoSClassCapacity` 和 `NrptCleanupScriptPath`

### 配置
- 完善 `.gitignore`：增加 .NET 构建产物、IDE 配置、日志文件、本地配置覆盖等规则

---

## [0.9.0] - Phase 5 完成

### Phase 5 · 内核优化评估（仅评估，无驱动代码）
- `docs/phase5-kernel-evaluation.md`：三条内核路径（WFP callout / NDIS LWF / XDP-eBPF）逐一评估全部否决
- ADR-024 Accepted：不进入内核改造；性能演进改走用户态三路线（AES-NI 套件 / wintun 批量 API / 流级多核）
- v9 路线图五阶段至此全部收口

### Phase 4 · 全部完成（M1-M5）
- M1 AgentCard/SemanticTag 布局定稿 + ADR-022/023
- M2 ipv8-ans crate 核心（35 测试）：三维寻址、租约式分片计划
- M3 ans.proto + gRPC 接线（3 项 gRPC e2e）
- M4 C# 接口先行 + 编排状态机 + 共享测试向量（13 契约）
- M5 多 Agent 协作验收（Rust 208 + C# 13 全量门禁）

### Phase 3 · 全部完成（M1-M5）
- M1 协议定稿与 ADR 闭环（ADR-019/007/010）
- M2 ipv8-routing + Engine 转发角色（routing 18 + Engine 多跳 7）
- M3 ipv8-qos + C# QoSManagerService（Rust 8 + C# 契约 2）
- M4 ipv8-resolver（13 测试，含 2 项 gRPC e2e）
- M5 多跳端到端验证（4 项，真实 UDP，CI 可跑）

### Phase 2 · 全部完成
- 证书认证握手（ipv8-tunnel::auth，7 测试全绿）
- MTU/分片（ipv8-codec::fragment，9 测试全绿）
- 认证握手接入 Engine 数据面（5 集成测试全绿）
- 认证模式贯通 gRPC 契约与 ipv8-node，同机回环实测 PASS
- ZoneServer 核心逻辑（src/cloud/zoneserver，8 测试全绿）
- ZoneServer gRPC 网络层 + 节点真机注册路径实测 PASS
- Fallback 分级降级（ipv8-tunnel::fallback，9 测试全绿）
- 分片接入 TUN 数据面，-Fragment 同机回环实测 PASS
- Fallback 接入 node 数据面与 gRPC 契约，-Fallback 同机回环实测 PASS
- zone 路径证书持久化，-Zone 重启闭环实测 PASS

### Phase 1 · 隧道核心·密码学部分
- ipv8-codec：40 字节基础包头编解码（零依赖纯函数）
- ipv8-ffi：C ABI 导出
- ipv8-tunnel：隧道引擎（28 测试全绿）
  - frame：10B 帧头，KeyID = suite ‖ epoch
  - crypto：HKDF 逐代派生 + ChaCha20-Poly1305/AES-256-GCM 双套件
  - handshake：X25519 临时密钥协商
  - tun_worker：v9 §8 读线程模型
- protocol-spec.md 规范定稿候选
- IPv8Plus.Abstractions：ITunAdapter + 4 事件契约（C#）
- WintunDevice.cs：wintun.dll P/Invoke
- IPv8Plus.Host：Program.cs 管理员门禁 + ClientOptions + NrptCleanupService
- deploy/client/*.ps1：install-wintun / setup-nrpt / cleanup-nrpt
- ipv8-grpc：gRPC(tonic) 桥（2 e2e 测试全绿）
- wintun-node：Phase 1 通包验证守护进程
- Phase 1 验收 PASS（同机回环，自动 UAC 提权）
