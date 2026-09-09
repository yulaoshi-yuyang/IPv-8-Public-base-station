# Changelog

所有显著的变更都会记录在此文件中。格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
并且本项目遵循 [语义化版本](https://semver.org/lang/zh-CN/) 规范。

## [Unreleased]

### 多核数据面（2026-09-09，ADR-024 用户态性能线）
- 新增 `ipv8-tunnel::flow::FlowShards`：Data 面 N-worker 流级分片，同流同 worker 保 nonce 唯一，epoch 同余类（`epoch ≡ shard mod stride`）免解密路由；线格式零改动
- `TunnelKeys` 加分片 SA（`with_shard`/`derive_shard`/`shard`/`stride`），轮换步幅 = 分片数，宽限期按代换算；默认 stride=1 逐字节零回归
- `Engine::split_shards(n)` 移交数据面并冻结单点 seal/Data，握手状态机保留；新 Init 重协商自动解冻（4 处握手点统一置 `sharded=false`）
- `ipv8-node --shards N`（默认 1）：Established 后主循环自动装填 worker，TUN 读线程分片优先投递、UDP 收线程 Data 帧按同余接管，`[stats]` 聚合分片计数并显示 `shards=`；仅真实 TUN 路径生效，`--no-tun` 回显验证件恒单点
- 分片错配（两端 N 不一致）经回归测试证明为**可诊断丢包、无损坏交付**
- 修正注释中把该性能线误标为 ADR-026 的引用，归正为 ADR-024（026 是 NAT 三级梯子提案）

### 测试
- Rust：新增 `flow.rs` 7 项分片单测（往返/套件/错配/分片重组/冻结/哈希打散）+ bench `flow_shards_scaling`；总数 213 → 227
- C#：`TestRunner` 25 → 36 项集成测试——NRPT 真实脚本执行（绝对/相对路径，带 BOM 防 PS5.1 GBK 误读中文路径）、QoS 并发入队守恒/出队无重无失/丢弃计数单调、AgentMesh 同名不同址共存/多标签交集排序、`tunnel.proto` 冻结面（RPC 清单 + TunnelStatus 字段 + 枚举）、MockTun 生命周期、Events 全子类型 `with` 复制完整性

### 工程化（2026-09-09）
- 建立 git 仓库（初始提交含 140 文件），`.gitignore` 排除 exe/zip/工具二进制与一次性分享产物
- `scripts/make-peer-pack.ps1`：跨机验证包（`deploy/cross-verify/` + zip）唯一再生成入口，禁止手工复制 exe
- `verify-loopback.ps1` / `verify-cross.ps1` / `notun-selftest.ps1`：加构建新鲜度护栏，自检默认优先 `target\release` 现建产物
- `docs/adr/README.md`：ADR 索引，含编号缺口（001-006 等在 v9 方案文档阶段）说明
- NDIS 协议驱动源码归档至 `archive/ipv8-ndis-protocol/`（ADR-024 否决内核路线），相关构建文档与安装脚本路径同步
- `性能评分报告.html` v2：回填双套件实测（引擎 AES-256-GCM 7.5 Gbps vs ChaCha 3.6 Gbps），总分 88 → 92

### 性能
- `bench_dataplane.rs` 扩为 ChaCha20-Poly1305 / AES-256-GCM 双套件对比：AEAD seal 0.55 → 1.03 GiB/s，引擎单程 0.40 → 0.85 GiB/s（i9-13900H 单线程 release）

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
