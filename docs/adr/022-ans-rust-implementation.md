# ADR-022: ANS 云端服务以 Rust 实现（v9 原案 C# 的偏差记录）

状态: Accepted（2026-09-05，Phase 4 M1 决议）
关联: v9 §ANS/AnswerService, ADR-021（自托管）, ADR-010（存储）, resolver/zoneserver 模板

## 背景

v9 目录树把 ANS（目录树中写作 AnswerService，含 answer.proto）列在
`src/cloud/` 的 C# 侧；而实际 Phase 2-3 演进中，ZoneServer 与 Resolver
两个云服务的**全部可验证逻辑**都以 Rust crate 交付
（`src/cloud/zoneserver`、`src/cloud/resolver`，lib/grpc/main 三层模板），
C# 侧只做接口先行的宿主编排。原因：

1. 同一 workspace 的编译/测试/clippy 门禁链路（159 项测试全在 CI 可跑的
   Rust 侧）；
2. protox 纯 Rust 生成，Windows 零 protoc 依赖（环境教训入档）；
3. 域分隔 PoP/JWT/防枚举等已验证语义可在 ANS 直接复用，
   双语言实现意味着每份安全逻辑要维护两份并做契约对齐。

## 决策

**ANS 核心（名字→地址、能力索引、任务匹配打分、卡片存储、租约）以
Rust crate `ipv8-ans` 交付**；v9 的 C# 交付物按以下方式保留而非消失：

- `IPv8Plus.Abstractions`：`IAnsService`/`IAgentMesh` 接口先行（v9 铁律 1），
  语义与 ans.proto 一一对应；
- `IPv8Plus.Host`：任务调度编排**状态机**（Pending→Matching→Planned→
  Leased→Completed/Expired）以 C# 交付——这是 v9 AnsService/AgentMeshService
  的宿主侧职责（客户端决策逻辑，不是云端解析逻辑）；
- 两侧以**共享测试向量**（JSON）锁行为一致：同一 TaskDescription 输入，
  Rust 规划器与 C# 状态机必须产出逐字段相同的计划。

## 后果

- v9 验收"多 Agent 协作任务调度"的证据链 = Rust e2e（注册→寻址→规划→
  租约）+ C# 状态机镜像测试，而非 C# 调 gRPC 的活链路（零 NuGet 离线
  环境约束，与 Phase 1-3 的 gRPC 验证策略一致）；
- ANS 守护进程 `ipv8-ans` 与 zoneserver/resolver 同级可独立部署（ADR-021）；
- 将来接入真 gRPC C# 客户端（NuGet 解禁）时，IAnsService 的实现替换为
  真客户端，编排状态机不动。
