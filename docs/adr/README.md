# ADR 索引（Architecture Decision Records）

本目录收录 Strata (IPv8+) 的架构决策记录。**一篇 = 一个决策**，状态字段见各文件头部。

> ⚠️ 编号说明：ADR-001~006、008~009、011~018 形成于 v9 方案文档阶段（《IPv8+
> 工程化方案 最终版 v9》，见 `docs/references/`），当时未拆分单文件落盘，本目录
> 只回填了从协议仓建立后才定稿的决策。**编号缺口 ≠ 决策缺失**，对应内容以 v9
> 方案文档为准；缺口区间保留给未来考古回填，不复用。

## 已定稿（Accepted）

| # | 标题 | 一句话结论 |
|---|------|-----------|
| 007 | [Resolver 隐私](007-resolver-privacy.md) | 匿名查询、最小披露；注意 ADR-026 对其收紧的例外 |
| 010 | [存储选型 SQLite/Postgres](010-storage-sqlite-postgres.md) | `trait Store` 抽象，持久化按触发条件后置 |
| 019 | [多跳头完整性](019-multihop-header-integrity.md) | RouteTrace 三陷阱定稿：初始 HopLimit 进签名明文、SrcPubKey 进消息体、转发输出为明文重建包 |
| 020 | [CapTag 扩展路径](020-captag-extension-path.md) | 能力标签走扩展头位图，兼容旧解析器 |
| 021 | [云组件可自托管](021-self-hostable-cloud.md) | ZoneServer/Resolver/ANS 端点零硬编码，部署方可整体自托管 |
| 022 | [ANS 的 Rust 实现](022-ans-rust-implementation.md) | ipv8-ans crate 为语义权威，C# 侧走共享测试向量锁定 |
| 023 | [AgentCard 与 ANS 边界](023-agentcard-ans-boundaries.md) | CardSig 必须存在：哈希↔密钥的唯一绑定手段 |
| 024 | [内核数据面评估结论](024-kernel-dataplane-evaluation-outcome.md) | **不进内核**：XDP/WFP/NDIS 全否决，性能演进走用户态 |
| 025 | [AEAD 双套件](025-aead-cipher-suites.md) | suite(1B)‖epoch KeyID；接收方只信本地配置防降级；AES-NI 实测引擎 3.6→7.5 Gbps（2026-09-09） |

## 提议中（Proposed）

| # | 标题 | 一句话结论 |
|---|------|-----------|
| 026 | [NAT 穿透与中继](026-nat-traversal-and-relay.md) | 三级可达梯子：IPv6 直连 → UDP 打洞（Resolver 兼职 STUN+Rendezvous）→ 自建 relay 兜底；数据面保持原生 AEAD 帧 |

## 维护约定

- 新 ADR 顺延编号，不复用缺口号。
- 状态流转：提议中 → 已定稿 / 已废弃（被取代时在新 ADR 里标注取代关系）。
- 实测数据回填（如吞吐、RTT）直接更新原文件并注明日期，不另开新篇。
