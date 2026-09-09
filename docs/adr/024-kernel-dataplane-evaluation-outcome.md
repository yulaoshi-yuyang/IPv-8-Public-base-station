# ADR-024: Phase 5 内核数据面评估结论——不进入内核改造

状态: Accepted（2026-09-06，Phase 5 决议）
关联: v9 §Phase 5（仅评估）, docs/phase5-kernel-evaluation.md, ADR-005（隧道加密）

## 背景

v9 将 WFP Callout / NDIS 中间驱动列为可选末期优化（"仅评估，不进主线"）。
Phase 5 评估已完成（测量工具 bench_dataplane.rs，i9-13900H 实测）：

- 引擎单核数据面 **0.37 GiB/s ≈ 3.2 Gbps**（满 MTU 单线程，多核可线性扩）；
- 引擎在纯 AEAD 之上仅增加 ~13% 成本——**瓶颈是 ChaCha20 加密，不是
  TUN/内核路径**；内核旁路的理论收益上限就是这 13%；
- XDP/eBPF for Windows（2025 现状 v1.4/v1.5-preview）：AF_XDP 面向入站 L2
  与策略钩子，不适配"出站封装 UDP 隧道"模型，且内核程序仍需签名驱动承载；
- WFP/NDIS 成本：EV 代码签名 + WHQL/attestation、蓝屏半径、每内核版本回归。

## 决策

**不实施任何内核数据面改造**（WFP callout、NDIS LWF、XDP 隧道化三条全部否决）。
Phase 5 交付物 = 评估报告（docs/phase5-kernel-evaluation.md）+ 本 ADR +
可复现基线 bench（`#[ignore]` 不入门禁）。v9 路线图的五个阶段至此收口。

性能演进若被需要，按性价比顺序走**用户态路线**：
1. AES-256-GCM(AES-NI) 密码套件评估（AEAD 吞吐 3-4×，需新 ADR 动 §10 基线）；
2. wintun 批量收发 API（wintun crate 升级或直连 DLL）；
3. 流级多核并行（引擎按对端分片，天然无共享）。

## 复评触发条件

任一命中即重开本 ADR（Superseded）：
- 部署画像出现 **≥10 Gbps 单流**或中继节点聚合吞吐超过多核 AEAD 预算；
- 目标平台移入 **CPU 受限**（无 AES-NI 的嵌入式 x86 等），ChaCha20 成为绝对瓶颈；
- 实测发现拷贝/上下文切换占比反转（引擎 overhead ≫ 13%，如 TUN 唤醒风暴）；
- 产品需要**入站早期丢弃**（抗 DDoS）——那是 XDP_DROP 的主场，与隧道加速分开立项。

## 后果

- 工程不引入内核驱动依赖：无 EV 证书、无 WHQL、无蓝屏半径、部署仍是
  "wintun.dll + 管理员"（与 Phase 1 一致）；
- 基线 bench 常驻仓库，任何数据面改动都有回归对照；
- v9 §Phase 5 从"可选优化"正式落为"评估后不做"，路线图闭环。
