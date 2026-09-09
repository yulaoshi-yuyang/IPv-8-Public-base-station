# ADR-019: 多跳场景的头部完整性保护

状态: Accepted（2026-09-05，Phase 3 M1 决议）
关联: protocol-spec §6.6/§10.3, ADR-005（隧道加密）, ADR-012

## 背景

v7 删除了基础包头 CRC32，完整性依赖隧道层 ChaCha20-Poly1305 AEAD。
Phase 1-2 单跳模型下隧道两端即源和目的，AEAD 事实上覆盖头部。
Phase 3 引入 Chord 多跳路由 + RouteTrace 扩展头后，中间节点需要读取
（甚至按设计改写 HopLimit/RouteTrace），DstAddr/CapTag/SecLevel 等
端到端字段落在 AEAD 保护范围之外。

## 风险

- 能力伪造：中间节点改 CapTag/SecLevel 冒充高权限节点。
- 路由劫持：改写 DstAddr 将包导进攻击者控制的环。

## 候选方案

1. **per-hop MAC**：每跳用上一跳协商的密钥对头部打 MAC。安全性最好，
   成本是头部新增字段 + 每跳密钥协商，破 40 字节定长布局。
2. **RouteTrace 签名链**：RouteTrace 扩展头内每跳追加签名。不改基础头，
   扩展头本就明文；但验证成本高、载荷可被截短（需链尾闭合证明）。
3. **仅源路由不转发**：多跳路径由源点完整指定并签名，中间节点只按
   签名执行不自主路由。实现最省，牺牲 Chord 自主路由的灵活性。

## 决策

**选定：方案 2 与方案 3 的合流——"源路由 + 路径单次签名"（RouteTrace 扩展头，
protocol-spec §6.6）。**

- 路径由源点在 NextHopList 中完整指定（方案 3 的"仅源路由不转发"），
  中间节点只按签名执行，不自主路由；
- 签名结构走 RouteTrace 明文扩展头（方案 2 的载体），但**整条路径只签一次**
  （源点一次 Ed25519 签名覆盖冻结的端到端字段 + 初始 HopLimit + 路径本体），
  而非逐跳追加——验证成本 O(1)/跳 降为整链一次，规避方案 2 原本的
  "验证成本高"缺点；
- SrcPubKey 随头携带，与 SrcAddr 的绑定复用 Phase 2 证书体系（信任锚本地
  验证，中转节点无需在线查询）；
- 域分隔 `"ipv8plus-routetrace"` 使签名不可挪用到注册/轮换场景。

对 v9 的偏差：v9 Phase 3 列 "ipv8-routing（CF 算法）"。Chord 一致性哈希
保留为 crate 内 feature gate（`chord`），**不进本轮验收**：同机回环验证
环境无法模拟 DHT 的真实延迟与分区，而 v9 验收语义"隧道内多跳路由 + QoS
标记"静态源路由即可满足。Chord 自主路由的完整性需求（中间节点自选下一跳）
出现时，须回头扩展本 ADR（逐跳追加签名，见 spec §6.6 末段预留）。

## 后果

- ipv8-routing 按本决议实现：route_trace 构建/验证 + StaticRouter；
- 不携带 RouteTrace 的包在多跳网络上不得转发（spec §10.3），
  "可信基础设施"假设自此撤销；
- 若不解决（被推翻），IPv8+ 多跳仅可用于私有/联盟网络。
