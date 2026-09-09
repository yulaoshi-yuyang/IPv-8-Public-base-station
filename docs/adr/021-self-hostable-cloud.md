# ADR-021: 云端组件按可自托管接口设计

状态: Accepted（Phase 1 云端最小版本起执行）
关联: protocol-spec §10.4, ADR-007（Resolver 隐私）, ADR-010（SQLite→PG）

## 背景

Resolver / ZoneServer / ANS 默认部署在单一云上，形成中心化信任点。
对照 Tailscale（协调服务器可自托管）与 DID 生态，产品化必须回答
"能否完全脱离官方云运行"。

## 决策

技术风险最低但必须第一天做的五条：

1. 端点全配置化：云端地址、命名空间根、信任锚列成部署 profile，
   禁止任何硬编码域名（含测试域名）。
2. proto 去厂商化：message 不含云厂商字段与账号体系耦合；演进走
   package 版本前缀。
3. 存储抽象：Resolver/ZoneServer 持久层接口化，SQLite 与 PostgreSQL
   双方言可用（收口 ADR-010 的并发限制）。
4. 信任锚可插拔：证书根与 JWT 签发者是配置输入，自托管 = 换根，不改码。
5. 协议层无状态依赖：Resolver 不可达时客户端靠本地缓存 + Fallback
   完整工作（这同时是断网能力，也是迁移能力）。

## 后果

- Phase 1 云端最小版本多一层仓储接口工作量（预估 +1 人日）。
- 换来部署主权：企业内网/联盟网络可整栈私有化。
