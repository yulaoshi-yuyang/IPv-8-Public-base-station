# ADR-023: AgentCard 数据模型与 ANS↔Resolver↔ZoneServer 边界

状态: Accepted（2026-09-05，Phase 4 M1 决议）
关联: protocol-spec §3.4/§6.7/§6.8, ADR-020（CapTag 扩容）, ADR-019（身份体系）, v9 §ANS

## 背景

v9 只给了 AgentCard 的名字（扩展头类型 4）与 ANS 的职责一句话，
数据格式、三维寻址算法、与 Resolver/ZoneServer 的边界全部留白。
实现前必须锁死，否则"多 Agent 协作"会退化成自由发挥。

## 决策

### 1. 三方边界（单一事实源原则）

| 服务 | 权威数据 | 不做什么 |
| --- | --- | --- |
| ZoneServer | addr ↔ Ed25519 公钥 绑定（证书/JWT/轮换） | 不知道能力、不知道入口 |
| Resolver | addr ↔ 隧道入口（ip:port/mtu/alt/ipv8_capable） | 不验证能力声明 |
| ANS | name/能力/卡片全文 ↔ addr ↔ **智能体公钥** | 不发证书、不管网络入口 |

- 两阶段注册：agent 先向 ZoneServer PoP 注册拿 addr+JWT，再向 ANS
  `RegisterAgent`（PoP 域 `ipv8plus-agent-card`，消息体含 name）。
  ANS 信任边界 = 本地信任锚验证书——addr↔key 绑定不重复发明。
- ResolveName 返回 `{addr, tunnel_entry, card}`：tunnel_entry 字段是
  ANS 从 Resolver 侧同步/本地冗余的读模型，**权威仍属 Resolver**；
  自托管最小部署（三服务同进程）时共享存储，跨部署时以 ANS 记录的
  条目 TTL ≤ Resolver 条目 TTL 约束陈旧窗口。

### 2. AgentCard 数据模型（ANS 侧全文，规范字节 = UTF-8 JSON 的
字段序固定序列化，哈希输入逐字节定义）

```
{ name, addr, capabilities: [SemanticTag 标签], endpoints?, qos_hint,
  not_after, sig }
```
- `card_hash`（包内头 §6.7 的 CardHash）= SHA-256(规范字节)[0..16]；
- 包内 AgentCard 头 = **摘要 + 智能体自身签名**（spec §6.7）；
- 标签格式锁 §6.8（小写 ASCII，≤32 标签，≤48B/标签）——精确匹配，
  **不做**全文检索/模糊匹配/语义推理（LLM 明确排除在本 Phase 外）。

### 3. 三维寻址 = 三个查询，不是三种算法

- 直接：name → {addr, entry, card}（哈希表，本 ADR §1 表）
- 能力：{标签集} → 精确倒排索引交集打分（qos_hint、剩余 TTL 权重）
- 任务：TaskDescription{required_caps, min_count, qos_level,
  timeout_ms} → 能力寻址取候选 → top-min_count 分片 + 租约
  （lease = ANS 侧记账；回报/超时回收 = 计划状态可恢复）

## 后果

- 能力标签 = ANS 全文、SemanticTag 头、能力索引三处共享同一
  §6.8 格式，无第二套词汇；
- 包内 128B AgentCard 头在多跳 MTU 预算内（1432-40-104-122-130 ≈
  936B 载荷余量），超限走分片（§8.3 链首规则不变）；
- DID/well-known 发现不在本期：name 就是 `.ipv8.net` 区内的标签名，
  DNS 桥接归 DnsHijack 客户端侧（v9 §7 既有链路）。
