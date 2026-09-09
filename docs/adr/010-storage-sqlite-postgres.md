# ADR-010: 云侧存储收口（SQLite → PostgreSQL）

状态: Accepted — **决议为 Postpone**（2026-09-05，Phase 3 M1 决议）
关联: ADR-021（自托管云）, ADR-007（Resolver 隐私）, zoneserver 持久层注释

## 背景

v9 铁律与 ADR-021 要求 Resolver/ZoneServer 可自托管、存储可替换：
设计稿写的是"SQLite 起步，PostgreSQL 收口"。现状（Phase 2 末）：
ZoneServer/（未来的）Resolver 全内存 HashMap，零持久化；
"云端 Resolver 最小版本 + SQLite"在 v9 Phase 1 清单中，实际交付以
内存态通过了全部回环验收。

## 问题：现在就做 SQLite 是否过早？

SQLite 若现在引入，会立即背上一个约束：**它只对单进程部署有意义**，
而自托管的主力形态（家用小机器）恰恰是单进程——真正需要 PG 的多租户/
高可用部署则必须一开始就 PG。也就是说 SQLite 与 PostgreSQL 不是
"平滑升级对"，而是两种部署形态：

- 单进程自托管：进程重启后"注册表 + 证书序列"从哪来？
- 多实例/托管服务：单机 SQLite 文件锁死扩展。

节点侧的证书持久化（Phase 2 已交付 --cert-cache）已经消掉了"重启即
丢证书"的最大痛点（证书可由节点缓存，服务端丢了可重新 PoP 注册续期）；
JWT 是无状态 HS256 自签，服务端重启同样只需换 seed 决策。
**因此服务端持久化当前唯一的真实损失是"已注册地址簿"（防冒注的
地址→公钥绑定）**——它决定同密钥重注册续期可以无限进行、换密钥轮换
必须凭旧 JWT。地址簿丢失 = 已分配地址可被抢占注册，安全语义降级。

## 决策

1. **本轮（Phase 3）不做 SQLite**：云 crate（zoneserver/resolver）的
   记录存储定义在 `trait Store`（内存实现 + 接口稳定），持久化实现
   不进 Phase 3 验收。
2. **SQLite 的触发条件**（任一命中即启动，独立里程碑，不阻塞 Phase 3）：
   - 出现"多实例托管"需求（≥2 个写进程共享一份地址簿）；
   - 运维提出"重启丢注册表"真实事故；
   - 需要按地址反查审计（如吊销列表持久化）。
3. **PostgreSQL 收口的触发条件**：多租户/水平扩展成为产品形态，或
   需要行级并发与备份体系时；届时 SQLite 数据量与 schema 兼容性
   由 trait Store 的迁移层保证。
4. `trait Store` 设计（落 zoneserver M4 时共享）：
   ```rust
   trait Store: Send {
       fn get(&self, addr: &IPv8Address) -> Option<Record>;
       fn insert(&mut self, addr: IPv8Address, rec: Record) -> Result<(), StoreError>;
       fn update(&mut self, addr: &IPv8Address, rec: Record) -> Result<(), StoreError>;
   }
   ```
   记录结构保持最小（verify_key + 证书序列号 + 时间戳），避免把
   schema 演化压力传导给 SQLite/PG 方言差异。

## 后果

- 与 v9 的偏差在 README 进度节显式记录："SQLite→PG 收口 → 持久化
  trait 先行，实现按触发条件后置"；
- ADR-021 的存储抽象条款由 `trait Store` 兑现（接口化目标达成，
  "双方言"部分随触发条件落地）；
- 本 ADR 状态 Accepted（决议本身），实施里程碑未排期；触发条件命中
  时新开 ADR 记录选型细节（WAL、连接池、迁移工具）。
