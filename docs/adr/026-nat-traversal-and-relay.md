# ADR-026：NAT 穿透与中继（三级可达梯子）

- 状态：提议中（待评审）
- 日期：2026-09-09
- 关联：v9 §11（FallbackManager 分级降级）、ADR-007（Resolver 隐私）、ADR-010（存储后置）、ADR-021（端点零硬编码）、`shared/ipv8-proto/resolver.proto`、`src/cloud/resolver`、`ipv8-node --learn-peer`、`src/tools/ws-node`

## 背景

产品形态要求「任意两台机器都能建立 IPv8+ 隧道」。当前可达性只有两种手段，均不足以覆盖该目标：

1. **静态预登记入口**（`Resolver.Register` 的 `tunnel_entry` / `alt_entries`）：要求节点自带公网可达入口，NAT 后节点无法登记有效入口。
2. **`--learn-peer` 半动态**：被动方从**首个合法帧的包源地址**现学对端真实出口。它解决了「内网侧发起、公网侧应答」的不对称场景，但前提是**至少一方公网可达**——双方都在 NAT 后时，谁的第一帧都到不了对方。

2026-09-09 本机实测坐实了这一缺口：开发机 IPv4 = `172.28.74.173`（RFC1918，NAT 后）、无任何 IPv6 全局地址（GUA）→ **双向都没有公网可进入口，IPv4/IPv6 直连在 IP 层物理不可达**。这不是协议或代码缺陷（隧道层握手/AEAD/证书已全绿，见 2026-09-06 记录），而是 overlay 无法凭空创造 underlay 的可达性。

已有的 cloudflared WS 中继（2026-09-06 外网定向验证 PASS）证明了「机器主动外连边缘」这条路可行，但只适合**两台固定机器的演示链路**，不适合作为产品主梁：每个用户需自行部署 connector + 绑定域名 hostname；免费版不透传 gRPC、空闲 100s 断连、并发受限；且中国大陆用户到 CF 边缘的可达性与延迟本身不稳定——产品生死不应系于第三方免费套餐。

## 决策

采用**三级可达梯子**，与 v9 §11 FallbackManager 的降级哲学一脉相承：从最优路径逐级回退，任一级成功即锁定数据面，失败按超时降级。三级依次为 **IPv6 直连 → UDP 打洞 → 中继兜底**。核心原则：**数据面始终是原生 AEAD 帧，穿透机制只解决「帧怎么送到对端」，不改变帧内容、不削弱端到端加密。**

### 级 1：IPv6 直连优先

两端都有 GUA 时直接 UDP 互连，无需打洞或中继。国内运营商现已普遍下发 GUA，此级命中率不低；但本机 v6 时有时无（2026-09-06 曾有 `2409:…`，今日已停发）说明它「多数时候可用但不能指望」，故为优先项而非唯一项。判定沿用 2026-09-06 教训：v6 可达性须多信号确认，不单信一条命令。

### 级 2：UDP 打洞（Resolver 兼职 STUN + 信令）

不为打洞新造服务，而是把已有零件升级拼装：

1. **observed_addr（STUN 白送）**：`Register` / `Rendezvous` 时，Resolver 记录请求的**包源地址**（NAT 映射后的公网 ip:port），作为 `observed_addr` 存入条目。节点无需自测公网地址——「公网看到的你」由服务端权威记录。
2. **Rendezvous（信令交换）**：新增 RPC，双方各自上报本端候选地址（直连 GUA + observed_addr），服务端**原子返回对端的候选集**。这就是打洞所需的「互相告知各自公网地址」信令，复用 Resolver 现有 gRPC 通道与 PoP 鉴权。
3. **同时打洞 + 首帧现学**：拿到对端候选后，两端**同时**向对方发包（hole punching），复用 `--learn-peer` 语义——谁的包先穿过 NAT 映射，对端即从该帧现学真实回包地址。不需要新增协商协议。
4. **成功率非 100%**：对称 NAT（端口不可预测映射）下打洞会失败，因此**级 3 是必需品不是可选项**。具体成功率需打样实测，不臆造数字。

### 级 3：中继兜底

打洞失败（或双端都无公网入口）时，经中继转发隧道帧：

1. **自建 relay 为主梁**：`ws-node` 从「逐 WS 消息 = 一隧道帧」的单向桥升级为**双向多会话转发器**。数据面仍是原生 AEAD 帧，relay 只见密文、不见明文——与端到端加密产品定位自洽。relay 鉴权复用 ZoneServer 签发的证书/JWT，验证连接方持合法身份才转发。
2. **cloudflared 降级为本级可选项**：作为「用户可选的海外中继」插入级 3，而非产品主梁。开发测试链路继续用它。
3. **降级缓存**：沿用 §11 的 5 分钟降级缓存——中继成功后一段时间内不再反复尝试打洞，到期自动回试更优路径。

### 隐私与安全（对 ADR-007 的必要收紧）

`observed_addr` 是 NAT 映射信息，泄露即暴露节点公网入口，**敏感度高于现有 `tunnel_entry`**。因此：

- ADR-007 的「匿名查询、最小披露」姿态对 `tunnel_entry` 仍成立，但 **`Rendezvous` 返回的 observed_addr 必须鉴权**——只有持合法证书/JWT、且 PoP 自证身份的请求方才可获得对端的打洞地址。匿名 `Resolve` **不返回** observed_addr。
- observed_addr 短 TTL，随 NAT 映射变化快速失效；不落长期存储（ADR-010：走 `trait Store` 抽象，持久化按触发条件后置）。
- relay 零信任：不解析帧内容，AAD 绑定（明文头进 AEAD 认证）不变，relay 篡改帧即认证失败。

## 线格式 / 契约改动点（评审重点）

1. `resolver.proto`：
   - `RegisterResponse` 增 `string observed_addr`（回显服务端所见源地址，供节点自检）。
   - 新增 `rpc Rendezvous(RendezvousRequest) returns (RendezvousResponse)`：请求含本端候选 + PoP 证明；响应含对端候选集（直连 + observed）+ ttl。
   - `ResolveResponse` **不含** observed_addr（隐私分级）。
2. `src/cloud/resolver`：`trait Store` 增 observed_addr 读写；Rendezvous 处理器做鉴权 + 原子返回。
3. `ipv8-node`：打洞编排（同时发包 + learn-peer 现学 + 三级超时降级），先以验证件形态落地。
4. `src/tools/ws-node`：双向多会话 relay + 证书鉴权。
5. `FallbackManager`：入口来源从「Resolver 预登记」扩展为「动态打洞结果」，四级梯子语义不变。

## 实现顺序

1. **先验证方向，不写新代码**：换有 v6 的网络（手机热点/其他 WiFi），把现有 LearnPeer 拓扑跑绿 → 证明「级 1」在真实网络成立。
2. Resolver 扩展（observed_addr + Rendezvous + 鉴权）。
3. 打洞编排（`ipv8-node` 验证件形态）。
4. relay 角色（ws-node 升级）。
5. 最后接入 C# 生产路径（受 NuGet 解禁限制，排最后）。

## 后果

- **正面**：三级梯子覆盖绝大多数网络组合（双 v6 / 单公网 / 双 NAT）；数据面与端到端加密零改动；大量复用已有零件（Resolver、--learn-peer、FallbackManager、ws-node），非从零造轮子。
- **负面**：打洞对对称 NAT 失败，强依赖 relay；relay 需自建 VPS，有运维与带宽成本；Rendezvous 引入鉴权与 observed_addr 生命周期管理复杂度。
- **风险**：observed_addr 若鉴权失守 = NAT 映射批量泄露，是本 ADR 最需严守的安全边界。
- **未决**：① 打洞实测成功率（决定 relay 容量规划）；② relay 自建 vs 纯 cloudflared 的成本/合规取舍；③ Rendezvous 是否需限频防枚举（呼应 ADR-007）。这些留待打样实测后在实现阶段补记，不在此臆断。
