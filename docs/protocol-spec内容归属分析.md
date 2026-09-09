# protocol-spec.md 内容归属分析

依据：《IPv8+ 工程化方案（最终版 v9）》全文 25 页（17 节）。
目标：钉死 protocol-spec.md 的边界——哪些内容属于协议规范正文，哪些必须写到别处。

---

## 结论先行

v9 里真正属于 protocol-spec.md 的内容**只有第 7 节（协议规范）的一半**：包头布局、字段偏移、PayloadLen 约束、Flags、扩展头注册表、扩展头通用格式、地址格式、MTU/开销计算、Payload 承载声明。其余 16 节全部是架构、实现、部署、工程治理，**不应进入规范正文**。

更重要的是：**第 7 节目前还不足以定稿**。作为一份可互操作的规范，它缺 8 项 normative 内容（见第三节），其中"未知扩展头如何处理"和"多跳场景下头部字段的可信边界"直接决定 ① ② 两条下一步建议能不能落地。

一句话判断标准：**换一个语言实现、换一个厂商部署，这条内容还成立吗？** 成立 → 规范；不成立 → 架构文档 / ADR / 代码 / 部署脚本。

---

## 一、准入三条件

一条内容写进 protocol-spec.md，必须同时满足：

1. **线上可见**：描述的是收发双方能在字节流里读到的东西（字段、偏移、编码、长度、语义）。
2. **互操作必需**：不写清楚，两个独立实现就会对不上（行为分歧、严格校验失败、无法解析）。
3. **与实现无关**：不含 Rust/C# 代码、不含 Windows API、不含进程/线程模型、不含云端部署拓扑、不含时间参数。

不满足第 3 条的一律降级到 ADR 或实现文档——这是"防屎山"在文档层面的体现。

---

## 二、写进 protocol-spec.md

### 2.1 已有内容，直接进正文（v9 §7.1–7.9）

| v9 章节 | 内容 | 进正文的形态 |
| --- | --- | --- |
| 7.1 + 7.2 | 40 字节基础头布局 + 字段说明表（Version/MinCompatVer/Flags/PayloadLen/HopLimit/NextHeader/SrcAddr/DstAddr/填充/ExtHeaders） | 保留 ASCII 图与表，偏移必须逐字段写成 normative 区间（如 `octets 3–4`） |
| 7.3 | `IPv8+ 包总长 ≤ 65467` 及 65535−20−8−40 推导 | 保留为 normative 约束 + informative 推导 |
| 7.4 | Flags 位定义（0-3 QoS / 4 E / 5 F / 6 X / 7-15 Reserved） | 保留，并补 Reserved 的发送/接收规则 |
| 7.5 | 扩展头类型注册表（0–6） | 保留为**注册表 + 分配规则**（见 3.4） |
| 7.6 | 扩展头通用格式（NextHeader / ExtLen / ExtLen×8） | 保留，补链式终止与最大链长 |
| 7.7 | 128 位地址格式（ASN/HostID/DeviceID/CapTag/SecLevel/Reserved） | 字段部分进正文；"不可压缩论证"进附录（informative） |
| 7.8 | 封装开销 68B、MTU 1432、有效载荷 1392 | **仅进数值与推导**；`Set-NetIPInterface` 等落地方式出去 |
| 7.9 | Payload 承载原始 IPv4/IPv6 包（IP-in-IP）、虚拟 IP 100.64.0.0/10 | 保留为 normative（决定了解封装契约） |

### 2.2 必须补的缺口（v9 没写，但 spec 不定稿就不能开工）

按返工成本降序：

1. **字节序与位序**（v9 全文未提）。Version 占 4 bit 在高半字节还是低半字节？PayloadLen/HopLimit 之外的多字节字段是大端还是小端？SrcAddr 从字节 7 开始是**非对齐**访问，Rust 侧 `#[repr(C)]` 与线上字节序的关系必须显式声明。不定这条，`encode.rs`/`decode.rs` 第一行代码就没法写。
2. **未知扩展头的处理规则**。收到注册表外的 NextHeader 编号，是"按 ExtLen 跳过继续解析"还是"丢弃包"？这是 IPv6 里被反复踩过的坑，也直接决定 **CapTag 扩容路径（建议②）能不能向后兼容**——老节点必须能跳过它看不懂的语义标签。
3. **多跳场景的头部保护与可信边界（建议①的规范落点）**。现状：Checkum 已删除，完整性完全依赖隧道层 ChaCha20-Poly1305。但 AEAD 覆盖的是**隧道两端之间**的载荷，而 Phase 3 的 ipv8-routing（Chord + RouteTrace 扩展头类型 5）意味着包要经过**中间节点**。中间节点必须能读甚至改写 DstAddr、HopLimit、NextHeader、扩展头——这些字段落在 AEAD 保护范围之外。规范必须写清楚三件事：
   - 哪些头部字段是"逐跳可变量"（hop-by-hop mutable），哪些是"端到端不可变量"；
   - 中间节点改写头部时，端到端完整性如何验证（改写后是否会破坏上层 AEAD 标签）；
   - RouteTrace / IdentityToken / SecLevel 是否需要 per-hop 签名或每跳 MAC，否则**路由劫持与能力伪造（改 CapTag/SecLevel 冒充高权限节点）在协议层不设防**。
   → 结论：spec 增一节"安全考虑与威胁模型（normative 部分）"，展开的分析另立 `docs/threat-model.md` + ADR-019。
4. **版本协商与 MinCompatVer 的实际行为**。v9 只有"用于版本降级协商"一句。必须定义：节点收到 `MinCompatVer > 自身版本` 的包时是丢弃还是回错、协商在哪一层发生（握手期还是逐包）、协商失败后由谁触发降级。
5. **分片字段的完整定义**。7.8 只说"Phase 2 实现并写入正式版"。但 Fragment 扩展头（类型 6）的**字段布局现在就应进 spec 占位**：偏移量单位（8 字节还是字节）、More-Fragments 位、标识符（Identification）字段放在哪、重组超时、分片包是否允许同时携带其他扩展头。规范里留 TBD 比 Phase 2 现场发明更安全。
6. **HopLimit 语义细节**。每跳减 1、到 0 丢弃已写；未写：初始值由谁决定、中间节点是否允许降低而不丢弃、超限时是否产生错误反馈（有无 ICMP Time Exceeded 等价物）、RouteTrace 节点是否计入跳数。
7. **地址的文本表示与保留值**。128 位地址怎么序列化成字符串（供 DNS 名称、日志、CLI 使用）？ASN=0、HostID=0、DeviceID=0xFFFF 等是否保留？是否存在组播/任意播语义？CapTag=0 是"无能力标签"还是"索引 0"——**这条正是建议②的根，必须先定哨兵值**。
8. **保留/填充字段的收发规则**。字节 39 的"32 位对齐填充"、Flags 位 7-15、地址 Reserved 24 位：必须写成 IPv6 同款措辞——**发送方置 0，接收方必须忽略**。否则严格校验的实现会与未来的字段扩展互相打死。
9. **加密标记与扩展头的一致性**。Flags.E=1 表示载荷已加密，但规范需说明：扩展头是否加密（v9 的扩展头链是明文可解析的，说明不加密）、E=0 时隧道层是否拒绝转发、E 位由谁设置、E 位本身不在 AEAD 内是否可接受。

---

## 三、不写进 protocol-spec.md（逐节去向）

| v9 章节 | 内容 | 为什么不能进规范 | 正确落点 |
| --- | --- | --- | --- |
| §1 | Overlay 定位确认 | 产品/架构定位 | `overlay-design.md` |
| §2 | 五层 + 云端架构图 | 系统分层，非线上格式 | `overlay-design.md` |
| §3 | 关键设计决策 14 行表 | 全是"为什么这样选"，ADR 的典型素材 | 逐条指向 ADR-001~018 + `README.md` 决策摘要 |
| §4 | 依赖方向三条铁律 | 代码组织约束 | `module-contracts.md` / `CONTRIBUTING.md` |
| §5 | 工程目录树、ADR 清单 | 仓库结构，会随重构漂移 | `README.md` |
| §6 | C#↔Rust↔云端 交互图 | 进程间/跨机调用拓扑 | `tunnel-protocol.md`、`module-contracts.md` |
| 7.10 | Rust `IPv8Header`/`IPv8Address` 结构体、`#[repr(C)]`、`new()` 唯一构造入口 | **最该警惕的一条**：这是内存布局不是线上格式。`IPv8Header` 含 `Vec<ExtensionHeader>`，其 `size_of` ≠ 40；把它写进规范会让实现者误以为"结构体就是包头字节"。且 `version: u8`/`min_compat_ver: u8` 是两个 u8，与线上共用 1 字节的 4+4 bit 编码不一致，规范里必须分开描述 | 代码 `header.rs` 注释 + ADR-014（内存布局）、ADR-013（偏移）、ADR-012（PayloadLen） |
| §8 | wintun 读线程 + mpsc + `to_vec()` + 显式 drop | 纯运行时线程模型 | `tunnel-protocol.md` 实现章节 / ADR-003 |
| §9 | 封装 7 步、拆壳 6 步、密钥轮换 1GB/1h、grace 60s | 流程与策略；轮换阈值是实现参数 | `tunnel-protocol.md` + ADR-005；阈值进 `appsettings.json` |
| §10 | `Add-DnsClientNrptRule` 命令、UDP+TCP 53、5353 备用端口、`PortConflictHandler.cs` | Windows 特定机制 + C# 代码 | `deploy/client/setup-nrpt.ps1`、`overlay-design.md`、代码 |
| 10 | `resolver.proto` 的 `ResolveResponse` 五字段 | **契约的权威来源是 .proto，不是文档**；复制进规范必然漂移 | `shared/ipv8-proto/*.proto` 为唯一来源，文档只放生成引用 |
| §11 | 四级降级、2s/8s/5s/3s、重试 2 次、5 分钟降级缓存 | 工程容错策略，与协议无关 | `Fallback` 模块文档 + `appsettings.json`（`FallbackOptions`） |
| §12 | 权限矩阵、`#Requires -RunAsAdministrator`、`Program.cs` 检查、`NrptCleanupService`、`cleanup-nrpt.ps1` | 操作系统与部署约束 | `README.md` 部署章节 + ADR-009/016/017 |
| §13 | `ITunAdapter`/`MockTunAdapter` 代码、Rust≥90%/C#≥80% 门禁 | 测试基建 | `module-contracts.md` + CI 配置 |
| §14 | Phase 0–5 路线图、¥30-50/月、周数 | 项目计划 | `README.md` / 项目管理文档 |
| §15 | 防屎山六条铁律 | 工程文化约束 | `CONTRIBUTING.md` |
| §16 | `setup-dev.ps1` 环境搭建 | 开发环境 | `scripts/` + `README.md` |
| §17 | v5→v9 演进表、"99/100 (A+)"、扣分原因 | 规范是长期契约文档，**不该含自评与版本八卦** | `CHANGELOG.md` / 评审记录 |

---

## 四、灰色地带（必须拆开，各留一半）

这几条 v9 写在一起，但一半是协议、一半是实现，切错就后悔：

1. **MTU/分片（7.8）**
   - 进规范：68B 开销构成、1432/1392 数值、"包总长 ≤ 65467"、Fragment 扩展头格式、MF/偏移语义。
   - 不进：`Set-NetIPInterface`、`install-wintun.ps1`、PMTUD 用哪种 ICMP 实现。
2. **外层封装（§9）**
   - 进规范：一句 normative——"IPv8+ 包承载于 IPv4/IPv6 + UDP 之内，外层字段取值规则见 `tunnel-protocol.md`"。
   - 不进：封装步骤、socket 代码、端口随机化策略。但**若外层 UDP 头之后还有隧道子头（如连接标识/序号）**，那个子头属线上格式，必须进规范或 `tunnel-protocol.md` 之一并交叉引用，不能只存在于 Rust 代码里。
3. **Resolver 返回的 `mtu` / `ipv8_capable`（§10）**
   - 进规范：语义一句（对端建议 MTU、对端是否支持本协议），以及"字段来源为部署配置，不绑定任何公共实例域名"（与 5.3 呼应）。
   - 不进：gRPC message 定义、超时值、SQLite/PG。
4. **SecLevel / CapTag（7.7）**
   - 进规范：字段编码、哨兵值、扩容时改用哪个扩展头承载全文。
   - 不进：谁签发能力标签、信任评估算法（ZoneServer 逻辑 → `overlay-design.md` + ADR-007）。
5. **IdentityToken 扩展头（类型 1）**
   - 进规范：令牌在扩展头内的编码（自包含 JWT / DID 引用）与最大长度。
   - 不进：证书链验证、JWT 签发流程（→ ADR-005 + ZoneServer 文档）。

---

## 五、三条下一步建议：落点与优先级

### ① 多跳头部保护写进威胁模型 —— 成立，优先级最高，成本最低

它同时命中二.2.3（规范缺口）和准入条件 2（不写清就无法实现中间节点）。建议拆两个动作：

- `docs/protocol-spec.md` 新增"安全考虑"小节：逐跳可变字段清单 + 端到端不可变字段清单 + AEAD 覆盖范围（明确"隧道两端"而非"源到目的"）。
- `docs/adr/019-multihop-header-integrity.md`：记录为什么删 CRC32 之后多跳仍需完整性、候选方案（per-hop MAC / RouteTrace 签名 / 只允许源路由不转发）。

**风险点**：Phase 0–2 单跳时这条完全不可见，等 Phase 3 的 Chord 路由跑起来再补，等于要给头部加字段——一旦发包上线，头部就改不动了。这是三条里唯一"现在不写、以后必须破协议"的。

### ② CapTag 扩容路径提前设计 —— 成立，但顺序上排在"未知扩展头跳过规则"之后

逻辑依赖很直接：`扩展头是全文、地址内 16 bit 是索引`这个方案，只有在**老节点能安全跳过它不认识的 SemanticTag 扩展头**时才可行。所以先定二.2.2（未知扩展头跳过 + ExtLen 单位 + 链长上限），再定 CapTag。

落地位置：

- 规范正文：`CapTag` 字段处加 normative——保留值（建议 `0xFFFF` 表示"索引不适用，全文见 SemanticTag 扩展头"）、以及"使用扩展头承载时地址内字段必须置为保留值"。
- 附录（informative）：一张演进图，把"16 bit 是索引 / 扩展头是全文 / 云端 ZoneServer 维护索引表"三层讲清楚。
- ADR-020：为什么选择"扩扩展头"而不是"扩地址到 256 bit"（后者会破 40 字节头与 128 位不可压缩论证）。

顺带收益：同一机制可以解释 Reserved 24 位的用途边界，避免将来有人偷偷往地址里塞新字段。

### ③ 云端组件按可自托管接口设计 —— 成立，但它不是规范问题

归属在架构与 ADR，**唯一需要进规范的只有一句**：本协议不得硬编码任何公共实例的端点、域名或信任根；`.ipv8.net` 命名空间根与 Resolver/ZoneServer 端点均为部署参数。这句话值得写，因为一旦协议里写死根域名，自托管就永久不可能了。

其余落在 `overlay-design.md` + ADR-021，具体抓手（成本都很低，但必须第一天做）：

- **端点全配置化**：沿用 v9 已有的 `appsettings.json` 外部化原则，把云端地址、命名空间根、信任锚列成部署 profile。
- **proto 去厂商化**：message 里不出现云厂商特定字段、不出现"账号体系"耦合；版本用 package 前缀而非新增不兼容字段。
- **存储抽象**：SQLite 与 PostgreSQL 双方言可用（v9 的 ADR-010 已识别并发限制，正好在这里收口为"接口 + 两个实现"）。
- **信任锚可插拔**：`CertificateService`/`JwtService` 的根证书与签发者作为配置输入，自托管即换根，不改代码。
- **协议层无状态依赖**：Resolver 挂掉时客户端行为要能纯靠本地缓存 + Fallback 走完（v9 §11 已具备，只需在文档里点明"这同时是断网与自托管迁移的能力"）。

**优先级判断**：① 必须现在做（否则破协议）→ ② 在定稿前做（只需一段文字 + 一个保留值）→ ③ 与 Phase 1 云端最小版本同步做（改动成本随代码量线性增长，但技术风险最低）。

---

## 六、v9 文档本身需复核的两处

1. **§12.4 `cleanup-nrpt.ps1` 的"已修正"仍有疑点**。v9 声称"实际代码已修正"，但其修正清单表格与代码块中的 `$rules =`、`foreach ($rule in $rules)`、`$_.Namespace`、`$($rule.Name)` 等位置的 `$` 与空格，在我这次从 PDF 提取出的文本里仍显示为 `foreach (ruleinrules)`、`已清理 NRPT 规则: (rule.Name)`。这可能是 PDF 排版/文本提取丢失，也可能文档确实残留。建议以仓库里的 `.ps1` 真身为唯一准，并在文档里改成指向脚本文件而不是内联粘贴——内联代码块正是这类"声称已修正"反复出现的根源。
2. **§17 演进表若干单元格串行错乱**（如 NRPT 清理一行出现 `ProcessIEHxoistt` / `eAdsSyenrcviceIH.Sotospt` 这类字符交叉），表格在 PDF 里已被压缩重排。若这份 PDF 要作为方案存档，建议表格改为纵向列表或转 Markdown 表格存放于仓库。

---

## 七、一页速查：spec 的最终目录骨架

```
1. 引言（范围、术语、Normative/Informative 约定）
2. 约定：字节序与位序、保留字段收发规则、对齐与非对齐访问   ← 新增
3. IPv8+ 地址格式（128 位）+ 文本表示 + 保留值 + CapTag 哨兵与扩展路径  ← 新增
4. 基础包头（40 字节）：布局图 + 逐字段偏移与语义
5. Flags 位定义
6. 扩展头：通用格式 → 链式解析与跳过规则（含未知编号）→ 最大链长/ExtLen 上限 → 类型注册表 + 编号分配规则   ← 新增
7. 载荷（Payload）：IP-in-IP 语义、外层封装指向 tunnel-protocol.md、虚拟 IP 空间
8. MTU、开销与分片：68/1432/1392、≤65467、Fragment 扩展头字段（Phase 2 前定布局）
9. 版本与兼容性：Version、MinCompatVer 协商行为、降级路径的协议侧规则   ← 新增
10. 安全考虑（normative）：AEAD 覆盖范围、逐跳可变 vs 端到端不可变字段、多跳完整性、E 位语义   ← 新增
11. 附录 A：设计论证（地址不可压缩、为何删 CRC32）
12. 附录 B：与 IPv4/IPv6 差异对照
```
