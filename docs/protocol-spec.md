# IPv8+ 协议规范（protocol-spec.md）

版本：0.1.0（Phase 0 定稿候选） ｜ 状态：Normative
关键词 MUST / MUST NOT / SHOULD / MAY 的含义遵循 RFC 2119。

判据：**换一个语言实现、换一个厂商部署，这条内容还成立吗？** 成立才进本文。
实现细节（线程模型、脚本、超时参数、gRPC message）一律在
`docs/tunnel-protocol.md`、`docs/overlay-design.md`、ADR 与代码中。

---

## 1. 引言

IPv8+ 是叠加网络（Overlay）的封装协议：IPv8+ 包承载于 IPv4/IPv6 + UDP 之内
（外层封装规则见 `tunnel-protocol.md`），对底层网络透明。

本文规定：地址格式、基础包头、Flags、扩展头机制、载荷语义、MTU 与长度约束、
版本兼容规则、安全考虑。

## 2. 约定

### 2.1 字节序与位序（normative）

- 所有多字节整数字段（Flags、PayloadLen、ASN、HostID、DeviceID、CapTag、
  扩展头 ExtLen 计数等）一律**网络字节序（大端）**。
- 共用一个字节的位域：**高 4 位在前**。字节 0 的 bit 7-4 为 Version，
  bit 3-0 为 MinCompatVer。
- 线上格式的权威定义是字节偏移表（§4.2），与任何语言的内存布局无关。
  实现体的结构内存布局（如 Rust `#[repr(C)]`）不得写入本文。

### 2.2 保留字段的收发规则（normative，IPv6 同款）

适用于：Flags 位 7-15、基础包头字节 39（对齐填充）、地址 Reserved 24 位。

- 发送方 MUST 将保留位置 0。
- 接收方 MUST 忽略保留位，MUST NOT 因其非零而丢弃数据包。
- 保留位未来可被分配新语义；分配后旧实现按"非零也忽略"继续互通。

## 3. IPv8+ 地址格式（128 位）

### 3.1 字段布局（线格式，大端）

| 偏移（地址内） | 字段 | 位宽 | 说明 |
| --- | --- | --- | --- |
| 0-3 | ASN | 32 | 自治系统号 |
| 4-7 | HostID | 32 | 主机标识 |
| 8-9 | DeviceID | 16 | 设备标识 |
| 10-11 | CapTag | 16 | 能力标签（索引，见 3.4） |
| 12 | SecLevel | 8 | 安全等级 |
| 13-15 | Reserved | 24 | 保留，发送置 0，接收忽略 |

### 3.2 文本表示（normative）

- **规范形式（canonical）**：地址 16 字节按大端顺序写成 32 个小写十六进制数字，
  无分隔符，不压缩零。例：`010203040a0b0c0d112233440200` + Reserved 6 位。
- 显示形式 MAY 采用分层写法 `asn.host_id.device_id:cap_tag:sec_level`（十进制或
  0x 十六进制由上层文档约定），但解析与持久化 MUST 以规范形式为准。

### 3.3 保留值（normative）

| 值 | 语义 |
| --- | --- |
| ASN = 0 | 保留，不得分配 |
| HostID = 0 | 保留，不得分配 |
| DeviceID = 0xFFFF | 保留：任意播（本节点任一设备） |
| CapTag = 0xFFFF | **哨兵**：地址内索引不适用，能力全文见 SemanticTag 扩展头（§3.4） |
| SecLevel = 0 | 公开/无等级 |

### 3.4 CapTag 语义与扩容路径（normative + informative）

- CapTag（16 bit）是 ZoneServer 维护的**能力索引表**中的短索引，不承载语义全文。
- 当能力描述超出 16 bit 索引表达能力时，节点 MUST 置 CapTag = 0xFFFF，
  并在包中携带 SemanticTag 扩展头（类型 2）承载全文（最小格式 §6.8）。
- 老节点 MUST 能按 ExtLen 跳过不认识的 SemanticTag 载荷（§6.2），
  据此把 CapTag 解释为"索引未知"而非丢弃包。

> 附录 A：为什么选"扩扩展头"而不是"扩地址到 256 bit"——后者破坏 40 字节头、
> 128 位不可压缩论证与所有既有解析器。详见 ADR-020。

## 4. 基础包头（40 字节固定）

### 4.1 布局图

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Ver  |MinCompat|              Flags (16)                       |  字节 0-2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          PayloadLen (16)      |  HopLimit (8) | NextHdr (8)  |  字节 3-6
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                    SrcAddr (128)                              |  字节 7-22
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                    DstAddr (128)                              |  字节 23-38
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  对齐填充 (8) ：发送置 0，接收忽略                              |  字节 39
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  扩展头链（可变长度，NextHdr ≠ 0 时存在）                       |  字节 40+
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

字段偏移严格连续（无幽灵字节）：PayloadLen 位于**字节 3-4**，HopLimit 字节 5，
NextHeader 字节 6，SrcAddr 字节 7-22，DstAddr 字节 23-38。

### 4.2 字段说明

| 字段 | 偏移 | 大小 | 规则 |
| --- | --- | --- | --- |
| Version | 0 (7-4) | 4 bit | 固定 0x8；不等于 0x8 的包 MUST 丢弃 |
| MinCompatVer | 0 (3-0) | 4 bit | 发送方要求的最低兼容版本（§9） |
| Flags | 1-2 | 16 bit | §5 |
| PayloadLen | 3-4 | 16 bit | 载荷字节数（不含包头与扩展头），≤ 65467（§8.2） |
| HopLimit | 5 | 8 bit | §4.3 |
| NextHeader | 6 | 8 bit | 首个扩展头类型编号；0 = 无扩展头 |
| SrcAddr / DstAddr | 7-22 / 23-38 | 128 bit | §3 |
| 填充 | 39 | 8 bit | §2.2 收发规则 |
| ExtHeaders | 40+ | 可变 | §6 |

### 4.3 HopLimit 语义（normative）

- 初始值由**发送方**决定，默认建议 64。
- 每个转发节点 MUST 将其减 1；减到 0 的包 MUST 丢弃，并 MAY 向源点回送
  超限控制消息（控制消息格式属 `tunnel-protocol.md`，等价 ICMP Time Exceeded）。
- 中间节点 MUST NOT 主动改写非零 HopLimit 为其他值（只允许减 1）。
- 携带 RouteTrace 扩展头的节点**计入跳数**（每个读取/追加点即一跳）。

## 5. Flags 位定义

| 位 | 名称 | 规则 |
| --- | --- | --- |
| 0-3 | QoS Level | 0=尽力而为，15=最高优先级；转发节点 MAY 据此调度 |
| 4 | E (Encrypted) | §5.1 |
| 5 | F (Fragment) | 1 = 本包是分片（§8.3） |
| 6 | X (Extension) | 1 = 存在扩展头链；与 NextHeader≠0 语义一致，冲突时 MUST 丢弃 |
| 7-15 | Reserved | §2.2 |

### 5.1 E 位语义（normative）

- E 位仅描述 **Payload 字段**的加密状态；扩展头链始终明文（可被中间节点解析，
  这是 RouteTrace/Fragment 可工作的前提）。
- E 位由隧道层发送方设置（AEAD 加密载荷后置 1；套件为
  ChaCha20-Poly1305 或 AES-256-GCM，见 ADR-025）。
- E 位在 AEAD 保护范围之外（§10.2），因此它只是**提示位**：接收方以解密
  实际成败为准，MUST NOT 单独依据 E 位做安全决策。
- 部署策略 SHOULD 规定：要求加密的隧道收到 E=0 的包直接丢弃（策略而非协议强制）。

## 6. 扩展头

### 6.1 通用格式

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  NextHeader(8)|   ExtLen(8)   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      载荷（ExtLen × 8 字节）    |
```

- ExtLen 单位为 8 字节；ExtLen MUST ≥ 1（载荷 0 长度非法）。
- 扩展头链 MUST NOT 超过 **64** 个头（防解析放大攻击）。

### 6.2 链式解析与跳过规则（normative）

- 解析从基础包头 NextHeader 开始；每个扩展头内 NextHeader 指向下一个头类型，
  **0 终止链**。
- 接收方遇到**注册表外的类型编号**：MUST 按 ExtLen 完整跳过该头继续解析，
  MUST NOT 丢弃数据包。
- 类型编号出现回路（同一编号在链中出现两次）：MUST 丢弃。
- 基础包头 NextHeader、X 位与链首必须三者一致，否则 MUST 丢弃。

### 6.3 类型注册表与分配规则

| 编号 | 名称 | 载荷 |
| --- | --- | --- |
| 0 | None（链尾哨兵，不得作为成员） | — |
| 1 | IdentityToken | §6.4 |
| 2 | SemanticTag | §6.8（Phase 4 定稿） |
| 3 | QoSReservation | §6.5（Phase 3 定稿） |
| 4 | AgentCard | §6.7（Phase 4 定稿） |
| 5 | RouteTrace | §6.6（Phase 3 定稿） |
| 6 | Fragment | §8.3 |
| 7-127 | IETF 式评审分配 | 需协议文档 |
| 128-255 | 实验/私有使用 | 不保证互通 |

新增编号 MUST 保持 §6.2 的跳过行为可用，禁止发明"必须理解否则丢包"的
强制性头类型（如确有需要，走版本号变更）。

### 6.4 IdentityToken 编码边界

令牌在扩展头内为自包含结构（不透明字节，最大 255×8 字节超限则分片），
内容格式（JWT/DID）由 ZoneServer 文档定义，本协议只保证承载。

### 6.5 QoSReservation（类型 3）布局（normative，Phase 3 定稿）

ExtLen = 1（8 字节载荷，64 bit 严格对齐）：

载荷 8 字节（ExtLen = 1），字段按字节偏移：

| 偏移 | 字段 | 位宽 | 说明 |
| --- | --- | --- | --- |
| 0-2 | TokenBucketRate | 24 | 速率承诺，单位 KiB/s，大端；0 = 仅提示无承诺 |
| 3-4 | BurstSize | 16 | 突发字节数；0 时速率承诺不生效 |
| 5 | QueueHint | 8 | 建议转发队列类（0-15） |
| 6-7 | Reserved | 16 | §2.2 收发规则 |

- QueueHint 与 Flags 的 QoS Level（§5）独立；二者不一致时转发节点 MAY
  以任一为准（均为提示，不做安全决策）。
- 中间节点对未实现承诺语义的本头 MUST 只读或忽略，MUST NOT 修改载荷。

### 6.6 RouteTrace（类型 5）布局（normative，Phase 3 定稿）

载荷 = `104 + 16×N` 字节（ExtLen = 13 + 2N，N = 1..64）：

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     SrcPubKey (256)                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      PathSig (512)                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  HopCount(8)  | InitHopLimit(8)|        Reserved (48)         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    NextHop[0] (128)                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          ... (共 HopCount 项)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **源路由 + 路径签名**（ADR-019 决议）：路径由源点完整指定，中间节点只按
  签名执行，不自主路由。
- 携带 RouteTrace 的包，RouteTrace MUST 位于扩展头链首（基头 NextHdr = 5）。
  PathSig 覆盖基头 NextHdr 但不覆盖链内指针，链首约束使"把 RouteTrace
  挪出链首/重排链"必然破坏 §6.2 三者一致性而被丢弃。
- SrcPubKey：源点 Ed25519 公钥（即 Phase 2 证书体系的 verify_key）。它与
  SrcAddr 的绑定证明（源证书：`addr ‖ pubkey ‖ not_after ‖ CA 签名`，
  120 字节线格式）MUST 经链中 **IdentityToken 扩展头（类型 1）**随包携带
  （§6.4 令牌承载约定的具体化）；中转/目的地用本地信任锚验证该证书，
  无需在线查询。多跳包缺 IdentityToken 头或证书验不过 → MUST 丢弃。
- InitHopLimit：源点发出时刻的 HopLimit 值（基头同值发出，源点不自减）。
  HopLimit 逐跳递减属 §10.2 可变量，故签名字段取 RouteTrace 内这份
  **不被改写的副本**；中转/目的地节点校验
  `当前 HopLimit == InitHopLimit − k`（k = 本机在 NextHopList 的下标，0 基，
  与 IP 语义一致：只有转发节点减 1，目的地不再减），被拉伸或压缩跳数
  预算的包即被拒。转发节点减 1 后 HopLimit 为 0 时 MUST 丢弃（§4.3）。
- PathSig：对以下消息体的 Ed25519 签名（域分隔防挪用到注册/轮换签名）：
  `"ipv8plus-routetrace" ‖ SrcPubKey(256) ‖ Version(4bit)‖MinCompatVer(4bit)‖
  Flags(16)‖PayloadLen(16)‖InitHopLimit(8)‖NextHdr(8)‖SrcAddr(128)‖
  DstAddr(128)‖HopCount(8)‖NextHopList(128×HopCount)`
  ——SrcPubKey 入签消除"同一 PathSig 对替换后的新公钥仍有效"的延展性；
  其余覆盖全部端到端不可变字段（§10.2）+ 初始跳数预算 + 路径本体。
- HopCount：下一跳列表长度，协议上限 **64**（载荷上限），部署 SHOULD 配 ≤ 8；
  HopCount=0 非法（MUST 丢弃）。
- NextHopList：第 i 项 = 从源点起第 i+1 跳的 IPv8+ 地址（末项 MUST 等于 DstAddr）。
- 转发节点（本机 = NextHop[k]）MUST：验证 PathSig → 校验 HopLimit 与跳位
  一致（见上条）→ 按 NextHop[k+1] 转发并**对基头 HopLimit 减 1**。任一步
  失败 MUST 丢弃并计数。目的地（本机 = 末项）MUST 验证 PathSig 后交付载荷；
  交付路径不减 HopLimit（与 IP 语义一致）。
- 中间节点 MUST NOT 改写 HopCount/NextHopList/SrcPubKey/PathSig 中任何字段。
- 携带 RouteTrace 的包被分片时，RouteTrace MUST 位于链首随首片传输（§8.3 规则）。
- 逐跳审计签名（每跳追加）是本布局的后置扩展：新字段走链中追加第二个
  RouteTrace 实例（类型 5 在链中出现两次的回路规则须先经版本变更修订），
  本轮不定义。

### 6.7 AgentCard（类型 4）布局（normative，Phase 4 定稿，ADR-023）

**摘要进包 + ANS 拉全文**：包内头只承载卡片指纹，全文（JSON：
name/capabilities/endpoints/qos/expiry）存 ANS，接收方按摘要经 ANS 取回
并校验哈希绑定。载荷 128 字节（ExtLen = 16，8B 严格对齐）：

| 偏移 | 字段 | 位宽/大小 | 说明 |
| --- | --- | --- | --- |
| 0 | Version | 8 | 卡片格式版本，当前 = 1 |
| 1-7 | Rsv | 56 | §2.2 收发规则 |
| 8-23 | CardHash | 128 | SHA-256(全文规范字节) 前 16 字节 |
| 24-31 | NotAfter | 64 | 卡片有效期（epoch 秒）；=0 视为已过期 |
| 32-63 | AgentPubKey | 256 | 智能体 Ed25519 公钥（ANS 注册的同一密钥） |
| 64-127 | CardSig | 512 | Ed25519 签名 over `"ipv8plus-agentcard" ‖ Version ‖ CardHash ‖ NotAfter ‖ AgentPubKey` |

- CardSig MUST 由智能体自身密钥签发（非 CA）：无签名时，攻击者可把
  CardHash 换成受害卡片的合法值实现冒充投递——签名是唯一把"这个哈希"
  绑定到"这个 agent"的手段，接收方验不过即丢包。
- 验证链：接收方验 CardSig（用头内 AgentPubKey）→ 检查 NotAfter → 按
  CardHash 向 ANS `GetAgent(name)` 取全文 → 重算哈希必须逐字节匹配。
  本头自身不含 name；name 由上层通道（会话建立/任务投递上下文）携带，
  或以 CapTag=0xFFFF + SemanticTag 头共存时按 ANS 反查。
- 本头 MUST NOT 被中间节点改写；是否消费由部署策略决定（协议层只保证
  完整性，不强制转发节点理解其语义——§6.2 跳过规则照常适用）。
- 多跳包同时携带 RouteTrace 与 AgentCard 时，链序 MUST 为
  Fragment(6, 仅分片包) → RouteTrace(5) → IdentityToken(1) →
  AgentCard(4) → SemanticTag(2)，每类至多一个（§6.2 回路规则不变），
  与 §6.6 链首约束一致。

### 6.8 SemanticTag（类型 2）最小格式（normative，Phase 4 定稿）

- 载荷 = UTF-8 编码的能力标签列表，以单个 `US`(U+001F) 分隔：
  `tag1 US tag2 US … US tagN`（末项后无分隔符）。
- 每个标签：1..=48 字节，MUST 为小写 ASCII 字母/数字/连字符（`a-z0-9-`），
  MUST NOT 以连字符开头/结尾；标签总数 1..=32；载荷总长 MUST ≤ 1536
  （= 192×8，留余量给同链其他头）。
- 接收方解析规则：非 UTF-8、含控制字符（唯一允许的 US 除外）、标签超限
  → MUST 忽略本头全部内容（按 §6.2 跳过），MUST NOT 丢包。
- 语义：全文标签与 ANS 能力索引同源——ANS 注册校验同一格式，
  包内携带时供目的地本地匹配，不经 ANS 往返。

## 7. 载荷（Payload）

- IPv8+ Payload 承载**完整原始 IP 包**（IPv4 或 IPv6，即 IP-in-IP）。
  内层协议由载荷首字节高 4 位（4=IPv4，6=IPv6）识别；其他值视为非 IP 载荷，
  交由上层处理。
- 外层封装（UDP 端口、隧道子头）见 `tunnel-protocol.md`；若外层含隧道子头，
  该子头在线上格式的权威定义也必须在 `tunnel-protocol.md` 中，本文交叉引用。
- 虚拟 IP 地址空间：Overlay 内层使用 `100.64.0.0/10`（CGNAT 范围）。

## 8. MTU、长度与分片

### 8.1 封装开销

IPv4 头 20 + UDP 头 8 + IPv8+ 基础头 40 = **68 字节**。
标准以太网 1500 MTU 下，IPv8+ 包上限 **1432 字节**，
有效载荷（无扩展头）上限 **1392 字节**。

### 8.2 长度约束（normative）

- 包总长 = 40 + 扩展头总长 + PayloadLen。
- PayloadLen ≤ **65467**（= 65535 − 20 − 8 − 40），保证封装进 IPv4/UDP
  不超 IPv4 总长上限。
- 超出上述约束的包 MUST 在发送前被拒绝构造，接收方 MUST 丢弃越界包。

### 8.3 Fragment 扩展头（类型 6）布局（normative，Phase 2 实现）

ExtLen = 1（8 字节载荷）：

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Identification (32)                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|R(3)|         Offset (13)     | Rsv (2) |M F (1)| Rsv (16)     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- Offset 单位 **8 字节**（与 IPv4 一致），即分片边界必须 8 字节对齐；
  13 bit 可表达 65528 字节，覆盖 PayloadLen 上限 65467。
- MF=1 表示还有后续分片；MF=0 为该 Identification 的最后一片（且必须
  是偏移最高的一片，接收方据此判断重组完成）。
- Flags.F（位 5）与扩展头的存在性 MUST 一致：F=1 ⇔ 链中含 Fragment 扩展头。
  接收方 MUST 丢弃 F=1 但无 Fragment 头、或 F=0 但带 Fragment 头的包。
- 重组超时 SHOULD 为 30 秒（部署参数），超时丢弃全部未重组分片。
- 分片包 SHOULD NOT 携带除 Fragment/IdentityToken 之外的其他扩展头。
- 每片 MUST NOT 超过链路 MTU；接收方对片长非 8 字节对齐（末片除外）MUST 丢弃。

## 9. 版本与兼容性

- Version 4 bit 固定 0x8；不匹配直接丢弃（演进走新协议号，不做原地升版）。
- MinCompatVer（§4.2）：
  - 节点收到 `MinCompatVer > 自身版本` 的包：MUST 丢弃（无法降级兼容）。
  - `MinCompatVer ≤ 自身版本`：MUST 接受并按自身版本处理。
  - 协商发生在**逐包判断 + 隧道握手层**：握手期双方交换版本，
    无法兼容则不建隧道，降级路径由 Fallback 模块负责（策略见实现文档）。

## 10. 安全考虑（normative 部分）

### 10.1 完整性现状

基础包头**无 Checksum**。载荷完整性依赖隧道层 AEAD
（ChaCha20-Poly1305 / AES-256-GCM，套件选择见 ADR-025）。

### 10.2 AEAD 覆盖范围（normative 声明）

- AEAD 保护的是**隧道两端之间**的载荷密文，**不覆盖** IPv8+ 基础包头与扩展头。
- 字段可信边界：

| 类别 | 字段 | 规则 |
| --- | --- | --- |
| 逐跳可变量 | HopLimit、RouteTrace 载荷、外层 IP/UDP | 中间节点合法改写，端到端不可信 |
| 端到端不可变量 | Version、Flags、PayloadLen、SrcAddr、DstAddr、CapTag、SecLevel | 中间节点 MUST NOT 改写；**但协议层当前无防改写手段**（见 10.3） |
| 仅提示位 | E、F、X 之外的语义由所在层负责 | — |

### 10.3 多跳完整性（Phase 3 已闭环）

Phase 1-2 单跳（隧道两端 = 源和目的），包头在 AEAD 之内，风险不显。
Phase 3 引入多跳后，**ADR-019 已决议**：要求转发的包 MUST 携带 RouteTrace
扩展头（§6.6）——源点对全部端到端不可变字段与路径本体做 Ed25519 签名，
中转/目的地各验一次；验证失败 MUST 丢弃。上表"端到端不可变量"自 Phase 3
起由 PathSig 提供协议层防改写手段。
不携带 RouteTrace 的包在多跳网络上 MUST NOT 被转发（单跳隧道内不受此限）。

### 10.4 部署中立性（normative）

本协议**不得硬编码任何公共实例的端点、域名或信任根**。`.ipv8.net` 命名空间根、
Resolver/ZoneServer 端点、证书信任锚均为部署参数（见 ADR-021 自托管设计）。

## 11. 附录 A：设计论证（informative）

- 地址不可压缩：ASN 32 + HostID 32 = 64 bit 已占一半，DeviceID 16 + CapTag 16
  + SecLevel 8 = 40 bit 无处安放，故保持 128 bit。
- 删 CRC32：隧道 AEAD 已提供认证加密，头部校验位收益低；IPv6 同思路。
  多跳场景的补偿方案见 ADR-019。
- CapTag 扩容走扩展头索引间接寻址，见 ADR-020。

## 12. 附录 B：与 IPv4/IPv6 差异对照（informative）

| 维度 | IPv4/IPv6 | IPv8+ |
| --- | --- | --- |
| 头长 | 20/40 | 40（固定 + 扩展链） |
| 校验 | 头校验和 | 无（依赖 AEAD） |
| 分片 | IPv4 头字段 | Fragment 扩展头 |
| 能力语义 | 无 | CapTag 索引 + SemanticTag 全文 |
| 版本协商 | 无 | MinCompatVer 逐包 + 握手 |
