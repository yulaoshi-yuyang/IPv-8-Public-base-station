# IPv8+ 架构总览与后续方案

> 版本：v2.1 / 2026-09-18（v2.0 基于仓库代码逐文件核对；v2.1 据 Hyper-V 双机真机实测回写）
> 核对方式：workspace 成员、驱动 C 源码、ping8 命令面、specs/tasks、dist 产物逐项对表 + 双 VM 实测。

---

## 1. 一页结论

**定位**：安全合格入场（X25519 握手、ChaCha20-Poly1305/AES-GCM AEAD、防重放、证书三验），
差异化竞争三点——**快**（RIO 用户态数据面、多路径竞速、FEC）、**全**（未修改程序经
wintun 直接跑）、**自由**（钩子判决、规则与路径全部用户态可编程）。
物理边界不变：**局域网做真协议（EtherType 0xFB14 裸帧），广域网做加密叠加层（UDP/WebSocket）**。

**截至今天的真实状态**：

1. Phase 1–5A（钩子、RIO、兼容、多路径/FEC、驱动只读可见性）代码完成且经历过实测。
2. Phase 5B（二层裸帧 + 邻居发现）代码全部落地，**本机 + Hyper-V 双机真机实测均通过**（驱动
   v0.11 六个 IOCTL、`ping8 l2`、ipv8-neigh 库 23 个单测、`ping8 neigh`）。两处与原 spec
   不同的事实仍成立：
   - **邻居发现走 UDP 45802 广播/单播（纯用户态，免驱动免管理员）**，不是 spec 写的 0xFB14
     裸帧（L2 承载推迟到 P8）。本机 20/20、双机 hello/watch/ACK 双向入表均实测通过。
   - **驱动侧 0xFB14 收发管道目前没有协议消费者**，由 `ping8 l2` 手工验证；`wintun-node`
     没有 `--l2`（P8 才做）。
3. **双机真机实测（tasks 6.5）已于 2026-09-18 全部完成**（Hyper-V 双 VM，Private 交换机，
   测试签名）：L2 双向裸帧字节级正确、UDP 邻居授权双向入表、N 拒绝不入表不应答、杀进程后
   neighbors.bin 留存、卸载后服务/注册表/设备节点/sys/dll/DriverStore 全部清零、重装恢复；
   **全程 0 蓝屏（严格核对 BugCheck 事件）**。workspace 420 passed / clippy `-D warnings` 通过。
   双机实测额外暴露并修复了驱动与打包链的四个真问题（详见 §4.2、§8 P6）。
4. `dist/driver/` 产物 8 文件齐全（sys/dll/inf/cat/cer/ping8.exe/安装.ps1/卸载.ps1），
   安装脚本装后自动启动（inf 已改 AUTO_START），卸载脚本对称清理。
5. 用户已决策：**P7b 内核驱动 Attestation 签名（blocked，需真实 EV 证书）**、
   **P8 邻居双轨收敛 + `node --l2`**（待开工）、**P9 服务化**（待开工）。
   P7a（自签 EV 工具）已闭环——用户态 .exe/.dll 签名美化 + 跨机信任分发。
   **P9.1 双 exe 拆分已落地**：Cargo 双 bin 同 main.rs，按 exe 文件名（ping8/ipv8adm）
   做命令白名单分割（ping8 禁 l2/driver/hook），见 §6.1。

**下一步（详见 §8）**：P6 已闭环 → P7a 自签 EV 工具已闭环（用户态签名美化，不覆盖内核）→
P7b 内核 Attestation 签名 blocked（需真实 EV 证书）→ P8 邻居双轨收敛 + `node --l2` 数据面（代码已完成，待真机验证）→
P9.2 Windows 服务化 + P9.3 `ping8 auto` 一键流程（P9.1 双 exe 拆分已完成）。

---

## 2. 仓库全景（2026-09-13 代码实况）

```
┌──────────────────────────── 用户机（Windows） ───────────────────────────┐
│ 未修改应用 ── wintun 虚拟网卡 ── ipv8-node（Rust 用户态数据面）             │
│                                   │                                       │
│        ping8.exe（签证/防火墙/信任/邻居/l2/driver/hook/serve/自更新）       │
│                                   │                                       │
│        ipv8proto.sys（NDIS 6.30 协议驱动 v0.11，0xFB14）+ ipv8prop.dll     │
└───────────────┬───────────────────────────────────────┬──────────────────┘
                │ UDP 45700（默认隧道，可改）             │ EtherType 0xFB14（局域网，待接协议）
                ▼                                         ▼
        广域叠加路径（NAT/中继/Cloudflare WS）      局域网真二层路径（管道已通、无消费者）
                │
   ┌────────────┴──────────── 服务侧（可选，自建） ────────────┐
   │ zoneserver:7070  resolver:7080  ans:7090（Rust + gRPC）    │
   │ portal: HTTP 9001 + DNS 5353 + DHCP（PowerShell + Web UI） │
   └───────────────────────────────────────────────────────────┘
```

| 组件 | 位置 | 形态 | 现状（代码核对） |
|---|---|---|---|
| 帧编解码 | `src/core/ipv8-codec` | Rust 库 | 40B 帧头/magic 0xFB14、握手帧、分片、版本兼容 |
| 路由 | `src/core/ipv8-routing` | Rust 库 | 静态路由、路由追踪、连接转发（cf） |
| QoS | `src/core/ipv8-qos` | Rust 库 | DSCP 分类、预留、调度器（FEC 门控复用其分类） |
| 隧道引擎 | `src/core/ipv8-tunnel` | Rust 库 | 握手、双 AEAD 套件、CA 证书三验、防重放、防滥用、中继故障切换、fallback；含 loopback/多跳/模糊/bench 测试 |
| gRPC 客户端 | `src/core/ipv8-grpc` | Rust 库 | 与云侧三件套通话 |
| 静态防火墙 | `src/core/ipv8-firewall` | Rust 库 | 协议/端口/源前缀/转发规则，供节点与 forwarder 使用 |
| 外部判决钩子 | `src/core/ipv8-hook` | Rust 库 | 环回 NDJSON（默认 45810/TCP）、流卸载、50ms 超时兜底、背压隔离，13 个测试 |
| 兼容处理 | `src/core/ipv8-compat` | Rust 零依赖库 | TTL 扣减、ICMP 回注、MSS 钳制、组播分类，38 个测试，热路径 ~11ns/包 |
| 前向纠错 | `src/core/ipv8-fec` | Rust 零依赖库 | K 帧 XOR 恢复（Type=6），18 个测试，发送侧 ~154ns/帧 |
| 邻居发现 | `src/core/ipv8-neigh` | Rust 零依赖库 | **IP8N 136B 报文、Ed25519 trait 注入、防重放、邻居表落盘，23 个测试；与传输无关** |
| C FFI | `src/core/ipv8-ffi` | Rust 库 | Phase 0 产物，当前非主路径 |
| 节点守护 | `src/adapter/wintun-node` → `ipv8-node.exe` | Rust 二进制 | TUN↔引擎↔UDP 全链路 + RIO（§3）；**无 `--l2`** |
| 用户客户端 | `src/tools/ipv8-client` → `ping8.exe` v3 | Rust 单文件 | 约 4100 行，命令面见 §6；启动即静默查门户自更新 |
| 透明转发 | `src/tools/ipv8-forward` | Rust 二进制 | 读防火墙规则做 TCP/UDP 端口转发（"节点是空气"） |
| 网络实测 | `src/tools/ipv8-netbench` | Rust 二进制 | NAT 类型/打洞成功率/吞吐/延迟/丢包 |
| WS 桥节点 | `src/tools/ws-node` | Rust 二进制 | serve/connect/relay 三模式，经 Cloudflare 承载 AEAD 帧，CA 验身份 |
| NDIS 驱动 | `src/driver/ipv8proto` → `ipv8proto.sys` | C / WDK | v0.11：6 个 IOCTL（含调试 INJECT）、0xFB14 双重过滤、收包 packet filter、有界帧池、CSQ（§4） |
| 属性页 | `src/driver/ipv8prop` → `ipv8prop.dll` | C++ COM | 已同步 180B ABI，显示版本/绑定/MAC/计数 |
| 云：ZoneServer | `src/cloud/zoneserver` | Rust + gRPC :7070 | 根 CA/JWT、区域注册 |
| 云：Resolver | `src/cloud/resolver` | Rust + gRPC :7080 | 名称注册解析，内存/SQLite/DHT 三套 store，mimalloc |
| 云：ANS | `src/cloud/ans` | Rust + gRPC :7090 | 权威名服务，信任锚验注册证书，有测试向量 |
| 门户 | `deploy/portal/` | PowerShell + 静态 Web | HTTP 9001 + DNS 5353 + DHCP 三合一；UI 含拓扑/向导/GeoIP/分配表；分发 ping8 安装包与版本号（自更新源） |
| 部署脚本 | `deploy/client`、`scripts/`、`dist/driver` | PowerShell | wintun 安装、NRPT、防火墙、驱动打包/安装/卸载（便携自定位）、跨机/环回验证 |
| C# 旧栈 | `src/adapter/wintun`(C#)、`src/services/*`、`tests/services` | .NET | **保留为非主路径组件**：36 个测试全过，含 AgentMesh↔Rust AnsService 共享测试向量逐步骤核对、tunnel.proto 冻结面、QoS 并发契约。数据面主路径已由 Rust 接管；C# 栈定位为跨语言一致性测试 + 未来服务化（Windows Service）参考骨架。CI 持续验证 |
| ~~孤立件~~ | ~~`src/tools/ipv8-toolkit`~~ | ~~Cargo.toml~~ | ~~已删除（无 src、不在 workspace、无引用）~~ |

workspace 统一 release 配置：`lto=true / codegen-units=1 / strip / panic=abort`，支撑单文件小体积发布。

---

## 3. 数据面现状（ipv8-node）

### 3.1 出站/入站流水线

```
出站：TUN 批量收包 → 钩子判决（可选）→ compat 处理（可选）→ QoS 分类
      → FEC 组帧（可选）→ AEAD 密封 → 单路/双路（--mp）UDP 发送（std 或 RIO）
入站：UDP 收割（std 双线程 / RIO 单事件循环）→ FEC 重建（可选）→ AEAD 验签+防重放
      → 入口集合判定/两级凭据迁移 → 钩子判决（可选）→ 入站 MSS 钳制（可选）→ 写回 TUN
```

### 3.2 功能开关矩阵（铁律：默认全关，不带参数 = 逐字节零回归）

| 开关 | 能力 | 备注 |
|---|---|---|
| `--rio on\|auto\|off` | RIO 极速收发，默认 auto | 火绒(sysdiag.sys)/360 钩子拦截 10045 时自动回退 std 并具名提示；真性能数据须干净环境 |
| `--cipher chacha\|aes` | AEAD 套件 | 两端必须一致，不协商；HKDF 会话缓存 |
| `--hook [addr] --hook-timeout --hook-policy accept\|drop --hook-payload N` | NFQUEUE 式外部判决 | 环回默认 45810；fail-open 默认；流 TTL 卸载 |
| `--compat [--mss-clamp N]` | TTL/ICMP/MSS/组播路由器行为 | effective_mtu=1432−40=1392；MSS v4=1352/v6=1332 |
| `--migrate` | WiFi↔4G 出口迁移不断连 | 强凭据（AEAD 帧/证书三验）立即刷新，弱凭据 10s 限速；两端同开 |
| `--mp --alt-ip/--alt-port` | 双路径包级竞速 | 复用防重放窗口去重；与 `--fallback` 互斥；丢包 p→≈p² |
| `--fec [--fec-k 2..16]` | DSCP≠0 低延迟流 XOR 纠错 | 默认 K=4（25% 冗余）；缺 ≥2 帧放弃不重传；两端同开才有收益 |
| `--auth --ca-seed --ed-seed --zone --cert-cache` | 证书认证握手 | 与明文引导路径并存，安全场景同用 |
| `--punch --shards --fallback --resolver --learn-peer --no-tun` | 打洞/分片/中继/云解析/无 TUN 自测 | 验证与部署辅助 |

节点默认 UDP 端口 **45700**（`--udp-port`，对端默认同端口）。

---

## 4. 内核驱动 ipv8proto v0.11（NDIS 6.30 协议驱动）

原则不变：**数据面归用户态，驱动只做"看得见 + 通管道"**；帧路径照 ndisprot630 官方成熟模型，
缩小蓝屏面。

### 4.1 IOCTL（`\\.\IPv8Proto`，SDDL `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;WD)`，METHOD_BUFFERED，magic=0xFB14）

> 权限：0x800–0x802 只读 IOCTL 普通用户即可调用（World 只读位）；0x803–0x805 数据面仅 SYSTEM/管理员。
> ipv8adm 只读查询以 GENERIC_READ 打开设备，l2 收发以 GENERIC_READ|WRITE 打开（提权进程）。

| 码 | IOCTL | 方向 | 内容 |
|---|---|---|---|
| 0x800 | GET_VERSION | 只读 | major/minor=0.11 + NDIS 版本 |
| 0x801 | GET_STATS | 只读 | open_count / unloading |
| 0x802 | GET_BINDINGS | 只读 | 变长绑定快照，每条 **180B**：rx/tx/rxdrop/txdrop(u64×4)、bound、ifindex、MAC[6]+pad、namechars、name[64]WCHAR |
| 0x803 | RECV_FRAME | 读（可挂起） | 入 16B{magic,ifindex(ANY=0xFFFFFFFF),保留}；出 16B 帧头 + 完整以太网帧 |
| 0x804 | SEND_FRAME | 写 | 入 16B 帧头 + 帧（14..1514，短帧补 60）；**强制 EtherType=0xFB14，src MAC 驱动覆写** |
| 0x805 | INJECT_FRAME | 写（调试） | 入格式同 SEND，直接送入接收队列（pending READ 或 FrameQueue），不经过 NDIS；仅用于单机验证接收侧代码 |

### 4.2 帧管线要点

- **EtherType 双重过滤**：`FrameTypeArray={{NdisMedium802_3,0xFB14}}` 是第一层提示，但双机实测
  发现在 Hyper-V netvsc 上该过滤不完全可靠（非 0xFB14 帧也会进入接收回调）；因此
  `IPv8IndicateOneFrame` 入口做第二层硬校验（以太网偏移 12/13 必须是 0xFB/0x14，
  `NdisGetDataBuffer` + 栈缓冲区兜底），不匹配只递增 RxDropped。**FrameTypeArray 绝不能登记
  0x0800**：实测会使 NDIS 把全部 IPv4 帧投递给本协议，干扰 TCP/IP 的 UDP 通信。
- **收包 packet filter（v0.11 双机实测根因修复）**：打开适配器完成后必须异步下发
  `OID_GEN_CURRENT_PACKET_FILTER = DIRECTED|BROADCAST|MULTICAST`（`IPv8SetPacketFilter`，
  FinishOpen 中调用）。netvsc miniport 不设此 filter 就不向协议驱动指示任何帧（Rx 恒 0）。
  只设 DIRECTED 会丢广播/组播，三标志缺一不可。
- DriverEntry 预分配 **128 RX + 32 TX** 个 1514B 帧节点（连续非分页内存块，约 240KB）+ NBL 池，
  失败回滚、驱动加载失败。NBL 池 `fAllocateNetBuffer=TRUE`（发送用合体分配
  `NdisAllocateNetBufferAndNetBufferList`，NDIS 契约要求该标志置位，否则恒返回 NULL →
  os error 1450；本机实测发现并修复）。
- 收包（DISPATCH_LEVEL）：`NdisGetDataBuffer` 连续拷贝 → 锁内三分支：匹配的 pending READ
  立即完成 / 入帧队列（无等待者时排队，双机实测跨时序验证）/ 丢弃计数；帧节点与 IRP 摘下后锁外操作。
- pending READ 用 **IO_CSQ**（cancel-safe IRP 队列），单把 FrameLock，无嵌套锁序；
  内核不做超时，超时由用户态 overlapped（WaitForSingleObject + CancelIoEx）控制。
- 发送：Tx 节点 + MDL（非分页免锁页）+ NBL → `NdisSendNetBufferLists`，IRP 一律 pending，
  只在 SendComplete 回完；池满返回 DEVICE_BUSY；不支持中途取消；src MAC 由驱动强制覆写。
- 本机 MAC：OpenAdapter 后异步 OID_802_3_CURRENT_ADDRESS，包装结构 CONTAINING_RECORD 取回。
- inf 服务配置 `StartType=2`（AUTO_START），协议组件开机即绑定；便携安装脚本 netcfg 装后
  显式 `sc start`，当次生效免重启。
- 卸载：拒新 IOCTL → 取消全部 pending READ（DEVICE_REMOVED）→ deregister（NDIS 保证 close 前
  在途发送完成）→ 释放池。便携卸载脚本在 netcfg -u 之外对称清理 DriverStore 包与
  System32\drivers 下残留 sys/dll（netcfg 只摘组件不删包，双机实测确认）。

### 4.3 ABI 镜像（三处逐字节一致，任一改动三处同改 + 版本号）

1. `src/driver/ipv8proto/driver.h`（C_ASSERT 180/16）
2. `src/tools/ipv8-client/src/main.rs`（const 断言，driver/l2 共用）
3. `src/driver/ipv8prop/ipv8prop.cpp`（static_assert 180）

### 4.4 签名现实（决定 L2 能不能给普通人用）

- 现状：测试签名（CN=IPv8 Test 自签 + certutil 入受信根/发布者），要求**开测试签名模式 +
  关 Secure Boot**。用户的主力/游戏机不能接受，第二台机即因此装不上。
- **P7a 已闭环**（自签 EV 代码签名工具）：用 .NET CertificateRequest + Pkcs12Builder 构造
  含 EV OID（`2.23.140.1.3`）的自签证书链，3DES+SHA1 PBE 导出兼容老 signtool 的 PFX，
  X509Store API 静默安装信任链。产物：`d:\代码\IPV 8\代码签名证书制作工具\` 五文件 +
  项目级 skill `.trae/skills/self-signed-ev-cert/`。**硬限制：仅用户态 .exe/.dll 签名美化，
  不能让 .sys 免测试签名加载。**
- **P7b blocked**（内核正道）：EV 代码签名证书注册 Windows 合作伙伴中心 → **证明签名（Attestation）**。
  协议驱动为按需启动、非启动关键驱动，适用证明签名，Win10/11 x64 无需测试签名、不动
  Secure Boot，也不需要全套 HLK 认证（以提交时中心策略为准）。需真实 EV 证书（~$360/年 + 硬件 token + 审核）。
- 在拿到 P7b 证书前，所有真机验证在 **Hyper-V 双 VM** 做（虚拟网卡可正常被协议驱动绑定）。

---

## 5. 邻居发现：必须正视的"双轨"现状

### 5.1 协议本体（ipv8-neigh，传输无关，已完成且测试充分）

以太网/UDP 载荷均为同一种 **136B 定长**报文，大端：

```
"IP8N"(4) | ver=1 | type(HELLO=1/ACK=2) | flags(保留)
| addr(16 IPv8) | ts_secs(u64) | nonce(u64) | pubkey(32 Ed25519) | sig(64)
```

- 签名域 = 前 72B（"IP8N" 自带域分隔）；签名/验签以 `SignatureOps` trait 注入，库本体零依赖；
  ping8 用 ed25519-dalek（verify_strict 拒弱键），身份复用 `.ipv8/node_seed.bin`。
- 防重放：时间窗 ±300s + 每公钥 64 nonce 环形去重；ACK 回显 nonce + 本端 pending 集合
  （30s 过期、上限 1024）。
- 决策三态：`AutoAck`（已授权，刷新 mac/addr 直接回 ACK）/ `NeedsConsent`（弹 Y/N）/
  `Reject`（坏签名/重放/超窗）。
- 邻居表 `%USERPROFILE%\.ipv8\neighbors.bin`：`"IP8N""NBHR"` 线格式，记录 64B/条，
  公钥为主键，同公钥换 IP/MAC 自动刷新；list/remove（地址/IP/MAC/公钥前缀均可定位）。
- 与 IPv8 数据帧天然区分：IP8N 首字节 'I'=0x49，IPv8 首字节高 4 位=0x8。

### 5.2 两条实际存在的传输轨

| | UDP 轨（已接协议、能用） | L2 轨（管道已通、无消费者） |
|---|---|---|
| 载体 | UDP 45802，广播 255.255.255.255 或 `--to` 单播（可跨网段） | EtherType 0xFB14 裸帧，驱动 IOCTL 收发 |
| 前置条件 | 仅防火墙放行（首次弹窗或 `ping8 firewall open`），**免驱动、免管理员、Secure Boot 无关** | v0.11 驱动已装且绑定成功（当前仅测试签名） |
| 命令 | `ping8 neigh init/hello/watch/list/remove` | `ping8 l2 bindings/peek/send/inject`（只通裸字节，不认 IP8N） |
| 对端标识 | 记录 mac 字段借存 IPv4（后 2B 为 0） | ifindex + 真实 MAC |
| 状态 | 建邻/授权/ACK/落盘全链路完成，**单机 20/20 + 双机实测通过**（Y 双向入表、N 拒绝不应答不入表、杀进程后 neighbors.bin 留存） | 发送（NBL 池修复后）+ 接收（inject 验证 pending READ/FrameQueue）本机管道已通；**双机双向裸帧字节级正确，两轮硬重启后仍通，drop=0** |

设计含义：库的传输无关抽象是对的，差异只在 ping8 的两个命令族各自接了不同 socket，
**wintun-node 完全没有消费任何一轨**。

### 5.3 收敛方向（P8，§8）

保持"有驱动用真二层，没驱动用 UDP"的自动双轨，策略与 RIO 三态一致（能用快的、不能用就
透明降级，绝不劝退）：

```
neigh 传输层（同一 ipv8-neigh 状态机与 neighbors.bin）
   ├─ L2 transport：ping8 l2 的 RECV/SEND IOCTL 之上跑 IP8N（广播 ff:ff:..:ff，ACK 单播 MAC）
   └─ UDP transport：现有 45802 逻辑原样保留
选择：驱动 v0.11+ 在且至少一张网卡 bound → L2 优先；否则 UDP。可 --neigh l2|udp|auto 强制。
```

之后再做原 spec 步骤 5：`ipv8-node --l2` 让引擎帧直接走 0xFB14，邻居表提供下一跳 MAC，
与 UDP 广域路径共存（同子网零中继直连，出子网回退 UDP/中继）。

---

## 6. 用户面、服务侧与端口

### 6.1 ping8 / ipv8adm 双 exe（P9.1 已完成，按 exe 文件名做命令白名单）

- 普通用户向：`install / auto / diagnose / status / addr / ping / visa show|renew|fingerprint /
  firewall open|close|list / neigh * / serve`
- 高级/运维向：`visa ca-init|issue|verify|revoke / firewall add|remove|toggle /
  trust listen|request / hook watch|stats / driver status|version|stats|bindings /
  l2 bindings|peek|send|inject`
- 自更新：每次启动独立线程查门户 `GET /api/ping8-version`（本地优先，5s 超时静默失败），
  新版从 `/api/client-package` 下载 → MZ 头 + 体积校验 → 运行中 exe 改名交换、失败回滚、
  旧版下次清理。**门户是唯一分发与版本源。**

### 6.2 端口表

| 端口 | 协议 | 用途 |
|---|---|---|
| 45700 | UDP | ipv8-node 默认隧道端口（`--udp-port` 可改） |
| 45800 | UDP | 部署约定的备用隧道路口（firewall open 标 Tunnel Alt） |
| 45801 | UDP | `trust` 信任交换（TRST）/ ipv8-netbench server |
| 45802 | UDP | IP8N 邻居发现（UDP 轨） |
| 45810 | TCP | 外部判决钩子，**仅 127.0.0.1** |
| 7070/7080/7090 | TCP | gRPC：zoneserver / resolver / ans |
| 9001 | TCP | portal HTTP；ws-node relay；cloudflared 回源（QUIC 出边） |
| 5353 | UDP | portal 本地 DNS（`*.ipv8.net` 经 NRPT 指向本机解析） |
| 9100 | TCP | `ping8 serve` / ipv8-forward 统计页默认端口 |

### 6.3 部署与运行形态（缺口）

- 已具备：wintun 安装、IPv8 地址分配、NRPT 规则、防火墙规则、托盘监视脚本、一键
  VBS（隐藏窗启动/终止）、驱动便携打包（`scripts/driver-pack.ps1` 产出 sys/dll/inf/cat/cer/
  ping8.exe + 中文 安装.ps1/卸载.ps1，整目录可拷走）。
- 缺口（用户硬性诉求，尚未做）：**node/portal 不是 Windows 服务**（P9.2），现在靠 VBS/计划任务式
  隐藏窗；需要正规服务化（开机自启、崩溃拉起、无窗口）。C# Host 是服务骨架但未承载 Rust
  数据面，不宜直接沿用。双 exe 拆分（P9.1）已完成。

---

## 7. 验证状态与缺口清单（不粉饰）

**已验证（有代码测试/实测证据）**

- 纯函数库单测：ipv8-compat 38、ipv8-fec 18、ipv8-neigh 23、ipv8-hook 13、rio 逻辑 10；
  workspace 全量 **420 passed / 0 failed / 5 ignored**，clippy `-D warnings` 零警告
  （2026-09-18 会话复验）；release 构建通过。
- Phase 5A：2026-09-12 提权实测（netcfg 安装、服务 RUNNING、三个 IOCTL 真实数据、
  装卸幂等循环、属性页 CLSID 注册）；仅余一张属性页 GUI 截图的人工证据项。
- Phase 5B 本机实测（2026-09-13）：
  - **UDP 邻居轨 20/20 PASS**：双隔离身份、Y 双向入表、neighbors.bin 落盘与新进程留存、
    AutoAck、remove、N 拒绝三条路径全覆盖。
  - **L2 发送**：修复 NBL 池 `fAllocateNetBuffer=FALSE` 致 `NdisAllocateNetBufferAndNetBufferList`
    恒返回 NULL（os error 1450）的 bug；修复后 Tx 计数正确，pktmon 确认 0xFB14 帧入栈。
  - **L2 接收**：通过调试 IOCTL `IOCTL_IPV8_INJECT_FRAME`（`ping8 l2 inject`）把帧直接送入
    接收队列，验证 pending READ 直交（CSQ）与 FrameQueue 入队/出队两条路径，payload 字节级正确。
- **Phase 5B 双机真机实测（2026-09-18，Hyper-V 双 VM，tasks 6.5 全部项）**：
  - L2 双向广播裸帧（A→B、B→A）字节级正确，bindings Rx/Tx 计数增长，drop=0；
    两轮硬复位（Restart-VM -Force）后心跳即时 Ok、驱动 AUTO_START 自动 RUNNING、L2 仍通。
  - UDP 邻居：清表后 hello/watch --yes/ACK 双向入表落盘；N 拒绝路径不应答、不入表、发起方
    15s ACK 超时；杀进程后新进程从 neighbors.bin 读到邻居（双机 77B 文件）。
  - 完整装卸循环：便携 卸载.ps1 后服务 1060、服务/ROOT/CLSID 注册表键全无、sys/dll 文件删除、
    DriverStore 引用 0、ICMP 0% 丢；重装后 v0.11 自动 RUNNING、L2 与 ICMP 恢复；
    严格核对系统事件，**0 条 BugCheck**。
  - 双机实测暴露并修复四处真问题（详见 §8 P6）：缺 packet filter（Rx 恒 0）、netvsc 上
    FrameTypeArray 不过滤（加入口硬校验）、误登记 0x0800 干扰 TCP/IP（回退仅 0xFB14）、
    inf2cat 未来日期失败仍签旧 cat 造成假包（改硬门禁）+ DriverVer UTC 日期 + 卸载残留清理。
- RIO 回退：火绒/360 拦截 10045 的自动回退在本机验证过；真 RIO 性能对比需干净双机/双 VM
  （双 VM 环境已就绪，可随时补测）。

**未验证 / 欠债**

1. ~~**5B 双机真机实测**~~：2026-09-18 已全部完成（见上）。
2. ~~**dist/driver 不完整**~~：已补齐 8 文件（sys/dll/inf/cat/cer/ping8.exe/安装.ps1/卸载.ps1）。
3. ~~**tasks.md 勾选陈旧**~~：Task 1–6 已据实勾完（含双机真机实测）。
4. **neigh 实现与 spec 不一致**：spec 仍写 L2 承载，实际为 UDP 45802。本文档为准；
   spec 在 P8 立项时修订（或标注"UDP 先行、L2 为 P8 传输之一"）。
5. **真 RIO/多路径/FEC 性能**只有微基准，没有干净环境端到端对比数据（双 VM 已具备补测条件）。
6. ~~`src/tools/ipv8-toolkit` 无 src、不在 workspace~~：已删除（无任何代码引用）。
7. ~~C# 旧栈去留未决~~：已明确保留为非主路径组件（36 个测试全过，含跨语言一致性锁），定位为未来服务化参考骨架。
8. 节点/门户服务化（§6.3，P9.2）、`ping8 auto` 一键流程（P9.3）未开工；双 exe 拆分（P9.1）已完成。

---

## 8. 后续方案（六阶段，按"先证伪、再解分发、后扩功能"排序）

### P6 — 分发包补齐 + 双机真机验收（2026-09-18 已闭环）

1. ~~`scripts/driver-pack.ps1` 产出 dist 目录 8 个文件齐全~~：已完成。
2. ~~**双机真机验收**~~：Hyper-V 双 VM（Private 交换机，192.168.200.1/.2，测试签名）全部通过：
   - L2 双向广播裸帧 hex 一致、bindings Rx/Tx 计数增长、MAC 真实、两轮硬重启后仍通；
   - UDP 轨 hello/watch（Y 双向入表、N 拒绝不入表）、杀进程后 neighbors.bin 留存；
   - 卸载后服务/注册表/设备节点/sys/dll/DriverStore 全部清零，重装恢复，0 蓝屏 0 卡死。
3. **双机实测额外修复（本次会话产出）**：
   - 驱动 v0.10→**v0.11**（ABI 不变，180B 结构未动）：补 `OID_GEN_CURRENT_PACKET_FILTER`
     （DIRECTED|BROADCAST|MULTICAST，缺它 netvsc 不指示帧）；收包入口加 EtherType 硬校验
     （FrameTypeArray 在 netvsc 不可靠）；FrameTypeArray 回退仅 0xFB14（登记 0x0800 会让 NDIS
     投递全部 IPv4 帧、干扰 TCP/IP UDP）；移除调试 DbgPrint。
   - inf：StartType 3→2（AUTO_START），DriverVer 同步；安装脚本装后 `sc start`。
   - 打包链：inf2cat 失败从 warning 改为硬中止（失败时旧 cat 被重签会产生"签名有效但哈希陈旧"
     的假包，netcfg 报 0xE000024B）；注意 **DriverVer 日期按 UTC 判定**，本地凌晨打包易踩
     "future date"；卸载脚本补 DriverStore 包与 sys/dll 文件清理。
4. 属性页补一张截图（5A 尾项，唯一遗留人工证据项）。
P8 门禁（蓝屏/卡死一票否决）已满足。

### P7a — 自签 EV 代码签名工具（2026-09-18 已闭环）

低成本替代：用 .NET `CertificateRequest` API 构造含 EV OID（`2.23.140.1.3`）的自签证书链，
`Pkcs12Builder` + `TripleDes3KeyPkcs12 + SHA1` PBE 导出兼容老 signtool 的 PFX，`.NET X509Store`
API 静默安装信任链（绕开 certutil 安全确认弹窗）。

**产物**：`d:\代码\IPV 8\代码签名证书制作工具\` 下五个文件 + 项目级 skill `.trae/skills/self-signed-ev-cert/`：
- `root.cer` 根 CA / `ev.cer` EV 子证书 / `ev.pfx` PFX（密码 ipv8ev）
- `install-trust.ps1` 跨机一键信任安装脚本（零弹窗，普通用户可跑）
- `make-ev-cert.ps1` 可重跑生成脚本（pwsh，全自动化闭环）

**技术坑与解法**（skill 内已沉淀）：
| 坑 | 解法 |
|---|---|
| EV OID 写不进 Certificate Policies | 手工 ASN.1：`30-09-30-07-06-05-67-81-0C-01-03` 塞 RawData |
| PFX 密码错误（.NET 9 默认 AES-GCM 老 signtool 不认） | `Pkcs12Builder` + `TripleDes3KeyPkcs12 + SHA1` PBE |
| 根 CA 装不上（certutil -addstore Root 弹安全确认） | `.NET X509Store('Root', CurrentUser).Add()` 静默写入 |

**验收**：signtool 签名 ping8.exe + RFC3161 时间戳 → `signtool verify /v /all` 全链信任 0 errors。
跨机分发：`root.cer + ev.cer + install-trust.ps1` 三文件打包，对方双击 install-trust.ps1 即消除 SmartScreen。

**硬限制（不可夸大）**：本证书不在 Microsoft Trusted Root Program 中，**不能让 .sys 免测试签名加载**，
仅用于用户态 `.exe/.dll` 签名美化（UAC 蓝色 / SmartScreen 信任 / 属性页"此数字签名正常"）。

### P7b — 内核驱动正规签名（blocked，需真实 EV 证书 + Attestation）

解除 Secure Boot 约束的正道：
1. 办理 EV 代码签名证书（硬件 token，~$360/年），注册 Windows 合作伙伴中心。
2. `driver-pack.ps1` 增加发布模式：同一 sys/dll 产物走合作伙伴中心证明签名提交，
   取回签名驱动替换测试签名路径；测试签名保留为开发模式（脚本参数切换）。
3. 在**未开测试签名、Secure Boot 开启**的干净 VM 上验证安装/卸载/裸帧收发。
4. 安装脚本按签名形态自动跳过证书导入与 testsigning 警告。

**当前状态**：blocked——EV 证书有费用与审核周期，属用户侧事务，代码架构无改动。
P7a 已闭环但不覆盖内核签名场景，两者是互补关系而非替代。

### P8 — 邻居双轨收敛 + `--l2` 数据面（代码已完成，待真机验证）

> 状态：8.1–8.4 代码全部落地，`cargo build --release` / `clippy -D warnings` / 全量测试通过。
> 剩余：Hyper-V 双 VM 真机验收（P8.4 验收表）。

#### P8.1  neigh 传输 trait 抽象

抽 `NeighborTransport` trait（Rust），两种实现共用 `NeighborProcessor` 与 neighbors.bin：

```rust
pub trait NeighborTransport: Send {
    fn recv(&mut self) -> Result<Ip8nPacket>;        // 收一个 IP8N
    fn send(&mut self, pkt: &Ip8nPacket, dst: &MacAddr) -> Result<()>;  // 发一个 IP8N（广播 ff:ff..:ff 或单播）
    fn local_mac(&self) -> MacAddr;                  // 本机 MAC
    fn name(&self) -> &'static str;                  // "l2" / "udp"
}
```

- `L2Transport`：封装现有 L2Socket（ping8 l2 的 RECV/SEND IOCTL），广播 MAC = ff:ff:ff:ff:ff:ff，
  ACK 单播回源 MAC；本机 MAC 取自 `ping8 l2 bindings`。
- `UdpTransport`：现有 45802 UDP 代码搬迁；广播 255.255.255.255，本机 MAC 取 ARP。

#### P8.2  auto 模式选择逻辑

```rust
fn select_transport() -> Box<dyn NeighborTransport> {
    // 1. 查 ping8 l2 bindings：是否至少一张网卡 bound 到 ipv8proto.sys
    // 2. bound → L2Transport；否则 → UdpTransport
    // 3. 用户可 --neigh l2|udp|auto 强制
}
```

默认 auto；`ping8 neigh hello/watch/list/remove` 全部走 trait，与传输层脱耦。

#### P8.3  `ipv8-node --l2` 数据面

新 flag `--l2`：同子网引擎帧封 0xFB14（dst MAC 由邻居表解析），与 UDP 路径共存：
- 本地邻居优先 L2 直发（帧 = EtherHeader(0xFB14) + 40B IPv8 帧头 + AEAD 密文）
- 无邻居/跨子网回退 UDP 45700
- 发送侧 src MAC 仍由驱动强制覆写（不引入绕过分支）
- 接收侧复用 AEAD/防重放/钩子全流水线

**安全边界**：L2 只改变"帧从哪张卡出去"，IP8N 签名负责邻居身份，AEAD 负责数据帧，
未授权邻居的帧不产生任何状态。禁止在数据面引入绕过验签的分支。

#### P8.4 验收

| 项 | 标准 |
|---|---|
| 双轨建邻等价 | 同一 VM 同一张网卡，ping8 neigh 分别用 l2 和 udp，建邻/授权/ACK/落盘结果一致 |
| `--l2` 互通 | 双 VM + wintun + P6 驱动 v0.11，ping / iperf3 正常，drop=0 |
| 零回归 | 不带 `--l2` 时 ipv8-node 行为与今天逐字节一致 |
| 安全 | 未授权邻居的 L2 帧不产生任何状态，与 UDP 轨行为一致 |

**需独立 spec**：`.trae/specs/phase8-l2-convergence/`，评审 trait 接口、帧封装细节、auto 策略后开工。

### P9 — 产品化：服务化 + 一键流程（P9.1 双 exe 拆分已完成）

#### P9.1  双 exe 命令分割（已完成）

实现方式：Cargo `[[bin]]` 声明两个 bin（`ping8` / `ipv8adm`）指向同一个 `src/main.rs`，
运行时通过 `env::current_exe().file_stem()` 判断自身名称，`ipv8adm` 放行全部命令，
`ping8` 拦截 `l2` / `driver` / `hook` 并提示改用 ipv8adm。无需拆分代码库，两个 exe 字节相同。

命令分割表同上（ping8 普通用户命令 / ipv8adm 全命令）。

#### P9.2  Windows Service 设计

ipv8-node 增加原生 Service 模式（无窗口，日志到文件）：

| 操作 | 命令 | 说明 |
|---|---|---|
| 安装服务 | `sc create IPv8Node binPath= "C:\...\ipv8-node.exe service" start= auto` | sc.exe 是 Windows 内置，不需要额外依赖 |
| 启动/停止 | `sc start IPv8Node` / `sc stop IPv8Node` | |
| 查看状态 | `sc query IPv8Node` | |
| 卸载 | `sc delete IPv8Node`（先 stop） | |
| 日志路径 | `%ProgramData%\IPv8\ipv8-node.log` | 滚动日志，单文件 ≤ 10MB，保留 5 份 |
| 崩溃恢复 | sc.exe start= auto + Windows 重启自动拉起；进程内心跳 30s 写 .pid 文件 | |

portal 同样服务化或由节点服务托管（P8 后决定，当前先让 ipv8-node 跑起来）。
废弃 VBS 启动方式——无窗口的 Windows Service 是正确形态。

#### P9.3  `ping8 auto` 一键流程

一条命令完成全部配置，零黑框、零弹窗：

```
ping8 auto
  1. 检查 Wintun 是否安装 → 没有则静默安装
  2. 检查 ipv8proto.sys 是否安装 → P7a 测试签名：certutil -addstore TestSigningRoot 导入；P7b 后跳过
  3. 检查服务状态 → sc create + sc start IPv8Node
  4. 检查 NRPT 规则 → netsh namespace add ipv8.net → 127.0.0.1
  5. 检查防火墙放行 → netsh advfirewall firewall add rule name=IPv8 dir=in/out action=allow protocol=UDP localport=45700,45802,45810
  6. 检查自更新 → 拉取门户版本号，有新版静默替换 ipv8-node.exe，失败自动回滚
  7. 全部 OK → 输出 "IPv8 已就绪，连接邻居吧"
```

#### P9.4  验收

| 项 | 标准 |
|---|---|
| 一键成功 | 普通用户全程一次 `ping8 auto`，无黑框、无弹窗、Secure Boot 开启 |
| 双 exe 就位 | ping8.exe 跑普通命令正常；高级命令提示用 ipv8adm；ipv8adm 跑 l2/driver/hook 正常 |
| 服务化 | sc query IPv8Node 显示 RUNNING；重启自动拉起；日志到 %ProgramData%\IPv8\ |
| 静默升级 | 门户推新版 → 拉取 → 替换 → 失败回滚，全过程用户无感知 |
| 回滚 | 自更新失败、服务启动失败 → ping8 diagnose 能检测并提示修复 |

---

## 9. 工程铁律（跨阶段不变）

1. **零回归**：所有数据面能力默认关闭；不带开关时执行路径不包含新分支（Phase 2–4 一贯做法）。
2. **内核最小面**：数据面永不下沉内核；驱动只做管道与计数；新 IOCTL 必须有界、可取消、
   输入不可信；`/WX /kernel` 零警告是提交门槛。
3. **ABI 三处镜像**：driver.h / ping8 / ipv8prop.cpp 同版本同字节，静态断言守门。
4. **降级不劝退**：RIO 被安全软件拦截、驱动缺席、签名为测试态——一律自动回退或给出
   人话提示，功能不瘫。
5. **单文件交付**：发布产物继续 LTO+strip 单 exe；脚本随包自定位，不依赖源码目录。
6. **编码纪律**：含中文的 PowerShell/INF 按既定规则保存（脚本 UTF-8 BOM、INF 打包转
   UTF-16 LE BOM），避免 PS 5.1 乱码事故复发。
7. **不碰宿主环境**：所有内核/双机验证先在 Hyper-V VM 完成，宿主力保游戏与日常使用稳定。
8. **证据先于宣称**：测试数、实测、截图做完再改文档状态；tasks/spec 与代码偏差必须在
   发现的当次对表回写。
