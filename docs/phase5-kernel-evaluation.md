# Phase 5 内核优化评估（v9 §"仅评估，不进入 Phase 1-4 主线"）

状态：评估完成（2026-09-06）｜决策见 **ADR-024**｜性质：调研 + 基线测量 + 可行性结论，**不含驱动实现**

## 1. 背景与评估对象

v9 把内核级数据面列为可选末期优化，两个候选：

- **WFP Callout Driver**：在 Windows 筛选平台挂 callout，零拷贝改写/重定向包；
- **NDIS 中间驱动（LWF）**：链路层截获全部帧，性能上限最高、风险也最高。

v9 的原始顾虑（§决策表）："WFP/NDIS 是时间炸弹；wintun 是 WireGuard/Tailscale 标准做法"。
本评估要回答：**从当前纯用户态 wintun 数据面下沉到内核，收益是否值得其成本与风险。**

2022 之后出现第三条路径 **XDP for Windows / eBPF for Windows**（微软开源），本次一并纳入评估。

## 2. 基线测量（可复现）

测量工具：`src/core/ipv8-tunnel/tests/bench_dataplane.rs`（全部 `#[ignore]`，不入门禁）。
运行：

```text
cargo test --release --test bench_dataplane -- --ignored --nocapture --test-threads=1
```

硬件：13th Gen Intel i9-13900H（20 逻辑核）、15.6 GB RAM、Windows 11 Pro。
载荷：满 MTU IPv8+ 包（1432B 线上 = 40B 头 + 1384B 载荷）。**单线程**数值（保守，生产按核数可横向扩展）。

| 路径 | 吞吐 | 换算（1432B 包） |
| --- | --- | --- |
| AEAD 纯 seal | 0.52 GiB/s | ~0.40 Mpps 单程 |
| AEAD seal+open 往返 | 0.26 GiB/s | ~0.20 Mpps |
| **引擎完整单程 seal→handle** | **0.37 GiB/s** | **0.28 Mpps ≈ 3.2 Gbps** |
| 分片（fragment only） | 9.38 GiB/s | 非瓶颈 |
| 分片 + 重组 | 1.94 GiB/s | 非瓶颈 |
| RouteTrace build（含 Ed25519 签） | 13.4 µs/包 | 仅多跳控制面 |
| RouteTrace verify（Ed25519 验签） | 30.5 µs/包 | 见 §3 注 |

## 3. 关键发现：瓶颈是加密，不是内核旁路能碰的地方

纯 AEAD seal 路径 ~0.40 Mpps，而**经过 Engine 全部逻辑（握手态、计数、
分片判定、重组器）后是 0.28 Mpps 单程**——引擎在 AEAD 之上只增加了
约 **13%** 的成本（TUN 拷贝、内存分配、状态机）。

含义：**内核旁路理论上至多回收这 13%**，而它无法触碰占大头的
ChaCha20-Poly1305 加解密——加密在任何数据面方案里都照做不误。
为省 13% 付出内核驱动的成本是净亏。

另一注脚：RouteTrace 验签 30.5 µs/包若**逐包**执行，会成为多跳转发的
显著开销（约 0.33 Mpps 封顶）。这反向验证了 Phase 3 的一个设计选择：
PathSig 是**每隧道握手期一次**的认证成本，不是逐包成本——若将来做
逐包防重放，应走 AEAD 而非 Ed25519（AEAD 已覆盖头部，无需额外验签）。

## 4. 三条路径的成本/收益

### 4.1 WFP Callout
- 收益：省 TUN 环形缓冲拷贝与用户/内核往返；对多连接服务器场景（每包 syscall 摊薄）有帮助。
- 成本：内核态 bug = 蓝屏；驱动需 **EV 代码签名证书 + Microsoft 强制签名（attestation/WHQL）**；
  每次内核大版本回归测试；崩溃转储调试链。**对本项目：至多 13% 收益，判负。**

### 4.2 NDIS 中间驱动
- 收益上限最高但要求实现完整 NDIS LWF + RSS/校验和卸载适配；HLK 认证周期长。
- 本项目是端侧 overlay（非网络设备厂商），投入无对标回报。**判负。**

### 4.3 XDP / eBPF for Windows（2022 后的新变量）
现状（截至评估日，属易变信息，来源见文末链接）：
- XDP for Windows 最新稳定 **v1.4.0（2025-07）**；eBPF for Windows **v1.4.0（2025-07）/ v1.5.0 预发布（2025-08）**。
- 提供 **AF_XDP** 用户态零拷贝收发环 + 内核 eBPF 程序（XDP_DROP/PASS/REDIRECT）。
- **约束**：XDP 主要在**接收侧**、针对**物理网卡 L2 帧**；我们的隧道要封装**出站**
  IPv8+ 包（构造 UDP payload），AF_XDP 是绕开 TCP/IP 栈直发 L2，与"把包交给 OS 走
  UDP"的模型相反——用它做隧道出口要自建 ARP/路由交互，工程量远超收益。
- 内核侧 eBPF 程序仍需**签名驱动承载**（"Proof of Verification" EKU，微软签发），
  并非免签；其网络钩子（bind/connect/listen/flow-redirect）面向策略与负载均衡，
  不是任意协议封装引擎。
- 结论：**不适配**本项目隧道出口模型；若将来做**入站侧早期过滤/DDoS 丢弃**
  （XDP_DROP 恶意 UDP），是它真正的用武之地——可列为独立特性评估，而非"数据面加速"。

## 5. 留在用户态的更划算优化（性价比高于任何内核路线）

1. **换加密套件**：ChaCha20 无硬件加速；若启用 **AES-256-GCM（AES-NI）**，AEAD 吞吐
   通常 3-4×，直接抬高 §2 上限数倍——零内核风险。可作后续 ADR 提案
   （涉及 §10 密码学基线与跨平台一致性，谨慎）。
2. **wintun 批量 API**：现用 `wintun 0.5.1` crate 无批量接口（已核对本地源码）；
   上游 wintun 支持 `SessionStart/EndBatch`，减少环形拷贝次数与唤醒。
   纯用户态、低风险。
3. **多核分片**：把 0.37 GiB/s 单线程按流摊到多核；典型接入链路
   （1-2.5 GbE ≈ 0.12-0.29 GiB/s）单核已够用，多流并发天然多核。

## 6. 结论

**不建议进入内核数据面改造**（WFP/NDIS/XDP 三条均否）。当前用户态单核
≈3.2 Gbps，已超典型部署链路速率，且瓶颈在加密——内核旁路触及不到。
v9 的"仅评估"定位成立：Phase 5 到此为止，交付本报告 + ADR-024 决策，
**不产出驱动代码**。

复评触发条件写入 ADR-024（10 Gbps+ 部署 / CPU 受限嵌入式 / 实测拷贝占比反转）。

## 参考（易变，评估日核实）
- XDP for Windows releases: https://github.com/microsoft/xdp-for-windows/releases
- eBPF for Windows releases: https://github.com/microsoft/ebpf-for-windows/releases
