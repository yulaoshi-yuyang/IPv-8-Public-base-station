# Phase 1 通包验证指南（Hyper-V 双 VM）

对应 v9 Phase 1 验收标准：**两台 Hyper-V VM 通过 wintun 收发第一个 IPv8+ 包**。
验证工具：`ipv8-node`（Rust 守护进程，链路 = wintun TUN ↔ 隧道引擎 ↔ UDP）。
生产路径仍是 C# Host + gRPC；本工具只做连通性证明。

## 前置检查（宿主机，管理员 PowerShell）

```powershell
# 1. Hyper-V 是否可用（无输出 = 需先在"启用或关闭 Windows 功能"里打开 Hyper-V 并重启）
Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All | Select-Object State

# 2. 虚拟交换机（Internal 类型即可让两台 VM 互 ping）
Get-VMSwitch
#    若无：New-VMSwitch -Name "IPv8Lab" -SwitchType Internal
```

## 构建与分发

宿主机（本仓库根目录）：

```powershell
cargo build --release -p ipv8-wintun-node
# 产物：target\release\ipv8-node.exe
```

拷进**两台 VM**各一份，连同已核验微软签名的驱动（本仓库 `deploy\client\wintun.dll`）
放到 exe **同目录**。

## VM 网络规划（示例）

| | VM-A | VM-B |
|---|---|---|
| 物理网段 IP | 192.168.1.11 | 192.168.1.12 |
| IPv8+ 地址（32hex：ASN=64500/HostID/DeviceID/CapTag/Sec/Reserved） | `0000fb14000000010001000001000000` | `0000fb14000000020001000001000000` |
| Overlay IP（CGNAT /10，ADR-015） | 100.64.0.1 | 100.64.0.2 |
| 角色 | **--initiate（主动）** | 被动 |

> 恰好一端主动：两端同时 Init 会被对方状态机拒绝 → 永久死锁。

## 启动（两台 VM 均需管理员 PowerShell）

```powershell
# 防火墙放行 UDP 45700 入站（每台一次）
New-NetFirewallRule -DisplayName "IPv8 tunnel" -Direction Inbound -Protocol UDP -LocalPort 45700 -Action Allow

# VM-A
.\ipv8-node.exe --self 0000fb14000000010001000001000000 `
  --peer-addr 0000fb14000000020001000001000000 --peer-ip 192.168.1.12 `
  --tun-ip 100.64.0.1 --initiate

# VM-B
.\ipv8-node.exe --self 0000fb14000000020001000001000000 `
  --peer-addr 0000fb14000000010001000001000000 --peer-ip 192.168.1.11 `
  --tun-ip 100.64.0.2
```

预期日志：被动方先打印 `Established`，主动方随后 `✅ 隧道 Established`。

## 通包验证

任一 VM：

```powershell
ping 100.64.0.2   # 对端填自己的对端值
```

**通过判据**：
1. `ping` 收到回包（ICMP 载荷全程在 ChaCha20-Poly1305 之内）；
2. 两端 `[stats]` 行中 `sealed`/`delivered` 随 ping 同步增长；
3. `dropped` 保持 0（非 0 说明有帧被 AEAD/重放/旧代规则拒绝——用 Wireshark 抓 UDP 45700 核对帧格式）。

进阶：`ping -f -l 1400`（勿超 1392 有效载荷，见 spec §8.1；带 DF 的分片路径属 Phase 2 MTU/分片任务）。

## 退出与清理

`Ctrl+C` 退出；TUN 网卡 `IPv8Plus` 保留（重启节点直接复用）。彻底移除：

```powershell
Remove-NetAdapter -Name IPv8Plus -Confirm:$false   # 或设备管理器禁用
```

## 故障速查

| 症状 | 原因与处理 |
|---|---|
| `WintunCreateAdapter 失败` | 非管理员；或 wintun.dll 不在 exe 同目录（用 `--dll` 指定） |
| 一方 `Initiating` 重发、另一方无反应 | 对端未启动 / 防火墙未放行 / peer-ip 写错 |
| 两端都停在 `Initiating` 重发 | 都带了 `--initiate`——恰好一端主动 |
| Established 但 ping 不通、dropped 增长 | 中间链路改包（MTU/代理）；Wireshark 过滤 `udp.port==45700` 看帧头 `01 02 <epoch8B>` 是否完好 |
