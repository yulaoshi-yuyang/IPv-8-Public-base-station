# IPv8+

IPv8+ 是一个面向广域网的新一代互联网协议实现，提供端到端加密、低延迟数据面与可编程流量判决。

> **与 IETF draft-thain-ipv8 的关系**：本项目的 IPv8+ 与 IETF 草案
> [draft-thain-ipv8](https://datatracker.ietf.org/doc/draft-thain-ipv8/) 是**相互独立**的协议设计。
> IETF 草案定位为 IPv4 的 64 位扩容协议（ASN 路由前缀 + IPv4 主机地址，线级兼容 IPv4）；
> 本项目 IPv8+ 定位为**加密叠加网络**（X25519 握手 + AEAD 加密 + wintun 透明承载），
> 通过隧道承载 IPv4/IPv6 流量，不修改网络层协议。两者除名称相似外无技术关联。

## 特性

- **加密通道**：X25519 密钥交换 + ChaCha20-Poly1305 / AES-GCM AEAD，防重放
- **低延迟数据面**：Windows Registered I/O (RIO) 用户态收发，多路径竞速，FEC 前向纠错
- **透明接入**：未修改的应用程序经 wintun 虚拟网卡直接走 IPv8+ 网络
- **可编程钩子**：出站（加密前）/ 入站（解密后）数据包可由外部程序判决（放行 / 丢弃 / 修改 / 延迟 / 镜像 / 限速）
- **双栈承载**：局域网内走 EtherType `0xFB14` 裸帧（NDIS 协议驱动），广域网走 UDP / WebSocket 加密叠加层

## 快速开始

环境要求：Windows 10/11 x64、Rust stable、.NET 8 SDK、WDK（驱动编译）。

```powershell
# 构建协议栈与工具
cargo build --release

# 构建 NDIS 驱动（需 Visual Studio + WDK）
msbuild src/driver/ipv8proto/ipv8proto.vcxproj /p:Configuration=Release

# 一键部署（需管理员权限，测试签名模式）
powershell -ExecutionPolicy Bypass -File deploy/client/setup-ipv8-full.ps1
```

详细架构与阶段计划见 [docs/architecture.md](docs/architecture.md)。

## 目录地图

- `src/core/` — IPv8+ 协议栈（编解码、路由、QoS、隧道、加密、钩子、FEC、邻居发现）
- `src/adapter/` — 虚拟网卡适配器（wintun 节点 Rust 实现）
- `src/cloud/` — 云端服务（ANS 分配、DNS 解析、区域服务器）
- `src/services/` — C# 主机服务（Agent Mesh、QoS 管理、NRPT 清理）
- `src/driver/` — Windows NDIS 协议驱动（ipv8proto.sys）与属性页 DLL
- `src/tools/` — 命令行工具（ping8、转发、压测、ws-node）
- `deploy/` — 部署脚本与客户端资源（wintun、防火墙、NRPT、门户 UI）
- `dist/driver/` — 驱动发布产物（sys / inf / cat / 签名证书 / 安装卸载脚本）
- `docs/` — 架构文档
- `shared/` — protobuf 协议定义与测试向量
- `scripts/` — 驱动打包、安装、交叉验证脚本

## 许可证

MIT License
