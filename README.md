# IPv8+

IPv8+ 是面向广域网的加密叠加网络：端到端 AEAD 隧道、低延迟用户态数据面、可编程流量判决，应用程序不经修改即可接入。

> **与 IETF draft-thain-ipv8 的关系**：两者相互独立。IETF 草案是 IPv4 的 64 位扩容协议；
> 本项目是 X25519 握手 + AEAD 加密 + wintun 透明承载的隧道网络，除名称外无技术关联。

## 特性

- **加密通道**：X25519 密钥交换 + ChaCha20-Poly1305 / AES-GCM，防重放
- **低延迟数据面**：Windows Registered I/O (RIO) 用户态收发，多路径竞速，FEC 前向纠错
- **透明接入**：未修改的应用程序经 wintun 虚拟网卡走 IPv8+ 网络
- **可编程钩子**：出站（加密前）/ 入站（解密后）数据包可由外部程序判决（放行 / 丢弃 / 修改 / 延迟 / 镜像 / 限速）

## 快速开始（产品路径：零内核驱动、零测试签名）

环境要求：Windows 10/11 x64；构建需 Rust stable。wintun.dll 是 WHQL 签名的官方未修改副本，
已编译期内嵌进单一 exe，首次运行自动释放到 `%ProgramData%\IPv8` 并校验。

```powershell
# 构建单文件节点（不需要 WDK，不需要开启 testsigning）
cargo build --release -p ipv8-wintun-node

# 运行（首次运行释放 wintun.dll；建虚拟网卡需管理员权限）
target\release\ipv8-node.exe --self <本机IPv8地址> --peer-addr <对端地址> `
    --peer-ip <对端外层IP> --tun-ip 100.64.x.y

# 零驱动自检：不加载 wintun、不建网卡、不用管理员
powershell -ExecutionPolicy Bypass -File scripts\notun-selftest.ps1
```

打包双机交叉验证包（含云端 zone server）：`scripts\make-peer-pack.ps1`。
需求边界见 [docs/charter.md](docs/charter.md)，运行记录见 [docs/log.md](docs/log.md)。

## 高级开发 P8：NDIS L2（仅限开发机）

局域网 EtherType `0xFB14` 裸帧承载是可选的高级路径，不是产品安装前提：

- 源码：`src/driver/ipv8proto`（NDIS 协议驱动）、`src/driver/ipv8prop`（属性页 DLL）
- 构建需 Visual Studio + WDK：`msbuild src/driver/ipv8proto/ipv8proto.vcxproj /p:Configuration=Release`
- 未 Attestation 签名，开发机需开启测试签名模式；决策背景见 [docs/adr/](docs/adr/)

## 目录地图

- `src/core/` — 协议栈 11 个 crate：codec / routing / qos / tunnel / grpc / ffi / firewall / hook / compat / fec / neigh
- `src/adapter/` — wintun 节点（单二进制，dll 内嵌自举，RIO 数据面）
- `src/cloud/` — 云端服务：ans（地址分配）/ resolver（会合解析）/ zoneserver（区域服务）
- `src/driver/` — NDIS 协议驱动 ipv8proto 与属性页 ipv8prop（P8，开发用）
- `src/tools/` — 命令行工具：ipv8-client / ipv8-forward / ipv8-netbench / ws-node
- `deploy/` — 部署脚本与客户端资源（wintun 权威副本、防火墙、NRPT、门户 UI）
- `scripts/` — 打包、交叉验证、自检脚本
- `shared/` — protobuf 协议定义与测试向量
- `docs/` — charter、停车场、依赖账、log、ADR、技术债册

## 许可证

MIT License。wintun.dll 为 WireGuard LLC 所有（GPLv2，随附版权声明见 `deploy/client/wintun-LICENSE`）。
