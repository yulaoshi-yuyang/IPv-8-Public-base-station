# 依赖登记册

新依赖 = 新承重墙，必须登记。同类库只许存在一个。

## Rust（Cargo workspace）

| 依赖 | 版本 | 用途 | 引入模块 |
|---|---|---|---|
| x25519-dalek | 2.0.1 | X25519 密钥交换 | ipv8-tunnel |
| ed25519-dalek | 2.2.0 | Ed25519 签名/验签（邻居、签证） | ipv8-tunnel, ipv8-client |
| chacha20poly1305 | 0.10.1 | ChaCha20-Poly1305 AEAD | ipv8-tunnel |
| aes-gcm | 0.10.3 | AES-GCM AEAD（备选套件） | ipv8-tunnel |
| sha2 | 0.10.9 | SHA-256（密钥派生、指纹） | ipv8-tunnel, ipv8-client |
| rand_core | 0.6.4 | 随机数（nonce、密钥生成） | ipv8-tunnel |
| tokio | 1.53.1 | 异步运行时 | wintun-node, cloud/*, ws-node |
| tonic | 0.12.3 | gRPC（云侧服务） | cloud/*, ipv8-grpc |
| prost | 0.13.5 | protobuf 编解码（gRPC 载荷） | cloud/*, ipv8-grpc |
| wintun | 0.5.1 | Windows TUN 设备 | wintun-node |
| windows-sys | 0.52 / 0.61 | Win32 FFI（RIO、Winsock、设备 IOCTL） | wintun-node |
| mimalloc | 0.1.52 | 高性能内存分配器 | cloud/resolver |
| rusqlite | 0.31.0 | SQLite 持久化（resolver 名称存储） | cloud/resolver |
| serde | 1.0.229 | 序列化（配置、钩子协议） | ipv8-client, ipv8-hook |
| serde_json | 1.0.151 | JSON 序列化 | ipv8-client, ipv8-hook |
| anyhow | 1.0.104 | 错误处理（应用层） | 多数二进制 |
| thiserror | 1.0.69 | 错误类型派生（库层） | ipv8-tunnel, ipv8-neigh |
| base64 | 0.22.1 | Base64 编解码（签证、指纹） | ipv8-client |
| tracing | 0.1.44 | 结构化日志 | 全部运行时组件 |
| tracing-subscriber | 0.3.23 | 日志订阅器（env-filter） | 全部运行时组件 |

## C# / .NET

| 依赖 | 版本 | 用途 |
|---|---|---|
| .NET SDK | 10 | 编译目标 |
| (无第三方 NuGet) | - | 全部使用 BCL |

## C / 驱动

| 依赖 | 版本 | 用途 |
|---|---|---|
| WDK | 随 VS | NDIS 驱动编译 |
| (无第三方) | - | 纯 Win32 + NDIS |

## 外部工具

| 工具 | 用途 | 是否随仓库分发 |
|---|---|---|
| wintun.dll | TUN 设备运行时 | 是（deploy/client/） |
| cloudflared.exe | Cloudflare 隧道 | 否（tools/cloudflared/，gitignore） |
