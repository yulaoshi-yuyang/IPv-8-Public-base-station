# 依赖登记册

新依赖 = 新承重墙，必须登记。同类库只许存在一个。

## Rust（Cargo workspace）

| 依赖 | 版本 | 用途 | 引入模块 |
|---|---|---|---|
| x25519-dalek | 2 | X25519 密钥交换 | ipv8-tunnel |
| ed25519-dalek | 2 | Ed25519 签名/验签（邻居、签证） | ipv8-tunnel, ipv8-client |
| chacha20poly1305 | 0.10 | ChaCha20-Poly1305 AEAD | ipv8-tunnel |
| sha2 | 0.10 | SHA-256（密钥派生、指纹） | ipv8-tunnel, ipv8-client |
| rand_core | 0.6 | 随机数（nonce、密钥生成） | ipv8-tunnel |
| aes-gcm | - | AES-GCM AEAD（备选套件） | ipv8-tunnel |
| tokio | 1 | 异步运行时 | wintun-node, cloud/* |
| tonic | 0.12 | gRPC（云侧服务） | cloud/*, ipv8-grpc |
| wintun | 0.5.1 | Windows TUN 设备 | wintun-node |
| windows-sys | 0.52 | Win32 FFI（RIO、 Winsock） | wintun-node |
| serde / serde_json | 1 | 序列化（配置、钩子协议） | ipv8-client, ipv8-hook |

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
