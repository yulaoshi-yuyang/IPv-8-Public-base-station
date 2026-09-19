# ipv8-hook

## 干什么
数据包外部判决总线，对标 Linux NFQUEUE 但无内核组件。数据面在每个内层包上
请求判决：流缓存命中直采，否则 NDJSON 经环回 TCP 交外部程序；
超时/断线/拥塞立即回退，绝不阻塞数据面。

## 对外暴露什么
`HookBus`、`HookConfig`、`PacketEvent`、`Direction`、`Action`、
`ClientMode`、`DEFAULT_PORT`（45810）。

## 内部文件
- `lib.rs` — 总线、流缓存与回退策略
- `protocol.rs` — NDJSON 线协议
- `ip.rs` — 内层 IP 包解析

## import 白名单
- workspace 内：无
- 外部：serde、serde_json、base64
