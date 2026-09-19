# resolver

## 干什么
IPv8+ 地址解析服务：节点登记"地址 ↔ 隧道入口"，查询方一次 RPC 拿回
入口、能力位、MTU、备用入口、TTL。核心零 IO，gRPC 层独立。

## 对外暴露什么
二进制 `ipv8-resolver.exe`；库类型 `NodeRecord` 及模块
`grpc`、`sqlite_store`、`dht_store`、`cached_store`。

## 内部文件
lib.rs（核心逻辑）/ grpc.rs（网络层）/ sqlite_store.rs / dht_store.rs /
cached_store.rs / main.rs（服务端入口）

## import 白名单
- workspace 内：ipv8-codec、ipv8-routing
- 外部：tonic、prost、tokio、tokio-stream、rusqlite、ed25519-dalek、
  ahash、smallvec、mimalloc、lru、parking_lot、tracing
