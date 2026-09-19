# ipv8-tunnel

## 干什么
IPv8+ 隧道引擎：封装/拆壳、X25519 握手、证书认证、AEAD 加解密、
密钥轮换（1GB/1h + 宽限）、分级降级与中继故障切换。

## 对外暴露什么
- `Engine` / `EngineStats` / `State`：引擎门面与状态机
- 帧：`FrameHead` / `FrameType` / `parse_head` / `write_head`
- 身份与握手：`Identity` / `TunnelKeys` / `create_init` / `accept_init`
- 证书：`CertAuthority` / `Cert` / `TrustAnchor` / `auth_init`
- 其余：`FallbackManager`、`FlowShards`、`RelayFailover`、`AbuseGuard`、`TunWorker` / `TunIo`

## 内部文件
frame / crypto / handshake / auth / encapsulate / engine / fallback / flow /
tun_worker / relay_failover / abuse_guard（各 .rs）

## import 白名单
- workspace 内：ipv8-codec、ipv8-routing
- 外部：x25519-dalek、ed25519-dalek、chacha20poly1305、aes-gcm、sha2、rand_core、hmac
