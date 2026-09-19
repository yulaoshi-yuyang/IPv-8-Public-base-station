# ws-node

## 干什么
Cloudflare WebSocket 桥节点：把原生 AEAD 隧道帧装进 WS 二进制消息，
经 Cloudflare 边缘暴露到公网。边缘只当哑管道，零信任面不扩大。
relay 模式先验身份再按明文 dst 头整条搬运，隧道目的地址不泄露。

## 对外暴露什么
二进制 `ipv8-ws-node.exe`，模式：`serve` / `connect` / `relay`。

## 内部文件
- `main.rs` — WS 收发、证书握手与中继路由

## import 白名单
- workspace 内：ipv8-tunnel、ipv8-codec
- 外部：tokio、tokio-tungstenite、futures-util
