# ipv8-netbench

## 干什么
NAT 穿透实测与网络质量工具：NAT 类型检测、打洞成功率、
吞吐、延迟、丢包测试，服务端/客户端同体。

## 对外暴露什么
二进制 `ipv8-netbench.exe`，子命令：
`server` / `nat` / `punch` / `throughput` / `latency` / `loss` / `all`。

## 内部文件
- `main.rs` — 协议、NAT 判定逻辑与各测试项

## import 白名单
- workspace 内：无
- 外部：无（仅 Rust std）
