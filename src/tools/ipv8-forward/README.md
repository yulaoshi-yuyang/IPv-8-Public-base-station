# ipv8-forward

## 干什么
IPv8 透明端口转发器：按防火墙规则 JSON 监听 TCP/UDP 端口，
匹配则转发、不匹配则拒绝；支持端口范围、协议与源地址过滤，
可转发到隧道内地址。节点只做管道，不处理用户数据。

## 对外暴露什么
二进制 `ipv8-forward.exe`（参数：`--rules`、`--bind`、`--stats-port`）。

## 内部文件
- `main.rs` — 规则加载、TCP/UDP 转发与统计

## import 白名单
- workspace 内：ipv8-firewall、ipv8-codec
- 外部：tokio、serde、serde_json、tracing
