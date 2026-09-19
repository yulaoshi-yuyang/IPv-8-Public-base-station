# wintun-node

## 干什么
IPv8+ 用户侧节点守护：wintun 虚拟网卡 ↔ 隧道引擎 ↔ UDP 外层，装配成完整数据链路。
单文件分发——wintun.dll 编译期内嵌，首次运行释放校验。

## 对外暴露什么
二进制 `ipv8-node.exe`。关键开关：`--no-tun`（零驱动/不提权）、`--dll`（覆盖 dll 路径）。
排查口诀：全部能力默认关；怪网络问题先去开关跑零回归基线，再逐个加回二分定位。
- `--rio auto`：被安全软件拦截（10045）自动回退 std 并具名提示
- `--mp`：双路径竞速，接收端防重放去重；单路全损不丢数据（另一路完整送达），代价是持续双发带宽
- `--fec`：仅 DSCP≠0 流；两端不一致时退化为不纠错——对端静默丢弃恢复帧（Type=6），数据帧照常收

## 内部文件
- `main.rs` — 参数解析、装配与主循环
- `dll_bootstrap.rs` — 内嵌 dll 的释放、SHA-256 校验、旧版本清理
- `rio.rs` — Registered I/O UDP 收发

## import 白名单
- workspace 内：ipv8-codec / compat / fec / hook / tunnel / grpc / zoneserver / resolver
- 外部：wintun 0.5、windows-sys 0.52、tokio 1、tokio-stream 0.1、tonic 0.12、sha2、tracing
