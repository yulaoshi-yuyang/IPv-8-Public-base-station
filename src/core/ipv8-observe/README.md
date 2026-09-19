# ipv8-observe

## 干什么

数据面质量信号的唯一生产者（ADR-0002）。纯函数、零依赖、不做 I/O：
从入站 Data 帧尾的明文计数器做稀疏滑动窗统计（期望/实收/重复/重置），
编码 124B 回执（FrameType=7），吃对端回执算 RTT，并产出两个滞回判决：
`--mp` alt 路径熔断、FEC 自适应门控。时钟全部由调用方注入。

## 对外暴露什么

- `ObserveNode`：喂帧 `observe_inbound`、出报告 `maybe_build_report`、
  吃报告 `ingest_report`、判决 `alt_disabled` / `fec_enabled`、读数 `rtt_us` / `path_counters`
- `PathId`、`ObserveConfig`、`PathCounters`、`DATA_MIN_FRAME`
- 策略配置：`BreakerConfig` / `GateConfig`
- 封包：`report::encode/decode`（124B 定长）；不接触任何网络/加密 API

## 内部文件

- `window.rs`：帧元数据提取 + 128 位图计数器窗（per-SA，≤8 条）
- `report.rs`：124B 回执布局与编解码（main/alt/union 三槽）
- `rtt.rs`：RTCP 式 LSR/DLSR 往返时延
- `policy.rs`：熔断与 FEC 门控两个滞回状态机
- `lib.rs`：ObserveNode 装配与跨窗差值

依赖：无第三方、无 workspace 内 crate（import 白名单：空）。
