# ipv8-qos

## 干什么
QoS 引擎：基头 QoS Level（4 bit）→ 4 级调度类，严格优先队列出队，
QoSReservation 报文构造。纯数据变换，不持有 IO。

## 对外暴露什么
`classify_base_header` / `class_of_level` / `qos_level_of_base_header` /
`NUM_CLASSES`、`PriorityScheduler`、`reservation_header` / `parse_reservation`。
当前数据面未接线，仅 e2e 测试使用（见停车场"QoS 调度接线"）。

## 内部文件
- `classifier.rs` — Level→4 级映射
- `scheduler.rs` — 有界严格优先队列（满则按可容忍度丢）
- `reservation.rs` — QoSReservation 报文构造/解析

## import 白名单
- workspace 内：ipv8-codec
- 外部：无
