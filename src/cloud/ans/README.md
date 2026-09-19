# ans

## 干什么
智能体命名服务：名字直接寻址、能力标签寻址、任务寻址（租约式分片，
防并发双订）。登记需持有证明 PoP，卡片经 CardSig 绑定到智能体密钥。

## 对外暴露什么
二进制 `ipv8-ans.exe`；库：`AgentCard`、`validate_tags`、
`ans_register_pop_message`、`ANS_REGISTER_DOMAIN`、`grpc` 模块。

## 内部文件
lib.rs（零 IO 核心）/ grpc.rs（gRPC 层）/ main.rs（服务端入口）；
tests_util.rs、vector_tests.rs 仅测试。

## import 白名单
- workspace 内：ipv8-codec、ipv8-routing
- 外部：tonic、prost、tokio、tokio-stream、ed25519-dalek、
  rand_core、sha2、tracing
