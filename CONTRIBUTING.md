# 贡献指南（CONTRIBUTING）

本文件面向给 Strata（IPv8+）提交改动的开发者。请先读完「质量门禁」与「红线」两节再动手。

方案依据：《IPv8+ 工程化方案（最终版 v9）》；协议权威：[docs/protocol-spec.md](docs/protocol-spec.md)；设计决策见 [docs/adr/](docs/adr/)。

## 1. 环境要求

| 组件 | 版本 / 说明 |
|---|---|
| 操作系统 | Windows 11 x64（客户端仅支持 Windows：wintun / NRPT / 低端口均为 Windows 机制，`Program.cs` 标了 `[SupportedOSPlatform("windows")]`） |
| Rust | stable toolchain，workspace edition 2021；`cargo` 需能联网拉取 crates.io |
| .NET SDK | 10.x；本机 SDK 若缺 `WorkloadAutoImportPropsLocator` 目录（MSB4276），根 [Directory.Build.props](Directory.Build.props) 已全局关闭 workload 解析器，纯桌面工程无需改动 |
| wintun.dll | 从 wintun.net 下载的官方签名版，已归档于 `deploy/client/wintun.dll`（微软数字签名 Valid）；仅真实网卡验证路径需要，CI 用 MockTun 不碰它 |
| 管理员权限 | 仅创建/配置真实 wintun 网卡时需要；`scripts/verify-loopback.ps1` 已封装 UAC 自提权 |

## 2. 快速上手

```powershell
# 协议引擎层（Rust）
cargo build --workspace
cargo test --workspace

# 服务/适配层（C#）
dotnet build IPv8Plus.slnx
dotnet run --project tests/services/IPv8Plus.Services.Tests   # 退出码 = 失败数，0 即全绿
```

数据面性能基准（标记为 `#[ignore]`，不进常规测试，需显式触发、单线程）：

```powershell
cargo test --release --test bench_dataplane -- --ignored --nocapture --test-threads=1
```

## 3. 质量门禁（提交前必须全过）

```powershell
# Rust：零警告 + 全测试
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

# C#：零警告 0 错误 + 契约测试
dotnet build IPv8Plus.slnx
dotnet run --project tests/services/IPv8Plus.Services.Tests
```

- C# 各 csproj 已开 `TreatWarningsAsErrors=true`，任何警告即编译失败。
- 任一门禁不过，视为改动未完成，不得提交。

## 4. 架构铁律

- **依赖方向**：上层调下层，下层绝不调上层；同层只经事件总线（`IPv8Plus.Abstractions.Events`）通信；跨层走接口（接口先行）。
- **Rust core 内部**顺序固定：`codec ← routing ← tunnel ← grpc`；`ffi` 仅 Phase 0 使用，已冻结（ADR-008）。新增依赖不得反向。
- **零硬编码**：部署参数（端口、MTU、命名空间根、网卡名等）一律走 `ClientOptions`（appsettings `Client` 节），配置外部化。
- **密码学边界**：CA 私钥只在 ZoneServer，节点侧用 `HostIdentity::with_cert`，不持 CA 私钥；AEAD 套件（ChaCha20-Poly1305 / AES-256-GCM，ADR-025）进 HKDF info 域分离，接收方只信本地配置的套件，帧内不符即 `SuiteMismatch` 丢弃计数（防降级）。改握手/封装前务必对照 ADR-025 与 spec §6。

## 5. 跨语言语义锁（Rust ↔ C#）

ANS / AgentMesh 这类两侧都实现的逻辑，用共享测试向量锁定语义一致，**改任何一侧裁决逻辑，另一侧必须同步并重放**：

- 向量放 `shared/test-vectors/*.json`，**必须纯 ASCII**。
- 两侧各写重放器：Rust = `vector_tests.rs`（走真实验签登记）；C# = `TestRunner` 的 `ANS_shared_vector_matches_rust`（Upsert 镜像免密）。
- 地址等十六进制字段**从代码生成**，禁止手写（历史上手填 `fb14` 实为 `64500`，一次重放即暴露）。

## 6. 红线：Windows PowerShell 5.1 与含中文文件

这几条是踩过的坑，违反会导致整库文件损坏或长时间空转：

1. **给 PowerShell 5.1 写的 `.ps1` 必须纯 ASCII。** 5.1 按 ANSI/GBK 解析源文件，中文注释的字节会吞掉换行，造成 `try/catch` 之类假性语法失衡——报错行号还会误导。脚本注释、输出请一律英文。
2. **含中文的文件只能用编辑器/Write/Edit 工具改，禁止 PS 管道批处理。** `(Get-Content -Raw) -replace … | Set-Content -Encoding UTF8` 在 5.1 下按 GBK 读入中文文件再写出 → 全文件乱码（`engine.rs` 曾整库毁容）。
3. **读中文日志用 `-Encoding Default`**，否则按 UTF-8 读 GBK 输出会匹配不到内容。
4. **同一失败诊断连续两次即换路径**，不要重复同一条命令空等（如文件锁、编码不匹配）。

## 7. 验证脚本（真实链路，需管理员）

- `scripts/verify-loopback.ps1`：同机双实例（IPv8Plus-A/B 两张真实 wintun 网卡 + 真 UDP 127.0.0.1）跑通包 / `-Auth` 认证握手 / `-Zone` ZoneServer 注册取证 / `-Fragment` 分片 / `-Fallback` 分级降级。自动 UAC 提权。
- `scripts/verify-cross.ps1`：跨机双角色（Role A 发起 / Role B 被动）。
- **通包判据是引擎四计数增长（sealed / delivered / frags_* ）且 `dropped=0`，不是 ping 回包**——同机双 TUN 拓扑下跨网卡 ping RTT 会被本机协议栈短路。
- **测分片必须拆开两个 MTU**：`--tun-mtu`（接口，OS 交给我们的整包上限）与 `--mtu`（引擎 IPv8+ 分片上限，默认 1432）。两者相同则大 ping 在 TUN 边界就被 Windows 先 IP 分片，IPv8+ 分片路径永远不触发。
- wintun 网卡**复用不删除**：PS 5.1 无 `Remove-NetAdapter`；脚本策略是重启即复用。

## 8. 提交与 PR 流程

当前工作副本尚无 git 仓库。约定如下：

1. `git init` 后按 [`.gitignore`](.gitignore) 提交（`target/`、`bin/`、`obj/`、`*.dll` 已排除；`deploy/**/*.dll` 例外保留官方 wintun.dll）。
2. 分支命名 `phase<N>-<主题>` 或 `fix/<简述>`；一个 PR 只做一件事。
3. PR 描述须写明：改动落在哪条 ADR/spec 条款下、动了哪些测试、门禁命令的输出结果；跨语言逻辑改动须附上共享向量重放通过的证据。
4. CI 配置见 `.github/workflows/ci.yml`：push / PR 到默认分支时自动跑 Rust（clippy `-D warnings` + test）与 C#（build + 契约测试）两条 windows 流水线；仓库推送到 GitHub 后即生效。

## 9. 变更记录

重大行为改动请在 [CHANGELOG.md](CHANGELOG.md) 追加条目，并同步受影响文档与 ADR 状态（Accepted / Postpone / Superseded）。
