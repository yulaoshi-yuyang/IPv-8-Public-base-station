# ipv8-client

## 干什么
IPv8+ 单文件客户端：安装入 PATH、一键自动配置、诊断、地址查看、
UDP 回显 ping、签证管理（Ed25519 签名、绑机器指纹、30 天续签）。

## 对外暴露什么
- `ping8.exe` — 用户面命令（普通用户可用）
- `ipv8adm.exe` — 高级管理入口（同一源码的第二 bin）

## 内部文件
- `main.rs` — install / auto / diagnose / addr / ping / visa / status 全部子命令

## import 白名单
- workspace 内：ipv8-codec、ipv8-firewall、ipv8-neigh
- 外部：ed25519-dalek、sha2、rand_core、serde、serde_json
