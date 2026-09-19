# 运行日志

散落的想法先记这里，不许开新文件。超 300 行归档为 docs/archive/YYYY-MM.md。

## 2026-09-19

- 删旧版文件：archive\ipv8-ndis-protocol（C 语言驱动原型，24 文件 813KB，README 从未收录）、deploy\portal\logs 9/19 之前全部运行日志与 shots 截图（共约 115 个）。保留当日活跃日志。
- 事故复盘：重启后属性页回退旧 UI——根因是 5C 验收只覆盖 System32 未更新 DriverStore 包。修复路径：运行 scripts/driver-pack.ps1 重新打包（会 inf2cat + 签名 + 生成 dist\driver\安装.ps1），再以管理员运行 dist\driver\安装.ps1 重装（脚本会清 DriverStore 旧 oem*.inf 包 + 幽灵 ROOT 设备节点 + 残留服务，再 netcfg 安装）。教训：驱动更新必须走 DriverStore，只拷 System32 不生效。
- start-ipv8.ps1：隧道段加"cloudflared 退出即重启"循环（3 次/10s 间隔），修开机早期 DNS 未就绪导致隧道起不来

## 2026-09-18

- 开源准备：修 .gitignore（补 pycache/bak/screenshots/exe 白名单）、清理根目录散文件、删 .bak 备份
- 文档回写：architecture.md 修正 P9.1 状态（双 exe 拆分已完成）、README 澄清与 IETF draft-thain-ipv8 无关
- 补编制：AGENTS.md、docs/charter.md、docs/parking-lot.md、docs/dependencies.md
- GitHub 仓库：yulaoshi-yuyang/IPv-8-Public-base-station
