# 运行日志

散落的想法先记这里，不许开新文件。超 300 行归档为 docs/archive/YYYY-MM.md。

## 2026-09-19
- 实验田 exp/ula-overlay（用户点名豁免 48h，不进 main）：mesh 内虚拟 IPv6 寻址。`--ula <net-id>` 默认关闭，与 --tun-ipv6 互斥。派生规则：/48 前缀=SHA-256("ipv8-ula-prefix:"‖net_id) 前 5B 首字节强制 0xfd（哈希派生禁手拍，防撞用户本地 ULA）；节点 IID=SHA-256("ipv8-ula-iid:"‖net_id‖节点16B线格式) 前 8B 清 U/L 位；全网同落 前缀::/64，TUN 仅加精确 /64 路由（红线：无 ::/0、不碰物理网卡 RA、公网 v6 路径原样）。设计决策：「节点公钥」哈希输入用 --self 16B 线格式（Identity::generate() 每次重启随机，违反稳定身份）。改动仅 main.rs（派生结果并入 tun_ipv6 字段，netsh/compat 下游零感知，零跨 crate）。新增 5 单测；clippy -D warnings + cargo test --workspace 全绿（44 套件 0 失败，含 e2e_loopback）。待真机双机验收：netsh show route 无 ::/0 泄漏、curl -6 出口不变、tracert 首跳物理网关、双端 ping 对方 ULA 经隧道。
- 三层楼重构完工：删 C# 栈平行宇宙（含 CI dotnet job）；wintun.dll 内嵌自举（dll_bootstrap.rs，释放/校验/幂等/自愈四项运行时验证通过）；cross-verify 认定生成目录（doctor.ps1 归 scripts，.gitignore）；根 README 重写为产品路径+P8 开发路径；9 个模块 README、ADR 0001、债务 4 笔登记；architecture.md（编制外 506 行）分诊后删除，活引用改道。全量 clippy -D warnings + cargo test 0 failed。
- 运营商设备嵌入需求入停车场。验证：核心 10 crate（codec/compat/fec/neigh/firewall/hook/routing/qos/tunnel/ffi）对 x86_64-unknown-linux-gnu cargo check 全过，核心栈零 Windows 依赖；平台特定代码隔离在 adapter/tools。
- --mp 熔断对抗评审（并入停车场条目，裁决日 2026-09-21）：①误熔断/该熔未熔成本不对称——丢冗余保护（高）vs 白耗一份带宽（低），阈值显著偏向不熔断；②滞回成对：触发=持续 N 窗口无回包，恢复=连续 M 次正常且恢复门槛严格高于触发（两者量纲不同，不可直接比数值，本意是"恢复更难"）；③可测性前置件（grep 证实）：外层数据面无逐包 ACK/回执，仅 ping8→门户 60s 与节点→resolver 20s 心跳，均与 alt 路径无关——探针/回执机制先于阈值设计，否则触发与恢复都无法测量。FEC 自适应启停同步入停车场：不对称性与 --mp 相反（恒开成本有界：25% 带宽+组帧等待延迟，且永不产生坏数据），动态门控优先级更低。
- --mp 熔断二轮评审：观测底座（alt 活性 + 丢包率信号）定为 --mp 熔断与 FEC 自适应的**共享前置件**，不立独立工作项（无独立用户价值，随宿主条目裁决时随行立项）。候选设计两条，裁决日一并定：①旁路探针——复用 IP8N HELLO/ACK 经 alt socket 收发；注意"45802 本来就在跑就能用"不成立，邻居流量既非 per-path 也非常驻（ping8 neigh watch 是前台命令），需改造；②in-band 轻量回执帧——新增 FrameType，接收端按重放窗口计数缺口周期上报（RTCP 思路），一帧双用（路径活性+丢包率）且精确，代价是协议扩展。勘误：有明确裁决日的是 2 条（--mp 熔断、FEC 自适应），非 3 条。
- --mp 熔断三轮评审：①观测底座立行进停车场（状态=v1.5 前置件，不设独立裁决日——排期问题的答案就是"随宿主开工"，立行只为可见性与防重复立项）；②停车场备注自锚点化（候选A=借 IP8N 心跳 / 候选B=in-band 回执帧）。纠正两点：log 是超 300 行**归档**到 docs/archive/ 而非滚走丢失，引用断不了线只会变远；Kimi 拟的锚点B"应用层应答透出"写错了对象，候选B是 in-band 回执帧。③"P8 连坐动摇底座传输假设"不成立：P8 是双轨**加** L2、UDP 轨原样保留（停车场邻居行原文即"当前走 UDP 45802"），候选A钉死 UDP 轨不会因 P8 返工，L2 只是可选升级源；裁决时仍与 P8 排序对表一次，成本低。
- 2026-09-21 裁决议程备案（三合一，选型是宿主组合的函数，当日无辩论空间）：①--mp 熔断开工否；②FEC 自适应开工否；③若任一开工→底座选型随宿主组合确定——只过 --mp 熔断则 A 可行（仅活性）；涉 FEC 自适应则必须 B（A 无丢包率信号）；双过则 B 强制；双弃则底座自动死亡免二次裁决。
- 性能尺盘点与 Kimi 四候选裁决：①"没有任何一把尺"不成立——ipv8-netbench 早已有（nat/punch/throughput/latency/loss/all），latency 输出 P50/P95/抖动/超时，本轮补 P99（clippy 过）。真正缺的是**基线快照纪律**：固定拓扑跑 all、数字记 log，作为性能条目排号与验收依据；不新建工具。②拥塞控制入停车场（真实缺口：裸 UDP 无 CC）。③QoS"缺位"定性错误——ipv8-qos 的 4 级严格优先队列（有界、满则按可容忍度丢）+classifier+reservation 早已实现，数据面（adapter/tools）零调用仅 e2e 测试使用，属"造好未接线"。**误判记录**：曾判 tunnel 的 qos dev-dep 为死依赖并删除，clippy 立即抓出 e2e_multihop 在用——根因是 grep 模式用连字符 `ipv8-qos` 匹配不到代码里的下划线 crate 名 `ipv8_qos`；已恢复 dev-dep，实际拆掉的只有 ed25519-dalek 的 dev-dependencies 重复声明（dependencies 已有，dev 构建继承）。教训：检索 crate 引用必须同时搜连字符与下划线两种形态。④PMTUD/GSO 入停车场（现状未查证）。⑤单流窗口扩张不立项：隧道是 UDP 逐帧转发无内部窗口，"吞吐=窗口/RTT"约束的是内层 TCP 端点自身，隧道不加窗。
- 四轮评审：①采纳——拥塞控制若过裁决则观测底座候选B必选（A 无 RTT），B 设计要件新增 RTT 采样（频率/时钟方式），底座行备注已同步；选型函数表扩展：涉 CC → B。②拒绝"性能基线 harness"第四条立项：尺=ipv8-netbench 已存在（P50/P95/P99/抖动/吞吐/丢包齐），再立 harness 行属平行宇宙记账；缺的是基线快照动作——09-21 裁决前跑一次固定拓扑 `all` 记入本文件即可。③"虚拟 IPv4 兼容层缺席"查证：100.64.0.0/10 CGNAT 已是默认寻址现状（wintun-node --tun-prefix 默认值、README 快速开始、verify-cross.ps1、ipv8-client NRPT 过滤均在用），不存在未挂号的缺席想法；若所指为超出该现状的增量，需补一句话定义与提出时间再立行。
- 收到项目简报（用户口径），两条新概念行入停车场（多 WAN 上行聚合、虚拟 IPv4 兼容层），48h 观察期自登记日 2026-09-19 起算。简报修正两处供外发使用：①"性能基线 harness 待补进表"不成立，尺=ipv8-netbench 已在，正解是基线快照动作（09-21 裁决前跑固定拓扑 all 记 log）；②"信号须走旁路"措辞不准——候选 B 是带内回执帧，准确说法是"信号须专门建设：旁路探针或带内回执帧"。新增部署约束入档：家用台式机控制面/上行仅百兆→控制面数据面分离；云轻量服务器三职（备案门户+IPv4 信令中继+NAT64 网关）；用户可感延迟预算 <200ms。
- 虚拟 IPv4 兼容层增量定界（采纳入行，裁决 2026-09-21）：基座（100.64/10 节点间 v4 互通）不含；增量=云轻量服务器以普通 mesh 节点入网+内核转发+NAT44 MASQUERADE 出公网 IPv4+全网 v4 默认路由经此（Tailscale exit-node 类比）。两个裁决注脚采纳：①带宽闸门——服务器 3M 峰值扛信令够、扛 legacy 数据流即瓶颈，通过条款须含"默认仅低带宽 IPv4-only 应用出网"；②入站=端口映射另一维护面，明确排除，需要时另立条目各自 48h。存疑标注：①"协议零改动"未验证——前提一是 OS 把 0.0.0.0/0 指进 tun 后引擎肯转发非本机流量（transit），前提二是"下发默认路由"的通道存在（resolver 下发还是手工逐节点配置）；验证命令：rg -n "forward|not.*self|dst" src/adapter/wintun-node/src/main.rs 与 rg -n "exit|default_route" src/。若 transit 不通，条目从"纯配置"升级为"引擎小改"，仍成立但工作量变。②与三职中的 NAT64 共用同一公网 IPv4 出口，角色不同层不冲突。

- 删旧版文件：archive\ipv8-ndis-protocol（C 语言驱动原型，24 文件 813KB，README 从未收录）、deploy\portal\logs 9/19 之前全部运行日志与 shots 截图（共约 115 个）。保留当日活跃日志。
- 边缘项收尾：check-build-size/clean-build 从根目录移入 scripts/ 并锚定仓库根（跨 cwd 可用），README 目录地图补录；删除根目录"代码签名证书制作工具"整包（ev.pfx 私钥副本 + makecert/signcode 遗留 SDK 工具 + ping8 测试 exe，共 30 文件）与 skill 内 3 个生成证书，make-ev-cert.ps1 以 skill 为唯一正本（384 行新版合入），.gitignore 加 *.pfx/*.p12 兜底，architecture.md P7a 同步。
- 事故复盘：重启后属性页回退旧 UI——根因是 5C 验收只覆盖 System32 未更新 DriverStore 包。修复路径：运行 scripts/driver-pack.ps1 重新打包（会 inf2cat + 签名 + 生成 dist\driver\安装.ps1），再以管理员运行 dist\driver\安装.ps1 重装（脚本会清 DriverStore 旧 oem*.inf 包 + 幽灵 ROOT 设备节点 + 残留服务，再 netcfg 安装）。教训：驱动更新必须走 DriverStore，只拷 System32 不生效。
- start-ipv8.ps1：隧道段加"cloudflared 退出即重启"循环（3 次/10s 间隔），修开机早期 DNS 未就绪导致隧道起不来

## 2026-09-18

- 开源准备：修 .gitignore（补 pycache/bak/screenshots/exe 白名单）、清理根目录散文件、删 .bak 备份
- 文档回写：architecture.md 修正 P9.1 状态（双 exe 拆分已完成）、README 澄清与 IETF draft-thain-ipv8 无关
- 补编制：AGENTS.md、docs/charter.md、docs/parking-lot.md、docs/dependencies.md
- GitHub 仓库：yulaoshi-yuyang/IPv-8-Public-base-station
