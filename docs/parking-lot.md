# 停车场

v1

| 想法 | 提出时间 | 状态 | 备注 |
|---|---|---|---|
| 多路径竞速（--mp） | 2026-09 | 已实现 | 作为 v1.5 能力，默认关闭 |
| FEC 前向纠错 | 2026-09 | 已实现 | 作为 v1.5 能力，默认关闭 |
| RIO 数据面 | 2026-09 | 已实现 | 默认 auto，被拦截时回退 std |
| 邻居发现 L2 承载 | 2026-09 | 已实现·真机验收 PASS | 双轨：UDP 45802 保留，`--l2` 走 ipv8proto.sys 0xFB14 裸帧（wintun-node L2Io）；2026-10-14 Hyper-V 双 VM 四判据 ALL PASS，验收期修缺陷 6 个，证据见 log 2026-10-14 |
| Windows 服务化 | 2026-09 | P9 待开工 | 当前靠计划任务（登录后延迟 30s，隐藏窗） |
| 驱动 Attestation 签名 | 2026-09 | P7b blocked | 需真实 EV 证书 |
| --mp 熔断（alt 持续无回包停双发） | 2026-09-19 | 已接线·待真机验收 | 09-20 接线（ADR-0002）：3 窗 main 活（≤600ms）且 alt 死透（>1000ms）触发停 alt，5 窗 alt 活且收包率≥50%（样本≥32）恢复，main 同死永不熔断；出站批级条件化，入站按 from SocketAddr 归槽 |
| FEC 自适应启停（按观测丢包率动态门控） | 2026-09-19 | 已接线·待真机验收 | 09-20 接线：门控输入=对端回执 union 槽丢包率，≥30‰ 两窗开／≤5‰ 五窗关／样本<32 冻结，初始关；已替换原 DSCP 静态判据（inner_dscp 连同测试删除）；恒开成本有界且永不产生坏数据 |
| 观测底座（alt 活性 + 丢包率 + RTT 信号，宿主：--mp 熔断 / FEC 自适应 / 拥塞控制） | 2026-09-19 | 已落地·ADR-0002 | ipv8-observe 零依赖 crate + FrameType=7（124B/200ms，AEAD 密封，与 Data 独立 nonce 空间防计数器插号），RTCP 式 LSR/DLSR RTT；拥塞控制已同表取数（ADR-0003 已接线） |
| 拥塞控制（裸 UDP 无 CC） | 2026-09-19 | 已接线·待真机验收 | 10-14 接线（ADR-0003）：--cc 默认关、--cc-ceil 必填；延迟主导（RTT≥min_rtt×1.25）+丢包兜底（union≥30‰）乘性降 ×0.7 不低 floor=max(ceil/16,64k)，好窗 +ceil/8 加性增不超 ceil，起步 ceil/4，样本<32 冻结，min_rtt 10s 过期重置；批粒度令牌桶口径=线上总字节（main+alt+恢复帧），分片活跃路径让位。验收判据：netbench UDP 2×ceil 打流→RTT 有界、吞吐收敛 ceil 附近、信令不断 |
| QoS 调度接线（4 级优先队列数据面零调用） | 2026-09-19 | 待开工 | 库完备（scheduler/classifier/reservation）；adapter/tools 数据面零调用，仅 tunnel e2e 测试用；接线点=引擎发送路径 |
| 外层 PMTUD / 发送侧 GSO | 2026-09-19 | 待开工 | 2026-10-13 查证收口：内层 MTU 已按隧道 overhead 收缩（TUN 接口=tun_mtu 默认 --mtu 1432；effective_mtu=mtu−40 出/入站 MSS 钳制；DF 大包回 ICMP+引擎分片路径）。增量=外层 UDP 路径 MTU 探测自适应与发送侧 GSO，纯优化非正确性缺口 |
| 多 WAN 上行聚合（--mp 出口复用） | 2026-09-19 | 概念 | 前置=第二条物理线路（花钱项）；宿主机制=--mp，依赖熔断/观测底座先行裁决 |
| 虚拟 IPv4 兼容层（增量=IPv4 出网 exit-node） | 2026-09-19 | slice 1 已接线·待真机验收（1:1 引擎零改动）；slice 2 会话池待开工（先 ADR） | 09-20 切片裁决：slice 1=1 client:1 exit 纯 OS 配置（deploy/exit-node/setup-exit.ps1+setup-client.ps1：转发+WinNAT+QoS 整形 3M / 防递归 pin+ActiveStore 默认路由），验收=D:\IPV8-VMs\verify-exit-node.ps1；slice 2=多客户会话池+按 TUN 包 dst 选 peer 密封，动 engine.rs（现 1:1 钉死 peer_addr/keys/state，engine.rs:123/67），先 ADR 再开工。入站端口映射明确排除。细节见 log 2026-09-19/20 |
| exit-node client DNS 跟随（解析平面） | 2026-10-13 | 概念 | slice 1 真机验收发现：默认路由进 wintun 后配在物理网卡的 DNS 不被选中（nslookup 回退 fec0:0:0:ffff::1，curl 域名空；--resolve 直连与 wintun 配 DNS 均成功，证路由/NAT 数据面无缺陷，PMTU 1400 正常）。setup-client.ps1 按登记范围只管路由。形态=可选 -Dns 参数（默认不改用户 DNS：涉信任/CDN 调度/企业 DNS）或 exit 侧 resolver，先 ADR 再开工。验收夹具临时配 223.5.5.5 到 IPv8Plus，非产品行为 |
| 移动端支持 | - | 待开工 | 无明确计划 |
| 运营商设备嵌入（核心栈作模块写入第三方设备） | 2026-09-19 | 待开工 | 核心栈平台中立已验证（10 crate Linux target 编译通过）；届时路径：冻结 ipv8-ffi C ABI（现为 Phase 0 面貌）+ Linux TUN 适配层替代 wintun + CI 加 linux 门禁。前置：v1 交付 |
| 可视化拓扑 UI | - | 待开工 | 门户已有基础 UI |