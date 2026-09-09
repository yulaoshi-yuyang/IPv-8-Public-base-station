# Strata (IPv8+)

在现有互联网上叠加一层透明加密通道，并把寻址从 IP 升维到智能体身份与能力。
方案依据：《IPv8+ 工程化方案（最终版 v9）》。

## 当前进度：Phase 1（隧道核心·密码学部分）

- [x] `src/core/ipv8-codec` — 40 字节基础包头编解码（零依赖纯函数）
  - 线格式夹具 + 1000 轮性质往返 + 截断/翻转不 panic 测试全绿
  - 未知扩展头按 ExtLen 跳过（ADR-020 前提）已实现
  - 保留字段"发送置 0、接收忽略"已实现
- [x] `src/core/ipv8-ffi` — C ABI 导出（仅 Phase 0 验证，Phase 1 冻结，ADR-008）
- [x] `src/core/ipv8-tunnel` — 隧道引擎（28 测试全绿）
  - `frame`：10B 帧头，KeyID = suite(1B) ‖ epoch（ADR-025；默认套件逐字节兼容旧格式）
  - `crypto`：HKDF 逐代派生 + ChaCha20-Poly1305/AES-256-GCM 双套件（部署配置、
    套件进派生 info 域分离）+ 1GB/1h 轮换 + 落后一代宽限 + 计数器严格递增抗重放；
    AAD 绑定明文头（改 CapTag/DstAddr 即解密失败）
  - `handshake`：X25519 临时密钥协商（含 MITM 演示测试 → Phase 2 接证书）
  - `tun_worker`：v9 §8 读线程模型（独立线程 + mpsc + 拷贝即释放），
    TunIo trait 注入 + MockTun，CI 不碰真实 wintun
- [x] `docs/protocol-spec.md` — 规范定稿候选（补齐 v9 九个 normative 缺口）
- [x] ADR-019/020/021
- [x] `src/services/IPv8Plus.Abstractions` — ITunAdapter + 4 事件契约（C#）
- [x] `src/adapter/wintun/WintunDevice.cs` — wintun.dll P/Invoke（仅设备生命周期，数据面在 Rust）
- [x] `src/services/IPv8Plus.Host` — Program.cs 管理员门禁 + ClientOptions + NrptCleanupService
- [x] `deploy/client/*.ps1` — install-wintun / setup-nrpt / cleanup-nrpt（v9 语法修正版）
- [x] `shared/ipv8-proto/tunnel.proto` — C#↔Rust gRPC 契约（TunPacket/WireFrame oneof 双向流 + StartHandshake/InjectFrame/GetStatus）
- [x] `src/core/ipv8-grpc` — gRPC(tonic) 桥（2 e2e 测试全绿：真实 TCP 双引擎握手 + ping/pong + 篡改丢弃计数）
  - 代码生成走 protox（纯 Rust），Windows 零 protoc 依赖
  - 这是 C# 宿主接入路径的 Rust 侧等价证明：C# 用同一 .proto 生成的客户端走同样的调用序
- [x] `src/adapter/wintun-node` — Phase 1 通包验证守护进程 `ipv8-node`（wintun TUN + Engine + UDP 三方粘合；
  --initiate/被动角色避免双主动死锁；官方 wintun.dll 已归档 deploy/client/ 并验证微软数字签名）
- [x] `docs/phase1-verification-guide.md` — Hyper-V 双 VM 通包验证手册
- [x] `scripts/verify-loopback.ps1` — 同机双实例自动提权验证脚本（UAC 一键）
- [x] **Phase 1 验收 PASS**（同机回环，自动 UAC 提权）：双 `ipv8-node` 实例经真实 wintun
  网卡（IPv8Plus-A/B）+ 真实 UDP(127.0.0.1) 完成 X25519 握手与双向封包/拆包；
  计数 `A.sealed+215 / A.delivered+214 / B.sealed+214 / B.delivered+214 / dropped=0`
- [ ] （可选增强）Hyper-V 双 VM 真跨机：同机 ping RTT 会被本机协议栈短路，
  完整 ping 往返需两台 VM/主机跑 `docs/phase1-verification-guide.md`（本机内存暂不足）
- [x] **跨机真网验证工具已备好**：`scripts/verify-cross.ps1`（Role A/B 双机对接，
  管理员自提权 + 防火墙自动放行 + 引擎计数判据 + 真端到端 ping RTT 证据；
  `-Zone` 走 ZoneServer 生产信任路径（`-ZoneHost` 可选落点）、`-Fragment` 走跨网线
  IPv8+ 分片）。**异网/跨 NAT 拓扑**（一侧公网 v6、一侧大内网）：`ipv8-node` 新增
  `--peer-ip` IPv6 支持（绑定族跟随对端）与 `--learn-peer`（内网侧首帧现学真实出口
  地址，天然打洞语义——内网机当发起方、v6 机应答并现学回包目的地）。
  对端文件包：`deploy/cross-verify/`（exe + wintun.dll + 脚本 + 使用说明），
  两台 Windows x64 各放一份即可开测。待真机实测回填结果。
  **包内 exe 一律由 `scripts/make-peer-pack.ps1` 再生成**（内部 `cargo build --release`
  后刷新 pack + `deploy/ipv8-cross-verify.zip`，勿手工复制）；若 `target\release` 被
  运行中的节点锁定，先 `cargo build … --target-dir target\pack` 再
  `powershell -File scripts\make-peer-pack.ps1 -SourceDir target\pack\release`。
- [x] **Phase 2 · 证书认证握手**（`ipv8-tunnel::auth`，7 测试全绿）
  - CA（Ed25519）签发 `addr ‖ ed_pub ‖ not_after` 证书；握手 Init/Resp 各附
    证书 + 对 transcript 的签名，接收方三验（CA 签名 → 有效期 → transcript 绑定）。
  - `mitm_is_now_detected` 与 `handshake::tests::mitm_cannot_derive_keys` 形成对照：
    无认证路径下换临时公钥可畅通，认证路径下 Bob 在 accept 阶段即拒绝。
- [x] **Phase 2 · MTU/分片**（`ipv8-codec::fragment`，9 测试全绿；spec §8.3 位图同步修正）
  - 分片器 + 重组器：每片带 Fragment 扩展头（链首），原扩展链仅首片携带；
    8 字节对齐、重叠/错序/超组/超时全部有回归测试，`dropped` 语义并入引擎计数。
- [x] **Phase 2 · 认证握手接入 Engine 数据面**（5 集成测试全绿，明文路径回归锁死）
  - `Engine::authenticated` + `start_auth_handshake` + `handle_frame_at(frame, now)`：
    AuthInit/AuthResp 帧类型走完整 seal/open 数据路径，认证失败（MITM/错配/伪造/过期）
    记录于 `last_auth_error` 且绝不建密钥；同一 Init 重发幂等重发同一 Resp。
  - **expected_peer 强制**：认证模式把 Resolver 给出的预期对端地址绑进校验，
    堵住"共享 CA 下证书合法但对话对象错配"这一残余攻击面。
  - 明文握手（Phase 1 已验收路径）逐方法保留，`plaintext_path_still_works` 防回归。
- [x] **Phase 2 · 认证模式贯通 gRPC 契约与 ipv8-node，同机回环实测 PASS**
  - tunnel.proto：`StartHandshakeRequest.auth + ca_seed + ed_seed`（信任锚预置，验证专用），
    `StatusResponse.authenticated + last_auth_error`；gRPC 桥用系统时钟驱动 `handle_frame_at`。
  - `ipv8-node --auth --ca-seed <64hex> --ed-seed <64hex>`：双端共享 CA 种子 = 预置信任锚。
  - `verify-loopback.ps1 -Auth` 实测：A/B 双真实 wintun 网卡 + 真 UDP，证书认证握手后
    `A.sealed+204 / A.delivered+201 / B.sealed+201 / B.delivered+205 / dropped=0` → PASS
  - 教训入档：verify 脚本保持纯 ASCII——Windows PowerShell 5.1 按 ANSI/GBK 解析源文件，
    中文注释字节会破坏语句结构（曾致 try/catch 假性失衡）。
- [x] **Phase 2 · ZoneServer 核心逻辑**（`src/cloud/zoneserver`，8 测试全绿）
  - **PoP 注册**：节点上送 Ed25519 公钥 + 该密钥对 `domain‖addr‖pub` 的签名，服务端验签才发证
    → 防冒注他人公钥；域分隔使注册签名无法挪用到轮换（反之亦然）。
  - **证书签发**：复用 ipv8-tunnel::auth 的 `Cert`/`CertAuthority`，与握手三验天然互认；
    `register→issue→HostIdentity::with_cert→认证握手` 端到端测试打通（节点不持 CA 私钥）。
  - **JWT（HS256）**：`sub=addr_text`+iat/exp，常定时序安全比较；过期/篡改/换 sub 全被拒。
  - **RotateKey**：需有效 JWT 且 sub==addr 且新密钥 PoP 有效，堵"偷 JWT 即换公钥"。
  - 契约 `zoneserver.proto` 已定（含 PoP/rotate-proof 字段）；信任锚经 `GetTrustAnchor` 下发。
- [x] **Phase 2 · ZoneServer gRPC 网络层 + 节点真机注册路径实测 PASS**
  - `ipv8-zoneserver` 守护进程（tonic，protox 生成，端口可配）；client stub 供节点复用。
  - `ipv8-node --zone http://…`：节点经 gRPC `GetTrustAnchor + Register(PoP)` 拿证书与锚，
    **CA 私钥全程只在服务端**；`verify-loopback.ps1 -Zone` 实测：本地 ZoneServer + 双真实
    wintun 节点注册取证 → 认证握手 Established → `A.sealed+193/delivered+190、
    B.sealed+190/delivered+194、dropped=0` → PASS。
  - zoneserver gRPC 测试 4 项（注册→JWT 回环、锚下发、坏 PoP=InvalidArgument、
    注册→证书→握手全流）。
- [x] **Phase 2 · Fallback 分级降级**（`ipv8-tunnel::fallback`，9 测试全绿）
  - v9 §11 逐条实现：四级路径（主隧道→备用入口级联→明文 TCP→明文 UDP）、
    分级超时（首握手 8s/已缓存 5s/首包 3s/Resolver 2s）、每入口独立重试预算
    （max_retries=2）、首包超时跳过预算直接降级、`ipv8_capable=false` 直通明文、
    5 分钟降级缓存到期自动恢复隧道尝试、隧道成功清缓存并把备用入口提正。
  - 纯状态机 + 注入时钟（now: u64），无 IO；socket/计时归宿主（C#/ipv8-node）。
- [x] **Phase 2 · 分片接入 TUN 数据面，-Fragment 同机回环实测 PASS**
  - `Engine::seal_frames`：内层 IP 包 → IPv8+ 整包 → 按 §8.3 分片 → 逐片 AEAD 封装；
    收侧 `handle_frame` 遇 Fragment 头交 `Reassembler`，重组成功后才解内层并计数
    `fragments_sent / fragments_reassembled`（透出到 stats 行与 gRPC TunnelStatus）。
  - `ipv8-node`：TUN 读线程逐帧 send_to；新增 `--tun-mtu`（接口 MTU）与 `--mtu`
    （引擎分片上限）解耦——不拆开的话大 ping 会在 TUN 边界被 Windows IP 分片，
    IPv8+ 分片路径永远触发不了；gRPC 桥 TUN 分支同步改 `seal_frames` 逐帧下发。
  - `verify-loopback.ps1 -Fragment` 实测：tun-mtu=4000 > 引擎 1432，`ping -l 3000`
    驱动 → `A.sealed+202/delivered+190、B.sealed+198/delivered+193、dropped=0、
    双端 frags_sent+8 / frags_reassembled+4` → PASS。
- [x] **Phase 2 · Fallback 接入 node 数据面与 gRPC 契约，-Fallback 同机回环实测 PASS**
  - `Engine` 新增握手重开/重协商原语：`abandon_handshake()`（发起方放弃超时尝试，
    换新临时密钥重开）、`reset()`（拆掉半开隧道，首包超时降级前作废旧密钥）；
    Established 下收到**不同** Init = 对端 fallback 重协商，认证三验照常、通过即换密钥
    （双方各自超时各自重发即可收敛，无协调协议）。
  - `ipv8-node --fallback [--alt-ip --alt-port]`：主循环由 `FallbackManager` 驱动——
    分级握手超时（8s/5s）→ 预算内幂等重发 → 入口级联（主→备）→ 明文级（UDP 直发原始
    IP 包，首字节 0x45/0x60 与隧道帧 0x01 demux）；Established 后数据面锁定到**实际
    成功入口**（不锁会往死主入口发数据——实测前抓到的真 bug）；首包超时 3s 判半开降级。
    统计行新增 `plain_tx/plain_rx`。`--fallback` 关闭时保持 Phase 1 无限幂等重发，零回归。
  - tunnel.proto fallback 决策面：`SetResolved`（喂 Resolver 入口/ipv8_capable）、
    `NextPath`（下一包路径 + 分级握手超时）、`RecordFailure/RecordSuccess`（成败→级别）；
    `TunnelStatus.fallback_level` 暴露当前级别。降级状态机在桥内 keyed per-peer，
    明文 TCP/UDP 传输归 C# 宿主直用 socket（桥只给决策）。gRPC e2e 测试 1 项覆盖
    主→备级联、全败落明文、成功提正+缓存超时、legacy 直通 PlainTcp 全链路。
  - `verify-loopback.ps1 -Fallback` 实测：A 主入口指死端口 45799 + 备用=45702（B 真实
    端口），主入口 8s×3 超时 → 级联备用 → Established →
    `A.sealed+39/delivered+31、B.sealed+6/delivered+6、dropped=0` → PASS。
- [x] **Phase 2 · zone 路径证书持久化，-Zone 重启闭环实测 PASS**
  - `ipv8-node --cert-cache <file>`（配 `--zone`）：注册成功后把「CA 公钥 + 证书」
    写入本地文件（仅公开材料，CA 签名自证完整性；私钥仍只走 `--ed-seed` 不落地）。
  - 重启时**离线三验**命中即免注册（文件结构 + CA 签名有效且未过期 + 证书主体 ==
    本机地址与公钥），命中则 ZoneServer 不可达也能起；任一环不过静默回退注册路径。
  - ZoneServer 侧配套放宽：`register` 对**同密钥**重注册视为续期放行（否则证书过 90 天
    而 JWT 仅 24h，重启恢复会永久死锁）；**换密钥**仍须走 `rotate_key` 的 JWT+新 PoP
    双因子，`duplicate_register_rejected` + `same_key_reregister_renews_cert` 双向锁死。
  - `verify-loopback.ps1 -Zone` 实测扩展：首轮注册取证通包后，杀掉 A+B+ZoneServer，
    带 `--cert-cache` 离线重启双节点 → 断言两端 `[cert-cache] HIT` 且二轮重握手通包
    `A sealed+188/delivered+176、B +177/+189、dropped 0/0` → RESULT: PASS。
- [x] **Phase 2 全部完成**
- [x] **Phase 3 · M1 协议定稿与 ADR 闭环**
  - ADR-019 **Accepted**：多跳 = 源路由 + RouteTrace 路径单次签名（方案 2/3 合流；
    Chord 自主路由降为 feature 骨架——同机回环无法模拟 DHT 分区，v9 验收语义
    "隧道内多跳路由"静态源路由即可满足；将来要自主路由须回头扩展本 ADR）
  - ADR-007 **Accepted**（Resolver 隐私）：Phase 3 落地最小披露+缓存 TTL；
    ODoH/多层架构记为跨信任域后的演进路径
  - ADR-010 **Accepted（Postpone 决议）**：SQLite→PG 按触发条件后置；
    云 crate 存储以 `trait Store` 抽象（resolver 已示范）
  - protocol-spec §6.5 QoSReservation（8B：rate24/burst16/hint8）、§6.6 RouteTrace
    （104+16N：SrcPubKey‖PathSig‖HopCount‖InitHopLimit‖Rsv6‖跳列表）定稿；
    PathSig 域分隔 `ipv8plus-routetrace`、SrcPubKey 入签防延展、链首约束
    （NextHdr=5 钉进签名）防链重排绕签；§10.3 缺口关闭（无 RouteTrace 不得转发）
- [x] **Phase 3 · M2 ipv8-routing + Engine 转发角色**（routing 18 + Engine 多跳 7）
  - `src/core/ipv8-routing`：build/verify 以 `PathSpec/VerifyInput` 结构体入参
    （签名权以闭包外置，crate 不接触私钥）；`StaticRouter`（邻接表 BFS）+
    `Router` trait；`cf.rs` Chord 为 feature 骨架（默认关，不进验收）
  - Engine 数据面：`enable_forwarding(anchor)` 开启 Relay；多跳包（链首 RouteTrace）
    **无论本机是中转还是目的地都必须先过三验**（PathSig/证书绑定/跳位一致），
    验证失败 `fwd_rejected`；中转 `ForwardTo` 输出 HopLimit−1 的**明文重建包**
    （重封装归"本节点↔下一跳"的另一条隧道——每段独立密钥，`seal_prebuilt`）；
    `seal_multihop` 源点 API：用自身证书签路径、附 IdentityToken 头（120B 证书
    线格式 `Cert::to_wire`），超 MTU 逐片分片。`EngineStats` 新增
    `forwarded / fwd_rejected`
  - 关键语义教训：初始 HopLimit 不能只进签名（中转无法反推）→ 必须是
    RouteTrace 内明文被签副本，校验式 `当前 == Init − k`（k=hops 下标，
    目的地不减，与 IP 语义一致）
- [x] **Phase 3 · M3 ipv8-qos + C# QoSManagerService**（Rust 8 + C# 契约 2）
  - classifier：基头 flags 低 4bit → 4 级（level/4）；scheduler：严格优先 +
    类内 FIFO + 每类有界（满则交还调用方并计数）；reservation：§6.5 只产出不消费
  - C#：`IQoSScheduler`（Abstractions，接口先行）+ Host `QoSManagerService`
    （4 级队列宿主实现，`QoSClassCapacity` 配置外部化）+ DI 注册 + 契约测试
- [x] **Phase 3 · M4 ipv8-resolver**（13 测试，含 2 项 gRPC e2e）
  - `resolver.proto` 按 v9 权威定义（Resolve 原子返回 入口/ipv8_capable/mtu/
    alt_ips/ttl；查询主体=canonical 地址文本，域名映射归 ANS/Phase 4）
  - PoP 登记（域 `ipv8plus-resolve` 防冒注入口）：首次必须自证；同公钥免签更新；
    换公钥 KeyConflict（身份迁移只能走 ZoneServer 轮换）；过期条目新身份可接管；
    TTL 服务端裁剪 [1s, 24h]；NotFound 不区分"未登记/已过期"（ADR-007 防枚举）；
    `trait Store` 抽象（内存实现，持久化按 ADR-010 触发条件后置）；serve 内嵌
    60s reaper
- [x] **Phase 3 · M5 多跳端到端验证（真实 UDP，CI 可跑）**（4 项，无需 wintun/UAC）
  - `tests/e2e_multihop.rs`：①A→R→B 全链（seal_multihop→R 验证排队→面向 B 隧道
    seal_prebuilt→B 三验交付，两条独立认证隧道各自握手）；②跳列表字节篡改→R 拒转；
    ③未启用转发的引擎一律拒收多跳包；④QoS Level 13 进签名后跨两跳原样搬运、
    目的地验签仍过
  - 三 wintun 进程 + 中继守护的脚本 `-MultiHop` 实测未排：中继需多隧道编排
    （地址→隧道映射 + 路由注入），与验证守护"单对端"定位冲突，留作
    Hyper-V 双 VM 手册的后续增强
- [x] **Phase 3 全部完成**（M1-M5）
- [x] **Phase 4 · M1 AgentCard/SemanticTag 布局定稿与 ADR**
  - spec §6.7 AgentCard（128B：Version‖Rsv‖CardHash16‖NotAfter8‖AgentPubKey32‖CardSig64，
    域 `ipv8plus-agentcard`）与 §6.8 SemanticTag（US 分隔标签，≤32 个 / ≤48B / 小写 ASCII）定稿；
    **摘要进包 + ANS 拉全文**（CardSig 由 agent 自身密钥签，防 CardHash 换值冒充投递）；
    §6.2 回路规则不改（同类型至多一个）；ADR-022（ANS 用 Rust 实现的 v9 偏差）、
    ADR-023（卡片数据模型 + ANS↔Resolver↔ZoneServer 边界 + 三维寻址定义）落 Accepted
- [x] **Phase 4 · M2 ipv8-ans crate 核心**（35 测试）
  - `src/cloud/ans` 零 IO：三验登记（证书绑定→CardSig→PoP 域 `ipv8plus-ans-register`）、
    名字/能力/任务三维寻址（精确标签覆盖 + qos + 剩余 TTL 打分排序 (qos↓,not_after↓,addr↑)）、
    租约式分片计划（防并发双订）、report_done 释放、reap 回收、`trait Store`；
    NotFound 不区分未登记/过期（ADR-007 防枚举）、KeyConflict 防换密钥、NameConflict 防抢占
- [x] **Phase 4 · M3 ans.proto + gRPC 接线**（3 项 gRPC e2e）
  - 五 RPC：RegisterAgent/ResolveName/Capability/PlanTask/ReportDone；build.rs protox 生成、
    tonic 接线、`ipv8-ans` 守护进程（serve 内嵌 60s reaper）；e2e 覆盖 v9 验收主链路
    （3 异构注册→寻址→规划→回报）、错误码映射、同名冲突
- [x] **Phase 4 · M4 C# 接口先行 + 编排状态机 + 共享向量**（C# 13 契约）
  - `IAnsService`/`IAgentMesh` + 计划生命周期 `PlanState`（Pending→Planned→Leased→Completed/Expired）；
    Host `AgentMeshService`（本地镜像 + 编排，与 Rust 逐规则对齐）；DI 注册
  - **共享测试向量** `shared/test-vectors/ans-plans.json`（纯 ASCII）：12 步剧本（能力排序/
    计划分片/租约算术/回报/回收）在 Rust（真实验签登记）与 C#（Upsert 镜像）两侧重放，
    逐步骤断言完全相同的裁决——任何一侧语义漂移即红（`ANS_shared_vector_matches_rust`）
- [x] **Phase 4 · M5 多 Agent 协作验收**
  - 证据链：① Rust 真实 UDP/gRPC 3 异构 agent→能力≥2 候选→PlanTask fan-out→租约回报/回收；
    ② C# 状态机对同一向量产出相同计划；③ AgentCard 头过隧道 AEAD 完整性测试
    （链明文段原样往返 + 篡改 version/公钥字节均破 AEAD）；④ 全量门禁（Rust 208 + C# 13）
- [x] **Phase 4 全部完成**（M1-M5）
- [x] **Phase 5 · 内核优化评估（仅评估，无驱动代码）**
  - `docs/phase5-kernel-evaluation.md`：三条内核路径（WFP callout / NDIS LWF /
    XDP-eBPF）逐一评估全部**否决**——实测基线（i9-13900H，
    `tests/bench_dataplane.rs`，4 项 `#[ignore]` 可复现）显示引擎单核
    0.37 GiB/s ≈ 3.2 Gbps，且引擎 overhead 仅占 AEAD 之上 ~13%：
    **瓶颈是 ChaCha20 加密，内核旁路触及不到**；XDP 面向入站 L2/策略钩子，
    不适配出站封装 UDP 隧道模型
  - ADR-024 **Accepted**：不进入内核改造；性能演进改走用户态三路线
    （AES-NI 套件 / wintun 批量 API / 流级多核）；复评触发条件明列
    （≥10Gbps 单流 / CPU 受限 / 拷贝占比反转 / 入站抗 DDoS 立项）
  - **v9 路线图五阶段至此全部收口**

验证中修复的三个真实缺陷（均有回归测试）：单 adapter 双 start_session 非法（官方
示例=单双工 session）；Windows UDP 端口不可达武装错误 10054 曾杀死收线程；
握手无幂等重发导致 Resp 丢失后永久卡 Initiating。

## 质量门禁

```
# Rust（协议引擎层）
cargo clippy --workspace --all-targets -- -D warnings   # 0 warning
cargo test --workspace                                  # 208 测试全绿

# C#（服务/适配层，.NET 10 SDK；本机 SDK 缺 workload 目录，
# Directory.Build.props 已全局关闭 workload 解析器）
dotnet build IPv8Plus.slnx                              # 0 警告 0 错误
dotnet run --project tests/services/IPv8Plus.Services.Tests   # 13 契约测试全绿
```

C# 侧当前为零外部 NuGet 包状态（xunit / Grpc 待联网后接入）：
Host 经 `FrameworkReference Microsoft.AspNetCore.App` 取 DI/Hosting/Logging/Configuration；
测试为自包含运行器（退出码 = 失败数），被测类 `ClientOptions` 经 Compile Link 共享。

## 工程结构

```
src/core/          协议引擎层（Rust）：codec / routing / qos / tunnel / grpc / ffi
src/adapter/       网络适配层：wintun.dll + 设备生命周期封装 + wintun-node 守护进程
src/services/      应用服务层（C#）：Abstractions / Host
src/cloud/         云端服务（Rust）：ZoneServer / Resolver / ANS（ADR-022：ANS 用 Rust 实现）
src/tools/         内部工具（ws-node 等）
shared/ipv8-proto/ gRPC 契约（.proto 为接口权威来源）
shared/test-vectors/ Rust↔C# 双侧一致性共享测试向量
docs/              规范 + 设计文档 + ADR + 参考资料
deploy/            部署脚本与二进制
scripts/           验证与测试脚本
tests/             测试项目
tools/             外部工具（cloudflared / grpcurl）
```

依赖方向铁律：上层调下层，下层绝不调上层；同层走事件总线；跨层走接口。
