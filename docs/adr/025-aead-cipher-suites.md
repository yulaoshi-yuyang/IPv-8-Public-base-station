# ADR-025：隧道 AEAD 密码套件（ChaCha20-Poly1305 / AES-256-GCM）

- 状态：已接受
- 日期：2026-09-06
- 关联：ADR-005（密钥代与逐代派生）、protocol-spec §5.1/§10.1、`src/core/ipv8-tunnel/src/crypto.rs`

## 背景

隧道数据面此前唯一使用 ChaCha20-Poly1305。x86-64 服务器上 AES-NI 使
AES-256-GCM 吞吐显著更高（内核态 IPsec/WireGuard 部署普遍默认 AES-GCM）；
而无 AES-NI 的平台（老 CPU、部分 ARM 边缘盒子）仍需 ChaCha20-Poly1305。
需要一个零回归的双套件方案。

## 决策

1. **部署配置、不做协商**：隧道两端各自在启动配置中指定套件
   （`Engine::set_cipher_suite`，仅允许握手完成前调用）。握手上行不变，
   不新增协商消息——协商会把套件变成攻击者可控输入（降级攻击面）。
2. **KeyID 线格式承载套件字节**：帧头 KeyID 8 字节改为
   `suite(1B) ‖ epoch 低 7B`。`suite`：0 = ChaCha20-Poly1305（默认），
   1 = AES-256-GCM；未知值 → `UnknownKeyId` 丢弃。
   epoch 在轮换阈值下永远 < 2^56，默认套件 KeyID[0]=0 与 Phase 1-4
   的纯 epoch 大端 8 字节**逐字节相同**（向后兼容是构造性成立）。
3. **套件进 HKDF info（域分离）**：派生 info 追加 suite 字节，同一
   DH/epoch 在两套件下得到不同密钥 → 即使误把 AES 密文喂给 ChaCha
   解密路径，也只是认证失败，不存在跨套件误解密。
4. **接收方不采信帧内套件派生密钥**：密钥派生只信本地配置的 suite；
   帧内 suite ≠ 本端配置 → `SuiteMismatch`（丢弃 + 计数，作为配置漂移
   诊断信号），绝不按对端声明切换解密方式。

## 后果

- 正面：服务器侧可切 AES-NI 提速；混合部署可按节点异构；默认零回归。
- 负面：套件不一致的两端握手后首帧即 SuiteMismatch（快速失败、可诊断，
  好于静默半通）。运维须保证成对配置（与 mtu 同类部署参数）。
- 验证：`crypto`（AES 往返、跨套件拒收、默认 KeyID 逐字节兼容）、
  `engine`（AES 端到端、套件漂移拒收）测试覆盖；旧 65 项全绿。
