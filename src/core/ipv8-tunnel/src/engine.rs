//! 隧道引擎门面：握手状态机 + 数据面封拆壳 + IPv8+ 包组装
//!
//! 角色（v9 §2 数据面）
//! - OS 把内IP 包写TUN [`Engine::seal_frame`] 组装并加IPv8+
//!   （载= 原始 IP 包，spec §7）→ 交给外层 UDP（Phase 1 wintun/OS 完成，测试用内存链路）
//! - 收到隧道[`Engine::handle_frame`]：握手帧走状态机
//!   Data 帧拆壳还IPv8+ 包并取出内层 IP 写回 TUN
//!
//! 两种握手模式
//! - **明文模式**（Phase 1，已回环验收）：`Engine::new` + `start_handshake`
//!   X25519 裸协商，无身份认证（MITM 缺口由认证模式补）
//! - **认证模式**（Phase 2）：`Engine::authenticated` + `start_auth_handshake` +
//!   [`Engine::handle_frame_at`]，CA 证书 + Ed25519 transcript 签名（auth.rs），
//!   强制绑定预期对端地址（peer_addr）。认证失败记录于 [`Engine::last_auth_error`]
//!   认证握手需要时钟，故走 `handle_frame_at(frame, now)`；`handle_frame` 委托 now=0
//!   对明Data 帧无影响（仅认证分支消费 now）
//!
//! Data 面（封装/拆壳/计数/轮换）两模式完全共用
use std::collections::VecDeque;

use ipv8_codec::{
    decode as decode_ipv8, encode, flags, fragment_packet, IPv8Address, IPv8Header, Reassembler,
    RouteTrace, DEFAULT_MTU, ExtType, ExtensionHeader,
};
use ipv8_routing::{build_route_trace, verify_for_next_hop, Decision, PathSpec, TracePolicy};

use crate::auth::{self, AuthError, AuthPending, HostIdentity, TrustAnchor, AUTH_BUNDLE_LEN};
use crate::crypto::{CipherSuite, Identity, TunnelKeys};
use crate::encapsulate::{decapsulate, encapsulate};
use crate::frame::{parse_head, write_head, FrameType, FRAME_HEADER_SIZE};
use crate::handshake::{accept_init, create_init, finish_init, PendingHandshake};

/// 握手是否完成
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// 初始，未发起握手
    Idle,
    /// 已发(Auth)Init，等Resp
    Initiating,
    /// 已收Init，等待把 Resp 交给对端
    Responding,
    /// 双方密钥就绪
    Established,
}

/// 认证模式所需的全部静态材料（构造期注入，握手期只读
struct AuthCtx {
    host: HostIdentity,
    trust: TrustAnchor,
}

/// 多跳转发上下文（spec §6.6 / ADR-019；None = 永不转发，Phase 1/2 行为
///
/// 源证书按 spec IdentityToken *随包携带**，故上下文只需本地信任锚
struct FwdCtx {
    /// 信任锚公钥（SrcAddr↔SrcPubKey 证书绑定
    anchor_pub: [u8; 32],
}

/// 一次转发的输出：重建后的完IPv8+ + 下一IPv8+ 地址
pub struct ForwardOut {
    pub packet: Vec<u8>,
    pub next: IPv8Address,
}

/// 单条隧道的引擎（Phase 1：点到点；多对端路由表属 Phase 3 ipv8-routing
pub struct Engine {
    /// 明文握手模式X25519 静态身份；认证模式None
    identity: Option<Identity>,
    /// 认证模式材料；明文模式为 None
    auth: Option<AuthCtx>,
    state: State,
    /// 明文握手发起方待完成状
    pending: Option<PendingHandshake>,
    /// 认证握手发起方待完成状
    auth_pending: Option<AuthPending>,
    /// 本端密钥（握手完成后
    keys: Option<TunnelKeys>,
    /// AEAD 套件部署配置（ADR-025：默ChaCha20 = 零回归；两端须人工一致）
    /// 于每条隧道建立后应用到密钥状
    cipher_suite: CipherSuite,
    /// 本端 IPv8+ 地址（wrap 时填 SrcAddr
    local_addr: IPv8Address,
    /// 对端 IPv8+ 地址（wrap 时填 DstAddr；认证模式亦expected_peer
    peer_addr: IPv8Address,
    /// 最近一Data 帧解出的内层 IP 包（待写TUN
    delivered: Option<Vec<u8>>,
    /// 已绑定的 Init 帧体（明64B / 认证 216B）：幂等重发判定
    bound_init: Option<Vec<u8>>,
    /// 为该 Init 生成过的完整 Resp 帧（Established 下重收同一 Init 时原样重发）
    cached_resp: Option<Vec<u8>>,
    /// 最近一次认证握手失败原因（成功或明文模式为 None
    last_auth_error: Option<AuthError>,
    /// 发送侧 IPv8+ 包分片上限（40B 头；v9 默认 1432
    mtu: usize,
    /// 分片 ID 计数器（u32 回绕复用；同一隧道短窗口内不冲突即可）
    frag_id: u32,
    /// 接收侧分片重组器
    reassembler: Reassembler,
    /// 累计计数（gRPC TunnelStatus / 健康检查，单调不减
    sealed_outbound: u64,
    delivered_inbound: u64,
    dropped_inbound: u64,
    /// 发送侧产出的分片帧数（>1 即发生过实际分片
    fragments_sent: u64,
    /// 接收侧完成的重组次数
    fragments_reassembled: u64,
    /// 多跳转发上下文；None = 不转发（Phase 1/2 零回归默认）
    fwd: Option<FwdCtx>,
    /// 待上层发往下一跳的完整 IPv8+ 包（HopLimit 已减
    forward_out: VecDeque<(IPv8Address, Vec<u8>)>,
    /// 成功转发包数
    forwarded: u64,
    /// 验证失败被拒的转发包数（含本不该找上我的
    fwd_rejected: u64,
}

impl Engine {
    /// 明文握手模式（Phase 1 已验收路径）
    pub fn new(identity: Identity, local_addr: IPv8Address, peer_addr: IPv8Address) -> Self {
        Self {
            identity: Some(identity),
            auth: None,
            state: State::Idle,
            pending: None,
            auth_pending: None,
            keys: None,
            local_addr,
            peer_addr,
            delivered: None,
            bound_init: None,
            cached_resp: None,
            last_auth_error: None,
            cipher_suite: CipherSuite::default(),
            mtu: DEFAULT_MTU,
            frag_id: 0,
            reassembler: Reassembler::new(),
            sealed_outbound: 0,
            delivered_inbound: 0,
            dropped_inbound: 0,
            fragments_sent: 0,
            fragments_reassembled: 0,
            fwd: None,
            forward_out: VecDeque::new(),
            forwarded: 0,
            fwd_rejected: 0,
        }
    }

    /// 认证握手模式（Phase 2）：host/trust 为静态材料，peer_addr 作预期对端绑
    pub fn authenticated(
        host: HostIdentity,
        trust: TrustAnchor,
        local_addr: IPv8Address,
        peer_addr: IPv8Address,
    ) -> Self {
        Self {
            identity: None,
            auth: Some(AuthCtx { host, trust }),
            state: State::Idle,
            pending: None,
            auth_pending: None,
            keys: None,
            local_addr,
            peer_addr,
            delivered: None,
            bound_init: None,
            cached_resp: None,
            last_auth_error: None,
            cipher_suite: CipherSuite::default(),
            mtu: DEFAULT_MTU,
            frag_id: 0,
            reassembler: Reassembler::new(),
            sealed_outbound: 0,
            delivered_inbound: 0,
            dropped_inbound: 0,
            fragments_sent: 0,
            fragments_reassembled: 0,
            fwd: None,
            forward_out: VecDeque::new(),
            forwarded: 0,
            fwd_rejected: 0,
        }
    }

    pub fn state(&self) -> State {
        self.state
    }

    pub fn local_addr(&self) -> IPv8Address {
        self.local_addr
    }

    pub fn peer_addr(&self) -> IPv8Address {
        self.peer_addr
    }

    /// 设定对端地址（StartHandshake 时经 Resolver 解析后注入）
    pub fn set_peer_addr(&mut self, addr: IPv8Address) {
        self.peer_addr = addr;
    }

    /// 配置本隧道的 AEAD 套件（ADR-025）。仅允许在握手完成前设置——
    /// 部署配置在 node 启动时注入，两端必须人工一致（不做线上协商）。
    /// 隧道已建立时忽略（防止半程改套件导致密钥链分裂）。
    pub fn set_cipher_suite(&mut self, suite: CipherSuite) {
        debug_assert!(self.keys.is_none(), "隧道已建立，禁止改套件");
        if self.keys.is_some() {
            return;
        }
        self.cipher_suite = suite;
    }

    /// 本引擎配置的套件
    pub fn cipher_suite(&self) -> CipherSuite {
        self.cipher_suite
    }

    /// 最近一次认证握手失败原因（MITM/错配/伪过期），无则 None
    pub fn last_auth_error(&self) -> Option<AuthError> {
        self.last_auth_error
    }

    /// 认证模式材料的信任锚公钥（node 用它 enable_forwarding 验源证书
    pub fn trust_anchor_bytes(&self) -> Option<[u8; 32]> {
        self.auth.as_ref().map(|c| c.trust.anchor_bytes())
    }

    /// 发起方（明文）：生成 HandshakeInit 帧
    pub fn start_handshake(&mut self) -> Vec<u8> {
        assert_eq!(self.state, State::Idle, "只能 Idle 发起");
        let identity = self.identity.as_ref().expect("明文模式必有静态身");
        let (body, pending) = create_init(identity);
        self.pending = Some(pending);
        self.state = State::Initiating;
        let mut frame = Vec::new();
        write_head(&mut frame, FrameType::HandshakeInit, &[0u8; 8]);
        frame.extend_from_slice(&body);
        frame
    }

    /// 发起方（认证）：生成 AuthInit 帧（证书 + transcript 签名）
    pub fn start_auth_handshake(&mut self) -> Vec<u8> {
        assert_eq!(self.state, State::Idle, "只能 Idle 发起");
        let ctx = self.auth.as_ref().expect("认证模式必有 auth 材料");
        let (bundle, pending) = auth::auth_init(&ctx.host);
        self.auth_pending = Some(pending);
        self.state = State::Initiating;
        let mut frame = Vec::new();
        write_head(&mut frame, FrameType::AuthInit, &[0u8; 8]);
        frame.extend_from_slice(&bundle);
        frame
    }

    /// 放弃当前未完成的握手尝试，回Idle 以便*全新临时密钥**重开
    /// Fallback 用：某入口握手超时后，调用方`record_failure` 决定是否重试
    /// 若要重试，先 `abandon_handshake()` `start_(auth_)handshake()` 重发Init
    /// 仅作用于发起方（Initiating）；Established/Idle 下为幂等空操作，绝不破坏已建隧道
    pub fn abandon_handshake(&mut self) {
        if self.state == State::Initiating {
            self.pending = None;
            self.auth_pending = None;
            self.bound_init = None;
            self.cached_resp = None;
            self.state = State::Idle;
        }
    }

    /// 强制拆掉当前隧道回到 Idle（任意状态），清全部会话材料
    /// Fallback 首包超时场景必需：隧握手成功但数据不（Established 半开），
    /// 降级明文恢复重试前必须拆旧密钥，防止用死隧道的密钥继续封包
    /// abandon_handshake 的区别：本方法连 Established 一起拆，语义是"这条
    /// 隧道作废"，调用方须自行保证对端同步重建（node 双方各自超时各自 reset 即可收敛）
    pub fn reset(&mut self) {
        self.state = State::Idle;
        self.pending = None;
        self.auth_pending = None;
        self.keys = None;
        self.bound_init = None;
        self.cached_resp = None;
    }

    /// 处理收到的隧道帧（明Data 模式；认证帧需时钟请用 handle_frame_at）
    pub fn handle_frame(&mut self, frame: &[u8]) -> Option<Vec<u8>> {
        self.handle_frame_at(frame, 0)
    }

    /// 处理收到的隧道帧，认证分支使用注入的 `now`（epoch 秒）
    /// 返回 Some( = 需发回对端的响应；None = 无需响应
    /// Data 帧拆壳成功后，内IP 包通过 [`take_delivered`] 取走
    pub fn handle_frame_at(&mut self, frame: &[u8], now: u64) -> Option<Vec<u8>> {
        let head = parse_head(frame).ok()?;
        let body = &frame[FRAME_HEADER_SIZE..];
        match head.frame_type {
            FrameType::HandshakeInit => {
                // 明文握手，幂等重发（详见认证分支同构注释）
    // Established 下收*不同** Init = 对端 fallback 重协商：
                // 用新 Init 替换旧隧道（旧半开隧道可能数据不通，以最新协商为准）
    match self.state {
                    State::Established if self.bound_init.as_deref() == Some(body) => {
                        self.cached_resp.clone() // 幂等重发
                    }
                    State::Idle | State::Established => {
                        let identity = self.identity.as_ref()?;
                        let (resp_body, mut keys) = accept_init(identity, body).ok()?;
                        keys.set_suite(self.cipher_suite);
                        self.keys = Some(keys);
                        self.state = State::Established;
                        self.bound_init = Some(body.to_vec());
                        let mut out = Vec::new();
                        write_head(&mut out, FrameType::HandshakeResp, &[0u8; 8]);
                        out.extend_from_slice(&resp_body);
                        self.cached_resp = Some(out.clone());
                        Some(out)
                    }
                    _ => None, // Initiating=双主动冲突（保留 Phase 1 死锁保护）
                }
            }
            FrameType::HandshakeResp => {
                if self.state != State::Initiating {
                    return None;
                }
                let pending = self.pending.take()?;
                let mut keys = match finish_init(pending, body) {
                    Ok(k) => k,
                    Err(_) => {
                        self.state = State::Idle; // 损坏/伪造 Resp → 允许重新发起
                        return None;
                    }
                };
                keys.set_suite(self.cipher_suite);
                self.keys = Some(keys);
                self.state = State::Established;
                None
            }
            FrameType::AuthInit => {
                // 握手UDP 丢包 + 幂等：同一 AuthInit（同一对端临时公钥）重
    // 时，原样重发缓存 Resp，密钥不变，真幂等。认证三验任一失败
                // （伪过期/MITM/错配）→ last_auth_error 并丢弃，绝不建密钥
    let expected = Some(self.peer_addr);
                match self.state {
                    State::Established if self.bound_init.as_deref() == Some(body) => {
                        self.cached_resp.clone() // 幂等重发
                    }
                    State::Idle | State::Established => {
                        // Idle 新建；Established+不同 Init = 对端 fallback 重协商，
                        // 认证三验 + expected_peer 照常执行，通过才替换旧隧道密钥
                        let ctx = self.auth.as_ref()?;
                        if body.len() != AUTH_BUNDLE_LEN {
                            self.last_auth_error = Some(AuthError::BadBundleLen);
                            return None;
                        }
                        let accepted =
                            auth::auth_accept(&ctx.host, &ctx.trust, body, expected, now);
                        match accepted {
                            Ok((resp_body, mut keys)) => {
                                keys.set_suite(self.cipher_suite);
                                let mut out = Vec::new();
                                write_head(&mut out, FrameType::AuthResp, &[0u8; 8]);
                                out.extend_from_slice(&resp_body);
                                self.keys = Some(keys);
                                self.state = State::Established;
                                self.bound_init = Some(body.to_vec());
                                self.cached_resp = Some(out.clone());
                                self.last_auth_error = None;
                                Some(out)
                            }
                            Err(e) => {
                                self.last_auth_error = Some(e);
                                None
                            }
                        }
                    }
                    _ => None, // Initiating：等自家 Resp，不响应
                }
            }
            FrameType::AuthResp => {
                if self.state != State::Initiating {
                    return None;
                }
                let pending = self.auth_pending.take()?;
                let ctx = self.auth.as_ref()?;
                if body.len() != AUTH_BUNDLE_LEN {
                    self.last_auth_error = Some(AuthError::BadBundleLen);
                    self.state = State::Idle; // 可重Init
                    return None;
                }
                let expected = Some(self.peer_addr);
                match auth::auth_finish_init(pending, &ctx.trust, expected, body, now) {
                    Ok(mut keys) => {
                        keys.set_suite(self.cipher_suite);
                        self.keys = Some(keys);
                        self.state = State::Established;
                        self.last_auth_error = None;
                    }
                    Err(e) => {
                        self.last_auth_error = Some(e);
                        self.state = State::Idle; // 失败：允许发起方重发Init
                    }
                }
                None
            }
            FrameType::Data => {
                // 拆壳失败（篡重放/旧代/未建立）计入丢弃，便于健康诊
    match self.keys.as_mut().and_then(|k| decapsulate(k, frame).ok()) {
                    Some(ipv8_pkt) => {
                        match decode_ipv8(&ipv8_pkt) {
                            Ok(d) => {
                                if d.header.flags & flags::FRAGMENT != 0 {
                                    // 分片：交重组器，完成才产出内层包
                                    match self.reassembler.insert(&d.header, d.payload) {
                                        Ok(Some(reassembled)) => {
                                            self.fragments_reassembled += 1;
                                            self.ingest_ipv8_packet(&reassembled, now);
                                        }
                                        Ok(None) => {} // 分片未齐：等待更多片，不算丢弃
                                        Err(_) => self.dropped_inbound += 1, // 重叠/畸形片
                                    }
                                } else {
                                    self.ingest_ipv8_packet(&ipv8_pkt, now);
                                }
                            }
                            Err(_) => self.dropped_inbound += 1,
                        }
                    }
                    None => self.dropped_inbound += 1,
                }
                None
            }
            FrameType::Rekey => None, // 轮换seal 内部 epoch 推进覆盖，显Rekey 帧留接口
        }
    }

    /// 取走最近一Data 帧解出的内层 IP 包（写回 TUN 用）
    pub fn take_delivered(&mut self) -> Option<Vec<u8>> {
        std::mem::take(&mut self.delivered)
    }

    /// 启用多跳转发（Relay，spec §6.6）：提供本地信任锚（验源证书绑定）
    /// 未调用的引擎永不转发（Phase 1/2 零回归默认）
    pub fn enable_forwarding(&mut self, anchor_pub: [u8; 32]) {
        self.fwd = Some(FwdCtx { anchor_pub });
    }

    /// 转发策略（未启用NoForward
    pub fn forward_policy(&self) -> TracePolicy {
        if self.fwd.is_some() {
            TracePolicy::Relay
        } else {
            TracePolicy::NoForward
        }
    }

    /// 源点构造多跳包并封装为发往**第一*的隧道帧组（MTU 逐片）
    ///
    /// 路径 = `hops`（不含本机、末= 目的地）；本机证书（认证模式持有
    /// IdentityToken 头随包，供中目的地验SrcAddr↔SrcPubKey 绑定
    /// （spec §6.6）。返回的帧仍*本机↔第一*这条既有隧道密钥封装—
    /// 每段隧道各自调用一次本 API 续程（node take_forward_packet
    /// 下一跳选对Engine）
    pub fn seal_multihop(
        &mut self,
        inner_ip: &[u8],
        dst: IPv8Address,
        hops: &[IPv8Address],
        init_hop_limit: u8,
    ) -> Result<Vec<Vec<u8>>, EngineError> {
        let ctx = self.auth.as_ref().ok_or(EngineError::NotEstablished)?;
        if self.keys.is_none() {
            return Err(EngineError::NotEstablished);
        }
        if hops.is_empty() || hops.last() != Some(&dst) {
            return Err(EngineError::Frame(crate::frame::FrameError::BadType(5)));
        }
        // flags：E（载荷将加密 X（attach 会补），签名基于最终
    let base_flags = flags::ENCRYPTED;
        let plen = inner_ip.len() as u16;
        let host = &ctx.host;
        let ed_pub = host.public_ed_key();
        let cert_wire = host.cert.to_wire();
        let trace = build_route_trace(
            &PathSpec {
                src_addr: self.local_addr,
                dst_addr: dst,
                min_compat_ver: 0,
                flags: base_flags | flags::HAS_EXTENSION,
                payload_len: plen,
                init_hop_limit,
                hops,
                src_pubkey: &ed_pub,
            },
            |msg| host.sign(msg),
        )
        .map_err(|_| EngineError::Frame(crate::frame::FrameError::BadType(5)))?;

        let mut hdr = IPv8Header::new(self.local_addr, dst, plen);
        hdr.hop_limit = init_hop_limit;
        hdr.flags = base_flags;
        hdr.attach_ext_headers(vec![
            ExtensionHeader::new(ExtType::RouteTrace, trace.to_payload().map_err(|_| EngineError::Frame(crate::frame::FrameError::BodyTooShort))?)
                .ok_or(EngineError::Frame(crate::frame::FrameError::BodyTooShort))?,
            ExtensionHeader::new(ExtType::IdentityToken, cert_wire)
                .ok_or(EngineError::Frame(crate::frame::FrameError::BodyTooShort))?,
        ]);
        let whole = encode(&hdr, inner_ip).map_err(|_| EngineError::Frame(crate::frame::FrameError::BodyTooShort))?;

        // seal_frames 同路的分逐片封装（首片带整链：RouteTrace+IdentityToken
    let id = self.frag_id;
        self.frag_id = self.frag_id.wrapping_add(1);
        let pkts = fragment_packet(&whole, self.mtu, id).map_err(|_| EngineError::NeedsFragmentation(whole.len()))?;
        let n = pkts.len() as u64;
        let keys = self.keys.as_mut().expect("上方已检");
        let mut out = Vec::with_capacity(pkts.len());
        for p in &pkts {
            out.push(encapsulate(keys, p).map_err(EngineError::Frame)?);
        }
        self.sealed_outbound += n;
        self.fragments_sent += n.saturating_sub(1);
        Ok(out)
    }

    /// 取走下一待转发明IPv8+ 及其下一跳地址
    pub fn take_forward_packet(&mut self) -> Option<(IPv8Address, Vec<u8>)> {
        self.forward_out.pop_front()
    }

    /// 统一数据面入口：目的中转分流（spec §6.6 / §10.3）
    ///
    /// 多跳包（链首 RouteTrace*无论本机是目的地还是中转**都必须先
    /// PathSig/证书/跳位三验——目的地验不过同样丢弃（防劫持改道后"看似
    /// 正常到达"）。未启用多跳的引擎（fwd=None）拒收一切多跳包
    fn ingest_ipv8_packet(&mut self, pkt: &[u8], now: u64) {
        let d = match decode_ipv8(pkt) {
            Ok(d) => d,
            Err(_) => {
                self.dropped_inbound += 1;
                return;
            }
        };
        // 非多跳包（无链首 RouteTrace）：Phase 1/2 行为——交付本TUN
        if d.header.next_header != ExtType::RouteTrace.wire() {
            self.delivered = Some(d.payload.to_vec());
            self.delivered_inbound += 1;
            return;
        }
        match self.route_decision(&d, pkt, now) {
            Some(Decision::Deliver) if d.header.dst_addr == self.local_addr => {
                self.delivered = Some(d.payload.to_vec());
                self.delivered_inbound += 1;
            }
            Some(Decision::ForwardTo { next, .. }) => {
                // §4.3：只有转发节点减 1；减0 不得再转
                let Some(new_hl) = d.header.hop_limit.checked_sub(1).filter(|&h| h > 0) else {
                    self.fwd_rejected += 1;
                    return;
                };
                let mut hdr = d.header.clone();
                hdr.hop_limit = new_hl;
                match encode(&hdr, d.payload) {
                    Ok(new_pkt) => {
                        self.forwarded += 1;
                        self.forward_out.push_back((next, new_pkt));
                    }
                    Err(_) => self.fwd_rejected += 1,
                }
            }
            // 验证失败 / 决策与 DstAddr 矛盾 / 未启用多跳：丢弃并计数
            _ => self.fwd_rejected += 1,
        }
    }

    /// 三段验证（PathSig / 源证书绑/ 跳位一致）。失败返None（0.3）
    fn route_decision(
        &self,
        d: &ipv8_codec::Decoded<'_>,
        pkt: &[u8],
        now: u64,
    ) -> Option<Decision> {
        let ctx = self.fwd.as_ref()?;
        // §6.6 链首：基头字节 0-6 校验（含 NextHdr==5），不符即绕签名攻击
        let head7: [u8; 7] = pkt[0..7].try_into().expect("decode 已保证≥40B");
        ipv8_routing::frozen_head(&head7)?;
        // RouteTrace 载荷解码（链首类5，decode 已保ext[0] 存在
    let trace = RouteTrace::from_payload(&d.header.ext_headers[0].payload).ok()?;
        // 源证书必须随包（IdentityToken = 120B Cert::to_wire，spec §6.6
    let idtok = d
            .header
            .ext_headers
            .iter()
            .find(|e| e.ext_type == ExtType::IdentityToken)?;
        if idtok.payload.len() != 120 {
            return None;
        }
        verify_for_next_hop(&ipv8_routing::VerifyInput {
            local_addr: self.local_addr,
            trace: &trace,
            head7: &head7,
            src_addr: d.header.src_addr,
            dst_addr: d.header.dst_addr,
            current_hop_limit: d.header.hop_limit,
            cert_wire: &idtok.payload,
            anchor_pub: &ctx.anchor_pub,
            now,
        })
        .ok()
    }

    /// 内层 IP 完整 IPv8+ 包（载荷 = 原始 IP 包）
    pub fn build_ipv8_packet(&self, inner_ip: &[u8]) -> Vec<u8> {
        let hdr = IPv8Header::new(self.local_addr, self.peer_addr, inner_ip.len() as u16);
        encode(&hdr, inner_ip).expect("构造合法：长度由调用方约束")
    }

    /// 封装一*已构建好* IPv8+ 包（不重写包头）为隧道帧
    ///
    /// 多跳中继专用：`take_forward_packet` 输出的重建包（DstAddr 是下一
    /// 之后的真目的）必须原样进本节点↔下一的隧道——点对点封装路径
    /// `seal_frame` 会覆DstAddr 为隧道对端，不能复用
    pub fn seal_prebuilt(&mut self, ipv8_pkt: &[u8]) -> Result<Vec<u8>, EngineError> {
        let keys = self.keys.as_mut().ok_or(EngineError::NotEstablished)?;
        if ipv8_pkt.len() > self.mtu {
            return Err(EngineError::NeedsFragmentation(ipv8_pkt.len()));
        }
        let frame = encapsulate(keys, ipv8_pkt).map_err(EngineError::Frame)?;
        self.sealed_outbound += 1;
        Ok(frame)
    }

    /// 设定发送侧 IPv8+ 包分片上限（40B 基础头）。v9 建议 1432 = 1500 - 68
    pub fn set_mtu(&mut self, mtu: usize) {
        self.mtu = mtu;
    }

    /// 内层 IP **单个**隧道帧。仅当整包不MTU（不会分片）时可用；
    /// 会分片的输入返回 `NeedsFragmentation(len)`——调用方必须改用
    /// [`seal_frames`] 逐帧发送，绝不能只取首帧（那等于丢包）
    /// 握手/控制路径与小包用本方法
    pub fn seal_frame(&mut self, inner_ip: &[u8]) -> Result<Vec<u8>, EngineError> {
        if self.keys.is_none() {
            return Err(EngineError::NotEstablished);
        }
        let whole = self.build_ipv8_packet(inner_ip);
        if whole.len() > self.mtu {
            return Err(EngineError::NeedsFragmentation(whole.len()));
        }
        let keys = self.keys.as_mut().expect("上方已检");
        let frame = encapsulate(keys, &whole).map_err(EngineError::Frame)?;
        self.sealed_outbound += 1;
        Ok(frame)
    }

    /// 内层 IP **一*隧道帧：包超 MTU 时先spec §8.3 分片再逐片封装
    /// 调用方需把每个帧作为独立 UDP 报文发出（分片跨包序保留IPv8+ Fragment 头）
    pub fn seal_frames(&mut self, inner_ip: &[u8]) -> Result<Vec<Vec<u8>>, EngineError> {
        if self.keys.is_none() {
            return Err(EngineError::NotEstablished);
        }
        let whole = self.build_ipv8_packet(inner_ip);
        let id = self.frag_id;
        self.frag_id = self.frag_id.wrapping_add(1);
        let pkts = fragment_packet(&whole, self.mtu, id).map_err(|e| {
            // 分片器只会因输入包非太小 MTU 失败；均归为帧错误透传
            EngineError::Frame(match e {
                ipv8_codec::FragmentError::MtuTooSmall(m) => crate::frame::FrameError::TooShort(m),
                _ => crate::frame::FrameError::BodyTooShort,
            })
        })?;
        let n = pkts.len() as u64;
        let keys = self.keys.as_mut().expect("上方已检");
        let mut out = Vec::with_capacity(pkts.len());
        for p in &pkts {
            out.push(encapsulate(keys, p).map_err(EngineError::Frame)?);
        }
        self.sealed_outbound += n;
        self.fragments_sent += n.saturating_sub(1); // 超出 1 的算分片产出
        Ok(out)
    }

    /// 状态快照（gRPC TunnelStatus 映射
    pub fn stats(&self) -> EngineStats {
        EngineStats {
            state: self.state,
            send_epoch: self.keys.as_ref().map(TunnelKeys::current_epoch),
            sealed_outbound: self.sealed_outbound,
            delivered_inbound: self.delivered_inbound,
            dropped_inbound: self.dropped_inbound,
            fragments_sent: self.fragments_sent,
            fragments_reassembled: self.fragments_reassembled,
            forwarded: self.forwarded,
            fwd_rejected: self.fwd_rejected,
            authenticated: self.auth.is_some(),
            last_auth_error: self.last_auth_error,
        }
    }

    /// 暴露密钥状态供测试/诊断
    pub fn epoch(&self) -> Option<u64> {
        self.keys.as_ref().map(TunnelKeys::current_epoch)
    }
}

/// 引擎状态快照（无地址/身份信息的纯诊断视图）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EngineStats {
    pub state: State,
    pub send_epoch: Option<u64>,
    pub sealed_outbound: u64,
    pub delivered_inbound: u64,
    pub dropped_inbound: u64,
    /// 发送侧产出额外分片数（不含未分片包本身
    pub fragments_sent: u64,
    /// 接收侧完成的重组次数
    pub fragments_reassembled: u64,
    /// 多跳中转成功转发的包数（HopLimit 已减并重建）
    pub forwarded: u64,
    /// 多跳验证失败被拒的包数（篡改/冒充/跳位不符/未启用转发）
    pub fwd_rejected: u64,
    /// 本引擎是否为认证握手模式
    pub authenticated: bool,
    /// 最近一次认证握手失败原因（无则 None
    pub last_auth_error: Option<AuthError>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineError {
    NotEstablished,
    /// 包超 MTU 会分片（携带实际包长）：单帧 API 拒绝，请改用 seal_frames 全帧发
    NeedsFragmentation(usize),
    Frame(crate::frame::FrameError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{provision, CertAuthority, NO_EXPIRY};

    fn a(n: u32) -> IPv8Address {
        IPv8Address::new(64500, n, 1, 0, 1)
    }

    /// 完整认证握手接入数据面：两个 Engine::authenticated handle_frame_at
    /// 建立隧道后，双向 ping/pong 通过真实seal/open 路径
    #[test]
    fn authenticated_engine_end_to_end() {
        let ca = CertAuthority::from_seed([0xC4u8; 32]);
        let trust = TrustAnchor::from_bytes(ca.public_key()).unwrap();
        let host_a = provision(&ca, a(1), [0xA1u8; 32], NO_EXPIRY);
        let host_b = provision(&ca, a(2), [0xB0u8; 32], NO_EXPIRY);
        let now = 1_700_000_000u64;

        let mut alice = Engine::authenticated(host_a, trust.clone(), a(1), a(2));
        let mut bob = Engine::authenticated(host_b, trust, a(2), a(1));

        let init = alice.start_auth_handshake();
        let resp = bob.handle_frame_at(&init, now).expect("Bob 应回 AuthResp");
        assert_eq!(bob.state(), State::Established);
        assert!(alice.handle_frame_at(&resp, now).is_none());
        assert_eq!(alice.state(), State::Established);
        assert_eq!(alice.last_auth_error(), None);

        // 数据面双
    let ping = [0x45u8, 0x00, 0x00, 0x14, b'p'];
        let f = alice.seal_frame(&ping).unwrap();
        bob.handle_frame_at(&f, now);
        assert_eq!(bob.take_delivered().as_deref(), Some(&ping[..]));
        let pong = [0x45u8, 0x00, 0x00, 0x14, b'q'];
        let fb = bob.seal_frame(&pong).unwrap();
        alice.handle_frame_at(&fb, now);
        assert_eq!(alice.take_delivered().as_deref(), Some(&pong[..]));
        assert_eq!(alice.stats().dropped_inbound, 0);
        assert_eq!(bob.stats().sealed_outbound, 1);
    }

    /// 认证模式下，中间人替AuthInit 的临时公Bob 记录 BadHandshakeSignature
    /// 且绝不进Established（对照明文模式此攻击可畅通）
    #[test]
    fn authenticated_engine_rejects_mitm() {
        let ca = CertAuthority::from_seed([0xC4u8; 32]);
        let trust = TrustAnchor::from_bytes(ca.public_key()).unwrap();
        let host_a = provision(&ca, a(1), [0xA1u8; 32], NO_EXPIRY);
        let host_b = provision(&ca, a(2), [0xB0u8; 32], NO_EXPIRY);
        let mallory = provision(&ca, a(3), [0x5Au8; 32], NO_EXPIRY);
        let now = 1u64;

        let mut alice = Engine::authenticated(host_a, trust.clone(), a(1), a(2));
        let mut bob = Engine::authenticated(host_b, trust, a(2), a(1));

        let mut init = alice.start_auth_handshake();
        // 换掉 AuthInit 的临时公钥（bytes[10..42]），其余Alice 的合法证
    let (evil, _p) = auth::auth_init(&mallory);
        init[FRAME_HEADER_SIZE..FRAME_HEADER_SIZE + 32].copy_from_slice(&evil[..32]);

        assert!(bob.handle_frame_at(&init, now).is_none());
        assert_eq!(bob.state(), State::Idle, "MITM 篡改后不得建隧道");
        assert_eq!(bob.last_auth_error(), Some(AuthError::BadHandshakeSignature));
        // Bob 没有密钥可发数据
        assert!(bob.seal_frame(b"x").is_err());
    }

    /// 合法 CA 下对话对象错配（Resolver 被投毒）：证签名都真，但不是预期对端
    #[test]
    fn authenticated_engine_enforces_expected_peer() {
        let ca = CertAuthority::from_seed([0xC4u8; 32]);
        let trust = TrustAnchor::from_bytes(ca.public_key()).unwrap();
        let host_a = provision(&ca, a(1), [0xA1u8; 32], NO_EXPIRY);
        let host_b = provision(&ca, a(2), [0xB0u8; 32], NO_EXPIRY);
        let mut alice = Engine::authenticated(host_a, trust.clone(), a(1), a(2));
        // Bob 被配置成预期addr(99)，但来的是合法的 Alice(1)
        let mut bob = Engine::authenticated(host_b, trust, a(2), a(99));
        let init = alice.start_auth_handshake();
        assert!(bob.handle_frame_at(&init, 1).is_none());
        assert!(matches!(
            bob.last_auth_error(),
            Some(AuthError::PeerMismatch { expected, got }) if expected==a(99) && got==a(1)
        ));
    }

    /// 认证 Established 后重发同一 AuthInit 幂等重发同一 AuthResp，密钥不
    #[test]
    fn authenticated_engine_idempotent_retransmit() {
        let ca = CertAuthority::from_seed([0xC4u8; 32]);
        let trust = TrustAnchor::from_bytes(ca.public_key()).unwrap();
        let host_a = provision(&ca, a(1), [0xA1u8; 32], NO_EXPIRY);
        let host_b = provision(&ca, a(2), [0xB0u8; 32], NO_EXPIRY);
        let mut alice = Engine::authenticated(host_a, trust.clone(), a(1), a(2));
        let mut bob = Engine::authenticated(host_b, trust, a(2), a(1));
        let init = alice.start_auth_handshake();
        let resp1 = bob.handle_frame_at(&init, 5).unwrap();
        let resp2 = bob.handle_frame_at(&init, 6).expect("同一 Init 重发应幂");
        assert_eq!(resp1, resp2, "重发必须逐字节相");
        assert_eq!(bob.state(), State::Established);
    }

    /// 明文路径回归：确认认证接入未破坏 Phase-1 状态机
    #[test]
    fn plaintext_path_still_works() {
        let ia = Identity::from_bytes([1u8; 32]);
        let ib = Identity::from_bytes([2u8; 32]);
        let mut alice = Engine::new(ia, a(1), a(2));
        let mut bob = Engine::new(ib, a(2), a(1));
        let init = alice.start_handshake();
        let resp = bob.handle_frame(&init).unwrap();
        alice.handle_frame(&resp);
        assert_eq!(alice.state(), State::Established);
        assert!(!alice.stats().authenticated, "明文模式标记应为 false");
        let pkt = [0x45u8, 0x00, 0x00, 0x14];
        let f = alice.seal_frame(&pkt).unwrap();
        bob.handle_frame(&f);
        assert_eq!(bob.take_delivered().as_deref(), Some(&pkt[..]));
    }

    /// AES-256-GCM 套件端到端：握手完成即切套件，Data 帧 KeyID[0]==1
    #[test]
    fn aes_suite_engine_roundtrip() {
        let ia = Identity::from_bytes([1u8; 32]);
        let ib = Identity::from_bytes([2u8; 32]);
        let mut alice = Engine::new(ia, a(1), a(2));
        let mut bob = Engine::new(ib, a(2), a(1));
        alice.set_cipher_suite(CipherSuite::Aes256Gcm);
        bob.set_cipher_suite(CipherSuite::Aes256Gcm);
        let init = alice.start_handshake();
        let resp = bob.handle_frame(&init).unwrap();
        alice.handle_frame(&resp);
        assert_eq!(alice.state(), State::Established);
        let pkt = [0x45u8, 0x00, 0x00, 0x14, b'a', b'v'];
        let f = alice.seal_frame(&pkt).unwrap();
        assert_eq!(f[2], 1, "AES 隧道 Data 帧 KeyID[0] 必须为 1");
        bob.handle_frame(&f);
        assert_eq!(bob.take_delivered().as_deref(), Some(&pkt[..]));
        assert_eq!(bob.stats().dropped_inbound, 0);
    }

    /// 套件漂移（只有一端配 AES）：帧必须被拒并计入丢弃，绝不误解密
    #[test]
    fn suite_drift_rejected_not_misdecrypted() {
        let ia = Identity::from_bytes([1u8; 32]);
        let ib = Identity::from_bytes([2u8; 32]);
        let mut alice = Engine::new(ia, a(1), a(2));
        let mut bob = Engine::new(ib, a(2), a(1));
        alice.set_cipher_suite(CipherSuite::Aes256Gcm); // bob 保持默认 ChaCha
        let init = alice.start_handshake();
        let resp = bob.handle_frame(&init).unwrap();
        alice.handle_frame(&resp);
        let pkt = [0x45u8, 0x00, 0x00, 0x14];
        let f = alice.seal_frame(&pkt).unwrap();
        bob.handle_frame(&f);
        assert_eq!(bob.take_delivered(), None, "套件漂移下绝不得交付");
        assert_eq!(bob.stats().dropped_inbound, 1);
    }

    /// Fallback 驱动原语：放弃超时的握手尝试后，可用**新临时密*重开并建成隧道；
    /// 旧尝试遗留的 Resp 必须被拒绝（防跨尝试混用）
    #[test]
    fn abandon_handshake_allows_retry_with_fresh_ephemeral() {
        let mut alice = Engine::new(Identity::from_bytes([1u8; 32]), a(1), a(2));
        let mut bob = Engine::new(Identity::from_bytes([2u8; 32]), a(2), a(1));

        // 尝试 1：发Init 但永远等不到 Resp（入口不可达
    let init1 = alice.start_handshake();
        assert_eq!(alice.state(), State::Initiating);
        // 对端是活的，Resp 发回 Alice 自己丢失"——此fallback 判定超时
        let resp1 = bob.handle_frame(&init1).expect("Bob 应答 attempt1");
        alice.abandon_handshake();
        assert_eq!(alice.state(), State::Idle, "放弃后回 Idle");
        // 迟到的旧 Resp 不能被接受（pending 已清，且密钥尝试已作废）
        assert!(alice.handle_frame(&resp1).is_none());
        assert_eq!(alice.state(), State::Idle);

        // 尝试 2：重开必须以全新临时密钥发Init（与Init 体不同）
        let init2 = alice.start_handshake();
        assert_ne!(init1, init2, "重开必须换临时密");
        // Bob 侧仍记着 attempt1 Established 不同 Init 视为对端 fallback
        // 重协商，直接应答并替换旧密钥（旧半开隧道作废，双方以最新协商为准）
        let resp2 = bob.handle_frame(&init2).expect("Established 下新 Init 应触发重协商");
        assert!(alice.handle_frame(&resp2).is_none());
        assert_eq!(alice.state(), State::Established);
        let f = alice.seal_frame(&[0x45u8, 0x00, 0x00, 0x14]).unwrap();
        bob.handle_frame(&f);
        assert_eq!(bob.take_delivered().as_deref(), Some(&[0x45u8, 0x00, 0x00, 0x14][..]));
        // 重协商后旧尝试的迟到 Resp（resp1）必须被拒：防跨会话混用
        alice.handle_frame(&resp1); // Established，收到旧 Resp 应忽        assert_eq!(alice.state(), State::Established, "迟到Resp 不得拆隧);
    }

    /// reset Established：旧密钥必须作废（seal NotEstablished），
    /// 这是"首包超时降级前拆死隧的原语
    #[test]
    fn reset_tears_down_established_tunnel() {
        let mut alice = Engine::new(Identity::from_bytes([1u8; 32]), a(1), a(2));
        let mut bob = Engine::new(Identity::from_bytes([2u8; 32]), a(2), a(1));
        let init = alice.start_handshake();
        let resp = bob.handle_frame(&init).unwrap();
        alice.handle_frame(&resp);
        assert_eq!(alice.state(), State::Established);
        alice.reset();
        assert_eq!(alice.state(), State::Idle);
        assert!(matches!(
            alice.seal_frame(&[0x45u8, 0x00, 0x00, 0x14]),
            Err(EngineError::NotEstablished)
        ), "reset 后旧密钥必须作废");
        // Idle 状态下可以重新发起
        let _ = alice.start_handshake();
        assert_eq!(alice.state(), State::Initiating);
    }

    /// Established 后调abandon 必须是无操作——绝不允许拆掉已建隧
    #[test]
    fn abandon_is_noop_when_established() {
        let mut alice = Engine::new(Identity::from_bytes([1u8; 32]), a(1), a(2));
        let mut bob = Engine::new(Identity::from_bytes([2u8; 32]), a(2), a(1));
        let init = alice.start_handshake();
        let resp = bob.handle_frame(&init).unwrap();
        alice.handle_frame(&resp);
        assert_eq!(alice.state(), State::Established);
        alice.abandon_handshake();
        assert_eq!(alice.state(), State::Established, "Established 不可 abandon 拆除");
        // 隧道仍可
    let f = alice.seal_frame(&[0x45u8, 0x00, 0x00, 0x14]).unwrap();
        bob.handle_frame(&f);
        assert_eq!(bob.take_delivered().as_deref(), Some(&[0x45u8, 0x00, 0x00, 0x14][..]));
    }

    // —多跳转发（spec §6.6 / ADR-019）：三节A→R→B，各段独立点对点隧道
    //    （明文握手即可——RouteTrace 的证书验证独立于隧道密钥）—
    use ipv8_codec::{encode as encode_pkt, ExtType as P3Ext, ExtensionHeader as P3ExtHdr};
    use ipv8_routing::{build_route_trace, PathSpec};

    /// 造一待转的多IPv8+ 明文包：链首 RouteTrace（源点签名）
    /// + IdentityToken（源证书 120B 载荷。cert_wire 可给伪造值以测拒收
    fn multihop_pkt(
        src: IPv8Address,
        dst: IPv8Address,
        hops: &[IPv8Address],
        init_hl: u8,
        inner: &[u8],
        src_seed: &[u8; 32],
        cert_wire: Vec<u8>,
    ) -> Vec<u8> {
        use ed25519_dalek::{Signer, SigningKey};
        let final_flags = flags::HAS_EXTENSION;
        let signing = SigningKey::from_bytes(src_seed);
        let src_pubkey = signing.verifying_key().to_bytes();
        let trace = build_route_trace(
            &PathSpec {
                src_addr: src,
                dst_addr: dst,
                min_compat_ver: 0,
                flags: final_flags,
                payload_len: inner.len() as u16,
                init_hop_limit: init_hl,
                hops,
                src_pubkey: &src_pubkey,
            },
            |msg| signing.sign(msg).to_bytes(),
        )
        .expect("路径合法");
        let mut hdr = IPv8Header::new(src, dst, inner.len() as u16);
        hdr.hop_limit = init_hl;
        hdr.flags = final_flags;
        hdr.attach_ext_headers(vec![
            P3ExtHdr::new(P3Ext::RouteTrace, trace.to_payload().unwrap()).unwrap(),
            P3ExtHdr::new(P3Ext::IdentityToken, cert_wire).unwrap(),
        ]);
        encode_pkt(&hdr, inner).unwrap()
    }

    /// 三节点隧道：A↔R、R↔B 各自 Established。返回四引擎 + + A 证书 + A seed
    fn hop3_setup() -> (Engine, Engine, Engine, Engine, [u8; 32], Vec<u8>, [u8; 32]) {
        let ca = CertAuthority::from_seed([0xC4u8; 32]);
        let anchor = ca.public_key();
        let host_a = provision(&ca, a(1), [0xA1u8; 32], NO_EXPIRY);
        let cert_a = host_a.cert.to_wire();

        let mut a_r = Engine::new(Identity::from_bytes([1u8; 32]), a(1), a(2));
        let mut r_a = Engine::new(Identity::from_bytes([2u8; 32]), a(2), a(1));
        let mut r_b = Engine::new(Identity::from_bytes([3u8; 32]), a(2), a(3));
        let mut b_r = Engine::new(Identity::from_bytes([4u8; 32]), a(3), a(2));
        r_a.enable_forwarding(anchor);
        b_r.enable_forwarding(anchor);
        let i1 = a_r.start_handshake();
        let s1 = r_a.handle_frame(&i1).unwrap();
        a_r.handle_frame(&s1);
        let i2 = r_b.start_handshake();
        let s2 = b_r.handle_frame(&i2).unwrap();
        r_b.handle_frame(&s2);
        assert_eq!(r_a.state(), State::Established);
        assert_eq!(b_r.state(), State::Established);
        (a_r, r_a, r_b, b_r, anchor, cert_a, [0xA1u8; 32])
    }

    #[test]
    fn multihop_relay_forwards_and_dst_delivers() {
        let (mut a_r, mut r_a, mut r_b, mut b_r, _an, cert_a, seed) = hop3_setup();
        let inner = vec![0x45u8, 0x00, 0x00, 0x14, b'x'];
        let pkt = multihop_pkt(a(1), a(3), &[a(2), a(3)], 64, &inner, &seed, cert_a);
        // A 用面R 的隧道封装（seal_prebuilt 保留 DstAddr=B
    let f1 = a_r.seal_prebuilt(&pkt).unwrap();
        r_a.handle_frame_at(&f1, 1);
        assert_eq!(r_a.take_delivered(), None, "中转不交付本");
        assert_eq!(r_a.stats().forwarded, 1);
        let (next, fpkt) = r_a.take_forward_packet().expect("应有转发输出");
        assert_eq!(next, a(3));
        assert_eq!(fpkt[5], 63, "R 转发应把 HopLimit 64 3");
        let f2 = r_b.seal_prebuilt(&fpkt).unwrap();
        b_r.handle_frame_at(&f2, 1);
        assert_eq!(b_r.take_delivered().as_deref(), Some(&inner[..]), "B 验证后交");
        assert_eq!(b_r.stats().fwd_rejected, 0);
        assert_eq!(b_r.stats().dropped_inbound, 0);
    }

    #[test]
    fn multihop_forged_source_cert_rejected() {
        let (mut a_r, mut r_a, .., seed) = hop3_setup();
        // 错配的源证书"（B 的证书冒A）→ 证书绑定阶段
    let ca = CertAuthority::from_seed([0xC4u8; 32]);
        let bob_cert = provision(&ca, a(3), [0xB0u8; 32], NO_EXPIRY).cert.to_wire();
        let pkt = multihop_pkt(
            a(1),
            a(3),
            &[a(2), a(3)],
            64,
            &[0x45, 0, 0, 0x14],
            &seed,
            bob_cert, // 声称源是 A 但证书是 B BadCertBinding
        );
        let f1 = a_r.seal_prebuilt(&pkt).unwrap();
        r_a.handle_frame_at(&f1, 1);
        assert_eq!(r_a.stats().fwd_rejected, 1, "证书冒充源点应被拒转");
        assert_eq!(r_a.stats().forwarded, 0);
        assert!(r_a.take_forward_packet().is_none());
    }

    #[test]
    fn multihop_rejected_when_forwarding_disabled() {
        // enable_forwarding 的引擎：多跳包一fwd_rejected（不转发、不交付
    let ca = CertAuthority::from_seed([0xC4u8; 32]);
        let host_a = provision(&ca, a(1), [0xA1u8; 32], NO_EXPIRY);
        let mut a_r = Engine::new(Identity::from_bytes([1u8; 32]), a(1), a(2));
        let mut r_a = Engine::new(Identity::from_bytes([2u8; 32]), a(2), a(1)); // 不转
    let i = a_r.start_handshake();
        let s = r_a.handle_frame(&i).unwrap();
        a_r.handle_frame(&s);
        let pkt = multihop_pkt(
            a(1),
            a(3),
            &[a(2), a(3)],
            64,
            &[0x45, 0, 0, 0x14],
            &[0xA1u8; 32],
            host_a.cert.to_wire(),
        );
        let f = a_r.seal_prebuilt(&pkt).unwrap();
        r_a.handle_frame_at(&f, 1);
        assert_eq!(r_a.stats().fwd_rejected, 1);
        assert_eq!(r_a.stats().forwarded, 0);
        assert_eq!(r_a.take_delivered(), None, "禁用转发时不得把多跳包交付本 TUN");
    }

    #[test]
    fn plaintext_packet_still_delivers_unchanged() {
        // RouteTrace 的普通包：转发开着也照常交付（零回归）
        let mut a_r = Engine::new(Identity::from_bytes([9u8; 32]), a(1), a(2));
        let mut r = Engine::new(Identity::from_bytes([2u8; 32]), a(2), a(1));
        r.enable_forwarding([0xC4u8; 32]);
        let i = a_r.start_handshake();
        let s = r.handle_frame(&i).unwrap();
        a_r.handle_frame(&s);
        let inner = vec![0x45u8, 0x00, 0x00, 0x14];
        let f = a_r.seal_frame(&inner).unwrap();
        r.handle_frame_at(&f, 1);
        assert_eq!(r.take_delivered().as_deref(), Some(&inner[..]));
        assert_eq!(r.stats().forwarded, 0);
        assert_eq!(r.stats().fwd_rejected, 0);
    }

    #[test]
    fn multihop_hoplimit_exhaustion_blocks_forward() {
        let (mut a_r, mut r_a, .., seed) = hop3_setup();
        let ca = CertAuthority::from_seed([0xC4u8; 32]);
        let host_a = provision(&ca, a(1), [0xA1u8; 32], NO_EXPIRY);
        // init=1：R（k=0）验证通过（current==init=1），但转发要减到 0 §4.3
    let pkt = multihop_pkt(
            a(1),
            a(3),
            &[a(2), a(3)],
            1,
            &[0x45, 0, 0, 0x14],
            &seed,
            host_a.cert.to_wire(),
        );
        let f = a_r.seal_prebuilt(&pkt).unwrap();
        r_a.handle_frame_at(&f, 1);
        assert_eq!(r_a.stats().forwarded, 0, "HopLimit 耗尽不得再转");
        assert_eq!(r_a.stats().fwd_rejected, 1);
    }

    #[test]
    fn multihop_hop_list_tamper_breaks_sig() {
        let (mut a_r, mut r_a, .., seed) = hop3_setup();
        let ca = CertAuthority::from_seed([0xC4u8; 32]);
        let host_a = provision(&ca, a(1), [0xA1u8; 32], NO_EXPIRY);
        let mut pkt = multihop_pkt(
            a(1),
            a(3),
            &[a(2), a(3)],
            64,
            &[0x45, 0, 0, 0x14],
            &seed,
            host_a.cert.to_wire(),
        );
        // RouteTrace 载荷起点 = 基头 40 + 头框2；hops[0] 在其 +104 处
    // hops[0] host_id 末字节：签名的列表摘要变BadPathSig
        let hops0 = 40 + 2 + 104;
        pkt[hops0 + 7] ^= 0x07;
        let f = a_r.seal_prebuilt(&pkt).unwrap();
        r_a.handle_frame_at(&f, 1);
        assert_eq!(r_a.stats().fwd_rejected, 1, "跳列表字节篡改必须破 PathSig 被拒");
        assert_eq!(r_a.stats().forwarded, 0);
    }

    /// 生产接缝全链路：源点 seal_multihop（认证模式，用自身证书签路径）→
    /// 中转验证转发 下一段隧seal_prebuilt 目的地三验后交付
    /// node 的多隧道编排一一对应（M5 实测的同逻辑）
    #[test]
    fn seal_multihop_end_to_end_three_node_chain() {
        let now = 1_700_000_000u64;
        let ca = CertAuthority::from_seed([0xC4u8; 32]);
        let trust = TrustAnchor::from_bytes(ca.public_key()).unwrap();
        let anchor = ca.public_key();
        let host_a = provision(&ca, a(1), [0xA1u8; 32], NO_EXPIRY);
        let host_r1 = provision(&ca, a(2), [0xB0u8; 32], NO_EXPIRY);
        let host_r2 = provision(&ca, a(2), [0xB0u8; 32], NO_EXPIRY);
        let host_b = provision(&ca, a(3), [0xC3u8; 32], NO_EXPIRY);

        let mut a_r = Engine::authenticated(host_a, trust.clone(), a(1), a(2));
        let mut r_a = Engine::authenticated(host_r1, trust.clone(), a(2), a(1));
        let mut r_b = Engine::authenticated(host_r2, trust.clone(), a(2), a(3));
        let mut b_r = Engine::authenticated(host_b, trust, a(3), a(2));
        r_a.enable_forwarding(anchor);
        b_r.enable_forwarding(anchor);

        // 两条认证隧道（A↔R、R↔B
    let i1 = a_r.start_auth_handshake();
        let s1 = r_a.handle_frame_at(&i1, now).unwrap();
        a_r.handle_frame_at(&s1, now);
        let i2 = r_b.start_auth_handshake();
        let s2 = b_r.handle_frame_at(&i2, now).unwrap();
        r_b.handle_frame_at(&s2, now);
        assert_eq!(a_r.state(), State::Established);
        assert_eq!(b_r.state(), State::Established);

        // 源点发多跳包：路[R, B]，签自身证书由引擎完
    let inner = vec![0x45u8, 0x00, 0x00, 0x14, b'm', b'u', b'l', b't', b'i'];
        let frames = a_r.seal_multihop(&inner, a(3), &[a(2), a(3)], 64).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(a_r.stats().sealed_outbound, 1);

        // R 面向 A 的引擎：验证→减跳→排队转发
        r_a.handle_frame_at(&frames[0], now);
        assert_eq!(r_a.take_delivered(), None);
        assert_eq!(r_a.stats().forwarded, 1, "R 应放行合法多跳包: {:?}", r_a.stats());
        let (next, fpkt) = r_a.take_forward_packet().unwrap();
        assert_eq!(next, a(3));
        assert_eq!(fpkt[5], 63);

        // R 面向 B 的隧道续程；B 三验后交
    let f2 = r_b.seal_prebuilt(&fpkt).unwrap();
        b_r.handle_frame_at(&f2, now);
        assert_eq!(b_r.take_delivered().as_deref(), Some(&inner[..]));
        assert_eq!(b_r.stats().fwd_rejected, 0);
        assert_eq!(b_r.stats().dropped_inbound, 0);
    }
}
