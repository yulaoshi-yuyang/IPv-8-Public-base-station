//! # ipv8-tunnel
//!
//! IPv8+ 隧道引擎：封装/拆壳、X25519 握手、ChaCha20-Poly1305、
//! 密钥轮换（1GB/1h + 宽限）、TUN 读线程模型。
//!
//! - [`frame`]：隧道帧格式（10B 帧头，KeyID=密钥代 epoch）
//! - [`crypto`]：HKDF 逐代密钥派生 + AEAD + 重放防护
//! - [`handshake`]：X25519 握手（Phase 1 明文，Phase 2 接证书认证）
//! - [`auth`]：证书认证握手（CA 证书 + Ed25519 transcript 签名，MITM 防护）
//! - [`engine`]：隧道引擎门面（状态机 + 数据面管线）
//! - [`encapsulate`]：IPv8+ ⇄ 隧道帧（AAD 绑定明文头，扩展头保持明文）
//! - [`fallback`]：v9 §11 分级降级状态机（四级路径 + 分级超时 + 降级缓存）
//! - [`tun_worker`]：独立读线程 + mpsc（v9 §8；设备经 TunIo 注入，CI 用 Mock）
//! - [`flow`]：流级分片数据面（ADR-026 多核：N worker 并行 seal/open，epoch 同余类路由）

pub mod abuse_guard;
pub mod auth;
pub mod crypto;
pub mod engine;
pub mod encapsulate;
pub mod fallback;
pub mod flow;
pub mod frame;
pub mod handshake;
pub mod relay_failover;
pub mod tun_worker;

pub use crypto::{Identity, TunnelKeys, GRACE_EPOCHS, ROTATE_BYTES, ROTATE_SECS};
pub use encapsulate::{decapsulate, encapsulate};
pub use frame::{
    compute_key_id, parse_head, write_head, FrameError, FrameHead, FrameType, FRAME_HEADER_SIZE,
    TUNNEL_VERSION,
};
pub use handshake::{accept_init, create_init, finish_init, PendingHandshake, HANDSHAKE_BODY_LEN};
pub use auth::{
    auth_accept, auth_finish_init, auth_init, provision, AuthError, AuthPending, Cert,
    CertAuthority, HostIdentity, TrustAnchor, NO_EXPIRY, AUTH_BUNDLE_LEN,
};
pub use engine::{Engine, EngineError, EngineStats, State};
pub use fallback::{FallbackManager, FallbackOptions, Failure, Level, Path, Resolved};
pub use flow::{hash_flow, FlowShards, ShardStats, Sink as ShardSink};
pub use relay_failover::{RelayFailover, RelayNode, FailoverConfig, FailoverEvent, FailoverStats, Health as RelayHealth};
pub use abuse_guard::{AbuseGuard, AbuseConfig, AbuseStats, BanLevel, Detection};
pub use tun_worker::{mock_tun, ClosableMockTun, MockTun, MockTunHandle, TunError, TunIo, TunWorker};
