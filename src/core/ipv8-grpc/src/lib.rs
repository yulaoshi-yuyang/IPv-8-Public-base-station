//! gRPC(tonic) 桥：把 [`Engine`] 暴露为 tunnel.proto 的 TunnelEngine 服务。
//!
//! 跨语言通信唯一通道（ADR-008：FFI 仅 Phase 0，Phase 1 起全走 gRPC）。
//! 帧字节经 `WireFrame.raw` / `TunPacket.raw` 裸搬运（v9：bytes raw = 1）。
//!
//! 并发模型：引擎在 `Arc<Mutex<Engine>>` 中（handle_frame/seal_frame 均同步且
//! 快，锁内无 IO），真实 TUN/UDP 的 IO 归 C# 宿主，本桥只做字节进出编排。

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use futures_core::Stream;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt as _;
use tonic::{Request, Response, Status};

use ipv8_codec::IPv8Address;
use ipv8_tunnel::{
    Engine, FallbackManager, FallbackOptions, Failure, Level, Path, Resolved, State,
};

pub mod pb {
    tonic::include_proto!("ipv8plus.tunnel.v1");
}

use pb::stream_in::Payload as InPayload;
use pb::stream_out::Payload as OutPayload;
use pb::tunnel_status::State as PbState;
use pb::{
    tunnel_engine_server::TunnelEngine, Empty, FallbackLevel, FallbackLevelResponse,
    InjectFrameResponse, NextPathRequest, NextPathResponse, RecordFailureRequest,
    RecordSuccessRequest, SetResolvedRequest, StartHandshakeRequest, StartHandshakeResponse,
    StreamIn, StreamOut, TunPacket, TunnelStatus, WireFrame,
};

/// 引擎包装：Clone + 内部可变（tonic service 要求）
#[derive(Clone)]
pub struct TunnelEngineService {
    inner: Arc<Mutex<Engine>>,
    /// v9 §11 降级状态机（多对端 keyed；IO 与计时归宿主）
    fb: Arc<Mutex<FallbackManager>>,
}

/// 证书过期校验所需墙钟（epoch 秒）；异常（早于 1970）回落 0。
fn now_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl TunnelEngineService {
    pub fn new(engine: Engine) -> Self {
        Self {
            inner: Arc::new(Mutex::new(engine)),
            fb: Arc::new(Mutex::new(FallbackManager::new(FallbackOptions::default()))),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Engine> {
        // 中毒锁仅在引擎 panic 时出现（bug 而非可恢复错误），传播 panic
        self.inner.lock().expect("engine mutex poisoned")
    }

    fn fb_lock(&self) -> std::sync::MutexGuard<'_, FallbackManager> {
        self.fb.lock().expect("fallback mutex poisoned")
    }
}

/// Level → proto 枚举（Ord 顺序即降级顺序）
fn to_pb_level(l: Level) -> FallbackLevel {
    match l {
        Level::MainTunnel => FallbackLevel::MainTunnel,
        Level::AltTunnel => FallbackLevel::AltTunnel,
        Level::PlainTcp => FallbackLevel::PlainTcp,
        Level::PlainUdp => FallbackLevel::PlainUdp,
    }
}

#[tonic::async_trait]
impl TunnelEngine for TunnelEngineService {
    type StreamPacketsStream =
        Pin<Box<dyn Stream<Item = Result<StreamOut, Status>> + Send + 'static>>;

    /// 数据面双向泵：
    /// - wire 帧入 → handle_frame；响应帧（HandshakeResp）→ to_wire；
    ///   拆壳成功 → take_delivered → to_tun
    /// - tun 包入 → seal_frame → to_wire（未建立隧道则丢弃，Fallback 归 C# 层）
    async fn stream_packets(
        &self,
        request: Request<tonic::Streaming<StreamIn>>,
    ) -> Result<Response<Self::StreamPacketsStream>, Status> {
        let mut inbound = request.into_inner();
        let svc = self.clone();
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<StreamOut, Status>>(64);

        tokio::spawn(async move {
            while let Some(msg) = inbound.next().await {
                let Ok(msg) = msg else { break }; // 客户端流错误，终止
                let Some(payload) = msg.payload else { continue };
                let outs: Vec<StreamOut> = match payload {
                    InPayload::Wire(frame) => {
                        let mut g = svc.lock();
                        let mut v = Vec::new();
                        if let Some(rf) = g.handle_frame_at(&frame.raw, now_epoch_secs()) {
                            v.push(out_wire(rf));
                        }
                        if let Some(tun) = g.take_delivered() {
                            v.push(out_tun(tun));
                        }
                        v
                    }
                    InPayload::Tun(tun) => {
                        // 超 MTU 的内层包会分片成多帧，逐帧交给宿主 UDP 发送
                        match svc.lock().seal_frames(&tun.raw) {
                            Ok(frames) => frames.into_iter().map(out_wire).collect(),
                            Err(_) => Vec::new(),
                        }
                    }
                };
                for out in outs {
                    if tx.send(Ok(out)).await.is_err() {
                        return; // 接收端关闭
                    }
                }
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    async fn start_handshake(
        &self,
        request: Request<StartHandshakeRequest>,
    ) -> Result<Response<StartHandshakeResponse>, Status> {
        let peer = IPv8Address::from_canonical_str(&request.into_inner().peer_addr_text)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let frame = {
            let mut g = self.lock();
            if g.state() != State::Idle {
                return Err(Status::failed_precondition("隧道已建立或握手中"));
            }
            g.set_peer_addr(peer);
            g.start_handshake()
        };
        Ok(Response::new(StartHandshakeResponse {
            init_frame: Some(WireFrame { raw: frame }),
        }))
    }

    /// 控制面即发即答路径（握手帧等；高吞吐 Data 走 StreamPackets）
    async fn inject_frame(
        &self,
        request: Request<WireFrame>,
    ) -> Result<Response<InjectFrameResponse>, Status> {
        let (resp, established) = {
            let mut g = self.lock();
            (
                g.handle_frame_at(&request.into_inner().raw, now_epoch_secs()),
                g.state() == State::Established,
            )
        };
        Ok(Response::new(InjectFrameResponse {
            response_frame: resp.map(|raw| WireFrame { raw }),
            established,
        }))
    }

    async fn get_status(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<TunnelStatus>, Status> {
        let g = self.lock();
        let stats = g.stats();
        Ok(Response::new(TunnelStatus {
            state: PbState::from(stats.state) as i32,
            send_epoch: stats.send_epoch.unwrap_or(0),
            local_addr_text: g.local_addr().to_canonical_string(),
            peer_addr_text: g.peer_addr().to_canonical_string(),
            sealed_outbound: stats.sealed_outbound,
            delivered_inbound: stats.delivered_inbound,
            dropped_inbound: stats.dropped_inbound,
            authenticated: stats.authenticated,
            last_auth_error: stats.last_auth_error.map(|e| e.to_string()).unwrap_or_default(),
            fallback_level: to_pb_level(
                self.fb_lock()
                    .level_of(&g.peer_addr().to_canonical_string())
                    .unwrap_or(Level::MainTunnel),
            ) as i32,
        }))
    }

    /// Resolver 结果 → 降级状态机缓存。ipv8_capable=false 直接进 PlainTcp。
    async fn set_resolved(
        &self,
        request: Request<SetResolvedRequest>,
    ) -> Result<Response<Empty>, Status> {
        let req = request.into_inner();
        let r = req
            .resolved
            .ok_or_else(|| Status::invalid_argument("resolved 缺失"))?;
        let resolved = Resolved {
            tunnel_entry: Some(r.tunnel_entry),
            alt_entries: r.alt_entries,
            ipv8_capable: r.ipv8_capable,
            last_good_entry: if r.last_good_entry.is_empty() {
                None
            } else {
                Some(r.last_good_entry)
            },
        };
        self.fb_lock().note_resolved(&req.peer, resolved);
        Ok(Response::new(Empty {}))
    }

    /// 问"下一个包走哪条路 + 本次握手给几秒超时"。
    async fn next_path(
        &self,
        request: Request<NextPathRequest>,
    ) -> Result<Response<NextPathResponse>, Status> {
        let peer = request.into_inner().peer;
        let mut fb = self.fb_lock();
        let timeout = fb.handshake_timeout(&peer).as_secs() as u32;
        let (kind, tunnel_entry) = match fb.next_path(&peer, now_epoch_secs()) {
            Path::Tunnel { entry } => (pb::next_path_response::Kind::Tunnel as i32, entry),
            Path::PlainTcp => (pb::next_path_response::Kind::PlainTcp as i32, String::new()),
            Path::PlainUdp => (pb::next_path_response::Kind::PlainUdp as i32, String::new()),
        };
        Ok(Response::new(NextPathResponse {
            kind,
            tunnel_entry,
            handshake_timeout_secs: timeout,
        }))
    }

    /// 报一次失败，返回降级后的级别（宿主据此决定重发/换入口/落明文）。
    async fn record_failure(
        &self,
        request: Request<RecordFailureRequest>,
    ) -> Result<Response<FallbackLevelResponse>, Status> {
        let req = request.into_inner();
        let kind = match pb::FailureKind::try_from(req.kind) {
            Ok(pb::FailureKind::HandshakeTimeout) => Failure::HandshakeTimeout,
            Ok(pb::FailureKind::FirstPacketTimeout) => Failure::FirstPacketTimeout,
            Ok(pb::FailureKind::LevelFailed) => Failure::LevelFailed,
            _ => return Err(Status::invalid_argument("未知 FailureKind")),
        };
        let level = {
            let mut fb = self.fb_lock();
            fb.record_failure(&req.peer, kind, now_epoch_secs());
            to_pb_level(fb.level_of(&req.peer).unwrap_or(Level::MainTunnel))
        };
        Ok(Response::new(FallbackLevelResponse { level: level as i32 }))
    }

    /// 报一次成功：隧道成功清降级缓存并把备用入口提正。
    async fn record_success(
        &self,
        request: Request<RecordSuccessRequest>,
    ) -> Result<Response<FallbackLevelResponse>, Status> {
        let req = request.into_inner();
        let path = if req.tunnel_entry.is_empty() {
            Path::PlainTcp
        } else {
            Path::Tunnel { entry: req.tunnel_entry }
        };
        let level = {
            let mut fb = self.fb_lock();
            fb.record_success(&req.peer, &path);
            to_pb_level(fb.level_of(&req.peer).unwrap_or(Level::MainTunnel))
        };
        Ok(Response::new(FallbackLevelResponse { level: level as i32 }))
    }
}

fn out_wire(raw: Vec<u8>) -> StreamOut {
    StreamOut { payload: Some(OutPayload::ToWire(WireFrame { raw })) }
}

fn out_tun(raw: Vec<u8>) -> StreamOut {
    StreamOut { payload: Some(OutPayload::ToTun(TunPacket { raw })) }
}

impl From<State> for PbState {
    fn from(s: State) -> Self {
        match s {
            State::Idle => PbState::Idle,
            State::Initiating => PbState::Initiating,
            State::Responding => PbState::Responding,
            State::Established => PbState::Established,
        }
    }
}

/// 启动服务。ADR-011：端口 0 = 随机，返回实际绑定地址。
pub async fn serve(
    engine: Engine,
    addr: SocketAddr,
) -> Result<(SocketAddr, tokio::task::JoinHandle<()>), Box<dyn std::error::Error + Send + Sync>> {
    let svc = TunnelEngineService::new(engine);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    let handle = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(pb::tunnel_engine_server::TunnelEngineServer::new(svc))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .expect("gRPC server exited with error");
    });
    Ok((local, handle))
}
