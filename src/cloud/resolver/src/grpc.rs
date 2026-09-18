//! Resolver gRPC 网络层（tonic；生成码来自 shared/ipv8-proto/resolver.proto）。
//!
//! 泛型设计：`ResolverGrpc<S>` 可搭配任意 `Store` 实现（内存 / SQLite / ...）。
//! 决策逻辑在 [`crate::ResolverService`]（零 IO），本文件只做协议映射与服务启动。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use tonic::{Request, Response, Status};

pub mod pb {
    tonic::include_proto!("ipv8plus.resolver.v1");
}

use pb::resolver_server::{Resolver as ResolverSvc, ResolverServer};
use pb::{
    RegisterRequest, RegisterResponse, RendezvousRequest, RendezvousResponse, ResolveRequest,
    ResolveResponse,
};

use crate::{ResolveError, ResolverService, Store};

/// gRPC 服务包装（泛型于存储后端 S）
///
/// 锁策略（P3 优化）：
/// - `RwLock` 替代 `Mutex`：resolve（读路径，占 90%+ 流量）并发执行，
///   register/rendezvous（写路径）独占。
/// - 读锁 ~25ns，写锁 ~65ns（parking_lot 自适应自旋、无 poisoning）。
/// - SqliteStore 已将 `Connection` 包入 `Mutex` 使其 `Sync`，
///   resolve 读路径只读 HashMap 缓存，不触碰 SQLite 连接。
#[derive(Clone)]
pub struct ResolverGrpc<S: Store> {
    inner: Arc<RwLock<ResolverService<S>>>,
}

impl<S: Store> ResolverGrpc<S> {
    pub fn new(s: ResolverService<S>) -> Self {
        Self { inner: Arc::new(RwLock::new(s)) }
    }

    #[inline]
    fn read(&self) -> RwLockReadGuard<'_, ResolverService<S>> {
        self.inner.read()
    }

    #[inline]
    fn write(&self) -> RwLockWriteGuard<'_, ResolverService<S>> {
        self.inner.write()
    }
}

/// 从 tonic 连接扩展取服务端所见源地址（NAT 后的公网 "ip:port"）。
fn observed_of<T>(req: &Request<T>) -> Option<String> {
    req.remote_addr().map(|a| a.to_string())
}

fn resolve_err(e: ResolveError) -> Status {
    match e {
        ResolveError::BadAddress => Status::invalid_argument(e.to_string()),
        ResolveError::BadProof => Status::invalid_argument(e.to_string()),
        ResolveError::NotFound => Status::not_found(e.to_string()),
        ResolveError::KeyConflict { .. } => Status::already_exists(e.to_string()),
    }
}

#[tonic::async_trait]
impl<S: Store + Send + Sync + 'static> ResolverSvc for ResolverGrpc<S> {
    async fn resolve(
        &self,
        req: Request<ResolveRequest>,
    ) -> Result<Response<ResolveResponse>, Status> {
        let r = req.into_inner();
        let out = self.read().resolve(&r.target_addr, Instant::now()).map_err(resolve_err)?;
        Ok(Response::new(ResolveResponse {
            tunnel_entry_ip: out.tunnel_entry,
            ipv8_capable: out.ipv8_capable,
            mtu: out.mtu,
            alt_ips: out.alt_entries.to_vec(),
            ttl: u32::try_from(out.ttl.as_secs()).unwrap_or(u32::MAX),
        }))
    }

    async fn register(
        &self,
        req: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        let observed = observed_of(&req);
        let r = req.into_inner();
        let out = {
            let mut g = self.write();
            g.register(
                &crate::RegisterSpec {
                    addr_text: &r.addr_text,
                    ed_pub: &r.ed_pub,
                    proof: &r.proof,
                    tunnel_entry: &r.tunnel_entry,
                    alt_entries: r.alt_entries,
                    ipv8_capable: r.ipv8_capable,
                    mtu: r.mtu,
                    ttl_secs: r.ttl as u64,
                    observed: observed.as_deref(),
                },
                Instant::now(),
            )
            .map_err(resolve_err)?
        };
        Ok(Response::new(RegisterResponse {
            ttl: u32::try_from(out.ttl.as_secs()).unwrap_or(u32::MAX),
            observed_addr: out.observed.unwrap_or_default(),
        }))
    }

    async fn rendezvous(
        &self,
        req: Request<RendezvousRequest>,
    ) -> Result<Response<RendezvousResponse>, Status> {
        let observed = observed_of(&req);
        let r = req.into_inner();
        let out = {
            let mut g = self.write();
            g.rendezvous(
                &r.addr_text,
                &r.peer_addr_text,
                &r.proof,
                &r.local_candidates,
                observed.as_deref(),
                Instant::now(),
            )
            .map_err(resolve_err)?
        };
        Ok(Response::new(RendezvousResponse {
            peer_candidates: out.peer_candidates,
            self_observed: out.self_observed.unwrap_or_default(),
            ttl: u32::try_from(out.ttl.as_secs()).unwrap_or(u32::MAX),
        }))
    }
}

/// 启动服务（泛型于存储后端 S）。
/// 端口 0 = 随机绑定；返回实际绑定地址与后台任务句柄。
/// 内嵌 reaper：每分钟清理过期条目。
pub async fn serve<S: Store + Send + Sync + 'static>(
    s: ResolverService<S>,
    addr: SocketAddr,
) -> Result<(SocketAddr, tokio::task::JoinHandle<()>), Box<dyn std::error::Error + Send + Sync>>
{
    let svc = ResolverGrpc::new(s);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    let inner = svc.inner.clone();
    let handle = tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        let server = tonic::transport::Server::builder()
            .add_service(ResolverServer::new(svc))
            .serve_with_incoming_shutdown(
                tokio_stream::wrappers::TcpListenerStream::new(listener),
                async {
                    loop {
                        tick.tick().await;
                        let _ = inner.write().sweep_expired(Instant::now());
                    }
                },
            );
        server.await.expect("resolver gRPC exited");
    });
    Ok((local, handle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use ipv8_codec::IPv8Address;
    use pb::resolver_client::ResolverClient;
    use crate::MemStore;

    async fn spawn() -> ResolverClient<tonic::transport::Channel> {
        let (local, _h) = serve(ResolverService::<MemStore>::new(), "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        ResolverClient::connect(format!("http://{local}")).await.unwrap()
    }

    fn addr_text(n: u32) -> String {
        IPv8Address::with_region(n as u64, 1, 0, 0x0100, 0).to_canonical_string()
    }

    fn pop(sk: &SigningKey, t: &str) -> Vec<u8> {
        sk.sign(&crate::register_pop_message(t, &sk.verifying_key().to_bytes()))
            .to_bytes()
            .to_vec()
    }

    /// 登记 → 原子解析回环
    #[tokio::test]
    async fn grpc_register_then_resolve_roundtrip() {
        let mut c = spawn().await;
        let sk = SigningKey::from_bytes(&[0xA1u8; 32]);
        let t = addr_text(1);
        let rr = c
            .register(RegisterRequest {
                name: "agent".into(),
                addr_text: t.clone(),
                ed_pub: sk.verifying_key().to_bytes().to_vec(),
                proof: pop(&sk, &t),
                tunnel_entry: "192.0.2.10:45700".into(),
                alt_entries: vec!["198.51.100.7:45700".into()],
                mtu: 1400,
                ttl: 120,
                ipv8_capable: true,
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(rr.ttl, 120);
        assert!(rr.observed_addr.starts_with("127.0.0.1:"), "observed 回显: {}", rr.observed_addr);

        let resp = c
            .resolve(ResolveRequest { target_addr: t, client_ipv8_addr: String::new() })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(resp.tunnel_entry_ip, "192.0.2.10:45700");
        assert_eq!(resp.alt_ips, vec!["198.51.100.7:45700".to_string()]);
        assert!(resp.ipv8_capable);
        assert_eq!(resp.mtu, 1400);
        assert_eq!(resp.ttl, 120);
    }

    /// 错误路径的 gRPC 状态码映射
    #[tokio::test]
    async fn grpc_status_codes() {
        let mut c = spawn().await;
        let e = c
            .resolve(ResolveRequest { target_addr: "zz".into(), client_ipv8_addr: String::new() })
            .await
            .unwrap_err();
        assert_eq!(e.code(), tonic::Code::InvalidArgument);
        let e = c
            .resolve(ResolveRequest {
                target_addr: addr_text(404),
                client_ipv8_addr: String::new(),
            })
            .await
            .unwrap_err();
        assert_eq!(e.code(), tonic::Code::NotFound);
        let sk = SigningKey::from_bytes(&[0xA1u8; 32]);
        let t = addr_text(1);
        let e = c
            .register(RegisterRequest {
                name: String::new(),
                addr_text: t.clone(),
                ed_pub: sk.verifying_key().to_bytes().to_vec(),
                proof: vec![0u8; 64],
                tunnel_entry: "e:1".into(),
                alt_entries: vec![],
                mtu: 0,
                ttl: 0,
                ipv8_capable: true,
            })
            .await
            .unwrap_err();
        assert_eq!(e.code(), tonic::Code::InvalidArgument);
    }

    /// ADR-026 端到端：两节点 register → 互相 rendezvous 拿到对端候选
    #[tokio::test]
    async fn grpc_rendezvous_swaps_observed_candidates() {
        use ed25519_dalek::Signer;
        let (local, _h) = serve(ResolverService::<MemStore>::new(), "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let mut ca = ResolverClient::connect(format!("http://{local}")).await.unwrap();
        let mut cb = ResolverClient::connect(format!("http://{local}")).await.unwrap();

        let ska = SigningKey::from_bytes(&[0xA1u8; 32]);
        let skb = SigningKey::from_bytes(&[0xB2u8; 32]);
        let (ta, tb) = (addr_text(1), addr_text(2));
        for (c, sk, t) in [(&mut ca, &ska, &ta), (&mut cb, &skb, &tb)] {
            c.register(RegisterRequest {
                name: String::new(),
                addr_text: t.clone(),
                ed_pub: sk.verifying_key().to_bytes().to_vec(),
                proof: sk
                    .sign(&crate::register_pop_message(t, &sk.verifying_key().to_bytes()))
                    .to_bytes()
                    .to_vec(),
                tunnel_entry: "10.0.0.1:45700".into(),
                alt_entries: vec![],
                mtu: 0,
                ttl: 0,
                ipv8_capable: true,
            })
            .await
            .unwrap();
        }

        let rz_msg = |a: &str, b: &str| crate::rendezvous_pop_message(a, b);
        let pa = ska.sign(&rz_msg(&ta, &tb)).to_bytes().to_vec();
        let ra = ca
            .rendezvous(RendezvousRequest {
                addr_text: ta.clone(),
                proof: pa,
                peer_addr_text: tb.clone(),
                local_candidates: vec![],
            })
            .await
            .unwrap()
            .into_inner();
        assert!(ra.self_observed.starts_with("127.0.0.1:"));
        let pb = skb.sign(&rz_msg(&tb, &ta)).to_bytes().to_vec();
        let rb = cb
            .rendezvous(RendezvousRequest {
                addr_text: tb.clone(),
                proof: pb,
                peer_addr_text: ta.clone(),
                local_candidates: vec![],
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(rb.peer_candidates.first().map(String::as_str), Some("127.0.0.1:45700"));
        assert!(rb.peer_candidates.contains(&ra.self_observed), "observed 原样应保留兜底");
        let ra2 = ca
            .rendezvous(RendezvousRequest {
                addr_text: ta,
                proof: ska.sign(&rz_msg(&ra2_addr(), &tb)).to_bytes().to_vec(),
                peer_addr_text: tb,
                local_candidates: vec![],
            })
            .await
            .unwrap()
            .into_inner();
        assert!(ra2.peer_candidates.contains(&rb.self_observed),
            "A 第二轮应看到 B 的 observed {:?}", rb.self_observed);
    }

    fn ra2_addr() -> String {
        addr_text(1)
    }

    /// 会合鉴权错误码
    #[tokio::test]
    async fn grpc_rendezvous_error_codes() {
        let mut c = spawn().await;
        let e = c
            .rendezvous(RendezvousRequest {
                addr_text: addr_text(1),
                proof: vec![0u8; 64],
                peer_addr_text: addr_text(2),
                local_candidates: vec![],
            })
            .await
            .unwrap_err();
        assert_eq!(e.code(), tonic::Code::NotFound);
        use ed25519_dalek::Signer;
        let sk = SigningKey::from_bytes(&[0xA1u8; 32]);
        let t = addr_text(1);
        c.register(RegisterRequest {
            name: String::new(),
            addr_text: t.clone(),
            ed_pub: sk.verifying_key().to_bytes().to_vec(),
            proof: sk
                .sign(&crate::register_pop_message(&t, &sk.verifying_key().to_bytes()))
                .to_bytes()
                .to_vec(),
            tunnel_entry: "10.0.0.1:45700".into(),
            alt_entries: vec![],
            mtu: 0,
            ttl: 0,
            ipv8_capable: true,
        })
        .await
        .unwrap();
        let e = c
            .rendezvous(RendezvousRequest {
                addr_text: t,
                proof: vec![0u8; 64],
                peer_addr_text: addr_text(2),
                local_candidates: vec![],
            })
            .await
            .unwrap_err();
        assert_eq!(e.code(), tonic::Code::InvalidArgument);
    }
}
