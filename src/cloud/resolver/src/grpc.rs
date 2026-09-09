//! Resolver gRPC 网络层（tonic；生成码来自 shared/ipv8-proto/resolver.proto）。
//! 分层与 zoneserver 一致：本文件只做 协议 ↔ 领域 映射 + serve + e2e 测试，
//! 决策逻辑全在 [`crate`]（零 IO，可脱离网络自测）。

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tonic::{Request, Response, Status};

pub mod pb {
    tonic::include_proto!("ipv8plus.resolver.v1");
}

use pb::resolver_server::{Resolver as ResolverSvc, ResolverServer};
use pb::{RegisterRequest, RegisterResponse, ResolveRequest, ResolveResponse};

use crate::{ResolveError, ResolverService};

#[derive(Clone)]
pub struct ResolverGrpc {
    inner: Arc<Mutex<ResolverService>>,
}

impl ResolverGrpc {
    pub fn new(s: ResolverService) -> Self {
        Self { inner: Arc::new(Mutex::new(s)) }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ResolverService> {
        self.inner.lock().expect("resolver mutex poisoned")
    }
}

fn resolve_err(e: ResolveError) -> Status {
    match e {
        ResolveError::BadAddress => Status::invalid_argument(e.to_string()),
        ResolveError::BadProof => Status::invalid_argument(e.to_string()),
        // 未登记/过期：NotFound（语义准确，且不泄露曾存在性——ADR-007）
        ResolveError::NotFound => Status::not_found(e.to_string()),
        ResolveError::KeyConflict { .. } => Status::already_exists(e.to_string()),
    }
}

#[tonic::async_trait]
impl ResolverSvc for ResolverGrpc {
    async fn resolve(
        &self,
        req: Request<ResolveRequest>,
    ) -> Result<Response<ResolveResponse>, Status> {
        let r = req.into_inner();
        let out = self.lock().resolve(&r.target_addr, Instant::now()).map_err(resolve_err)?;
        Ok(Response::new(ResolveResponse {
            tunnel_entry_ip: out.tunnel_entry,
            ipv8_capable: out.ipv8_capable,
            mtu: out.mtu,
            alt_ips: out.alt_entries,
            ttl: u32::try_from(out.ttl.as_secs()).unwrap_or(u32::MAX),
        }))
    }

    async fn register(
        &self,
        req: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        let r = req.into_inner();
        let ttl = {
            let mut g = self.lock();
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
                },
                Instant::now(),
            )
            .map_err(resolve_err)?
        };
        Ok(Response::new(RegisterResponse {
            ttl: u32::try_from(ttl.as_secs()).unwrap_or(u32::MAX),
        }))
    }
}

/// 启动服务（ADR-011：端口 0 = 随机；返回实际绑定地址与后台句柄）。
/// 服务任务内嵌 reaper：每分钟清理过期条目（自托管内存有界）。
pub async fn serve(
    s: ResolverService,
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
                        let _ = inner.lock().expect("resolver mutex poisoned").sweep_expired(Instant::now());
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

    async fn spawn() -> ResolverClient<tonic::transport::Channel> {
        let (local, _h) = serve(ResolverService::new(), "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        ResolverClient::connect(format!("http://{local}")).await.unwrap()
    }

    fn addr_text(n: u32) -> String {
        IPv8Address::new(64500, n, 1, 0, 1).to_canonical_string()
    }

    fn pop(sk: &SigningKey, t: &str) -> Vec<u8> {
        sk.sign(&crate::register_pop_message(t, &sk.verifying_key().to_bytes()))
            .to_bytes()
            .to_vec()
    }

    /// 登记 → 原子解析回环（v9 验收：一次 RPC 拿全字段）
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
        // 坏地址文本
        let e = c
            .resolve(ResolveRequest { target_addr: "zz".into(), client_ipv8_addr: String::new() })
            .await
            .unwrap_err();
        assert_eq!(e.code(), tonic::Code::InvalidArgument);
        // 未登记 → NotFound（不泄露存在性）
        let e = c
            .resolve(ResolveRequest {
                target_addr: addr_text(404),
                client_ipv8_addr: String::new(),
            })
            .await
            .unwrap_err();
        assert_eq!(e.code(), tonic::Code::NotFound);
        // 坏 PoP
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
}
