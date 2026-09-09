//! ZoneServer 的 gRPC 接线（tonic）。纯逻辑在 crate 根（已全量测试），
//! 本层只做 pb ⇔ 核心类型转换 + 墙钟注入 + 并发锁。
//!
//! 与 ipv8-grpc（隧道桥）同构：`Arc<Mutex<ZoneServer>>`，锁内无 IO。
//! 注意：`pb` 模块同时向节点侧提供生成好的 **client stub**（`zone_server_client`）——
//! 契约生成物不属于分层依赖（v9 铁律约束的是服务实现，客户端桩是接口本身）。

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tonic::{Request, Response, Status};

use crate::{ZoneError, ZoneServer, DEFAULT_VALIDITY_SECS};

pub mod pb {
    tonic::include_proto!("ipv8plus.zoneserver.v1");
}

use pb::zone_server_server::{ZoneServer as ZoneServerSvc, ZoneServerServer};
use pb::{
    GetTrustAnchorRequest, GetTrustAnchorResponse, RegisterRequest, RegisterResponse,
    RotateKeyRequest, VerifyTokenRequest, VerifyTokenResponse,
};

fn now_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn zone_err(e: ZoneError) -> Status {
    match e {
        ZoneError::BadAddress | ZoneError::BadKeyLength | ZoneError::BadProof => {
            Status::invalid_argument(e.to_string())
        }
        ZoneError::BadToken | ZoneError::TokenExpired { .. } | ZoneError::TokenMismatch => {
            Status::unauthenticated(e.to_string())
        }
        other => Status::failed_precondition(other.to_string()),
    }
}

/// 可克隆的服务包装（tonic 每连接要求 Clone + Send + Sync）
#[derive(Clone)]
pub struct ZoneServerService {
    inner: Arc<Mutex<ZoneServer>>,
}

impl ZoneServerService {
    pub fn new(z: ZoneServer) -> Self {
        Self { inner: Arc::new(Mutex::new(z)) }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ZoneServer> {
        self.inner.lock().expect("zoneserver mutex poisoned")
    }
}

fn issued_to_resp(i: &crate::Issued) -> RegisterResponse {
    RegisterResponse {
        verify_key: i.cert.verify_key.to_vec(),
        not_after: i.cert.not_after,
        ca_sig: i.cert.ca_sig.to_vec(),
        jwt: i.jwt.clone(),
    }
}

#[tonic::async_trait]
impl ZoneServerSvc for ZoneServerService {
    async fn register(
        &self,
        req: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        let r = req.into_inner();
        let issued = {
            let mut g = self.lock();
            g.register(&r.addr_text, &r.ed_pub, &r.proof, DEFAULT_VALIDITY_SECS, now_epoch_secs())
        }
        .map_err(zone_err)?;
        Ok(Response::new(issued_to_resp(&issued)))
    }

    async fn get_trust_anchor(
        &self,
        _req: Request<GetTrustAnchorRequest>,
    ) -> Result<Response<GetTrustAnchorResponse>, Status> {
        let ca_pub = self.lock().trust_anchor().to_vec();
        Ok(Response::new(GetTrustAnchorResponse { ca_pub }))
    }

    async fn rotate_key(
        &self,
        req: Request<RotateKeyRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        let r = req.into_inner();
        // sub 即权威地址：客户端无法对第三方地址冒用本 JWT（rotate PoP 以 sub 构造）
        let issued = {
            let mut g = self.lock();
            let sub = g.verify_token(&r.jwt, now_epoch_secs()).map_err(zone_err)?;
            g.rotate_key(
                &r.jwt,
                &sub,
                &r.new_ed_pub,
                &r.proof,
                DEFAULT_VALIDITY_SECS,
                now_epoch_secs(),
            )
        }
        .map_err(zone_err)?;
        Ok(Response::new(issued_to_resp(&issued)))
    }

    async fn verify_token(
        &self,
        req: Request<VerifyTokenRequest>,
    ) -> Result<Response<VerifyTokenResponse>, Status> {
        let jwt = req.into_inner().jwt;
        let now = now_epoch_secs();
        let (ok, sub, exp) = match self.lock().verify_token_claims(&jwt, now) {
            Ok((sub, exp)) => (true, sub, exp),
            Err(_) => (false, String::new(), 0u64),
        };
        Ok(Response::new(VerifyTokenResponse { ok, sub, exp }))
    }
}

/// 启动服务（ADR-011：端口 0 = 随机；返回实际绑定地址与后台句柄）
pub async fn serve(
    z: ZoneServer,
    addr: SocketAddr,
) -> Result<(SocketAddr, tokio::task::JoinHandle<()>), Box<dyn std::error::Error + Send + Sync>>
{
    let svc = ZoneServerService::new(z);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    let handle = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(ZoneServerServer::new(svc))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .expect("zoneserver gRPC exited");
    });
    Ok((local, handle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use ipv8_codec::IPv8Address;
    use ipv8_tunnel::auth::{Cert, HostIdentity, TrustAnchor};
    use ipv8_tunnel::{Engine, State};
    use pb::zone_server_client::ZoneServerClient;

    async fn spawn(z: ZoneServer) -> ZoneServerClient<tonic::transport::Channel> {
        let (local, _h) = serve(z, "127.0.0.1:0".parse().unwrap()).await.unwrap();
        ZoneServerClient::connect(format!("http://{local}")).await.unwrap()
    }

    fn addr_text(n: u32) -> String {
        IPv8Address::new(64500, n, 1, 0, 1).to_canonical_string()
    }

    /// 客户端辅助：用签名私钥对注册请求签 PoP
    fn sign_register(sk: &SigningKey, text: &str) -> (Vec<u8>, Vec<u8>) {
        let vk = sk.verifying_key().to_bytes();
        let msg = ipv8_tunnel::auth::register_pop_message(text, &vk);
        (vk.to_vec(), sk.sign(&msg).to_bytes().to_vec())
    }

    #[tokio::test]
    async fn grpc_register_then_verify_token_roundtrip() {
        let mut c = spawn(ZoneServer::from_seeds([0xC4u8; 32], [0x2Au8; 32])).await;
        let sk = SigningKey::from_bytes(&[0xA1u8; 32]);
        let text = addr_text(1);
        let (ed, proof) = sign_register(&sk, &text);

        let reg = c
            .register(RegisterRequest {
                addr_text: text.clone(),
                ed_pub: ed,
                proof,
                label: String::new(),
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(reg.verify_key.len(), 32);
        assert_eq!(reg.ca_sig.len(), 64);
        assert!(!reg.jwt.is_empty());

        let v = c
            .verify_token(VerifyTokenRequest { jwt: reg.jwt.clone() })
            .await
            .unwrap()
            .into_inner();
        assert!(v.ok);
        assert_eq!(v.sub, text);
        assert!(v.exp > 0);
    }

    #[tokio::test]
    async fn grpc_returns_trust_anchor_verifiable_as_client() {
        let z = ZoneServer::from_seeds([0xC4u8; 32], [0x2Au8; 32]);
        let anchor_bytes = z.trust_anchor();
        let mut c = spawn(z).await;
        let r = c
            .get_trust_anchor(GetTrustAnchorRequest {})
            .await
            .unwrap()
            .into_inner();
        assert_eq!(&r.ca_pub[..], &anchor_bytes[..]);
        // 客户端能直接构造成 TrustAnchor
        assert!(TrustAnchor::from_bytes(r.ca_pub.try_into().unwrap()).is_ok());
    }

    #[tokio::test]
    async fn grpc_bad_proof_is_invalid_argument() {
        let mut c = spawn(ZoneServer::from_seeds([0xC4u8; 32], [0x2Au8; 32])).await;
        let sk = SigningKey::from_bytes(&[0xA1u8; 32]);
        let text = addr_text(1);
        let (ed, _proof) = sign_register(&sk, &text);
        let err = c
            .register(RegisterRequest {
                addr_text: text,
                ed_pub: ed,
                proof: vec![0u8; 64],
                label: String::new(),
            })
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    /// 经 gRPC 注册一个节点，返回其 HostIdentity（不碰 CA 私钥）。
    async fn enroll(
        c: &mut ZoneServerClient<tonic::transport::Channel>,
        n: u32,
        seed: u8,
    ) -> HostIdentity {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let text = addr_text(n);
        let (ed, proof) = sign_register(&sk, &text);
        let r = c
            .register(RegisterRequest {
                addr_text: text.clone(),
                ed_pub: ed,
                proof,
                label: String::new(),
            })
            .await
            .unwrap()
            .into_inner();
        let cert = Cert {
            addr: IPv8Address::from_canonical_str(&text).unwrap(),
            verify_key: r.verify_key.try_into().unwrap(),
            not_after: r.not_after,
            ca_sig: r.ca_sig.try_into().unwrap(),
        };
        HostIdentity::with_cert(IPv8Address::from_canonical_str(&text).unwrap(), [seed; 32], cert)
    }

    /// 端到端：客户端只持自己的 Ed 私钥 → 经 gRPC 注册拿证书 → 构造 HostIdentity
    /// （全程不碰 CA 私钥）→ 信任锚来自 gRPC → 认证握手 Establishes + 数据面双向。
    #[tokio::test]
    async fn grpc_full_flow_register_issue_cert_into_handshake() {
        let z = ZoneServer::from_seeds([0xC4u8; 32], [0x2Au8; 32]);
        let anchor_bytes = z.trust_anchor();
        let mut c = spawn(z).await;

        let got = c
            .get_trust_anchor(GetTrustAnchorRequest {})
            .await
            .unwrap()
            .into_inner()
            .ca_pub;
        assert_eq!(&got[..], &anchor_bytes[..]);
        let anchor = TrustAnchor::from_bytes(anchor_bytes).unwrap();

        let host_a = enroll(&mut c, 1, 0xA1).await;
        let host_b = enroll(&mut c, 2, 0xB0).await;

        let (a1, a2) = (host_a.addr, host_b.addr);
        let mut alice = Engine::authenticated(host_a, anchor.clone(), a1, a2);
        let mut bob = Engine::authenticated(host_b, anchor, a2, a1);

        let now = 1_700_000_000u64;
        let init = alice.start_auth_handshake();
        let resp = bob.handle_frame_at(&init, now).expect("gRPC 注册的证书应被信任锚接受");
        alice.handle_frame_at(&resp, now);
        assert_eq!(alice.state(), State::Established);
        assert_eq!(bob.state(), State::Established);

        // 数据面双向验证（证明证书→握手→会话密钥链路真实可用）
        let ping = [0x45u8, 0x00, 0x00, 0x14, b'p'];
        let f = alice.seal_frame(&ping).unwrap();
        bob.handle_frame_at(&f, now);
        assert_eq!(bob.take_delivered().as_deref(), Some(&ping[..]));
    }
}
