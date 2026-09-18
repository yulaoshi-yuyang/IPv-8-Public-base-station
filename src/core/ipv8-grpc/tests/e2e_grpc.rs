//! gRPC 桥端到端验证：两个 TunnelEngine 服务（Alice/Bob）经真实 TCP 通道
//! 完成握手并互发内层 IP 包。这是 C# 宿主接入路径的 Rust 侧等价证明——
//! C# 用同一 tunnel.proto 生成的客户端，走的就是这里验证的调用序。

use std::net::SocketAddr;
use std::time::Duration;

use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Channel, Server};

use ipv8_codec::IPv8Address;
use ipv8_grpc::pb::stream_in::Payload as InPayload;
use ipv8_grpc::pb::stream_out::Payload as OutPayload;
use ipv8_grpc::pb::{
    tunnel_engine_client::TunnelEngineClient, tunnel_engine_server::TunnelEngineServer, Empty,
    StartHandshakeRequest, StreamIn, StreamOut, TunPacket, WireFrame,
};
use ipv8_grpc::TunnelEngineService;
use ipv8_tunnel::{Engine, Identity};

const A2B: &[u8] = b"ping via grpc";
const B2A: &[u8] = b"pong via grpc";

fn addr(n: u32) -> IPv8Address {
    IPv8Address::with_region(n as u64, 1, 0, 1, 0)
}

async fn spawn_engine(engine: Engine) -> (SocketAddr, Channel) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local = listener.local_addr().unwrap();
    let svc = TunnelEngineService::new(engine);
    tokio::spawn(async move {
        Server::builder()
            .add_service(TunnelEngineServer::new(svc))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    let channel = Channel::from_shared(format!("http://{local}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    (local, channel)
}

/// 从双向流里取下一个非空 payload（带超时，避免测试挂死）
async fn next_payload(stream: &mut tonic::Streaming<StreamOut>, label: &str) -> OutPayload {
    let Ok(res) = tokio::time::timeout(Duration::from_secs(5), stream.message()).await else {
        panic!("{label}: 等待输出超时");
    };
    let msg = res.expect("流错误").expect("空消息");
    msg.payload.unwrap_or_else(|| panic!("{label}: 缺少 oneof payload"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn grpc_handshake_and_bidirectional_ping_pong() {
    let (_a_addr, a_ch) = spawn_engine(Engine::new(
        Identity::from_bytes([0xA1u8; 32]),
        addr(1),
        addr(2),
    ))
    .await;
    let (_b_addr, b_ch) = spawn_engine(Engine::new(
        Identity::from_bytes([0xB0u8; 32]),
        addr(2),
        addr(1),
    ))
    .await;

    let mut alice = TunnelEngineClient::new(a_ch);
    let mut bob = TunnelEngineClient::new(b_ch);

    // ---- 控制面握手：StartHandshake → InjectFrame(Init) → InjectFrame(Resp) ----
    let init = alice
        .start_handshake(StartHandshakeRequest { peer_addr_text: addr(2).to_canonical_string() })
        .await
        .unwrap()
        .into_inner()
        .init_frame
        .expect("应返回 HandshakeInit 帧");

    let resp = bob
        .inject_frame(WireFrame { raw: init.raw })
        .await
        .unwrap()
        .into_inner();
    assert!(resp.established, "Bob 处理 Init 后即 Established");
    let resp_frame = resp.response_frame.expect("Bob 应回 HandshakeResp");

    let done = alice
        .inject_frame(WireFrame { raw: resp_frame.raw })
        .await
        .unwrap()
        .into_inner();
    assert!(done.established, "Alice 处理 Resp 后即 Established");

    // ---- 数据面：各开一条 StreamPackets，交换内层 IP 包 ----
    let (a_tx, a_rx) = tokio::sync::mpsc::channel::<StreamIn>(8);
    let (b_tx, b_rx) = tokio::sync::mpsc::channel::<StreamIn>(8);

    let mut a_out = alice
        .stream_packets(ReceiverStream::new(a_rx))
        .await
        .unwrap()
        .into_inner();
    let mut b_out = bob
        .stream_packets(ReceiverStream::new(b_rx))
        .await
        .unwrap()
        .into_inner();

    // A → B
    a_tx.send(tun_in(A2B.to_vec())).await.unwrap();
    let wire_ab = match next_payload(&mut a_out, "alice→wire").await {
        OutPayload::ToWire(f) => f,
        _ => panic!("Alice 应产出 ToWire"),
    };
    b_tx.send(wire_in(wire_ab.raw)).await.unwrap();
    match next_payload(&mut b_out, "bob→tun").await {
        OutPayload::ToTun(t) => assert_eq!(t.raw, A2B),
        _ => panic!("Bob 应产出 ToTun"),
    }

    // B → A
    b_tx.send(tun_in(B2A.to_vec())).await.unwrap();
    let wire_ba = match next_payload(&mut b_out, "bob→wire").await {
        OutPayload::ToWire(f) => f,
        _ => panic!("Bob 应产出 ToWire"),
    };
    a_tx.send(wire_in(wire_ba.raw.clone())).await.unwrap();
    match next_payload(&mut a_out, "alice→tun").await {
        OutPayload::ToTun(t) => assert_eq!(t.raw, B2A),
        _ => panic!("Alice 应产出 ToTun"),
    }

    // ---- 状态快照：计数一致 ----
    let st = alice.get_status(Empty {}).await.unwrap().into_inner();
    assert_eq!(st.sealed_outbound, 1);
    assert_eq!(st.delivered_inbound, 1);
    assert_eq!(st.peer_addr_text, addr(2).to_canonical_string());
    let stb = bob.get_status(Empty {}).await.unwrap().into_inner();
    assert_eq!(stb.sealed_outbound, 1);
    assert_eq!(stb.delivered_inbound, 1);

    // 篡改帧注入 → 丢弃计数增长，不 panic
    let mut evil = wire_ba.raw.clone();
    let mid = evil.len() / 2;
    evil[mid] ^= 0xFF;
    a_tx.send(wire_in(evil)).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let st2 = alice.get_status(Empty {}).await.unwrap().into_inner();
    assert_eq!(st2.dropped_inbound, 1, "篡改帧必须计入 dropped_inbound");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn start_handshake_validates_address_text() {
    let (_addr, ch) = spawn_engine(Engine::new(
        Identity::from_bytes([1u8; 32]),
        addr(1),
        addr(2),
    ))
    .await;
    let mut client = TunnelEngineClient::new(ch);
    let err = client
        .start_handshake(StartHandshakeRequest { peer_addr_text: "not-hex".into() })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    // 合法地址进入 Initiating 后，重复发起应被拒
    client
        .start_handshake(StartHandshakeRequest { peer_addr_text: addr(9).to_canonical_string() })
        .await
        .unwrap();
    let err2 = client
        .start_handshake(StartHandshakeRequest { peer_addr_text: addr(9).to_canonical_string() })
        .await
        .unwrap_err();
    assert_eq!(err2.code(), tonic::Code::FailedPrecondition);
}

fn tun_in(raw: Vec<u8>) -> StreamIn {
    StreamIn { payload: Some(InPayload::Tun(TunPacket { raw })) }
}

fn wire_in(raw: Vec<u8>) -> StreamIn {
    StreamIn { payload: Some(InPayload::Wire(WireFrame { raw })) }
}

/// gRPC 契约暴露的 Fallback 决策面端到端（C# 宿主将按此调用序驱动降级）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grpc_fallback_decision_surface() {
    use ipv8_grpc::pb::{
        next_path_response::Kind as Pk, FailureKind as Fk, FallbackLevel, NextPathRequest,
        RecordFailureRequest, RecordSuccessRequest, ResolvedEntry, SetResolvedRequest,
    };
    let (_addr, ch) = spawn_engine(Engine::new(
        Identity::from_bytes([0xA1u8; 32]),
        addr(1),
        addr(2),
    ))
    .await;
    let mut client = TunnelEngineClient::new(ch);
    let peer = addr(2).to_canonical_string();

    // Resolver 结果喂入：主入口 + 一个备用
    client
        .set_resolved(SetResolvedRequest {
            peer: peer.clone(),
            resolved: Some(ResolvedEntry {
                tunnel_entry: "10.0.0.1:45701".into(),
                alt_entries: vec!["10.0.0.2:45702".into()],
                ipv8_capable: true,
                last_good_entry: String::new(),
            }),
        })
        .await
        .unwrap();

    // 首次决策：主隧道 + 首次握手超时 8s
    let np = client.next_path(NextPathRequest { peer: peer.clone() }).await.unwrap().into_inner();
    assert_eq!(np.kind, Pk::Tunnel as i32);
    assert_eq!(np.tunnel_entry, "10.0.0.1:45701");
    assert_eq!(np.handshake_timeout_secs, 8);

    // 主入口握手超时 ×3（max_retries=2 内重发，第 3 次换备用入口）
    for _ in 0..3 {
        let r = client
            .record_failure(RecordFailureRequest { peer: peer.clone(), kind: Fk::HandshakeTimeout as i32 })
            .await
            .unwrap()
            .into_inner();
        let _ = r;
    }
    let np2 = client.next_path(NextPathRequest { peer: peer.clone() }).await.unwrap().into_inner();
    assert_eq!(np2.kind, Pk::Tunnel as i32, "备用入口仍是隧道");
    assert_eq!(np2.tunnel_entry, "10.0.0.2:45702");

    // 备用也耗尽 → 明文级
    for _ in 0..3 {
        client
            .record_failure(RecordFailureRequest { peer: peer.clone(), kind: Fk::HandshakeTimeout as i32 })
            .await
            .unwrap();
    }
    let np3 = client.next_path(NextPathRequest { peer: peer.clone() }).await.unwrap().into_inner();
    assert_eq!(np3.kind, Pk::PlainTcp as i32, "全入口失败必须落明文 TCP");

    // 降级期间 get_status 暴露级别
    let st = client.get_status(Empty {}).await.unwrap().into_inner();
    assert_eq!(st.fallback_level, FallbackLevel::PlainTcp as i32);

    // 隧道成功（假设 TTL 后恢复尝试）：备用提正 + 清缓存 → MainTunnel
    let rs = client
        .record_success(RecordSuccessRequest { peer: peer.clone(), tunnel_entry: "10.0.0.2:45702".into() })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(rs.level, FallbackLevel::MainTunnel as i32);
    let np4 = client.next_path(NextPathRequest { peer: peer.clone() }).await.unwrap().into_inner();
    assert_eq!(np4.tunnel_entry, "10.0.0.2:45702", "成功过的备用入口应被提正为主入口");
    assert_eq!(np4.handshake_timeout_secs, 5, "last_good 已记录 → 缓存超时 5s");

    // 非 IPv8+ 对端 → 跳过隧道尝试直落 PlainTcp
    client
        .set_resolved(SetResolvedRequest {
            peer: "legacy".into(),
            resolved: Some(ResolvedEntry {
                tunnel_entry: String::new(),
                alt_entries: vec![],
                ipv8_capable: false,
                last_good_entry: String::new(),
            }),
        })
        .await
        .unwrap();
    let np5 = client.next_path(NextPathRequest { peer: "legacy".into() }).await.unwrap().into_inner();
    assert_eq!(np5.kind, Pk::PlainTcp as i32);
}
