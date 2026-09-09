//! Phase 1 端到端验证（CI 可跑）：两台虚拟节点经"内存链路"过隧道通信。
//! 这是 v9 "两台 Hyper-V VM 通第一个包" 的无驱动等价物——
//! 验证除真实 wintun/UDP 之外的全部分包路径。

use ipv8_codec::IPv8Address;
use ipv8_tunnel::{Engine, State, TunWorker, mock_tun};

fn addr(n: u32) -> IPv8Address {
    IPv8Address::new(64500, n, 1, 0, 1)
}

#[test]
fn handshake_then_bidirectional_ip_exchange() {
    let mut alice = Engine::new(
        ipv8_tunnel::Identity::from_seed([10u8; 32]),
        addr(1),
        addr(2),
    );
    let mut bob = Engine::new(
        ipv8_tunnel::Identity::from_seed([20u8; 32]),
        addr(2),
        addr(1),
    );

    assert_eq!(alice.state(), State::Idle);
    let init = alice.start_handshake();
    assert_eq!(alice.state(), State::Initiating);

    // Bob 处理 Init → 回 Resp
    let resp = bob.handle_frame(&init).expect("应有握手响应");
    assert_eq!(bob.state(), State::Established);

    // Alice 处理 Resp
    assert!(alice.handle_frame(&resp).is_none());
    assert_eq!(alice.state(), State::Established);

    // ---- 数据面：假 IPv4 包 ping → pong ----
    let ping = [0x45u8, 0x00, 0x00, 0x1C, b'p', b'i', b'n', b'g'];
    let frame = alice.seal_frame(&ping).unwrap();

    // 模拟外层网络：帧进 Bob 的 TUN（经 TunWorker 线程路径）
    let (bob_device, ctl) = mock_tun();
    ctl.feed_inbound(frame.clone());
    let (worker, rx) = TunWorker::spawn(bob_device, Some);
    let received = rx.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
    assert_eq!(received, frame, "TUN 读线程必须原样投递拷贝");
    // 唤醒阻塞在 recv() 的读线程（等价真实设备 session 关闭），再 join
    ctl.close();
    worker.shutdown();

    let none = bob.handle_frame(&received);
    assert!(none.is_none(), "Data 帧不产生响应帧");
    assert_eq!(bob.take_delivered().as_deref(), Some(&ping[..]), "内层 IP 包应完整还原");

    // Bob 回 pong
    let pong = [0x45u8, 0x00, 0x00, 0x1C, b'p', b'o', b'n', b'g'];
    let back = bob.seal_frame(&pong).unwrap();
    alice.handle_frame(&back);
    assert_eq!(alice.take_delivered().as_deref(), Some(&pong[..]));
}

#[test]
fn rotation_survives_e2e() {
    // 灌超过 ROTATE_BYTES 的流量触发轮换，验证双方仍互通
    let mut alice = Engine::new(ipv8_tunnel::Identity::from_seed([1u8; 32]), addr(1), addr(2));
    let mut bob = Engine::new(ipv8_tunnel::Identity::from_seed([2u8; 32]), addr(2), addr(1));
    let resp = bob.handle_frame(&alice.start_handshake()).unwrap();
    alice.handle_frame(&resp);

    // 连续性：灌一批包验证多帧连续互通（4097B 载荷 > 1376B 片预算 → 分片路径）
    let big = vec![0u8; 4096];
    for i in 0..4u8 {
        let payload = [&big[..], &[i]].concat();
        let frames = alice.seal_frames(&payload).unwrap();
        assert_eq!(frames.len(), 3, "4097/1376 片预算 → 3 片，实际 {}", frames.len());
        for f in &frames {
            bob.handle_frame(f);
        }
        assert_eq!(bob.take_delivered().as_deref(), Some(&payload[..]), "分片重组必须逐字节还原");
    }
    assert_eq!(alice.stats().fragments_sent, 8, "4 包 × 2 额外片");
    assert_eq!(bob.stats().fragments_reassembled, 4);

    // 窗口语义：乱序（后发先到）接受；精确重复拒绝
    let f1 = alice.seal_frame(b"one").unwrap();
    let f2 = alice.seal_frame(b"two").unwrap();
    bob.handle_frame(&f2);
    assert_eq!(bob.take_delivered().as_deref(), Some(&b"two"[..]));
    bob.handle_frame(&f1);
    assert_eq!(bob.take_delivered().as_deref(), Some(&b"one"[..]), "窗内乱序应重组投递");
    bob.handle_frame(&f1);
    assert!(bob.take_delivered().is_none(), "精确重复帧被 Replay 拒绝，delivered 不变");
}

#[test]
fn seal_frame_refuses_oversize_but_seal_frames_handles_it() {
    // 契约：单帧 API 对会分片的输入明确拒绝（防静默丢数据），多帧 API 正常工作
    let mut alice = Engine::new(ipv8_tunnel::Identity::from_seed([3u8; 32]), addr(1), addr(2));
    let mut bob = Engine::new(ipv8_tunnel::Identity::from_seed([4u8; 32]), addr(2), addr(1));
    let resp = bob.handle_frame(&alice.start_handshake()).unwrap();
    alice.handle_frame(&resp);

    let big = vec![0x77u8; 5000]; // 40 + 5000 > 1432
    assert!(matches!(alice.seal_frame(&big), Err(ipv8_tunnel::EngineError::NeedsFragmentation(n)) if n == big.len() + 40));
    // 小包仍走单帧
    assert!(alice.seal_frame(b"tiny").is_ok());
    // 大包走多帧且端到端可用
    let frames = alice.seal_frames(&big).unwrap();
    for f in &frames {
        bob.handle_frame(f);
    }
    assert_eq!(bob.take_delivered().as_deref(), Some(&big[..]));
}

#[test]
fn fragments_arriving_out_of_order_reassemble() {
    // UDP 不保证序：末片先到也能重组（IPv8+ Fragment 头携带 offset，接收方按位覆盖）
    let mut alice = Engine::new(ipv8_tunnel::Identity::from_seed([5u8; 32]), addr(1), addr(2));
    let mut bob = Engine::new(ipv8_tunnel::Identity::from_seed([6u8; 32]), addr(2), addr(1));
    let resp = bob.handle_frame(&alice.start_handshake()).unwrap();
    alice.handle_frame(&resp);

    let big = vec![0xABu8; 3000];
    let frames = alice.seal_frames(&big).unwrap();
    assert!(frames.len() >= 3);
    for f in frames.iter().rev() {
        bob.handle_frame(f);
    }
    assert_eq!(bob.take_delivered().as_deref(), Some(&big[..]), "逆序分片仍应完整重组");
}

#[test]
fn tampered_frame_dropped_in_e2e() {
    // 中间链路篡改 → 静默丢帧，不 panic、不投递
    let mut alice = Engine::new(ipv8_tunnel::Identity::from_seed([3u8; 32]), addr(1), addr(2));
    let mut bob = Engine::new(ipv8_tunnel::Identity::from_seed([4u8; 32]), addr(2), addr(1));
    let resp = bob.handle_frame(&alice.start_handshake()).unwrap();
    alice.handle_frame(&resp);

    let mut frame = alice.seal_frame(b"secret traffic").unwrap();
    let mid = frame.len() / 2;
    frame[mid] ^= 0xFF;
    bob.handle_frame(&frame);
    assert!(bob.take_delivered().is_none(), "篡改帧不得产出内层包");
}

#[test]
fn data_before_handshake_is_dropped() {
    let mut bob = Engine::new(ipv8_tunnel::Identity::from_seed([9u8; 32]), addr(2), addr(1));
    let fake_data = {
        let mut a = Engine::new(ipv8_tunnel::Identity::from_seed([8u8; 32]), addr(1), addr(2));
        // 未握手 → seal 应报 NotEstablished
        assert_eq!(
            a.seal_frame(b"x").err().map(|e| format!("{e:?}")),
            Some("NotEstablished".to_string())
        );
        // 伪造一个 Data 帧壳
        let mut f = vec![0x01, 0x02];
        f.extend_from_slice(&0u64.to_be_bytes());
        f.resize(64, 0);
        f
    };
    assert!(bob.handle_frame(&fake_data).is_none());
    assert_eq!(bob.state(), State::Idle);
}
