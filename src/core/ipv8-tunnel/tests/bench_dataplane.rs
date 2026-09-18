//! 数据面性能画像（Phase 5 评估基线，v9 §"仅评估不实现"）。
//!
//! 全部 `#[ignore]`：不进常规门禁（避免 CI 机器抖动导致断言不稳），
//! 用固定命令跑并打印吞吐：
//!
//! ```text
//! cargo test --release --test bench_dataplane -- --ignored --nocapture --test-threads=1
//! ```
//!
//! 回答的问题：当前纯用户态数据面的吞吐天花板在哪，从而判断
//! "内核旁路/零拷贝"优化是否存在真实收益空间。

use std::time::Instant;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use ed25519_dalek::{Signer, Verifier};
use ipv8_codec::{encode, fragment_packet, IPv8Address, IPv8Header, Reassembler, RouteTrace};
use ipv8_routing::build_route_trace;
use ipv8_tunnel::crypto::{CipherSuite, Identity, TunnelKeys};
use ipv8_tunnel::{Engine, FlowShards, ShardSink, State};

fn gib_per_s(bytes: u64, secs: f64) -> f64 {
    bytes as f64 / secs / (1 << 30) as f64
}

const PAYLOAD: usize = 1424 - 40; // 满 MTU 的 IPv8+ 包载荷（1432-40-8 就近取整）
const ROUNDS: u64 = 100_000;

#[test]
#[ignore] // 性能画像：显式运行
fn aead_seal_and_roundtrip_throughput() {
    let hdr = [0x45u8; 40]; // 充当明文头（AAD）
    let secret = vec![0xA5u8; PAYLOAD];

    for suite in [CipherSuite::ChaCha20Poly1305, CipherSuite::Aes256Gcm] {
        // 纯 seal 吞吐（同一密钥对象连发，counter 递增无回绕成本）
        let mut tx = TunnelKeys::with_suite([7u8; 32], true, suite);
        let t = Instant::now();
        for _ in 0..ROUNDS {
            tx.seal(&hdr, &secret);
        }
        let seal_s = t.elapsed().as_secs_f64();

        // seal→open 新鲜往返（每轮新帧，counter 单调，replay 路径零干扰）
        let mut tx2 = TunnelKeys::with_suite([8u8; 32], true, suite);
        let mut rx2 = TunnelKeys::with_suite([8u8; 32], false, suite);
        let t = Instant::now();
        for _ in 0..ROUNDS {
            let (kid, body) = tx2.seal(&hdr, &secret);
            rx2.open(&kid, &body, &hdr).expect("新鲜帧必须可解");
        }
        let rt_s = t.elapsed().as_secs_f64();
        println!(
            "[bench] AEAD({:?}) seal {:.2} GiB/s | seal+open 往返 {:.2} GiB/s（payload {}B，单线程）",
            suite,
            gib_per_s(ROUNDS * PAYLOAD as u64, seal_s),
            gib_per_s(ROUNDS * PAYLOAD as u64, rt_s),
            PAYLOAD
        );
    }
}

#[test]
#[ignore]
fn fragment_reassemble_throughput() {
    let src = IPv8Address::with_region(1, 0, 0, 0, 0);
    let mut big = vec![0u8; 60_000];
    big[0] = 0x45;
    let hdr = IPv8Header::new(src, src, big.len() as u16);
    let whole = encode(&hdr, &big).unwrap();
    let mtu = 1432usize;
    let rounds = ROUNDS / 40; // 60KB/片 ≈ 42 帧，轮数缩到可比较量级

    let t = Instant::now();
    let mut chunks = Vec::new();
    for i in 0..rounds {
        chunks = fragment_packet(&whole, mtu, i as u32).unwrap();
    }
    let frag_s = t.elapsed().as_secs_f64();

    let t = Instant::now();
    let mut re = Reassembler::new();
    for i in 0..rounds {
        let pkts = fragment_packet(&whole, mtu, i as u32).unwrap();
        let mut done = None;
        for p in &pkts {
            let d = ipv8_codec::decode(p).unwrap();
            if let Ok(Some(r)) = re.insert(&d.header, d.payload) {
                done = Some(r);
            }
        }
        assert!(done.is_some(), "第 {i} 组必须重组完成");
    }
    let re_s = t.elapsed().as_secs_f64();
    println!(
        "[bench] fragment {:.2} GiB/s | frag+reassemble {:.2} GiB/s（60KB 包 @ MTU 1432）",
        gib_per_s(rounds * 60_000, frag_s),
        gib_per_s(rounds * 60_000 * 2, re_s)
    );
    assert!(!chunks.is_empty());
    big[1] = 1; // 防优化掉
}

#[test]
#[ignore]
fn routetrace_build_verify_cost() {
    let hops = [IPv8Address::with_region(2, 0, 0, 0, 0), IPv8Address::with_region(3, 0, 0, 0, 0)];
    let sk = ed25519_dalek::SigningKey::from_bytes(&[0xA1u8; 32]);
    let pk = sk.verifying_key().to_bytes();
    let spec = ipv8_routing::PathSpec {
        src_addr: IPv8Address::with_region(1, 0, 0, 0, 0),
        dst_addr: hops[1],
        min_compat_ver: 0,
        flags: 0x40,
        payload_len: 8,
        init_hop_limit: 64,
        hops: &hops,
        src_pubkey: &pk,
    };
    let t = Instant::now();
    let mut trace: Option<RouteTrace> = None;
    for _ in 0..ROUNDS {
        trace = Some(build_route_trace(&spec, |m| sk.sign(m).to_bytes()).unwrap());
    }
    let build_s = t.elapsed().as_secs_f64();

    let trace = trace.unwrap();
    let t = Instant::now();
    for _ in 0..ROUNDS {
        // 验签主导项：消息体重建 + Ed25519 verify
        let msg = ipv8_codec::route_trace_message(&ipv8_codec::TraceSigInput {
            src_addr: &IPv8Address::with_region(1, 0, 0, 0, 0),
            dst_addr: &hops[1],
            min_compat_ver: 0,
            flags: 0x40,
            payload_len: 8,
            init_hop_limit: 64,
            src_pubkey: &trace.src_pubkey,
            hops: &trace.hops,
        });
        let sig = ed25519_dalek::Signature::from_bytes(&trace.path_sig);
        sk.verifying_key().verify(&msg, &sig).unwrap();
    }
    let verify_s = t.elapsed().as_secs_f64();
    println!(
        "[bench] RouteTrace build {:.1} µs/次（含签名）| verify {:.1} µs/次（单线程）",
        build_s / ROUNDS as f64 * 1e6,
        verify_s / ROUNDS as f64 * 1e6
    );
}

#[test]
#[ignore]
fn engine_loopback_data_plane() {
    // 纯引擎回环（明文握手，无 socket 无 TUN）：seal→handle 单程成本
    for suite in [CipherSuite::ChaCha20Poly1305, CipherSuite::Aes256Gcm] {
        let mut alice = Engine::new(
            Identity::from_bytes([1u8; 32]),
            IPv8Address::with_region(1, 0, 0, 0, 0),
            IPv8Address::with_region(2, 0, 0, 0, 0),
        );
        let mut bob = Engine::new(
            Identity::from_bytes([2u8; 32]),
            IPv8Address::with_region(2, 0, 0, 0, 0),
            IPv8Address::with_region(1, 0, 0, 0, 0),
        );
        alice.set_cipher_suite(suite);
        bob.set_cipher_suite(suite);
        let resp = bob.handle_frame(&alice.start_handshake()).unwrap();
        alice.handle_frame(&resp);
        assert_eq!(alice.state(), State::Established);
        let inner: Vec<u8> = (0..PAYLOAD as u8).collect();
        let t = Instant::now();
        for _ in 0..ROUNDS {
            let f = alice.seal_frame(&inner).unwrap();
            bob.handle_frame(&f);
            let _ = bob.take_delivered();
        }
        let s = t.elapsed().as_secs_f64();
        println!(
            "[bench] 引擎单程 seal→handle({:?}) {:.2} Mpps | {:.2} GiB/s ≈ {:.1} Gbps（纯引擎，不含 socket/TUN/wintun）",
            suite,
            ROUNDS as f64 / s / 1e6,
            gib_per_s(ROUNDS * PAYLOAD as u64, s),
            ROUNDS as f64 / s * 1432.0 * 8.0 / 1e9
        );
    }
}

/// 流级分片多核吞吐（ADR-026）：seal 侧 N worker 并行封装 + 单线程搬运喂入对端。
/// 口径含 channel 搬运（比纯 seal 保守），但并行度收益清晰可见。
#[test]
#[ignore]
fn flow_shards_scaling() {
    const N_SHARDS: &[usize] = &[1, 2, 4, 8];
    const FLOWS: usize = 64;
    const ROUNDS: u64 = 40_000;

    for suite in [CipherSuite::ChaCha20Poly1305, CipherSuite::Aes256Gcm] {
        for &n in N_SHARDS {
            let (mut alice, mut bob) = plain_pair(suite);
            let resp = bob.handle_frame(&alice.start_handshake()).unwrap();
            alice.handle_frame(&resp);
            let (a_shards, al, ap, mtu) = alice.split_shards(n).unwrap();
            let (b_shards, bl, bp, _) = bob.split_shards(n).unwrap();

            let (a_frames, a_out) = frame_collector();
            let (b_frames, b_out) = frame_collector();
            let b_ok = Arc::new(AtomicU64::new(0));
            let b_sink = {
                let c = b_ok.clone();
                Arc::new(move |_: Vec<u8>| {
                    c.fetch_add(1, Ordering::Relaxed);
                })
            };
            let noop: ShardSink = Arc::new(|_| {});
            let ash = FlowShards::new(a_shards, al, ap, mtu, a_frames, noop.clone());
            let bsh = FlowShards::new(b_shards, bl, bp, mtu, b_frames, b_sink);

            // 多流载荷（src 末字节区分 64 条流）
            let flows: Vec<Vec<u8>> = (0..FLOWS as u8)
                .map(|i| {
                    let mut p = vec![0x45u8; PAYLOAD];
                    p[15] = i; // IPv4 src 末字节（offset 12..16）
                    p
                })
                .collect();

            let t = Instant::now();
            let deadline = t + std::time::Duration::from_secs(60);
            let mut next = 0u64;
            loop {
                // 注入侧：持续喂到全部发出（channel 背压自然限流）
                while next < ROUNDS {
                    if ash.seal_dispatch(&flows[(next as usize) % FLOWS]).is_err() {
                        break; // worker 停摆：交给下一轮搬运/判定处理
                    }
                    next += 1;
                }
                // 搬运 A→B
                let fa: Vec<Vec<u8>> = a_out.lock().unwrap().drain(..).collect();
                for f in &fa {
                    bsh.handle_inbound(f);
                }
                // 搬运 B→A（回显帧；A 侧 sink 计数丢弃）
                let fb: Vec<Vec<u8>> = b_out.lock().unwrap().drain(..).collect();
                for f in &fb {
                    ash.handle_inbound(f);
                }
                let done = b_ok.load(Ordering::Relaxed);
                if done >= ROUNDS {
                    break;
                }
                if next >= ROUNDS && fa.is_empty() && fb.is_empty()
                    && Instant::now() > deadline
                {
                    panic!(
                        "n={n} {:?} 停滞：delivered={done}/{ROUNDS}",
                        suite,
                    );
                }
                std::thread::sleep(std::time::Duration::from_micros(200));
            }
            let s = t.elapsed().as_secs_f64();
            println!(
                "[bench] 流级分片({suite:?}, n={n}) 往返吞吐 {:.2} GiB/s ≈ {:.1} Gbps | {:.2} Mpps",
                gib_per_s(ROUNDS * PAYLOAD as u64, s),
                ROUNDS as f64 / s * 1432.0 * 8.0 / 1e9,
                ROUNDS as f64 / s / 1e6
            );
        }
    }
}

fn plain_pair(suite: CipherSuite) -> (Engine, Engine) {
    let mut alice = Engine::new(
        Identity::from_bytes([1u8; 32]),
        IPv8Address::with_region(1, 0, 0, 0, 0),
        IPv8Address::with_region(2, 0, 0, 0, 0),
    );
    let mut bob = Engine::new(
        Identity::from_bytes([2u8; 32]),
        IPv8Address::with_region(2, 0, 0, 0, 0),
        IPv8Address::with_region(1, 0, 0, 0, 0),
    );
    alice.set_cipher_suite(suite);
    bob.set_cipher_suite(suite);
    (alice, bob)
}

fn frame_collector() -> (ShardSink, Arc<std::sync::Mutex<Vec<Vec<u8>>>>) {
    let out = Arc::new(std::sync::Mutex::new(Vec::new()));
    let o = out.clone();
    (Arc::new(move |v: Vec<u8>| o.lock().unwrap().push(v)), out)
}
