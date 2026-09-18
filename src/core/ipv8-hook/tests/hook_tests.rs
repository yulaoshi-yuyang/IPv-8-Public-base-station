//! HookBus 端到端测试：真实 TCP 环回连接，用最小 JSON 客户端驱动。

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::Duration;

use ipv8_hook::{Action, ClientMode, Direction, HookBus, HookConfig, PacketEvent};

fn test_config(timeout_ms: u64, default: Action, queue: usize) -> HookConfig {
    HookConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        timeout: Duration::from_millis(timeout_ms),
        default_action: default,
        payload_prefix: 64,
        flow_ttl_cap: Duration::from_secs(10),
        dispatch_capacity: queue,
        client_queue: 4, // 故意小，便于制造背压
    }
}

/// 最小客户端：连上 → hello → 返回 (stream, 服务端下发的第一行 hello_ack)
fn connect(bus: &HookBus, mode: ClientMode, name: &str) -> TcpStream {
    let mut s = TcpStream::connect(bus.local_addr()).unwrap();
    s.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
    s.set_nodelay(true).unwrap();
    writeln!(
        s,
        r#"{{"type":"hello","mode":"{}","name":"{}","version":1}}"#,
        if mode == ClientMode::Decision { "decision" } else { "observer" },
        name
    )
    .unwrap();
    let mut reader = BufReader::new(s.try_clone().unwrap());
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    assert!(line.contains("hello_ack"), "want hello_ack, got {line}");
    s
}

fn read_event(s: &TcpStream) -> serde_json::Value {
    let mut reader = BufReader::new(s.try_clone().unwrap());
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap()
}

fn send_verdict(s: &mut TcpStream, id: u64, action: &str, ttl_ms: u64) {
    writeln!(
        s,
        r#"{{"type":"verdict","id":{id},"action":"{action}","ttl_ms":{ttl_ms}}}"#
    )
    .unwrap();
}

/// 构造一个 TCP 443 的 IPv4 内层包
fn tcp_packet(sport: u16) -> Vec<u8> {
    let mut p = vec![0u8; 40];
    p[0] = 0x45;
    p[9] = 6;
    p[12..16].copy_from_slice(&[100, 64, 0, 1]);
    p[16..20].copy_from_slice(&[100, 64, 0, 2]);
    p[20..22].copy_from_slice(&sport.to_be_bytes());
    p[22..24].copy_from_slice(&443u16.to_be_bytes());
    p
}

#[test]
fn no_client_uses_default_immediately() {
    let bus = HookBus::start(test_config(50, Action::Accept, 64)).unwrap();
    let pkt = tcp_packet(1111);
    let v = bus.evaluate(&PacketEvent {
        direction: Direction::Out,
        packet: &pkt,
    });
    assert!(v.accepted());
    assert!(!v.source.is_authoritative());
    let st = bus.stats_snapshot();
    assert_eq!(st["seen"], 1);
    assert_eq!(st["fallback"], 1);
}

#[test]
fn decider_accept_and_drop() {
    let bus = HookBus::start(test_config(500, Action::Accept, 64)).unwrap();
    let mut dec = connect(&bus, ClientMode::Decision, "fw");

    // 第一个包 → accept
    let pkt = tcp_packet(2222);
    let bus2 = bus.clone();
    let pkt2 = pkt.clone();
    let h = std::thread::spawn(move || {
        bus2.evaluate(&PacketEvent {
            direction: Direction::Out,
            packet: &pkt2,
        })
    });
    let ev = read_event(&dec);
    assert_eq!(ev["dport"], 443);
    assert_eq!(ev["proto"], "tcp");
    let id = ev["id"].as_u64().unwrap();
    send_verdict(&mut dec, id, "accept", 0);
    assert!(h.join().unwrap().accepted());

    // 第二个包 → drop
    let pkt3 = tcp_packet(3333);
    let bus3 = bus.clone();
    let h = std::thread::spawn(move || {
        bus3.evaluate(&PacketEvent {
            direction: Direction::In,
            packet: &pkt3,
        })
    });
    let ev = read_event(&dec);
    let id = ev["id"].as_u64().unwrap();
    send_verdict(&mut dec, id, "drop", 0);
    assert!(!h.join().unwrap().accepted());
    assert_eq!(bus.stats_snapshot()["dropped"], 1);
}

#[test]
fn second_decider_is_downgraded_to_observer() {
    let bus = HookBus::start(test_config(500, Action::Accept, 64)).unwrap();
    let _dec = connect(&bus, ClientMode::Decision, "fw1");
    let mut s = TcpStream::connect(bus.local_addr()).unwrap();
    writeln!(s, r#"{{"type":"hello","mode":"decision","name":"fw2","version":1}}"#).unwrap();
    let mut reader = BufReader::new(s.try_clone().unwrap());
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let ack: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(ack["ok"], false);
    assert_eq!(ack["mode"], "observer");

    // fw2 的判决无效：evaluate 仍超时回退默认
    let pkt = tcp_packet(4444);
    let t = std::time::Instant::now();
    let v = bus.evaluate(&PacketEvent {
        direction: Direction::Out,
        packet: &pkt,
    });
    // 无真判决 → 超时(80ms)后默认 accept；fw2 的 drop 被忽略
    assert!(v.accepted());
    assert!(t.elapsed() >= Duration::from_millis(70));
}

#[test]
fn timeout_falls_back_to_default() {
    let bus = HookBus::start(test_config(80, Action::Drop, 64)).unwrap();
    let _dec = connect(&bus, ClientMode::Decision, "slow"); // 连上但从不判决
    let pkt = tcp_packet(5555);
    let t = std::time::Instant::now();
    let v = bus.evaluate(&PacketEvent {
        direction: Direction::Out,
        packet: &pkt,
    });
    assert!(!v.accepted()); // fail-close：默认 drop
    assert!(t.elapsed() >= Duration::from_millis(70));
    assert_eq!(bus.stats_snapshot()["fallback"], 1);
    assert_eq!(bus.stats_snapshot()["dropped"], 1);
}

#[test]
fn flow_cache_makes_subsequent_packets_free() {
    let bus = HookBus::start(test_config(500, Action::Accept, 64)).unwrap();
    let mut dec = connect(&bus, ClientMode::Decision, "fw");

    let pkt = tcp_packet(6666);
    let pkt2 = pkt.clone();
    let bus2 = bus.clone();
    let h = std::thread::spawn(move || {
        bus2.evaluate(&PacketEvent {
            direction: Direction::Out,
            packet: &pkt2,
        })
    });
    let ev = read_event(&dec);
    send_verdict(&mut dec, ev["id"].as_u64().unwrap(), "drop", 2000);
    assert!(!h.join().unwrap().accepted());

    // 同流第二个包：判决者不会再收到事件，直接采用缓存（drop）
    let v = bus.evaluate(&PacketEvent {
        direction: Direction::In, // 反向同流，key 相同
        packet: &pkt,
    });
    assert_eq!(v.source, ipv8_hook::VerdictSource::Cached);
    assert!(!v.accepted());
    assert_eq!(bus.stats_snapshot()["cached"], 1);
}

#[test]
fn decider_disconnect_resolves_pending_immediately() {
    let bus = HookBus::start(test_config(5000, Action::Accept, 64)).unwrap();
    let dec = connect(&bus, ClientMode::Decision, "fw");

    let pkt = tcp_packet(7777);
    let bus2 = bus.clone();
    let h = std::thread::spawn(move || {
        bus2.evaluate(&PacketEvent {
            direction: Direction::Out,
            packet: &pkt,
        })
    });
    // 等事件到达判决者，然后断开（不判决）
    let _ev = read_event(&dec);
    drop(dec);

    let t = std::time::Instant::now();
    let v = h.join().unwrap();
    // 不应等 5s 超时，而是立即回退
    assert!(t.elapsed() < Duration::from_millis(1000));
    assert!(v.accepted()); // 默认 accept
}

#[test]
fn slow_decider_with_full_queue_falls_back_fast() {
    // 判决者不读：用大事件（~87KB/个）迅速填满其 TCP 内核缓冲和客户端队列，
    // 后续包必须立即回退，绝不允许在数据面堆积等待。
    let cfg = HookConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        timeout: Duration::from_millis(120),
        default_action: Action::Accept,
        payload_prefix: 65000,
        flow_ttl_cap: Duration::from_secs(10),
        dispatch_capacity: 64,
        client_queue: 4,
    };
    let bus = HookBus::start(cfg).unwrap();
    let _dec = connect(&bus, ClientMode::Decision, "stuck");

    // 先确保 hello 处理完
    std::thread::sleep(Duration::from_millis(100));

    // 每个包 65KB、且用不同源端口 → 不同流，避免流缓存短路
    let mut fell_back_fast = 0;
    for port in 8000u16..8012 {
        let mut pkt = vec![0x45u8; 65507];
        pkt[20..22].copy_from_slice(&port.to_be_bytes());
        pkt[22..24].copy_from_slice(&443u16.to_be_bytes());
        let t = std::time::Instant::now();
        let _ = bus.evaluate(&PacketEvent {
            direction: Direction::Out,
            packet: &pkt,
        });
        if t.elapsed() < Duration::from_millis(50) {
            fell_back_fast += 1;
        }
    }
    // 4 深队列最多卡住少数几个，其余必须是亚毫秒级回退
    assert!(fell_back_fast >= 6, "expected fast fallback, got {fell_back_fast}/12");
}

#[test]
fn observer_receives_copy_but_cannot_decide() {
    let bus = HookBus::start(test_config(500, Action::Accept, 64)).unwrap();
    let mut dec = connect(&bus, ClientMode::Decision, "fw");
    let obs = connect(&bus, ClientMode::Observer, "recorder");

    let pkt = tcp_packet(9001);
    let pkt2 = pkt.clone();
    let bus2 = bus.clone();
    let h = std::thread::spawn(move || {
        bus2.evaluate(&PacketEvent {
            direction: Direction::Out,
            packet: &pkt2,
        })
    });

    // 判决者与观察者都应收到事件
    let ev_dec = read_event(&dec);
    let ev_obs = read_event(&obs);
    assert_eq!(ev_dec["id"], ev_obs["id"]);
    send_verdict(&mut dec, ev_dec["id"].as_u64().unwrap(), "accept", 0);
    assert!(h.join().unwrap().accepted());
}

#[test]
fn garbage_packets_still_evaluate_without_panic() {
    let bus = HookBus::start(test_config(50, Action::Accept, 64)).unwrap();
    for bad in [vec![], vec![0xff], vec![0x45], vec![0; 1500]] {
        let v = bus.evaluate(&PacketEvent {
            direction: Direction::Out,
            packet: &bad,
        });
        assert!(v.accepted());
    }
}
