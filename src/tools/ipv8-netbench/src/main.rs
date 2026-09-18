//! ipv8-netbench — NAT 穿透实测 + 吞吐/延迟/丢包工具
//!
//! 用法：
//!   ipv8-netbench server --port 45801              # 启动测试服务端（被动端）
//!   ipv8-netbench nat --server <IP>[:port]         # NAT 类型检测
//!   ipv8-netbench punch --server <IP>[:port]       # 打洞成功率测试
//!   ipv8-netbench throughput --server <IP>[:port] # 吞吐测试
//!   ipv8-netbench latency --server <IP>[:port]]    # 延迟测试
//!   ipv8-netbench loss --server <IP>[:port]]      # 丢包测试
//!   ipv8-netbench all --server <IP>[:port]        # 全部测试

use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

const MAGIC: u32 = 0x4E425448; // "NBTH" = NetBencH
const DEFAULT_PORT: u16 = 45801;
const PUNCH_KNOCK: &[u8] = b"IP8PUNCH";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NatType {
    NoNat,
    FullCone,
    RestrictedCone,
    PortRestrictedCone,
    Symmetric,
    Unknown,
}

impl NatType {
    fn name(&self) -> &'static str {
        match self {
            NatType::NoNat => "无 NAT（公网直连）",
            NatType::FullCone => "全锥（Full Cone）",
            NatType::RestrictedCone => "限制锥（Restricted Cone）",
            NatType::PortRestrictedCone => "端口限制锥（Port Restricted Cone）",
            NatType::Symmetric => "对称 NAT（Symmetric）",
            NatType::Unknown => "未知",
        }
    }

    fn punch_success_rate(&self) -> &'static str {
        match self {
            NatType::NoNat => "100%（直连无需打洞）",
            NatType::FullCone => "95%+（几乎都能通）",
            NatType::RestrictedCone => "70-85%（需对端先敲门）",
            NatType::PortRestrictedCone => "40-60%（需双方同时敲门）",
            NatType::Symmetric => "5-15%（基本打不通，需中继）",
            NatType::Unknown => "未知",
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        usage();
        std::process::exit(2);
    }

    match args[1].as_str() {
        "server" => {
            let port: u16 = args.iter()
                .position(|a| a == "--port")
                .and_then(|i| args.get(i + 1))
                .and_then(|s| s.parse().ok())
                .unwrap_or(DEFAULT_PORT);
            run_server(port);
        }
        "nat" => {
            let server = parse_server_arg(&args);
            test_nat(server);
        }
        "punch" => {
            let server = parse_server_arg(&args);
            test_punch(server);
        }
        "throughput" => {
            let server = parse_server_arg(&args);
            test_throughput(server);
        }
        "latency" => {
            let server = parse_server_arg(&args);
            test_latency(server);
        }
        "loss" => {
            let server = parse_server_arg(&args);
            test_loss(server);
        }
        "all" => {
            let server = parse_server_arg(&args);
            test_nat(server);
            println!();
            test_punch(server);
            println!();
            test_latency(server);
            println!();
            test_loss(server);
            println!();
            test_throughput(server);
        }
        "help" | "--help" | "-h" => usage(),
        _ => {
            eprintln!("未知命令: {}", args[1]);
            usage();
            std::process::exit(2);
        }
    }
}

fn usage() {
    println!("ipv8-netbench — NAT 穿透实测 + 吞吐/延迟/丢包工具");
    println!();
    println!("用法:");
    println!("  ipv8-netbench server [--port 45801]               启动测试服务端");
    println!("  ipv8-netbench nat --server <IP>[:端口]            NAT 类型检测");
    println!("  ipv8-netbench punch --server <IP>[:端口]          打洞成功率测试");
    println!("  ipv8-netbench throughput --server <IP>[:端口]     吞吐测试 (Mbps)");
    println!("  ipv8-netbench latency --server <IP>[:端口]         延迟测试 (ms)");
    println!("  ipv8-netbench loss --server <IP>[:端口]            丢包测试");
    println!("  ipv8-netbench all --server <IP>[:端口]             全部测试");
    println!();
    println!("示例:");
    println!("  ipv8-netbench server --port 45801");
    println!("  ipv8-netbench all --server 2409:8938::1");
    println!("  ipv8-netbench all --server 192.168.1.12:45801");
}

fn parse_server_arg(args: &[String]) -> SocketAddr {
    let server_str = args.iter()
        .position(|a| a == "--server")
        .and_then(|i| args.get(i + 1))
        .unwrap_or_else(|| {
            eprintln!("错误: 缺少 --server 参数");
            std::process::exit(2);
        });
    parse_addr(server_str)
}

fn parse_addr(s: &str) -> SocketAddr {
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return addr;
    }
    // 尝试 IP:默认端口
    if let Ok(ip) = s.parse::<std::net::IpAddr>() {
        return SocketAddr::new(ip, DEFAULT_PORT);
    }
    eprintln!("错误: 无法解析地址 {s}");
    std::process::exit(2);
}

fn make_pkt(cmd: u8, seq: u32, payload: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(9 + payload.len());
    pkt.extend_from_slice(&MAGIC.to_be_bytes());
    pkt.push(cmd);
    pkt.extend_from_slice(&seq.to_be_bytes());
    pkt.extend_from_slice(payload);
    pkt
}

fn parse_pkt(data: &[u8]) -> Option<(u8, u32, &[u8])> {
    if data.len() < 9 { return None; }
    let magic = u32::from_be_bytes(data[0..4].try_into().ok()?);
    if magic != MAGIC { return None; }
    let cmd = data[4];
    let seq = u32::from_be_bytes(data[5..9].try_into().ok()?);
    Some((cmd, seq, &data[9..]))
}

// ── 服务端 ─────────────────────────────────────────────────────

fn run_server(port: u16) {
    let sock = match UdpSocket::bind(format!("0.0.0.0:{port}")) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("错误: 端口 {port} 绑定失败: {e}");
            std::process::exit(1);
        }
    };
    let _ = sock.set_read_timeout(Some(Duration::from_secs(1)));
    println!("  [server] 监听 0.0.0.0:{port} ...");
    println!("  [server] 等待测试请求");
    println!();

    let mut buf = [0u8; 65536];
    let mut sessions: HashMap<SocketAddr, u32> = HashMap::new();

    loop {
        match sock.recv_from(&mut buf) {
            Ok((n, src)) => {
                // 打洞敲门包 — 静默吸收
                if n == PUNCH_KNOCK.len() && &buf[..n] == PUNCH_KNOCK {
                    continue;
                }
                let (cmd, seq, payload) = match parse_pkt(&buf[..n]) {
                    Some(t) => t,
                    None => continue,
                };

                match cmd {
                    1 => {
                        // NAT 检测请求 — 回复 observed 地址
                        let observed = src.to_string();
                        let reply = make_pkt(1, seq, observed.as_bytes());
                        let _ = sock.send_to(&reply, src);
                    }
                    2 => {
                        // NAT 检测请求2 — 从不同端口回复（用另一个 socket）
                        let alt_sock = UdpSocket::bind("0.0.0.0:0").unwrap();
                        let observed = src.to_string();
                        let reply = make_pkt(2, seq, observed.as_bytes());
                        let _ = alt_sock.send_to(&reply, src);
                    }
                    3 => {
                        // 打洞测试 — 收到敲门包后回复确认
                        let reply = make_pkt(3, seq, b"OK");
                        let _ = sock.send_to(&reply, src);
                    }
                    4 => {
                        // 吞吐测试 — 接收数据包，统计字节数
                        *sessions.entry(src).or_insert(0) += n as u32;
                        // 每 100 包回复一次 ACK
                        if seq % 100 == 0 {
                            let count = sessions[&src];
                            let reply = make_pkt(4, seq, &count.to_be_bytes());
                            let _ = sock.send_to(&reply, src);
                        }
                    }
                    5 => {
                        // 延迟测试 — 原样返回
                        let reply = make_pkt(5, seq, payload);
                        let _ = sock.send_to(&reply, src);
                    }
                    6 => {
                        // 丢包测试 — 原样返回
                        let reply = make_pkt(6, seq, payload);
                        let _ = sock.send_to(&reply, src);
                    }
                    0xFF => {
                        // 结束会话
                        if let Some(count) = sessions.remove(&src) {
                            let reply = make_pkt(0xFF, seq, &count.to_be_bytes());
                            let _ = sock.send_to(&reply, src);
                        } else {
                            let reply = make_pkt(0xFF, seq, &0u32.to_be_bytes());
                            let _ = sock.send_to(&reply, src);
                        }
                    }
                    _ => {}
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock
                       || e.kind() == std::io::ErrorKind::TimedOut => continue,
            Err(e) => {
                eprintln!("  [server] 接收错误: {e}");
            }
        }
    }
}

// ── NAT 类型检测 ───────────────────────────────────────────────

fn test_nat(server: SocketAddr) {
    println!("╔══════════════════════════════════════════════╗");
    println!("║  NAT 类型检测                                  ║");
    println!("╚══════════════════════════════════════════════╝");
    println!("  服务端: {server}");
    println!();

    let sock = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => { eprintln!("  [!] socket 创建失败: {e}"); return; }
    };
    let _ = sock.set_read_timeout(Some(Duration::from_secs(3)));
    let local_addr = sock.local_addr().unwrap();
    println!("  本地绑定地址: {local_addr}");

    // 步骤 1: 从同一 socket 向服务端发包，拿 observed 地址
    let pkt1 = make_pkt(1, 1, b"nat-test");
    let _ = sock.send_to(&pkt1, server);
    let mut buf = [0u8; 1024];
    let observed1 = match sock.recv_from(&mut buf) {
        Ok((n, _)) => {
            if let Some((1, _, payload)) = parse_pkt(&buf[..n]) {
                String::from_utf8_lossy(payload).to_string()
            } else { String::new() }
        }
        Err(e) => {
            eprintln!("  [!] 步骤 1 失败（服务端不可达）: {e}");
            return;
        }
    };
    println!("  步骤 1: observed 地址 = {observed1}");

    // 解析 observed 的 IP 和端口
    let parts: Vec<&str> = observed1.rsplitn(2, ':').collect();
    if parts.len() != 2 {
        eprintln!("  [!] observed 地址格式异常: {observed1}");
        return;
    }
    let observed_port: u16 = parts[0].parse().unwrap_or(0);
    let observed_ip = parts[1];
    println!("  observed IP: {observed_ip}, 端口: {observed_port}");

    // 比较 local port 和 observed port
    let local_port = local_addr.port();
    let port_changed = local_port != observed_port;
    println!("  本地端口: {local_port}, 映射端口: {observed_port}");

    if !port_changed {
        // 端口没变 — 可能无 NAT 或 full cone
        // 尝试从另一个端口发包看 observed 是否变
        let alt_sock = UdpSocket::bind("0.0.0.0:0").unwrap();
        let _ = alt_sock.set_read_timeout(Some(Duration::from_secs(3)));
        let pkt2 = make_pkt(1, 2, b"nat-test2");
        let _ = alt_sock.send_to(&pkt2, server);
        let observed2 = match alt_sock.recv_from(&mut buf) {
            Ok((n, _)) => {
                if let Some((1, _, payload)) = parse_pkt(&buf[..n]) {
                    String::from_utf8_lossy(payload).to_string()
                } else { String::new() }
            }
            Err(_) => { eprintln!("  [!] 步骤 2 失败"); return; }
        };
        let parts2: Vec<&str> = observed2.rsplitn(2, ':').collect();
        let observed2_port: u16 = parts2.first().and_then(|s| s.parse().ok()).unwrap_or(0);
        let alt_local_port = alt_sock.local_addr().unwrap().port();
        println!("  步骤 2: 换端口发包");
        println!("    本地端口: {alt_local_port}, 映射端口: {observed2_port}");

        if alt_local_port == observed2_port {
            let nat_type = NatType::NoNat;
            print_nat_result(nat_type, &observed1, local_port);
        } else {
            let nat_type = NatType::FullCone;
            print_nat_result(nat_type, &observed1, local_port);
        }
        return;
    }

    // 端口变了 — 可能是对称 NAT 或限制锥
    // 步骤 3: 从同一个 socket 再发一次，看端口是否稳定
    let pkt3 = make_pkt(1, 3, b"nat-test3");
    let _ = sock.send_to(&pkt3, server);
    let observed3 = match sock.recv_from(&mut buf) {
        Ok((n, _)) => {
            if let Some((1, _, payload)) = parse_pkt(&buf[..n]) {
                String::from_utf8_lossy(payload).to_string()
            } else { String::new() }
        }
        Err(_) => { eprintln!("  [!] 步骤 3 失败"); return; }
    };
    let parts3: Vec<&str> = observed3.rsplitn(2, ':').collect();
    let observed3_port: u16 = parts3.first().and_then(|s| s.parse().ok()).unwrap_or(0);
    println!("  步骤 3: 同端口再发");
    println!("    第一次映射端口: {observed_port}, 第二次映射端口: {observed3_port}");

    if observed_port != observed3_port {
        // 同一 socket 两次发包端口都变 → 对称 NAT
        let nat_type = NatType::Symmetric;
        print_nat_result(nat_type, &observed1, local_port);
        return;
    }

    // 端口稳定但和本地不同 → 限制锥或端口限制锥
    // 步骤 4: 用 cmd=2 让服务端从不同端口回复
    let pkt4 = make_pkt(2, 4, b"alt-port-test");
    let _ = sock.send_to(&pkt4, server);
    match sock.recv_from(&mut buf) {
        Ok((n, _)) => {
            if let Some((2, _, _)) = parse_pkt(&buf[..n]) {
                // 从不同端口收到了回复 → 限制锥（允许任意源端口）
                let nat_type = NatType::RestrictedCone;
                print_nat_result(nat_type, &observed1, local_port);
            } else {
                let nat_type = NatType::Unknown;
                print_nat_result(nat_type, &observed1, local_port);
            }
        }
        Err(_) => {
            // 从不同端口收不到回复 → 端口限制锥
            let nat_type = NatType::PortRestrictedCone;
            print_nat_result(nat_type, &observed1, local_port);
        }
    }
}

fn print_nat_result(nat_type: NatType, observed: &str, local_port: u16) {
    println!();
    println!("  ┌─────────────────────────────────────────┐");
    println!("  │  NAT 类型: {:<34}│", nat_type.name());
    println!("  │  打洞成功率: {:<31}│", nat_type.punch_success_rate());
    println!("  │  映射地址: {:<33}│", observed);
    println!("  │  本地端口: {local_port:<33}│", );
    println!("  └─────────────────────────────────────────┘");
    println!();
    match nat_type {
        NatType::Symmetric => {
            println!("  ⚠ 对称 NAT: 打洞几乎不可能成功，需要中继（TURN/Relay）");
            println!("    建议：部署 WebSocket 中继节点作为回退");
        }
        NatType::PortRestrictedCone => {
            println!("  ℹ 端口限制锥: 双方需同时发送敲门包才能打洞");
            println!("    建议：确保 Rendezvous 周期内双方都发 PUNCH_KNOCK");
        }
        NatType::RestrictedCone => {
            println!("  ℹ 限制锥: 对端先敲门即可打洞");
            println!("    建议：当前 Rendezvous 机制可覆盖");
        }
        NatType::FullCone | NatType::NoNat => {
            println!("  ✓ 打洞条件优秀，几乎都能成功");
        }
        NatType::Unknown => {
            println!("  ? NAT 类型未确定，建议手动验证");
        }
    }
}

// ── 打洞成功率测试 ──────────────────────────────────────────────

fn test_punch(server: SocketAddr) {
    println!("╔══════════════════════════════════════════════╗");
    println!("║  打洞成功率测试                                ║");
    println!("╚══════════════════════════════════════════════╝");
    println!("  服务端: {server}");
    println!();

    let total = 20u32;
    let mut success = 0u32;
    let mut timeouts = 0u32;

    for i in 1..=total {
        let sock = match UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => s,
            Err(_) => { timeouts += 1; continue; }
        };
        let _ = sock.set_read_timeout(Some(Duration::from_millis(2000)));

        // 先发敲门包
        let _ = sock.send_to(PUNCH_KNOCK, server);

        // 然后发测试包
        let pkt = make_pkt(3, i, b"punch");
        let _ = sock.send_to(&pkt, server);

        let mut buf = [0u8; 256];
        match sock.recv_from(&mut buf) {
            Ok((n, _)) => {
                if let Some((3, _, payload)) = parse_pkt(&buf[..n]) {
                    if payload == b"OK" {
                        success += 1;
                        print!("  [{i:02}/{total}] ✓ ");
                    } else {
                        print!("  [{i:02}/{total}] ✗ ");
                    }
                } else {
                    print!("  [{i:02}/{total}] ✗ ");
                }
            }
            Err(_) => {
                timeouts += 1;
                print!("  [{i:02}/{total}] ✗ timeout ");
            }
        }

        if i % 5 == 0 { println!(); }
        std::thread::sleep(Duration::from_millis(200));
    }

    println!();
    println!("  ┌─────────────────────────────────────────┐");
    println!("  │  打洞成功: {success}/{total} ({:.0}%)", success as f64 / total as f64 * 100.0);
    println!("  │  超时次数: {timeouts}");
    println!("  └─────────────────────────────────────────┘");
    let rate = success as f64 / total as f64;
    if rate >= 0.8 {
        println!("  ✓ 打洞可靠，可直连");
    } else if rate >= 0.4 {
        println!("  ℹ 打洞不稳定，建议保留中继备用");
    } else {
        println!("  ⚠ 打洞困难，需要中继");
    }
}

// ── 吞吐测试 ────────────────────────────────────────────────────

fn test_throughput(server: SocketAddr) {
    println!("╔══════════════════════════════════════════════╗");
    println!("║  吞吐测试 (Mbps)                               ║");
    println!("╚══════════════════════════════════════════════╝");
    println!("  服务端: {server}");
    println!();

    let sock = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => { eprintln!("  [!] socket 创建失败: {e}"); return; }
    };
    let _ = sock.set_read_timeout(Some(Duration::from_secs(5)));

    let payload_size = 1400usize;
    let total_packets = 10000u32;
    let total_bytes = payload_size * total_packets as usize;

    println!("  发送 {total_packets} 包 × {payload_size}B = {:.2} MB", total_bytes as f64 / 1024.0 / 1024.0);

    let payload = vec![0x42u8; payload_size];
    let mut ack_count = 0u32;
    let start = Instant::now();

    for i in 1..=total_packets {
        let pkt = make_pkt(4, i, &payload);
        let _ = sock.send_to(&pkt, server);

        // 检查 ACK（非阻塞）
        let mut buf = [0u8; 64];
        match sock.recv_from(&mut buf) {
            Ok((n, _)) => {
                if let Some((4, _, ack_payload)) = parse_pkt(&buf[..n]) {
                    if ack_payload.len() >= 4 {
                        ack_count = u32::from_be_bytes(ack_payload[..4].try_into().unwrap_or([0; 4]));
                    }
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => {}
        }
    }

    // 发送结束包，拿最终统计
    let end_pkt = make_pkt(0xFF, 0, b"end");
    let _ = sock.send_to(&end_pkt, server);

    let mut buf = [0u8; 64];
    if let Ok((n, _)) = sock.recv_from(&mut buf) {
        if let Some((0xFF, _, ack_payload)) = parse_pkt(&buf[..n]) {
            if ack_payload.len() >= 4 {
                ack_count = u32::from_be_bytes(ack_payload[..4].try_into().unwrap_or([0; 4]));
            }
        }
    }

    let elapsed = start.elapsed();
    let elapsed_secs = elapsed.as_secs_f64();
    let received_bytes = ack_count as usize * payload_size;
    let throughput_mbps = (received_bytes as f64 * 8.0) / 1_000_000.0 / elapsed_secs;

    println!();
    println!("  ┌─────────────────────────────────────────┐");
    println!("  │  发送: {total_packets} 包, {:.2} MB", total_bytes as f64 / 1024.0 / 1024.0);
    println!("  │  接收: {ack_count} 包, {:.2} MB", received_bytes as f64 / 1024.0 / 1024.0);
    println!("  │  耗时: {elapsed_secs:.2}s");
    println!("  │  吞吐: {throughput_mbps:.2} Mbps");
    println!("  │  丢包率: {:.1}%", (1.0 - ack_count as f64 / total_packets as f64) * 100.0);
    println!("  └─────────────────────────────────────────┘");

    if throughput_mbps >= 50.0 {
        println!("  ✓ 吞吐良好，适合大文件传输");
    } else if throughput_mbps >= 10.0 {
        println!("  ℹ 吞吐一般，日常使用够用");
    } else {
        println!("  ⚠ 吞吐偏低，可能是带宽限制或丢包");
    }
}

// ── 延迟测试 ────────────────────────────────────────────────────

fn test_latency(server: SocketAddr) {
    println!("╔══════════════════════════════════════════════╗");
    println!("║  延迟测试 (ms)                                 ║");
    println!("╚══════════════════════════════════════════════╝");
    println!("  服务端: {server}");
    println!();

    let sock = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => { eprintln!("  [!] socket 创建失败: {e}"); return; }
    };
    let _ = sock.set_read_timeout(Some(Duration::from_secs(3)));

    let total = 50u32;
    let mut rtts: Vec<u128> = Vec::with_capacity(total as usize);
    let mut timeouts = 0u32;

    for i in 1..=total {
        let pkt = make_pkt(5, i, b"ping");
        let start = Instant::now();
        let _ = sock.send_to(&pkt, server);

        let mut buf = [0u8; 256];
        match sock.recv_from(&mut buf) {
            Ok((n, _)) => {
                if let Some((5, _, _)) = parse_pkt(&buf[..n]) {
                    let rtt = start.elapsed().as_micros();
                    rtts.push(rtt);
                    if i % 10 == 0 {
                        println!("  [{i:02}/{total}] RTT = {:.2} ms", rtt as f64 / 1000.0);
                    }
                }
            }
            Err(e) => {
                timeouts += 1;
                let timed_out = e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::WouldBlock;
                if timed_out && i % 10 == 0 {
                    println!("  [{i:02}/{total}] 超时");
                }
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    if rtts.is_empty() {
        println!();
        println!("  ✗ 所有请求超时，无法到达服务端");
        return;
    }

    rtts.sort();
    let min = rtts.first().unwrap();
    let max = rtts.last().unwrap();
    let avg: f64 = rtts.iter().map(|&r| r as f64).sum::<f64>() / rtts.len() as f64;
    let p50 = rtts[rtts.len() / 2];
    let p95_idx = ((rtts.len() as f64) * 0.95) as usize;
    let p95 = rtts[p95_idx.min(rtts.len() - 1)];
    let jitter = if rtts.len() > 1 {
        let mut diffs = Vec::new();
        for i in 1..rtts.len() {
            diffs.push((rtts[i] as i64 - rtts[i-1] as i64).unsigned_abs() as f64);
        }
        diffs.iter().sum::<f64>() / diffs.len() as f64
    } else { 0.0 };

    println!();
    println!("  ┌─────────────────────────────────────────┐");
    println!("  │  最小: {:.2} ms", *min as f64 / 1000.0);
    println!("  │  最大: {:.2} ms", *max as f64 / 1000.0);
    println!("  │  平均: {:.2} ms", avg / 1000.0);
    println!("  │  P50:  {:.2} ms", p50 as f64 / 1000.0);
    println!("  │  P95:  {:.2} ms", p95 as f64 / 1000.0);
    println!("  │  抖动: {:.2} ms", jitter / 1000.0);
    println!("  │  超时: {timeouts}/{total}");
    println!("  └─────────────────────────────────────────┘");

    let avg_ms = avg / 1000.0;
    if avg_ms < 30.0 {
        println!("  ✓ 延迟优秀，适合实时通信");
    } else if avg_ms < 100.0 {
        println!("  ℹ 延迟可接受，日常使用没问题");
    } else {
        println!("  ⚠ 延迟较高，可能影响实时通信");
    }
}

// ── 丢包测试 ────────────────────────────────────────────────────

fn test_loss(server: SocketAddr) {
    println!("╔══════════════════════════════════════════════╗");
    println!("║  丢包测试                                      ║");
    println!("╚══════════════════════════════════════════════╝");
    println!("  服务端: {server}");
    println!();

    let sock = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => { eprintln!("  [!] socket 创建失败: {e}"); return; }
    };
    let _ = sock.set_read_timeout(Some(Duration::from_secs(2)));

    let total = 200u32;
    let mut received = 0u32;
    let mut lost = 0u32;
    let mut out_of_order = 0u32;
    let mut last_seq = 0u32;

    println!("  发送 {total} 包，每包间隔 50ms");

    for i in 1..=total {
        let pkt = make_pkt(6, i, b"loss");
        let _ = sock.send_to(&pkt, server);

        let mut buf = [0u8; 256];
        match sock.recv_from(&mut buf) {
            Ok((n, _)) => {
                if let Some((6, seq, _)) = parse_pkt(&buf[..n]) {
                    received += 1;
                    if seq < last_seq {
                        out_of_order += 1;
                    }
                    last_seq = seq;
                } else {
                    lost += 1;
                }
            }
            Err(_) => {
                lost += 1;
            }
        }

        if i % 50 == 0 {
            let rate = received as f64 / i as f64 * 100.0;
            println!("  [{i}/{total}] 已接收 {received}, 丢失 {lost}, 到达率 {rate:.1}%");
        }

        std::thread::sleep(Duration::from_millis(50));
    }

    let loss_rate = lost as f64 / total as f64 * 100.0;
    let delivery_rate = received as f64 / total as f64 * 100.0;

    println!();
    println!("  ┌─────────────────────────────────────────┐");
    println!("  │  总发送: {total}");
    println!("  │  已接收: {received}");
    println!("  │  丢失:   {lost}");
    println!("  │  到达率: {delivery_rate:.1}%");
    println!("  │  丢包率: {loss_rate:.1}%");
    println!("  │  乱序:   {out_of_order}");
    println!("  └─────────────────────────────────────────┘");

    if loss_rate < 1.0 {
        println!("  ✓ 链路质量优秀，丢包率 < 1%");
    } else if loss_rate < 5.0 {
        println!("  ℹ 轻微丢包，影响有限");
    } else {
        println!("  ⚠ 丢包率较高，可能影响通信质量");
        println!("    建议：启用前向纠错（FEC）或降低码率");
    }
}
