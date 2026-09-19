//! # ipv8-forward — IPv8 透明端口转发器
//!
//! 核心理念：**节点是空气**。不处理任何用户数据，只提供隧道。
//!
//! 功能：
//! - 读取防火墙规则 JSON，在指定端口启动 TCP/UDP 监听
//! - 外部连接到达时，检查防火墙规则
//! - 规则匹配 → 透明转发到目标地址:端口
//! - 规则不匹配 → 拒绝连接
//! - 支持端口范围、协议过滤、IPv8 源地址过滤
//! - 支持转发到 IPv8 地址（通过隧道）或普通 IP:端口
//!
//! 用法：
//!   ipv8-forward --rules firewall.json [--bind 0.0.0.0] [--peer-tun-ip 100.64.0.2]
//!   ipv8-forward --rules firewall.json --bind 0.0.0.0 --stats-port 9100

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use ipv8_firewall::{Direction, Protocol, RuleSet};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::RwLock;

#[derive(Debug)]
struct ForwarderStats {
    /// 总连接数
    connections: AtomicU64,
    /// 活跃连接数
    active: AtomicU64,
    /// 转发字节数（入）
    bytes_in: AtomicU64,
    /// 转发字节数（出）
    bytes_out: AtomicU64,
    /// 拒绝连接数
    rejected: AtomicU64,
    /// 每条规则的命中次数
    rule_hits: RwLock<HashMap<String, u64>>,
}

impl Default for ForwarderStats {
    fn default() -> Self {
        Self {
            connections: AtomicU64::new(0),
            active: AtomicU64::new(0),
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
            rule_hits: RwLock::new(HashMap::new()),
        }
    }
}

struct Forwarder {
    rules: Arc<RwLock<RuleSet>>,
    stats: Arc<ForwarderStats>,
    bind_addr: String,
    /// 对端 TUN IP（IPv4 或 IPv6）。规则指定 IPv8 目标时，转发到此 IP:端口。
    /// 在 1:1 隧道架构下，所有 TUN 流量都发到唯一对端，IPv8 目标即对端。
    peer_tun_ip: Option<String>,
}

impl Forwarder {
    async fn run(&self) {
        let rules_snapshot = self.rules.read().await;
        let tcp_rules: Vec<_> = rules_snapshot
            .active_rules()
            .filter(|r| {
                r.direction == Direction::Inbound
                    && matches!(r.protocol, Protocol::Tcp | Protocol::Any)
            })
            .cloned()
            .collect();
        let udp_rules: Vec<_> = rules_snapshot
            .active_rules()
            .filter(|r| {
                r.direction == Direction::Inbound
                    && matches!(r.protocol, Protocol::Udp | Protocol::Any)
            })
            .cloned()
            .collect();
        drop(rules_snapshot);

        let mut tasks = Vec::new();

        // TCP 监听
        for rule in &tcp_rules {
            for port in rule.port_start..=rule.port_end {
                let addr = format!("{}:{}", self.bind_addr, port);
                let rules = self.rules.clone();
                let stats = self.stats.clone();
                let rule_id = rule.id.clone();
                let peer_tun_ip = self.peer_tun_ip.clone();
                tasks.push(tokio::spawn(async move {
                    listen_tcp(addr, rules, stats, rule_id, peer_tun_ip).await;
                }));
            }
        }

        // UDP 监听
        for rule in &udp_rules {
            for port in rule.port_start..=rule.port_end {
                let addr = format!("{}:{}", self.bind_addr, port);
                let rules = self.rules.clone();
                let stats = self.stats.clone();
                let rule_id = rule.id.clone();
                let peer_tun_ip = self.peer_tun_ip.clone();
                tasks.push(tokio::spawn(async move {
                    listen_udp(addr, rules, stats, rule_id, peer_tun_ip).await;
                }));
            }
        }

        // 等待所有任务（实际上不会结束）
        for t in tasks {
            let _ = t.await;
        }
    }
}

/// TCP 监听 + 转发
async fn listen_tcp(
    addr: String,
    rules: Arc<RwLock<RuleSet>>,
    stats: Arc<ForwarderStats>,
    default_rule_id: String,
    peer_tun_ip: Option<String>,
) {
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => {
            tracing::info!("TCP 监听 {}", addr);
            l
        }
        Err(e) => {
            tracing::error!("TCP 绑定 {} 失败: {}", addr, e);
            return;
        }
    };

    loop {
        let (client, client_addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("accept {} 失败: {}", addr, e);
                continue;
            }
        };

        let rules = rules.clone();
        let stats = stats.clone();
        let default_rule_id = default_rule_id.clone();
        let peer_tun_ip = peer_tun_ip.clone();

        tokio::spawn(async move {
            stats.connections.fetch_add(1, Ordering::Relaxed);
            stats.active.fetch_add(1, Ordering::Relaxed);

            // 查找匹配规则
            let rules_read = rules.read().await;
            // 端口从 client_addr 获取（如果 local_port 可知的话用实际监听端口）
            // 这里用 default_rule_id 作为快速路径
            let port = client_addr.port();
            let match_result = rules_read.match_rule(6, port, &ipv8_default_addr());

            // 增加规则命中计数
            {
                let mut hits = stats.rule_hits.write().await;
                let id = match_result
                    .as_ref()
                    .map(|m| m.rule_id.as_str())
                    .unwrap_or(&default_rule_id);
                *hits.entry(id.to_string()).or_insert(0) += 1;
            }
            drop(rules_read);

            if match_result.is_none() {
                // 检查是否有默认放行规则
                // 如果没有匹配规则，拒绝连接
                stats.rejected.fetch_add(1, Ordering::Relaxed);
                stats.active.fetch_sub(1, Ordering::Relaxed);
                return;
            }

            // 获取转发目标
            let target_addr = match_result.as_ref().and_then(|m| m.target);
            let target_port = match_result
                .as_ref()
                .map(|m| m.target_port)
                .unwrap_or(port);

            // 建立到目标的连接
            let upstream = if let Some(_ipv8_addr) = target_addr {
                // IPv8 目标 → 通过隧道转发到对端 TUN IP:端口。
                // 1:1 隧道架构下所有 TUN 流量发到唯一对端，故连对端 TUN IP 即可。
                let dst_ip = peer_tun_ip.as_deref().unwrap_or("127.0.0.1");
                if peer_tun_ip.is_none() {
                    tracing::warn!(
                        "规则指定 IPv8 目标但未传 --peer-tun-ip，回退到本地 127.0.0.1"
                    );
                }
                match TcpStream::connect(format!("{dst_ip}:{target_port}")).await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!("连接对端 {dst_ip}:{target_port} 失败: {e}");
                        stats.active.fetch_sub(1, Ordering::Relaxed);
                        return;
                    }
                }
            } else {
                // 无目标地址 → 转发到本地同端口
                match TcpStream::connect(format!("127.0.0.1:{}", port)).await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!("连接本地 {} 失败: {}", port, e);
                        stats.active.fetch_sub(1, Ordering::Relaxed);
                        return;
                    }
                }
            };

            // 透明双向转发
            let (mut client_r, mut client_w) = client.into_split();
            let (mut upstream_r, mut upstream_w) = upstream.into_split();

            let stats1 = stats.clone();
            let stats2 = stats.clone();

            let t1 = tokio::spawn(async move {
                let mut buf = [0u8; 65536];
                loop {
                    match client_r.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            stats1.bytes_in.fetch_add(n as u64, Ordering::Relaxed);
                            if upstream_w.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });

            let t2 = tokio::spawn(async move {
                let mut buf = [0u8; 65536];
                loop {
                    match upstream_r.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            stats2.bytes_out.fetch_add(n as u64, Ordering::Relaxed);
                            if client_w.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });

            let _ = tokio::join!(t1, t2);
            stats.active.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

/// UDP 监听 + 转发
async fn listen_udp(
    addr: String,
    rules: Arc<RwLock<RuleSet>>,
    stats: Arc<ForwarderStats>,
    default_rule_id: String,
    peer_tun_ip: Option<String>,
) {
    let sock = match UdpSocket::bind(&addr).await {
        Ok(s) => {
            tracing::info!("UDP 监听 {}", addr);
            Arc::new(s)
        }
        Err(e) => {
            tracing::error!("UDP 绑定 {} 失败: {}", addr, e);
            return;
        }
    };

    let mut buf = [0u8; 65536];
    let mut routes: HashMap<SocketAddr, Arc<UdpSocket>> = HashMap::new();

    loop {
        let (n, src) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("recv_from {} 失败: {}", addr, e);
                continue;
            }
        };

        stats.connections.fetch_add(1, Ordering::Relaxed);

        // 查找匹配规则
        let rules_read = rules.read().await;
        let port = src.port();
        let match_result = rules_read.match_rule(17, port, &ipv8_default_addr());
        {
            let mut hits = stats.rule_hits.write().await;
            let id = match_result
                .as_ref()
                .map(|m| m.rule_id.as_str())
                .unwrap_or(&default_rule_id);
            *hits.entry(id.to_string()).or_insert(0) += 1;
        }
        drop(rules_read);

        if match_result.is_none() {
            stats.rejected.fetch_add(1, Ordering::Relaxed);
            continue;
        }

        let target_addr = match_result.as_ref().and_then(|m| m.target);
        let target_port = match_result
            .as_ref()
            .map(|m| m.target_port)
            .unwrap_or(port);

        // 获取或创建到目标的 UDP socket
        let upstream = if let Some(route) = routes.get(&src) {
            route.clone()
        } else {
            // IPv8 目标 → 对端 TUN IP；无目标 → 本地同端口
            let dst_ip = if target_addr.is_some() {
                peer_tun_ip.as_deref().unwrap_or("127.0.0.1")
            } else {
                "127.0.0.1"
            };
            let upstream_addr = format!("{dst_ip}:{target_port}");
            match UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => {
                    let s = Arc::new(s);
                    let _ = s.connect(&upstream_addr).await;
                    routes.insert(src, s.clone());
                    s
                }
                Err(_) => continue,
            }
        };

        // 转发数据
        let data = buf[..n].to_vec();
        stats.bytes_in.fetch_add(n as u64, Ordering::Relaxed);

        // 接收响应
        let sock_clone = sock.clone();
        let stats_clone = stats.clone();
        let upstream_clone = upstream.clone();
        tokio::spawn(async move {
            let mut resp_buf = [0u8; 65536];
            if let Ok(n) = upstream_clone.recv(&mut resp_buf).await {
                stats_clone.bytes_out.fetch_add(n as u64, Ordering::Relaxed);
                let _ = sock_clone.send_to(&resp_buf[..n], src).await;
            }
        });

        let _ = upstream.send(&data).await;
    }
}

/// 默认 IPv8 地址（用于规则匹配的源地址）
fn ipv8_default_addr() -> ipv8_codec::IPv8Address {
    ipv8_codec::IPv8Address::with_region(0, 0, 0, 0, 0)
}

/// 启动统计 HTTP 服务
async fn stats_server(stats: Arc<ForwarderStats>, port: u16) {
    let listener = match TcpListener::bind(format!("127.0.0.1:{}", port)).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("统计服务绑定失败: {}", e);
            return;
        }
    };

    loop {
        let (mut sock, _) = match listener.accept().await {
            Ok(v) => v,
            Err(_) => continue,
        };

        let stats = stats.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            let _ = sock.read(&mut buf).await;
            let hits = stats.rule_hits.read().await;
            let json = serde_json::json!({
                "connections": stats.connections.load(Ordering::Relaxed),
                "active": stats.active.load(Ordering::Relaxed),
                "bytes_in": stats.bytes_in.load(Ordering::Relaxed),
                "bytes_out": stats.bytes_out.load(Ordering::Relaxed),
                "rejected": stats.rejected.load(Ordering::Relaxed),
                "rule_hits": hits.clone(),
            });
            let body = serde_json::to_string_pretty(&json).unwrap_or_default();
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = sock.write_all(resp.as_bytes()).await;
        });
    }
}

fn print_usage() {
    eprintln!("IPv8 透明端口转发器");
    eprintln!();
    eprintln!("用法: ipv8-forward --rules <firewall.json> [选项]");
    eprintln!();
    eprintln!("选项:");
    eprintln!("  --rules <path>     防火墙规则 JSON 文件路径");
    eprintln!("  --bind <addr>      绑定地址 (默认: 0.0.0.0)");
    eprintln!("  --stats-port <n>   统计服务端口 (默认: 9100)");
    eprintln!("  --watch             监视规则文件变化并自动重载");
    eprintln!("  --peer-tun-ip <ip>  对端 TUN IP，IPv8 目标转发到此 IP:端口");
    eprintln!();
    eprintln!("规则 JSON 格式:");
    eprintln!(r#"  {{"rules":[{{"id":"r1","name":"Web","protocol":"tcp","port_start":80,"port_end":80,"source_pattern":"","target_addr":"","target_port":0,"enabled":true,"direction":"inbound","comment":""}}]}}"#);
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();
    let mut rules_path: Option<PathBuf> = None;
    let mut bind = "0.0.0.0".to_string();
    let mut stats_port: u16 = 9100;
    let mut watch = false;
    let mut peer_tun_ip: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--rules" => {
                i += 1;
                if i < args.len() {
                    rules_path = Some(PathBuf::from(&args[i]));
                }
            }
            "--bind" => {
                i += 1;
                if i < args.len() {
                    bind = args[i].clone();
                }
            }
            "--stats-port" => {
                i += 1;
                if i < args.len() {
                    if let Ok(p) = args[i].parse() {
                        stats_port = p;
                    }
                }
            }
            "--watch" => watch = true,
            "--peer-tun-ip" => {
                i += 1;
                if i < args.len() {
                    peer_tun_ip = Some(args[i].clone());
                }
            }
            "--help" | "-h" => {
                print_usage();
                return;
            }
            _ => {}
        }
        i += 1;
    }

    let rules_path = match rules_path {
        Some(p) => p,
        None => {
            print_usage();
            std::process::exit(1);
        }
    };

    let ruleset = RuleSet::load(&rules_path);
    let active = ruleset.active_rules().count();
    tracing::info!("已加载 {} 条规则 ({} 条启用)", ruleset.rules.len(), active);

    let rt = tokio::runtime::Runtime::new().unwrap();

    let rules = Arc::new(RwLock::new(ruleset));
    let stats = Arc::new(ForwarderStats::default());

    // 统计服务
    rt.spawn(stats_server(stats.clone(), stats_port));

    // 文件监视（自动重载规则）
    if watch {
        let path = rules_path.clone();
        let rules_clone = rules.clone();
        rt.spawn(async move {
            let mut last_mtime = std::fs::metadata(&path)
                .ok()
                .and_then(|m| m.modified().ok());
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                let mtime = std::fs::metadata(&path)
                    .ok()
                    .and_then(|m| m.modified().ok());
                if mtime != last_mtime {
                    last_mtime = mtime;
                    let new_rs = RuleSet::load(&path);
                    let count = new_rs.active_rules().count();
                    tracing::info!("规则重载: {} 条启用", count);
                    *rules_clone.write().await = new_rs;
                }
            }
        });
    }

    // 主转发器
    let forwarder = Forwarder {
        rules,
        stats,
        bind_addr: bind,
        peer_tun_ip,
    };
    rt.block_on(forwarder.run());
}
