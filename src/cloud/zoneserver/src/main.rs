//! ipv8-zoneserver — ZoneServer 独立守护进程（gRPC over TCP）。
//!
//! 用法: ipv8-zoneserver [--addr 127.0.0.1:7070] [--ca-seed <64hex>] [--jwt-seed <64hex>]
//! 未给种子时随机生成（生产正确姿势；重启即换新信任根=所有旧证书作废）。
//! 固定种子仅供可复现的验证环境（回环脚本/联调）。

use std::net::SocketAddr;
use std::str::FromStr;

use ipv8_zoneserver::ZoneServer;

fn parse_seed(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn arg_value(argv: &[String], flag: &str) -> Option<String> {
    argv.iter()
        .position(|a| a == flag)
        .and_then(|i| argv.get(i + 1))
        .filter(|v| !v.starts_with("--"))
        .cloned()
}

#[tokio::main]
async fn main() {
    // 结构化日志走 stderr，stdout 的 "listening on" 行保持给验证脚本匹配。
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))).with_writer(std::io::stderr).init();
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let addr_str = arg_value(&argv, "--addr").unwrap_or_else(|| "127.0.0.1:7070".to_string());
    let Ok(addr) = SocketAddr::from_str(&addr_str) else {
        tracing::error!(addr = %addr_str, "[zoneserver] --addr 非法");
        std::process::exit(2);
    };
    let ca_seed = match arg_value(&argv, "--ca-seed") {
        Some(s) => match parse_seed(&s) {
            Some(b) => Some(b),
            None => {
                eprintln!("[zoneserver] --ca-seed 必须是 64 个十六进制字符");
                std::process::exit(2);
            }
        },
        None => None,
    };
    let jwt_seed = match arg_value(&argv, "--jwt-seed") {
        Some(s) => match parse_seed(&s) {
            Some(b) => Some(b),
            None => {
                eprintln!("[zoneserver] --jwt-seed 必须是 64 个十六进制字符");
                std::process::exit(2);
            }
        },
        None => None,
    };

    let z = match (ca_seed, jwt_seed) {
        (Some(ca), Some(jk)) => ZoneServer::from_seeds(ca, jk),
        _ => ZoneServer::generate(),
    };
    let anchor = hex::encode(&z.trust_anchor()[..]);
    let (local, handle) = match ipv8_zoneserver::grpc::serve(z, addr).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = %e, "[zoneserver] 启动失败");
            std::process::exit(1);
        }
    };
    println!("[zoneserver] listening on {local}（CA 指纹 {anchor}…）");
    let _ = handle.await;
}

/// 极简 hex（避免为日志多引依赖）
mod hex {
    pub fn encode(b: &[u8]) -> String {
        const H: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(b.len() * 2);
        for x in b {
            s.push(H[(x >> 4) as usize] as char);
            s.push(H[(x & 0x0F) as usize] as char);
        }
        s
    }
}
