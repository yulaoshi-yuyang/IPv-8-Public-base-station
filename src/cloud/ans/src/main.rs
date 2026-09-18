//! ipv8-ans — ANS 独立守护进程（gRPC over TCP）。
//!
//! 用法: ipv8-ans [--addr 127.0.0.1:7090] [--anchor <64hex>] [--root .ipv8.net]
//! --anchor 为信任锚公钥（验注册证书）；省略时用随机 CA 的公钥并打印
//! （仅自测便利——生产锚来自 ZoneServer 部署参数，ADR-021）。

use std::net::SocketAddr;
use std::str::FromStr;

use ed25519_dalek::{SigningKey, VerifyingKey};

fn arg_value(argv: &[String], flag: &str) -> Option<String> {
    argv.iter()
        .position(|a| a == flag)
        .and_then(|i| argv.get(i + 1))
        .filter(|v| !v.starts_with("--"))
        .cloned()
}

fn parse_pub(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

#[tokio::main]
async fn main() {
    // 结构化日志走 stderr，stdout 的 "listening on" 行保持给验证脚本匹配。
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))).with_writer(std::io::stderr).init();
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let addr_str = arg_value(&argv, "--addr").unwrap_or_else(|| "127.0.0.1:7090".to_string());
    let Ok(addr) = SocketAddr::from_str(&addr_str) else {
        tracing::error!(addr = %addr_str, "[ans] --addr 非法");
        std::process::exit(2);
    };
    let root = arg_value(&argv, "--root").unwrap_or_else(|| ".ipv8.net".to_string());
    let anchor = match arg_value(&argv, "--anchor") {
        Some(s) => match parse_pub(&s) {
            Some(b) => b,
            None => {
                eprintln!("[ans] --anchor 必须是 64 个十六进制字符（CA 公钥）");
                std::process::exit(2);
            }
        },
        None => {
            // 自测便利：随机 CA，打印公钥供客户端配置
            let sk = SigningKey::generate(&mut rand_core::OsRng);
            let pk: [u8; 32] = sk.verifying_key().to_bytes();
            let hex: String = pk.iter().map(|b| format!("{b:02x}")).collect();
            println!("[ans] 未指定 --anchor，本次随机信任锚: {hex}（重启即失效，仅供自测）");
            pk
        }
    };
    // 合法性自检：锚必须是能解析的 Ed25519 公钥
    if VerifyingKey::from_bytes(&anchor).is_err() {
        eprintln!("[ans] 锚公钥非法");
        std::process::exit(2);
    }
    let (local, handle) =
        match ipv8_ans::grpc::serve(ipv8_ans::AnsService::new(anchor, root), addr).await {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(error = %e, "[ans] 启动失败");
                std::process::exit(1);
            }
        };
    println!("[ans] listening on {local}（内存存储，ADR-010 持久化后置）");
    let _ = handle.await;
}
