//! ipv8-resolver — Resolver 独立守护进程（gRPC over TCP）。
//!
//! 用法: ipv8-resolver [--addr 127.0.0.1:7080]
//! 纯逻辑无信任根（登记授权靠节点自身 PoP 签名），故无种子参数。

use std::net::SocketAddr;
use std::str::FromStr;

fn arg_value(argv: &[String], flag: &str) -> Option<String> {
    argv.iter()
        .position(|a| a == flag)
        .and_then(|i| argv.get(i + 1))
        .filter(|v| !v.starts_with("--"))
        .cloned()
}

#[tokio::main]
async fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let addr_str = arg_value(&argv, "--addr").unwrap_or_else(|| "127.0.0.1:7080".to_string());
    let Ok(addr) = SocketAddr::from_str(&addr_str) else {
        eprintln!("[resolver] --addr 非法: {addr_str}");
        std::process::exit(2);
    };
    let (local, handle) = match ipv8_resolver::grpc::serve(ipv8_resolver::ResolverService::new(), addr).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[resolver] 启动失败: {e}");
            std::process::exit(1);
        }
    };
    println!("[resolver] listening on {local}（内存存储，ADR-010 持久化后置）");
    let _ = handle.await;
}
