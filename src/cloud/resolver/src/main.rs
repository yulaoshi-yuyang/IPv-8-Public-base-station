//! ipv8-resolver — Resolver 独立守护进程（gRPC over TCP）。
//!
//! 用法: ipv8-resolver [--addr 127.0.0.1:7080] [--db <path>]
//! - `--addr` : gRPC 监听地址
//! - `--db`   : SQLite 数据库路径（省略则用内存存储，重启即丢）

use std::net::SocketAddr;
use std::str::FromStr;

use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

use ipv8_resolver::Store;

fn arg_value(argv: &[String], flag: &str) -> Option<String> {
    argv.iter()
        .position(|a| a == flag)
        .and_then(|i| argv.get(i + 1))
        .filter(|v| !v.starts_with("--"))
        .cloned()
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))).with_writer(std::io::stderr).init();

    let argv: Vec<String> = std::env::args().skip(1).collect();
    let addr_str = arg_value(&argv, "--addr").unwrap_or_else(|| "127.0.0.1:7080".to_string());
    let Ok(addr) = SocketAddr::from_str(&addr_str) else {
        tracing::error!(addr = %addr_str, "[resolver] --addr 非法");
        std::process::exit(2);
    };

    let db_path = arg_value(&argv, "--db");

    // 两条独立路径（类型不同，不能合并到一个 match 里）
    let result = match db_path {
        Some(path) => {
            run_sqlite(path, addr).await
        }
        None => {
            run_memory(addr).await
        }
    };

    if let Err(e) = result {
        tracing::error!(error = %e, "[resolver] 运行失败");
        std::process::exit(1);
    }
}

async fn run_memory(addr: SocketAddr) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use ipv8_resolver::MemStore;
    tracing::warn!("[resolver] 未指定 --db，使用内存存储（重启即丢失所有登记）");
    let service = ipv8_resolver::ResolverService::<MemStore>::new();
    let (local, handle) = ipv8_resolver::grpc::serve(service, addr).await?;
    println!("[resolver] listening on {local}（memory 存储）");
    let _ = handle.await;
    Ok(())
}

async fn run_sqlite(path: String, addr: SocketAddr) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use ipv8_resolver::sqlite_store::SqliteStore;
    let store = SqliteStore::open(&path)?;
    let n = store.len();
    tracing::info!(path = %path, loaded = n, "[resolver] SQLite 存储已加载");
    let service = ipv8_resolver::ResolverService::with_store(store);
    let (local, handle) = ipv8_resolver::grpc::serve(service, addr).await?;
    println!("[resolver] listening on {local}（sqlite 存储）");
    let _ = handle.await;
    Ok(())
}
