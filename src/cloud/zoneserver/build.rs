//! 构建脚本：protox（纯 Rust）解析 zoneserver.proto → tonic-build 生成。
//! 与 ipv8-grpc 同路线：Windows 零 protoc 依赖。

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../shared/ipv8-proto");
    let proto_file = proto_root.join("zoneserver.proto");
    println!("cargo:rerun-if-changed={}", proto_file.display());

    let descriptor = protox::compile([&proto_file], [&proto_root])?;
    tonic_build::configure()
        .build_server(true)
        .build_client(true) // 节点侧（ipv8-node）复用同一 client stub
        .compile_fds(descriptor)?;
    Ok(())
}
