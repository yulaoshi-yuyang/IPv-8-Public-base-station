//! 构建脚本：protox（纯 Rust）解析 resolver.proto → tonic-build 生成。
//! 与 zoneserver/ipv8-grpc 同路线：Windows 零 protoc 依赖。

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../shared/ipv8-proto");
    let proto_file = proto_root.join("resolver.proto");
    println!("cargo:rerun-if-changed={}", proto_file.display());

    let descriptor = protox::compile([&proto_file], [&proto_root])?;
    tonic_build::configure()
        .build_server(true)
        .build_client(true) // 客户端（C# Host 经各自插件 / Rust 测试复用 stub）
        .compile_fds(descriptor)?;
    Ok(())
}
