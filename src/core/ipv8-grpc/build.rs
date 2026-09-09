//! 构建脚本：用 protox（纯 Rust）解析 tunnel.proto，
//! 再交给 tonic-build 生成服务端/客户端代码。
//! 选择 protox 而非 protoc 的原因：Windows 上零外部二进制依赖。

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../shared/ipv8-proto");
    let proto_file = proto_root.join("tunnel.proto");

    // 契约变更时重新生成
    println!("cargo:rerun-if-changed={}", proto_file.display());

    let descriptor = protox::compile([&proto_file], [&proto_root])?;
    tonic_build::configure()
        .build_server(true)
        .build_client(true) // 环回测试与未来 C# 侧调试工具共用
        .compile_fds(descriptor)?;
    Ok(())
}
