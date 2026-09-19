//! dll_bootstrap — 单文件分发的 wintun.dll 自举
//!
//! 是什么：把编译期内嵌的官方 wintun.dll（WHQL 签名、字节未修改）
//! 释放到本机固定位置并做完整性校验，之后 wintun crate 从该路径加载。
//! 输入：无（内嵌字节 + 系统环境变量）
//! 输出：Ok(可加载的 dll 路径) / Err(可读原因)

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// 官方未修改的 wintun.dll。签名是对整段字节的绑定，释放后签名仍然有效。
const WINTUN_DLL: &[u8] = include_bytes!("../../../../deploy/client/wintun.dll");

/// 确保内嵌 dll 已落地且完好，返回可加载路径。
/// 已存在且哈希一致则直接复用，不做重复写入；文件名带哈希，
/// 升级产生的新版本与旧版本永不互相踩锁。
pub fn ensure_embedded_dll() -> Result<PathBuf, String> {
    let tag = hash_tag(WINTUN_DLL);
    let dir = base_dir()?;
    let target = dir.join(format!("wintun-{tag}.dll"));

    if is_intact(&target, WINTUN_DLL)? {
        reap_old(&dir, &target);
        return Ok(target);
    }

    // 目标存在但损坏/残缺：先删除（被锁就报错，绝不带伤加载）
    if target.exists() {
        std::fs::remove_file(&target)
            .map_err(|e| format!("无法替换损坏的 wintun.dll: {e}"))?;
    }

    // 原子落地：写全临时文件再重命名，中途失败不留半成品
    std::fs::create_dir_all(&dir).map_err(|e| format!("创建目录 {dir:?} 失败: {e}"))?;
    let tmp = dir.join(format!("wintun-{tag}.{}.tmp", std::process::id()));
    std::fs::write(&tmp, WINTUN_DLL).map_err(|e| format!("释放 wintun.dll 失败: {e}"))?;
    std::fs::rename(&tmp, &target).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("wintun.dll 落地失败: {e}")
    })?;

    reap_old(&dir, &target);
    Ok(target)
}

/// 首选机器级 ProgramData（计划任务提权运行时天然可写）；
/// 不可写时退到当前用户 LocalAppData，保证非服务化场景也能自举。
fn base_dir() -> Result<PathBuf, String> {
    if let Ok(programdata) = std::env::var("PROGRAMDATA") {
        let dir = PathBuf::from(programdata).join("IPv8");
        if probe_writable(&dir) {
            return Ok(dir);
        }
    }
    if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
        return Ok(PathBuf::from(local_app_data).join("IPv8"));
    }
    Err("找不到 ProgramData 或 LOCALAPPDATA，无法释放 wintun.dll".to_string())
}

/// 建目录并写删探针，确认目录链真正可写（而非只看是否存在）。
fn probe_writable(dir: &Path) -> bool {
    let probe = dir.join(format!(".write-probe-{}", std::process::id()));
    let result = (|| -> std::io::Result<()> {
        std::fs::create_dir_all(dir)?;
        std::fs::write(&probe, b"x")?;
        std::fs::remove_file(&probe)
    })();
    result.is_ok()
}

/// 磁盘文件长度与 SHA-256 均与内嵌字节一致才算完好。
fn is_intact(path: &Path, expected: &[u8]) -> Result<bool, String> {
    if !path.exists() {
        return Ok(false);
    }
    let on_disk = std::fs::read(path).map_err(|e| format!("读取已释放的 wintun.dll 失败: {e}"))?;
    Ok(on_disk.len() == expected.len()
        && Sha256::digest(&on_disk) == Sha256::digest(expected))
}

/// 内容哈希前 4 字节的十六进制（8 字符），作为文件名的版本标签。
fn hash_tag(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest[..4].iter().map(|b| format!("{b:02x}")).collect()
}

/// 尽力清理旧哈希的 dll；正在被旧进程占用时删除会失败，忽略即可，
/// 下次启动再试——不报错、不影响本次启动。
fn reap_old(dir: &Path, keep: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let is_old_wintun = path.extension().and_then(|x| x.to_str()) == Some("dll")
            && path
                .file_name()
                .and_then(|x| x.to_str())
                .is_some_and(|n| n.starts_with("wintun-"))
            && path != keep;
        if is_old_wintun {
            let _ = std::fs::remove_file(&path);
        }
    }
}
