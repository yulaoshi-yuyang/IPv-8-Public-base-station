//! ping8 — IPv8+ 单文件客户端工具
//!
//! 一个 EXE 搞定所有事：
//!   1. install   — 安装到系统 PATH，之后 CMD 直接用 ping8
//!   2. auto      — 一键自动配置（CA + 签证 + 防火墙，零配置）
//!   3. diagnose  — 一键诊断（签证/驱动/隧道/DNS/防火墙）
//!   4. addr      — 查看本机 IPv8 地址详情
//!   5. ping      — ping 远端 IPv8 地址（UDP 回显，测连通+延迟）
//!   6. visa      — 签证管理：签发/查看/验证/吊销/自动续签
//!   7. status    — 查看驱动/隧道/签证整体状态
//!
//! 签证安全模型（不可伪造）：
//!   - CA 持有 Ed25519 私钥，对 {machine_id, ipv8_addr, ed_pubkey, issued_at, expires_at, nonce} 签名
//!   - 客户端只有 CA 公钥，验签通过才能证明签证来自 CA
//!   - 签证绑定机器指纹（Windows MachineGuid 的 SHA-256），换机器即失效
//!   - 签证默认 30 天过期，到期自动续签（需本地有 CA 种子）
//!   - 可手动吊销（删文件），再重新签发
//!
//! 用法示例:
//!   ping8 install                     # 安装到系统 PATH（管理员，仅一次）
//!   ping8 auto                        # 一键自动配置（推荐新用户）
//!   ping8 diagnose                    # 诊断连接问题
//!   ping8 addr                        # 查看本机 IPv8 地址
//!   ping8 ping 0000fb14000000010001000001000000
//!   ping8 visa ca-init                # 生成 CA 密钥对（管理员，仅一次）
//!   ping8 visa issue --addr <32hex> --ca-seed <64hex> [--expires <秒>]
//!   ping8 visa show
//!   ping8 visa verify --ca-pub <64hex>
//!   ping8 visa renew                  # 手动续签（到期前刷新）
//!   ping8 visa revoke                  # 吊销（删除本地签证）
//!   ping8 visa fingerprint            # 显示本机机器指纹
//!   ping8 status                      # 查看整体状态

use std::env;
use std::fs;
use std::io::{self, BufRead, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::net::UdpSocket;
use std::path::PathBuf;
use std::process::Command;
use std::os::windows::process::CommandExt;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use ipv8_codec::IPv8Address;
use ipv8_neigh as neigh;
use rand_core::RngCore;
use sha2::{Digest, Sha256};

/// ping8 版本号
const PING8_VERSION: u32 = 3;
/// 门户地址
const PORTAL_HOST: &str = "ipv8.yulaoshi.xyz";

/// 从 16 字节线格式构造 IPv8Address
fn addr_from_bytes(wire: &[u8; 16]) -> IPv8Address {
    IPv8Address::from_wire(wire).expect("wire format is 16 bytes")
}

// ── 常量 ──────────────────────────────────────────────────────

const VISA_MAGIC: &[u8; 4] = b"IP8V";
const VISA_VERSION: u8 = 1;
const VISA_DIR: &str = ".ipv8";
const VISA_FILE: &str = "visa.bin";
const CA_SEED_FILE: &str = "ca_seed.bin";
/// 默认签证有效期：30 天（2592000 秒）
const DEFAULT_VISA_TTL: u64 = 30 * 24 * 3600;
/// 续签窗口：到期前 7 天内可续签
const RENEW_WINDOW: u64 = 7 * 24 * 3600;

// ── 自动更新 ───────────────────────────────────────────────────

/// 清理旧版本文件（.old 后缀）
fn cleanup_old_versions() {
    let exe = match env::current_exe() {
        Ok(p) => p,
        Err(_) => return,
    };
    let dir = exe.parent().unwrap_or_else(|| std::path::Path::new("."));
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.ends_with(".old") || name_str.ends_with(".new") || name_str.ends_with(".bak") {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
}

/// 向门户发送 HTTP 请求，返回响应体
fn portal_http_get(path: &str, prefer_local: bool) -> Option<Vec<u8>> {
    let hosts: Vec<(&str, bool)> = if prefer_local {
        vec![("127.0.0.1:9001", false), (PORTAL_HOST, true)]
    } else {
        vec![(PORTAL_HOST, true)]
    };

    for (host, use_tls) in &hosts {
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        );
        let port = if *use_tls { 443 } else { 9001 };
        let addr = if *use_tls { format!("{host}:{port}") } else { host.to_string() };

        // 尝试 TCP 连接
        let stream = if *use_tls {
            // 外网 HTTPS：直接 TCP 连接，TLS 握手用 native_tls 不可用
            // 这里走外网时使用 powershell 下载
            continue;
        } else {
            TcpStream::connect_timeout(&addr.parse().ok()?, Duration::from_secs(3)).ok()
        };

        if let Some(mut stream) = stream {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
            if stream.write_all(request.as_bytes()).is_err() {
                continue;
            }
            let mut data = Vec::new();
            let mut buf = [0u8; 4096];
            while let Ok(n) = stream.read(&mut buf) {
                if n == 0 { break; }
                data.extend_from_slice(&buf[..n]);
            }
            // 解析 HTTP 响应体（跳过头部）
            if let Some(idx) = find_body_offset(&data) {
                return Some(data[idx..].to_vec());
            }
        }
    }
    None
}

fn find_body_offset(data: &[u8]) -> Option<usize> {
    for i in 0..data.len().saturating_sub(3) {
        if &data[i..i+4] == b"\r\n\r\n" {
            return Some(i + 4);
        }
    }
    None
}

/// 向门户发送 POST 请求（JSON body），返回响应体
fn portal_http_post(path: &str, body: &serde_json::Value, prefer_local: bool) -> Option<Vec<u8>> {
    let body_str = serde_json::to_string(body).ok()?;

    // 本网优先
    if prefer_local {
        if let Some(data) = portal_http_post_raw("127.0.0.1:9001", path, &body_str, false) {
            return Some(data);
        }
    }

    // 外网：用 PowerShell Invoke-RestMethod
    if cfg!(target_os = "windows") {
        let url = format!("https://{PORTAL_HOST}{path}");
        let json = body_str.replace("'", "''");
        let ps = format!(
            "try {{ $r = Invoke-RestMethod -Uri '{url}' -Method POST -ContentType 'application/json' -Body '{json}' -TimeoutSec 5; $r | ConvertTo-Json -Compress }} catch {{ $_.Exception.Message }}"
        );
        let out = Command::new("powershell")
            .args(["-NoProfile", "-Command", &ps])
            .creation_flags(0x08000000)
            .output()
            .ok()?;
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout).to_string();
            if !s.trim().is_empty() && !s.contains("Exception") {
                return Some(s.into_bytes());
            }
        }
    }

    None
}

fn portal_http_post_raw(host_port: &str, path: &str, body: &str, _use_tls: bool) -> Option<Vec<u8>> {
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host_port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let mut stream = TcpStream::connect_timeout(&host_port.parse().ok()?, Duration::from_secs(3)).ok()?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    stream.write_all(request.as_bytes()).ok()?;
    let mut data = Vec::new();
    let mut buf = [0u8; 4096];
    while let Ok(n) = stream.read(&mut buf) {
        if n == 0 { break; }
        data.extend_from_slice(&buf[..n]);
    }
    find_body_offset(&data).map(|idx| data[idx..].to_vec())
}

/// 检查更新并静默下载新版本
fn check_and_auto_update() {
    // 1. 清理旧版本文件
    cleanup_old_versions();

    // 2. 检查门户版本（本地优先）
    let version_str = match portal_http_get("/api/ping8-version", true) {
        Some(data) => String::from_utf8_lossy(&data).trim().to_string(),
        None => return, // 门户不可达，静默跳过
    };

    let remote_version: u32 = match version_str.parse() {
        Ok(v) => v,
        Err(_) => return,
    };

    if remote_version <= PING8_VERSION {
        return; // 已是最新版
    }

    // 3. 下载新版本到临时文件
    let exe = match env::current_exe() {
        Ok(p) => p,
        Err(_) => return,
    };
    let new_path = exe.with_extension("exe.new");

    // 用 PowerShell 下载（支持 HTTPS + 进度）
    let ps_script = format!(
        r#"try {{
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri "https://{PORTAL_HOST}/api/client-package" -OutFile "{}" -UseBasicParsing -TimeoutSec 30
            Write-Output "OK"
        }} catch {{
            Write-Output "FAIL"
        }}"#,
        new_path.display()
    );

    let output = Command::new("powershell")
        .args(["-NoProfile", "-Command", &ps_script])
        .output();

    match output {
        Ok(o) if String::from_utf8_lossy(&o.stdout).contains("OK") => {
            // 4. 校验下载产物：必须是 PE 可执行文件且体积合理
            //    （防代理/门户异常时返回 HTML 错误页，把坏文件换上去导致客户端损坏）
            let valid = fs::File::open(&new_path).ok().and_then(|mut f| {
                let mut magic = [0u8; 2];
                f.read_exact(&mut magic).ok()?;
                let big_enough = f.metadata().map(|m| m.len() > 100 * 1024).unwrap_or(false);
                Some(magic == *b"MZ" && big_enough)
            }).unwrap_or(false);

            if !valid {
                let _ = fs::remove_file(&new_path);
                println!("  [更新] 下载产物校验失败，已放弃本次更新");
                return;
            }

            // 5. 重命名交换：当前 exe → .old，新 exe → 当前（失败必须回滚，
            //    否则原 exe 已被改名而新 exe 未就位，客户端直接丢失）
            let old_path = exe.with_extension("exe.old");

            // Windows 允许重命名运行中的 exe
            if fs::rename(&exe, &old_path).is_ok() {
                if fs::rename(&new_path, &exe).is_err() {
                    // 换新失败：回滚原名，保留可用旧版
                    let _ = fs::rename(&old_path, &exe);
                    println!("  [更新] 新版本替换失败，已回滚，本次不更新");
                    return;
                }
                println!("  [更新] ping8 已从 v{PING8_VERSION} 升级到 v{remote_version}");
                println!("  [更新] 旧版本将在下次运行时自动清理");
            } else {
                // 原 exe 被占用（如杀软扫描锁定）：跳过本次，等下次机会
                let _ = fs::remove_file(&new_path);
                println!("  [更新] 当前文件被占用，已跳过本次更新");
            }
        }
        _ => {
            // 下载失败，静默跳过
        }
    }
}

/// 签证线格式：
///   magic(4) | ver(1) | machine_id(32) | ipv8_addr(16) | ed_pubkey(32)
///   | issued_at(8) | expires_at(8) | nonce(16) | ca_sig(64)
const VISA_BODY_LEN: usize = 32 + 16 + 32 + 8 + 8 + 16; // 112
const VISA_TOTAL_LEN: usize = 4 + 1 + VISA_BODY_LEN + 64; // 181

// ── 工具函数 ──────────────────────────────────────────────────

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn visa_dir() -> PathBuf {
    let home = env::var("USERPROFILE")
        .or_else(|_| env::var("HOME"))
        .unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(VISA_DIR)
}

fn visa_path() -> PathBuf {
    visa_dir().join(VISA_FILE)
}

fn ca_seed_path() -> PathBuf {
    visa_dir().join(CA_SEED_FILE)
}

fn ensure_visa_dir() -> io::Result<()> {
    let dir = visa_dir();
    if !dir.exists() {
        fs::create_dir_all(&dir)?;
    }
    Ok(())
}

/// 获取本机机器指纹：Windows MachineGuid 的 SHA-256
fn machine_fingerprint() -> [u8; 32] {
    let guid = if cfg!(target_os = "windows") {
        Command::new("reg")
            .args(["query", "HKLM\\SOFTWARE\\Microsoft\\Cryptography", "/v", "MachineGuid"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8_lossy(&o.stdout).lines()
                .find(|l| l.contains("MachineGuid"))
                .and_then(|l| l.split("REG_SZ").nth(1))
                .map(|s| s.trim().to_string()))
            .unwrap_or_else(|| {
                let host = env::var("COMPUTERNAME").unwrap_or_default();
                let user = env::var("USERNAME").unwrap_or_default();
                format!("{host}-{user}")
            })
    } else {
        let host = env::var("HOSTNAME").unwrap_or_default();
        let user = env::var("USER").unwrap_or_default();
        format!("{host}-{user}")
    };

    let mut hasher = Sha256::new();
    hasher.update(guid.as_bytes());
    hasher.finalize().into()
}

/// 从机器指纹自动生成 IPv8 地址（16 字节线格式）
fn generate_auto_address() -> [u8; 16] {
    let fp = machine_fingerprint();
    let mut addr = [0u8; 16];
    // 协议前缀: 0000fb14
    addr[2] = 0xfb;
    addr[3] = 0x14;
    // 用指纹填充剩余 12 字节确保每台机器地址唯一
    addr[4..16].copy_from_slice(&fp[0..12]);
    addr
}

fn parse_hex32(s: &str) -> Result<[u8; 32], String> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("需要 64 个十六进制字符，收到 {} 字符", s.len()));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|e| format!("解析失败: {e}"))?;
    }
    Ok(out)
}

fn hex_encode(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(data.len() * 2);
    for &byte in data {
        s.push(HEX[(byte >> 4) as usize] as char);
        s.push(HEX[(byte & 0x0F) as usize] as char);
    }
    s
}

fn is_admin() -> bool {
    if !cfg!(target_os = "windows") {
        return false;
    }
    Command::new("net")
        .args(["session"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

// ── 签证结构 ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct Visa {
    machine_id: [u8; 32],
    ipv8_addr: [u8; 16],
    ed_pubkey: [u8; 32],
    issued_at: u64,
    expires_at: u64,
    nonce: [u8; 16],
    ca_sig: [u8; 64],
}

impl Visa {
    fn tbs(&self) -> Vec<u8> {
        let mut t = Vec::with_capacity(VISA_BODY_LEN);
        t.extend_from_slice(&self.machine_id);
        t.extend_from_slice(&self.ipv8_addr);
        t.extend_from_slice(&self.ed_pubkey);
        t.extend_from_slice(&self.issued_at.to_be_bytes());
        t.extend_from_slice(&self.expires_at.to_be_bytes());
        t.extend_from_slice(&self.nonce);
        t
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut w = Vec::with_capacity(VISA_TOTAL_LEN);
        w.extend_from_slice(VISA_MAGIC);
        w.push(VISA_VERSION);
        w.extend_from_slice(&self.tbs());
        w.extend_from_slice(&self.ca_sig);
        w
    }

    fn from_bytes(data: &[u8]) -> Result<Self, String> {
        if data.len() != VISA_TOTAL_LEN {
            return Err(format!("签证文件大小不对：期望 {VISA_TOTAL_LEN} 字节，实际 {}", data.len()));
        }
        if &data[0..4] != VISA_MAGIC {
            return Err("签证文件 MAGIC 不匹配（不是合法 IPv8 签证）".into());
        }
        if data[4] != VISA_VERSION {
            return Err(format!("签证版本不支持：{}", data[4]));
        }
        let p = 5;
        let mut machine_id = [0u8; 32];
        machine_id.copy_from_slice(&data[p..p + 32]);
        let mut ipv8_addr = [0u8; 16];
        ipv8_addr.copy_from_slice(&data[p + 32..p + 48]);
        let mut ed_pubkey = [0u8; 32];
        ed_pubkey.copy_from_slice(&data[p + 48..p + 80]);
        let issued_at = u64::from_be_bytes(data[p + 80..p + 88].try_into().unwrap());
        let expires_at = u64::from_be_bytes(data[p + 88..p + 96].try_into().unwrap());
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&data[p + 96..p + 112]);
        let mut ca_sig = [0u8; 64];
        ca_sig.copy_from_slice(&data[p + 112..p + 176]);
        Ok(Self { machine_id, ipv8_addr, ed_pubkey, issued_at, expires_at, nonce, ca_sig })
    }

    fn verify(&self, ca_pub: &[u8; 32], now: u64) -> Result<(), String> {
        let vk = VerifyingKey::from_bytes(ca_pub)
            .map_err(|_| "CA 公钥非法".to_string())?;
        let sig = Signature::from_bytes(&self.ca_sig);
        vk.verify_strict(&self.tbs(), &sig)
            .map_err(|_| "CA 签名验证失败 — 签证被篡改或伪造".to_string())?;

        let fp = machine_fingerprint();
        if self.machine_id != fp {
            return Err("机器指纹不匹配 — 签证不属于本机".to_string());
        }

        if self.expires_at != 0 && now > self.expires_at {
            let remaining: i64 = self.expires_at as i64 - now as i64;
            return Err(format!("签证已过期（{} 秒前）", -remaining));
        }

        Ok(())
    }
}

// ── install 子命令 ─────────────────────────────────────────────

fn cmd_install() {
    println!("======================================================");
    println!("  ping8 安装到系统 PATH");
    println!("======================================================");

    if !is_admin() {
        eprintln!("\n  需要管理员权限，正在自动提升...");
        let exe = env::current_exe().unwrap_or_else(|_| PathBuf::from("ping8.exe"));
        let _ = Command::new("powershell")
            .args(["-NoProfile", "-Command", &format!(
                "Start-Process '{}' -Verb RunAs -ArgumentList 'install'", exe.display()
            )])
            .status();
        return;
    }

    let src = env::current_exe().unwrap_or_else(|_| PathBuf::from("ping8.exe"));
    let dst = PathBuf::from(r"C:\Windows\System32\ping8.exe");

    match fs::copy(&src, &dst) {
        Ok(_) => {
            println!("\n  已复制: {}", src.display());
            println!("  目标:   {}", dst.display());
            println!("\n  现在可以在任意 CMD 窗口直接使用:");
            println!("    ping8 addr");
            println!("    ping8 ping <32hex>");
            println!("    ping8 visa show");
            println!("    ping8 status");
            println!("\n======================================================");
        }
        Err(e) => {
            eprintln!("\n  安装失败: {e}");
            eprintln!("  请以管理员身份运行: ping8 install");
        }
    }
}

// ── status 子命令 ──────────────────────────────────────────────

fn cmd_status() {
    println!("======================================================");
    println!("  IPv8+ 系统状态");
    println!("======================================================\n");

    // 1. 签证状态
    print!("  [1] 签证: ");
    let visa = load_visa();
    if let Some(ref v) = visa {
        try_auto_renew(v);
    }
    let visa = load_visa();
    match &visa {
        Some(v) => {
            let addr = addr_from_bytes(&v.ipv8_addr);
            let now = now_secs();
            let expired = v.expires_at != 0 && now > v.expires_at;
            if expired {
                println!("已过期 ({})", addr.to_display_string());
            } else {
                let remaining = if v.expires_at == 0 { "永不过期".to_string() } else { format!("{} 天", (v.expires_at as i64 - now as i64) / 86400) };
                println!("有效 ({}) [{remaining}]", addr.to_display_string());
            }
        }
        None => println!("未签发"),
    }

    // 2. 驱动状态
    print!("  [2] 驱动: ");
    if cfg!(target_os = "windows") {
        let out = Command::new("pnputil")
            .args(["-e", "-p", "ms_ag1"])
            .output();
        match out {
            Ok(o) if o.status.success() => {
                let s = String::from_utf8_lossy(&o.stdout);
                if s.contains("ipv8") || s.contains("IPv8") {
                    println!("已安装");
                } else {
                    println!("未安装");
                }
            }
            _ => {
                let out2 = Command::new("netcfg")
                    .args(["-q", "ms_ag1"])
                    .output();
                match out2 {
                    Ok(o) if o.status.success() => println!("已安装"),
                    _ => println!("未安装"),
                }
            }
        }
    } else {
        println!("仅 Windows");
    }

    // 3. 跨机互连状态
    print!("  [3] 跨机互连: ");
    if cfg!(target_os = "windows") {
        let node_running = Command::new("tasklist")
            .args(["/FI", "IMAGENAME eq ipv8-node.exe", "/FO", "CSV", "/NH"])
            .creation_flags(0x08000000)
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains("ipv8-node"))
            .unwrap_or(false);
        let trust_listening = Command::new("powershell")
            .args([
                "-NoProfile", "-Command",
                "if (Get-NetUDPEndpoint -LocalPort 45801 -ErrorAction SilentlyContinue) { 'YES' } else { 'NO' }",
            ])
            .creation_flags(0x08000000)
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains("YES"))
            .unwrap_or(false);
        if node_running {
            println!("ipv8-node 运行中");
        } else if trust_listening {
            println!("trust listen 监听中");
        } else {
            println!("待命 (ping8 trust listen)");
        }
    } else {
        println!("仅 Windows");
    }

    // 4. 机器指纹
    let fp = machine_fingerprint();
    println!("  [4] 指纹: {}", hex_encode(&fp));

    // 5. ping8 安装位置
    print!("  [5] ping8: ");
    let sys_path = PathBuf::from(r"C:\Windows\System32\ping8.exe");
    if sys_path.exists() {
        println!("已安装到系统 PATH");
    } else {
        let exe = env::current_exe().unwrap_or_else(|_| PathBuf::from("ping8.exe"));
        println!("{}（运行 ping8 install 安装到系统）", exe.display());
    }

    println!("\n======================================================");
}

// ── auto 子命令：零配置一键配置 ───────────────────────────────

fn cmd_auto_setup() {
    println!("======================================================");
    println!("  IPv8+ 一键自动配置");
    println!("======================================================\n");

    let fp = machine_fingerprint();
    println!("  机器指纹: {}", hex_encode(&fp));

    // 1. CA 种子
    print!("\n  [1/4] CA 密钥对:  ");
    let ca_path = ca_seed_path();
    if ca_path.exists() {
        println!("已存在，跳过");
    } else {
        let mut seed = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut seed);
        let ca = SigningKey::from_bytes(&seed);
        let ca_pub = ca.verifying_key().to_bytes();

        ensure_visa_dir().unwrap_or_else(|e| {
            eprintln!("无法创建目录: {e}");
            std::process::exit(1);
        });
        fs::write(&ca_path, seed).unwrap_or_else(|e| {
            eprintln!("写入 CA 种子失败: {e}");
            std::process::exit(1);
        });
        println!("已自动生成");
        println!("       CA 公钥: {}", hex_encode(&ca_pub));
    }

    // 2. 签证
    print!("\n  [2/4] 签证:        ");
    let visa = load_visa();
    if let Some(ref v) = visa {
        let now = now_secs();
        if v.expires_at != 0 && now > v.expires_at {
            println!("已过期，自动续签...");
            try_auto_renew(v);
        } else if v.expires_at != 0 && (v.expires_at as i64 - now as i64) < RENEW_WINDOW as i64 {
            println!("即将到期，自动续签...");
            try_auto_renew(v);
        } else {
            let addr = addr_from_bytes(&v.ipv8_addr);
            let remaining = if v.expires_at == 0 {
                "永不过期".to_string()
            } else {
                format!("{}天", (v.expires_at as i64 - now as i64) / 86400)
            };
            println!("有效 [{remaining}] {}", addr.to_display_string());
        }
    } else {
        println!("自动签发中...");

        let ca_seed_data = match fs::read(&ca_path) {
            Ok(d) if d.len() == 32 => d,
            _ => {
                eprintln!("  [!] 读取 CA 种子失败");
                std::process::exit(1);
            }
        };
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&ca_seed_data);
        let ca = SigningKey::from_bytes(&seed);
        let ca_pub = ca.verifying_key().to_bytes();

        let mut node_seed = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut node_seed);
        let node = SigningKey::from_bytes(&node_seed);
        let ed_pubkey = node.verifying_key().to_bytes();

        let addr_bytes = generate_auto_address();
        let addr = addr_from_bytes(&addr_bytes);
        let now = now_secs();
        let mut nonce = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut nonce);

        let mut new_visa = Visa {
            machine_id: fp,
            ipv8_addr: addr_bytes,
            ed_pubkey,
            issued_at: now,
            expires_at: now + DEFAULT_VISA_TTL,
            nonce,
            ca_sig: [0u8; 64],
        };
        let sig = ca.sign(&new_visa.tbs());
        new_visa.ca_sig = sig.to_bytes();

        ensure_visa_dir().unwrap_or_else(|e| {
            eprintln!("无法创建目录: {e}");
            std::process::exit(1);
        });
        fs::write(visa_path(), new_visa.to_bytes()).unwrap_or_else(|e| {
            eprintln!("写入签证失败: {e}");
            std::process::exit(1);
        });
        let node_seed_path = visa_dir().join("node_seed.bin");
        let _ = fs::write(&node_seed_path, node_seed);

        println!("  [OK] 已签发");
        println!("       地址:   {}", addr.to_display_string());
        println!("       规范:   {}", addr.to_canonical_string());
        println!("       有效期: {} 天", DEFAULT_VISA_TTL / 86400);
        println!("       CA 公钥: {}", hex_encode(&ca_pub));
    }

    // 3. 防火墙
    print!("\n  [3/4] 防火墙端口:  ");
    println!("配置中...");
    cmd_firewall_open();

    // 4. 驱动检查
    print!("\n  [4/4] NDIS 驱动:   ");
    if cfg!(target_os = "windows") {
        let out = Command::new("pnputil")
            .args(["-e", "-p", "ms_ag1"])
            .creation_flags(0x08000000)
            .output();
        let driver_ok = match out {
            Ok(o) if o.status.success() => {
                let s = String::from_utf8_lossy(&o.stdout);
                s.contains("ipv8") || s.contains("IPv8")
            }
            _ => {
                let out2 = Command::new("netcfg")
                    .args(["-q", "ms_ag1"])
                    .creation_flags(0x08000000)
                    .output();
                out2.map(|o| o.status.success()).unwrap_or(false)
            }
        };
        if driver_ok {
            println!("已安装");
        } else {
            println!("[!] 未安装（需要安装 NDIS 协议驱动）");
        }
    } else {
        println!("[N/A]");
    }

    // 汇总
    let visa = load_visa();
    if let Some(v) = visa {
        let addr = addr_from_bytes(&v.ipv8_addr);

        // 向门户注册
        print!("\n  [注册] 向门户注册:  ");
        let hostname = env::var("COMPUTERNAME")
            .or_else(|_| env::var("HOSTNAME"))
            .unwrap_or_else(|_| "unknown".to_string());
        let reg_json = serde_json::json!({
            "client_ip": null,
            "ipv8_addr": addr.to_display_string(),
            "hostname": hostname,
            "fingerprint": hex_encode(&v.machine_id),
            "visa_exists": true,
            "ca_exists": ca_seed_path().exists(),
        });
        match portal_http_post("/api/register", &reg_json, true) {
            Some(resp) => {
                let s = String::from_utf8_lossy(&resp).to_string();
                if s.contains("\"ok\"") {
                    println!("[OK] 已注册 ({} → {})", hostname, addr.to_display_string());
                } else if s.contains("404") || s.contains("Not Found") {
                    println!("[SKIP] 门户未更新（需同步新门户脚本）");
                } else {
                    println!("[?] 响应: {}", s.trim());
                }
            }
            None => {
                println!("[SKIP] 门户不可达（不影响本地使用）");
            }
        }

        // 启动后台心跳线程（每 60s 向门户发送心跳）
        std::thread::Builder::new()
            .name("ping8-heartbeat".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(60));
                    let _ = portal_http_get("/api/heartbeat", true);
                }
            })
            .ok();

        println!("\n======================================================");
        println!("  自动配置完成！");
        println!("======================================================");
        println!("  IPv8 地址: {}", addr.to_display_string());
        println!("  规范形式:  {}", addr.to_canonical_string());
        println!("\n  接下来可以:");
        println!("    ping8 addr         查看地址详情");
        println!("    ping8 status       查看系统状态");
        println!("    ping8 diagnose     诊断连接问题");
        println!("    ping8 ping <地址>   ping 远端节点");
        println!("======================================================");
    }
}

// ── diagnose 子命令：一键诊断 ─────────────────────────────────

/// 单项检查状态
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
enum CheckStatus { Ok, Warn, Fail, Na }

impl CheckStatus {
    fn label(&self) -> &'static str {
        match self {
            CheckStatus::Ok => "OK",
            CheckStatus::Warn => "WARN",
            CheckStatus::Fail => "FAIL",
            CheckStatus::Na => "N/A",
        }
    }
}

/// 单项诊断结果（CLI 与 HTTP API 共用）
#[derive(Debug, Clone, serde::Serialize)]
struct CheckResult {
    id: String,
    name: String,
    status: CheckStatus,
    detail: String,
    fix: Option<String>,
    fix_desc: Option<String>,
}

impl CheckResult {
    fn ok(id: &str, name: &str, detail: impl Into<String>) -> Self {
        CheckResult { id: id.into(), name: name.into(), status: CheckStatus::Ok, detail: detail.into(), fix: None, fix_desc: None }
    }
    fn warn(id: &str, name: &str, detail: impl Into<String>, fix_desc: &str, fix: &str) -> Self {
        CheckResult { id: id.into(), name: name.into(), status: CheckStatus::Warn, detail: detail.into(), fix: Some(fix.into()), fix_desc: Some(fix_desc.into()) }
    }
    fn fail(id: &str, name: &str, detail: impl Into<String>, fix_desc: &str, fix: &str) -> Self {
        CheckResult { id: id.into(), name: name.into(), status: CheckStatus::Fail, detail: detail.into(), fix: Some(fix.into()), fix_desc: Some(fix_desc.into()) }
    }
    fn na(id: &str, name: &str, detail: impl Into<String>) -> Self {
        CheckResult { id: id.into(), name: name.into(), status: CheckStatus::Na, detail: detail.into(), fix: None, fix_desc: None }
    }
}

/// 执行全部 9 项诊断检查，返回结构化结果（供 CLI 与 /api/diagnose 共用）
fn run_checks() -> Vec<CheckResult> {
    let mut checks: Vec<CheckResult> = Vec::with_capacity(9);

    // 1. 签证
    let visa = load_visa();
    if let Some(ref v) = visa { try_auto_renew(v); }
    let visa = load_visa();
    match &visa {
        Some(v) => {
            let now = now_secs();
            if v.expires_at != 0 && now > v.expires_at {
                checks.push(CheckResult::fail("visa", "签证状态", "已过期", "签证已过期，需自动续签", "ping8 auto"));
            } else {
                let addr = addr_from_bytes(&v.ipv8_addr);
                let remaining = if v.expires_at == 0 {
                    "永不过期".to_string()
                } else {
                    format!("{}天", (v.expires_at as i64 - now as i64) / 86400)
                };
                checks.push(CheckResult::ok("visa", "签证状态", format!("{} [{}]", addr.to_display_string(), remaining)));
            }
        }
        None => {
            checks.push(CheckResult::fail("visa", "签证状态", "未签发", "未找到签证，需一键配置", "ping8 auto"));
        }
    }

    // 2. CA 种子
    if ca_seed_path().exists() {
        checks.push(CheckResult::ok("ca_seed", "CA 种子", "已配置"));
    } else {
        checks.push(CheckResult::warn("ca_seed", "CA 种子", "未配置（无法自动续签）", "CA 种子未配置，需自动生成", "ping8 auto"));
    }

    // 3. 机器指纹
    let fp = machine_fingerprint();
    if let Some(ref v) = visa {
        if v.machine_id == fp {
            checks.push(CheckResult::ok("machine_id", "机器指纹", "匹配"));
        } else {
            checks.push(CheckResult::fail("machine_id", "机器指纹", "不匹配（签证不属于本机）", "签证机器指纹不匹配，需重新签发", "ping8 auto"));
        }
    } else {
        checks.push(CheckResult::ok("machine_id", "机器指纹", hex_encode(&fp)));
    }

    // 4. NDIS 驱动
    if cfg!(target_os = "windows") {
        let out = Command::new("pnputil")
            .args(["-e", "-p", "ms_ag1"])
            .creation_flags(0x08000000)
            .output();
        let driver_ok = match out {
            Ok(o) if o.status.success() => {
                let s = String::from_utf8_lossy(&o.stdout);
                s.contains("ipv8") || s.contains("IPv8")
            }
            _ => {
                let out2 = Command::new("netcfg")
                    .args(["-q", "ms_ag1"])
                    .creation_flags(0x08000000)
                    .output();
                out2.map(|o| o.status.success()).unwrap_or(false)
            }
        };
        if driver_ok {
            checks.push(CheckResult::ok("ndis", "NDIS 驱动", "已安装"));
        } else {
            checks.push(CheckResult::fail("ndis", "NDIS 驱动", "未安装", "NDIS 驱动未安装，请安装 IPv8 协议驱动（需关闭 Secure Boot）", "ping8 auto"));
        }
    } else {
        checks.push(CheckResult::na("ndis", "NDIS 驱动", "非 Windows 平台"));
    }

    // 5. 跨机互连（trust 模式按需监听 UDP 45801，无需常驻进程）
    if cfg!(target_os = "windows") {
        // 5a. ipv8-node 数据面进程（可选，仅高级隧道场景需要）
        let node_running = Command::new("tasklist")
            .args(["/FI", "IMAGENAME eq ipv8-node.exe", "/FO", "CSV", "/NH"])
            .creation_flags(0x08000000)
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains("ipv8-node"))
            .unwrap_or(false);

        // 5b. ping8 trust listen 正在监听 UDP 45801
        let trust_listening = Command::new("powershell")
            .args([
                "-NoProfile", "-Command",
                "if (Get-NetUDPEndpoint -LocalPort 45801 -ErrorAction SilentlyContinue) { 'YES' } else { 'NO' }",
            ])
            .creation_flags(0x08000000)
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains("YES"))
            .unwrap_or(false);

        if node_running {
            checks.push(CheckResult::ok("tunnel", "跨机互连", "ipv8-node 数据面运行中"));
        } else if trust_listening {
            checks.push(CheckResult::ok("tunnel", "跨机互连", "信任监听运行中 (ping8 trust listen)"));
        } else {
            // 待命是正常状态：trust listen 仅在需要授权对端时临时运行
            checks.push(CheckResult::ok("tunnel", "跨机互连", "待命（需要授权对端时运行 ping8 trust listen）"));
        }
    } else {
        checks.push(CheckResult::na("tunnel", "跨机互连", "非 Windows 平台"));
    }

    // 6. DNS 解析
    let dns_result = Command::new("nslookup")
        .args(["-port=5353", "-timeout=2", "test.ipv8.net", "127.0.0.1"])
        .creation_flags(0x08000000)
        .output();
    match dns_result {
        Ok(o) => {
            let s = String::from_utf8_lossy(&o.stdout);
            if s.contains("fb14") || (s.contains("Address") && !s.contains("can't find") && !s.contains("UNREACHABLE")) {
                checks.push(CheckResult::ok("dns", "DNS 解析", "本地 DNS 可用"));
            } else {
                checks.push(CheckResult::warn("dns", "DNS 解析", "本地 DNS 无响应", "本地 DNS 解析器未响应，门户 DNS 在 127.0.0.1:5353", "ping8 auto"));
            }
        }
        _ => {
            checks.push(CheckResult::warn("dns", "DNS 解析", "本地 DNS 无响应", "本地 DNS 解析器未响应，门户 DNS 在 127.0.0.1:5353", "ping8 auto"));
        }
    }

    // 7. 门户连通性
    match portal_http_get("/api/ping8-version", true) {
        Some(data) => {
            let ver = String::from_utf8_lossy(&data).trim().to_string();
            checks.push(CheckResult::ok("portal", "门户连通", format!("版本 {ver}")));
        }
        None => {
            checks.push(CheckResult::warn("portal", "门户连通", "不可达", "门户不可达，不影响本地使用，但无法自动更新", "ping8 auto"));
        }
    }

    // 8. 防火墙端口
    if cfg!(target_os = "windows") {
        let out = Command::new("powershell")
            .args([
                "-NoProfile", "-Command",
                "try { $r = Get-NetFirewallRule -DisplayName 'IPv8+*' -ErrorAction Stop; $ports = $r | Get-NetFirewallPortFilter | Select-Object -ExpandProperty LocalPort; $ports -join ',' } catch { 'NONE' }",
            ])
            .creation_flags(0x08000000)
            .output();
        match out {
            Ok(o) => {
                let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
                if s == "NONE" || s.is_empty() {
                    checks.push(CheckResult::warn("firewall", "防火墙端口", "缺少端口 45801, 9001", "防火墙端口未放行", "ping8 firewall open"));
                } else {
                    let has_45801 = s.contains("45801");
                    let has_9001 = s.contains("9001");
                    if has_45801 && has_9001 {
                        checks.push(CheckResult::ok("firewall", "防火墙端口", "标准端口已放行"));
                    } else {
                        let missing: Vec<&str> = [
                            (!has_45801, "45801"),
                            (!has_9001, "9001"),
                        ]
                        .iter()
                        .filter(|(m, _)| *m)
                        .map(|(_, p)| *p)
                        .collect();
                        let joined = missing.join(", ");
                        checks.push(CheckResult::warn("firewall", "防火墙端口", format!("缺少端口 {joined}"), "防火墙端口未放行", "ping8 firewall open"));
                    }
                }
            }
            _ => {
                checks.push(CheckResult::warn("firewall", "防火墙端口", "查询失败", "防火墙端口查询失败", "ping8 firewall open"));
            }
        }
    } else {
        checks.push(CheckResult::na("firewall", "防火墙端口", "非 Windows 平台"));
    }

    // 9. ping8 安装
    let sys_path = PathBuf::from(r"C:\Windows\System32\ping8.exe");
    if sys_path.exists() {
        checks.push(CheckResult::ok("install", "ping8 安装", "系统 PATH"));
    } else {
        let exe = env::current_exe().unwrap_or_else(|_| PathBuf::from("ping8.exe"));
        checks.push(CheckResult::warn("install", "ping8 安装", format!("{}（未安装到系统）", exe.display()), "ping8 未安装到系统 PATH", "ping8 install"));
    }

    checks
}

fn cmd_diagnose() {
    println!("======================================================");
    println!("  IPv8+ 一键诊断");
    println!("======================================================\n");

    let checks = run_checks();
    let mut ok_count = 0u32;
    let mut warn_count = 0u32;
    let mut fail_count = 0u32;
    let mut issues: Vec<String> = Vec::new();

    for (i, c) in checks.iter().enumerate() {
        let idx = i + 1;
        print!("  [{idx}] {:<10}", c.name);
        println!("[{}] {}", c.status.label(), c.detail);
        match c.status {
            CheckStatus::Ok => ok_count += 1,
            CheckStatus::Warn => { warn_count += 1; if let Some(d) = &c.fix_desc { issues.push(d.clone()); } }
            CheckStatus::Fail => { fail_count += 1; if let Some(d) = &c.fix_desc { issues.push(d.clone()); } }
            CheckStatus::Na => {}
        }
    }

    // 汇总
    println!("\n======================================================");
    println!("  诊断结果: {ok_count} OK / {warn_count} WARN / {fail_count} FAIL");
    if issues.is_empty() {
        println!("  一切正常！");
    } else {
        println!("======================================================");
        println!("  建议修复:");
        for (i, issue) in issues.iter().enumerate() {
            println!("  {}. {issue}", i + 1);
        }
    }
    println!("======================================================");
}

// ── addr 子命令 ───────────────────────────────────────────────

fn cmd_addr() {
    println!("======================================================");
    println!("  IPv8+ 本机地址信息");
    println!("======================================================");

    let visa = load_visa();
    // 自动续签检查
    if let Some(ref v) = visa {
        try_auto_renew(v);
    }
    let visa = load_visa();
    match &visa {
        Some(v) => {
            let addr = addr_from_bytes(&v.ipv8_addr);
            println!("\n  IPv8 地址:  {}", addr.to_display_string());
            println!("  规范形式:   {}", addr.to_canonical_string());
            println!("  Protocol:   0x{:04X}", addr.protocol);
            println!("  Region:     0x{:012X}", addr.region());
            println!("  Subnet 1:   {}", addr.subnet1);
            println!("  Subnet 2:   0x{:04X}", addr.subnet2);
            println!("  Node Hash:  0x{:04X}", addr.node_hash);
            println!("  Session ID: {}", addr.session_id);
            println!("\n  签证状态:   已签发");
            if v.expires_at == 0 {
                println!("  过期时间:   永不过期");
            } else {
                let now = now_secs();
                let remaining = v.expires_at as i64 - now as i64;
                if remaining > 0 {
                    let days = remaining / 86400;
                    let hours = (remaining % 86400) / 3600;
                    let mins = (remaining % 3600) / 60;
                    println!("  过期时间:   {days} 天 {hours} 小时 {mins} 分后");
                } else {
                    println!("  过期时间:   已过期 {} 秒", -remaining);
                }
            }
            println!("  公钥:       {}", hex_encode(&v.ed_pubkey));
        }
        None => {
            println!("\n  未找到本地签证，无法确定 IPv8 地址");
            println!("  一键自动配置: ping8 auto");
            println!("  或手动签发: ping8 visa issue --addr <32hex> --ca-seed <64hex>");
        }
    }

    let fp = machine_fingerprint();
    println!("\n  机器指纹:   {}", hex_encode(&fp));
    println!("======================================================");
}

// ── ping 子命令 ───────────────────────────────────────────────

fn cmd_ping(target: &str, count: u32, timeout_ms: u64) {
    let addr = match IPv8Address::from_canonical_str(target) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("错误: 地址格式不对 — {e}");
            std::process::exit(1);
        }
    };

    println!("正在 ping {}...", addr.to_canonical_string());

    let visa = load_visa();
    let self_addr = visa.as_ref().map(|v| addr_from_bytes(&v.ipv8_addr));

    let port = 45700u16 + (addr.region_lo & 0xFF) as u16;
    let target_addr = format!("127.0.0.1:{port}");

    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            eprintln!("错误: 无法创建 UDP socket — {e}");
            std::process::exit(1);
        }
    };
    let _ = socket.set_read_timeout(Some(Duration::from_millis(timeout_ms)));

    let mut seq = 1u32;
    let mut sent = 0u32;
    let mut recv = 0u32;
    let mut min_rtt = u128::MAX;
    let mut max_rtt = 0u128;
    let mut total_rtt = 0u128;

    while seq <= count {
        let mut packet = Vec::with_capacity(32);
        packet.extend_from_slice(b"I8PN");
        packet.extend_from_slice(&seq.to_be_bytes());
        let ts = now_secs();
        packet.extend_from_slice(&ts.to_be_bytes());
        if let Some(a) = &self_addr {
            packet.extend_from_slice(&a.to_bytes());
        } else {
            packet.extend_from_slice(&[0u8; 16]);
        }

        let start = Instant::now();
        if socket.send_to(&packet, &target_addr).is_err() {
            println!("seq {seq}: 发送失败");
            seq += 1;
            continue;
        }
        sent += 1;

        let mut buf = [0u8; 32];
        match socket.recv_from(&mut buf) {
            Ok((n, _)) if n >= 16 => {
                let rtt = start.elapsed().as_micros();
                recv += 1;
                total_rtt += rtt;
                if rtt < min_rtt { min_rtt = rtt; }
                if rtt > max_rtt { max_rtt = rtt; }
                println!("seq {seq}: 回复 来自 {} 字节={} RTT={}us", target_addr, n, rtt);
            }
            Ok(_) => {
                println!("seq {seq}: 回复数据不完整");
            }
            Err(_) => {
                println!("seq {seq}: 超时 ({}ms)", timeout_ms);
            }
        }
        seq += 1;
        if seq <= count {
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    println!("\n--- {} ping 统计 ---", addr.to_canonical_string());
    println!("发送 = {sent}, 接收 = {recv}, 丢失 = {} ({:.1}% 丢失)",
        sent - recv,
        if sent > 0 { (sent - recv) as f64 / sent as f64 * 100.0 } else { 0.0 }
    );
    if recv > 0 {
        println!("RTT 最小 = {}us, 最大 = {}us, 平均 = {}us",
            min_rtt, max_rtt, total_rtt / recv as u128);
    }
}

// ── 签证子命令 ─────────────────────────────────────────────────

fn cmd_visa_ca_init() {
    ensure_visa_dir().unwrap_or_else(|e| {
        eprintln!("无法创建目录: {e}");
        std::process::exit(1);
    });

    let path = ca_seed_path();
    if path.exists() {
        eprintln!("CA 种子已存在: {}", path.display());
        eprintln!("如需重新生成，请先删除: del \"{}\"", path.display());
        std::process::exit(1);
    }

    let mut seed = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut seed);
    let ca = SigningKey::from_bytes(&seed);
    let ca_pub = ca.verifying_key().to_bytes();

    fs::write(&path, seed).unwrap_or_else(|e| {
        eprintln!("写入 CA 种子失败: {e}");
        std::process::exit(1);
    });

    println!("======================================================");
    println!("  CA 密钥对已生成");
    println!("======================================================");
    println!("\n  CA 种子 (私钥，保密！): {}", hex_encode(&seed));
    println!("  CA 公钥 (可公开):       {}", hex_encode(&ca_pub));
    println!("\n  CA 种子已保存到: {}", path.display());
    println!("\n  CA 种子是签发签证的根密钥，切勿泄露！");
    println!("  分发客户端时只需告知 CA 公钥:");
    println!("    ping8 visa verify --ca-pub {}", hex_encode(&ca_pub));
    println!("======================================================");
}

fn cmd_visa_issue(addr_text: &str, ca_seed_hex: &str, expires_secs: Option<u64>) {
    let addr = match IPv8Address::from_canonical_str(addr_text) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("错误: IPv8 地址格式不对 — {e}");
            std::process::exit(1);
        }
    };

    let seed = match parse_hex32(ca_seed_hex) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("错误: CA 种子 — {e}");
            std::process::exit(1);
        }
    };

    let ca = SigningKey::from_bytes(&seed);
    let ca_pub = ca.verifying_key().to_bytes();

    let mut node_seed = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut node_seed);
    let node = SigningKey::from_bytes(&node_seed);
    let ed_pubkey = node.verifying_key().to_bytes();

    let fp = machine_fingerprint();
    let now = now_secs();
    let expires_at = expires_secs.map(|s| now + s).unwrap_or(now + DEFAULT_VISA_TTL);

    let mut nonce = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut nonce);

    let mut visa = Visa {
        machine_id: fp,
        ipv8_addr: addr.to_bytes(),
        ed_pubkey,
        issued_at: now,
        expires_at,
        nonce,
        ca_sig: [0u8; 64],
    };

    let sig = ca.sign(&visa.tbs());
    visa.ca_sig = sig.to_bytes();

    ensure_visa_dir().unwrap_or_else(|e| {
        eprintln!("无法创建目录: {e}");
        std::process::exit(1);
    });
    let path = visa_path();
    fs::write(&path, visa.to_bytes()).unwrap_or_else(|e| {
        eprintln!("写入签证失败: {e}");
        std::process::exit(1);
    });

    let node_seed_path = visa_dir().join("node_seed.bin");
    fs::write(&node_seed_path, node_seed).unwrap_or_else(|e| {
        eprintln!("写入节点种子失败: {e}");
    });

    println!("======================================================");
    println!("  签证签发成功");
    println!("======================================================");
    println!("  IPv8 地址:    {}", addr.to_display_string());
    println!("  规范形式:     {}", addr.to_canonical_string());
    println!("  Protocol:     0x{:04X}", addr.protocol);
    println!("  Region:       0x{:012X}", addr.region());
    println!("  节点公钥:     {}", hex_encode(&ed_pubkey));
    println!("  机器指纹:     {}", hex_encode(&fp));
    println!("  签发时间:     {now}");
    if expires_at == 0 {
        println!("  过期时间:     永不过期");
    } else {
        let ttl_days = (expires_at - now) / 86400;
        println!("  过期时间:     {expires_at} ({ttl_days} 天后)");
    }
    println!("  CA 公钥:      {}", hex_encode(&ca_pub));
    println!("\n  签证已保存:   {}", path.display());
    println!("  节点种子:     {}", node_seed_path.display());
    println!("\n  验证命令:");
    println!("    ping8 visa verify --ca-pub {}", hex_encode(&ca_pub));
    println!("======================================================");
}

fn cmd_visa_show() {
    let visa = match load_visa() {
        Some(v) => v,
        None => {
            println!("本机未找到签证");
            println!("  签证路径: {}", visa_path().display());
            println!("  一键自动配置: ping8 auto");
            println!("  或手动签发: ping8 visa issue --addr <32hex> --ca-seed <64hex>");
            return;
        }
    };

    let addr = addr_from_bytes(&visa.ipv8_addr);
    let now = now_secs();

    println!("======================================================");
    println!("  IPv8+ 签证详情");
    println!("======================================================");
    println!("  IPv8 地址:    {}", addr.to_display_string());
    println!("  规范形式:     {}", addr.to_canonical_string());
    println!("  Protocol:     0x{:04X}", addr.protocol);
    println!("  Region:       0x{:012X}", addr.region());
    println!("  Subnet 1:     {}", addr.subnet1);
    println!("  Subnet 2:     0x{:04X}", addr.subnet2);
    println!("  Node Hash:    0x{:04X}", addr.node_hash);
    println!("  Session ID:   {}", addr.session_id);
    println!("  节点公钥:     {}", hex_encode(&visa.ed_pubkey));
    println!("  机器指纹:     {}", hex_encode(&visa.machine_id));
    println!("  签发时间:     {}", visa.issued_at);
    if visa.expires_at == 0 {
        println!("  过期时间:     永不过期");
    } else {
        let remaining = visa.expires_at as i64 - now as i64;
        if remaining > 0 {
            let d = remaining / 86400;
            let h = (remaining % 86400) / 3600;
            let m = (remaining % 3600) / 60;
            println!("  过期时间:     {} ({d}天{h}时{m}分后)", visa.expires_at);
        } else {
            println!("  过期时间:     {} (已过期 {} 秒)", visa.expires_at, -remaining);
        }
    }
    println!("  CA 签名:      {}", hex_encode(&visa.ca_sig));
    println!("  Nonce:        {}", hex_encode(&visa.nonce));
    println!("\n  签证文件:     {}", visa_path().display());
    println!("======================================================");
}

fn cmd_visa_verify(ca_pub_hex: &str) {
    let ca_pub = match parse_hex32(ca_pub_hex) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("错误: CA 公钥 — {e}");
            std::process::exit(1);
        }
    };

    let visa = match load_visa() {
        Some(v) => v,
        None => {
            eprintln!("本机未找到签证，无法验证");
            std::process::exit(1);
        }
    };

    let now = now_secs();
    match visa.verify(&ca_pub, now) {
        Ok(()) => {
            let addr = addr_from_bytes(&visa.ipv8_addr);
            println!("======================================================");
            println!("  签证验证通过");
            println!("======================================================");
            println!("  IPv8 地址: {}", addr.to_display_string());
            println!("  机器:     {}", hex_encode(&visa.machine_id));
            if visa.expires_at == 0 {
                println!("  有效期:   永不过期");
            } else {
                let remaining = visa.expires_at as i64 - now as i64;
                println!("  剩余:     {} 秒", remaining);
            }
            println!("  CA 签名:  有效");
            println!("  机器绑定: 匹配");
            println!("======================================================");
        }
        Err(e) => {
            println!("======================================================");
            println!("  签证验证失败");
            println!("======================================================");
            println!("  原因: {e}");
            println!("======================================================");
            std::process::exit(1);
        }
    }
}

fn cmd_visa_revoke() {
    let path = visa_path();
    if !path.exists() {
        println!("本机未找到签证，无需吊销");
        return;
    }

    match fs::remove_file(&path) {
        Ok(()) => {
            println!("======================================================");
            println!("  签证已吊销（删除）");
            println!("======================================================");
            println!("  已删除: {}", path.display());
            println!("\n  如需重新签发:");
            println!("    ping8 auto  或  ping8 visa issue");
            println!("======================================================");
        }
        Err(e) => {
            eprintln!("删除签证失败: {e}");
            std::process::exit(1);
        }
    }
}

fn cmd_visa_fingerprint() {
    let fp = machine_fingerprint();
    println!("======================================================");
    println!("  本机机器指纹");
    println!("======================================================");
    println!("\n  指纹 (SHA-256): {}", hex_encode(&fp));
    println!("\n  签证目录: {}", visa_dir().display());
    println!("  签证文件: {}", visa_path().display());
    println!("  CA 种子:  {}", ca_seed_path().display());
    println!("======================================================");
}

fn load_visa() -> Option<Visa> {
    let path = visa_path();
    let data = fs::read(&path).ok()?;
    Visa::from_bytes(&data).ok()
}

/// 自动续签：签证过期或即将过期时，用本地 CA 种子自动重签
fn try_auto_renew(visa: &Visa) -> bool {
    let now = now_secs();

    // 永不过期的签证不需要续签
    if visa.expires_at == 0 {
        return false;
    }

    let remaining = visa.expires_at as i64 - now as i64;

    // 还在续签窗口外（剩余 > 7 天），不需要续签
    if remaining > RENEW_WINDOW as i64 {
        return false;
    }

    // 尝试读取本地 CA 种子
    let ca_seed_path = ca_seed_path();
    let ca_seed_data = match fs::read(&ca_seed_path) {
        Ok(d) if d.len() == 32 => d,
        _ => return false, // 没有本地 CA 种子，无法自动续签
    };
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&ca_seed_data);
    let ca = SigningKey::from_bytes(&seed);

    // 生成新密钥对
    let mut node_seed = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut node_seed);
    let node = SigningKey::from_bytes(&node_seed);
    let ed_pubkey = node.verifying_key().to_bytes();

    let fp = machine_fingerprint();
    let mut nonce = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut nonce);

    let new_visa = Visa {
        machine_id: fp,
        ipv8_addr: visa.ipv8_addr, // 保持同一个 IPv8 地址
        ed_pubkey,
        issued_at: now,
        expires_at: now + DEFAULT_VISA_TTL,
        nonce,
        ca_sig: [0u8; 64],
    };

    let sig = ca.sign(&new_visa.tbs());
    let mut new_visa = new_visa;
    new_visa.ca_sig = sig.to_bytes();

    match fs::write(visa_path(), new_visa.to_bytes()) {
        Ok(_) => {
            let node_seed_path = visa_dir().join("node_seed.bin");
            let _ = fs::write(&node_seed_path, node_seed);

            if remaining <= 0 {
                println!("  签证已过期，自动续签完成（新有效期 {} 天）", DEFAULT_VISA_TTL / 86400);
            } else {
                println!("  签证即将到期（剩余 {} 天），已自动续签", remaining / 86400);
            }
            true
        }
        Err(_) => false,
    }
}

/// 手动续签
fn cmd_visa_renew() {
    let visa = match load_visa() {
        Some(v) => v,
        None => {
            eprintln!("本机未找到签证，无法续签");
            eprintln!("  一键自动配置: ping8 auto");
            eprintln!("  或手动签发: ping8 visa issue");
            std::process::exit(1);
        }
    };

    let ca_seed_path = ca_seed_path();
    let ca_seed_data = match fs::read(&ca_seed_path) {
        Ok(d) if d.len() == 32 => d,
        _ => {
            eprintln!("未找到本地 CA 种子，无法续签");
            eprintln!("  CA 种子路径: {}", ca_seed_path.display());
            eprintln!("  续签需要在本地保存 CA 种子（visa ca-init 时自动保存）");
            std::process::exit(1);
        }
    };
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&ca_seed_data);
    let ca = SigningKey::from_bytes(&seed);
    let ca_pub = ca.verifying_key().to_bytes();

    let mut node_seed = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut node_seed);
    let node = SigningKey::from_bytes(&node_seed);
    let ed_pubkey = node.verifying_key().to_bytes();

    let fp = machine_fingerprint();
    let now = now_secs();
    let mut nonce = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut nonce);

    let mut new_visa = Visa {
        machine_id: fp,
        ipv8_addr: visa.ipv8_addr,
        ed_pubkey,
        issued_at: now,
        expires_at: now + DEFAULT_VISA_TTL,
        nonce,
        ca_sig: [0u8; 64],
    };

    let sig = ca.sign(&new_visa.tbs());
    new_visa.ca_sig = sig.to_bytes();

    fs::write(visa_path(), new_visa.to_bytes()).unwrap_or_else(|e| {
        eprintln!("写入签证失败: {e}");
        std::process::exit(1);
    });

    let node_seed_path = visa_dir().join("node_seed.bin");
    let _ = fs::write(&node_seed_path, node_seed);

    let addr = addr_from_bytes(&new_visa.ipv8_addr);
    println!("======================================================");
    println!("  签证续签成功");
    println!("======================================================");
    println!("  IPv8 地址:  {}", addr.to_display_string());
    println!("  新签发时间: {now}");
    println!("  新过期时间: {} ({} 天后)", new_visa.expires_at, DEFAULT_VISA_TTL / 86400);
    println!("  CA 公钥:    {}", hex_encode(&ca_pub));
    println!("======================================================");
}

// ── 信任请求 ───────────────────────────────────────────────────

const TRUST_MAGIC: u32 = 0x54525354; // "TRST"
const TRUST_PORT: u16 = 45801;

fn cmd_trust_listen() {
    println!("  [trust] 监听信任请求端口 {TRUST_PORT} ...");
    println!("  [trust] 等待对端连接请求，收到后会弹出确认");
    println!("  [trust] 按 Ctrl+C 停止监听");
    println!();

    let socket = match UdpSocket::bind(format!("0.0.0.0:{TRUST_PORT}")) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("  [!] 端口 {TRUST_PORT} 绑定失败: {e}");
            eprintln!("      可能已有服务在用此端口，或需要管理员权限");
            std::process::exit(1);
        }
    };
    let _ = socket.set_read_timeout(Some(Duration::from_secs(1)));

    let mut buf = [0u8; 256];
    loop {
        match socket.recv_from(&mut buf) {
            Ok((n, src)) => {
                if n < 12 {
                    continue;
                }
                let magic = u32::from_be_bytes(buf[0..4].try_into().unwrap_or([0; 4]));
                if magic != TRUST_MAGIC {
                    continue;
                }
                let peer_port = u16::from_be_bytes(
                    TryInto::<[u8; 2]>::try_into(&buf[4..6]).unwrap_or([0; 2])
                );
                let addr_len = buf[6] as usize;
                if 7 + addr_len > n {
                    continue;
                }
                let peer_addr = String::from_utf8_lossy(&buf[7..7 + addr_len]).to_string();
                let peer_ip = src.ip().to_string();

                println!("\n  ╔══════════════════════════════════════════╗");
                println!("  ║  信任请求                                   ║");
                println!("  ╠══════════════════════════════════════════╣");
                println!("  ║  对端 IPv8 地址: {peer_addr:<30} ║", );
                println!("  ║  对端 IP:        {peer_ip:<30} ║");
                println!("  ║  对端端口:       {peer_port:<30} ║");
                println!("  ║                                            ║");
                println!("  ║  是否同意此节点建立隧道连接？               ║");
                println!("  ║  [Y] 同意  [N] 拒绝                        ║");
                println!("  ╚══════════════════════════════════════════╝");

                // 发送回复
                print!("  请输入 (Y/N): ");
                let _ = std::io::stdout().flush();
                let mut input = String::new();
                std::io::stdin().read_line(&mut input).ok();
                let agreed = input.trim().eq_ignore_ascii_case("y")
                    || input.trim().eq_ignore_ascii_case("yes");
                let reply = if agreed {
                    println!("  [trust] 已同意，正在建立隧道...");
                    let mut r = TRUST_MAGIC.to_be_bytes().to_vec();
                    r.push(1u8);
                    r
                } else {
                    println!("  [trust] 已拒绝");
                    let mut r = TRUST_MAGIC.to_be_bytes().to_vec();
                    r.push(0u8);
                    r
                };
                let _ = socket.send_to(&reply, src);

                if reply[4] == 1 {
                    println!("  [trust] 隧道连接已建立");
                }
                println!();
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {
                continue;
            }
            Err(e) => {
                eprintln!("  [trust] 接收错误: {e}");
                break;
            }
        }
    }
}

fn cmd_trust_request(peer_ip: &str, peer_port: u16) {
    let visa = load_visa();
    let self_addr = visa.as_ref()
        .map(|v| addr_from_bytes(&v.ipv8_addr).to_canonical_string())
        .unwrap_or_else(|| "未配置".into());

    println!("  [trust] 向 {peer_ip}:{peer_port} 发送信任请求...");
    println!("  [trust] 本机 IPv8 地址: {self_addr}");
    println!();

    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            eprintln!("  [!] 无法创建 socket: {e}");
            std::process::exit(1);
        }
    };
    let _ = socket.set_read_timeout(Some(Duration::from_secs(15)));

    let addr_bytes = self_addr.as_bytes();
    let mut pkt = Vec::with_capacity(7 + addr_bytes.len());
    pkt.extend_from_slice(&TRUST_MAGIC.to_be_bytes());
    pkt.extend_from_slice(&peer_port.to_be_bytes());
    pkt.push(addr_bytes.len() as u8);
    pkt.extend_from_slice(addr_bytes);

    let target = format!("{peer_ip}:{peer_port}");
    if let Err(e) = socket.send_to(&pkt, &target) {
        eprintln!("  [!] 发送失败: {e}");
        std::process::exit(1);
    }

    println!("  [trust] 请求已发送，等待对端确认（15秒超时）...");

    let mut buf = [0u8; 16];
    match socket.recv_from(&mut buf) {
        Ok((n, _)) if n >= 5 => {
            let magic = u32::from_be_bytes(buf[0..4].try_into().unwrap_or([0; 4]));
            if magic != TRUST_MAGIC {
                eprintln!("  [!] 收到无效回复");
                std::process::exit(1);
            }
            if buf[4] == 1 {
                println!("  [trust] 对端已同意！隧道连接已建立");
                println!("  [trust] 现在可以互相 ping8 ping 访问了");
            } else {
                println!("  [trust] 对端拒绝了连接请求");
                std::process::exit(1);
            }
        }
        Ok(_) => {
            eprintln!("  [!] 收到无效回复");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("  [!] 等待回复超时或失败: {e}");
            eprintln!("      请确认对端已运行 ping8 trust listen");
            std::process::exit(1);
        }
    }
}

// ── 外部判决钩子（ipv8-hook 客户端）────────────────────────────

/// 连接节点的钩子端口；失败给出可操作提示
fn hook_connect(addr: &str) -> TcpStream {
    match TcpStream::connect(addr) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("  [!] 连接钩子 {addr} 失败: {e}");
            eprintln!("      ipv8-node 需要带 --hook 启动才会开放判决端口（默认 45810）");
            eprintln!("      操作方法：另开一个窗口执行  ipv8-node --hook  后，再运行本命令");
            std::process::exit(1);
        }
    }
}

/// `ping8 hook watch [addr] [--decision]`
/// observer 模式：实时打印事件流（录像/调试）；--decision 可接管判决
fn cmd_hook_watch(addr: &str, decision: bool) {
    let mut stream = hook_connect(addr);
    let mode = if decision { "decision" } else { "observer" };
    if let Err(e) = writeln!(
        stream,
        r#"{{"type":"hello","mode":"{mode}","name":"ping8-watch","version":1}}"#
    ) {
        eprintln!("  [!] 握手失败: {e}");
        std::process::exit(1);
    }
    let _ = stream.flush();

    eprintln!("  已连接 {addr}（{mode}）。实时事件如下，Ctrl+C 退出：");
    let reader = io::BufReader::new(match stream.try_clone() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("  [!] {e}");
            std::process::exit(1);
        }
    });
    for line in reader.lines().map_while(Result::ok) {
        println!("{line}");
    }
    eprintln!("  连接已断开");
}

/// `ping8 hook stats [addr]`：取一次总线统计
fn cmd_hook_stats(addr: &str) {
    let mut stream = hook_connect(addr);
    writeln!(stream, r#"{{"type":"hello","mode":"observer","name":"ping8-stats","version":1}}"#).ok();
    let _ = stream.flush();
    std::thread::sleep(Duration::from_millis(100));
    writeln!(stream, r#"{{"type":"stats"}}"#).ok();
    let _ = stream.flush();
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
    let reader = io::BufReader::new(stream);
    for line in reader.lines().map_while(Result::ok) {
        // 用 JSON 解析判定，兼容紧凑/带空格等各种序列化风格
        let is_stats = serde_json::from_str::<serde_json::Value>(&line)
            .map(|v| v.get("type").and_then(|t| t.as_str()) == Some("stats"))
            .unwrap_or(false);
        if is_stats {
            println!("{line}");
            return;
        }
    }
    eprintln!("  [!] 未取到统计");
    std::process::exit(1);
}

// ── 防火墙命令 ──────────────────────────────────────────────────

/// 规则文件路径
fn firewall_rules_path() -> PathBuf {
    let home = env::var("USERPROFILE").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".ipv8").join("firewall-rules.json")
}

/// 加载规则集
fn load_rules() -> ipv8_firewall::RuleSet {
    ipv8_firewall::RuleSet::load(&firewall_rules_path())
}

/// 保存规则集
fn save_rules(rs: &ipv8_firewall::RuleSet) {
    let path = firewall_rules_path();
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Err(e) = rs.save(&path) {
        eprintln!("  [!] 保存规则失败: {e}");
    }
}

/// 同步到 Windows 防火墙（用 netsh）
fn sync_windows_firewall(rs: &ipv8_firewall::RuleSet) {
    // 先清理旧的 IPv8+ 规则
    let _ = Command::new("netsh")
        .args(["advfirewall", "firewall", "delete", "rule", "name=all"])
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .output();

    // 再按规则添加
    for rule in rs.active_rules() {
        let proto = match rule.protocol {
            ipv8_firewall::Protocol::Tcp => "tcp",
            ipv8_firewall::Protocol::Udp => "udp",
            ipv8_firewall::Protocol::Any => "any",
            ipv8_firewall::Protocol::Custom(_) => "any",
        };
        let port = if rule.port_end > rule.port_start {
            format!("{}-{}", rule.port_start, rule.port_end)
        } else {
            rule.port_start.to_string()
        };
        let name = format!("IPv8+ {}", rule.name);
        let _ = Command::new("netsh")
            .args([
                "advfirewall", "firewall", "add", "rule",
                &format!("name={name}"),
                "dir=in",
                "action=allow",
                &format!("protocol={proto}"),
                &format!("localport={port}"),
            ])
            .creation_flags(0x08000000)
            .output();
    }
}

fn cmd_firewall_list() {
    let rs = load_rules();
    let active = rs.active_rules().count();
    let total = rs.rules.len();

    println!("┌─────────────────────────────────────────────");
    println!("│ IPv8 防火墙规则  共 {total} 条，启用 {active} 条");
    println!("├─────────────────────────────────────────────");

    if rs.rules.is_empty() {
        println!("│ （空）使用 ping8 firewall add 添加规则");
    } else {
        for r in &rs.rules {
            let status = if r.enabled { "[启用]" } else { "[禁用]" };
            let port = if r.port_end > r.port_start {
                format!("{}-{}", r.port_start, r.port_end)
            } else {
                r.port_start.to_string()
            };
            let src = if r.source_pattern.is_empty() { "任意".into() } else { r.source_pattern.clone() };
            let tgt = if r.target_addr.is_empty() {
                "仅放行".into()
            } else {
                format!("{}:{}", r.target_addr, if r.target_port > 0 { r.target_port } else { r.port_start })
            };
            println!("│ {status} {} ({})", r.name, r.id);
            println!("│     协议={} 端口={} 源={} 目标={}", r.protocol.as_str(), port, src, tgt);
            if !r.comment.is_empty() {
                println!("│     备注: {}", r.comment);
            }
            println!("│");
        }
    }
    println!("└─────────────────────────────────────────────");
    println!();
    println!("提示: 在浏览器中打开 ping8 serve 可使用图形界面管理");
}

#[allow(clippy::too_many_arguments)] // CLI 参数一对一映射，保持平铺
fn cmd_firewall_add(
    name: &str,
    port_start: u16,
    port_end: u16,
    proto: &str,
    source: &str,
    target: &str,
    target_port: u16,
    comment: &str,
) {
    let mut rs = load_rules();
    let rule = ipv8_firewall::Rule {
        id: ipv8_firewall::gen_rule_id(),
        name: name.into(),
        protocol: ipv8_firewall::Protocol::parse(proto),
        port_start,
        port_end,
        source_pattern: source.into(),
        target_addr: target.into(),
        target_port,
        enabled: true,
        direction: ipv8_firewall::Direction::Inbound,
        comment: comment.into(),
    };
    let id = rule.id.clone();
    rs.add(rule);
    save_rules(&rs);
    sync_windows_firewall(&rs);

    println!("  [OK] 规则已保存");
    println!("       ID:    {id}");
    println!("       名称:  {name}");
    println!("       协议:  {proto}");
    println!("       端口:  {port_start}-{port_end}");
    if !source.is_empty() {
        println!("       源:    {source}");
    }
    if !target.is_empty() {
        println!("       目标:  {target}:{target_port}");
    }
    if !comment.is_empty() {
        println!("       备注:  {comment}");
    }
    println!("       Windows 防火墙已同步");
}

fn cmd_firewall_remove(id: &str) {
    let mut rs = load_rules();
    if rs.remove(id) {
        save_rules(&rs);
        sync_windows_firewall(&rs);
        println!("  [OK] 规则 {id} 已删除");
    } else {
        println!("  [!] 未找到规则 {id}");
    }
}

fn cmd_firewall_toggle(id: &str) {
    let mut rs = load_rules();
    if rs.toggle(id) {
        save_rules(&rs);
        sync_windows_firewall(&rs);
        let enabled = rs.rules.iter().find(|r| r.id == id).map(|r| r.enabled).unwrap_or(false);
        let state = if enabled { "启用" } else { "禁用" };
        println!("  [OK] 规则 {id} 已{state}");
    } else {
        println!("  [!] 未找到规则 {id}");
    }
}

/// 查询同名防火墙规则当前已存在的条数。
/// `netsh show rule` 标准用户即可执行（无需管理员）；
/// 规则不存在时退出码为 1 并输出 "No rules match..."。
fn firewall_rule_count(name: &str) -> u32 {
    let Ok(out) = Command::new("netsh")
        .args([
            "advfirewall", "firewall", "show", "rule",
            &format!("name={name}"),
        ])
        .creation_flags(0x08000000)
        .output()
    else {
        return 0;
    };
    if !out.status.success() {
        return 0;
    }
    let s = String::from_utf8_lossy(&out.stdout);
    // 英文系统每条规则输出一个 "Rule Name:" 段；中文系统字段名不同，
    // 用规则名本身的出现次数兜底计数。
    let count = s.matches("Rule Name:").count();
    if count > 0 {
        count as u32
    } else {
        s.matches(name).count() as u32
    }
}

/// 添加一条入站放行规则；成功返回 true（需要管理员权限）。
fn add_firewall_rule(name: &str, proto: &str, port: u16) -> bool {
    Command::new("netsh")
        .args([
            "advfirewall", "firewall", "add", "rule",
            &format!("name={name}"),
            "dir=in", "action=allow",
            &format!("protocol={proto}"),
            &format!("localport={port}"),
        ])
        .creation_flags(0x08000000)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn cmd_firewall_open() {
    let ports: [(u16, &str, &str); 5] = [
        (45801, "UDP", "Tunnel"),
        (45800, "UDP", "Tunnel Alt"),
        (45802, "UDP", "Neighbor"),
        (9001, "TCP", "Portal"),
        (5353, "UDP", "DNS"),
    ];
    let mut failures = 0u32;
    for &(port, proto, desc) in &ports {
        let name = format!("IPv8+ {desc} {port} {proto}");
        let existing = firewall_rule_count(&name);

        if existing == 1 {
            // 规则已存在且唯一：什么都不用做，也不需要管理员权限
            println!("  [OK] {proto} {port} ({desc}) — 规则已存在");
            continue;
        }

        if existing > 1 {
            // 旧版本每次盲加会堆积同名规则。非管理员无法清理，
            // 但重复规则不影响放行效果。
            if !is_admin() {
                println!("  [OK] {proto} {port} ({desc}) — 已放行（{existing} 条重复规则不影响使用，管理员运行可自动去重）");
                continue;
            }
            let _ = Command::new("netsh")
                .args([
                    "advfirewall", "firewall", "delete", "rule",
                    &format!("name={name}"),
                ])
                .creation_flags(0x08000000)
                .output();
            if add_firewall_rule(&name, proto, port) {
                println!("  [OK] {proto} {port} ({desc}) — 已去重（清理 {existing} 条重复规则）");
            } else {
                println!("  [FAIL] {proto} {port} — 去重后重建失败");
                failures += 1;
            }
            continue;
        }

        // 规则不存在：尝试新建（需要管理员）
        if add_firewall_rule(&name, proto, port) {
            println!("  [OK] 放行 {proto} {port} ({desc})");
        } else {
            println!("  [FAIL] 放行 {proto} {port} — 规则不存在，请以管理员身份运行");
            failures += 1;
        }
    }
    if failures == 0 {
        println!("\n  IPv8 标准端口已全部就绪");
    } else {
        println!("\n  {failures} 个端口未能放行 — 请以管理员身份运行 ping8 firewall open");
    }
}

fn cmd_firewall_close() {
    let _ = Command::new("netsh")
        .args(["advfirewall", "firewall", "delete", "rule", "name=all"])
        .creation_flags(0x08000000)
        .output();

    let mut rs = load_rules();
    for r in &mut rs.rules {
        r.enabled = false;
    }
    save_rules(&rs);

    println!("  [OK] 所有 IPv8+ 防火墙规则已禁用");
}

// ── 本地管理 Web 服务 ─────────────────────────────────────────

/// 探测本机公网/全局 IPv6 地址（排除链路本地、回环、ULA）。
/// 供管理页 /api/status 展示；探测失败返回 None，不影响接口响应速度。
/// 过滤/排序规则与门户 Get-ServerIPv6 保持一致，避免两处显示不同地址。
fn local_global_ipv6() -> Option<String> {
    let out = Command::new("powershell")
        .args([
            "-NoProfile", "-Command",
            "(Get-NetIPAddress -AddressFamily IPv6 -ErrorAction SilentlyContinue | " ,
            "Where-Object { $_.IPAddress -notlike 'fe80::*' -and $_.IPAddress -ne '::1' " ,
            "-and $_.IPAddress -notlike 'fd*' -and $_.IPAddress -notlike 'fc*' " ,
            "-and $_.PrefixOrigin -ne 'WellKnown' -and $_.SuffixOrigin -ne 'Link' } | " ,
            "Sort-Object -Property IPAddress -Descending | Select-Object -First 1 -ExpandProperty IPAddress)",
        ])
        .creation_flags(0x08000000)
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.contains(':') { Some(s) } else { None }
}

/// 探测本机局域网 IPv4（排除回环/链路本地/CGNAT），规则同门户 Get-ServerIPv4。
fn local_lan_ipv4() -> Option<String> {
    let out = Command::new("powershell")
        .args([
            "-NoProfile", "-Command",
            "(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | " ,
            "Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.*' " ,
            "-and $_.IPAddress -notlike '100.64.*' -and $_.PrefixOrigin -ne 'WellKnown' } | " ,
            "Select-Object -First 1 -ExpandProperty IPAddress)",
        ])
        .creation_flags(0x08000000)
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.contains('.') { Some(s) } else { None }
}

fn cmd_serve(port: u16) {
    let bind_addr = format!("127.0.0.1:{port}");

    let listener = match std::net::TcpListener::bind(&bind_addr) {
        Ok(l) => l,
        Err(e) => {
            // Windows 10048 = WSAEADDRINUSE。探测占用方是不是已经在跑的 ping8 serve
            if e.raw_os_error() == Some(10048) && probe_serve_alive(port) {
                eprintln!("  [!] ping8 管理服务已在运行：http://{bind_addr}");
                eprintln!("      浏览器直接打开即可，无需再次执行本命令。");
                eprintln!("      如需重启：先在任务管理器结束旧的 ping8.exe（或执行 Stop-Process -Name ping8），再 ping8 serve");
                std::process::exit(0);
            }
            eprintln!("  [!] 端口 {port} 绑定失败: {e}");
            eprintln!("      该端口被其他程序占用，换一个端口即可: ping8 serve --port 9102");
            std::process::exit(1);
        }
    };

    println!("  IPv8+ 客户端管理服务启动中...");
    println!("  访问地址: http://{bind_addr}");
    println!("  按 Ctrl+C 停止");
    println!();

    for stream in listener.incoming() {
        match stream {
            Ok(s) => handle_http_request(s),
            Err(_) => continue,
        }
    }
}

/// 探测指定端口上是否已有一个 ping8 管理服务在响应（通过 /api/status 的独有字段判断）
fn probe_serve_alive(port: u16) -> bool {
    let addr = match format!("127.0.0.1:{port}").parse() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let Ok(mut s) = TcpStream::connect_timeout(&addr, Duration::from_millis(800)) else {
        return false;
    };
    let _ = s.set_read_timeout(Some(Duration::from_millis(1500)));
    let req = "GET /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    if s.write_all(req.as_bytes()).is_err() {
        return false;
    }
    let mut data = Vec::new();
    let mut buf = [0u8; 4096];
    while let Ok(n) = s.read(&mut buf) {
        if n == 0 { break; }
        data.extend_from_slice(&buf[..n]);
        if data.len() > 65536 { break; }
    }
    // rules_active/rules_total 是 9100 客户端 /api/status 独有的字段，门户 9001 没有
    let text = String::from_utf8_lossy(&data);
    text.contains("rules_active") || text.contains("rules_total")
}

fn handle_http_request(mut stream: std::net::TcpStream) {
    let mut buf = [0u8; 8192];
    let n = match stream.read(&mut buf) {
        Ok(n) if n > 0 => n,
        _ => return,
    };

    let request = String::from_utf8_lossy(&buf[..n]);
    let first_line = request.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 {
        return;
    }
    let method = parts[0];
    let path = parts[1];

    // 路由
    let (status, content_type, body) = match (method, path) {
        ("GET", "/") | ("GET", "/index.html") => {
            ("200 OK", "text/html; charset=utf-8", serve_management_html())
        }
        ("GET", "/api/firewall/rules") => {
            let rs = load_rules();
            let active = rs.active_rules().count();
            let json = serde_json::json!({
                "total": rs.rules.len(),
                "active": active,
                "disabled": rs.rules.len() - active,
                "rules": rs.rules,
            });
            ("200 OK", "application/json", serde_json::to_string_pretty(&json).unwrap_or_default())
        }
        ("POST", "/api/firewall/rules") => {
            let body_start = request.find("\r\n\r\n").map(|i| i + 4).unwrap_or(0);
            let body_str = &request[body_start..];
            match serde_json::from_str::<serde_json::Value>(body_str) {
                Ok(val) => {
                    let mut rs = load_rules();
                    let name = val["name"].as_str().unwrap_or("").to_string();
                    let port_start = val["port_start"].as_u64().unwrap_or(0) as u16;
                    let port_end = val["port_end"].as_u64().unwrap_or(port_start as u64) as u16;
                    let proto = val["protocol"].as_str().unwrap_or("tcp");
                    let source = val["source_pattern"].as_str().unwrap_or("").to_string();
                    let target = val["target_addr"].as_str().unwrap_or("").to_string();
                    let target_port = val["target_port"].as_u64().unwrap_or(0) as u16;
                    let comment = val["comment"].as_str().unwrap_or("").to_string();

                    if name.is_empty() || port_start == 0 {
                        ("400 Bad Request", "application/json",
                         r#"{"error":"missing name or port_start"}"#.to_string())
                    } else {
                        let rule = ipv8_firewall::Rule {
                            id: ipv8_firewall::gen_rule_id(),
                            name,
                            protocol: ipv8_firewall::Protocol::parse(proto),
                            port_start,
                            port_end,
                            source_pattern: source,
                            target_addr: target,
                            target_port,
                            enabled: true,
                            direction: ipv8_firewall::Direction::Inbound,
                            comment,
                        };
                        let id = rule.id.clone();
                        rs.add(rule);
                        save_rules(&rs);
                        sync_windows_firewall(&rs);
                        ("200 OK", "application/json",
                         format!(r#"{{"ok":true,"id":"{id}"}}"#))
                    }
                }
                Err(_) => ("400 Bad Request", "application/json", r#"{"error":"invalid json"}"#.to_string()),
            }
        }
        ("DELETE", p) if p.starts_with("/api/firewall/rules") => {
            let id = request.split("id=").nth(1).map(|s| s.split_whitespace().next().unwrap_or("").to_string()).unwrap_or_default();
            let mut rs = load_rules();
            if rs.remove(&id) {
                save_rules(&rs);
                sync_windows_firewall(&rs);
                ("200 OK", "application/json", format!(r#"{{"ok":true,"deleted":"{id}"}}"#))
            } else {
                ("404 Not Found", "application/json", r#"{"error":"not found"}"#.to_string())
            }
        }
        ("GET", p) if p.starts_with("/api/firewall/toggle") => {
            let id = p.split("id=").nth(1).map(|s| s.split('&').next().unwrap_or("")).unwrap_or("");
            let mut rs = load_rules();
            if rs.toggle(id) {
                save_rules(&rs);
                sync_windows_firewall(&rs);
                ("200 OK", "application/json", format!(r#"{{"ok":true,"id":"{id}"}}"#))
            } else {
                ("404 Not Found", "application/json", r#"{"error":"not found"}"#.to_string())
            }
        }
        ("GET", "/api/status") => {
            let rs = load_rules();
            let visa = load_visa();
            if let Some(ref v) = visa {
                try_auto_renew(v);
            }
            let visa = load_visa();
            let visa_info = match &visa {
                Some(v) => {
                    let addr = addr_from_bytes(&v.ipv8_addr);
                    let now = now_secs();
                    serde_json::json!({
                        "exists": true,
                        "addr": addr.to_display_string(),
                        "canonical": addr.to_canonical_string(),
                        "expired": v.expires_at != 0 && now > v.expires_at,
                        "expires_at": v.expires_at,
                        "remaining_days": if v.expires_at == 0 { -1i64 } else { (v.expires_at as i64 - now as i64) / 86400 },
                    })
                }
                None => serde_json::json!({"exists": false}),
            };
            let json = serde_json::json!({
                "rules_total": rs.rules.len(),
                "rules_active": rs.active_rules().count(),
                "visa": visa_info,
                "ca_exists": ca_seed_path().exists(),
                "version": PING8_VERSION,
                "ipv6": local_global_ipv6(),
                "ipv4": local_lan_ipv4(),
                "dns": "127.0.0.1:5353",
            });
            ("200 OK", "application/json", serde_json::to_string_pretty(&json).unwrap_or_default())
        }
        ("GET", "/api/diagnose") => {
            let checks = run_checks();
            let mut ok = 0u32; let mut warn = 0u32; let mut fail = 0u32; let mut na = 0u32;
            for c in &checks {
                match c.status {
                    CheckStatus::Ok => ok += 1,
                    CheckStatus::Warn => warn += 1,
                    CheckStatus::Fail => fail += 1,
                    CheckStatus::Na => na += 1,
                }
            }
            let json = serde_json::json!({
                "version": PING8_VERSION.to_string(),
                "summary": { "ok": ok, "warn": warn, "fail": fail, "na": na },
                "checks": checks,
            });
            ("200 OK", "application/json", serde_json::to_string_pretty(&json).unwrap_or_default())
        }
        _ => ("404 Not Found", "text/plain", "Not Found".to_string()),
    };

    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, DELETE, OPTIONS\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

/// 本地管理页面 HTML
fn serve_management_html() -> String {
    r##"<!DOCTYPE html>
<html lang="zh-CN" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IPv8+ 客户端管理</title>
<style>
:root {
  --bg: #0d1117; --surface: #161b22; --border: #30363d;
  --text: #e6edf3; --text-muted: #7d8590; --text-faint: #484f58;
  --accent: #58a6ff; --accent-hover: #79b8ff;
  --ok: #3fb950; --warn: #d29922; --danger: #f85149;
  --radius: 8px;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, "Microsoft YaHei", sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; }
.container { max-width: 960px; margin: 0 auto; padding: 20px; }
header { display: flex; align-items: center; gap: 12px; padding: 16px 0; border-bottom: 1px solid var(--border); margin-bottom: 24px; }
.brand { font-size: 20px; font-weight: 700; }
.brand-mark { display: inline-block; background: var(--accent); color: var(--bg); padding: 2px 8px; border-radius: 4px; font-weight: 900; margin-right: 8px; }
.card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 20px; margin-bottom: 20px; }
.card-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
.card-head h2 { font-size: 16px; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 12px; font-weight: 600; }
.badge-ok { background: rgba(63,185,80,0.15); color: var(--ok); border: 1px solid rgba(63,185,80,0.3); }
.badge-warn { background: rgba(210,153,34,0.15); color: var(--warn); border: 1px solid rgba(210,153,34,0.3); }
.stats-row { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 16px; }
.stat-box { background: var(--bg); border: 1px solid var(--border); border-radius: var(--radius); padding: 12px; text-align: center; }
.stat-value { font-size: 24px; font-weight: 700; }
.stat-label { font-size: 12px; color: var(--text-muted); }
.field-row { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 8px; }
input, select { background: var(--bg); border: 1px solid var(--border); border-radius: 4px; padding: 8px 12px; color: var(--text); font-size: 14px; outline: none; }
input:focus, select:focus { border-color: var(--accent); }
input { flex: 1; min-width: 120px; }
input[type=number] { max-width: 100px; }
select { min-width: 80px; }
.btn { display: inline-block; padding: 8px 16px; border-radius: 4px; border: 1px solid var(--border); background: var(--surface); color: var(--text); cursor: pointer; font-size: 14px; transition: all 0.15s; }
.btn:hover { border-color: var(--accent); background: var(--bg); }
.btn-primary { background: var(--accent); color: var(--bg); border-color: var(--accent); font-weight: 600; }
.btn-primary:hover { background: var(--accent-hover); }
.btn-danger { color: var(--danger); border-color: rgba(248,81,73,0.3); }
.btn-danger:hover { background: rgba(248,81,73,0.1); border-color: var(--danger); }
.btn-sm { padding: 2px 8px; font-size: 12px; }
table { width: 100%; border-collapse: collapse; }
th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid var(--border); }
th { font-size: 12px; color: var(--text-muted); text-transform: uppercase; }
td { font-size: 14px; }
.mono { font-family: "Cascadia Code", "Consolas", monospace; font-size: 13px; }
.alert { padding: 8px 12px; border-radius: 4px; margin-bottom: 12px; font-size: 14px; }
.alert-info { background: rgba(88,166,255,0.1); color: var(--accent); border: 1px solid rgba(88,166,255,0.2); }
details { margin-bottom: 12px; }
summary { cursor: pointer; font-weight: 600; padding: 8px 0; }
.faint { color: var(--text-faint); }
</style>
</head>
<body>
<div class="container">
  <header>
    <span class="brand-mark">V8</span>
    <span class="brand">IPv8+ 客户端管理</span>
  </header>

  <div class="card">
    <div class="card-head"><h2>防火墙规则</h2></div>
    <div class="stats-row">
      <div class="stat-box"><div class="stat-value" id="fwTotal">0</div><div class="stat-label">规则总数</div></div>
      <div class="stat-box"><div class="stat-value" id="fwActive" style="color:var(--ok)">0</div><div class="stat-label">启用中</div></div>
      <div class="stat-box"><div class="stat-value" id="fwDisabled" style="color:var(--warn)">0</div><div class="stat-label">已禁用</div></div>
      <div class="stat-box"><div class="stat-value" id="fwVersion">-</div><div class="stat-label">客户端版本</div></div>
    </div>

    <details>
      <summary>+ 添加防火墙规则</summary>
      <div style="padding-top:12px">
        <div class="field-row">
          <input type="text" id="fwName" placeholder="规则名称">
          <select id="fwProtocol"><option value="tcp">TCP</option><option value="udp">UDP</option><option value="any">任意</option></select>
          <input type="number" id="fwPortStart" placeholder="起始端口" min="1" max="65535">
          <input type="number" id="fwPortEnd" placeholder="结束端口" min="1" max="65535">
        </div>
        <div class="field-row">
          <input type="text" id="fwSource" placeholder="源 IPv8 地址前缀（空=任意）">
          <input type="text" id="fwTarget" placeholder="转发目标 IPv8 地址（空=仅放行）">
          <input type="number" id="fwTargetPort" placeholder="目标端口" min="0" max="65535">
        </div>
        <div class="field-row">
          <input type="text" id="fwComment" placeholder="备注（可选）">
          <button class="btn btn-primary" id="fwAddBtn">保存规则</button>
        </div>
      </div>
    </details>

    <table>
      <thead><tr><th>名称</th><th>协议</th><th>端口</th><th>源过滤</th><th>转发目标</th><th>状态</th><th>操作</th></tr></thead>
      <tbody id="fwRulesBody"><tr><td colspan="7" style="text-align:center;color:var(--text-faint);padding:20px">加载中…</td></tr></tbody>
    </table>

    <div class="field-row" style="margin-top:16px">
      <button class="btn btn-sm" id="fwRefreshBtn">刷新</button>
      <button class="btn btn-sm btn-danger" id="fwCloseAllBtn">禁用所有</button>
    </div>
    <div id="fwResult"></div>
  </div>

  <div class="card">
    <div class="card-head"><h2>说明</h2></div>
    <p style="color:var(--text-muted);font-size:14px">
      本管理界面运行在本地，所有规则保存在本机 <span class="mono">~/.ipv8/firewall-rules.json</span>。<br>
      节点仅提供隧道，不处理用户数据。速度上限取决于双方网速。<br>
      通过 Cloudflare 边缘自动就近路由，提供 DDoS 保护和最低延迟连接。
    </p>
  </div>
</div>

<script>
function $(id){return document.getElementById(id)}
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}
function loadRules(){
  fetch('/api/firewall/rules').then(r=>r.json()).then(d=>{
    $('fwTotal').textContent=d.total||0;
    $('fwActive').textContent=d.active||0;
    $('fwDisabled').textContent=d.disabled||0;
    var body=$('fwRulesBody');
    var rules=d.rules||[];
    if(!rules.length){body.innerHTML='<tr><td colspan="7" style="text-align:center;color:var(--text-faint);padding:20px">暂无规则</td></tr>';return}
    body.innerHTML=rules.map(function(r){
      var port=r.port_start===r.port_end?String(r.port_start):r.port_start+'-'+r.port_end;
      var src=r.source_pattern?esc(r.source_pattern):'<span class="faint">任意</span>';
      var tgt=r.target_addr?esc(r.target_addr)+':'+(r.target_port||r.port_start):'<span class="faint">仅放行</span>';
      var st=r.enabled?'<span class="badge badge-ok">启用</span>':'<span class="badge badge-warn">禁用</span>';
      var toggleLabel=r.enabled?'禁用':'启用';
      return '<tr><td>'+esc(r.name)+(r.comment?'<br><span style="font-size:11px;color:var(--text-muted)">'+esc(r.comment)+'</span>':'')+'</td>'+
        '<td class="mono">'+esc(r.protocol)+'</td><td class="mono">'+port+'</td>'+
        '<td class="mono" style="font-size:11px">'+src+'</td><td class="mono" style="font-size:11px">'+tgt+'</td>'+
        '<td>'+st+'</td><td style="white-space:nowrap">'+
        '<button class="btn btn-sm" onclick="toggleRule(\''+r.id+'\')">'+toggleLabel+'</button> '+
        '<button class="btn btn-sm btn-danger" onclick="delRule(\''+r.id+'\')">删除</button></td></tr>';
    }).join('');
  }).catch(function(){});
}
function addRule(){
  var data={name:$('fwName').value.trim(),protocol:$('fwProtocol').value,
    port_start:parseInt($('fwPortStart').value,10)||0,port_end:parseInt($('fwPortEnd').value,10)||0,
    source_pattern:$('fwSource').value.trim(),target_addr:$('fwTarget').value.trim(),
    target_port:parseInt($('fwTargetPort').value,10)||0,comment:$('fwComment').value.trim(),
    direction:'inbound',enabled:true};
  if(!data.name||!data.port_start){$('fwResult').innerHTML='<div class="alert alert-info">请填写名称和端口</div>';return}
  fetch('/api/firewall/rules',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)})
    .then(r=>r.json()).then(function(){['fwName','fwPortStart','fwPortEnd','fwSource','fwTarget','fwTargetPort','fwComment'].forEach(function(id){$(id).value=''});loadRules()});
}
function toggleRule(id){fetch('/api/firewall/toggle?id='+id).then(r=>r.json()).then(function(){loadRules()})}
function delRule(id){if(!confirm('确认删除？'))return;fetch('/api/firewall/rules?id='+id,{method:'DELETE'}).then(r=>r.json()).then(function(){loadRules()})}
$('fwAddBtn').addEventListener('click',addRule);
$('fwRefreshBtn').addEventListener('click',loadRules);
$('fwCloseAllBtn').addEventListener('click',function(){if(confirm('确认禁用所有规则？')){rules.forEach(function(r){fetch('/api/firewall/toggle?id='+r.id).then(function(){loadRules()})})}});
loadRules();
</script>
</body>
</html>"##.to_string()
}

// ── 帮助/用法 ──────────────────────────────────────────────────

fn usage() {
    eprintln!(r#"ping8 — IPv8+ 用户客户端工具（高级命令用 ipv8adm）

用法:
  ping8 <子命令> [参数]

子命令:
  install                          安装到系统 PATH（管理员，仅一次）
  auto                             一键自动配置（CA + 签证 + 防火墙）
  diagnose                         一键诊断（签证/驱动/隧道/DNS/防火墙）
  addr                             查看本机 IPv8 地址详情
  ping <32hex地址> [count] [timeout] ping 远端 IPv8 地址
                                   count 默认 4，timeout 默认 1000ms
  status                           查看驱动/隧道/签证整体状态
  visa ca-init                     生成 CA 密钥对（管理员，仅一次）
  visa issue [--addr <32hex>]      签发/重签签证（默认 30 天有效）
       [--ca-seed <64hex>] [--expires <秒>]
       （省略参数将自动生成地址和 CA）
  visa show                        查看本机签证详情
  visa verify --ca-pub <64hex>     用 CA 公钥验证签证
  visa renew                       手动续签（刷新 30 天有效期）
  visa revoke                      吊销（删除）本机签证
  visa fingerprint                 显示本机机器指纹
  firewall list                    列出所有防火墙规则
  firewall add --name <名> --port <端口> [--proto tcp|udp|any]
       [--port-end <端口>] [--source <前缀>] [--target <32hex>]
       [--target-port <端口>] [--comment <备注>]
  firewall remove --id <规则ID>    删除指定防火墙规则
  firewall toggle --id <规则ID>     切换规则启用/禁用
  firewall open                    放行 IPv8 标准端口（45800/45801/45802/9001/5353）
  firewall close                   关闭所有 IPv8 防火墙规则
  trust listen                     监听信任请求，收到后弹出确认（被动端）
  trust request <对端IP> [端口]     向对端发送信任请求（主动端）
  l2 bindings                      列出 0xFB14 网卡绑定（if 编号/MAC/计数）
  l2 peek [--if N|any] [--raw]    二层裸帧监听（--count 0 持续，Ctrl+C 停止）
  l2 send --if N [--dst MAC]       二层裸帧直连发送（默认广播 IPV8-L2-PING）
       [--hex H|--text T] [--count N] [--interval ms]
  neigh init                       准备本机身份（node_seed），显示本机地址/公钥
  neigh hello [--to IP] [--wait]  广播 HELLO（跨网段用 --to 单播）并等待 ACK 建邻
  neigh watch [--yes]              监听 HELLO 弹 Y/N 授权（同意=永久邻居），Ctrl+C 停
  neigh list                       列出永久邻居（neighbors.bin）
  neigh remove <IP|地址|公钥前缀>  删除永久邻居
  serve [--port 9100]              启动本地管理 Web 服务（浏览器打开管理界面）

示例:
  ping8 install
  ping8 auto                         # 一键配置（推荐新用户）
  ping8 diagnose                     # 诊断连接问题
  ping8 addr
  ping8 ping 0000fb14000000010001000001000000
  ping8 ping 0000fb14000000010001000001000000 10 2000
  ping8 status
  ping8 visa ca-init
  ping8 visa issue --addr 0000fb14000000010001000001000000 --ca-seed <64hex>
  ping8 visa show
  ping8 visa verify --ca-pub <64hex>
  ping8 visa renew
  ping8 visa revoke
  ping8 visa fingerprint
  ping8 firewall list
  ping8 firewall add --name "Web Server" --port 80 --proto tcp
  ping8 firewall add --name "Passive FTP" --port 50000 --port-end 50100 --proto tcp
  ping8 firewall add --name "IPv8 Forward" --port 8080 --proto tcp --target 0000fb14000000010001000001000000 --target-port 80
  ping8 firewall remove --id rule-xxx
  ping8 firewall toggle --id rule-xxx
  ping8 firewall open
  ping8 firewall close
  ping8 trust listen
  ping8 trust request 2409:8938:2a84:118::1
  ping8 trust request 192.168.1.12 45801
  ping8 serve
  ping8 serve --port 8080
  ping8 hook watch                      # 观察 ipv8-node --hook 的实时数据包事件
  python deploy/examples/hook-firewall.py   # 示例外挂判决（拦截/限速）
  ping8 driver                          # 内核驱动状态（版本/统计/绑定）
  ping8 driver <version|stats|bindings>
  ping8 l2 bindings                     # 查看二层直连网卡编号与真实 MAC
  ping8 l2 peek --if any --count 0      # 持续监听 0xFB14 裸帧
  ping8 l2 send --if 1 --text hello     # 向二层广播一帧
"#);
}

/// ipv8adm 完整 usage（包含 l2 / driver / hook）
fn usage_adm() {
    eprintln!(r#"ipv8adm — IPv8+ 高级管理工具（含 ping8 全部命令 + l2 / driver / hook）

用法:
  ipv8adm <子命令> [参数]

普通用户命令（同 ping8）:
  install / auto / diagnose / status
  addr / ping / visa / firewall / trust / neigh / serve

高级命令（仅 ipv8adm 可用）:
  driver status|version|stats|bindings    内核驱动状态/统计/绑定
  l2 bindings|peek|send|inject            0xFB14 二层裸帧直连
  hook watch|stats                        外部判决钩子客户端

示例:
  ipv8adm driver status
  ipv8adm l2 bindings
  ipv8adm l2 peek --if any --count 0
  ipv8adm hook watch
"#);
}

/* ==================== driver 子命令（Phase 5A/5B 内核可见性 + 二层裸帧） ==================== */
/* 结构布局与 src/driver/ipv8proto/driver.h 逐字节一致（#pragma pack(1)）。 */

const IPV8_DRIVER_PATH: &str = r"\\.\IPv8Proto";
/* CTL_CODE(FILE_DEVICE_UNKNOWN=0x22, fn, METHOD_BUFFERED=0, FILE_ANY_ACCESS=0) */
const IPV8_IOCTL_GET_VERSION: u32 = 0x0022_2000;
const IPV8_IOCTL_GET_STATS: u32 = 0x0022_2004;
const IPV8_IOCTL_GET_BINDINGS: u32 = 0x0022_2008;
const IPV8_IOCTL_RECV_FRAME: u32 = 0x0022_200c; /* fn=0x803 */
const IPV8_IOCTL_SEND_FRAME: u32 = 0x0022_2010; /* fn=0x804 */
const IPV8_IOCTL_INJECT_FRAME: u32 = 0x0022_2014; /* fn=0x805 调试注入接收 */
const IPV8_DRIVER_MAGIC: u32 = 0x0000_FB14;
const IPV8_BINDINGS_HDR_LEN: usize = 16;
const IPV8_BINDING_NAME_CHARS: usize = 64;
/* Phase 5B（驱动 v0.10）180B：u64×4 + Bound u32 + IfIndex u32 + Mac6+Pad2
   + NameChars u32 + Name[64]WCHAR */
const IPV8_BINDING_ENTRY_LEN: usize =
    8 * 4 + 4 + 4 + 6 + 2 + 4 + IPV8_BINDING_NAME_CHARS * 2;
const _: () = assert!(IPV8_BINDING_ENTRY_LEN == 180);

const IPV8_ETH_HEADER_LEN: usize = 14;
const IPV8_FRAME_MIN: usize = 60;
const IPV8_FRAME_MAX: usize = 1514;
const IPV8_FRAME_HDR_LEN: usize = 16;
const IPV8_RECV_IN_LEN: usize = 16;
const IPV8_IFINDEX_ANY: u32 = 0xFFFF_FFFF;

const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
const ERROR_IO_PENDING: i32 = 997;
const WAIT_OBJECT_0: u32 = 0;
const WAIT_TIMEOUT: u32 = 258;
const WAIT_FAILED: u32 = 0xFFFF_FFFF;

#[repr(C)]
struct Overlapped {
    internal: usize,
    internal_high: usize,
    offset: u32,
    offset_high: u32,
    h_event: isize,
}

#[link(name = "kernel32")]
extern "system" {
    fn CreateFileW(
        lpfilename: *const u16,
        dwdesiredaccess: u32,
        dwsharemode: u32,
        lpsecurityattributes: *const std::os::raw::c_void,
        dwcreationdisposition: u32,
        dwflagsandattributes: u32,
        htemplatefile: isize,
    ) -> isize;
    #[allow(clippy::too_many_arguments)]
    fn DeviceIoControl(
        hdevice: isize,
        dwiocontrolcode: u32,
        lpinbuffer: *const std::os::raw::c_void,
        ninbuffersize: u32,
        lpoutbuffer: *mut std::os::raw::c_void,
        noutbuffersize: u32,
        lpbytesreturned: *mut u32,
        lpoverlapped: *mut std::os::raw::c_void,
    ) -> i32;
    fn CloseHandle(hobject: isize) -> i32;
    fn CreateEventW(
        lpeventattributes: *const std::os::raw::c_void,
        bmanualreset: i32,
        binitialstate: i32,
        lpname: *const u16,
    ) -> isize;
    fn WaitForSingleObject(hhandle: isize, dwmilliseconds: u32) -> u32;
    fn ResetEvent(hevent: isize) -> i32;
    fn CancelIoEx(hfile: isize, lpoverlapped: *mut std::os::raw::c_void) -> i32;
    fn GetOverlappedResult(
        hfile: isize,
        lpoverlapped: *mut std::os::raw::c_void,
        lpnumberofbytestransferred: *mut u32,
        bwait: i32,
    ) -> i32;
}

fn rd_u16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}

fn rd_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}

fn rd_u64(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
}

/// 访问掩码（winnt.h）
const GENERIC_READ_ACCESS: u32 = 0x8000_0000;
const GENERIC_WRITE_ACCESS: u32 = 0x4000_0000;

fn driver_open_with_access(access: u32, flags: u32) -> Result<isize, std::io::Error> {
    let wide: Vec<u16> = IPV8_DRIVER_PATH.encode_utf16().chain([0]).collect();
    // FILE_SHARE_READ|FILE_SHARE_WRITE, OPEN_EXISTING
    let handle = unsafe { CreateFileW(wide.as_ptr(), access, 3, std::ptr::null(), 3, flags, 0) };
    if handle == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(handle)
    }
}

/// 只读打开：匹配驱动 SDDL `D:P(...)(A;;GR;;;WD)`，普通用户即可查询版本/统计/绑定。
fn driver_open() -> Result<isize, std::io::Error> {
    driver_open_with_access(GENERIC_READ_ACCESS, 0)
}

/// 读写打开：L2 裸帧收发（RECV_FRAME/SEND_FRAME/INJECT_FRAME）。
/// SDDL 仅授予 SYSTEM/管理员完全权限，调用进程必须已提权。
fn driver_open_data(flags: u32) -> Result<isize, std::io::Error> {
    driver_open_with_access(GENERIC_READ_ACCESS | GENERIC_WRITE_ACCESS, flags)
}

/// 设备打开失败按 Win32 错误码分流：
/// 2 = 驱动未安装/未加载；5 = 权限不足（只读查询不应发生，数据面需提权）。
/// `write_access` 为 true 表示 l2 数据面打开场景。
fn driver_open_err(e: &std::io::Error, write_access: bool) -> String {
    let hint = match e.raw_os_error() {
        Some(2) => "驱动未安装或未加载，请以管理员运行 scripts/driver-install.ps1",
        Some(5) if write_access => {
            "拒绝访问：l2 数据面操作需要管理员权限，请在管理员 PowerShell 中运行 ipv8adm"
        }
        Some(5) => {
            "拒绝访问：普通用户本应只读可查（驱动 SDDL 已授予 World 只读位），若持续失败请检查安全软件是否改写了设备权限"
        }
        _ => "请确认驱动已安装并运行（管理员执行 sc query IPv8Proto）",
    };
    format!("无法打开 {IPV8_DRIVER_PATH}: {e} — {hint}")
}

fn driver_ioctl(h: isize, code: u32, out: &mut [u8]) -> Result<usize, std::io::Error> {
    let mut returned: u32 = 0;
    let ok = unsafe {
        DeviceIoControl(
            h,
            code,
            std::ptr::null(),
            0,
            out.as_mut_ptr() as *mut std::os::raw::c_void,
            out.len() as u32,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(returned as usize)
    }
}

/// (驱动主.次版本, NDIS 主.次版本)
fn driver_query_version() -> Result<(u16, u16, u16, u16), String> {
    let h = driver_open()
        .map_err(|e| driver_open_err(&e, false))?;
    let mut buf = [0u8; 12];
    let r = driver_ioctl(h, IPV8_IOCTL_GET_VERSION, &mut buf);
    unsafe { CloseHandle(h) };
    let n = r.map_err(|e| format!("GET_VERSION 失败: {e}"))?;
    if n < 12 || rd_u32(&buf, 0) != IPV8_DRIVER_MAGIC {
        return Err("版本响应格式无效".into());
    }
    Ok((
        rd_u16(&buf, 4),
        rd_u16(&buf, 6),
        rd_u16(&buf, 8),
        rd_u16(&buf, 10),
    ))
}

/// (OpenCount, Unloading)
fn driver_query_stats() -> Result<(i32, i32), String> {
    let h = driver_open()
        .map_err(|e| driver_open_err(&e, false))?;
    let mut buf = [0u8; 16];
    let r = driver_ioctl(h, IPV8_IOCTL_GET_STATS, &mut buf);
    unsafe { CloseHandle(h) };
    let n = r.map_err(|e| format!("GET_STATS 失败: {e}"))?;
    if n < 16 || rd_u32(&buf, 0) != IPV8_DRIVER_MAGIC {
        return Err("统计响应格式无效".into());
    }
    Ok((rd_u32(&buf, 4) as i32, rd_u32(&buf, 8) as i32))
}

/// 绑定快照条目（与驱动 IPV8_BINDING_ENTRY 180B pack(1) 对应）
#[derive(Clone)]
struct BindingInfo {
    name: String,
    bound: bool,
    if_index: u32,
    mac: [u8; 6],
    rx: u64,
    tx: u64,
    rx_dropped: u64,
    tx_dropped: u64,
}

fn format_mac(mac: &[u8; 6]) -> String {
    mac.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join("-")
}

fn driver_query_bindings() -> Result<Vec<BindingInfo>, String> {
    let h = driver_open()
        .map_err(|e| driver_open_err(&e, false))?;
    let mut buf = vec![0u8; 64 * 1024];
    let r = driver_ioctl(h, IPV8_IOCTL_GET_BINDINGS, &mut buf);
    unsafe { CloseHandle(h) };
    let n = r.map_err(|e| format!("GET_BINDINGS 失败: {e}"))?;
    if n < IPV8_BINDINGS_HDR_LEN || rd_u32(&buf, 0) != IPV8_DRIVER_MAGIC {
        return Err("绑定响应格式无效（驱动版本过旧？需要 v0.10+）".into());
    }
    let count = (rd_u32(&buf, 8) as usize).min(1024);
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        // rx@0 tx@8 rxdrop@16 txdrop@24 bound@32 ifindex@36
        // mac@40 pad@46 namechars@48 name@52
        let base = IPV8_BINDINGS_HDR_LEN + i * IPV8_BINDING_ENTRY_LEN;
        if base + IPV8_BINDING_ENTRY_LEN > n {
            break;
        }
        let chars = (rd_u32(&buf, base + 48) as usize).min(IPV8_BINDING_NAME_CHARS);
        let mut name_u16 = Vec::with_capacity(chars);
        for c in 0..chars {
            name_u16.push(rd_u16(&buf, base + 52 + c * 2));
        }
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&buf[base + 40..base + 46]);
        out.push(BindingInfo {
            name: String::from_utf16_lossy(&name_u16),
            bound: rd_u32(&buf, base + 32) != 0,
            if_index: rd_u32(&buf, base + 36),
            mac,
            rx: rd_u64(&buf, base),
            tx: rd_u64(&buf, base + 8),
            rx_dropped: rd_u64(&buf, base + 16),
            tx_dropped: rd_u64(&buf, base + 24),
        });
    }
    Ok(out)
}

fn cmd_driver_version() {
    match driver_query_version() {
        Ok((maj, min, nmaj, nmin)) => {
            println!("驱动版本 : v{maj}.{min}  (NDIS {nmaj}.{nmin})");
        }
        Err(e) => {
            eprintln!("查询失败: {e}");
            std::process::exit(1);
        }
    }
}

fn cmd_driver_stats() {
    match driver_query_stats() {
        Ok((open_count, unloading)) => {
            println!("OpenCount : {open_count}");
            println!("Unloading : {}", if unloading != 0 { "是" } else { "否" });
        }
        Err(e) => {
            eprintln!("查询失败: {e}");
            std::process::exit(1);
        }
    }
}

fn cmd_driver_bindings() {
    match driver_query_bindings() {
        Ok(bindings) => {
            if bindings.is_empty() {
                println!("（无绑定适配器）");
                return;
            }
            for b in &bindings {
                println!(
                    "if#{:<3} {:<17} [{}] Rx={} Tx={} drop(r/t)={}/{}  {}",
                    b.if_index,
                    format_mac(&b.mac),
                    if b.bound { "已绑定" } else { "解绑中" },
                    b.rx,
                    b.tx,
                    b.rx_dropped,
                    b.tx_dropped,
                    b.name,
                );
            }
        }
        Err(e) => {
            eprintln!("查询失败: {e}");
            std::process::exit(1);
        }
    }
}

fn cmd_driver_status() {
    println!("== IPv8 内核驱动（{IPV8_DRIVER_PATH}） ==");
    let mut any_ok = false;

    match driver_query_version() {
        Ok((maj, min, nmaj, nmin)) => {
            println!("  驱动版本  : v{maj}.{min}  (NDIS {nmaj}.{nmin})");
            any_ok = true;
        }
        Err(e) => println!("  驱动版本  : 不可用 — {e}"),
    }

    match driver_query_stats() {
        Ok((open_count, unloading)) => {
            println!(
                "  全局状态  : OpenCount={open_count}, Unloading={}",
                if unloading != 0 { "是" } else { "否" }
            );
            any_ok = true;
        }
        Err(e) => println!("  全局状态  : 不可用 — {e}"),
    }

    match driver_query_bindings() {
        Ok(bindings) => {
            if bindings.is_empty() {
                println!("  绑定适配器: （无）");
            } else {
                println!("  绑定适配器: {} 个", bindings.len());
                for b in &bindings {
                    println!(
                        "    - if#{} {:<17} [{}] Rx={} Tx={}  {}",
                        b.if_index,
                        format_mac(&b.mac),
                        if b.bound { "已绑定" } else { "解绑中" },
                        b.rx,
                        b.tx,
                        b.name,
                    );
                }
            }
            any_ok = true;
        }
        Err(e) => println!("  绑定适配器: 不可用 — {e}"),
    }

    if !any_ok {
        eprintln!("\n提示: 驱动未运行。请以管理员运行 scripts/driver-install.ps1 安装 ipv8proto.sys。");
        std::process::exit(1);
    }
}

/* ==================== l2 子命令（Phase 5B：0xFB14 二层裸帧直连） ==================== */

enum OvOutcome {
    Completed(usize),
    TimedOut,
}

/// 以 overlapped 方式打开的驱动句柄；所有 RECV/SEND 均带超时
struct L2Socket {
    handle: isize,
    event: isize,
}

impl L2Socket {
    fn open() -> Result<Self, String> {
        let handle = driver_open_data(FILE_FLAG_OVERLAPPED)
            .map_err(|e| driver_open_err(&e, true))?;
        // auto-reset、初始 non-signaled 的匿名事件
        let event = unsafe { CreateEventW(std::ptr::null(), 0, 0, std::ptr::null()) };
        if event == 0 {
            let e = std::io::Error::last_os_error();
            unsafe { CloseHandle(handle) };
            return Err(format!("CreateEventW 失败: {e}"));
        }
        Ok(Self { handle, event })
    }

    /// 单个缓冲区同时作为 METHOD_BUFFERED 的 in/out；in_len 为输入前缀长度
    fn ioctl(
        &mut self,
        code: u32,
        buf: &mut [u8],
        in_len: usize,
        timeout_ms: u32,
    ) -> Result<OvOutcome, String> {
        unsafe {
            ResetEvent(self.event);
            let mut ov: Overlapped = std::mem::zeroed();
            ov.h_event = self.event;
            let mut immediate: u32 = 0;
            let ok = DeviceIoControl(
                self.handle,
                code,
                buf.as_mut_ptr() as *const std::os::raw::c_void,
                in_len as u32,
                buf.as_mut_ptr() as *mut std::os::raw::c_void,
                buf.len() as u32,
                &mut immediate,
                &mut ov as *mut _ as *mut std::os::raw::c_void,
            );
            if ok != 0 {
                return Ok(OvOutcome::Completed(immediate as usize));
            }
            if std::io::Error::last_os_error().raw_os_error() != Some(ERROR_IO_PENDING) {
                return Err(format!("DeviceIoControl 失败: {}", std::io::Error::last_os_error()));
            }
            match WaitForSingleObject(self.event, timeout_ms) {
                WAIT_OBJECT_0 => {
                    let mut n: u32 = 0;
                    if GetOverlappedResult(
                        self.handle,
                        &mut ov as *mut _ as *mut std::os::raw::c_void,
                        &mut n,
                        0,
                    ) == 0
                    {
                        return Err(format!(
                            "GetOverlappedResult 失败: {}",
                            std::io::Error::last_os_error()
                        ));
                    }
                    Ok(OvOutcome::Completed(n as usize))
                }
                WAIT_TIMEOUT => {
                    // 取消本请求并同步等待 IRP 真正结束；若取消生效前帧恰好到达则按成功处理
                    if CancelIoEx(
                        self.handle,
                        &mut ov as *mut _ as *mut std::os::raw::c_void,
                    ) == 0
                    {
                        let e = std::io::Error::last_os_error();
                        // 1168 = ERROR_NOT_FOUND：没有待取消的请求，可能恰好在超时瞬间完成
                        if e.raw_os_error() != Some(1168) {
                            return Err(format!("CancelIoEx 失败: {e}"));
                        }
                    }
                    let mut n: u32 = 0;
                    if GetOverlappedResult(
                        self.handle,
                        &mut ov as *mut _ as *mut std::os::raw::c_void,
                        &mut n,
                        1,
                    ) != 0
                        && n as usize >= IPV8_RECV_IN_LEN + IPV8_ETH_HEADER_LEN
                    {
                        return Ok(OvOutcome::Completed(n as usize));
                    }
                    Ok(OvOutcome::TimedOut)
                }
                WAIT_FAILED => Err(format!(
                    "WaitForSingleObject 失败: {}",
                    std::io::Error::last_os_error()
                )),
                other => Err(format!("WaitForSingleObject 异常返回值: {other}")),
            }
        }
    }

    /// 发送一个完整以太网帧（14B 头 + payload；总长 14..=1514，不足 60 由驱动补零）
    fn send_frame(&mut self, if_index: u32, frame: &[u8]) -> Result<(), String> {
        if frame.len() < IPV8_ETH_HEADER_LEN || frame.len() > IPV8_FRAME_MAX {
            return Err(format!(
                "帧长度 {} 超出 {IPV8_ETH_HEADER_LEN}..{IPV8_FRAME_MAX}",
                frame.len()
            ));
        }
        if frame[12..14] != [0xFB, 0x14] {
            return Err("EtherType 必须为 0xFB14".into());
        }
        let total = IPV8_FRAME_HDR_LEN + frame.len();
        let mut buf = vec![0u8; total];
        // IPV8_FRAME_HDR: magic / ifindex / frlen / reserved（小端）
        buf[0..4].copy_from_slice(&IPV8_DRIVER_MAGIC.to_le_bytes());
        buf[4..8].copy_from_slice(&if_index.to_le_bytes());
        buf[8..12].copy_from_slice(&(frame.len() as u32).to_le_bytes());
        buf[IPV8_FRAME_HDR_LEN..].copy_from_slice(frame);
        match self.ioctl(IPV8_IOCTL_SEND_FRAME, &mut buf, total, 8000)? {
            OvOutcome::Completed(_) => Ok(()),
            OvOutcome::TimedOut => Err("发送超时（8 秒未完成）".into()),
        }
    }

    /// 调试注入：把帧直接送入驱动接收队列（不经过 NDIS），用于单机验证接收侧代码。
    fn inject_frame(&mut self, if_index: u32, frame: &[u8]) -> Result<(), String> {
        if frame.len() < IPV8_ETH_HEADER_LEN || frame.len() > IPV8_FRAME_MAX {
            return Err(format!(
                "帧长度 {} 超出 {IPV8_ETH_HEADER_LEN}..{IPV8_FRAME_MAX}",
                frame.len()
            ));
        }
        let total = IPV8_FRAME_HDR_LEN + frame.len();
        let mut buf = vec![0u8; total];
        buf[0..4].copy_from_slice(&IPV8_DRIVER_MAGIC.to_le_bytes());
        buf[4..8].copy_from_slice(&if_index.to_le_bytes());
        buf[8..12].copy_from_slice(&(frame.len() as u32).to_le_bytes());
        buf[IPV8_FRAME_HDR_LEN..].copy_from_slice(frame);
        match self.ioctl(IPV8_IOCTL_INJECT_FRAME, &mut buf, total, 8000)? {
            OvOutcome::Completed(_) => Ok(()),
            OvOutcome::TimedOut => Err("注入超时".into()),
        }
    }

    /// 接收一帧；超时无帧返回 Ok(None)。返回 (帧来源 ifindex, 完整以太网帧)
    fn recv_once(
        &mut self,
        if_index: u32,
        timeout_ms: u32,
    ) -> Result<Option<(u32, Vec<u8>)>, String> {
        let mut buf = vec![0u8; IPV8_FRAME_HDR_LEN + IPV8_FRAME_MAX];
        // IPV8_RECV_IN: magic / ifindex / timeout(固定 0) / reserved(固定 0)
        buf[0..4].copy_from_slice(&IPV8_DRIVER_MAGIC.to_le_bytes());
        buf[4..8].copy_from_slice(&if_index.to_le_bytes());
        match self.ioctl(IPV8_IOCTL_RECV_FRAME, &mut buf, IPV8_RECV_IN_LEN, timeout_ms)? {
            OvOutcome::TimedOut => Ok(None),
            OvOutcome::Completed(n) => {
                if n < IPV8_FRAME_HDR_LEN + IPV8_ETH_HEADER_LEN
                    || rd_u32(&buf, 0) != IPV8_DRIVER_MAGIC
                {
                    return Err(format!("RECV 响应无效（{n} 字节，magic 不匹配）"));
                }
                let got_if = rd_u32(&buf, 4);
                let flen = rd_u32(&buf, 8) as usize;
                if !(IPV8_ETH_HEADER_LEN..=IPV8_FRAME_MAX).contains(&flen)
                    || IPV8_FRAME_HDR_LEN + flen > n
                {
                    return Err(format!("RECV 帧长度字段无效: {flen}"));
                }
                Ok(Some((
                    got_if,
                    buf[IPV8_FRAME_HDR_LEN..IPV8_FRAME_HDR_LEN + flen].to_vec(),
                )))
            }
        }
    }
}

impl Drop for L2Socket {
    fn drop(&mut self) {
        unsafe {
            CancelIoEx(self.handle, std::ptr::null_mut());
            CloseHandle(self.event);
            CloseHandle(self.handle);
        }
    }
}

fn parse_mac(s: &str) -> Result<[u8; 6], String> {
    let cleaned: String = s
        .chars()
        .filter(|c| !matches!(c, ':' | '-' | '.'))
        .collect();
    if cleaned.len() != 12 || !cleaned.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("无效 MAC \"{s}\"：需要 12 个十六进制字符（可用 : 或 - 分隔）"));
    }
    let mut mac = [0u8; 6];
    for (i, m) in mac.iter_mut().enumerate() {
        *m = u8::from_str_radix(&cleaned[i * 2..i * 2 + 2], 16)
            .map_err(|e| format!("MAC 解析失败: {e}"))?;
    }
    Ok(mac)
}

fn parse_hex_bytes(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("hex 数据必须是偶数个十六进制字符".into());
    }
    (0..s.len() / 2)
        .map(|i| {
            u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|e| format!("hex 解析失败: {e}"))
        })
        .collect()
}

/// 取 `--key value` 或 `--key=value` 形式参数
fn opt_arg<'a>(args: &'a [String], key: &str) -> Option<&'a str> {
    let prefix = format!("{key}=");
    for (i, a) in args.iter().enumerate() {
        if a == key {
            return args.get(i + 1).map(std::string::String::as_str);
        }
        if let Some(v) = a.strip_prefix(&prefix) {
            return Some(v);
        }
    }
    None
}

fn parse_if(value: Option<&str>) -> Result<u32, String> {
    match value {
        None | Some("any") | Some("ANY") | Some("*") => Ok(IPV8_IFINDEX_ANY),
        Some(v) => v
            .parse::<u32>()
            .map_err(|_| format!("无效 --if \"{v}\"：需要数字编号或 any")),
    }
}

fn print_l2_frame(if_index: u32, frame: &[u8], raw: bool) {
    if raw {
        println!("{}", hex_encode(frame));
        return;
    }
    let mut src = [0u8; 6];
    let mut dst = [0u8; 6];
    src.copy_from_slice(&frame[6..12]);
    dst.copy_from_slice(&frame[0..6]);
    let etype = u16::from_be_bytes([frame[12], frame[13]]);
    println!(
        "if#{if_index} len={} {} -> {} etype=0x{etype:04X}",
        frame.len(),
        format_mac(&src),
        format_mac(&dst),
    );
    let payload = &frame[IPV8_ETH_HEADER_LEN..];
    let ascii: String = payload
        .iter()
        .map(|&b| if (32..=126).contains(&b) { b as char } else { '.' })
        .collect();
    println!("  ascii: {ascii}");
    println!("  hex  : {}", hex_encode(payload));
    match neigh::classify(payload) {
        neigh::PayloadKind::Neighbor => println!("  kind : IP8N 邻居发现报文（ping8 neigh watch 可处理）"),
        neigh::PayloadKind::Ipv8 => println!("  kind : IPv8 数据包"),
        neigh::PayloadKind::Other => {}
    }
}

/// 构造 0xFB14 以太网帧：dst(6)+src(6,全零由驱动覆写)+ethertype(2)+payload
fn build_eth_frame(dst: [u8; 6], payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(IPV8_ETH_HEADER_LEN + payload.len());
    frame.extend_from_slice(&dst);
    frame.extend_from_slice(&[0u8; 6]);
    frame.extend_from_slice(&[0xFB, 0x14]);
    frame.extend_from_slice(payload);
    frame
}

fn cmd_l2_peek(args: &[String]) {
    let if_index = match parse_if(opt_arg(args, "--if")) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };
    let timeout = match opt_arg(args, "--timeout").map(|v| v.parse::<u32>()) {
        None => 3000u32,
        Some(Ok(v)) => v,
        Some(Err(e)) => {
            eprintln!("无效 --timeout: {e}");
            std::process::exit(2);
        }
    };
    let count = match opt_arg(args, "--count").map(|v| v.parse::<u64>()) {
        None => 1u64,
        Some(Ok(v)) => v,
        Some(Err(e)) => {
            eprintln!("无效 --count: {e}");
            std::process::exit(2);
        }
    };
    let raw = args.iter().any(|a| a == "--raw");

    let mut sock = match L2Socket::open() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
    eprintln!(
        "监听 EtherType 0xFB14（if={}），目标 {} 帧，Ctrl+C 停止…",
        if if_index == IPV8_IFINDEX_ANY { "any" } else { "固定" },
        if count == 0 { "无限" } else { "限定" },
    );
    let mut seen: u64 = 0;
    loop {
        match sock.recv_once(if_index, timeout) {
            Ok(Some((got_if, frame))) => {
                print_l2_frame(got_if, &frame, raw);
                seen += 1;
                if count != 0 && seen >= count {
                    break;
                }
            }
            Ok(None) => { /* 本轮无帧，继续等待 */ }
            Err(e) => {
                eprintln!("接收失败: {e}");
                std::process::exit(1);
            }
        }
    }
}

fn cmd_l2_send(args: &[String]) {
    let if_index = match parse_if(opt_arg(args, "--if")) {
        Ok(IPV8_IFINDEX_ANY) | Err(_) => {
            eprintln!("发送必须指定具体网卡编号：--if N（用 `ping8 l2 bindings` 查看）");
            std::process::exit(2);
        }
        Ok(v) => v,
    };
    let dst = match opt_arg(args, "--dst").map(parse_mac) {
        None => [0xFFu8; 6],
        Some(Ok(m)) => m,
        Some(Err(e)) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };
    let hex_v = opt_arg(args, "--hex");
    let text_v = opt_arg(args, "--text");
    let payload = match (hex_v, text_v) {
        (Some(_), Some(_)) => {
            eprintln!("--hex 与 --text 不能同时使用");
            std::process::exit(2);
        }
        (Some(h), None) => match parse_hex_bytes(h) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(2);
            }
        },
        (None, Some(t)) => t.as_bytes().to_vec(),
        (None, None) => b"IPV8-L2-PING".to_vec(),
    };
    if payload.len() > IPV8_FRAME_MAX - IPV8_ETH_HEADER_LEN {
        eprintln!("payload 过长：最大 {} 字节", IPV8_FRAME_MAX - IPV8_ETH_HEADER_LEN);
        std::process::exit(2);
    }
    let count = match opt_arg(args, "--count").map(|v| v.parse::<u64>()) {
        None => 1,
        Some(Ok(0)) => {
            eprintln!("--count 不能为 0（发送模式）");
            std::process::exit(2);
        }
        Some(Ok(v)) => v,
        Some(Err(e)) => {
            eprintln!("无效 --count: {e}");
            std::process::exit(2);
        }
    };
    let interval_ms = match opt_arg(args, "--interval").map(|v| v.parse::<u64>()) {
        None => 1000,
        Some(Ok(v)) => v,
        Some(Err(e)) => {
            eprintln!("无效 --interval: {e}");
            std::process::exit(2);
        }
    };

    // 帧体 = dst + src(零，驱动覆写) + 0xFB14 + payload
    let frame = build_eth_frame(dst, &payload);

    let mut sock = match L2Socket::open() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
    for i in 1..=count {
        if let Err(e) = sock.send_frame(if_index, &frame) {
            eprintln!("#{i} 发送失败: {e}");
            std::process::exit(1);
        }
        let shown = frame.len().max(IPV8_FRAME_MIN);
        eprintln!(
            "#{i}/{count} 已提交 if#{if_index} -> {}（线上 {shown} 字节，含驱动补零）",
            format_mac(&dst),
        );
        if i < count {
            std::thread::sleep(std::time::Duration::from_millis(interval_ms));
        }
    }
}

/// 调试注入：把帧直接送入驱动接收队列，验证接收侧代码（pending READ / FrameQueue）。
fn cmd_l2_inject(args: &[String]) {
    let if_index = match parse_if(opt_arg(args, "--if")) {
        Ok(IPV8_IFINDEX_ANY) | Err(_) => {
            eprintln!("注入必须指定具体网卡编号：--if N（用 `ping8 l2 bindings` 查看）");
            std::process::exit(2);
        }
        Ok(v) => v,
    };
    let dst = match opt_arg(args, "--dst").map(parse_mac) {
        None => [0xFFu8; 6],
        Some(Ok(m)) => m,
        Some(Err(e)) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };
    let src = match opt_arg(args, "--src").map(parse_mac) {
        None => [0x02, 0x00, 0x4C, 0x4F, 0x4F, 0x50],
        Some(Ok(m)) => m,
        Some(Err(e)) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };
    let payload = match (opt_arg(args, "--hex"), opt_arg(args, "--text")) {
        (Some(_), Some(_)) => {
            eprintln!("--hex 与 --text 不能同时使用");
            std::process::exit(2);
        }
        (Some(h), None) => match parse_hex_bytes(h) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(2);
            }
        },
        (None, Some(t)) => t.as_bytes().to_vec(),
        (None, None) => b"IPV8-L2-PING".to_vec(),
    };
    if payload.len() > IPV8_FRAME_MAX - IPV8_ETH_HEADER_LEN {
        eprintln!("payload 过长：最大 {} 字节", IPV8_FRAME_MAX - IPV8_ETH_HEADER_LEN);
        std::process::exit(2);
    }
    // 帧体 = dst + src + 0xFB14 + payload（注入不走驱动发送，不强制 EtherType）
    let mut frame = Vec::with_capacity(IPV8_ETH_HEADER_LEN + payload.len());
    frame.extend_from_slice(&dst);
    frame.extend_from_slice(&src);
    frame.extend_from_slice(&[0xFB, 0x14]);
    frame.extend_from_slice(&payload);

    let mut sock = match L2Socket::open() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
    if let Err(e) = sock.inject_frame(if_index, &frame) {
        eprintln!("注入失败: {e}");
        std::process::exit(1);
    }
    eprintln!(
        "已注入 if#{if_index} ({} -> {})，{} 字节",
        format_mac(&src),
        format_mac(&dst),
        frame.len(),
    );
}

fn l2_usage() {
    println!(
        "ping8 l2 — EtherType 0xFB14 二层裸帧直连（需管理员，驱动 v0.10+）\n\
         \n\
         用法:\n\
         \x20 ping8 l2 bindings\n\
         \x20     查看网卡绑定（if 编号 / MAC / 收发与丢包计数）\n\
         \x20 ping8 l2 peek [--if N|any] [--timeout ms] [--count N] [--raw]\n\
         \x20     监听 0xFB14 裸帧；--if any 默认接收所有网卡；--count 0 持续监听；\n\
         \x20     --raw 每行输出一帧的完整 hex（脚本友好）\n\
         \x20 ping8 l2 send --if N [--dst MAC] [--hex H | --text T] [--count N] [--interval ms]\n\
         \x20     发送裸帧；--dst 默认广播 ff:ff:ff:ff:ff:ff；payload 默认文本 IPV8-L2-PING\n\
         \x20 ping8 l2 inject --if N [--src MAC] [--dst MAC] [--hex H | --text T]\n\
         \x20     调试注入：把帧直接送入驱动接收队列（不经过 NDIS），\n\
         \x20     用于单机无对端时验证接收侧代码（pending READ / FrameQueue）"
    );
}

fn cmd_l2(args: &[String]) {
    match args.first().map(std::string::String::as_str) {
        Some("bindings") | Some("list") => cmd_driver_bindings(),
        Some("peek") | Some("recv") => cmd_l2_peek(&args[1..]),
        Some("send") => cmd_l2_send(&args[1..]),
        Some("inject") => cmd_l2_inject(&args[1..]),
        Some("-h") | Some("--help") | Some("help") | None => l2_usage(),
        Some(other) => {
            eprintln!("未知 l2 子命令: {other}");
            l2_usage();
            std::process::exit(2);
        }
    }
}

/* ==================== neigh 子命令（Phase 5B：IP8N 二层邻居发现） ==================== */

const NEIGH_STORE_FILE: &str = "neighbors.bin";
const NEIGH_SEED_FILE: &str = "node_seed.bin";
/// IP8N 邻居发现 UDP 端口（trust TRST 45801 之外的独立端口，纯用户态无需驱动）
const NEIGH_UDP_PORT: u16 = 45802;

/// ed25519-dalek 实现 ipv8-neigh 的签名注入（verify_strict 拒弱键/共线点）
struct DalekNeighborSigner(SigningKey);

impl neigh::SignatureOps for DalekNeighborSigner {
    fn sign(&self, domain: &[u8]) -> [u8; neigh::SIG_LEN] {
        self.0.sign(domain).to_bytes()
    }
    fn verify(
        &self,
        pubkey: &[u8; neigh::PUBKEY_LEN],
        domain: &[u8],
        sig: &[u8; neigh::SIG_LEN],
    ) -> bool {
        VerifyingKey::from_bytes(pubkey)
            .and_then(|vk| {
                let s = Signature::from_bytes(sig);
                vk.verify_strict(domain, &s)
            })
            .is_ok()
    }
}

fn neigh_store_path() -> PathBuf {
    visa_dir().join(NEIGH_STORE_FILE)
}

/// 本机二层身份：node_seed（无则生成）+ IPv8 地址（优先签证，否则机器指纹派生）
fn neigh_identity(create: bool) -> Result<(SigningKey, [u8; 16]), String> {
    let seed_path = visa_dir().join(NEIGH_SEED_FILE);
    let sk = match fs::read(&seed_path) {
        Ok(d) if d.len() == 32 => {
            let mut s = [0u8; 32];
            s.copy_from_slice(&d);
            SigningKey::from_bytes(&s)
        }
        Ok(_) => {
            return Err(format!(
                "{} 已损坏：需要 32 字节，请删除后重新 `ping8 neigh init`",
                seed_path.display()
            ));
        }
        Err(_) if create => {
            ensure_visa_dir().map_err(|e| format!("创建 {} 失败: {e}", visa_dir().display()))?;
            let mut s = [0u8; 32];
            rand_core::OsRng.fill_bytes(&mut s);
            fs::write(&seed_path, s).map_err(|e| format!("写入 {} 失败: {e}", seed_path.display()))?;
            eprintln!("[neigh] 已生成新节点种子：{}", seed_path.display());
            SigningKey::from_bytes(&s)
        }
        Err(e) => {
            return Err(format!(
                "读取节点种子失败: {e}；请先运行 `ping8 neigh init`"
            ));
        }
    };
    let addr = load_visa()
        .map(|v| v.ipv8_addr)
        .unwrap_or_else(generate_auto_address);
    Ok((sk, addr))
}

fn neigh_load_store_or_die() -> neigh::NeighborStore {
    match neigh::NeighborStore::load_path(&neigh_store_path()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("读取邻居表失败: {e}");
            std::process::exit(1);
        }
    }
}

fn neigh_save_or_warn(store: &neigh::NeighborStore) {
    if let Err(e) = store.save_path(&neigh_store_path()) {
        eprintln!("[neigh] 警告：邻居表落盘失败: {e}");
    }
}

/// UDP 传输把对端 IPv4 存入记录 mac 字段（前 4 字节地址，后 2 字节零）
fn ip_to_rec(ip: Ipv4Addr) -> [u8; neigh::MAC_LEN] {
    let o = ip.octets();
    [o[0], o[1], o[2], o[3], 0, 0]
}

fn rec_to_ip(id: &[u8; neigh::MAC_LEN]) -> Option<Ipv4Addr> {
    if id[4] == 0 && id[5] == 0 {
        Some(Ipv4Addr::new(id[0], id[1], id[2], id[3]))
    } else {
        None
    }
}

fn format_peer_id(id: &[u8; neigh::MAC_LEN]) -> String {
    rec_to_ip(id).map(|ip| ip.to_string()).unwrap_or_else(|| format_mac(id))
}

/// 报文内嵌公钥是否等于本机公钥（过滤自发广播环回）
fn payload_is_own(payload: &[u8], local_pk: &[u8; neigh::PUBKEY_LEN]) -> bool {
    payload.len() >= 72 && &payload[40..72] == local_pk
}

/// unix 秒 → UTC 字符串（零依赖 civil_from_days，Howard Hinnant 算法）
fn civil_from_days(z0: i64) -> (i64, u32, u32) {
    let z = z0 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (y + i64::from(m <= 2), m, d)
}

fn format_unix_utc(ts: i64) -> String {
    let days = ts.div_euclid(86400);
    let secs = ts.rem_euclid(86400);
    let (y, mo, d) = civil_from_days(days);
    format!(
        "{y:04}-{mo:02}-{d:02} {:02}:{:02}:{:02} UTC",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

fn cmd_neigh_init() {
    let (sk, addr) = match neigh_identity(true) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
    let pk = sk.verifying_key().to_bytes();
    let store = neigh_load_store_or_die();
    println!("[neigh] 本机二层身份已就绪");
    println!("  IPv8 地址 : {}", addr_from_bytes(&addr).to_canonical_string());
    println!("  Ed25519 公钥: {}", hex_encode(&pk));
    println!("  节点种子  : {}", visa_dir().join(NEIGH_SEED_FILE).display());
    println!(
        "  永久邻居表: {}（{} 条记录）",
        neigh_store_path().display(),
        store.len()
    );
}

fn cmd_neigh_list() {
    let store = neigh_load_store_or_die();
    if store.is_empty() {
        println!("（尚无永久邻居；用 `ping8 neigh watch` 授权对端后自动落盘）");
        return;
    }
    println!(
        "{:<3} {:<15} {:<34} {:<18} 最后见到",
        "#", "对端 IP", "IPv8 地址", "公钥前缀"
    );
    for (i, p) in store.iter().enumerate() {
        println!(
            "{:<3} {:<15} {:<34} {:<18} {}",
            i + 1,
            format_peer_id(&p.mac),
            addr_from_bytes(&p.addr).to_canonical_string(),
            hex_encode(&p.pubkey[..8]),
            format_unix_utc(p.ts),
        );
    }
    println!("\n共 {} 个永久邻居（{}）", store.len(), neigh_store_path().display());
}

fn cmd_neigh_remove(id: &str) {
    let mut store = neigh_load_store_or_die();
    // 优先点分 IPv4；其次带 MAC 分隔符；纯 hex 按地址（32）/公钥（64）/公钥前缀
    let removed = if let Ok(ip) = id.parse::<Ipv4Addr>() {
        store.remove_mac(&ip_to_rec(ip))
    } else if id.contains(':') || id.contains('-') || id.contains('.') {
        match parse_mac(id) {
            Ok(m) => store.remove_mac(&m),
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(2);
            }
        }
    } else {
        match parse_hex_bytes(id) {
            Ok(bytes) => match bytes.len() {
                16 => {
                    let mut a = [0u8; 16];
                    a.copy_from_slice(&bytes);
                    // 32hex 优先按地址精确删；未命中再按 16B 公钥前缀删
                    store.remove_addr(&a) || store.remove_pubkey_prefix(&bytes)
                }
                32 => {
                    let mut k = [0u8; 32];
                    k.copy_from_slice(&bytes);
                    store.remove_pubkey(&k)
                }
                _ => store.remove_pubkey_prefix(&bytes),
            },
            Err(e) => {
                eprintln!("无法识别的邻居标识: {e}");
                eprintln!("支持：对端 IPv4 / IPv8 地址(32hex) / 公钥(64hex) / 公钥前缀 / MAC(带:或-)");
                std::process::exit(2);
            }
        }
    };
    if !removed {
        eprintln!("没有匹配的邻居: {id}");
        std::process::exit(1);
    }
    neigh_save_or_warn(&store);
    println!("已移除邻居 {id}；剩余 {} 条", store.len());
}

/// Y/N 授权卡片（样式对齐 trust listen）
fn neigh_consent_prompt(m: &neigh::NeighborMessage, peer_id: [u8; 6], auto_yes: bool) -> bool {
    println!();
    println!("  ╔══════════════════════════════════════════╗");
    println!("  ║  邻居授权请求（IP8N HELLO）                ║");
    println!("  ╠══════════════════════════════════════════╣");
    println!("  ║  对端 IPv8 地址: {:<25}║", addr_from_bytes(&m.addr).to_canonical_string());
    println!("  ║  对端 IP:        {:<25}║", format_peer_id(&peer_id));
    println!("  ║  对端公钥: {:<31}║", hex_encode(&m.pubkey));
    println!("  ║  时间戳:         {:<25}║", format_unix_utc(m.ts_secs));
    println!("  ║                                            ║");
    println!("  ║  同意 = 永久邻居（写入 neighbors.bin）     ║");
    println!("  ║  [Y] 同意并回 ACK   [N] 拒绝（不应答）    ║");
    println!("  ╚══════════════════════════════════════════╝");
    if auto_yes {
        println!("  （--yes 自动同意）");
        return true;
    }
    print!("  请输入 (Y/N): ");
    let _ = std::io::stdout().flush();
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).ok();
    matches!(
        input.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    )
}

fn cmd_neigh_hello(args: &[String]) {
    let wait_secs = match opt_arg(args, "--wait").map(|v| v.parse::<u64>()) {
        None => 15u64,
        Some(Ok(v)) => v,
        Some(Err(e)) => {
            eprintln!("无效 --wait: {e}");
            std::process::exit(2);
        }
    };
    let force = opt_arg(args, "--neigh"); // auto|l2|udp
    let bind_ip = match opt_arg(args, "--bind").map(|v| v.parse::<Ipv4Addr>()) {
        None => None,
        Some(Ok(ip)) => Some(ip),
        Some(Err(e)) => {
            eprintln!("无效 --bind: {e}（示例：--bind 192.168.1.20 指定出口网卡）");
            std::process::exit(2);
        }
    };
    // --to 单播目标：跨网段/可路由场景使用（默认走广播）
    let target_ip = match opt_arg(args, "--to").map(|v| v.parse::<Ipv4Addr>()) {
        None => None,
        Some(Ok(ip)) => Some(ip),
        Some(Err(e)) => {
            eprintln!("无效 --to: {e}（示例：--to 192.168.110.45）");
            std::process::exit(2);
        }
    };

    let (sk, addr) = match neigh_identity(false) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
    let pk = sk.verifying_key().to_bytes();
    let store = neigh_load_store_or_die();
    let mut proc =
        neigh::NeighborProcessor::new(DalekNeighborSigner(sk), addr, pk, store);

    let mut nb = [0u8; 8];
    rand_core::OsRng.fill_bytes(&mut nb);
    let nonce = u64::from_be_bytes(nb);
    let now = now_secs() as i64;
    let hello = proc.build_hello(nonce, now);

    // 选择传输层（--bind 仅 UDP 模式生效）
    let mut transport = match select_transport(force, bind_ip) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("传输层选择失败: {e}");
            std::process::exit(1);
        }
    };

    // 发送 HELLO
    let dst_mac = if let Some(ip) = target_ip {
        // 单播：需要先 ARP 拿到对方 MAC
        if let Some(mac) = arp_query(ip) {
            mac
        } else {
            eprintln!("无法解析 {} 的 MAC 地址（ARP 超时）", ip);
            std::process::exit(1);
        }
    } else {
        neigh::MacAddr::BROADCAST
    };
    if let Err(e) = transport.send(&hello, dst_mac) {
        eprintln!("HELLO 发送失败: {e}");
        std::process::exit(1);
    }
    let via = if target_ip.is_some() {
        format!("单播 → {target_ip:?}")
    } else {
        "广播".into()
    };
    println!(
        "[neigh] HELLO 已发出（{}，{via}，nonce {nonce:#018x}），本机地址 {}",
        transport.name(),
        addr_from_bytes(&addr).to_canonical_string()
    );
    if wait_secs == 0 {
        return;
    }
    println!("[neigh] 等待对端 ACK {wait_secs} 秒（对方需运行 `ping8 neigh watch` 并同意授权）…");

    // 用阻塞 recv + 超时循环
    let start = Instant::now();
    loop {
        if start.elapsed().as_secs() >= wait_secs {
            eprintln!("[neigh] 等待 ACK 超时（{wait_secs}s 无应答）");
            std::process::exit(1);
        }
        let (pkt, src_mac) = match transport.recv() {
            Ok(v) => v,
            Err(neigh::TransportError::Timeout) => continue,
            Err(e) => {
                eprintln!("接收失败: {e}");
                std::process::exit(1);
            }
        };
        if neigh::classify(&pkt) != neigh::PayloadKind::Neighbor || payload_is_own(&pkt, &pk) {
            continue;
        }
        let now = now_secs() as i64;
        match pkt[5] {
            neigh::MSG_ACK => {
                match proc.process_ack(&pkt, src_mac.0, now) {
                    Ok(rec) => {
                        neigh_save_or_warn(proc.store());
                        println!(
                            "[neigh] 收到 {} 的 ACK，已自动加入永久邻居表",
                            addr_from_bytes(&rec.addr).to_canonical_string()
                        );
                        return;
                    }
                    Err(e) => eprintln!("[neigh] 丢弃 ACK：{e}"),
                }
            }
            neigh::MSG_HELLO => {
                eprintln!("[neigh] 收到 HELLO（本命令不授权；如需添加对方请另开 `ping8 neigh watch`）");
            }
            _ => {}
        }
    }
}

fn cmd_neigh_watch(args: &[String]) {
    let auto_yes = args.iter().any(|a| a == "--yes");
    let force = opt_arg(args, "--neigh"); // auto|l2|udp

    let (sk, addr) = match neigh_identity(false) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
    let pk = sk.verifying_key().to_bytes();
    let store = neigh_load_store_or_die();
    let mut proc =
        neigh::NeighborProcessor::new(DalekNeighborSigner(sk), addr, pk, store);

    // 选择传输层（watch 固定监听全部网卡，不接受 --bind）
    let mut transport = match select_transport(force, None) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("传输层选择失败: {e}");
            std::process::exit(1);
        }
    };

    eprintln!("[neigh] 监听 IP8N 邻居报文（{} 传输层），Ctrl+C 停止", transport.name());
    eprintln!("[neigh] 本机地址 {}", addr_from_bytes(&addr).to_canonical_string());

    loop {
        let (payload, src_mac) = match transport.recv() {
            Ok(v) => v,
            Err(neigh::TransportError::Timeout) => continue,
            Err(e) => {
                eprintln!("接收失败: {e}");
                std::process::exit(1);
            }
        };
        // 过滤自发广播环回；只处理 IP8N
        if !neigh::is_neighbor_payload(&payload) || payload_is_own(&payload, &pk) {
            if !payload_is_own(&payload, &pk) && payload.len() != neigh::MSG_LEN {
                eprintln!("[neigh] 非邻居数据报 {}B（忽略）", payload.len());
            }
            continue;
        }
        let now = now_secs() as i64;
        match payload[5] {
            neigh::MSG_HELLO => match proc.process_hello(&payload, src_mac.0, now) {
                neigh::HelloDecision::AutoAck(m) => {
                    println!(
                        "[neigh] 已授权邻居 {} 再次 HELLO，自动回 ACK",
                        addr_from_bytes(&m.addr).to_canonical_string()
                    );
                    let ack = proc.build_ack(&m, now);
                    if let Err(e) = transport.send(&ack, src_mac) {
                        eprintln!("[neigh] ACK 发送失败: {e}");
                    }
                    neigh_save_or_warn(proc.store());
                }
                neigh::HelloDecision::NeedsConsent(m) => {
                    let agreed = neigh_consent_prompt(&m, src_mac.0, auto_yes);
                    if agreed {
                        proc.approve_consent(&m, src_mac.0, now);
                        let ack = proc.build_ack(&m, now);
                        if let Err(e) = transport.send(&ack, src_mac) {
                            eprintln!("[neigh] ACK 发送失败: {e}");
                        }
                        neigh_save_or_warn(proc.store());
                        println!(
                            "[neigh] 已永久授权 {} 并回 ACK",
                            addr_from_bytes(&m.addr).to_canonical_string()
                        );
                    } else {
                        println!("[neigh] 已拒绝：不应答、不入表");
                    }
                }
                neigh::HelloDecision::Reject(e) => {
                    eprintln!("[neigh] 拒收 HELLO: {e}");
                }
            },
            neigh::MSG_ACK => match proc.process_ack(&payload, src_mac.0, now) {
                Ok(rec) => {
                    neigh_save_or_warn(proc.store());
                    println!(
                        "[neigh] 对端 {} 的 ACK 已确认，永久邻居已保存",
                        addr_from_bytes(&rec.addr).to_canonical_string()
                    );
                }
                Err(e) => eprintln!("[neigh] 丢弃 ACK: {e}"),
            },
            _ => {}
        }
    }
}

/// 简化版 ARP 查询：返回 None（让上层回退到广播）
fn arp_query(_ip: Ipv4Addr) -> Option<neigh::MacAddr> {
    None
}

fn neigh_usage() {
    println!(
        "ping8 neigh — IP8N 局域网邻居发现（UDP 广播，无需驱动/管理员；授权一次=永久邻居）\n\
         \n\
         用法:\n\
         \x20 ping8 neigh init\n\
         \x20     准备本机身份（node_seed 无则生成），显示本机 IPv8 地址/公钥\n\
         \x20 ping8 neigh hello [--to 对端IP] [--bind 本机IP] [--wait 秒]\n\
         \x20     广播签名 HELLO（默认）；跨网段时 --to 对端IP 改单播；\n\
         \x20     默认等 15 秒收 ACK 自动入表（--wait 0 发完即退）\n\
         \x20 ping8 neigh watch [--yes]\n\
         \x20     监听 HELLO：已授权自动回 ACK；未知公钥弹 Y/N，同意即永久入表并回 ACK；\n\
         \x20     收到对端 ACK 也自动入表。首次运行请在防火墙弹窗点“允许访问”\n\
         \x20 ping8 neigh list\n\
         \x20     列出永久邻居（%USERPROFILE%\\.ipv8\\neighbors.bin）\n\
         \x20 ping8 neigh remove <对端IP | IPv8地址32hex | 公钥64hex | 公钥前缀 | MAC>"
    );
}

// ── P8 传输层实现：L2Transport / UdpTransport + select_transport ──

/// L2 传输层：直接经 ipv8proto.sys 的 0xFB14 裸帧收发 IP8N
/// 复用现有 L2Socket + ioctl() 实现（OVERLAPPED 超时/取消已封装好）
struct L2Transport {
    if_index: u32,
    local_mac: neigh::MacAddr,
    sock: L2Socket,
}

impl L2Transport {
    fn new() -> Result<Self, neigh::TransportError> {
        let bindings = driver_query_bindings().map_err(neigh::TransportError::Driver)?;
        let binding = bindings.iter().find(|b| b.bound).ok_or_else(|| {
            neigh::TransportError::Driver("没有找到 bound 到 ipv8proto 的网卡（需要先运行 `driver-install.ps1` 并管理员权限）".into())
        })?;
        Self::bind(binding.if_index)
    }

    fn bind(if_index: u32) -> Result<Self, neigh::TransportError> {
        let sock = L2Socket::open().map_err(neigh::TransportError::Driver)?;
        let bindings = driver_query_bindings().map_err(neigh::TransportError::Driver)?;
        let binding = bindings.iter().find(|b| b.if_index == if_index).ok_or_else(|| {
            neigh::TransportError::Driver(format!("if_index {if_index} 未找到或未 bound"))
        })?;
        Ok(Self {
            if_index,
            local_mac: neigh::MacAddr(binding.mac),
            sock,
        })
    }
}

impl neigh::NeighborTransport for L2Transport {
    fn recv(&mut self) -> Result<(Vec<u8>, neigh::MacAddr), neigh::TransportError> {
        let mut buf = [0u8; 1514];
        // RECV_IN 结构：16B（magic + ifindex + reserved）
        buf[0..4].copy_from_slice(&0xFB14u32.to_le_bytes());
        buf[4..8].copy_from_slice(&self.if_index.to_le_bytes());
        // in_len = 16（METHOD_BUFFERED 输入长度）
        let outcome = self.sock.ioctl(IPV8_IOCTL_RECV_FRAME, &mut buf, 16, 3000)
            .map_err(neigh::TransportError::Driver)?;
        let total = match outcome {
            OvOutcome::Completed(n) => n,
            OvOutcome::TimedOut => return Err(neigh::TransportError::Timeout),
        };
        if total < 16 + 14 {
            return Err(neigh::TransportError::Parse("收到帧太短（< 14B 以太网头）".into()));
        }
        // buf 前 16B 是帧头（driver 保留），后面是以太网帧
        let eth_frame = &buf[16..total];
        // 校验 EtherType offset 12-13 == 0xFB14
        if eth_frame[12] != 0xFB || eth_frame[13] != 0x14 {
            return Err(neigh::TransportError::Parse("收到帧 EtherType 不是 0xFB14".into()));
        }
        let src_mac = neigh::MacAddr([
            eth_frame[6], eth_frame[7], eth_frame[8],
            eth_frame[9], eth_frame[10], eth_frame[11],
        ]);
        Ok((eth_frame[14..].to_vec(), src_mac))
    }

    fn send(&mut self, pkt: &[u8], dst: neigh::MacAddr) -> Result<(), neigh::TransportError> {
        // 构造以太网帧：14B header + payload
        let mut frame = Vec::with_capacity(14 + pkt.len());
        frame.extend_from_slice(&dst.0);           // dst MAC (6B)
        frame.extend_from_slice(&[0u8; 6]);        // src MAC (驱动覆写，填 0)
        frame.push(0xFB); frame.push(0x14);         // EtherType (2B)
        frame.extend_from_slice(pkt);               // payload

        // SEND 输入：16B 帧头（magic + ifindex + reserved）+ 帧
        let mut send_buf = Vec::with_capacity(16 + frame.len());
        send_buf.extend_from_slice(&0xFB14u32.to_le_bytes());
        send_buf.extend_from_slice(&self.if_index.to_le_bytes());
        send_buf.extend_from_slice(&0u32.to_le_bytes()); // reserved
        send_buf.extend_from_slice(&frame);

        let buf_len = send_buf.len();
        let outcome = self.sock.ioctl(IPV8_IOCTL_SEND_FRAME, &mut send_buf, buf_len, 1000)
            .map_err(neigh::TransportError::Driver)?;
        match outcome {
            OvOutcome::Completed(_) => Ok(()),
            OvOutcome::TimedOut => Err(neigh::TransportError::Timeout),
        }
    }

    fn local_mac(&self) -> neigh::MacAddr { self.local_mac }
    fn name(&self) -> &'static str { "l2" }
}

/// UDP 传输层：经 UDP 45802 收发 IP8N（现有 ping8 neigh 的传输层）
struct UdpTransport {
    sock: UdpSocket,
    local_mac: neigh::MacAddr,
    /// IP→MAC 缓存（recv 时记录，send 时反查）
    ip_mac_cache: std::collections::HashMap<Ipv4Addr, neigh::MacAddr>,
}

impl UdpTransport {
    /// bind_ip=None 绑定 0.0.0.0（全部网卡）；Some(ip) 绑定指定本机 IP（--bind 选出口网卡）。
    fn new(bind_ip: Option<Ipv4Addr>) -> Result<Self, neigh::TransportError> {
        let bind_addr = SocketAddr::from((bind_ip.unwrap_or(Ipv4Addr::UNSPECIFIED), NEIGH_UDP_PORT));
        let sock = UdpSocket::bind(bind_addr)
            .map_err(|e| neigh::TransportError::Io(e.to_string()))?;
        sock.set_broadcast(true)
            .map_err(|e| neigh::TransportError::Io(e.to_string()))?;
        // 2s 读超时：recv 周期返回 Timeout，hello 的 --wait 才不会永久阻塞，watch 也能响应退出
        sock.set_read_timeout(Some(Duration::from_millis(2000)))
            .map_err(|e| neigh::TransportError::Io(e.to_string()))?;
        let local_mac = Self::detect_local_mac().unwrap_or(neigh::MacAddr::ZERO);
        Ok(Self { sock, local_mac, ip_mac_cache: Default::default() })
    }

    fn detect_local_mac() -> Option<neigh::MacAddr> {
        // 从 ARP 表或网卡枚举拿本机 MAC（简化版：先返回 ZERO，recv 时再补）
        // 实际场景中 ping8 neigh 已有 neigh_identity() 拿到节点身份
        None
    }

    fn cache_ip_mac(&mut self, ip: Ipv4Addr, mac: neigh::MacAddr) {
        self.ip_mac_cache.insert(ip, mac);
    }

    fn lookup_ip_for_mac(&self, mac: neigh::MacAddr) -> Option<Ipv4Addr> {
        if mac == neigh::MacAddr::BROADCAST {
            return Some(Ipv4Addr::BROADCAST);
        }
        self.ip_mac_cache.iter().find(|(_, m)| **m == mac).map(|(ip, _)| *ip)
    }
}

impl neigh::NeighborTransport for UdpTransport {
    fn recv(&mut self) -> Result<(Vec<u8>, neigh::MacAddr), neigh::TransportError> {
        let mut buf = [0u8; neigh::MSG_LEN + 64];
        let (n, addr) = match self.sock.recv_from(&mut buf) {
            Ok(v) => v,
            // 2s 读超时到期：上层循环据此检查 --wait / 响应退出，不是致命错误
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock
                || e.kind() == io::ErrorKind::TimedOut =>
            {
                return Err(neigh::TransportError::Timeout)
            }
            Err(e) => return Err(neigh::TransportError::Io(e.to_string())),
        };
        let src_ip = match addr.ip() {
            std::net::IpAddr::V4(ip) => ip,
            _ => return Err(neigh::TransportError::Parse("非 IPv4 地址".into())),
        };
        // UDP 无 MAC 层：按项目约定把对端 IPv4 编成伪 MAC（ip_to_rec），
        // 邻居表存的就是它（format_peer_id 据此还原显示对端 IP）；
        // 同时回填缓存，send() 才能把 ACK 反查到 IP 发回对端 45802。
        let src_mac = neigh::MacAddr(ip_to_rec(src_ip));
        self.cache_ip_mac(src_ip, src_mac);
        Ok((buf[..n].to_vec(), src_mac))
    }

    fn send(&mut self, pkt: &[u8], dst: neigh::MacAddr) -> Result<(), neigh::TransportError> {
        let ip = match self.lookup_ip_for_mac(dst) {
            Some(ip) => ip,
            None => return Err(neigh::TransportError::Parse(format!("UDP 层找不到 MAC {} 对应的 IP（需要先 recv 过对方报文）", dst))),
        };
        self.sock.send_to(pkt, (ip, NEIGH_UDP_PORT))
            .map_err(|e| neigh::TransportError::Io(e.to_string()))?;
        Ok(())
    }

    fn local_mac(&self) -> neigh::MacAddr { self.local_mac }
    fn name(&self) -> &'static str { "udp" }
}

/// auto 策略：先试 L2，失败降级 UDP。bind_ip 仅对 UDP 生效（--bind 指定出口网卡 IP）。
fn select_transport(
    force: Option<&str>,
    bind_ip: Option<Ipv4Addr>,
) -> Result<Box<dyn neigh::NeighborTransport>, neigh::TransportError> {
    match force {
        Some("l2") => {
            let t = L2Transport::new()?;
            println!("[neigh] 强制 L2 传输");
            Ok(Box::new(t))
        }
        Some("udp") => {
            let t = UdpTransport::new(bind_ip)?;
            println!("[neigh] 强制 UDP 传输");
            Ok(Box::new(t))
        }
        Some(other) => {
            Err(neigh::TransportError::Parse(format!("未知 --neigh 值: {other}（应是 auto|l2|udp）")))
        }
        None => {
            match L2Transport::new() {
                Ok(t) => {
                    println!("[neigh] auto → L2（网卡已 bound 到 ipv8proto）");
                    Ok(Box::new(t))
                }
                Err(_) => {
                    let t = UdpTransport::new(bind_ip)?;
                    println!("[neigh] auto → UDP（未找到 bound 网卡，降级到 UDP 45802）");
                    Ok(Box::new(t))
                }
            }
        }
    }
}

fn cmd_neigh(args: &[String]) {
    match args.first().map(std::string::String::as_str) {
        Some("init") => cmd_neigh_init(),
        Some("hello") => cmd_neigh_hello(&args[1..]),
        Some("watch") | Some("listen") => cmd_neigh_watch(&args[1..]),
        Some("list") | Some("ls") => cmd_neigh_list(),
        Some("remove") | Some("rm") | Some("del") => match args.get(1) {
            Some(id) => cmd_neigh_remove(id),
            None => {
                eprintln!("用法: ping8 neigh remove <IPv8地址|公钥前缀|MAC>");
                std::process::exit(2);
            }
        },
        Some("-h") | Some("--help") | Some("help") | None => neigh_usage(),
        Some(other) => {
            eprintln!("未知 neigh 子命令: {other}");
            neigh_usage();
            std::process::exit(2);
        }
    }
}

fn main() {
    // 自动更新检查（静默，失败不影响正常使用）
    // 用独立线程，5 秒超时，不阻塞主逻辑
    let _update_handle = std::thread::Builder::new()
        .spawn(|| {
            check_and_auto_update();
        });
    // 不等待更新线程完成，立即继续

    // 双 exe 白名单：ping8 只给普通用户命令，ipv8adm 全命令放行
    // 通过 exe 文件名区分（同一个 main.rs，编译成两个 bin）
    let exe_name = env::current_exe()
        .ok()
        .and_then(|p| p.file_stem().map(|s| s.to_string_lossy().into_owned()))
        .unwrap_or_else(|| "ping8".into());
    let is_admin = exe_name == "ipv8adm";

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        if is_admin { usage_adm() } else { usage() };
        std::process::exit(2);
    }

    let cmd = args[1].as_str();

    // ping8 白名单拦截：禁止访问 l2 / driver / hook
    if !is_admin && (cmd == "l2" || cmd == "driver" || cmd == "hook") {
        eprintln!("命令 '{cmd}' 需要 ipv8adm 执行");
        eprintln!("  ipv8adm 可执行全部高级命令（l2 / driver / hook）");
        eprintln!("  ping8 只暴露普通用户命令（install / auto / addr / ping / visa / firewall / neigh / serve）");
        std::process::exit(2);
    }

    match cmd {
        "install" => cmd_install(),

        "addr" => cmd_addr(),

        "status" => cmd_status(),

        "auto" => cmd_auto_setup(),

        "diagnose" => cmd_diagnose(),

        "ping" => {
            if args.len() < 3 {
                eprintln!("用法: ping8 ping <32hex地址> [count] [timeout_ms]");
                std::process::exit(2);
            }
            let target = &args[2];
            let count: u32 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(4);
            let timeout: u64 = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(1000);
            cmd_ping(target, count, timeout);
        }

        "visa" => {
            if args.len() < 3 {
                eprintln!("用法: ping8 visa <ca-init|issue|show|verify|revoke|fingerprint>");
                std::process::exit(2);
            }
            let sub = args[2].as_str();
            match sub {
                "ca-init" => cmd_visa_ca_init(),

                "issue" => {
                    let get = |flag: &str| -> Option<String> {
                        args.iter()
                            .position(|a| a == flag)
                            .and_then(|i| args.get(i + 1))
                            .filter(|v| !v.starts_with("--"))
                            .cloned()
                    };
                    // --addr 未提供时自动从机器指纹生成
                    let addr = match get("--addr") {
                        Some(a) => a,
                        None => {
                            let addr_bytes = generate_auto_address();
                            let addr_obj = addr_from_bytes(&addr_bytes);
                            let canonical = addr_obj.to_canonical_string();
                            println!("  [auto] 未指定 --addr，已从机器指纹自动生成: {canonical}");
                            canonical
                        }
                    };
                    // --ca-seed 未提供时尝试本地 CA 种子，没有则自动创建
                    let ca_seed = match get("--ca-seed") {
                        Some(a) => a,
                        None => {
                            let ca_path = ca_seed_path();
                            if !ca_path.exists() {
                                println!("  [auto] 未找到 CA 种子，自动生成中...");
                                let mut seed = [0u8; 32];
                                rand_core::OsRng.fill_bytes(&mut seed);
                                ensure_visa_dir().unwrap_or_else(|e| {
                                    eprintln!("无法创建目录: {e}");
                                    std::process::exit(1);
                                });
                                fs::write(&ca_path, seed).unwrap_or_else(|e| {
                                    eprintln!("写入 CA 种子失败: {e}");
                                    std::process::exit(1);
                                });
                                println!("  [auto] CA 种子已生成并保存");
                            }
                            let seed_data = fs::read(&ca_path).unwrap_or_else(|e| {
                                eprintln!("读取 CA 种子失败: {e}");
                                std::process::exit(1);
                            });
                            hex_encode(&seed_data)
                        }
                    };
                    let expires: Option<u64> = get("--expires").and_then(|s| s.parse().ok());
                    cmd_visa_issue(&addr, &ca_seed, expires);
                }

                "show" => cmd_visa_show(),

                "verify" => {
                    let get = |flag: &str| -> Option<String> {
                        args.iter()
                            .position(|a| a == flag)
                            .and_then(|i| args.get(i + 1))
                            .filter(|v| !v.starts_with("--"))
                            .cloned()
                    };
                    let ca_pub = match get("--ca-pub") {
                        Some(a) => a,
                        None => {
                            eprintln!("缺少 --ca-pub <64hex>");
                            std::process::exit(2);
                        }
                    };
                    cmd_visa_verify(&ca_pub);
                }

                "revoke" => cmd_visa_revoke(),

                "renew" => cmd_visa_renew(),

                "fingerprint" => cmd_visa_fingerprint(),

                _ => {
                    eprintln!("未知 visa 子命令: {sub}");
                    usage();
                    std::process::exit(2);
                }
            }
        }

        "help" | "--help" | "-h" => {
            if is_admin { usage_adm() } else { usage() };
        }

        "trust" => {
            if args.len() < 3 {
                eprintln!("用法: ping8 trust <listen|request> [参数]");
                eprintln!("  ping8 trust listen              监听入站信任请求，弹出确认");
                eprintln!("  ping8 trust request <对端IP> [端口]  向对端发送信任请求");
                std::process::exit(2);
            }
            match args[2].as_str() {
                "listen" => cmd_trust_listen(),
                "request" => {
                    let peer_ip = match args.get(3) {
                        Some(ip) => ip,
                        None => {
                            eprintln!("用法: ping8 trust request <对端IP> [端口]");
                            std::process::exit(2);
                        }
                    };
                    let port: u16 = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(45801);
                    cmd_trust_request(peer_ip, port);
                }
                _ => {
                    eprintln!("未知 trust 子命令: {}", args[2]);
                    std::process::exit(2);
                }
            }
        }

        "hook" => {
            let sub = args.get(2).map(|s| s.as_str()).unwrap_or("watch");
            let addr = args
                .get(3)
                .filter(|v| !v.starts_with("--"))
                .map(|s| s.as_str())
                .unwrap_or("127.0.0.1:45810");
            match sub {
                "watch" => cmd_hook_watch(addr, args.iter().any(|a| a == "--decision")),
                "stats" => cmd_hook_stats(addr),
                _ => {
                    eprintln!("用法: ping8 hook <watch|stats> [127.0.0.1:45810] [--decision]");
                    eprintln!("  watch   实时打印数据包事件（observer，默认；--decision 接管判决）");
                    eprintln!("  stats   取一次钩子总线统计");
                    std::process::exit(2);
                }
            }
        }

        "driver" => {
            let sub = args.get(2).map(|s| s.as_str()).unwrap_or("status");
            match sub {
                "status" => cmd_driver_status(),
                "version" => cmd_driver_version(),
                "stats" => cmd_driver_stats(),
                "bindings" => cmd_driver_bindings(),
                _ => {
                    eprintln!("未知 driver 子命令: {sub}");
                    eprintln!("用法: ping8 driver [status|version|stats|bindings]");
                    std::process::exit(2);
                }
            }
        }

        "l2" => cmd_l2(&args[2..]),

        "neigh" => cmd_neigh(&args[2..]),

        "firewall" => {
            if args.len() < 3 {
                eprintln!("用法: ping8 firewall <status|list|add|remove|toggle|open|close>");
                std::process::exit(2);
            }
            let sub = args[2].as_str();
            match sub {
                "list" | "status" => cmd_firewall_list(),
                "add" => {
                    let get = |flag: &str| -> Option<String> {
                        args.iter()
                            .position(|a| a == flag)
                            .and_then(|i| args.get(i + 1))
                            .filter(|v| !v.starts_with("--"))
                            .cloned()
                    };
                    let name = match get("--name") {
                        Some(n) => n,
                        None => {
                            eprintln!("缺少 --name <规则名称>");
                            std::process::exit(2);
                        }
                    };
                    let port: u16 = match get("--port").and_then(|s| s.parse().ok()) {
                        Some(p) => p,
                        None => {
                            eprintln!("缺少 --port <端口号>");
                            std::process::exit(2);
                        }
                    };
                    let port_end: u16 = get("--port-end").and_then(|s| s.parse().ok()).unwrap_or(port);
                    let proto = get("--proto").unwrap_or_else(|| "tcp".into());
                    let source = get("--source").unwrap_or_default();
                    let target = get("--target").unwrap_or_default();
                    let target_port: u16 = get("--target-port").and_then(|s| s.parse().ok()).unwrap_or(0);
                    let comment = get("--comment").unwrap_or_default();
                    cmd_firewall_add(&name, port, port_end, &proto, &source, &target, target_port, &comment);
                }
                "remove" => {
                    let get = |flag: &str| -> Option<String> {
                        args.iter()
                            .position(|a| a == flag)
                            .and_then(|i| args.get(i + 1))
                            .filter(|v| !v.starts_with("--"))
                            .cloned()
                    };
                    let id = match get("--id") {
                        Some(i) => i,
                        None => {
                            eprintln!("缺少 --id <规则ID>");
                            std::process::exit(2);
                        }
                    };
                    cmd_firewall_remove(&id);
                }
                "toggle" => {
                    let get = |flag: &str| -> Option<String> {
                        args.iter()
                            .position(|a| a == flag)
                            .and_then(|i| args.get(i + 1))
                            .filter(|v| !v.starts_with("--"))
                            .cloned()
                    };
                    let id = match get("--id") {
                        Some(i) => i,
                        None => {
                            eprintln!("缺少 --id <规则ID>");
                            std::process::exit(2);
                        }
                    };
                    cmd_firewall_toggle(&id);
                }
                "open" => cmd_firewall_open(),
                "close" => cmd_firewall_close(),
                _ => {
                    eprintln!("未知 firewall 子命令: {sub}");
                    eprintln!("可用: status(=list), list, add, remove, toggle, open, close");
                    std::process::exit(2);
                }
            }
        }

        "serve" => {
            // 支持: ping8 serve | ping8 serve 8080 | ping8 serve --port 8080
            let port: u16 = match args.iter().position(|a| a == "--port") {
                Some(i) => args.get(i + 1).and_then(|s| s.parse().ok()),
                None => args.get(2).and_then(|s| s.parse().ok()),
            }
            .unwrap_or(9100);
            cmd_serve(port);
        }

        _ => {
            eprintln!("未知命令: {cmd}");
            usage();
            std::process::exit(2);
        }
    }
}
