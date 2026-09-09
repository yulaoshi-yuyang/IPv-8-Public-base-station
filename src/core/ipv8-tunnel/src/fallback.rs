//! Fallback 分级降级（v9 §11 的 Phase 2 实现，纯逻辑 + 注入时钟）。
//!
//! 四级路径（level 越小越优先）：
//! ```text
//! 0 MainTunnel    IPv8+ 隧道，Resolver 主入口
//! 1 AltTunnel     IPv8+ 隧道，Resolver 备用入口（级联尝试）
//! 2 PlainTcp      明文 IPv4 TCP（对方不支持 IPv8+ 或隧道全败时）
//! 3 PlainUdp      明文 IPv4 UDP（最后手段，不加密）
//! ```
//!
//! 降级触发（v9 条件表逐条实现于 record_failure/next_path）：
//! - 首次握手超时（8s）→ 重试至 max_retries(2) → 耗尽后降级
//! - 已缓存节点握手超时（5s，见 handshake_timeout）→ 同上
//! - 首包超时（3s，隧道已建但数据不通）→ 直接降级，不浪费重试预算
//! - 备用入口全部失败 → PlainTcp；TCP 失败 → PlainUdp
//! - Resolver 报 ipv8_capable=false → 直接 PlainTcp（note_resolved 处理）
//! - 降级缓存：明文级停留 degradation_cache_ttl（5min）不再试隧道；
//!   到期 next_path 自动回 MainTunnel 重试（v9"过期后自动恢复尝试"）；
//!   隧道任一时刻成功 → record_success 立即清缓存。
//!
//! IO 归属：本模块只回答"下一个包走哪条路 / 这次用多短超时 / 这次尝试算
//! 成功还是失败、要不要降级"；实际 socket 与计时由宿主（C# Host / ipv8-node）执行。

use std::collections::HashMap;
use std::time::Duration;

/// §11 FallbackOptions 的等价配置
#[derive(Debug, Clone)]
pub struct FallbackOptions {
    /// Resolver gRPC 超时（宿主计时用）
    pub resolver_timeout: Duration,
    /// 首次隧道握手超时
    pub first_handshake_timeout: Duration,
    /// 已缓存节点的隧道握手超时（跳过 Resolver 查询，更快放弃）
    pub cached_handshake_timeout: Duration,
    /// 首包响应超时（隧道建立后第一个包）
    pub first_packet_timeout: Duration,
    /// 同一级的失败重试次数（降级前）
    pub max_retries: u32,
    /// 降级缓存 TTL：明文级期间暂停隧道重试的时长
    pub degradation_cache_ttl: Duration,
}

impl Default for FallbackOptions {
    fn default() -> Self {
        Self {
            resolver_timeout: Duration::from_secs(2),
            first_handshake_timeout: Duration::from_secs(8),
            cached_handshake_timeout: Duration::from_secs(5),
            first_packet_timeout: Duration::from_secs(3),
            max_retries: 2,
            degradation_cache_ttl: Duration::from_secs(300),
        }
    }
}

/// 发送路径决策
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Path {
    /// IPv8+ 隧道，使用指定入口（Resolver 主/备）
    Tunnel { entry: String },
    /// 明文 IPv4 TCP
    PlainTcp,
    /// 明文 IPv4 UDP
    PlainUdp,
}

/// 降级级别（Ord 即降级顺序）
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    MainTunnel,
    AltTunnel,
    PlainTcp,
    PlainUdp,
}

/// Resolver 原子返回的入口信息（缓存供 Resolver 超时时回退）
#[derive(Debug, Clone, Default)]
pub struct Resolved {
    pub tunnel_entry: Option<String>,
    pub alt_entries: Vec<String>,
    pub ipv8_capable: bool,
    /// 上次成功握手的入口（非空 ⇒ "已缓存节点"，握手用更短超时）
    pub last_good_entry: Option<String>,
}

/// 失败事件源
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// 隧道握手超时
    HandshakeTimeout,
    /// 隧道已建但首包无响应
    FirstPacketTimeout,
    /// 当前级彻底失败（拒连/不可达）：整级计一次失败后走重试/降级
    LevelFailed,
}

#[derive(Clone)]
struct PeerState {
    resolved: Resolved,
    level: Level,
    /// 当前级别/入口已发生的失败次数（重试预算）
    failures_at_level: u32,
    /// AltTunnel 级：当前使用的备用入口索引
    alt_idx: usize,
    /// 进入明文级的时刻（秒）；None = 无降级缓存
    degraded_at: Option<u64>,
    /// 降级缓存 TTL（秒），建 Peer 时从 opts 固化，避免借用冲突
    ttl_secs: u64,
    /// 每个入口/级别的重试上限
    max_retries: u32,
}

/// 多对端降级管理器
pub struct FallbackManager {
    opts: FallbackOptions,
    peers: HashMap<String, PeerState>,
}

impl FallbackManager {
    pub fn new(opts: FallbackOptions) -> Self {
        Self { opts, peers: HashMap::new() }
    }

    pub fn options(&self) -> &FallbackOptions {
        &self.opts
    }

    /// Resolver 成功回包 → 刷新该对端缓存。
    /// ipv8_capable=true：视为全新机会（清降级缓存、回主隧道）。
    /// false：直接 PlainTcp（v9 降级路径 2，跳过隧道尝试）。
    pub fn note_resolved(&mut self, peer: &str, r: Resolved) {
        let ttl = self.opts.degradation_cache_ttl.as_secs();
        let retries = self.opts.max_retries;
        let s = self
            .peers
            .entry(peer.to_string())
            .or_insert_with(|| PeerState {
                resolved: Resolved::default(),
                level: Level::MainTunnel,
                failures_at_level: 0,
                alt_idx: 0,
                degraded_at: None,
                ttl_secs: ttl,
                max_retries: retries,
            });
        s.resolved = r;
        if s.resolved.ipv8_capable {
            s.level = Level::MainTunnel;
            s.failures_at_level = 0;
            s.alt_idx = 0;
            s.degraded_at = None;
        } else {
            s.level = Level::PlainTcp;
            s.degraded_at = None; // 非降级而来，不占缓存窗口
        }
    }

    /// 握手该用的超时：已缓存节点 5s / 首次 8s（v9 分级超时判据）
    pub fn handshake_timeout(&self, peer: &str) -> Duration {
        match self.peers.get(peer) {
            Some(p) if p.resolved.last_good_entry.is_some() => {
                self.opts.cached_handshake_timeout
            }
            _ => self.opts.first_handshake_timeout,
        }
    }

    /// 首包超时（供宿主计时）
    pub fn first_packet_timeout(&self) -> Duration {
        self.opts.first_packet_timeout
    }

    /// 决定下一个包的发送路径（含降级缓存到期自动恢复）
    pub fn next_path(&mut self, peer: &str, now: u64) -> Path {
        let s = self.peer_mut(peer);
        if matches!(s.level, Level::PlainTcp | Level::PlainUdp) {
            match s.degraded_at {
                Some(at) if now.saturating_sub(at) < s.ttl_secs => {
                    // 缓存有效期内：稳定停在明文级
                    return match s.level {
                        Level::PlainUdp => Path::PlainUdp,
                        _ => Path::PlainTcp,
                    };
                }
                Some(_) => {
                    // TTL 到期：自动恢复隧道尝试（v9 §11 降级缓存语义）
                    s.degraded_at = None;
                    s.level = Level::MainTunnel;
                    s.failures_at_level = 0;
                    s.alt_idx = 0;
                }
                None => {
                    // 首次进入明文级：开始计时
                    s.degraded_at = Some(now);
                    return match s.level {
                        Level::PlainUdp => Path::PlainUdp,
                        _ => Path::PlainTcp,
                    };
                }
            }
        }
        match s.level {
            Level::MainTunnel => Path::Tunnel {
                entry: s.resolved.tunnel_entry.clone().unwrap_or_default(),
            },
            Level::AltTunnel => {
                // 备用入口按序级联：alt_idx 指向当前尝试的入口（越界钳到表尾）
                let idx = s.alt_idx.min(s.resolved.alt_entries.len().saturating_sub(1));
                Path::Tunnel {
                    entry: s.resolved.alt_entries.get(idx).cloned().unwrap_or_default(),
                }
            }
            Level::PlainTcp => Path::PlainTcp,
            Level::PlainUdp => Path::PlainUdp,
        }
    }

    /// 记录一次失败，按 v9 规则推进重试/降级。
    /// 入口序列 = [主入口, alt0, alt1, ...]，每个入口独立重试预算；
    /// 全部入口耗尽（"所有入口失败"）才降明文。
    pub fn record_failure(&mut self, peer: &str, f: Failure, now: u64) {
        let s = self.peer_mut(peer);
        let skip_retry = matches!(f, Failure::FirstPacketTimeout);
        match s.level {
            Level::MainTunnel | Level::AltTunnel => {
                if !skip_retry {
                    s.failures_at_level += 1;
                    if s.failures_at_level <= s.max_retries {
                        return; // 当前入口预算内：留在本入口重试
                    }
                }
                s.failures_at_level = 0;
                // 换下一个入口（Main → alt0 → alt1 → …）
                let next_alt = match s.level {
                    Level::MainTunnel => 0usize,
                    _ => s.alt_idx + 1,
                };
                if next_alt < s.resolved.alt_entries.len() {
                    s.alt_idx = next_alt;
                    s.level = Level::AltTunnel;
                } else {
                    // 所有入口均失败 → PlainTcp，开始降级缓存计时
                    s.alt_idx = 0;
                    s.level = Level::PlainTcp;
                    s.degraded_at = Some(now);
                }
            }
            Level::PlainTcp => s.level = Level::PlainUdp,
            Level::PlainUdp => {}
        }
    }

    /// 当前路径成功 → 复位状态；隧道成功还会记 last_good 并把备用提正
    pub fn record_success(&mut self, peer: &str, path: &Path) {
        let s = self.peer_mut(peer);
        match path {
            Path::Tunnel { entry } => {
                s.level = Level::MainTunnel;
                s.failures_at_level = 0;
                s.degraded_at = None;
                s.resolved.last_good_entry = Some(entry.clone());
                if s.resolved.tunnel_entry.as_deref() != Some(entry.as_str())
                    && s.resolved.alt_entries.iter().any(|a| a == entry)
                {
                    s.resolved.tunnel_entry = Some(entry.clone());
                    if let Some(pos) = s.resolved.alt_entries.iter().position(|a| a == entry) {
                        s.resolved.alt_entries.remove(pos);
                    }
                }
            }
            Path::PlainTcp | Path::PlainUdp => {
                // 明文成功：确认隧道暂不可用，降级缓存窗口继续走表
            }
        }
    }

    /// 诊断：该对端当前级别
    pub fn level_of(&self, peer: &str) -> Option<Level> {
        self.peers.get(peer).map(|p| p.level)
    }

    fn peer_mut(&mut self, peer: &str) -> &mut PeerState {
        let ttl = self.opts.degradation_cache_ttl.as_secs();
        let retries = self.opts.max_retries;
        self.peers.entry(peer.to_string()).or_insert_with(|| PeerState {
            resolved: Resolved::default(),
            level: Level::MainTunnel,
            failures_at_level: 0,
            alt_idx: 0,
            degraded_at: None,
            ttl_secs: ttl,
            max_retries: retries,
        })
    }
}

impl std::fmt::Debug for FallbackManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FallbackManager").field("peers", &self.peers.len()).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 10_000;

    fn mgr() -> FallbackManager {
        FallbackManager::new(FallbackOptions::default())
    }

    fn resolved(main: &str, alts: &[&str], ipv8: bool) -> Resolved {
        Resolved {
            tunnel_entry: Some(main.into()),
            alt_entries: alts.iter().map(|s| s.to_string()).collect(),
            ipv8_capable: ipv8,
            last_good_entry: None,
        }
    }

    #[test]
    fn default_timeouts_match_v9() {
        let o = FallbackOptions::default();
        assert_eq!(o.resolver_timeout, Duration::from_secs(2));
        assert_eq!(o.first_handshake_timeout, Duration::from_secs(8));
        assert_eq!(o.cached_handshake_timeout, Duration::from_secs(5));
        assert_eq!(o.first_packet_timeout, Duration::from_secs(3));
        assert_eq!(o.max_retries, 2);
        assert_eq!(o.degradation_cache_ttl, Duration::from_secs(300));
    }

    #[test]
    fn handshake_timeout_uses_cached_when_node_known() {
        let mut m = mgr();
        assert_eq!(m.handshake_timeout("p"), Duration::from_secs(8)); // 首次
        m.note_resolved("p", resolved("e0", &[], true));
        let path = m.next_path("p", NOW);
        m.record_success("p", &path); // 记 last_good_entry
        assert_eq!(m.handshake_timeout("p"), Duration::from_secs(5)); // 已缓存
    }

    #[test]
    fn main_tunnel_retries_then_degrades_to_alt() {
        let mut m = mgr();
        m.note_resolved("p", resolved("main", &["a1", "a2"], true));
        assert_eq!(m.next_path("p", NOW), Path::Tunnel { entry: "main".into() });

        // max_retries=2：第 1、2 次失败留级，第 3 次降级
        m.record_failure("p", Failure::HandshakeTimeout, NOW);
        m.record_failure("p", Failure::HandshakeTimeout, NOW);
        assert_eq!(m.level_of("p"), Some(Level::MainTunnel), "重试预算内不降级");
        m.record_failure("p", Failure::HandshakeTimeout, NOW);
        assert_eq!(m.level_of("p"), Some(Level::AltTunnel));
        assert_eq!(m.next_path("p", NOW), Path::Tunnel { entry: "a1".into() });
        // 备用级联：同级失败预算耗尽后换下一个备用入口
        m.record_failure("p", Failure::HandshakeTimeout, NOW);
        m.record_failure("p", Failure::HandshakeTimeout, NOW);
        m.record_failure("p", Failure::HandshakeTimeout, NOW);
        assert_eq!(m.next_path("p", NOW), Path::Tunnel { entry: "a2".into() }, "级联到 a2");
        // 备用也耗尽 → PlainTcp
        m.record_failure("p", Failure::HandshakeTimeout, NOW);
        m.record_failure("p", Failure::HandshakeTimeout, NOW);
        m.record_failure("p", Failure::HandshakeTimeout, NOW);
        assert_eq!(m.next_path("p", NOW), Path::PlainTcp);
    }

    #[test]
    fn first_packet_timeout_skips_retry_budget() {
        // v9：首包超时（隧道建好但数据不通）不浪费重试，直接降级
        let mut m = mgr();
        m.note_resolved("p", resolved("main", &[], true));
        m.record_failure("p", Failure::FirstPacketTimeout, NOW);
        assert_eq!(m.level_of("p"), Some(Level::PlainTcp), "无备用入口时首包超时直接明文");
        assert_eq!(m.next_path("p", NOW), Path::PlainTcp);
    }

    #[test]
    fn tcp_failure_cascades_to_udp() {
        let mut m = mgr();
        m.note_resolved("p", resolved("main", &[], true));
        m.record_failure("p", Failure::FirstPacketTimeout, NOW); // → PlainTcp
        m.record_failure("p", Failure::LevelFailed, NOW); // TCP 也败
        assert_eq!(m.level_of("p"), Some(Level::PlainUdp));
        assert_eq!(m.next_path("p", NOW), Path::PlainUdp);
    }

    #[test]
    fn not_ipv8_capable_goes_straight_to_tcp() {
        let mut m = mgr();
        m.note_resolved("p", resolved("main", &["a1"], false));
        assert_eq!(m.next_path("p", NOW), Path::PlainTcp, "对端不支持 IPv8+，跳过隧道尝试");
        assert_eq!(m.level_of("p"), Some(Level::PlainTcp));
    }

    #[test]
    fn degradation_cache_holds_for_ttl_then_recovers() {
        let mut m = mgr();
        m.note_resolved("p", resolved("main", &[], true));
        m.record_failure("p", Failure::FirstPacketTimeout, NOW); // 进明文 + 起缓存
        assert_eq!(m.next_path("p", NOW), Path::PlainTcp);
        // TTL 内：始终明文，不再试隧道
        for t in [NOW + 30, NOW + 299] {
            assert_eq!(m.next_path("p", t), Path::PlainTcp, "t={t} 应处于降级缓存");
        }
        // 到期（>=300s）：自动恢复隧道尝试
        assert_eq!(m.next_path("p", NOW + 300), Path::Tunnel { entry: "main".into() });
        assert_eq!(m.level_of("p"), Some(Level::MainTunnel));
    }

    #[test]
    fn tunnel_success_clears_degradation_and_promotes_alt() {
        let mut m = mgr();
        m.note_resolved("p", resolved("main", &["a1"], true));
        m.record_failure("p", Failure::HandshakeTimeout, NOW);
        m.record_failure("p", Failure::HandshakeTimeout, NOW);
        m.record_failure("p", Failure::HandshakeTimeout, NOW); // → AltTunnel
        let alt = m.next_path("p", NOW);
        assert_eq!(alt, Path::Tunnel { entry: "a1".into() });
        // 备用入口成功：清缓存、提正为主入口、从 alt 列表移除
        m.record_success("p", &alt);
        assert_eq!(m.level_of("p"), Some(Level::MainTunnel));
        assert_eq!(m.next_path("p", NOW + 1), Path::Tunnel { entry: "a1".into() });
    }

    #[test]
    fn per_peer_states_are_independent() {
        let mut m = mgr();
        m.note_resolved("a", resolved("main_a", &[], true));
        m.note_resolved("b", resolved("main_b", &[], true));
        m.record_failure("a", Failure::FirstPacketTimeout, NOW); // a 降级
        assert_eq!(m.next_path("a", NOW), Path::PlainTcp);
        assert_eq!(m.next_path("b", NOW), Path::Tunnel { entry: "main_b".into() }, "b 不受影响");
    }
}
