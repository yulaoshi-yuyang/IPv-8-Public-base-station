//! 滥用自动封禁
//!
//! 自动检测异常流量并封禁恶意节点：
//! - 速率限制：每秒包数 / 字节数超过阈值 → 标记
//! - 异常检测：连接失败率过高、小包轰炸、扫描行为 → 标记
//! - 自动封禁：达到阈值后自动加入黑名单，TTL 过期自动解封
//! - 逐级升级：警告 → 临时封禁 → 永久封禁

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// 封禁级别
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BanLevel {
    /// 正常（未封禁）
    None,
    /// 警告（仅记录，不阻断）
    Warn,
    /// 临时封禁
    TempBan,
    /// 永久封禁
    PermBan,
}

/// 节点行为统计
#[derive(Debug, Clone)]
struct NodeStats {
    /// 滑动窗口内的包数（按秒桶）
    pkt_buckets: Vec<(Instant, u64)>,
    /// 滑动窗口内的字节数
    byte_buckets: Vec<(Instant, u64)>,
    /// 连接失败次数
    conn_failures: u32,
    /// 连接成功次数
    conn_successes: u32,
    /// 被标记次数（过期后重置）
    strikes: u32,
    /// 总临时封禁次数（不随过期重置，用于升级判定）
    ban_count: u32,
    /// 当前封禁级别
    ban_level: BanLevel,
    /// 封禁时间
    banned_at: Option<Instant>,
    /// 封禁时长（TempBan 用）
    ban_duration: Option<Duration>,
    /// 最后活动时间
    last_active: Instant,
    /// 最后一次封禁原因
    last_ban_reason: String,
}

impl Default for NodeStats {
    fn default() -> Self {
        Self {
            pkt_buckets: Vec::new(),
            byte_buckets: Vec::new(),
            conn_failures: 0,
            conn_successes: 0,
            strikes: 0,
            ban_count: 0,
            ban_level: BanLevel::None,
            banned_at: None,
            ban_duration: None,
            last_active: Instant::now(),
            last_ban_reason: String::new(),
        }
    }
}

/// 封禁配置
#[derive(Debug, Clone)]
pub struct AbuseConfig {
    /// 滑动窗口大小
    pub window: Duration,
    /// 每秒最大包数（超过触发警告）
    pub pps_warn: u32,
    /// 每秒最大包数（超过触发临时封禁）
    pub pps_ban: u32,
    /// 每秒最大字节数（超过触发封禁）
    pub bps_ban: u64,
    /// 连接失败率阈值（0.0-1.0，超过触发封禁）
    pub failure_rate_threshold: f64,
    /// 触发封禁的最小连接尝试次数
    pub min_attempts_for_failure_rate: u32,
    /// 警告几次后升级为临时封禁
    pub warn_to_ban_strikes: u32,
    /// 临时封禁几次后升级为永久封禁
    pub temp_to_perm_strikes: u32,
    /// 临时封禁时长
    pub temp_ban_duration: Duration,
    /// 小包轰炸阈值：小于此字节的包占比超过 small_pkt_ratio 触发
    pub small_pkt_size: usize,
    /// 小包占比阈值
    pub small_pkt_ratio: f64,
}

impl Default for AbuseConfig {
    fn default() -> Self {
        Self {
            window: Duration::from_secs(10),
            pps_warn: 500,
            pps_ban: 2000,
            bps_ban: 10_000_000, // 10 MB/s = 80 Mbps
            failure_rate_threshold: 0.8,
            min_attempts_for_failure_rate: 10,
            warn_to_ban_strikes: 3,
            temp_to_perm_strikes: 3,
            temp_ban_duration: Duration::from_secs(300),
            small_pkt_size: 64,
            small_pkt_ratio: 0.9,
        }
    }
}

/// 检测结果
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Detection {
    /// 正常
    Normal,
    /// 警告
    Warn { reason: String },
    /// 封禁
    Ban { level: BanLevel, reason: String, duration: Option<Duration> },
}

/// 滥用封禁管理器
pub struct AbuseGuard {
    config: AbuseConfig,
    nodes: HashMap<String, NodeStats>,
    /// 黑名单（永久封禁）
    blacklist: Vec<String>,
}

impl AbuseGuard {
    pub fn new(config: AbuseConfig) -> Self {
        Self {
            config,
            nodes: HashMap::new(),
            blacklist: Vec::new(),
        }
    }

    /// 是否被封禁
    pub fn is_banned(&self, node: &str) -> bool {
        if self.blacklist.iter().any(|n| n == node) {
            return true;
        }
        match self.nodes.get(node) {
            Some(s) => matches!(s.ban_level, BanLevel::TempBan | BanLevel::PermBan),
            None => false,
        }
    }

    /// 获取封禁信息
    pub fn ban_info(&self, node: &str) -> Option<(BanLevel, Option<Duration>, &str)> {
        self.nodes.get(node).map(|s| {
            (s.ban_level, s.ban_duration, s.last_ban_reason.as_str())
        })
    }

    /// 记录一个包到达
    ///
    /// 返回检测结果：Normal / Warn / Ban
    pub fn record_packet(&mut self, node: &str, pkt_size: usize, now: Instant) -> Detection {
        let stats = self.nodes.entry(node.to_string()).or_default();
        stats.last_active = now;

        // 如果已封禁，检查是否解封
        if stats.ban_level == BanLevel::TempBan {
            if let Some(banned_at) = stats.banned_at {
                if let Some(dur) = stats.ban_duration {
                    if now.duration_since(banned_at) >= dur {
                        // 解封
                        stats.ban_level = BanLevel::None;
                        stats.banned_at = None;
                        stats.ban_duration = None;
                        stats.strikes = 0;
                    } else {
                        return Detection::Ban {
                            level: BanLevel::TempBan,
                            reason: stats.last_ban_reason.clone(),
                            duration: stats.ban_duration,
                        };
                    }
                }
            }
        }

        if stats.ban_level == BanLevel::PermBan {
            return Detection::Ban {
                level: BanLevel::PermBan,
                reason: stats.last_ban_reason.clone(),
                duration: None,
            };
        }

        // 更新滑动窗口
        Self::push_bucket(&mut stats.pkt_buckets, now, 1, self.config.window);
        Self::push_bucket(&mut stats.byte_buckets, now, pkt_size as u64, self.config.window);

        // 计算窗口内速率
        let pps = Self::sum_buckets(&stats.pkt_buckets, now, self.config.window);
        let bps = Self::sum_buckets(&stats.byte_buckets, now, self.config.window);
        let window_secs = self.config.window.as_secs_f64();
        let pps_rate = pps as f64 / window_secs;
        let bps_rate = bps as f64 / window_secs;

        // 小包检测
        let small_pkt_ratio = if pkt_size < self.config.small_pkt_size {
            // 粗略估计：如果当前包是小包，查看窗口中小包占比
            let small_count = stats.pkt_buckets.iter()
                .filter(|(t, _)| now.duration_since(*t) < self.config.window)
                .count() as f64;
            let total = stats.pkt_buckets.iter()
                .filter(|(t, _)| now.duration_since(*t) < self.config.window)
                .count() as f64;
            if total > 0.0 { small_count / total } else { 0.0 }
        } else {
            0.0
        };

        // 检测逻辑
        let mut detected = vec![];

        // 速率检测
        if pps_rate as u32 >= self.config.pps_ban {
            detected.push(format!("包速率 {pps_rate:.0} pps 超过封禁阈值 {}", self.config.pps_ban));
        } else if pps_rate as u32 >= self.config.pps_warn {
            detected.push(format!("包速率 {pps_rate:.0} pps 超过警告阈值 {}", self.config.pps_warn));
        }

        // 字节速率检测
        if bps_rate as u64 >= self.config.bps_ban {
            let mbps = bps_rate * 8.0 / 1_000_000.0;
            detected.push(format!("字节速率 {mbps:.1} Mbps 超过封禁阈值"));
        }

        // 小包轰炸检测
        if small_pkt_ratio > self.config.small_pkt_ratio && pps > 100 {
            detected.push(format!("小包占比 {:.0}% 疑似轰炸", small_pkt_ratio * 100.0));
        }

        if detected.is_empty() {
            return Detection::Normal;
        }

        let reason = detected.join("; ");
        stats.strikes += 1;

        // 逐级升级：strikes 累积到 warn_to_ban → 临时封禁，ban_count 累积到 temp_to_perm → 永久
        if stats.ban_count + 1 >= self.config.temp_to_perm_strikes {
            stats.ban_count += 1;
            stats.ban_level = BanLevel::PermBan;
            stats.banned_at = Some(now);
            stats.ban_duration = None;
            stats.last_ban_reason = reason.clone();
            self.blacklist.push(node.to_string());
            Detection::Ban {
                level: BanLevel::PermBan,
                reason,
                duration: None,
            }
        } else if stats.strikes >= self.config.warn_to_ban_strikes {
            stats.ban_count += 1;
            stats.ban_level = BanLevel::TempBan;
            stats.banned_at = Some(now);
            stats.ban_duration = Some(self.config.temp_ban_duration);
            stats.last_ban_reason = reason.clone();
            Detection::Ban {
                level: BanLevel::TempBan,
                reason,
                duration: Some(self.config.temp_ban_duration),
            }
        } else {
            stats.last_ban_reason = reason.clone();
            Detection::Warn { reason }
        }
    }

    /// 记录连接结果
    pub fn record_conn_result(&mut self, node: &str, success: bool, now: Instant) {
        let stats = self.nodes.entry(node.to_string()).or_default();
        stats.last_active = now;

        if success {
            stats.conn_successes += 1;
        } else {
            stats.conn_failures += 1;
        }

        // 检查失败率
        let total = stats.conn_failures + stats.conn_successes;
        if total >= self.config.min_attempts_for_failure_rate {
            let rate = stats.conn_failures as f64 / total as f64;
            if rate > self.config.failure_rate_threshold {
                let reason = format!(
                    "连接失败率 {:.0}% ({}/{})",
                    rate * 100.0,
                    stats.conn_failures,
                    total
                );
                stats.strikes += 1;

                if stats.ban_count + 1 >= self.config.temp_to_perm_strikes {
                    stats.ban_count += 1;
                    stats.ban_level = BanLevel::PermBan;
                    stats.banned_at = Some(now);
                    stats.ban_duration = None;
                    stats.last_ban_reason = reason;
                    self.blacklist.push(node.to_string());
                } else if stats.strikes >= self.config.warn_to_ban_strikes {
                    stats.ban_count += 1;
                    stats.ban_level = BanLevel::TempBan;
                    stats.banned_at = Some(now);
                    stats.ban_duration = Some(self.config.temp_ban_duration);
                    stats.last_ban_reason = reason;
                }
            }
        }
    }

    /// 手动封禁
    pub fn ban(&mut self, node: &str, level: BanLevel, reason: &str, now: Instant) {
        let stats = self.nodes.entry(node.to_string()).or_default();
        stats.ban_level = level;
        stats.banned_at = Some(now);
        stats.ban_duration = match level {
            BanLevel::TempBan => Some(self.config.temp_ban_duration),
            _ => None,
        };
        stats.last_ban_reason = reason.to_string();

        if level == BanLevel::PermBan && !self.blacklist.iter().any(|n| n == node) {
            self.blacklist.push(node.to_string());
        }
    }

    /// 手动解封
    pub fn unban(&mut self, node: &str) -> bool {
        self.blacklist.retain(|n| n != node);
        if let Some(stats) = self.nodes.get_mut(node) {
            let was_banned = stats.ban_level >= BanLevel::TempBan;
            stats.ban_level = BanLevel::None;
            stats.banned_at = None;
            stats.ban_duration = None;
            stats.strikes = 0;
            was_banned
        } else {
            false
        }
    }

    /// 获取黑名单
    pub fn blacklist(&self) -> &[String] {
        &self.blacklist
    }

    /// 获取所有被监控的节点
    pub fn monitored_nodes(&self) -> Vec<String> {
        self.nodes.keys().cloned().collect()
    }

    /// 清理长时间不活跃的节点统计
    pub fn gc(&mut self, max_idle: Duration, now: Instant) {
        self.nodes.retain(|_, s| {
            s.ban_level == BanLevel::PermBan
                || now.duration_since(s.last_active) < max_idle
        });
    }

    /// 统计摘要
    pub fn stats(&self) -> AbuseStats {
        AbuseStats {
            monitored: self.nodes.len(),
            banned: self.nodes.values()
                .filter(|s| s.ban_level >= BanLevel::TempBan)
                .count(),
            permanent: self.blacklist.len(),
            warned: self.nodes.values()
                .filter(|s| s.ban_level == BanLevel::Warn)
                .count(),
        }
    }

    fn push_bucket(buckets: &mut Vec<(Instant, u64)>, now: Instant, val: u64, window: Duration) {
        buckets.push((now, val));
        // 清理过期桶
        let cutoff = now - window;
        buckets.retain(|(t, _)| *t > cutoff);
    }

    fn sum_buckets(buckets: &[(Instant, u64)], now: Instant, window: Duration) -> u64 {
        let cutoff = now - window;
        buckets.iter()
            .filter(|(t, _)| *t > cutoff)
            .map(|(_, v)| v)
            .sum()
    }
}

/// 滥用统计
#[derive(Debug, Clone)]
pub struct AbuseStats {
    pub monitored: usize,
    pub banned: usize,
    pub permanent: usize,
    pub warned: usize,
}

impl std::fmt::Display for AbuseStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "  监控节点: {}", self.monitored)?;
        writeln!(f, "  临时封禁: {}", self.banned)?;
        writeln!(f, "  永久封禁: {}", self.permanent)?;
        writeln!(f, "  警告中: {}", self.warned)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config() -> AbuseConfig {
        AbuseConfig {
            window: Duration::from_secs(1),
            pps_warn: 100,
            pps_ban: 300,
            bps_ban: 5_000_000,
            failure_rate_threshold: 0.8,
            min_attempts_for_failure_rate: 5,
            warn_to_ban_strikes: 2,
            temp_to_perm_strikes: 3,
            temp_ban_duration: Duration::from_secs(1),
            small_pkt_size: 64,
            small_pkt_ratio: 0.9,
        }
    }

    #[test]
    fn normal_traffic_not_banned() {
        let mut guard = AbuseGuard::new(make_config());
        let now = Instant::now();

        // 10 pps 正常流量
        for _ in 0..10 {
            guard.record_packet("node-A", 1000, now);
        }

        assert!(!guard.is_banned("node-A"));
        assert_eq!(guard.stats().banned, 0);
    }

    #[test]
    fn high_pps_triggers_warn() {
        let mut guard = AbuseGuard::new(make_config());
        let t0 = Instant::now();

        // 模拟 1 秒内发 200 包 → 200 pps > warn 阈值 100
        for i in 0..200 {
            let now = t0 + Duration::from_millis(i);
            let det = guard.record_packet("node-B", 500, now);
            if matches!(det, Detection::Warn { .. }) {
                assert!(!guard.is_banned("node-B"));
                return;
            }
        }
        panic!("应该触发警告");
    }

    #[test]
    fn excessive_pps_triggers_ban() {
        let mut guard = AbuseGuard::new(make_config());
        let t0 = Instant::now();

        // 模拟 1 秒内发 600 包 → 600 pps > ban 阈值 300
        // 连续触发 2 次 warn → 临时封禁
        for i in 0..600 {
            let now = t0 + Duration::from_millis(i);
            guard.record_packet("node-C", 500, now);
        }

        assert!(guard.is_banned("node-C"));
    }

    #[test]
    fn temp_ban_expires() {
        let mut guard = AbuseGuard::new(make_config());
        let t0 = Instant::now();

        // 触发临时封禁
        for i in 0..600 {
            let now = t0 + Duration::from_millis(i);
            guard.record_packet("node-D", 500, now);
        }
        assert!(guard.is_banned("node-D"));

        // 等待封禁过期（1 秒）
        let t1 = t0 + Duration::from_secs(2);
        let det = guard.record_packet("node-D", 1000, t1);
        assert!(!guard.is_banned("node-D"));
        assert_eq!(det, Detection::Normal);
    }

    #[test]
    fn repeated_bans_escalate_to_permanent() {
        let mut guard = AbuseGuard::new(make_config());
        let t0 = Instant::now();

        // 每轮触发临时封禁，多轮后升级为永久
        for round in 0..5 {
            let base = t0 + Duration::from_secs(round * 5);
            // 每轮 600 包/秒 > ban 阈值
            for i in 0..600 {
                let now = base + Duration::from_millis(i);
                guard.record_packet("node-E", 500, now);
            }
        }

        assert!(guard.is_banned("node-E"));
        let (level, _, _) = guard.ban_info("node-E").unwrap();
        assert_eq!(level, BanLevel::PermBan);
    }

    #[test]
    fn high_failure_rate_triggers_ban() {
        let mut guard = AbuseGuard::new(make_config());
        let now = Instant::now();

        // 10 次连接，9 次失败
        for _ in 0..9 {
            guard.record_conn_result("node-F", false, now);
        }
        guard.record_conn_result("node-F", true, now);

        assert!(guard.is_banned("node-F"));
    }

    #[test]
    fn manual_ban_and_unban() {
        let mut guard = AbuseGuard::new(make_config());
        let now = Instant::now();

        guard.ban("node-G", BanLevel::PermBan, "手动封禁测试", now);
        assert!(guard.is_banned("node-G"));
        assert_eq!(guard.blacklist().len(), 1);

        assert!(guard.unban("node-G"));
        assert!(!guard.is_banned("node-G"));
        assert_eq!(guard.blacklist().len(), 0);
    }

    #[test]
    fn gc_cleans_idle_nodes() {
        let mut guard = AbuseGuard::new(make_config());
        let now = Instant::now();

        guard.record_packet("idle-node", 500, now);
        assert_eq!(guard.stats().monitored, 1);

        guard.gc(Duration::from_secs(60), now + Duration::from_secs(120));
        assert_eq!(guard.stats().monitored, 0);
    }

    #[test]
    fn high_bps_triggers_ban() {
        let mut guard = AbuseGuard::new(make_config());
        let t0 = Instant::now();

        // 大包高速发送：1 秒内发 200 个 50KB 包 = 10 MB/s = 80 Mbps
        for i in 0..200 {
            let now = t0 + Duration::from_millis(i * 5); // 1 秒内 200 包
            guard.record_packet("node-H", 50000, now);
        }

        // 200 * 50000 / 1s = 10 MB/s > bps_ban 阈值 5 MB/s
        assert!(guard.is_banned("node-H"));
    }

    #[test]
    fn different_nodes_independent() {
        let mut guard = AbuseGuard::new(make_config());
        let t0 = Instant::now();

        // node-I 发大量包被封禁
        for i in 0..600 {
            let now = t0 + Duration::from_millis(i);
            guard.record_packet("node-I", 500, now);
        }
        assert!(guard.is_banned("node-I"));

        // node-J 正常
        guard.record_packet("node-J", 1000, t0);
        assert!(!guard.is_banned("node-J"));
    }

    #[test]
    fn stats_summary() {
        let mut guard = AbuseGuard::new(make_config());
        let t0 = Instant::now();

        guard.record_packet("node-K", 500, t0);
        for i in 0..600 {
            let now = t0 + Duration::from_millis(i);
            guard.record_packet("node-L", 500, now);
        }

        let stats = guard.stats();
        assert!(stats.monitored >= 2);
        assert!(stats.banned >= 1);
    }
}
