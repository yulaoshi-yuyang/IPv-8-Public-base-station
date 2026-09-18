//! 多中继自动故障切换
//!
//! 监控多个中继节点的健康状态，主中继挂了自动切到备用中继。
//! 核心设计：
//! - 健康检查：周期性 ping 每个中继，超时 = 不健康
//! - 自动切换：主中继不健康时，切到延迟最低的备用中继
//! - 恢复回切：原主中继恢复后，不会立即切回（防抖），稳定 N 秒后才回切
//! - 负载均衡：多个健康中继之间按延迟排序，选最优

use std::time::{Duration, Instant};

/// 中继节点信息
#[derive(Debug, Clone)]
pub struct RelayNode {
    /// 中继标识（URL 或地址）
    pub addr: String,
    /// 优先级（0 = 最高 = 主中继）
    pub priority: u8,
    /// 最后已知的延迟
    pub last_latency: Option<Duration>,
    /// 最后健康检查时间
    last_check: Option<Instant>,
    /// 连续失败次数
    fail_count: u32,
    /// 恢复期连续成功次数（用于 recover_threshold 判定）
    success_streak: u32,
    /// 是否健康
    healthy: bool,
}

/// 故障切换策略配置
#[derive(Debug, Clone)]
pub struct FailoverConfig {
    /// 健康检查间隔
    pub check_interval: Duration,
    /// 健康检查超时
    pub check_timeout: Duration,
    /// 连续失败几次判定为不健康
    pub fail_threshold: u32,
    /// 恢复后需要连续成功几次才判定为健康
    pub recover_threshold: u32,
    /// 恢复后多久才回切到主中继（防抖）
    pub recover_debounce: Duration,
}

impl Default for FailoverConfig {
    fn default() -> Self {
        Self {
            check_interval: Duration::from_secs(10),
            check_timeout: Duration::from_secs(3),
            fail_threshold: 3,
            recover_threshold: 2,
            recover_debounce: Duration::from_secs(30),
        }
    }
}

/// 中继健康状态
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    /// 健康
    Healthy,
    /// 不健康
    Unhealthy,
    /// 未知（还没检查过）
    Unknown,
}

/// 故障切换事件
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailoverEvent {
    /// 中继变不健康
    RelayDown { addr: String, reason: String },
    /// 中继恢复健康
    RelayUp { addr: String, latency: Duration },
    /// 活跃中继切换
    Switched { from: String, to: String, reason: String },
}

/// 多中继故障切换管理器
pub struct RelayFailover {
    config: FailoverConfig,
    relays: Vec<RelayNode>,
    /// 当前活跃中继索引
    active_idx: usize,
    /// 原主中继恢复时间（用于防抖）
    primary_recovered_at: Option<Instant>,
    /// 事件日志（保留最近 100 条）
    events: Vec<FailoverEvent>,
}

impl RelayFailover {
    /// 创建故障切换管理器
    ///
    /// relays 按 priority 排序，priority 最小的是主中继
    pub fn new(config: FailoverConfig, mut relays: Vec<(String, u8)>) -> Self {
        relays.sort_by_key(|(_, p)| *p);
        let nodes: Vec<RelayNode> = relays
            .into_iter()
            .map(|(addr, priority)| RelayNode {
                addr,
                priority,
                last_latency: None,
                last_check: None,
                fail_count: 0,
                success_streak: 0,
                healthy: true, // 初始假设健康
            })
            .collect();

        Self {
            config,
            relays: nodes,
            active_idx: 0,
            primary_recovered_at: None,
            events: Vec::new(),
        }
    }

    /// 获取当前活跃中继
    pub fn active(&self) -> Option<&RelayNode> {
        self.relays.get(self.active_idx)
    }

    /// 获取当前活跃中继地址
    pub fn active_addr(&self) -> Option<&str> {
        self.active().map(|r| r.addr.as_str())
    }

    /// 获取所有中继
    pub fn relays(&self) -> &[RelayNode] {
        &self.relays
    }

    /// 获取最近事件
    pub fn events(&self) -> &[FailoverEvent] {
        &self.events
    }

    /// 获取中继健康状态
    pub fn health_of(&self, addr: &str) -> Health {
        self.relays
            .iter()
            .find(|r| r.addr == addr)
            .map(|r| if r.healthy { Health::Healthy } else { Health::Unhealthy })
            .unwrap_or(Health::Unknown)
    }

    /// 记录一次健康检查结果
    ///
    /// 返回是否触发了中继切换
    pub fn record_check(&mut self, addr: &str, latency: Option<Duration>, now: Instant) -> bool {
        let idx = match self.relays.iter().position(|r| r.addr == addr) {
            Some(i) => i,
            None => return false,
        };

        // 先收集需要做的操作，避免借用冲突
        enum Action {
            None,
            RelayUp { latency: Duration, is_primary: bool },
            RelayDown { fail_count: u32 },
            SwitchFromDown,
        }

        let action = {
            let relay = &mut self.relays[idx];
            relay.last_check = Some(now);

            match latency {
                Some(lat) => {
                    relay.last_latency = Some(lat);
                    relay.fail_count = 0;
                    relay.success_streak = relay.success_streak.saturating_add(1);

                    let was_unhealthy = !relay.healthy;
                    if was_unhealthy {
                        // 需连续成功 recover_threshold 次才恢复健康（防单次误判抖动）
                        if relay.success_streak >= self.config.recover_threshold {
                            relay.healthy = true;
                            let is_primary = idx == 0;
                            Action::RelayUp { latency: lat, is_primary }
                        } else {
                            Action::None
                        }
                    } else if idx == 0 && self.active_idx != 0 {
                        if let Some(recovered) = self.primary_recovered_at {
                            if now.duration_since(recovered) >= self.config.recover_debounce {
                                return self.do_switch_to_primary(addr, now);
                            }
                        }
                        Action::None
                    } else {
                        Action::None
                    }
                }
                None => {
                    relay.fail_count += 1;
                    relay.success_streak = 0;

                    if relay.healthy && relay.fail_count >= self.config.fail_threshold {
                        relay.healthy = false;
                        let fc = relay.fail_count;
                        let is_active = idx == self.active_idx;
                        if is_active {
                            Action::SwitchFromDown
                        } else {
                            Action::RelayDown { fail_count: fc }
                        }
                    } else {
                        Action::None
                    }
                }
            }
        };

        match action {
            Action::None => false,
            Action::RelayUp { latency, is_primary } => {
                self.push_event(FailoverEvent::RelayUp {
                    addr: addr.to_string(),
                    latency,
                });
                if is_primary {
                    self.primary_recovered_at = Some(now);
                }
                false
            }
            Action::RelayDown { fail_count } => {
                self.push_event(FailoverEvent::RelayDown {
                    addr: addr.to_string(),
                    reason: format!("连续 {fail_count} 次健康检查失败"),
                });
                false
            }
            Action::SwitchFromDown => {
                self.push_event(FailoverEvent::RelayDown {
                    addr: addr.to_string(),
                    reason: "活跃中继健康检查失败".into(),
                });
                self.switch_to_best(now)
            }
        }
    }

    fn do_switch_to_primary(&mut self, addr: &str, _now: Instant) -> bool {
        let old = self.relays[self.active_idx].addr.clone();
        self.active_idx = 0;
        self.push_event(FailoverEvent::Switched {
            from: old,
            to: addr.to_string(),
            reason: "主中继恢复且稳定".into(),
        });
        true
    }

    /// 切换到最优的可用中继
    fn switch_to_best(&mut self, now: Instant) -> bool {
        // 在健康的中继中选延迟最低的
        let best = self
            .relays
            .iter()
            .enumerate()
            .filter(|(_, r)| r.healthy)
            .min_by_key(|(_, r)| {
                r.last_latency
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(u64::MAX)
            })
            .map(|(i, _)| i);

        match best {
            Some(new_idx) if new_idx != self.active_idx => {
                let from = self.relays[self.active_idx].addr.clone();
                let to = self.relays[new_idx].addr.clone();
                self.active_idx = new_idx;
                self.push_event(FailoverEvent::Switched {
                    from,
                    to,
                    reason: "活跃中继故障，切换到最优备用".into(),
                });
                let _ = now;
                true
            }
            Some(_) => false, // 已经是最优
            None => {
                // 所有中继都挂了
                self.push_event(FailoverEvent::Switched {
                    from: self.relays[self.active_idx].addr.clone(),
                    to: "无可用中继".into(),
                    reason: "所有中继均不健康".into(),
                });
                false
            }
        }
    }

    /// 是否需要健康检查（基于上次检查时间）
    pub fn needs_check(&self, addr: &str, now: Instant) -> bool {
        match self.relays.iter().find(|r| r.addr == addr) {
            Some(r) => match r.last_check {
                Some(last) => now.duration_since(last) >= self.config.check_interval,
                None => true,
            },
            None => false,
        }
    }

    /// 获取需要检查的中继列表
    pub fn relays_needing_check(&self, now: Instant) -> Vec<String> {
        self.relays
            .iter()
            .filter(|r| self.needs_check(&r.addr, now))
            .map(|r| r.addr.clone())
            .collect()
    }

    /// 统计摘要
    pub fn stats(&self) -> FailoverStats {
        let healthy = self.relays.iter().filter(|r| r.healthy).count();
        let unhealthy = self.relays.len() - healthy;
        let avg_latency = self
            .relays
            .iter()
            .filter_map(|r| r.last_latency)
            .map(|d| d.as_millis() as f64)
            .collect::<Vec<_>>();
        let avg_ms = if avg_latency.is_empty() {
            0.0
        } else {
            avg_latency.iter().sum::<f64>() / avg_latency.len() as f64
        };

        FailoverStats {
            total: self.relays.len(),
            healthy,
            unhealthy,
            active: self.active_addr().unwrap_or("无").to_string(),
            active_priority: self.relays.get(self.active_idx).map(|r| r.priority).unwrap_or(0),
            avg_latency_ms: avg_ms,
            events: self.events.len(),
        }
    }

    fn push_event(&mut self, event: FailoverEvent) {
        if self.events.len() >= 100 {
            self.events.remove(0);
        }
        self.events.push(event);
    }
}

/// 故障切换统计
#[derive(Debug, Clone)]
pub struct FailoverStats {
    pub total: usize,
    pub healthy: usize,
    pub unhealthy: usize,
    pub active: String,
    pub active_priority: u8,
    pub avg_latency_ms: f64,
    pub events: usize,
}

impl std::fmt::Display for FailoverStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "  中继总数: {}", self.total)?;
        writeln!(f, "  健康: {}", self.healthy)?;
        writeln!(f, "  不健康: {}", self.unhealthy)?;
        writeln!(f, "  当前活跃: {} (优先级 {})", self.active, self.active_priority)?;
        writeln!(f, "  平均延迟: {:.1} ms", self.avg_latency_ms)?;
        writeln!(f, "  事件数: {}", self.events)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config() -> FailoverConfig {
        FailoverConfig {
            check_interval: Duration::from_secs(1),
            check_timeout: Duration::from_millis(500),
            fail_threshold: 2,
            recover_threshold: 1,
            recover_debounce: Duration::from_secs(2),
        }
    }

    fn make_failover() -> RelayFailover {
        RelayFailover::new(
            make_config(),
            vec![
                ("relay-main.example.com".into(), 0),
                ("relay-backup1.example.com".into(), 1),
                ("relay-backup2.example.com".into(), 2),
            ],
        )
    }

    #[test]
    fn initial_state() {
        let fo = make_failover();
        assert_eq!(fo.active_addr(), Some("relay-main.example.com"));
        assert_eq!(fo.relays().len(), 3);
        assert!(fo.events().is_empty());
    }

    #[test]
    fn relay_down_triggers_switch() {
        let mut fo = make_failover();
        let now = Instant::now();

        // 主中继失败 2 次
        fo.record_check("relay-main.example.com", None, now);
        fo.record_check("relay-main.example.com", None, now);

        // 主中继应该不健康了
        assert_eq!(fo.health_of("relay-main.example.com"), Health::Unhealthy);

        // 应该切换到 backup1（backup1 和 backup2 都没检查过，延迟 None）
        // 选 priority 最小的健康中继
        assert_ne!(fo.active_addr(), Some("relay-main.example.com"));
    }

    #[test]
    fn relay_down_then_recover() {
        let mut fo = make_failover();
        let t0 = Instant::now();

        // backup1 有延迟数据，backup2 也有
        fo.record_check("relay-backup1.example.com", Some(Duration::from_millis(50)), t0);
        fo.record_check("relay-backup2.example.com", Some(Duration::from_millis(80)), t0);

        // 主中继挂了
        fo.record_check("relay-main.example.com", None, t0);
        fo.record_check("relay-main.example.com", None, t0);

        // 应该切到 backup1（延迟更低）
        assert_eq!(fo.active_addr(), Some("relay-backup1.example.com"));

        // 主中继恢复
        let t1 = t0 + Duration::from_secs(3);
        fo.record_check("relay-main.example.com", Some(Duration::from_millis(30)), t1);

        // 防抖期内不回切
        assert_eq!(fo.active_addr(), Some("relay-backup1.example.com"));

        // 防抖期过后回切
        let t2 = t1 + Duration::from_secs(3);
        fo.record_check("relay-main.example.com", Some(Duration::from_millis(30)), t2);
        assert_eq!(fo.active_addr(), Some("relay-main.example.com"));
    }

    #[test]
    fn all_relays_down() {
        let mut fo = make_failover();
        let now = Instant::now();

        for _ in 0..2 {
            fo.record_check("relay-main.example.com", None, now);
            fo.record_check("relay-backup1.example.com", None, now);
            fo.record_check("relay-backup2.example.com", None, now);
        }

        assert_eq!(fo.health_of("relay-main.example.com"), Health::Unhealthy);
        assert_eq!(fo.health_of("relay-backup1.example.com"), Health::Unhealthy);
        assert_eq!(fo.health_of("relay-backup2.example.com"), Health::Unhealthy);
    }

    #[test]
    fn switch_to_lowest_latency() {
        let mut fo = make_failover();
        let now = Instant::now();

        // 给 backup2 更低延迟
        fo.record_check("relay-backup1.example.com", Some(Duration::from_millis(100)), now);
        fo.record_check("relay-backup2.example.com", Some(Duration::from_millis(20)), now);

        // 主中继挂了
        fo.record_check("relay-main.example.com", None, now);
        fo.record_check("relay-main.example.com", None, now);

        // 应该切到 backup2（延迟 20ms < 100ms）
        assert_eq!(fo.active_addr(), Some("relay-backup2.example.com"));
    }

    #[test]
    fn needs_check_respects_interval() {
        let mut fo = make_failover();
        let t0 = Instant::now();

        // 初始需要检查
        assert!(fo.needs_check("relay-main.example.com", t0));

        // 记录检查
        fo.record_check("relay-main.example.com", Some(Duration::from_millis(10)), t0);

        // 间隔内不需要
        assert!(!fo.needs_check("relay-main.example.com", t0));

        // 间隔后需要
        let t1 = t0 + Duration::from_secs(2);
        assert!(fo.needs_check("relay-main.example.com", t1));
    }

    #[test]
    fn stats_summary() {
        let mut fo = make_failover();
        let now = Instant::now();

        fo.record_check("relay-main.example.com", Some(Duration::from_millis(30)), now);
        fo.record_check("relay-backup1.example.com", Some(Duration::from_millis(50)), now);

        let stats = fo.stats();
        assert_eq!(stats.total, 3);
        assert_eq!(stats.healthy, 3);
        assert_eq!(stats.unhealthy, 0);
        assert!(stats.avg_latency_ms > 0.0);
    }

    #[test]
    fn event_log_records_switches() {
        let mut fo = make_failover();
        let now = Instant::now();

        fo.record_check("relay-backup1.example.com", Some(Duration::from_millis(50)), now);
        fo.record_check("relay-main.example.com", None, now);
        fo.record_check("relay-main.example.com", None, now);

        // 应该有 RelayDown + Switched 事件
        assert!(fo.events().iter().any(|e| matches!(e, FailoverEvent::RelayDown { .. })));
        assert!(fo.events().iter().any(|e| matches!(e, FailoverEvent::Switched { .. })));
    }
}
