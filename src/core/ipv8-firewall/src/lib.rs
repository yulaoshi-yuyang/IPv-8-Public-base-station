//! # ipv8-firewall — 防火墙规则引擎
//!
//! 核心理念：**透明中继**。节点不处理任何用户数据，只提供隧道。
//! 防火墙控制哪些端口/协议/IPv8 地址对可以通过隧道互访。
//!
//! - [`Protocol`]：支持所有标准协议 + 自定义协议号
//! - [`Rule`]：单条放行规则（端口范围 + 协议 + 源地址过滤 + 转发目标）
//! - [`RuleSet`]：规则集合，JSON 持久化 + 匹配查询

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use ipv8_codec::IPv8Address;
use serde::{Deserialize, Serialize};

/// 协议类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// 传输控制协议
    Tcp,
    /// 用户数据报协议
    Udp,
    /// 任意协议
    Any,
    /// 自定义协议号（IANA 协议号）
    Custom(u8),
}

impl Protocol {
    /// 从字符串解析协议
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "tcp" => Self::Tcp,
            "udp" => Self::Udp,
            "any" | "*" | "all" => Self::Any,
            _ => {
                if let Ok(n) = s.parse::<u8>() {
                    Self::Custom(n)
                } else {
                    Self::Any
                }
            }
        }
    }

    /// 匹配：规则协议是否匹配实际协议
    pub fn matches(&self, actual: u8) -> bool {
        match self {
            Self::Any => true,
            Self::Tcp => actual == 6,
            Self::Udp => actual == 17,
            Self::Custom(n) => *n == actual,
        }
    }

    /// 返回字符串表示
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Any => "any",
            Self::Custom(_) => "custom",
        }
    }
}

/// 单条防火墙规则
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// 规则 ID（唯一标识）
    pub id: String,
    /// 规则名称（用户可读）
    pub name: String,
    /// 协议类型
    pub protocol: Protocol,
    /// 监听端口起始
    pub port_start: u16,
    /// 监听端口结束（含）
    pub port_end: u16,
    /// 源 IPv8 地址前缀过滤（空 = 任意源）
    ///
    /// 格式：32 字符 hex 的前缀，如 "fb14000000000001" 匹配该前缀开头的所有地址。
    /// 支持通配符 "*" 表示任意。
    #[serde(default)]
    pub source_pattern: String,
    /// 转发目标 IPv8 地址（32 hex），为空则仅做端口放行不做转发
    #[serde(default)]
    pub target_addr: String,
    /// 转发目标端口（0 = 保持原端口）
    #[serde(default)]
    pub target_port: u16,
    /// 是否启用
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// 传输方向：inbound = 外部→内部，outbound = 内部→外部
    #[serde(default = "default_direction")]
    pub direction: Direction,
    /// 备注
    #[serde(default)]
    pub comment: String,
}

fn default_enabled() -> bool {
    true
}

fn default_direction() -> Direction {
    Direction::Inbound
}

/// 传输方向
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    /// 入站（外部 → 内部）
    Inbound,
    /// 出站（内部 → 外部）
    Outbound,
}

/// 规则匹配结果
#[derive(Debug, Clone)]
pub struct MatchResult {
    /// 匹配到的规则 ID
    pub rule_id: String,
    /// 转发目标地址（None = 仅放行，不转发）
    pub target: Option<IPv8Address>,
    /// 转发目标端口
    pub target_port: u16,
}

/// 防火墙规则集合
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleSet {
    /// 规则列表
    pub rules: Vec<Rule>,
}

impl RuleSet {
    /// 从 JSON 文件加载
    pub fn load(path: &Path) -> Self {
        match fs::read_to_string(path) {
            Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    /// 保存为 JSON 文件
    pub fn save(&self, path: &Path) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        fs::write(path, json).map_err(|e| e.to_string())
    }

    /// 添加规则
    pub fn add(&mut self, rule: Rule) {
        // 同 ID 替换
        if let Some(pos) = self.rules.iter().position(|r| r.id == rule.id) {
            self.rules[pos] = rule;
        } else {
            self.rules.push(rule);
        }
    }

    /// 删除规则
    pub fn remove(&mut self, id: &str) -> bool {
        let before = self.rules.len();
        self.rules.retain(|r| r.id != id);
        self.rules.len() != before
    }

    /// 切换规则启用状态
    pub fn toggle(&mut self, id: &str) -> bool {
        if let Some(r) = self.rules.iter_mut().find(|r| r.id == id) {
            r.enabled = !r.enabled;
            true
        } else {
            false
        }
    }

    /// 获取启用的规则
    pub fn active_rules(&self) -> impl Iterator<Item = &Rule> {
        self.rules.iter().filter(|r| r.enabled)
    }

    /// 匹配连接请求
    ///
    /// 参数：
    /// - `protocol`：IANA 协议号（TCP=6, UDP=17）
    /// - `port`：目标端口
    /// - `source`：源 IPv8 地址
    pub fn match_rule(
        &self,
        protocol: u8,
        port: u16,
        source: &IPv8Address,
    ) -> Option<MatchResult> {
        for rule in self.active_rules() {
            if !rule.protocol.matches(protocol) {
                continue;
            }
            if port < rule.port_start || port > rule.port_end {
                continue;
            }
            if !rule.source_pattern.is_empty() && rule.source_pattern != "*" {
                let src_str = source.to_canonical_string();
                if !src_str.starts_with(&rule.source_pattern.to_ascii_lowercase()) {
                    continue;
                }
            }
            // 匹配成功
            let target = if rule.target_addr.is_empty() {
                None
            } else {
                IPv8Address::from_canonical_str(&rule.target_addr).ok()
            };
            let target_port = if rule.target_port == 0 {
                port
            } else {
                rule.target_port
            };
            return Some(MatchResult {
                rule_id: rule.id.clone(),
                target,
                target_port,
            });
        }
        None
    }

    /// 统计各端口/协议的活跃规则数
    pub fn stats(&self) -> HashMap<String, usize> {
        let mut map = HashMap::new();
        map.insert("total".into(), self.rules.len());
        map.insert("active".into(), self.active_rules().count());
        map.insert("disabled".into(), self.rules.len() - self.active_rules().count());
        map
    }
}

/// 生成规则 ID
pub fn gen_rule_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    format!("rule-{ts:x}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipv8_codec::PROTOCOL_MAGIC;

    fn make_addr(region: u64) -> IPv8Address {
        IPv8Address::with_region(region, 0, 0, 0, 0)
    }

    #[test]
    fn protocol_match() {
        assert!(Protocol::Tcp.matches(6));
        assert!(!Protocol::Tcp.matches(17));
        assert!(Protocol::Udp.matches(17));
        assert!(Protocol::Any.matches(6));
        assert!(Protocol::Any.matches(17));
        assert!(Protocol::Custom(132).matches(132));
        assert!(!Protocol::Custom(132).matches(6));
    }

    #[test]
    fn rule_match_basic() {
        let rs = RuleSet {
            rules: vec![Rule {
                id: "r1".into(),
                name: "Web".into(),
                protocol: Protocol::Tcp,
                port_start: 80,
                port_end: 80,
                source_pattern: String::new(),
                target_addr: String::new(),
                target_port: 0,
                enabled: true,
                direction: Direction::Inbound,
                comment: String::new(),
            }],
        };
        // 匹配 TCP:80
        assert!(rs.match_rule(6, 80, &make_addr(1)).is_some());
        // 不匹配 UDP:80
        assert!(rs.match_rule(17, 80, &make_addr(1)).is_none());
        // 不匹配 TCP:81
        assert!(rs.match_rule(6, 81, &make_addr(1)).is_none());
    }

    #[test]
    fn rule_match_port_range() {
        let rs = RuleSet {
            rules: vec![Rule {
                id: "r1".into(),
                name: "Passive FTP".into(),
                protocol: Protocol::Tcp,
                port_start: 50000,
                port_end: 50100,
                source_pattern: String::new(),
                target_addr: String::new(),
                target_port: 0,
                enabled: true,
                direction: Direction::Inbound,
                comment: String::new(),
            }],
        };
        assert!(rs.match_rule(6, 50000, &make_addr(1)).is_some());
        assert!(rs.match_rule(6, 50050, &make_addr(1)).is_some());
        assert!(rs.match_rule(6, 50100, &make_addr(1)).is_some());
        assert!(rs.match_rule(6, 49999, &make_addr(1)).is_none());
        assert!(rs.match_rule(6, 50101, &make_addr(1)).is_none());
    }

    #[test]
    fn rule_match_source_pattern() {
        let rs = RuleSet {
            rules: vec![Rule {
                id: "r1".into(),
                name: "Region Only".into(),
                protocol: Protocol::Any,
                port_start: 1,
                port_end: 65535,
                source_pattern: "fb14000000000001".into(),
                target_addr: String::new(),
                target_port: 0,
                enabled: true,
                direction: Direction::Inbound,
                comment: String::new(),
            }],
        };
        // 匹配 region=1
        let addr1 = IPv8Address::with_region(1, 0, 0, 0, 0);
        assert!(rs.match_rule(6, 80, &addr1).is_some());
        // 不匹配 region=2
        let addr2 = IPv8Address::with_region(2, 0, 0, 0, 0);
        assert!(rs.match_rule(6, 80, &addr2).is_none());
    }

    #[test]
    fn rule_match_forward() {
        let target = make_addr(42);
        let rs = RuleSet {
            rules: vec![Rule {
                id: "r1".into(),
                name: "Forward to 42".into(),
                protocol: Protocol::Tcp,
                port_start: 8080,
                port_end: 8080,
                source_pattern: String::new(),
                target_addr: target.to_canonical_string(),
                target_port: 80,
                enabled: true,
                direction: Direction::Inbound,
                comment: String::new(),
            }],
        };
        let m = rs.match_rule(6, 8080, &make_addr(1)).unwrap();
        assert_eq!(m.target_port, 80);
        assert!(m.target.is_some());
        assert_eq!(m.target.unwrap(), target);
    }

    #[test]
    fn disabled_rule_ignored() {
        let rs = RuleSet {
            rules: vec![Rule {
                id: "r1".into(),
                name: "Disabled".into(),
                protocol: Protocol::Any,
                port_start: 1,
                port_end: 65535,
                source_pattern: String::new(),
                target_addr: String::new(),
                target_port: 0,
                enabled: false,
                direction: Direction::Inbound,
                comment: String::new(),
            }],
        };
        assert!(rs.match_rule(6, 80, &make_addr(1)).is_none());
    }

    #[test]
    fn ruleset_crud() {
        let mut rs = RuleSet::default();
        let r = Rule {
            id: "test".into(),
            name: "Test".into(),
            protocol: Protocol::Tcp,
            port_start: 80,
            port_end: 80,
            source_pattern: String::new(),
            target_addr: String::new(),
            target_port: 0,
            enabled: true,
            direction: Direction::Inbound,
            comment: String::new(),
        };
        rs.add(r.clone());
        assert_eq!(rs.rules.len(), 1);
        rs.add(r.clone()); // 同 ID 替换
        assert_eq!(rs.rules.len(), 1);
        assert!(rs.toggle("test"));
        assert!(!rs.rules[0].enabled);
        assert!(rs.remove("test"));
        assert!(rs.rules.is_empty());
    }

    #[test]
    fn ruleset_persist() {
        let path = std::env::temp_dir().join("ipv8_firewall_test.json");
        let rs = RuleSet {
            rules: vec![Rule {
                id: "persist".into(),
                name: "Persist Test".into(),
                protocol: Protocol::Udp,
                port_start: 53,
                port_end: 53,
                source_pattern: String::new(),
                target_addr: String::new(),
                target_port: 0,
                enabled: true,
                direction: Direction::Inbound,
                comment: "test".into(),
            }],
        };
        rs.save(&path).unwrap();
        let loaded = RuleSet::load(&path);
        assert_eq!(loaded.rules.len(), 1);
        assert_eq!(loaded.rules[0].id, "persist");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn protocol_magic_allows_any() {
        // 确保协议 magic 0xFB14 的地址也能被规则匹配
        let addr = IPv8Address::new(PROTOCOL_MAGIC, 1, 2, 3, 0, 0, 0, 0);
        let rs = RuleSet {
            rules: vec![Rule {
                id: "r1".into(),
                name: "Any".into(),
                protocol: Protocol::Any,
                port_start: 1,
                port_end: 65535,
                source_pattern: String::new(),
                target_addr: String::new(),
                target_port: 0,
                enabled: true,
                direction: Direction::Inbound,
                comment: String::new(),
            }],
        };
        assert!(rs.match_rule(6, 443, &addr).is_some());
    }
}
