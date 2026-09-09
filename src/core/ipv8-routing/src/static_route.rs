//! `Router` 抽象与静态源路由实现（ADR-019：转发只按签名路径执行）。
//!
//! Router 的角色边界：RouteTrace 验证（route_trace.rs）回答"这个包该不该
//! 由我转、转给谁"；Router 回答"我自己要发的多跳包，下一跳是谁"。
//! 二者在源点建路径时交汇：`StaticRouter::path_to(dst)` 给出完整跳列表，
//! 源点据此签 RouteTrace。

use ipv8_codec::IPv8Address;
use std::collections::HashMap;

/// 转发/源路由决策抽象。实现者 MUST 保证同 (src,dst) 的路径稳定
/// （路径变化 = 重新签名，属控制面事件）。
pub trait Router {
    /// 从本机到 dst 的完整下一跳列表（不含本机、含 dst 本身；
    /// 与 spec §6.6 NextHopList 定义一致）。无路径返回 None。
    fn path_to(&self, dst: IPv8Address) -> Option<Vec<IPv8Address>>;
}

/// 静态源路由：手工配置的邻接表上跑 BFS 最短跳路径（≤ max_hops 跳）。
/// 验证拓扑（A→R→B）与小型联盟部署的直接形态。
#[derive(Debug, Clone)]
pub struct StaticRouter {
    /// 本机地址
    local: IPv8Address,
    /// 无向邻接表：addr → 直连邻居集合
    links: HashMap<IPv8Address, Vec<IPv8Address>>,
    /// 路径跳数上限（部署值，spec 协议上限 64 之下收紧；默认 8）
    max_hops: usize,
}

impl StaticRouter {
    pub fn new(local: IPv8Address) -> Self {
        Self { local, links: HashMap::new(), max_hops: 8 }
    }

    pub fn with_max_hops(mut self, n: usize) -> Self {
        self.max_hops = n.max(1);
        self
    }

    /// 登记一条无向链路（两端互为邻居）
    pub fn add_link(&mut self, a: IPv8Address, b: IPv8Address) {
        self.links.entry(a).or_default().push(b);
        self.links.entry(b).or_default().push(a);
    }

    /// 本机是否直连某邻居（转发决策"下一跳是否可达"的物理前提）
    pub fn is_neighbor(&self, addr: IPv8Address) -> bool {
        self.links.get(&self.local).is_some_and(|n| n.contains(&addr))
    }

    pub fn local(&self) -> IPv8Address {
        self.local
    }

    fn neighbors(&self, a: &IPv8Address) -> &[IPv8Address] {
        self.links.get(a).map(Vec::as_slice).unwrap_or(&[])
    }
}

impl Router for StaticRouter {
    fn path_to(&self, dst: IPv8Address) -> Option<Vec<IPv8Address>> {
        if dst == self.local {
            return None; // 发给自己的包不走多跳
        }
        // BFS：prev[child] = parent，回溯成路径
        let mut prev: HashMap<IPv8Address, IPv8Address> = HashMap::new();
        let mut queue = std::collections::VecDeque::new();
        prev.insert(self.local, self.local);
        queue.push_back(self.local);
        while let Some(cur) = queue.pop_front() {
            if cur == dst {
                break;
            }
            for nb in self.neighbors(&cur) {
                if !prev.contains_key(nb) {
                    prev.insert(*nb, cur);
                    queue.push_back(*nb);
                }
            }
        }
        if !prev.contains_key(&dst) {
            return None;
        }
        // 回溯 dst ← ... ← local，反转为正向列表
        let mut rev = vec![dst];
        let mut cur = dst;
        loop {
            let p = *prev.get(&cur)?;
            if p == self.local {
                break;
            }
            rev.push(p);
            cur = p;
        }
        rev.reverse();
        if rev.len() > self.max_hops {
            return None;
        }
        Some(rev)
    }
}
