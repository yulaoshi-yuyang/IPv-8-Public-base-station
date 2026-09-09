//! Chord 一致性哈希（v9 `ipv8-routing/cf.rs`）。
//!
//! **状态：骨架，不进 Phase 3 验收**（ADR-019 决议：本轮多跳走静态源路由
//! 加路径签名，`chord` feature 默认关闭）。Chord 自主路由意味着中间节点
//! 自选下一跳，与 RouteTrace 的按签名路径执行互斥；届时须回头扩展
//! ADR-019（逐跳追加签名），本文件的 finger table 维护逻辑才能接线。

/// 键空间位宽（IPv8+ 地址哈希到 64 bit ID 的简化：取 ASN+HostID）。
/// 真实现按 zone 参数化，此处仅锁接口形状。
pub const M: usize = 64;

/// 节点 ID（模 2^M 环上位置）
pub type NodeId = u64;

/// 把 IPv8+ 地址映到环上 ID（大端 ASN‖HostID 的前 8 字节，与 zone 同构）。
pub fn node_id(asn: u32, host_id: u32) -> NodeId {
    ((asn as u64) << 32) | host_id as u64
}

#[cfg(feature = "chord")]
pub mod chord {
    use super::*;

    /// finger table 槽数（≤ M）
    pub const F: usize = M;

    /// 单个后继/前驱指针
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Successor {
        pub id: NodeId,
        /// 物理入口（由上层 Resolver 解析，此处仅占位保真类型形状）
        pub addr: [u8; 16],
    }

    /// 一个 Chord 节点的路由表。骨架仅含结构与距离工具，join/stabilize
    /// 的完整状态机待 ADR-019 扩展后实现（见模块级注释）。
    #[derive(Debug, Clone, Default)]
    pub struct Node {
        pub id: NodeId,
        pub successor: Option<Successor>,
        pub predecessor: Option<Successor>,
        pub fingers: Vec<Successor>,
    }

    impl Node {
        pub fn new(id: NodeId) -> Self {
            Self { id, successor: None, predecessor: None, fingers: vec![] }
        }

        /// 环上距离：a 顺时针到 b 的跳数（模 2^M，用 wrapping 技巧避免 u128）
        pub fn dist(a: NodeId, b: NodeId) -> NodeId {
            b.wrapping_sub(a)
        }

        /// 目标 k 落在 (n, successor] 区间内？（骨架判定，供 find_successor 用）
        pub fn in_open_interval(k: NodeId, n: NodeId, succ: NodeId) -> bool {
            if n < succ {
                k > n && k <= succ
            } else {
                k > n || k <= succ // 跨界（环绕）
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_id_is_bigendian_asn_host() {
        assert_eq!(node_id(0x0000fb14, 0x0000000a), 0x0000fb14_0000000a);
    }

    #[test]
    fn distance_wraps_around_ring() {
        // 环上相邻两点，顺时针距离应小；反向应巨大（wrapping）
        let a = node_id(0, u32::MAX); // 0x0000_0000_FFFF_FFFF
        let b = node_id(1, 0); // 0x0000_0001_0000_0000，恰为 a 的下一位
        assert_eq!(distance(a, b), 1);
        assert_eq!(distance(b, a), u64::MAX);
    }

    fn distance(a: NodeId, b: NodeId) -> NodeId {
        // 与 chord::dist 同式（feature 关时也能测纯数学）
        b.wrapping_sub(a)
    }
}
