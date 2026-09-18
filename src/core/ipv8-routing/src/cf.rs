//! Chord 一致性哈希 + DHT 键值存储（P2：Resolver 分布式底座）。
//!
//! 实现范围（对齐 Stoica 01 论文核心子集）：
//! - **环维护**：join / stabilize / notify / find_successor
//! - **路由**：finger table + closest_preceding_finger，O(log N) 跳
//! - **DHT 存储**：每个节点存落在 (predecessor, self] 区间的键值对
//! - **传输抽象**：`ChordRpc` trait，进程内测试用直连，生产可接 gRPC
//!
//! 不在本轮：并发 stabilize / 故障恢复 / 数据冗余复制 / successor list。
//! P2 目标是"单 Resolver → 多节点 DHT Resolver 能跑通"，正确性
//! 优先于可用性。

/// 键空间位宽（IPv8+ 地址哈希到 64 bit ID：取 ASN+HostID）。
pub const M: usize = 64;

/// 节点 ID（模 2^M 环上位置）
pub type NodeId = u64;

/// 把 IPv8+ 地址映到环上 ID（大端 ASN‖HostID，与 zone 同构）。
pub fn node_id(asn: u32, host_id: u32) -> NodeId {
    ((asn as u64) << 32) | host_id as u64
}

/// 环上顺时针距离：a → b 的模 2^M 差值。
pub fn ring_dist(a: NodeId, b: NodeId) -> NodeId {
    b.wrapping_sub(a)
}

/// 目标 k 是否落在开区间 (lo, hi] 内（环绕正确处理）。
pub fn in_open_interval(k: NodeId, lo: NodeId, hi: NodeId) -> bool {
    if lo < hi {
        k > lo && k <= hi
    } else {
        k > lo || k <= hi // 跨界（环绕过零点）
    }
}

/// 目标 k 是否落在闭区间 [lo, hi] 内。
pub fn in_closed_interval(k: NodeId, lo: NodeId, hi: NodeId) -> bool {
    k == lo || in_open_interval(k, lo, hi)
}

/// finger table 槽数 = M = 64
pub const FINGER_COUNT: usize = M;

/// 单个后继/前驱指针（节点 ID + 物理入口地址）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeInfo {
    pub id: NodeId,
    /// 物理入口（16B = IPv8+ 地址线格式，由上层 Resolver 解析）
    pub addr: [u8; 16],
}

impl NodeInfo {
    pub fn new(id: NodeId, addr: [u8; 16]) -> Self {
        Self { id, addr }
    }
}

/// Chord 节点间 RPC 抽象。
///
/// 实现者负责把调用投递到目标节点（进程内直连 / gRPC / UDP 均可）。
/// P2 测试用 `InProcessRpc`（HashMap 找节点 → 直接调用）。
pub trait ChordRpc {
    /// 问节点 n：你的后继是谁？
    fn get_successor(&self, n: NodeId) -> Option<NodeInfo>;
    /// 问节点 n：你的前驱是谁？
    fn get_predecessor(&self, n: NodeId) -> Option<NodeInfo>;
    /// 让节点 n 把我（caller）设为它的前驱（如果我更接近）。
    fn notify(&self, n: NodeId, caller: NodeInfo);
    /// 问节点 n：key k 的后继是谁（递归/迭代查找）。
    fn find_successor(&self, n: NodeId, k: NodeId) -> Option<NodeInfo>;
    /// 问节点 n：最接近 k 的前置 finger 是谁。
    fn closest_preceding_finger(&self, n: NodeId, k: NodeId) -> Option<NodeInfo>;
    /// DHT 写入：从节点 from 出发，找到 key 的负责节点并存入 value。
    /// 返回负责节点 ID。
    fn dht_put(&self, from: NodeId, key: NodeId, value: Vec<u8>) -> Option<NodeId>;
    /// DHT 读取：从节点 from 出发，找到 key 的负责节点并读值。
    fn dht_get(&self, from: NodeId, key: NodeId) -> Option<Vec<u8>>;
}

// Blanket impl：Arc<T> 和 &T 也实现 ChordRpc，
// 便于在多节点共享同一个 RPC 句柄。
impl<T: ChordRpc + ?Sized> ChordRpc for std::sync::Arc<T> {
    fn get_successor(&self, n: NodeId) -> Option<NodeInfo> {
        (**self).get_successor(n)
    }
    fn get_predecessor(&self, n: NodeId) -> Option<NodeInfo> {
        (**self).get_predecessor(n)
    }
    fn notify(&self, n: NodeId, caller: NodeInfo) {
        (**self).notify(n, caller)
    }
    fn find_successor(&self, n: NodeId, k: NodeId) -> Option<NodeInfo> {
        (**self).find_successor(n, k)
    }
    fn closest_preceding_finger(&self, n: NodeId, k: NodeId) -> Option<NodeInfo> {
        (**self).closest_preceding_finger(n, k)
    }
    fn dht_put(&self, from: NodeId, key: NodeId, value: Vec<u8>) -> Option<NodeId> {
        (**self).dht_put(from, key, value)
    }
    fn dht_get(&self, from: NodeId, key: NodeId) -> Option<Vec<u8>> {
        (**self).dht_get(from, key)
    }
}

impl<T: ChordRpc + ?Sized> ChordRpc for &T {
    fn get_successor(&self, n: NodeId) -> Option<NodeInfo> {
        (**self).get_successor(n)
    }
    fn get_predecessor(&self, n: NodeId) -> Option<NodeInfo> {
        (**self).get_predecessor(n)
    }
    fn notify(&self, n: NodeId, caller: NodeInfo) {
        (**self).notify(n, caller)
    }
    fn find_successor(&self, n: NodeId, k: NodeId) -> Option<NodeInfo> {
        (**self).find_successor(n, k)
    }
    fn closest_preceding_finger(&self, n: NodeId, k: NodeId) -> Option<NodeInfo> {
        (**self).closest_preceding_finger(n, k)
    }
    fn dht_put(&self, from: NodeId, key: NodeId, value: Vec<u8>) -> Option<NodeId> {
        (**self).dht_put(from, key, value)
    }
    fn dht_get(&self, from: NodeId, key: NodeId) -> Option<Vec<u8>> {
        (**self).dht_get(from, key)
    }
}

/// 一个 Chord 节点的完整状态：路由表 + DHT 存储。
#[derive(Debug, Clone)]
pub struct ChordNode {
    pub id: NodeId,
    pub addr: [u8; 16],
    pub successor: Option<NodeInfo>,
    pub predecessor: Option<NodeInfo>,
    /// finger table：fingers[i] 对应 id + 2^i 的后继
    pub fingers: Vec<Option<NodeInfo>>,
    /// DHT 本地存储：只存 (predecessor.id, self.id] 区间的键
    pub store: std::collections::HashMap<NodeId, Vec<u8>>,
    /// fix_fingers 下一个要刷新的槽位索引
    next_fix: usize,
}

impl ChordNode {
    /// 创建一个孤立节点（自己是自己的后继/前驱，单节点环）。
    pub fn new(id: NodeId, addr: [u8; 16]) -> Self {
        let info = NodeInfo::new(id, addr);
        let mut fingers = vec![None; FINGER_COUNT];
        fingers[0] = Some(info); // finger[0] = successor
        Self {
            id,
            addr,
            successor: Some(info),
            predecessor: Some(info),
            fingers,
            store: std::collections::HashMap::new(),
            next_fix: 0,
        }
    }

    /// 节点信息快照
    pub fn info(&self) -> NodeInfo {
        NodeInfo::new(self.id, self.addr)
    }

    // ── 查询类（只读，不需要 RPC） ────────────────────────────────

    /// 本地判断：k 的后继是不是我自己？
    /// 即 k ∈ (predecessor, self]
    pub fn i_am_responsible_for(&self, k: NodeId) -> bool {
        let pred = self.predecessor.map(|p| p.id).unwrap_or(self.id);
        in_open_interval(k, pred, self.id) || k == self.id
    }

    /// 从 finger table 找最接近 k 且在 k 之前的节点（§IV.B）。
    pub fn closest_preceding_finger(&self, k: NodeId) -> Option<NodeInfo> {
        // 从最远的 finger 往回扫，第一个落在 (self, k) 区间内的就是最近
        for i in (0..FINGER_COUNT).rev() {
            if let Some(f) = self.fingers[i] {
                if in_open_interval(f.id, self.id, k) {
                    return Some(f);
                }
            }
        }
        self.successor // fallback：后继
    }

    // ── 写入类（修改本地状态，不做 RPC） ────────────────────────

    /// 设置后继（同时更新 finger[0]）。
    fn set_successor(&mut self, s: NodeInfo) {
        self.successor = Some(s);
        self.fingers[0] = Some(s);
    }

    /// 收到 notify：候选前驱 candidate 说它可能是我的前驱。
    /// 如果它确实比当前前驱更接近我（落在 (predecessor, self) 内），就更新。
    pub fn notified(&mut self, candidate: NodeInfo) {
        let need_update = match self.predecessor {
            None => true,
            Some(p) => in_open_interval(candidate.id, p.id, self.id),
        };
        if need_update {
            self.predecessor = Some(candidate);
        }
    }

    // ── 带 RPC 的核心操作 ────────────────────────────────────────

    /// 查找 key k 的后继节点（递归查找，§IV.2）。
    ///
    /// 先看 k 是不是落在我和我后继之间——是就返回后继。
    /// 否则找最接近 k 的前置 finger，递归问它。
    pub fn find_successor<R: ChordRpc>(&self, k: NodeId, rpc: &R) -> Option<NodeInfo> {
        let succ = self.successor?;
        if in_closed_interval(k, self.id, succ.id) {
            return Some(succ);
        }
        let n_prime = self.closest_preceding_finger(k);
        let n_prime_id = n_prime?.id;
        if n_prime_id == self.id {
            // 已经找不到更近的了，后继就是答案（防止无限递归）
            return Some(succ);
        }
        rpc.find_successor(n_prime_id, k)
    }

    /// 加入一个已有环（通过 bootstrap 节点）。
    /// 只初始化 successor 和 finger[0]，stabilize 会逐步完善。
    pub fn join<R: ChordRpc>(&mut self, bootstrap: NodeId, rpc: &R) -> bool {
        match rpc.find_successor(bootstrap, self.id) {
            Some(succ) => {
                self.set_successor(succ);
                self.predecessor = None; // 等 stabilize 时由后继 notify 我
                true
            }
            None => false,
        }
    }

    /// 周期性 stabilize（§IV.3）：
    /// 1. 问后继它的前驱 x
    /// 2. 如果 x 比当前后继更接近我（落在 (self, successor) 内），更新后继
    /// 3. 通知后继"我可能是你的前驱"
    pub fn stabilize<R: ChordRpc>(&mut self, rpc: &R) {
        let succ = match self.successor {
            Some(s) => s,
            None => return,
        };

        // 问后继的前驱；后继 == 自己时直接读本地，避免自 RPC 死锁
        let pred_of_succ = if succ.id == self.id {
            self.predecessor
        } else {
            rpc.get_predecessor(succ.id)
        };

        if let Some(x) = pred_of_succ {
            // x 在我和后继之间 → 它才是我真正的后继
            // 注意：succ.id == self.id 时（初始单节点环），
            // in_open_interval(x.id, self.id, succ.id) 退化为
            // in_open_interval(x.id, self.id, self.id)，
            // 环绕情形下任何 x != self.id 都为真 → 正确更新后继。
            if x.id != succ.id && in_open_interval(x.id, self.id, succ.id) {
                self.set_successor(x);
            }
        }

        // 通知后继：我可能是你的前驱
        // 单节点环时（后继=自己），不用通知自己
        if succ.id != self.id {
            rpc.notify(succ.id, self.info());
        }
    }

    /// 周期性刷新 finger table 中的一个槽位（§IV.4）。
    /// 每次调用只刷新一个（round-robin），避免一次性全量 RPC。
    pub fn fix_fingers<R: ChordRpc>(&mut self, rpc: &R) {
        // finger[i] = find_successor(id + 2^i)
        let i = self.next_fix;
        let start = self.id.wrapping_add(1u64 << i); // 注意：i∈[0,63]，1<<63 OK
        if let Some(s) = self.find_successor(start, rpc) {
            self.fingers[i] = Some(s);
        }
        self.next_fix = (self.next_fix + 1) % FINGER_COUNT;
    }

    // ── DHT 操作 ────────────────────────────────────────────────

    /// 存一个键值对：路由到负责节点后落盘。
    /// 返回负责节点的 ID（方便测试验证）。
    pub fn dht_put<R: ChordRpc>(&mut self, key: NodeId, value: Vec<u8>, rpc: &R) -> Option<NodeId> {
        let owner = self.find_successor(key, rpc)?;
        if owner.id == self.id {
            // 我就是负责节点，直接存
            self.store.insert(key, value);
        } else {
            // 远程节点，走 RPC put（此处简化：调用方直接操作目标节点 store）
            // 生产环境需要单独的 put RPC；P2 测试用 InProcessRpc 直接写入。
            // 为保持 trait 简洁，put 由上层 DhtService 统一编排。
            return None;
        }
        Some(owner.id)
    }

    /// 取一个键的值：路由到负责节点后读取。
    pub fn dht_get<R: ChordRpc>(&self, key: NodeId, rpc: &R) -> Option<Vec<u8>> {
        let owner = self.find_successor(key, rpc)?;
        if owner.id == self.id {
            self.store.get(&key).cloned()
        } else {
            // 远程 get：P2 测试通过 InProcessRpc 直接读目标节点 store
            None
        }
    }
}

// ── 测试辅助：进程内 RPC ──────────────────────────────────────────
//
// 放在模块底部，生产代码不依赖；tests 模块直接用。
// test-utils feature 打开后，其他 crate 也能用来写集成测试。

#[cfg(any(test, feature = "test-utils"))]
pub mod test_infra {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    /// 进程内 RPC：用全局 HashMap 找到节点，直接调用其方法。
    /// 所有节点共享同一个 InProcessRpc 实例，模拟真实网络。
    ///
    /// 锁层级铁律（防止死锁）：
    /// 1. `nodes` 锁（HashMap 级）：只用来查节点 Arc，查完立即释放
    /// 2. 单个节点锁（ChordNode 级）：在 `nodes` 锁外获取
    /// 3. 绝不在持节点锁时持有 `nodes` 锁，否则 RPC 回调会死锁
    pub struct InProcessRpc {
        nodes: Mutex<HashMap<NodeId, Arc<Mutex<ChordNode>>>>,
    }

    impl Default for InProcessRpc {
        fn default() -> Self {
            Self::new()
        }
    }

    impl InProcessRpc {
        pub fn new() -> Self {
            Self { nodes: Mutex::new(HashMap::new()) }
        }

        pub fn register(&self, node: Arc<Mutex<ChordNode>>) {
            let id = node.lock().unwrap().id;
            self.nodes.lock().unwrap().insert(id, node);
        }

        /// 按 ID 取节点 Arc（拷贝出来后就释放 nodes 锁）。
        fn get_node(&self, id: NodeId) -> Option<Arc<Mutex<ChordNode>>> {
            self.nodes.lock().unwrap().get(&id).cloned()
        }

        /// 只读操作：取节点锁 → 调用 → 返回（nodes 锁在取 Arc 后就放了）
        fn read<F, T>(&self, id: NodeId, f: F) -> Option<T>
        where
            F: FnOnce(&ChordNode) -> T,
        {
            let node = self.get_node(id)?;
            let result = f(&node.lock().unwrap());
            Some(result)
        }

        /// 只写操作：取节点锁 → 调用 → 返回
        fn write<F, T>(&self, id: NodeId, f: F) -> Option<T>
        where
            F: FnOnce(&mut ChordNode) -> T,
        {
            let node = self.get_node(id)?;
            let result = f(&mut node.lock().unwrap());
            Some(result)
        }

        /// 所有节点 ID 快照
        fn all_ids(&self) -> Vec<NodeId> {
            self.nodes
                .lock()
                .unwrap()
                .keys()
                .copied()
                .collect()
        }
    }

    impl ChordRpc for InProcessRpc {
        fn get_successor(&self, n: NodeId) -> Option<NodeInfo> {
            self.read(n, |node| node.successor).flatten()
        }

        fn get_predecessor(&self, n: NodeId) -> Option<NodeInfo> {
            self.read(n, |node| node.predecessor).flatten()
        }

        fn notify(&self, n: NodeId, caller: NodeInfo) {
            self.write(n, |node| node.notified(caller));
        }

        fn find_successor(&self, n: NodeId, k: NodeId) -> Option<NodeInfo> {
            // 迭代式实现，不在持节点锁时发 RPC（否则死锁）
            self.iterative_find_successor(n, k)
        }

        fn closest_preceding_finger(&self, n: NodeId, k: NodeId) -> Option<NodeInfo> {
            self.read(n, |node| node.closest_preceding_finger(k)).flatten()
        }

        fn dht_put(&self, from: NodeId, key: NodeId, value: Vec<u8>) -> Option<NodeId> {
            let owner = self.iterative_find_successor(from, key)?;
            self.write(owner.id, |node| {
                node.store.insert(key, value);
            })?;
            Some(owner.id)
        }

        fn dht_get(&self, from: NodeId, key: NodeId) -> Option<Vec<u8>> {
            let owner = self.iterative_find_successor(from, key)?;
            self.read(owner.id, |node| node.store.get(&key).cloned())?
        }
    }

    impl InProcessRpc {
        /// 迭代式 find_successor（避免递归 + 持锁造成的死锁）。
        pub fn iterative_find_successor(&self, start: NodeId, k: NodeId) -> Option<NodeInfo> {
            let mut current = start;
            // 最多跳 FINGER_COUNT 次（O(log N) 上界），防环
            for _ in 0..FINGER_COUNT {
                let node = self.get_node(current)?;
                let n = node.lock().unwrap();
                let succ = n.successor?;
                // 如果 k 在 (current, succ] 之间，succ 就是答案
                if in_closed_interval(k, n.id, succ.id) {
                    return Some(succ);
                }
                // 否则找最接近的前置 finger 继续问
                let next = n.closest_preceding_finger(k)?;
                let next_id = next.id;
                drop(n); // 提前释放节点锁

                if succ.id == current || current == next_id {
                    // 没进展了，后继就是答案
                    return Some(succ);
                }
                current = next_id;
            }
            None // 超出跳数上限（不应发生在正常环上）
        }

        /// 辅助：让所有节点各跑一轮 stabilize + 若干 fix_fingers，
        /// 模拟一段时间后的收敛状态。
        pub fn converge(&self, rounds: usize) {
            for _ in 0..rounds {
                let ids = self.all_ids();
                // 每个节点 stabilize 一次
                for id in &ids {
                    if let Some(node) = self.get_node(*id) {
                        node.lock().unwrap().stabilize(self);
                    }
                }
                // 每个节点 fix_fingers 若干次（逐槽刷新 finger table）
                for _ in 0..FINGER_COUNT {
                    for id in &ids {
                        if let Some(node) = self.get_node(*id) {
                            node.lock().unwrap().fix_fingers(self);
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_infra::InProcessRpc;
    use std::sync::{Arc, Mutex};

    fn addr_from_id(id: NodeId) -> [u8; 16] {
        let mut a = [0u8; 16];
        a[..8].copy_from_slice(&id.to_be_bytes());
        a
    }

    fn make_node(id: NodeId) -> (Arc<Mutex<ChordNode>>, NodeInfo) {
        let addr = addr_from_id(id);
        let node = Arc::new(Mutex::new(ChordNode::new(id, addr)));
        let info = NodeInfo::new(id, addr);
        (node, info)
    }

    fn setup_ring(ids: &[NodeId]) -> (Arc<InProcessRpc>, Vec<Arc<Mutex<ChordNode>>>) {
        let rpc = Arc::new(InProcessRpc::new());
        let mut nodes = Vec::new();
        for (i, &id) in ids.iter().enumerate() {
            let (node, _) = make_node(id);
            rpc.register(node.clone());
            if i > 0 {
                // 依次加入：节点 i 通过节点 0 加入
                let bootstrap = ids[0];
                node.lock().unwrap().join(bootstrap, &*rpc);
            }
            nodes.push(node);
        }
        // 收敛
        rpc.converge(10);
        (rpc, nodes)
    }

    #[test]
    fn node_id_is_bigendian_asn_host() {
        assert_eq!(node_id(0x0000fb14, 0x0000000a), 0x0000fb14_0000000a);
    }

    #[test]
    fn distance_wraps_around_ring() {
        let a = node_id(0, u32::MAX);
        let b = node_id(1, 0);
        assert_eq!(ring_dist(a, b), 1);
        assert_eq!(ring_dist(b, a), u64::MAX);
    }

    #[test]
    fn interval_wrapping() {
        // 正常区间
        assert!(in_open_interval(5, 1, 10));
        assert!(!in_open_interval(1, 1, 10)); // 开区间不包含 lo
        assert!(in_open_interval(10, 1, 10)); // 闭区间包含 hi
        // 环绕
        assert!(in_open_interval(u64::MAX, u64::MAX - 5, 5));
        assert!(in_open_interval(1, u64::MAX - 5, 5));
        assert!(!in_open_interval(u64::MAX / 2, u64::MAX - 5, 5));
    }

    #[test]
    fn single_node_is_own_successor() {
        let (n, _) = make_node(42);
        let n = n.lock().unwrap();
        assert_eq!(n.successor.unwrap().id, 42);
        assert_eq!(n.predecessor.unwrap().id, 42);
        assert!(n.i_am_responsible_for(42));
        assert!(n.i_am_responsible_for(100)); // 单节点环，所有 key 都归它
    }

    #[test]
    fn two_node_join_and_stabilize() {
        let rpc = Arc::new(InProcessRpc::new());
        let (n1, _) = make_node(100);
        let (n2, _) = make_node(200);
        rpc.register(n1.clone());
        rpc.register(n2.clone());

        // n2 通过 n1 加入
        assert!(n2.lock().unwrap().join(100, &*rpc));

        // stabilize 几轮
        rpc.converge(5);

        // n1 的后继 = 200，前驱 = 200（两节点环互相指）
        let n1g = n1.lock().unwrap();
        let n2g = n2.lock().unwrap();
        assert_eq!(n1g.successor.unwrap().id, 200);
        assert_eq!(n1g.predecessor.unwrap().id, 200);
        assert_eq!(n2g.successor.unwrap().id, 100);
        assert_eq!(n2g.predecessor.unwrap().id, 100);
    }

    #[test]
    fn three_node_ring_correct_successors() {
        let (_, nodes) = setup_ring(&[100, 300, 200]); // 乱序加入
        let ids: Vec<NodeId> = nodes
            .iter()
            .map(|n| n.lock().unwrap().successor.unwrap().id)
            .collect();
        // 环上顺序：100 → 200 → 300 → 100
        let n100 = nodes.iter().find(|n| n.lock().unwrap().id == 100).unwrap();
        let n200 = nodes.iter().find(|n| n.lock().unwrap().id == 200).unwrap();
        let n300 = nodes.iter().find(|n| n.lock().unwrap().id == 300).unwrap();

        assert_eq!(n100.lock().unwrap().successor.unwrap().id, 200);
        assert_eq!(n200.lock().unwrap().successor.unwrap().id, 300);
        assert_eq!(n300.lock().unwrap().successor.unwrap().id, 100);

        assert_eq!(n100.lock().unwrap().predecessor.unwrap().id, 300);
        assert_eq!(n200.lock().unwrap().predecessor.unwrap().id, 100);
        assert_eq!(n300.lock().unwrap().predecessor.unwrap().id, 200);
        let _ = ids;
    }

    #[test]
    fn find_successor_routes_correctly() {
        let (rpc, _) = setup_ring(&[100, 200, 300, 400, 500]);

        // key=150 的后继应该是 200
        let s1 = rpc.iterative_find_successor(100, 150).unwrap();
        assert_eq!(s1.id, 200);

        // key=350 的后继应该是 400
        let s2 = rpc.iterative_find_successor(200, 350).unwrap();
        assert_eq!(s2.id, 400);

        // key=550 环绕的后继应该是 100
        let s3 = rpc.iterative_find_successor(500, 550).unwrap();
        assert_eq!(s3.id, 100);

        // key=99 环绕的后继应该是 100
        let s4 = rpc.iterative_find_successor(300, 99).unwrap();
        assert_eq!(s4.id, 100);
    }

    #[test]
    fn dht_put_and_get_across_nodes() {
        let (rpc, _) = setup_ring(&[100, 200, 300]);

        // 从节点 100 存 key=250（归 300 管）
        let owner = rpc.dht_put(100, 250, b"hello".to_vec()).unwrap();
        assert_eq!(owner, 300);

        // 从节点 200 查 key=250，能找到
        let val = rpc.dht_get(200, 250).unwrap();
        assert_eq!(val, b"hello");

        // 从节点 300 查也能找到
        let val2 = rpc.dht_get(300, 250).unwrap();
        assert_eq!(val2, b"hello");

        // 不存在的 key 返回 None
        assert!(rpc.dht_get(100, 999).is_none());
    }

    #[test]
    fn dht_key_distribution_across_three_nodes() {
        let (rpc, nodes) = setup_ring(&[100, 200, 300]);

        // 存 30 个随机 key
        for i in 0..30u64 {
            let key = i * 23 + 7; // 分散的 key
            rpc.dht_put(100, key, vec![i as u8]);
        }

        // 每个节点应该分到大约 10 个 key（均匀分布下）
        let counts: Vec<usize> = nodes
            .iter()
            .map(|n| n.lock().unwrap().store.len())
            .collect();
        let total: usize = counts.iter().sum();
        assert_eq!(total, 30, "所有 key 都应该被存储");

        // 简单合理性检查：没有节点存了全部 30 个（说明分布了）
        for &c in &counts {
            assert!(c < 30, "每个节点都应该只存一部分 key，实际 {c}/30");
        }
    }

    #[test]
    fn responsible_for_matches_ring_position() {
        let (_, nodes) = setup_ring(&[100, 200, 300]);
        let n100 = nodes.iter().find(|n| n.lock().unwrap().id == 100).unwrap();
        let n200 = nodes.iter().find(|n| n.lock().unwrap().id == 200).unwrap();
        let n300 = nodes.iter().find(|n| n.lock().unwrap().id == 300).unwrap();

        // key=150 ∈ (100, 200] → 归 200
        assert!(!n100.lock().unwrap().i_am_responsible_for(150));
        assert!(n200.lock().unwrap().i_am_responsible_for(150));
        assert!(!n300.lock().unwrap().i_am_responsible_for(150));

        // key=100 → 归 100（自己的 ID）
        assert!(n100.lock().unwrap().i_am_responsible_for(100));

        // key=50 环绕 → ∈ (300, 100] → 归 100
        assert!(n100.lock().unwrap().i_am_responsible_for(50));
        assert!(!n300.lock().unwrap().i_am_responsible_for(50));
    }
}
