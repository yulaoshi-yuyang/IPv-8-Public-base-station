//! DHT 存储后端：把 Resolver 的登记数据放到 Chord DHT 上。
//!
//! 每个 Resolver 节点同时是一个 Chord 节点。登记/查询请求通过
//! DHT put/get 路由到负责 key 的节点，实现分布式解析。
//!
//! Key 映射：用 `node_id(addr.protocol, addr.region_hi, addr.region_mid, addr.region_lo)` 把 IPv8 地址映
//! 到 64 位 Chord 环上（与节点 ID 同构，Region 粒度路由）。

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use ipv8_codec::IPv8Address;
use ipv8_routing::cf::{ChordNode, ChordRpc, NodeId, node_id};

use crate::{Entry, NodeRecord, Store};

// ── Entry ↔ Vec<u8> 二进制编解码 ────────────────────────────────
//
//  格式（小端）：
//    ed_pub: 32 bytes
//    tunnel_entry_len: u16, tunnel_entry: [u8]
//    alt_entries_count: u16, for each: len:u16 + bytes
//    ipv8_capable: u8
//    mtu: u32
//    registered_at_secs: u64  (SystemTime 秒级时间戳，过期判定用)
//    ttl_secs: u64
//    observed_tag: u8 (0 = none, 1 = some)
//      if some: addr_len:u16 + addr + timestamp_secs:u64
//    local_candidates_count: u16, for each: len:u16 + bytes

fn encode_entry(e: &Entry) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);

    // ed_pub
    buf.extend_from_slice(&e.ed_pub);

    // tunnel_entry
    let te = e.rec.tunnel_entry.as_bytes();
    buf.extend_from_slice(&(te.len() as u16).to_le_bytes());
    buf.extend_from_slice(te);

    // alt_entries
    buf.extend_from_slice(&(e.rec.alt_entries.len() as u16).to_le_bytes());
    for a in &e.rec.alt_entries {
        let b = a.as_bytes();
        buf.extend_from_slice(&(b.len() as u16).to_le_bytes());
        buf.extend_from_slice(b);
    }

    buf.push(e.rec.ipv8_capable as u8);
    buf.extend_from_slice(&e.rec.mtu.to_le_bytes());

    // registered_at: Instant → SystemTime 秒级近似
    let reg_secs = instant_to_system_secs(e.rec.registered_at);
    buf.extend_from_slice(&reg_secs.to_le_bytes());

    buf.extend_from_slice(&e.rec.ttl.as_secs().to_le_bytes());

    // observed
    match &e.rec.observed {
        None => buf.push(0),
        Some((addr, t)) => {
            buf.push(1);
            let b = addr.as_bytes();
            buf.extend_from_slice(&(b.len() as u16).to_le_bytes());
            buf.extend_from_slice(b);
            let t_secs = instant_to_system_secs(*t);
            buf.extend_from_slice(&t_secs.to_le_bytes());
        }
    }

    // local_candidates
    buf.extend_from_slice(&(e.rec.local_candidates.len() as u16).to_le_bytes());
    for c in &e.rec.local_candidates {
        let b = c.as_bytes();
        buf.extend_from_slice(&(b.len() as u16).to_le_bytes());
        buf.extend_from_slice(b);
    }

    buf
}

fn decode_entry(data: &[u8]) -> Option<Entry> {
    let mut p = 0;

    // ed_pub
    if p + 32 > data.len() {
        return None;
    }
    let mut ed_pub = [0u8; 32];
    ed_pub.copy_from_slice(&data[p..p + 32]);
    p += 32;

    // tunnel_entry
    let te_len = read_u16(data, &mut p)? as usize;
    let tunnel_entry = read_str(data, &mut p, te_len)?;

    // alt_entries
    let alt_count = read_u16(data, &mut p)? as usize;
    let mut alt_entries = Vec::with_capacity(alt_count);
    for _ in 0..alt_count {
        let len = read_u16(data, &mut p)? as usize;
        alt_entries.push(read_str(data, &mut p, len)?);
    }

    // ipv8_capable
    if p + 1 > data.len() {
        return None;
    }
    let ipv8_capable = data[p] != 0;
    p += 1;

    // mtu
    let mtu = read_u32(data, &mut p)?;

    // registered_at_secs
    let reg_secs = read_u64(data, &mut p)?;

    // ttl
    let ttl_secs = read_u64(data, &mut p)?;
    let ttl = Duration::from_secs(ttl_secs);

    // observed
    if p + 1 > data.len() {
        return None;
    }
    let obs_tag = data[p];
    p += 1;
    let observed = match obs_tag {
        0 => None,
        1 => {
            let len = read_u16(data, &mut p)? as usize;
            let addr = read_str(data, &mut p, len)?;
            let t_secs = read_u64(data, &mut p)?;
            Some((addr, system_secs_to_instant(t_secs)))
        }
        _ => return None,
    };

    // local_candidates
    let lc_count = read_u16(data, &mut p)? as usize;
    let mut local_candidates = Vec::with_capacity(lc_count);
    for _ in 0..lc_count {
        let len = read_u16(data, &mut p)? as usize;
        local_candidates.push(read_str(data, &mut p, len)?);
    }

    let registered_at = system_secs_to_instant(reg_secs);

    Some(Entry {
        ed_pub,
        rec: NodeRecord {
            tunnel_entry,
            alt_entries: alt_entries.into(),
            ipv8_capable,
            mtu,
            registered_at,
            ttl,
            observed,
            local_candidates: local_candidates.into(),
        },
    })
}

// Instant ↔ SystemTime 近似换算（秒级精度，对分钟/小时级 TTL 够用）

fn instant_to_system_secs(t: Instant) -> u64 {
    let now_inst = Instant::now();
    let now_sys = SystemTime::now();
    if t >= now_inst {
        let d = t.duration_since(now_inst);
        now_sys
            .checked_add(d)
            .and_then(|s| s.duration_since(SystemTime::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(u64::MAX / 2)
    } else {
        let d = now_inst.duration_since(t);
        now_sys
            .checked_sub(d)
            .and_then(|s| s.duration_since(SystemTime::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

fn system_secs_to_instant(secs: u64) -> Instant {
    let target = SystemTime::UNIX_EPOCH + Duration::from_secs(secs);
    let now_sys = SystemTime::now();
    let now_inst = Instant::now();
    match target.duration_since(now_sys) {
        Ok(d) => now_inst + d,
        Err(e) => {
            // 目标在过去：从 now_inst 往回减。
            // DHT 条目都是分钟/小时级 TTL，绝不可能早于 Instant 起点，
            // 直接减是安全的。
            now_inst - e.duration()
        }
    }
}

#[inline]
fn read_u16(data: &[u8], p: &mut usize) -> Option<u16> {
    if *p + 2 > data.len() {
        return None;
    }
    let v = u16::from_le_bytes(data[*p..*p + 2].try_into().ok()?);
    *p += 2;
    Some(v)
}

#[inline]
fn read_u32(data: &[u8], p: &mut usize) -> Option<u32> {
    if *p + 4 > data.len() {
        return None;
    }
    let v = u32::from_le_bytes(data[*p..*p + 4].try_into().ok()?);
    *p += 4;
    Some(v)
}

#[inline]
fn read_u64(data: &[u8], p: &mut usize) -> Option<u64> {
    if *p + 8 > data.len() {
        return None;
    }
    let v = u64::from_le_bytes(data[*p..*p + 8].try_into().ok()?);
    *p += 8;
    Some(v)
}

#[inline]
fn read_str(data: &[u8], p: &mut usize, len: usize) -> Option<String> {
    if *p + len > data.len() {
        return None;
    }
    let s = String::from_utf8_lossy(&data[*p..*p + len]).into_owned();
    *p += len;
    Some(s)
}

// ── DHT Store 实现 ──────────────────────────────────────────────

/// DHT 存储后端：把 Entry 存到 Chord 分布式哈希表中。
///
/// 每个 `DhtStore` 实例对应一个 Chord 节点。通过 `ChordRpc` trait
/// 与环上其他节点通信。测试用 `InProcessRpc`，生产环境替换为
/// gRPC/QUIC 等真实网络实现。
pub struct DhtStore<R: ChordRpc> {
    node: Arc<Mutex<ChordNode>>,
    rpc: R,
}

impl<R: ChordRpc> DhtStore<R> {
    /// 创建 DHT 存储（节点需已加入环）。
    pub fn new(node: Arc<Mutex<ChordNode>>, rpc: R) -> Self {
        Self { node, rpc }
    }

    /// 获取本地 Chord 节点 ID。
    pub fn node_id(&self) -> NodeId {
        self.node.lock().unwrap().id
    }

    /// IPv8Address → DHT Key（Region 粒度，与节点 ID 同构）
    fn addr_to_key(addr: &IPv8Address) -> NodeId {
        // 从新字段重建旧 asn/host_id 语义，保持 DHT 键空间兼容
        let asn = ((addr.region_hi as u32) << 16) | (addr.protocol as u32);
        let host_id = ((addr.region_mid as u32) << 16) | (addr.region_lo as u32);
        node_id(asn, host_id)
    }
}

impl<R: ChordRpc> Store for DhtStore<R> {
    fn get(&self, addr: &IPv8Address) -> Option<Arc<Entry>> {
        let key = Self::addr_to_key(addr);
        let my_id = self.node_id();
        let data = self.rpc.dht_get(my_id, key)?;
        decode_entry(&data).map(Arc::new)
    }

    fn insert(&mut self, addr: IPv8Address, e: Entry) {
        let key = Self::addr_to_key(&addr);
        let data = encode_entry(&e);
        let my_id = self.node_id();
        // 忽略失败（DHT 写失败是分布式常态，上层靠 TTL/重试兜底）
        let _ = self.rpc.dht_put(my_id, key, data);
    }

    fn sweep_expired(&mut self, now: Instant) -> usize {
        // DHT 模式下，每个节点只清理自己负责的本地存储部分。
        // 远程节点的过期条目由各自的 reaper 清理。
        let mut node = self.node.lock().unwrap();
        let mut to_remove = Vec::new();

        for (key, data) in node.store.iter() {
            let expired = decode_entry(data)
                .map(|e| e.rec.is_expired(now))
                .unwrap_or(true); // 解码失败也算过期，清掉
            if expired {
                to_remove.push(*key);
            }
        }

        let count = to_remove.len();
        for k in to_remove {
            node.store.remove(&k);
        }

        count
    }

    fn len(&self) -> usize {
        self.node.lock().unwrap().store.len()
    }
}

// ── 测试基础设施 ────────────────────────────────────────────────

#[cfg(test)]
pub mod test_infra {
    //! 测试用 DHT 基础设施：复用 ipv8-routing 的 InProcessRpc。
    //! 仅在 test 编译时可用。
    pub use ipv8_routing::cf::test_infra::InProcessRpc;
    pub use ipv8_routing::cf::{ChordNode, FINGER_COUNT, NodeId, NodeInfo, node_id};

    use super::*;

    /// 搭建 N 个 DHT 节点的环，返回所有节点的 DhtStore + 共享 RPC。
    /// 节点 ID 按 100, 200, 300... 递增，便于调试。
    pub fn setup_dht_ring(
        n: usize,
    ) -> (Vec<DhtStore<Arc<InProcessRpc>>>, Arc<InProcessRpc>) {
        let rpc = Arc::new(InProcessRpc::new());
        let mut stores = Vec::with_capacity(n);

        for i in 0..n {
            let id = NodeId::from((i as u64 + 1) * 100);
            let addr = [0u8; 16];
            let node = Arc::new(Mutex::new(ChordNode::new(id, addr)));
            rpc.register(node.clone());

            if i > 0 {
                let bootstrap = NodeId::from(100u64);
                node.lock().unwrap().join(bootstrap, &*rpc);
            }

            stores.push(DhtStore::new(node, rpc.clone()));
        }

        // 收敛
        rpc.converge(10);

        (stores, rpc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_infra::*;

    fn test_addr(asn: u32, host: u32) -> IPv8Address {
        IPv8Address::new(
            (asn & 0xFFFF) as u16,
            ((asn >> 16) & 0xFFFF) as u16,
            ((host >> 16) & 0xFFFF) as u16,
            (host & 0xFFFF) as u16,
            0,
            0,
            0,
            0,
        )
    }

    fn make_entry(seed: u8) -> Entry {
        Entry {
            ed_pub: [seed; 32],
            rec: NodeRecord {
                tunnel_entry: format!("10.0.0.{}:4000", seed),
                alt_entries: smallvec::smallvec![format!("192.168.1.{}:4000", seed)],
                ipv8_capable: true,
                mtu: 1432,
                registered_at: Instant::now(),
                ttl: Duration::from_secs(300),
                observed: Some((
                    format!("203.0.113.{}:12345", seed),
                    Instant::now(),
                )),
                local_candidates: smallvec::smallvec![format!("192.168.0.{}:5000", seed)],
            },
        }
    }

    #[test]
    fn p2_encode_decode_roundtrip() {
        let e = make_entry(42);
        let data = encode_entry(&e);
        let decoded = decode_entry(&data).expect("decode failed");
        assert_eq!(decoded.ed_pub, e.ed_pub);
        assert_eq!(decoded.rec.tunnel_entry, e.rec.tunnel_entry);
        assert_eq!(decoded.rec.alt_entries, e.rec.alt_entries);
        assert_eq!(decoded.rec.ipv8_capable, e.rec.ipv8_capable);
        assert_eq!(decoded.rec.mtu, e.rec.mtu);
        assert_eq!(decoded.rec.ttl, e.rec.ttl);
        assert_eq!(decoded.rec.local_candidates, e.rec.local_candidates);
        assert_eq!(
            decoded.rec.observed.as_ref().map(|(a, _)| a.clone()),
            e.rec.observed.as_ref().map(|(a, _)| a.clone())
        );
    }

    #[test]
    fn p2_dht_put_get_single_node() {
        let (stores, _rpc) = setup_dht_ring(1);
        let mut store = stores.into_iter().next().unwrap();

        let addr = test_addr(1, 7);
        let entry = make_entry(7);
        store.insert(addr, entry.clone());

        let got = store.get(&addr).expect("get failed");
        assert_eq!(got.ed_pub, entry.ed_pub);
        assert_eq!(got.rec.tunnel_entry, entry.rec.tunnel_entry);
    }

    #[test]
    fn p2_dht_three_node_put_on_node1_get_on_node3() {
        let (mut stores, _rpc) = setup_dht_ring(3);

        let addr = test_addr(0, 150); // key = 150 → 节点 200 负责
        let entry = make_entry(1);
        stores[0].insert(addr, entry.clone());

        // 从节点 3 查
        let got = stores[2].get(&addr).expect("get from node 3 failed");
        assert_eq!(got.ed_pub, entry.ed_pub);
        assert_eq!(got.rec.tunnel_entry, entry.rec.tunnel_entry);
        assert_eq!(got.rec.mtu, entry.rec.mtu);
    }

    #[test]
    fn p2_dht_five_node_keys_distributed_across_ring() {
        let (mut stores, _rpc) = setup_dht_ring(5);

        // 写入 25 个均匀分布的 key（步长 23，覆盖整个 1..575 区间）
        for i in 1..=25u32 {
            let key = i * 23; // 23, 46, 69, ..., 575
            let addr = test_addr(0, key);
            let entry = make_entry(i as u8);
            stores[0].insert(addr, entry);
        }

        // 5 个节点应该都分到了 key
        let total: usize = stores.iter().map(|s| s.len()).sum();
        assert_eq!(total, 25, "total entries should be 25");

        for (i, store) in stores.iter().enumerate() {
            assert!(
                store.len() >= 2,
                "node {} should have at least 2 keys, got {}",
                i,
                store.len()
            );
        }

        // 从任意节点查都能查到
        for i in 1..=25u32 {
            let key = i * 23;
            let addr = test_addr(0, key);
            let got = stores[4].get(&addr).unwrap_or_else(|| panic!("key {i} not found"));
            assert_eq!(got.ed_pub, [i as u8; 32]);
        }
    }

    #[test]
    fn p2_sweep_expired_removes_dead_entries() {
        let (mut stores, _rpc) = setup_dht_ring(3);

        // 写入一个已过期的条目
        let addr = test_addr(0, 999);
        let mut entry = make_entry(99);
        entry.rec.ttl = Duration::from_secs(1);
        entry.rec.registered_at = Instant::now() - Duration::from_secs(60);
        stores[1].insert(addr, entry);

        // 确认写入成功
        assert!(stores[0].get(&addr).is_some());

        // 每个节点 sweep
        let mut total_removed = 0;
        for store in &mut stores {
            total_removed += store.sweep_expired(Instant::now());
        }
        assert_eq!(total_removed, 1, "should have removed 1 expired entry");

        // 再查应该没了
        assert!(stores[0].get(&addr).is_none());
        assert!(stores[2].get(&addr).is_none());
    }

    #[test]
    fn p2_unknown_key_returns_none() {
        let (stores, _rpc) = setup_dht_ring(3);
        let addr = test_addr(99, 9999);
        assert!(stores[1].get(&addr).is_none());
    }
}
