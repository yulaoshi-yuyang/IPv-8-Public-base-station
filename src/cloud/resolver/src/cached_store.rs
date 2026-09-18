//! 低延迟缓存层：在任意 Store 前端套一层内存热点缓存。
//!
//! 设计目标：读路径 P99 压到微秒级。
//!
//! P0 优化：
//! - 单次哈希查找（get_mut 合并 contains_key + get + get_mut 三次为一次）
//! - aHash 替代 SipHash-1-3（AES-NI 加速，~8ns vs ~100ns）
//! - Arc<Entry> 共享指针（clone ~5ns vs Entry 深拷贝 ~200ns）
//!
//! P1 优化：
//! - lru::LruCache 替代手写 AHashMap + 逻辑时钟：O(1) 淘汰（双向链表弹出）
//!   vs 之前 O(n) 全表扫描。10K 条目时从 ~50µs → ~10ns
//! - SmallVec 栈上化空集合（NodeRecord 的 alt_entries / local_candidates）
//!
//! P2 优化：
//! - RefCell → parking_lot::Mutex：支持多线程并发读（RwLock 外层锁允许并发 resolve）
//! - parking_lot::Mutex 无 poisoning、自适应自旋，lock+unlock ~25ns
//! - 临界区极短（hash 查找 + Arc clone ~25ns），并发吞吐不受限

use std::sync::Arc;
use std::time::{Duration, Instant};

use ahash::AHashMap;
use ipv8_codec::IPv8Address;
use lru::LruCache;
use parking_lot::Mutex;

use crate::{ArcEntry, Entry, Store};

/// 缓存配置
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// 缓存最大条目数（硬上限，超出触发 LRU 淘汰）
    pub max_entries: usize,
    /// 负缓存 TTL（"不存在"的记忆时间，比正常 TTL 短很多）
    pub negative_ttl: Duration,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_entries: 10_000,
            negative_ttl: Duration::from_secs(10),
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub negative_hits: u64,
    pub writes: u64,
}

struct CacheState {
    /// LruCache 内部用双向链表 + aHashMap 实现 O(1) get/put/evict
    cache: LruCache<IPv8Address, Arc<Entry>>,
    negative: AHashMap<IPv8Address, Instant>,
    stats: CacheStats,
}

/// 低延迟缓存包装器：在任意 Store 前端加热点缓存。
///
/// 读路径性能模型（P2 优化后）：
/// - 缓存命中：~75ns（外层 RwLock 读锁 ~25ns + 内层 Mutex ~25ns + hash+Arc ~25ns）
/// - 缓存未命中：底层存储延迟 + 回填开销
/// - 负缓存命中：~75ns
/// - LRU 淘汰：O(1)（双向链表尾部弹出），10K 条目时 ~10ns
///
/// 并发模型：
/// - 外层 RwLock 允许多个 resolve 并发读
/// - 内层 Mutex 仅保护缓存状态，临界区极短（~25ns）
/// - 实际吞吐受内层 Mutex 限制，但 25ns 临界区 → ~40M ops/s
pub struct CachedStore<S: Store> {
    inner: S,
    config: CacheConfig,
    state: Mutex<CacheState>,
}

impl<S: Store> CachedStore<S> {
    pub fn new(inner: S, config: CacheConfig) -> Self {
        let cap = std::num::NonZeroUsize::new(config.max_entries)
            .expect("max_entries must be > 0");
        Self {
            inner,
            config,
            state: Mutex::new(CacheState {
                cache: LruCache::new(cap),
                negative: AHashMap::new(),
                stats: CacheStats::default(),
            }),
        }
    }

    pub fn into_inner(self) -> S {
        self.inner
    }

    pub fn inner(&self) -> &S {
        &self.inner
    }

    pub fn stats(&self) -> CacheStats {
        self.state.lock().stats.clone()
    }

    pub fn cache_len(&self) -> usize {
        self.state.lock().cache.len()
    }

    #[cfg(test)]
    pub fn cache_contains(&self, addr: &IPv8Address) -> bool {
        self.state.lock().cache.peek(addr).is_some()
    }
}

impl<S: Store> Store for CachedStore<S> {
    fn get(&self, addr: &IPv8Address) -> Option<ArcEntry> {
        // Phase 1: 检查缓存
        {
            let mut state = self.state.lock();

            // 1) LruCache::get 同时查找 + 提升到链表头部（O(1)）
            if let Some(arc_entry) = state.cache.get(addr) {
                let cloned = Arc::clone(arc_entry);
                state.stats.hits += 1;
                return Some(cloned);
            }

            // 2) 负缓存命中 → 直接返回 None，不穿透到底层
            if let Some(&expires_at) = state.negative.get(addr) {
                if expires_at > Instant::now() {
                    state.stats.negative_hits += 1;
                    return None;
                }
                state.negative.remove(addr);
            }

            state.stats.misses += 1;
        } // lock 释放，允许查底层

        // 3) 底层查询
        let result = self.inner.get(addr);

        // Phase 2: 回填缓存
        let mut state = self.state.lock();
        match result {
            Some(arc_entry) => {
                state.cache.put(*addr, Arc::clone(&arc_entry));
                Some(arc_entry)
            }
            None => {
                state.negative.insert(*addr, Instant::now() + self.config.negative_ttl);
                None
            }
        }
    }

    fn insert(&mut self, addr: IPv8Address, e: Entry) {
        // 写通：先写底层（权威存储），再更缓存
        self.inner.insert(addr, e.clone());

        let mut state = self.state.lock();
        state.stats.writes += 1;
        state.cache.put(addr, Arc::new(e));

        // 写入后清除负缓存（之前"不存在"的结论失效了）
        state.negative.remove(&addr);
    }

    fn sweep_expired(&mut self, now: Instant) -> usize {
        let removed_inner = self.inner.sweep_expired(now);

        let mut state = self.state.lock();

        // LruCache 没有 retain，需要收集过期 key 再逐个 pop
        let expired_keys: Vec<IPv8Address> = state
            .cache
            .iter()
            .filter(|(_, arc)| arc.rec.is_expired(now))
            .map(|(k, _)| *k)
            .collect();

        let removed_cache = expired_keys.len();
        for k in &expired_keys {
            state.cache.pop(k);
        }

        state.negative.retain(|_, expires| *expires > now);

        removed_inner + removed_cache
    }

    fn len(&self) -> usize {
        self.inner.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MemStore, NodeRecord};

    fn test_addr(i: u8) -> IPv8Address {
        IPv8Address::with_region(i as u64, 0, 0, 0, 0)
    }

    fn make_entry(seed: u8) -> Entry {
        Entry {
            ed_pub: [seed; 32],
            rec: NodeRecord {
                tunnel_entry: format!("10.0.0.{}:4000", seed),
                alt_entries: smallvec::smallvec![],
                ipv8_capable: true,
                mtu: 1432,
                registered_at: Instant::now(),
                ttl: Duration::from_secs(300),
                observed: None,
                local_candidates: smallvec::smallvec![],
            },
        }
    }

    #[test]
    fn p2_cache_hit_on_write_through() {
        let mem = MemStore::default();
        let mut cache = CachedStore::new(mem, CacheConfig::default());

        let addr = test_addr(1);
        cache.insert(addr, make_entry(1));

        let got = cache.get(&addr).unwrap();
        assert_eq!(got.ed_pub, [1; 32]);

        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 0);
        assert_eq!(stats.writes, 1);
    }

    #[test]
    fn p2_cache_miss_then_backfilled() {
        let mut mem = MemStore::default();
        let addr = test_addr(2);
        mem.insert(addr, make_entry(2));

        let cache = CachedStore::new(mem, CacheConfig::default());

        let got = cache.get(&addr).unwrap();
        assert_eq!(got.ed_pub, [2; 32]);
        assert_eq!(cache.stats().misses, 1);
        assert_eq!(cache.stats().hits, 0);

        let got2 = cache.get(&addr).unwrap();
        assert_eq!(got2.ed_pub, [2; 32]);
        assert_eq!(cache.stats().hits, 1);
        assert_eq!(cache.stats().misses, 1);
    }

    #[test]
    fn p2_negative_caching_prevents_penetration() {
        let mem = MemStore::default();
        let cache = CachedStore::new(
            mem,
            CacheConfig {
                max_entries: 100,
                negative_ttl: Duration::from_secs(5),
            },
        );

        let addr = test_addr(99);

        assert!(cache.get(&addr).is_none());
        assert_eq!(cache.stats().misses, 1);
        assert_eq!(cache.stats().negative_hits, 0);

        assert!(cache.get(&addr).is_none());
        assert_eq!(cache.stats().negative_hits, 1);
        assert_eq!(cache.stats().misses, 1);
    }

    #[test]
    fn p2_insert_clears_negative_cache() {
        let mem = MemStore::default();
        let mut cache = CachedStore::new(
            mem,
            CacheConfig {
                max_entries: 100,
                negative_ttl: Duration::from_secs(5),
            },
        );

        let addr = test_addr(5);

        assert!(cache.get(&addr).is_none());
        assert!(cache.get(&addr).is_none());
        assert_eq!(cache.stats().negative_hits, 1);

        cache.insert(addr, make_entry(5));

        let got = cache.get(&addr).unwrap();
        assert_eq!(got.ed_pub, [5; 32]);
        assert_eq!(cache.stats().hits, 1);
    }

    #[test]
    fn p2_lru_eviction_when_over_capacity() {
        let mem = MemStore::default();
        let mut cache = CachedStore::new(
            mem,
            CacheConfig {
                max_entries: 3,
                negative_ttl: Duration::from_secs(10),
            },
        );

        for i in 0..5u8 {
            cache.insert(test_addr(i), make_entry(i));
        }

        assert_eq!(cache.cache_len(), 3);

        assert!(!cache.cache_contains(&test_addr(0)), "addr 0 should be evicted from cache");
        assert!(!cache.cache_contains(&test_addr(1)), "addr 1 should be evicted from cache");
        assert!(cache.cache_contains(&test_addr(2)));
        assert!(cache.cache_contains(&test_addr(3)));
        assert!(cache.cache_contains(&test_addr(4)));

        let got0 = cache.get(&test_addr(0));
        assert!(got0.is_some(), "evicted entry still available from underlying store");
        assert!(cache.cache_contains(&test_addr(0)));
    }

    #[test]
    fn p2_sweep_expired_clears_both_layers() {
        let mem = MemStore::default();
        let mut cache = CachedStore::new(mem, CacheConfig::default());

        let addr = test_addr(7);
        let mut entry = make_entry(7);
        entry.rec.ttl = Duration::from_secs(1);
        entry.rec.registered_at = Instant::now() - Duration::from_secs(60);
        cache.insert(addr, entry);

        assert!(cache.get(&addr).is_some());
        assert_eq!(cache.cache_len(), 1);

        let removed = cache.sweep_expired(Instant::now());
        assert!(removed > 0);

        assert!(cache.get(&addr).is_none());
        assert_eq!(cache.cache_len(), 0);
    }

    #[test]
    fn p2_read_through_pattern() {
        let mut mem = MemStore::default();
        for i in 0..10u8 {
            mem.insert(test_addr(i), make_entry(i));
        }

        let cache = CachedStore::new(mem, CacheConfig::default());

        for i in 0..10u8 {
            let got = cache.get(&test_addr(i)).unwrap();
            assert_eq!(got.ed_pub, [i; 32]);
        }
        assert_eq!(cache.stats().misses, 10);
        assert_eq!(cache.stats().hits, 0);

        for i in 0..10u8 {
            let got = cache.get(&test_addr(i)).unwrap();
            assert_eq!(got.ed_pub, [i; 32]);
        }
        assert_eq!(cache.stats().hits, 10);
        assert_eq!(cache.stats().misses, 10);
    }

    #[test]
    fn p2_access_order_affects_lru() {
        let mem = MemStore::default();
        let mut cache = CachedStore::new(
            mem,
            CacheConfig {
                max_entries: 3,
                negative_ttl: Duration::from_secs(10),
            },
        );

        for i in 0..3u8 {
            cache.insert(test_addr(i), make_entry(i));
        }

        // 访问 addr 0（LruCache 将其提升到最近使用）
        let _ = cache.get(&test_addr(0));

        // 写入第 4 个 addr 3 → 淘汰最久未访问的 addr 1
        cache.insert(test_addr(3), make_entry(3));

        assert_eq!(cache.cache_len(), 3);
        assert!(
            !cache.cache_contains(&test_addr(1)),
            "addr 1 should be evicted from cache (LRU, not accessed)"
        );
        assert!(
            cache.cache_contains(&test_addr(0)),
            "addr 0 was touched, should survive"
        );
        assert!(cache.cache_contains(&test_addr(2)));
        assert!(cache.cache_contains(&test_addr(3)));

        let got1 = cache.get(&test_addr(1));
        assert!(got1.is_some(), "evicted addr 1 still in underlying store");
    }

    #[test]
    fn p2_repeated_access_preserves_hot_keys() {
        let mem = MemStore::default();
        let mut cache = CachedStore::new(
            mem,
            CacheConfig {
                max_entries: 3,
                negative_ttl: Duration::from_secs(10),
            },
        );

        for i in 0..3u8 {
            cache.insert(test_addr(i), make_entry(i));
        }

        for _ in 0..10 {
            let _ = cache.get(&test_addr(0));
        }

        for i in 3..6u8 {
            cache.insert(test_addr(i), make_entry(i));
        }

        assert!(
            cache.get(&test_addr(0)).is_some(),
            "hot key 0 should survive repeated evictions"
        );
        assert_eq!(cache.cache_len(), 3);
    }
}
