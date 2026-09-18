//! SQLite 持久化存储（ADR-010：自托管形态的落地实现）。
//!
//! 设计：写通缓存（write-through cache）
//! - 读：直接走内存 HashMap（微秒级，与 MemStore 同速）
//! - 写：同时更新内存 + SQLite（毫秒级，注册/心跳可接受）
//! - 启动：从 SQLite 加载所有未过期条目到内存
//! - 过期清理：同时从内存和 SQLite 中删除
//!
//! 时间处理：`Instant` 不可序列化，用进程启动时的
//! `(Instant, SystemTime)` 基点做近似换算。对分钟~小时级
//! TTL 完全够用，系统时钟跳变的影响可忽略。

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use parking_lot::Mutex;
use rusqlite::{params, Connection};

use ipv8_codec::IPv8Address;

use crate::{Entry, NodeRecord, Store};

/// SQLite 表结构版本（将来升级 schema 用）
const SCHEMA_VERSION: u32 = 1;

const CREATE_TABLE_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS nodes (
    addr_hex       TEXT PRIMARY KEY,    -- IPv8+ 地址 canonical 32hex
    ed_pub         BLOB NOT NULL,       -- 32B Ed25519 公钥
    tunnel_entry   TEXT NOT NULL,       -- 主入口 "ip:port"
    alt_entries    TEXT NOT NULL DEFAULT '[]',  -- JSON 数组
    ipv8_capable   INTEGER NOT NULL DEFAULT 1,  -- bool
    mtu            INTEGER NOT NULL DEFAULT 0,
    registered_at  REAL NOT NULL,       -- unix 时间戳（秒，浮点数保留毫秒精度）
    ttl_secs       REAL NOT NULL,       -- TTL 秒数
    observed_addr  TEXT,                 -- NULL 表示无
    observed_at    REAL,                 -- NULL 表示无
    local_cands    TEXT NOT NULL DEFAULT '[]',  -- JSON 数组
    updated_at     REAL NOT NULL        -- 最后写入时间（诊断用）
);
CREATE INDEX IF NOT EXISTS idx_nodes_registered_at ON nodes(registered_at);
CREATE INDEX IF NOT EXISTS idx_nodes_observed_at ON nodes(observed_at);
"#;

/// 时间换算基点：进程启动时刻的 Instant 与 SystemTime 配对。
/// 用 `instant - base.instant ≈ system_time - base.system` 的近似
/// 关系做双向换算。误差来源 = 两次读取之间的时间差（微秒级）
/// + 系统时钟跳变（罕见，对 TTL 语义无影响）。
pub(crate) struct TimeBase {
    pub instant: Instant,
    pub system: SystemTime,
}

impl TimeBase {
    pub fn now() -> Self {
        // 先读 SystemTime 再读 Instant——SystemTime 可能因系统调用慢一点，
        // Instant 是纯 CPU 寄存器级读取。误差方向一致。
        let system = SystemTime::now();
        let instant = Instant::now();
        Self { instant, system }
    }

    /// Instant → SystemTime（近似；支持基点之前的时间）
    pub fn to_system(&self, t: Instant) -> SystemTime {
        if t >= self.instant {
            self.system + t.duration_since(self.instant)
        } else {
            // t 在基点之前：算出差值并从 system 时间减去
            let d = self.instant.duration_since(t);
            self.system.checked_sub(d).unwrap_or(SystemTime::UNIX_EPOCH)
        }
    }

    /// SystemTime → Instant（近似；支持基点之前的时间）
    pub fn to_instant(&self, t: SystemTime) -> Instant {
        match t.duration_since(self.system) {
            Ok(d) => self.instant + d,
            Err(e) => {
                // t 在基点之前
                let d = e.duration();
                // 夹紧到 instant 基点前最多 1 小时（防止系统时钟大幅回跳导致 Instant 溢出）
                let max_back = Duration::from_secs(3600);
                let clamped = d.min(max_back);
                self.instant.checked_sub(clamped).unwrap_or(self.instant)
            }
        }
    }
}

fn system_to_secs(t: SystemTime) -> f64 {
    match t.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(d) => d.as_secs_f64(),
        Err(_) => 0.0,
    }
}

fn secs_to_system(s: f64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs_f64(s.max(0.0))
}

fn encode_json_strings(list: &[String]) -> String {
    // 手工拼 JSON 数组，避免引入 serde_json 依赖
    let mut s = String::from('[');
    for (i, item) in list.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push('"');
        // 转义 JSON 字符串里的特殊字符
        for c in item.chars() {
            match c {
                '"' => s.push_str("\\\""),
                '\\' => s.push_str("\\\\"),
                '\n' => s.push_str("\\n"),
                '\r' => s.push_str("\\r"),
                '\t' => s.push_str("\\t"),
                c if (c as u32) < 0x20 => {
                    s.push_str(&format!("\\u{:04x}", c as u32));
                }
                c => s.push(c),
            }
        }
        s.push('"');
    }
    s.push(']');
    s
}

fn decode_json_strings(s: &str) -> Vec<String> {
    // 极简 JSON 数组解析（只处理字符串数组，够用）
    let s = s.trim();
    if !s.starts_with('[') || !s.ends_with(']') {
        return Vec::new();
    }
    let inner = &s[1..s.len() - 1];
    if inner.trim().is_empty() {
        return Vec::new();
    }

    let mut result = Vec::new();
    let mut current = String::new();
    let mut in_string = false;
    let mut escape = false;
    let chars: Vec<char> = inner.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];
        if escape {
            match c {
                '"' => current.push('"'),
                '\\' => current.push('\\'),
                '/' => current.push('/'),
                'n' => current.push('\n'),
                'r' => current.push('\r'),
                't' => current.push('\t'),
                'u' => {
                    // \uXXXX
                    if i + 4 < chars.len() {
                        let hex: String = chars[i + 1..=i + 4].iter().collect();
                        if let Ok(code) = u32::from_str_radix(&hex, 16) {
                            if let Some(ch) = char::from_u32(code) {
                                current.push(ch);
                            }
                        }
                        i += 4;
                    }
                }
                _ => current.push(c),
            }
            escape = false;
        } else if in_string {
            if c == '\\' {
                escape = true;
            } else if c == '"' {
                in_string = false;
                result.push(std::mem::take(&mut current));
            } else {
                current.push(c);
            }
        } else if c == '"' {
            in_string = true;
        }
        // 非字符串内的逗号、空白直接跳过
        i += 1;
    }
    result
}

pub struct SqliteStore {
    cache: HashMap<IPv8Address, Arc<Entry>>,
    conn: Mutex<Connection>,
    base: TimeBase,
}

impl SqliteStore {
    /// 打开或创建 SQLite 数据库，并加载未过期条目到内存缓存。
    pub fn open<P: AsRef<std::path::Path>>(path: P) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(path)?;
        conn.execute_batch(CREATE_TABLE_SQL)?;

        // 记录 schema 版本
        conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;

        // WAL 模式：读不阻塞写，写不阻塞读（注册并发时更顺）
        conn.pragma_update(None, "journal_mode", "WAL")?;
        // 同步模式 NORMAL：性能更好，崩溃时最多丢最后一次事务
        // （注册数据丢了就丢了，节点下次心跳重登就行）
        conn.pragma_update(None, "synchronous", "NORMAL")?;

        let base = TimeBase::now();
        let now_secs = system_to_secs(base.system);

        // 加载所有未过期条目到缓存（用块限制 stmt 生命周期，
        // 确保返回前 stmt 已 drop，conn 可以安全 move）
        let cache = {
            let mut stmt = conn.prepare(
                "SELECT addr_hex, ed_pub, tunnel_entry, alt_entries, ipv8_capable, mtu,
                        registered_at, ttl_secs, observed_addr, observed_at, local_cands
                 FROM nodes
                 WHERE registered_at + ttl_secs > ?1",
            )?;

            let mut cache: HashMap<IPv8Address, Arc<Entry>> = HashMap::new();
            let rows = stmt.query_map(params![now_secs], |row| {
                let addr_hex: String = row.get(0)?;
                let ed_pub_blob: Vec<u8> = row.get(1)?;
                let tunnel_entry: String = row.get(2)?;
                let alt_entries_json: String = row.get(3)?;
                let ipv8_capable: i64 = row.get(4)?;
                let mtu: i64 = row.get(5)?;
                let registered_at_secs: f64 = row.get(6)?;
                let ttl_secs: f64 = row.get(7)?;
                let observed_addr: Option<String> = row.get(8)?;
                let observed_at_secs: Option<f64> = row.get(9)?;
                let local_cands_json: String = row.get(10)?;

                let addr = IPv8Address::from_canonical_str(&addr_hex)
                    .map_err(|e| rusqlite::Error::FromSqlConversionFailure(
                        0, rusqlite::types::Type::Text,
                        Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
                    ))?;

                let mut ed_pub = [0u8; 32];
                if ed_pub_blob.len() == 32 {
                    ed_pub.copy_from_slice(&ed_pub_blob);
                } else {
                    return Err(rusqlite::Error::FromSqlConversionFailure(
                        1, rusqlite::types::Type::Blob,
                        Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData,
                            format!("ed_pub 长度不对: {}", ed_pub_blob.len())))
                    ));
                }

                let alt_entries = decode_json_strings(&alt_entries_json);
                let local_candidates = decode_json_strings(&local_cands_json);

                let registered_at = base.to_instant(secs_to_system(registered_at_secs));
                let ttl = Duration::from_secs_f64(ttl_secs.max(0.0));

                let observed = match (observed_addr, observed_at_secs) {
                    (Some(a), Some(t)) => Some((a, base.to_instant(secs_to_system(t)))),
                    _ => None,
                };

                Ok((addr, Entry {
                    ed_pub,
                    rec: NodeRecord {
                        tunnel_entry,
                        alt_entries: alt_entries.into(),
                        ipv8_capable: ipv8_capable != 0,
                        mtu: mtu as u32,
                        registered_at,
                        ttl,
                        observed,
                        local_candidates: local_candidates.into(),
                    },
                }))
            })?;

            for row_result in rows {
                match row_result {
                    Ok((addr, entry)) => {
                        cache.insert(addr, Arc::new(entry));
                    }
                    Err(e) => {
                        eprintln!("[resolver] 跳过损坏的行: {e}");
                    }
                }
            }
            cache // stmt 和 rows 在此块末尾 drop，conn 解除借用
        };

        Ok(Self { cache, conn: Mutex::new(conn), base })
    }

    /// 写入一条记录到 SQLite（upsert）
    fn upsert_db(&self, addr: &IPv8Address, entry: &Entry) -> Result<(), rusqlite::Error> {
        let now_secs = system_to_secs(self.base.to_system(Instant::now()));
        let reg_secs = system_to_secs(self.base.to_system(entry.rec.registered_at));
        let ttl_secs = entry.rec.ttl.as_secs_f64();
        let (obs_addr, obs_at) = match &entry.rec.observed {
            Some((a, t)) => (Some(a.as_str()), Some(system_to_secs(self.base.to_system(*t)))),
            None => (None, None),
        };

        self.conn.lock().execute(
            "INSERT INTO nodes (
                addr_hex, ed_pub, tunnel_entry, alt_entries, ipv8_capable, mtu,
                registered_at, ttl_secs, observed_addr, observed_at, local_cands, updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
            ON CONFLICT(addr_hex) DO UPDATE SET
                ed_pub = excluded.ed_pub,
                tunnel_entry = excluded.tunnel_entry,
                alt_entries = excluded.alt_entries,
                ipv8_capable = excluded.ipv8_capable,
                mtu = excluded.mtu,
                registered_at = excluded.registered_at,
                ttl_secs = excluded.ttl_secs,
                observed_addr = excluded.observed_addr,
                observed_at = excluded.observed_at,
                local_cands = excluded.local_cands,
                updated_at = excluded.updated_at",
            params![
                addr.to_canonical_string(),
                entry.ed_pub.as_slice(),
                entry.rec.tunnel_entry,
                encode_json_strings(&entry.rec.alt_entries),
                entry.rec.ipv8_capable as i64,
                entry.rec.mtu as i64,
                reg_secs,
                ttl_secs,
                obs_addr,
                obs_at,
                encode_json_strings(&entry.rec.local_candidates),
                now_secs,
            ],
        )?;
        Ok(())
    }
}

impl Store for SqliteStore {
    fn get(&self, addr: &IPv8Address) -> Option<Arc<Entry>> {
        self.cache.get(addr).cloned()
    }

    fn insert(&mut self, addr: IPv8Address, e: Entry) {
        // 先写 DB，再写缓存。DB 失败则不更新缓存（保持一致）。
        if let Err(e) = self.upsert_db(&addr, &e) {
            tracing::error!(error = %e, "[resolver] SQLite 写入失败，仅更新内存缓存");
        }
        self.cache.insert(addr, Arc::new(e));
    }

    fn sweep_expired(&mut self, now: Instant) -> usize {
        let before = self.cache.len();
        // 内存清理
        self.cache.retain(|_, e| !e.rec.is_expired(now));
        let removed_mem = before - self.cache.len();

        // SQLite 清理
        let now_secs = system_to_secs(self.base.to_system(now));
        let removed_db = self.conn.lock().execute(
            "DELETE FROM nodes WHERE registered_at + ttl_secs <= ?1",
            params![now_secs],
        ).unwrap_or(0);

        tracing::debug!(
            "[resolver] 过期清理: 内存 {removed_mem} 条, DB {removed_db} 条"
        );

        // 返回内存清理数（与 MemStore 语义一致，调用方主要关心内存回收）
        removed_mem
    }

    fn len(&self) -> usize {
        self.cache.len()
    }
}

// SqliteStore 不实现 Default（需要路径参数），但 Store: Default 的约束
// 在 ResolverService::new() 里用。SqliteStore 走 with_store 构造路径。

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NodeRecord;

    fn temp_db_path() -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let tid = format!("{:?}", std::thread::current().id())
            .replace('(', "").replace(')', "").replace("ThreadId", "t");
        let mut p = std::env::temp_dir();
        p.push(format!("ipv8-resolver-test-{}-{}-{}.db", std::process::id(), tid, n));
        let _ = std::fs::remove_file(&p);
        p
    }

    fn make_addr(n: u32) -> IPv8Address {
        IPv8Address::with_region(n as u64, 1, 0, 0x0100, 0)
    }

    fn make_entry() -> Entry {
        Entry {
            ed_pub: [0xAA; 32],
            rec: NodeRecord {
                tunnel_entry: "10.0.0.1:45700".into(),
                alt_entries: smallvec::smallvec!["10.0.0.2:45700".into()],
                ipv8_capable: true,
                mtu: 1432,
                registered_at: Instant::now(),
                ttl: Duration::from_secs(300),
                observed: Some(("203.0.113.1:50000".into(), Instant::now())),
                local_candidates: smallvec::smallvec!["192.168.1.1:45700".into()],
            },
        }
    }

    #[test]
    fn insert_then_get_roundtrip() {
        let path = temp_db_path();
        let mut store = SqliteStore::open(&path).unwrap();
        let addr = make_addr(1);
        let entry = make_entry();

        store.insert(addr, entry.clone());
        assert_eq!(store.len(), 1);

        let got = store.get(&addr).unwrap();
        assert_eq!(got.ed_pub, entry.ed_pub);
        assert_eq!(got.rec.tunnel_entry, entry.rec.tunnel_entry);
        assert_eq!(got.rec.alt_entries, entry.rec.alt_entries);
        assert_eq!(got.rec.ipv8_capable, entry.rec.ipv8_capable);
        assert_eq!(got.rec.mtu, entry.rec.mtu);
        assert_eq!(got.rec.ttl, entry.rec.ttl);
        assert_eq!(got.rec.local_candidates, entry.rec.local_candidates);
        // observed 的 IP 部分应该一致
        assert_eq!(
            got.rec.observed.as_ref().unwrap().0,
            entry.rec.observed.as_ref().unwrap().0
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn persistence_across_reopen() {
        let path = temp_db_path();
        let addr = make_addr(42);
        let entry = make_entry();

        // 第一次：写入
        {
            let mut store = SqliteStore::open(&path).unwrap();
            store.insert(addr, entry.clone());
            assert_eq!(store.len(), 1);
        }

        // 第二次：重新打开，验证数据还在
        {
            let store = SqliteStore::open(&path).unwrap();
            assert_eq!(store.len(), 1, "重启后应加载到 1 条记录");
            let got = store.get(&addr).expect("应能查到刚写入的地址");
            assert_eq!(got.rec.tunnel_entry, entry.rec.tunnel_entry);
            assert_eq!(got.rec.alt_entries, entry.rec.alt_entries);
            assert_eq!(got.rec.mtu, entry.rec.mtu);
        }

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn expired_entries_not_loaded_on_startup() {
        let path = temp_db_path();
        let addr = make_addr(99);

        // 手工插入一条已过期的记录（直接用 SQL 写旧时间戳）
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(CREATE_TABLE_SQL).unwrap();
            let past = system_to_secs(SystemTime::now() - Duration::from_secs(1000));
            conn.execute(
                "INSERT INTO nodes (addr_hex, ed_pub, tunnel_entry, alt_entries, ipv8_capable,
                    mtu, registered_at, ttl_secs, observed_addr, observed_at, local_cands, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    addr.to_canonical_string(),
                    [0u8; 32].as_slice(),
                    "old:1",
                    "[]",
                    1,
                    0,
                    past,
                    100.0,  // TTL 100 秒，但 registered_at 是 1000 秒前 → 已过期
                    Option::<String>::None,
                    Option::<f64>::None,
                    "[]",
                    past,
                ],
            ).unwrap();
        }

        // 打开时应跳过过期条目
        let store = SqliteStore::open(&path).unwrap();
        assert_eq!(store.len(), 0, "过期条目不应加载到内存");
        assert!(store.get(&addr).is_none());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn sweep_expired_removes_from_both_cache_and_db() {
        let path = temp_db_path();
        let mut store = SqliteStore::open(&path).unwrap();

        // 插入一条短 TTL 的记录
        let addr = make_addr(7);
        let mut entry = make_entry();
        entry.rec.ttl = Duration::from_secs(1);
        entry.rec.registered_at = Instant::now() - Duration::from_secs(10); // 已过期
        store.insert(addr, entry);

        assert_eq!(store.len(), 1);

        // 清理
        let removed = store.sweep_expired(Instant::now());
        assert_eq!(removed, 1);
        assert_eq!(store.len(), 0);
        assert!(store.get(&addr).is_none());

        // 验证 DB 里也删了
        let count: i64 = store.conn.lock().query_row(
            "SELECT COUNT(*) FROM nodes",
            [],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(count, 0);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn upsert_updates_existing_entry() {
        let path = temp_db_path();
        let mut store = SqliteStore::open(&path).unwrap();
        let addr = make_addr(5);

        let mut e1 = make_entry();
        e1.rec.tunnel_entry = "old:1".to_string();
        store.insert(addr, e1);

        let mut e2 = make_entry();
        e2.rec.tunnel_entry = "new:2".to_string();
        e2.rec.mtu = 1500;
        e2.rec.alt_entries = smallvec::smallvec!["alt1:1".into(), "alt2:2".into()];
        store.insert(addr, e2.clone());

        assert_eq!(store.len(), 1, "upsert 不增加条数");
        assert_eq!(store.get(&addr).unwrap().rec.tunnel_entry, "new:2");
        assert_eq!(store.get(&addr).unwrap().rec.mtu, 1500);

        // 重启验证
        drop(store);
        let store2 = SqliteStore::open(&path).unwrap();
        let got = store2.get(&addr).unwrap();
        assert_eq!(got.rec.tunnel_entry, "new:2");
        assert_eq!(got.rec.mtu, 1500);
        assert_eq!(got.rec.alt_entries.to_vec(), vec!["alt1:1", "alt2:2"]);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn json_encoding_decoding_roundtrip() {
        let cases = vec![
            vec![],
            vec!["a".to_string()],
            vec!["a".to_string(), "b".to_string(), "c".to_string()],
            vec!["hello world".to_string(), "with\"quotes\"".to_string()],
            vec!["new\nline".to_string(), "tab\there".to_string()],
            vec!["中文".to_string(), "emoji🚀".to_string()],
        ];
        for case in cases {
            let encoded = encode_json_strings(&case);
            let decoded = decode_json_strings(&encoded);
            assert_eq!(decoded, case, "编码: {encoded}");
        }
    }
}
