//! 共享测试向量执行器（Phase 4 M4 / ADR-022 双侧一致性锁）。
//!
//! 读 `shared/test-vectors/ans-plans.json`，在**真实 AnsService**（含证书/
//! CardSig/PoP 全验签）上重放剧本：能力排序、计划分片、租约算术、回报与
//! 回收裁决。C# AgentMeshService 用同一 JSON 跑同一断言（TestRunner），
//! 任何一侧语义漂移 → 对应测试红。

use ed25519_dalek::SigningKey;
use serde_json::Value;

use crate::tests_util::*;
use crate::{AnsService, TaskDescription};

fn vector() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../shared/test-vectors/ans-plans.json");
    let raw = std::fs::read_to_string(path).expect("共享测试向量缺失");
    serde_json::from_str(&raw).expect("向量 JSON 非法")
}

fn str_list(v: &Value, key: &str) -> Vec<String> {
    v[key].as_array().unwrap().iter().map(|s| s.as_str().unwrap().to_string()).collect()
}

#[test]
fn shared_vector_rust_semantics() {
    let doc = vector();
    let mut s = AnsService::new(anchor(), ROOT);

    // 登记：seed/host/caps/qos/not_after 全来自向量
    for ag in doc["agents"].as_array().unwrap() {
        let host = ag["host"].as_u64().unwrap() as u32;
        let seed = ag["seed"].as_u64().unwrap() as u8;
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let a = Agent {
            sk,
            a: addr(host),
            name: ag["name"].as_str().unwrap().to_string(),
            caps: str_list(ag, "caps"),
            qos: ag["qos"].as_u64().unwrap() as u8,
        };
        let not_after = ag["not_after"].as_u64().unwrap();
        let k = kit(&ca(), &a, not_after);
        let t = text(host);
        s.register(&spec_of(&k, &t), NOW).expect("向量 agent 登记必须成功");
    }

    // 计划按创建顺序编号：plan_seq 从 1 起
    let mut created: Vec<u64> = Vec::new();
    for step in doc["steps"].as_array().unwrap() {
        match step["do"].as_str().unwrap() {
            "capability" => {
                let now = step["at"].as_u64().unwrap();
                let hits = s.search_capability(
                    &str_list(step, "required"),
                    step["min_qos"].as_u64().unwrap() as u8,
                    step["exclude_leased"].as_bool().unwrap(),
                    now,
                );
                let got: Vec<String> = hits.iter().map(|r| r.name.clone()).collect();
                let want: Vec<String> = str_list(step, "expect_names");
                assert_eq!(got, want, "capability @{} 失配", now);
            }
            "plan" => {
                let now = step["at"].as_u64().unwrap();
                let task = TaskDescription {
                    required_caps: str_list(step, "required"),
                    min_count: step["min_count"].as_u64().unwrap() as usize,
                    qos_level: step["qos"].as_u64().unwrap() as u8,
                    timeout_ms: step["timeout_ms"].as_u64().unwrap(),
                };
                match s.plan_task(&task, now) {
                    Ok(p) => {
                        assert_eq!(
                            step["expect_error"].as_str(),
                            None,
                            "向量预期失败却成功"
                        );
                        let addrs: Vec<String> =
                            p.assignments.iter().map(|a| a.addr.to_canonical_string()).collect();
                        assert_eq!(addrs, str_list(step, "expect_assign_addrs"));
                        let secs = p.assignments[0].lease_expiry - p.created_at;
                        assert_eq!(secs, step["expect_lease_secs"].as_u64().unwrap(), "租约算术");
                        created.push(p.plan_id);
                    }
                    Err(e) => {
                        assert_eq!(
                            step["expect_error"].as_str(),
                            Some("insufficient"),
                            "非预期失败: {e}"
                        );
                        assert!(
                            matches!(e, crate::AnsError::Insufficient { .. }),
                            "错误类型漂移: {e}"
                        );
                    }
                }
            }
            "report" => {
                let now = step["at"].as_u64().unwrap();
                let pid = created[step["plan_seq"].as_u64().unwrap() as usize - 1];
                let a = ipv8_codec::IPv8Address::from_canonical_str(
                    step["addr_text"].as_str().unwrap(),
                )
                .unwrap();
                let ok = s.report_done(pid, a, now).is_ok();
                assert_eq!(ok, step["expect_released"].as_bool().unwrap());
            }
            "reap" => {
                let now = step["at"].as_u64().unwrap();
                s.reap(now);
                let hits = s.search_capability(
                    &str_list(step, "probe_required"),
                    0,
                    true,
                    now,
                );
                let got: Vec<String> = hits.iter().map(|r| r.name.clone()).collect();
                assert_eq!(got, str_list(step, "expect_available_after"), "reap 后可用集");
            }
            other => panic!("未知步骤 {other}"),
        }
    }
    // 全部登记存活（not_after=4e9）
    assert_eq!(s.len(), 3);
}
