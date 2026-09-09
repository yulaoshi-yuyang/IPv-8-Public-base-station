//! ANS gRPC 网络层（tonic；生成码来自 shared/ipv8-proto/ans.proto）。
//! 分层与 zoneserver/resolver 一致：本文件只做 协议 ↔ 领域 映射 + serve +
//! e2e 测试，全部决策逻辑在 [`crate`]（零 IO，可脱离网络自测）。

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tonic::{Request, Response, Status};

pub mod pb {
    tonic::include_proto!("ipv8plus.ans.v1");
}

use pb::ans_server::{Ans as AnsSvc, AnsServer};
use pb::{
    AgentCardSummaryMsg, AgentView, CapabilityRequest, CapabilityResponse, Plan as PbPlan,
    PlanTaskRequest, RegisterAgentRequest, RegisterAgentResponse, ReportDoneRequest,
    ReportDoneResponse, ResolveNameRequest,
};

use crate::{
    AnsError, AnsService, Plan, RegisterSpec, ResolvedAgent, TaskDescription, CARD_VERSION,
};

/// 墙钟 epoch 秒（卡片有效期/租约判定）
fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Clone)]
pub struct AnsGrpc {
    inner: Arc<Mutex<AnsService>>,
}

impl AnsGrpc {
    pub fn new(s: AnsService) -> Self {
        Self { inner: Arc::new(Mutex::new(s)) }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, AnsService> {
        self.inner.lock().expect("ans mutex poisoned")
    }
}

fn ans_err(e: AnsError) -> Status {
    match e {
        AnsError::BadName
        | AnsError::BadAddress
        | AnsError::BadTags
        | AnsError::BadCard
        | AnsError::BadProof => Status::invalid_argument(e.to_string()),
        AnsError::BadCert => Status::unauthenticated(e.to_string()),
        AnsError::KeyConflict | AnsError::NameConflict => Status::already_exists(e.to_string()),
        // NotFound 不区分"未登记/已过期"（ADR-007 防枚举），语义映射 gRPC NOT_FOUND
        AnsError::NotFound => Status::not_found(e.to_string()),
        AnsError::Insufficient { .. } => Status::failed_precondition(e.to_string()),
    }
}

fn summary_msg(r: &ResolvedAgent) -> AgentCardSummaryMsg {
    AgentCardSummaryMsg {
        version: r.summary.version as u32,
        card_hash: r.summary.card_hash.to_vec(),
        not_after: r.summary.not_after,
        agent_pubkey: r.summary.agent_pubkey.to_vec(),
        card_sig: r.summary.card_sig.to_vec(),
    }
}

fn view(r: &ResolvedAgent) -> AgentView {
    AgentView {
        name: r.name.clone(),
        addr_text: r.addr.to_canonical_string(),
        tunnel_entry: r.tunnel_entry.clone(),
        capabilities: r.capabilities.clone(),
        endpoints: r.endpoints.clone(),
        qos_hint: r.qos_hint as u32,
        not_after: r.not_after,
        summary: Some(summary_msg(r)),
    }
}

#[tonic::async_trait]
impl AnsSvc for AnsGrpc {
    async fn register_agent(
        &self,
        req: Request<RegisterAgentRequest>,
    ) -> Result<Response<RegisterAgentResponse>, Status> {
        let r = req.into_inner();
        let proto_card = r.card.ok_or_else(|| Status::invalid_argument("card 缺失"))?;
        let card_sig_arr: [u8; 64] = r
            .card_sig
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("card_sig 应为 64B"))?;
        let card = crate::AgentCard {
            version: if proto_card.version == CARD_VERSION as u32 { CARD_VERSION } else { proto_card.version as u8 },
            name: proto_card.name,
            addr: ipv8_codec::IPv8Address::from_canonical_str(&proto_card.addr_text)
                .map_err(|_| Status::invalid_argument("card.addr_text 非法"))?,
            capabilities: proto_card.capabilities,
            endpoints: proto_card.endpoints,
            qos_hint: proto_card.qos_hint.min(15) as u8,
            not_after: proto_card.not_after,
            tunnel_entry: proto_card.tunnel_entry,
        };
        let hash = {
            let mut g = self.lock();
            g.register(
                &RegisterSpec {
                    addr_text: &r.addr_text,
                    cert_wire: &r.cert_wire,
                    card: &card,
                    card_sig: &card_sig_arr,
                    pop: &r.pop,
                },
                now_epoch_secs(),
            )
            .map_err(ans_err)?
        };
        Ok(Response::new(RegisterAgentResponse { card_hash: hash.to_vec() }))
    }

    async fn resolve_name(
        &self,
        req: Request<ResolveNameRequest>,
    ) -> Result<Response<AgentView>, Status> {
        let r = self
            .lock()
            .resolve_name(&req.into_inner().name, now_epoch_secs())
            .map_err(ans_err)?;
        Ok(Response::new(view(&r)))
    }

    async fn capability(
        &self,
        req: Request<CapabilityRequest>,
    ) -> Result<Response<CapabilityResponse>, Status> {
        let q = req.into_inner();
        let hits = self.lock().search_capability(
            &q.required_caps,
            q.min_qos.min(15) as u8,
            q.exclude_leased,
            now_epoch_secs(),
        );
        Ok(Response::new(CapabilityResponse { agents: hits.iter().map(view).collect() }))
    }

    async fn plan_task(
        &self,
        req: Request<PlanTaskRequest>,
    ) -> Result<Response<PbPlan>, Status> {
        let t = req
            .into_inner()
            .task
            .ok_or_else(|| Status::invalid_argument("task 缺失"))?;
        let task = TaskDescription {
            required_caps: t.required_caps,
            min_count: t.min_count as usize,
            qos_level: t.qos_level.min(15) as u8,
            timeout_ms: t.timeout_ms,
        };
        let plan = self.lock().plan_task(&task, now_epoch_secs()).map_err(ans_err)?;
        Ok(Response::new(to_pb_plan(&plan)))
    }

    async fn report_done(
        &self,
        req: Request<ReportDoneRequest>,
    ) -> Result<Response<ReportDoneResponse>, Status> {
        let r = req.into_inner();
        let addr = ipv8_codec::IPv8Address::from_canonical_str(&r.addr_text)
            .map_err(|_| Status::invalid_argument("addr_text 非法"))?;
        let released = self
            .lock()
            .report_done(r.plan_id, addr, now_epoch_secs())
            .is_ok();
        Ok(Response::new(ReportDoneResponse { released }))
    }
}

fn to_pb_plan(p: &Plan) -> PbPlan {
    PbPlan {
        plan_id: p.plan_id,
        assignments: p
            .assignments
            .iter()
            .map(|a| pb::Assignment {
                addr_text: a.addr.to_canonical_string(),
                shard_id: a.shard_id as u32,
                lease_expiry: a.lease_expiry,
            })
            .collect(),
        created_at: p.created_at,
    }
}

/// 启动服务（ADR-011：端口 0 = 随机）。服务任务内嵌 reaper：
/// 每分钟释放过期租约 + 摘除过期卡片（自托管内存有界）。
pub async fn serve(
    s: AnsService,
    addr: SocketAddr,
) -> Result<(SocketAddr, tokio::task::JoinHandle<()>), Box<dyn std::error::Error + Send + Sync>>
{
    let svc = AnsGrpc::new(s);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    let inner = svc.inner.clone();
    let handle = tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        let server = tonic::transport::Server::builder()
            .add_service(AnsServer::new(svc))
            .serve_with_incoming_shutdown(
                tokio_stream::wrappers::TcpListenerStream::new(listener),
                async {
                    loop {
                        tick.tick().await;
                        let _ = inner.lock().expect("ans mutex poisoned").reap(now_epoch_secs());
                    }
                },
            );
        server.await.expect("ans gRPC exited");
    });
    Ok((local, handle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests_util::{self as tu, Agent as TestAgent};
    use pb::ans_client::AnsClient;
    use pb::{AgentCard as PbAgentCard, TaskDescriptionMsg};

    async fn spawn() -> AnsClient<tonic::transport::Channel> {
        let (local, _h) = serve(
            AnsService::new(tu::anchor(), ".ipv8.net"),
            "127.0.0.1:0".parse().unwrap(),
        )
        .await
        .unwrap();
        AnsClient::connect(format!("http://{local}")).await.unwrap()
    }

    fn reg_msg(ag: &TestAgent) -> RegisterAgentRequest {
        let card = ag.card(tu::far_future());
        let kit = tu::kit(&tu::ca(), ag, tu::far_future());
        RegisterAgentRequest {
            addr_text: kit.card.addr.to_canonical_string(),
            cert_wire: kit.cert,
            card: Some(PbAgentCard {
                version: 1,
                name: card.name,
                addr_text: card.addr.to_canonical_string(),
                capabilities: card.capabilities,
                endpoints: card.endpoints,
                qos_hint: card.qos_hint as u32,
                not_after: tu::far_future(),
                tunnel_entry: card.tunnel_entry,
            }),
            card_sig: kit.card_sig.to_vec(),
            pop: kit.pop,
        }
    }

    /// v9 验收主链路：3 异构 agent 注册 → 名字/能力寻址 → 任务规划 → 回报。
    #[tokio::test]
    async fn grpc_multihop_agent_collaboration_flow() {
        let mut c = spawn().await;
        let a1 = TestAgent::new(0xA1, 1, "ocrworker", &["ocr", "layout"], 5);
        let a2 = TestAgent::new(0xB2, 2, "translator", &["ocr", "translate"], 9);
        let a3 = TestAgent::new(0xC3, 3, "summarist", &["summarize"], 7);
        for ag in [&a1, &a2, &a3] {
            let rr = c.register_agent(reg_msg(ag)).await.unwrap().into_inner();
            assert_eq!(rr.card_hash.len(), 16, "回显 16B 卡片哈希");
        }

        // 直接寻址
        let v = c
            .resolve_name(ResolveNameRequest { name: a2.name() })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(v.addr_text, crate::tests_util::addr_text(2));
        assert_eq!(v.summary.unwrap().agent_pubkey.len(), 32);

        // 能力寻址：ocr 命中两个
        let caps = c
            .capability(CapabilityRequest {
                required_caps: vec!["ocr".into()],
                min_qos: 0,
                exclude_leased: true,
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(caps.agents.len(), 2);
        assert_eq!(caps.agents[0].name, a2.name(), "qos 高者先");

        // 任务规划：{ocr}×2 → 两个都租
        let plan = c
            .plan_task(PlanTaskRequest {
                task: Some(TaskDescriptionMsg {
                    required_caps: vec!["ocr".into()],
                    min_count: 2,
                    qos_level: 0,
                    timeout_ms: 60_000,
                }),
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(plan.assignments.len(), 2);
        // 再查能力：全部被租，排除租约后为空
        let caps2 = c
            .capability(CapabilityRequest {
                required_caps: vec!["ocr".into()],
                min_qos: 0,
                exclude_leased: true,
            })
            .await
            .unwrap()
            .into_inner();
        assert!(caps2.agents.is_empty());
        // 回报一个 → 重获 1
        let done = c
            .report_done(ReportDoneRequest {
                plan_id: plan.plan_id,
                addr_text: plan.assignments[0].addr_text.clone(),
            })
            .await
            .unwrap()
            .into_inner();
        assert!(done.released);
        let caps3 = c
            .capability(CapabilityRequest {
                required_caps: vec!["ocr".into()],
                min_qos: 0,
                exclude_leased: true,
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(caps3.agents.len(), 1);
    }

    /// 候选不足 → FAILED_PRECONDITION；未知名字 → NOT_FOUND（含防枚举语义）。
    #[tokio::test]
    async fn grpc_error_mapping() {
        let mut c = spawn().await;
        let e = c
            .resolve_name(ResolveNameRequest { name: "ghost.ipv8.net".into() })
            .await
            .unwrap_err();
        assert_eq!(e.code(), tonic::Code::NotFound);

        let ag = TestAgent::new(0xA1, 1, "solo", &["ocr"], 5);
        c.register_agent(reg_msg(&ag)).await.unwrap();
        let e = c
            .plan_task(PlanTaskRequest {
                task: Some(TaskDescriptionMsg {
                    required_caps: vec!["ocr".into(), "missing-cap".into()],
                    min_count: 1,
                    qos_level: 0,
                    timeout_ms: 5_000,
                }),
            })
            .await
            .unwrap_err();
        assert_eq!(e.code(), tonic::Code::FailedPrecondition);

        // 坏 PoP → INVALID_ARGUMENT
        let mut bad = reg_msg(&TestAgent::new(0xB2, 2, "b", &["x"], 1));
        bad.pop = vec![0u8; 64];
        let e = c.register_agent(bad).await.unwrap_err();
        assert_eq!(e.code(), tonic::Code::InvalidArgument);
    }

    /// 同名冲突 → ALREADY_EXISTS。
    #[tokio::test]
    async fn grpc_name_conflict_is_already_exists() {
        let mut c = spawn().await;
        c.register_agent(reg_msg(&TestAgent::new(0xA1, 1, "dup", &["a"], 5)))
            .await
            .unwrap();
        let e = c
            .register_agent(reg_msg(&TestAgent::new(0xB2, 2, "dup", &["a"], 5)))
            .await
            .unwrap_err();
        assert_eq!(e.code(), tonic::Code::AlreadyExists);
    }
}
