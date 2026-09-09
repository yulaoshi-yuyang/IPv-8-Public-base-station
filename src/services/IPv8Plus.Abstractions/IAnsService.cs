namespace IPv8Plus.Abstractions;

/// <summary>能力寻址/直接寻址的返回视图（与 ans.proto AgentView 字段一一对应）。</summary>
public sealed record CapabilityAgent(
    string Name,
    string AddrText,
    string TunnelEntry,
    IReadOnlyList<string> Capabilities,
    IReadOnlyList<string> Endpoints,
    int QosHint,
    ulong NotAfter);

/// <summary>任务描述（与 ans.proto TaskDescriptionMsg 对应；精确标签匹配，无语义推理）。</summary>
public sealed record TaskDescription(
    IReadOnlyList<string> RequiredCaps,
    int MinCount,
    int QosLevel,
    long TimeoutMs);

/// <summary>一条分片指派。</summary>
public sealed record TaskAssignment(string AddrText, int ShardId, ulong LeaseExpiry);

/// <summary>任务计划输出。</summary>
public sealed record TaskPlan(ulong PlanId, IReadOnlyList<TaskAssignment> Assignments, ulong CreatedAt);

/// <summary>候选不足异常（对应 Rust Insufficient，计划不产生、无副作用）。</summary>
public sealed class InsufficientCandidatesException(int wanted, int got)
    : Exception($"候选不足：需 {wanted}，得 {got}")
{
    public int Wanted { get; } = wanted;
    public int Got { get; } = got;
}

/// <summary>
/// ANS 三维寻址契约（v9 Phase 4 · 铁律 1：接口先行）。
/// 语义权威在 Rust ipv8-ans（ADR-022）；本接口的宿主实现承载客户端编排，
/// 两侧以同一测试向量锁行为一致（契约测试 Ans_matches_rust_e2e_vector）。
/// </summary>
public interface IAnsService
{
    /// <summary>直接寻址：name → 视图；未登记或已过期统一 null（防枚举）。</summary>
    CapabilityAgent? ResolveName(string name);

    /// <summary>
    /// 能力寻址：精确标签覆盖 + qos 下限过滤，排序 (qos 降, 剩余 TTL 降, addr 升)；
    /// excludeLeased=true 时排除持有未过期租约者（发现型查询可传 false）。
    /// </summary>
    IReadOnlyList<CapabilityAgent> Capability(
        IReadOnlyList<string> requiredCaps, int minQos, bool excludeLeased, ulong now);
}

/// <summary>计划生命周期（ADR-023 §3 租约式协作的最小状态集）。</summary>
public enum PlanState
{
    /// <summary>已提交待匹配</summary>
    Pending,

    /// <summary>匹配中（预留的显式态，当前实现在 PlanTask 内原子完成）</summary>
    Matching,

    /// <summary>已产出计划（分片已定，租约已起）</summary>
    Planned,

    /// <summary>分片已投递/执行中（宿主回报开始）</summary>
    Leased,

    /// <summary>全部回报完成</summary>
    Completed,

    /// <summary>租约到期未完成（回收候选重规划由上层决定）</summary>
    Expired,
}

/// <summary>
/// AgentMesh 编排契约（v9 AgentMeshService：注册/发现/调度）。
/// 云端权威注册表在 Rust ANS；本接口管理**本地任务生命周期**与租约回报，
/// 状态机 Pending→Planned→Leased→Completed/Expired。
/// </summary>
public interface IAgentMesh
{
    /// <summary>任务寻址：能力匹配取候选 → 分片 + 起租。候选不足抛 InsufficientCandidatesException。</summary>
    TaskPlan PlanTask(TaskDescription task, ulong now);

    /// <summary>回报完成：释放租约；plan 不匹配或无租约返回 false。</summary>
    bool ReportDone(ulong planId, string addrText, ulong now);

    /// <summary>查询计划状态（未知 planId 返回 null）。</summary>
    PlanState? GetPlanState(ulong planId);

    /// <summary>回收过期租约：全部租约到期且未完成的计划转 Expired，返回转换数。</summary>
    int ReapExpired(ulong now);
}
