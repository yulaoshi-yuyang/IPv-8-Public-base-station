using IPv8Plus.Abstractions;

namespace IPv8Plus.Host;

/// <summary>
/// ANS 客户端本地镜像 + AgentMesh 编排（ADR-022：云端权威在 Rust ipv8-ans，
/// 本类承载宿主侧读模型缓存与**任务生命周期状态机**）。
///
/// 排序/覆盖/租约语义与 Rust `AnsService` 逐规则对齐（ADR-023 §3）：
/// - 覆盖 = required ⊆ agent.caps（精确标签，Ordinal 比较）
/// - 过滤 = 未过期 ∧ (¬exclude_leased ∨ 无未过期租约) ∧ qos_hint ≥ minQos
/// - 排序 = (qos 降, not_after 降, addrText 升) —— addrText 为 canonical
///   32hex，Ordinal 字符串比较与 Rust 的 to_canonical_string 比较一致
/// - 租约秒 = clamp((timeout_ms + 999) / 1000, 1, 3600)
/// 两侧以共享测试向量锁行为（tests/services/.../TestRunner 双向核对）。
/// </summary>
public sealed class AgentMeshService : IAnsService, IAgentMesh
{
    private sealed class Agent(
        string name,
        string addrText,
        int qos,
        ulong notAfter,
        List<string> caps)
    {
        public string Name { get; } = name;
        public string AddrText { get; } = addrText;
        public int Qos { get; } = qos;
        public ulong NotAfter { get; } = notAfter;
        public List<string> Caps { get; } = caps;
        public ulong? LeaseExpiry { get; set; }
        public ulong? LeasePlan { get; set; }
        public bool LeasedAt(ulong now) => LeaseExpiry > now;
    }

    private sealed class PlanRecord(TaskPlan plan, HashSet<string> pendingAcks, ulong expiry)
    {
        public TaskPlan Plan { get; } = plan;
        public HashSet<string> PendingAcks { get; } = pendingAcks;
        public int TotalShards { get; } = plan.Assignments.Count;
        public ulong Expiry { get; } = expiry;
        public PlanState State { get; set; } = PlanState.Planned;
    }

    private readonly object _gate = new();
    private readonly List<Agent> _agents = [];
    private readonly Dictionary<string, Agent> _byName = new(StringComparer.Ordinal);
    private readonly Dictionary<string, Agent> _byAddr = new(StringComparer.Ordinal);
    private readonly Dictionary<ulong, PlanRecord> _plans = [];
    private ulong _nextPlanId = 1;
    // ResolveName 契约无 now 参数：新鲜度以最近一次带 now 的调用为参考时钟
    private ulong _lastSeenNow;

    /// <summary>注册/更新本地镜像条目（真实部署由 ANS gRPC 同步；测试直接喂）。</summary>
    public void Upsert(CapabilityAgent a)
    {
        ArgumentException.ThrowIfNullOrEmpty(a.AddrText);
        lock (_gate)
        {
            if (_byAddr.TryGetValue(a.AddrText, out var existing))
            {
                _byName.Remove(existing.Name);
                _agents.Remove(existing);
            }
            var agent = new Agent(a.Name, a.AddrText, a.QosHint, a.NotAfter, [.. a.Capabilities]);
            _agents.Add(agent);
            _byName[agent.Name] = agent;
            _byAddr[agent.AddrText] = agent;
        }
    }

    /// <inheritdoc />
    public CapabilityAgent? ResolveName(string name)
    {
        lock (_gate)
        {
            // 镜像 Rust 语义：未登记与已过期统一 null（防枚举）。
            // 无 now 参数时用参考时钟；新登记的 agent 时钟未到即视为有效。
            if (!_byName.TryGetValue(name, out var a) || a.NotAfter <= _lastSeenNow)
            {
                return null;
            }
            return ToView(a);
        }
    }

    /// <inheritdoc />
    public IReadOnlyList<CapabilityAgent> Capability(
        IReadOnlyList<string> requiredCaps, int minQos, bool excludeLeased, ulong now)
    {
        lock (_gate)
        {
            _lastSeenNow = now;
            return Match(requiredCaps, minQos, excludeLeased, now).Select(ToView).ToList();
        }
    }

    /// <inheritdoc />
    public TaskPlan PlanTask(TaskDescription task, ulong now)
    {
        if (task.MinCount <= 0)
        {
            throw new InsufficientCandidatesException(task.MinCount, 0);
        }
        lock (_gate)
        {
            _lastSeenNow = now;
            var cands = Match(task.RequiredCaps, task.QosLevel, excludeLeased: true, now);
            if (cands.Count < task.MinCount)
            {
                throw new InsufficientCandidatesException(task.MinCount, cands.Count);
            }
            var leaseSecs = Math.Clamp((task.TimeoutMs + 999) / 1000, 1, 3600);
            var expiry = now + (ulong)leaseSecs;
            var planId = _nextPlanId++;
            var assignments = new List<TaskAssignment>(task.MinCount);
            var pending = new HashSet<string>(StringComparer.Ordinal);
            for (var i = 0; i < task.MinCount; i++)
            {
                var a = cands[i];
                a.LeasePlan = planId;
                a.LeaseExpiry = expiry;
                assignments.Add(new TaskAssignment(a.AddrText, i, expiry));
                pending.Add(a.AddrText);
            }
            var plan = new TaskPlan(planId, assignments, now);
            _plans[planId] = new PlanRecord(plan, pending, expiry);
            return plan;
        }
    }

    /// <inheritdoc />
    public bool ReportDone(ulong planId, string addrText, ulong now)
    {
        lock (_gate)
        {
            _lastSeenNow = now;
            if (!_byAddr.TryGetValue(addrText, out var agent)
                || agent.LeasePlan != planId || agent.LeaseExpiry is null)
            {
                return false; // 未知地址 / 无租约 / plan 不符
            }
            agent.LeasePlan = null;
            agent.LeaseExpiry = null;
            if (_plans.TryGetValue(planId, out var rec)
                && rec.State is PlanState.Planned or PlanState.Leased)
            {
                rec.PendingAcks.Remove(addrText);
                rec.State = rec.PendingAcks.Count == 0 ? PlanState.Completed : PlanState.Leased;
            }
            return true;
        }
    }

    /// <inheritdoc />
    public PlanState? GetPlanState(ulong planId)
    {
        lock (_gate)
        {
            return _plans.TryGetValue(planId, out var rec) ? rec.State : null;
        }
    }

    /// <inheritdoc />
    public int ReapExpired(ulong now)
    {
        lock (_gate)
        {
            _lastSeenNow = now;
            // 1) 释放到期租约（与 Rust 的 lease 回收一致）
            foreach (var a in _agents)
            {
                if (a.LeaseExpiry is { } exp && exp <= now)
                {
                    a.LeasePlan = null;
                    a.LeaseExpiry = null;
                }
            }
            // 2) Planned/Leased 且整体到期 → Expired
            var converted = 0;
            foreach (var rec in _plans.Values)
            {
                if (rec.State is PlanState.Planned or PlanState.Leased && rec.Expiry <= now)
                {
                    rec.State = PlanState.Expired;
                    converted++;
                }
            }
            // 3) 过期卡片摘除
            foreach (var a in _agents.Where(x => x.NotAfter <= now).ToList())
            {
                _agents.Remove(a);
                _byName.Remove(a.Name);
                _byAddr.Remove(a.AddrText);
            }
            return converted;
        }
    }

    /// <summary>存活镜像条目数（观测/测试）。</summary>
    public int Count
    {
        get
        {
            lock (_gate)
            {
                return _agents.Count;
            }
        }
    }

    private List<Agent> Match(IReadOnlyList<string> required, int minQos, bool excludeLeased, ulong now)
    {
        return _agents
            .Where(a => a.NotAfter > now)
            .Where(a => !excludeLeased || !a.LeasedAt(now))
            .Where(a => a.Qos >= minQos && required.All(r => a.Caps.Contains(r)))
            .OrderByDescending(a => a.Qos)
            .ThenByDescending(a => a.NotAfter)
            .ThenBy(a => a.AddrText, StringComparer.Ordinal)
            .ToList();
    }

    private static CapabilityAgent ToView(Agent a) =>
        new(a.Name, a.AddrText, string.Empty, [.. a.Caps], [], a.Qos, a.NotAfter);
}
