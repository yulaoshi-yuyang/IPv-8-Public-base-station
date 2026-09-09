using IPv8Plus.Abstractions;
using IPv8Plus.Abstractions.Events;
using IPv8Plus.Host;
using IPv8Plus.Services.Tests;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

// 轻量测试运行器：零外部包（xunit 待联网接入后迁移）。退出码 = 失败数。

var failures = new List<string>();
Action<string, Action> check = (name, body) =>
{
    try { body(); Console.WriteLine($"  ok  {name}"); }
    catch (Exception ex) { failures.Add($"{name}: {ex.Message}"); Console.WriteLine($"FAIL  {name}: {ex.Message}"); }
};

check("MockTun_roundtrips", MockTunRoundtrips);
check("Events_carry_timestamp_and_payload", EventsCarryTimestampAndPayload);
check("ClientOptions_defaults_match_v9", ClientOptionsDefaultsMatchV9);
check("ClientOptions_binds_from_json", ClientOptionsBindsFromJson);
check("QoS_class_mapping_matches_rust", QoSClassMappingMatchesRust);
check("QoS_strict_priority_and_bounded_drop", QoSStrictPriorityAndBoundedDrop);
check("ANS_shared_vector_matches_rust", AnsSharedVectorMatchesRust);
check("ANS_plan_lifecycle_transitions", AnsPlanLifecycleTransitions);
check("ANS_report_mismatch_false", AnsReportMismatchFalse);
check("ANS_plan_min_count_zero_throws", AnsPlanMinCountZeroThrows);
check("ANS_second_plan_excludes_leased", AnsSecondPlanExcludesLeased);
check("ANS_get_plan_state_unknown_null", AnsGetPlanStateUnknownNull);
check("ANS_resolve_name_expiry_and_unknown_null", AnsResolveNameExpiryAndUnknownNull);
check("ClientOptions_full_bind_keeps_defaults", ClientOptionsFullBindKeepsDefaults);
check("QoS_class_of_level_clamps", QoSClassOfLevelClamps);
check("QoS_capacity_clamped_to_min_one", QoSCapacityClampedToMinOne);
check("QoS_negative_class_throws", QoSNegativeClassThrows);
check("QoS_multi_class_dequeue_order", QoSMultiClassDequeueOrder);
check("ANS_upsert_replaces_same_addr", AnsUpsertReplacesSameAddr);
check("ANS_upsert_empty_addr_throws", AnsUpsertEmptyAddrThrows);
check("ANS_lease_visible_to_discovery", AnsLeaseVisibleToDiscovery);
check("ANS_lease_seconds_clamped", AnsLeaseSecondsClamped);
check("ANS_plan_expiry_and_lease_release", AnsPlanExpiryAndLeaseRelease);
check("NRPT_stop_without_script_is_noop", NrptStopWithoutScriptIsNoop);
check("Events_fallback_fields_roundtrip", EventsFallbackFieldsRoundtrip);

Console.WriteLine(failures.Count == 0 ? "全部通过" : $"{failures.Count} 个失败");
return failures.Count;

static void MockTunRoundtrips()
{
    using var tun = new MockTunAdapter();
    tun.StartAsync().GetAwaiter().GetResult();

    tun.FeedInbound(new byte[] { 1, 2, 3 });
    var inbound = tun.ReadAsync().GetAwaiter().GetResult();
    AssertEqual(new byte[] { 1, 2, 3 }, inbound, "inbound");

    var original = new byte[] { 9, 8, 7 };
    tun.WriteAsync(original).GetAwaiter().GetResult();
    original[0] = 0xFF; // 篡改原数组不得影响已写入包（拷贝语义契约）
    var outbound = tun.ReadOutboundAsync().GetAwaiter().GetResult();
    AssertEqual(new byte[] { 9, 8, 7 }, outbound, "outbound 必须是独立拷贝");
}

static void EventsCarryTimestampAndPayload()
{
    var evt = new PacketReceivedEvent(new byte[] { 42 }) with { OccurredAt = DateTimeOffset.UnixEpoch };
    if (evt.RawPacket[0] != 42) throw new Exception("payload");
    if (evt.OccurredAt != DateTimeOffset.UnixEpoch) throw new Exception("timestamp");

    var fb = new FallbackTriggeredEvent("010203040a0b0c0d1122334402000000", 2, "handshake timeout");
    if (fb is not ModuleEvent) throw new Exception("base type");
    if (fb.OccurredAt <= DateTimeOffset.UnixEpoch) throw new Exception("default timestamp");
}

static void ClientOptionsDefaultsMatchV9()
{
    var o = new ClientOptions();
    if (o.Mtu != 1432) throw new Exception($"Mtu={o.Mtu}");           // v9: 1500-68
    if (o.LocalGrpcRustEnginePort != 0) throw new Exception("port");   // ADR-011 随机端口
    if (o.NamespaceRoot != ".ipv8.net") throw new Exception("root");
}

static void ClientOptionsBindsFromJson()
{
    var file = Path.Combine(Path.GetTempPath(), $"ipv8plus-test-{Guid.NewGuid():N}.json");
    try
    {
        File.WriteAllText(file, """
        { "Client": { "Mtu": 1400, "NamespaceRoot": ".lab.ipv8" } }
        """);
        var config = new ConfigurationBuilder().AddJsonFile(file).Build();
        var o = new ClientOptions();
        config.GetSection(ClientOptions.Section).Bind(o);
        if (o.Mtu != 1400) throw new Exception("Mtu bind");
        if (o.NamespaceRoot != ".lab.ipv8") throw new Exception("root bind");
        if (o.TunAdapterName != "IPv8Plus") throw new Exception("默认值应保持");
    }
    finally
    {
        File.Delete(file);
    }
}

static void QoSClassMappingMatchesRust()
{
    // ipv8-qos::class_of_level = level >> 2，C# IQoSScheduler.ClassOfLevel 必须一致
    (int level, int want)[] cases = { (0, 0), (3, 0), (4, 1), (7, 1), (8, 2), (11, 2), (12, 3), (15, 3) };
    foreach (var (level, want) in cases)
    {
        if (IQoSScheduler.ClassOfLevel(level) != want)
            throw new Exception($"level {level} -> 类 {IQoSScheduler.ClassOfLevel(level)}, 期望 {want}");
    }

    if (IQoSScheduler.NumClasses != 4) throw new Exception("NumClasses 必须为 4");
}

static void QoSStrictPriorityAndBoundedDrop()
{
    var opts = Options.Create(new ClientOptions { QoSClassCapacity = 2 });
    var qos = new QoSManagerService(opts);

    // 类满返回 false + 计数；不影响其他类
    if (!qos.TryEnqueue(0, new byte[] { 1 })) throw new Exception("首个应成功");
    if (!qos.TryEnqueue(0, new byte[] { 2 })) throw new Exception("第二个应成功");
    if (qos.TryEnqueue(0, new byte[] { 3 })) throw new Exception("类 0 满应拒绝");
    if (!qos.TryEnqueue(3, new byte[] { 9 })) throw new Exception("类 3 独立容量");
    if (qos.DroppedCount != 1) throw new Exception($"dropped={qos.DroppedCount}");
    if (qos.Backlog != 3) throw new Exception($"backlog={qos.Backlog}");

    // 严格优先：高优类最后入队但最先出
    var first = qos.DequeueNext();
    if (first is null || first[0] != 9) throw new Exception("最高优先类应最先出队");
    // 类内 FIFO：1 先于 2
    var second = qos.DequeueNext();
    var third = qos.DequeueNext();
    if (second is null || second[0] != 1) throw new Exception("类内 FIFO 1");
    if (third is null || third[0] != 2) throw new Exception("类内 FIFO 2");
    if (qos.DequeueNext() is not null) throw new Exception("空队应返回 null");

    // 非法类号抛异常
    try { qos.TryEnqueue(99, Array.Empty<byte>()); throw new Exception("应抛 ArgumentOutOfRangeException"); }
    catch (ArgumentOutOfRangeException) { }
}

static void AssertEqual(byte[] expect, byte[] actual, string what)
{
    if (!expect.SequenceEqual(actual))
        throw new Exception($"{what}: [{string.Join(",", expect)}] vs [{string.Join(",", actual)}]");
}

// —— 共享测试向量：与 Rust AnsService 逐步骤核对（ADR-022 双侧一致性锁） ——

static void AnsSharedVectorMatchesRust()
{
    var path = FindRepoFile(Path.Combine("shared", "test-vectors", "ans-plans.json"));
    using var doc = System.Text.Json.JsonDocument.Parse(File.ReadAllText(path));
    var mesh = new AgentMeshService();

    foreach (var ag in doc.RootElement.GetProperty("agents").EnumerateArray())
    {
        mesh.Upsert(new CapabilityAgent(
            ag.GetProperty("name").GetString()!,
            ag.GetProperty("addr_text").GetString()!,
            string.Empty,
            StrList(ag, "caps"),
            [],
            ag.GetProperty("qos").GetInt32(),
            ag.GetProperty("not_after").GetUInt64()));
    }

    var createdPlans = new List<ulong>(); // 仅成功计划占 plan_seq
    var stepNo = 0;
    foreach (var step in doc.RootElement.GetProperty("steps").EnumerateArray())
    {
        stepNo++;
        var what = $"step{stepNo}({step.GetProperty("do").GetString()})";
        switch (step.GetProperty("do").GetString())
        {
            case "capability":
            {
                var hits = mesh.Capability(
                    StrList(step, "required"),
                    step.GetProperty("min_qos").GetInt32(),
                    step.GetProperty("exclude_leased").GetBoolean(),
                    step.GetProperty("at").GetUInt64());
                ExpectSeq(hits.Select(h => h.Name).ToList(), StrList(step, "expect_names"), what);
                break;
            }
            case "plan":
            {
                var now = step.GetProperty("at").GetUInt64();
                var task = new TaskDescription(
                    StrList(step, "required"),
                    step.GetProperty("min_count").GetInt32(),
                    step.GetProperty("qos").GetInt32(),
                    step.GetProperty("timeout_ms").GetInt64());
                var expectErr = step.TryGetProperty("expect_error", out var ee) ? ee.GetString() : null;
                if (expectErr == "insufficient")
                {
                    try
                    {
                        mesh.PlanTask(task, now);
                        throw new Exception($"{what}: 预期失败却成功");
                    }
                    catch (InsufficientCandidatesException) { /* 预期路径 */ }
                }
                else
                {
                    var plan = mesh.PlanTask(task, now);
                    ExpectSeq(
                        plan.Assignments.Select(a => a.AddrText).ToList(),
                        StrList(step, "expect_assign_addrs"),
                        what);
                    var secs = plan.Assignments[0].LeaseExpiry - plan.CreatedAt;
                    if (secs != step.GetProperty("expect_lease_secs").GetUInt64())
                    {
                        throw new Exception($"{what}: 租约 {secs}s != 预期");
                    }
                    createdPlans.Add(plan.PlanId);
                }
                break;
            }
            case "report":
            {
                var planId = createdPlans[step.GetProperty("plan_seq").GetInt32() - 1];
                var ok = mesh.ReportDone(
                    planId,
                    step.GetProperty("addr_text").GetString()!,
                    step.GetProperty("at").GetUInt64());
                if (ok != step.GetProperty("expect_released").GetBoolean())
                {
                    throw new Exception($"{what}: released={ok} 与预期不符");
                }
                break;
            }
            case "reap":
            {
                var now = step.GetProperty("at").GetUInt64();
                mesh.ReapExpired(now);
                var hits = mesh.Capability(StrList(step, "probe_required"), 0, true, now);
                ExpectSeq(hits.Select(h => h.Name).ToList(), StrList(step, "expect_available_after"), what);
                break;
            }
            default:
                throw new Exception($"{what}: 未知步骤类型");
        }
    }

    if (mesh.Count != 3)
    {
        throw new Exception($"存活镜像数 {mesh.Count}，应为 3");
    }
}

static List<string> StrList(System.Text.Json.JsonElement el, string key)
{
    return el.GetProperty(key).EnumerateArray().Select(x => x.GetString()!).ToList();
}

static void ExpectSeq(List<string> got, List<string> want, string what)
{
    if (!got.SequenceEqual(want))
    {
        throw new Exception($"{what}: [{string.Join(",", got)}] != [{string.Join(",", want)}]");
    }
}

static string FindRepoFile(string rel)
{
    var dir = new DirectoryInfo(AppContext.BaseDirectory);
    while (dir is not null)
    {
        var p = Path.Combine(dir.FullName, rel);
        if (File.Exists(p))
        {
            return p;
        }
        dir = dir.Parent;
    }
    throw new FileNotFoundException($"共享测试向量未找到: {rel}");
}

// —— AgentMesh 状态机直接契约（不依赖共享向量） ——

static AgentMeshService MeshWith(params (string name, int qos, ulong notAfter, string[] caps)[] agents)
{
    var mesh = new AgentMeshService();
    foreach (var (name, qos, notAfter, caps) in agents)
    {
        mesh.Upsert(new CapabilityAgent(name, name + ".addr", "", caps, [], qos, notAfter));
    }
    return mesh;
}

static void AnsPlanLifecycleTransitions()
{
    var mesh = MeshWith(("a.x", 5, 4_000_000_000, ["ocr"]), ("b.x", 5, 4_000_000_000, ["ocr"]));
    var plan = mesh.PlanTask(new TaskDescription(["ocr"], 2, 0, 60_000), 1_000);
    if (mesh.GetPlanState(plan.PlanId) != PlanState.Planned)
    {
        throw new Exception("刚规划应为 Planned");
    }
    mesh.ReportDone(plan.PlanId, plan.Assignments[0].AddrText, 1_001);
    if (mesh.GetPlanState(plan.PlanId) != PlanState.Leased)
    {
        throw new Exception("部分回报应为 Leased");
    }
    mesh.ReportDone(plan.PlanId, plan.Assignments[1].AddrText, 1_002);
    if (mesh.GetPlanState(plan.PlanId) != PlanState.Completed)
    {
        throw new Exception("全部回报应为 Completed");
    }
}

static void AnsReportMismatchFalse()
{
    var mesh = MeshWith(("a.x", 5, 4_000_000_000, ["ocr"]));
    var plan = mesh.PlanTask(new TaskDescription(["ocr"], 1, 0, 60_000), 1_000);
    if (mesh.ReportDone(plan.PlanId + 999, "a.x.addr", 1_000))
    {
        throw new Exception("错 planId 必须 false");
    }
    if (mesh.ReportDone(plan.PlanId, "ghost.addr", 1_000))
    {
        throw new Exception("未知地址必须 false");
    }
    if (!mesh.ReportDone(plan.PlanId, "a.x.addr", 1_000))
    {
        throw new Exception("正租约回报应 true");
    }
    if (mesh.ReportDone(plan.PlanId, "a.x.addr", 1_001))
    {
        throw new Exception("重复回报（无租约）必须 false");
    }
}

static void AnsPlanMinCountZeroThrows()
{
    var mesh = MeshWith(("a.x", 5, 4_000_000_000, ["ocr"]));
    try
    {
        mesh.PlanTask(new TaskDescription(["ocr"], 0, 0, 5_000), 1_000);
        throw new Exception("min_count=0 必须抛");
    }
    catch (InsufficientCandidatesException e)
    {
        if (e.Wanted != 0)
        {
            throw new Exception("Wanted 应为 0");
        }
    }
}

static void AnsSecondPlanExcludesLeased()
{
    var mesh = MeshWith(("a.x", 9, 4_000_000_000, ["ocr"]), ("b.x", 5, 4_000_000_000, ["ocr"]));
    mesh.PlanTask(new TaskDescription(["ocr"], 1, 0, 60_000), 1_000); // 租走 a
    var p2 = mesh.PlanTask(new TaskDescription(["ocr"], 1, 0, 60_000), 1_000); // 只能拿 b
    if (p2.Assignments[0].AddrText != "b.x.addr")
    {
        throw new Exception($"第二个计划应拿 b，实际 {p2.Assignments[0].AddrText}");
    }
    // 都租走 → 第三个失败无副作用
    try
    {
        mesh.PlanTask(new TaskDescription(["ocr"], 1, 0, 60_000), 1_000);
        throw new Exception("应无候选");
    }
    catch (InsufficientCandidatesException) { }
}

static void AnsGetPlanStateUnknownNull()
{
    var mesh = MeshWith();
    if (mesh.GetPlanState(12345) is not null)
    {
        throw new Exception("未知 planId 应 null");
    }
}

static void AnsResolveNameExpiryAndUnknownNull()
{
    var mesh = MeshWith(("a.x", 5, 1_500, ["ocr"]), ("b.x", 5, 4_000_000_000, ["ocr"]));
    if (mesh.ResolveName("ghost.x") is not null)
    {
        throw new Exception("未登记必须 null（防枚举语义）");
    }
    if (mesh.Capability(["ocr"], 0, true, 2_000).Count != 1)
    {
        throw new Exception("a.x 在 now=2000 应已过期出清");
    }
    if (mesh.ResolveName("a.x") is not null)
    {
        throw new Exception("参考时钟(2000)后 a.x 视为过期");
    }
    if (mesh.ResolveName("b.x") is null)
    {
        throw new Exception("b.x 应可解析");
    }
}

// —— 以下为改进项「C# 侧测试量偏少」扩充的边界/契约测试（零外部包） ——

static void ClientOptionsFullBindKeepsDefaults()
{
    // 只覆盖部分键：未提供的键必须保持默认（配置外部化回归锁）
    var file = Path.Combine(Path.GetTempPath(), $"ipv8plus-test-{Guid.NewGuid():N}.json");
    try
    {
        File.WriteAllText(file, """
        { "Client": { "TunAdapterName": "StrataNet", "QoSClassCapacity": 7 } }
        """);
        var config = new ConfigurationBuilder().AddJsonFile(file).Build();
        var o = new ClientOptions();
        config.GetSection(ClientOptions.Section).Bind(o);
        if (o.TunAdapterName != "StrataNet") throw new Exception("TunAdapterName bind");
        if (o.QoSClassCapacity != 7) throw new Exception("QoSClassCapacity bind");
        if (o.Mtu != 1432) throw new Exception("未覆盖的 Mtu 应保持默认");
        if (o.LocalGrpcRustEnginePort != 0) throw new Exception("未覆盖的端口应保持默认");
        if (o.NamespaceRoot != ".ipv8.net") throw new Exception("未覆盖的根应保持默认");
        if (!o.NrptCleanupScriptPath.EndsWith("cleanup-nrpt.ps1")) throw new Exception("脚本默认路径");
    }
    finally
    {
        File.Delete(file);
    }
}

static void QoSClassOfLevelClamps()
{
    // IQoSScheduler.ClassOfLevel 对越界输入钳位（level>>2 后再 clamp 0..3）
    if (IQoSScheduler.ClassOfLevel(-1) != 0) throw new Exception("负 level 应钳到 0");
    if (IQoSScheduler.ClassOfLevel(0) != 0) throw new Exception("0 -> 0");
    if (IQoSScheduler.ClassOfLevel(15) != 3) throw new Exception("15 -> 3");
    if (IQoSScheduler.ClassOfLevel(99) != 3) throw new Exception("超界应钳到 3");
    if (IQoSScheduler.ClassOfLevel(int.MinValue) != 0) throw new Exception("int.MinValue 钳到 0");
    if (IQoSScheduler.ClassOfLevel(int.MaxValue) != 3) throw new Exception("int.MaxValue 钳到 3");
}

static void QoSCapacityClampedToMinOne()
{
    // 配置负容量被 Math.Max(1, …) 钳到 1：每类仍可容 1 帧，第 2 帧拒
    var qos = new QoSManagerService(Options.Create(new ClientOptions { QoSClassCapacity = 0 }));
    if (!qos.TryEnqueue(2, new byte[] { 1 })) throw new Exception("容量钳到 >=1，首帧应成功");
    if (qos.TryEnqueue(2, new byte[] { 2 })) throw new Exception("容量 1 的第二帧应拒绝");
    if (qos.DroppedCount != 1) throw new Exception("dropped 计数应为 1");
}

static void QoSNegativeClassThrows()
{
    var qos = new QoSManagerService(Options.Create(new ClientOptions()));
    try { qos.TryEnqueue(-1, Array.Empty<byte>()); throw new Exception("负类号应抛"); }
    catch (ArgumentOutOfRangeException) { }
    try { qos.TryEnqueue(4, Array.Empty<byte>()); throw new Exception("类号 4（== NumClasses）应抛"); }
    catch (ArgumentOutOfRangeException) { }
}

static void QoSMultiClassDequeueOrder()
{
    var qos = new QoSManagerService(Options.Create(new ClientOptions { QoSClassCapacity = 8 }));
    qos.TryEnqueue(1, new byte[] { 11 });
    qos.TryEnqueue(1, new byte[] { 12 });
    qos.TryEnqueue(2, new byte[] { 21 });
    qos.TryEnqueue(0, new byte[] { 01 });
    // 出队序 = 类降序，类内 FIFO：2 → 1,1 → 0
    byte[] Expect(byte b)
    {
        var got = qos.DequeueNext();
        if (got is null || got[0] != b) throw new Exception($"期望 {b}，实得 {(got is null ? "null" : got[0].ToString())}");
        return got;
    }
    Expect(21); Expect(11); Expect(12); Expect(01);
    if (qos.DequeueNext() is not null) throw new Exception("排空后应 null");
    if (qos.Backlog != 0) throw new Exception("Backlog 应归零");
}

static void AnsUpsertReplacesSameAddr()
{
    // 同 addr 再 upsert = 整条替换：旧名字出清、新 caps/qos 生效、总数不变
    var mesh = new AgentMeshService();
    mesh.Upsert(new CapabilityAgent("old.name", "addr-1", "", ["ocr"], [], 3, 4_000_000_000));
    mesh.Upsert(new CapabilityAgent("new.name", "addr-1", "", ["asr"], [], 9, 4_000_000_000));
    if (mesh.Count != 1) throw new Exception($"总数 {mesh.Count}，应为 1");
    if (mesh.ResolveName("old.name") is not null) throw new Exception("旧名字应出清");
    var hit = mesh.Capability(["asr"], 0, true, 1_000);
    if (hit.Count != 1 || hit[0].Name != "new.name" || hit[0].QosHint != 9)
    {
        throw new Exception("新条目应生效（名字与 qos 均更新）");
    }
    if (mesh.Capability(["ocr"], 0, true, 1_000).Count != 0) throw new Exception("旧 caps 应失效");
}

static void AnsUpsertEmptyAddrThrows()
{
    var mesh = new AgentMeshService();
    try
    {
        mesh.Upsert(new CapabilityAgent("a", "", "", [], [], 0, 4_000_000_000));
        throw new Exception("空 addr 必须抛");
    }
    catch (ArgumentException) { }
}

static void AnsLeaseVisibleToDiscovery()
{
    // exclude_leased=false（发现型查询）应能看到在租 agent，且视图字段完整
    var mesh = MeshWith(("a.x", 7, 4_000_000_000, ["ocr"]));
    mesh.PlanTask(new TaskDescription(["ocr"], 1, 0, 60_000), 1_000);
    if (mesh.Capability(["ocr"], 0, true, 1_001).Count != 0) throw new Exception("排除租约后应无候选");
    var seen = mesh.Capability(["ocr"], 0, false, 1_001);
    if (seen.Count != 1) throw new Exception("发现型查询应看到在租者");
    if (seen[0].Name != "a.x" || seen[0].QosHint != 7 || seen[0].NotAfter != 4_000_000_000)
    {
        throw new Exception("视图字段应保持");
    }
}

static void AnsLeaseSecondsClamped()
{
    var mesh = MeshWith(("a.x", 5, 4_000_000_000, ["ocr"]));
    // timeout_ms=0 → ceil(0/1000)=0 → clamp 下限 1
    var p1 = mesh.PlanTask(new TaskDescription(["ocr"], 1, 0, 0), 10_000);
    if (p1.Assignments[0].LeaseExpiry - p1.CreatedAt != 1) throw new Exception("租约下限应为 1s");
    // timeout_ms=7_200_000（2h）→ 7200s → clamp 上限 3600
    var p2 = mesh.PlanTask(new TaskDescription(["ocr"], 1, 0, 7_200_000), 20_000);
    if (p2.Assignments[0].LeaseExpiry - p2.CreatedAt != 3_600) throw new Exception("租约上限应为 3600s");
}

static void AnsPlanExpiryAndLeaseRelease()
{
    var mesh = MeshWith(("a.x", 5, 4_000_000_000, ["ocr"]), ("b.x", 5, 4_000_000_000, ["ocr"]));
    var plan = mesh.PlanTask(new TaskDescription(["ocr"], 2, 0, 1_000), 100_000); // 租约 1s → 到期 100_001
    // 只回报一个，另一个留欠 → 到期整体转 Expired
    mesh.ReportDone(plan.PlanId, plan.Assignments[0].AddrText, 100_000);
    if (mesh.GetPlanState(plan.PlanId) != PlanState.Leased) throw new Exception("部分回报应 Leased");
    var converted = mesh.ReapExpired(100_001);
    if (converted != 1) throw new Exception($"应转换 1 个计划，实得 {converted}");
    if (mesh.GetPlanState(plan.PlanId) != PlanState.Expired) throw new Exception("到期应转 Expired");
    // 到期租约释放：两者重新可被规划（Expired 状态不阻止后续计划）
    var again = mesh.PlanTask(new TaskDescription(["ocr"], 2, 0, 1_000), 100_002);
    if (again.Assignments.Count != 2) throw new Exception("释放后应可再次规划 2 分片");
    if (mesh.ReapExpired(100_003) != 1) throw new Exception("新计划同样应到期转换");
    // Completed 的计划不受 reap 影响（不再被计为转换）
    var p3 = mesh.PlanTask(new TaskDescription(["ocr"], 1, 0, 1_000), 100_004);
    mesh.ReportDone(p3.PlanId, p3.Assignments[0].AddrText, 100_005);
    if (mesh.GetPlanState(p3.PlanId) != PlanState.Completed) throw new Exception("应 Completed");
    mesh.ReapExpired(100_999);
    if (mesh.GetPlanState(p3.PlanId) != PlanState.Completed) throw new Exception("Completed 不得被 reap 改成 Expired");
}

static void NrptStopWithoutScriptIsNoop()
{
    // 配置指向不存在的脚本：StopAsync 必须安全跳过（不抛、不启进程）
    var opts = Options.Create(new ClientOptions
    {
        NrptCleanupScriptPath = Path.Combine("does-not-exist", $"no-such-{Guid.NewGuid():N}.ps1"),
    });
    var svc = new NrptCleanupService(NullLogger<NrptCleanupService>.Instance, opts);
    svc.StartAsync(CancellationToken.None).GetAwaiter().GetResult(); // no-op
    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
    svc.StopAsync(cts.Token).GetAwaiter().GetResult(); // 应即刻返回而非挂起/抛出
}

static void EventsFallbackFieldsRoundtrip()
{
    var e = new FallbackTriggeredEvent("0000fb14000000010001000001000000", 3, "plain udp");
    if (e.PeerAddrText != "0000fb14000000010001000001000000") throw new Exception("peer");
    if (e.Level != 3) throw new Exception("level");
    if (e.Reason != "plain udp") throw new Exception("reason");
    var established = new TunnelEstablishedEvent(e.PeerAddrText, 42);
    if (established.InitialEpoch != 42) throw new Exception("epoch");
}
