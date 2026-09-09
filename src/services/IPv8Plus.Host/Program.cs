using System.Security.Principal;
using System.Runtime.Versioning;
using IPv8Plus.Host;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

// v9 §12：客户端仅支持 Windows（wintun/NRPT/低端口均为 Windows 机制）
[assembly: SupportedOSPlatform("windows")]

// v9 §12.3：程序启动权限检查（wintun 设备创建 + DNS 低端口 + NRPT 修改）
if (!IsAdmin())
{
    Console.Error.WriteLine("错误: IPv8+ 客户端需要管理员权限运行");
    Console.Error.WriteLine("原因: wintun 设备创建 + DNS 代理监听低端口 + NRPT 规则修改");
    Console.Error.WriteLine("请右键 → 以管理员身份运行");
    return 1;
}

var builder = Microsoft.Extensions.Hosting.Host.CreateApplicationBuilder(args);
builder.Services.Configure<ClientOptions>(builder.Configuration.GetSection(ClientOptions.Section));
builder.Services.AddSingleton<IPv8Plus.Abstractions.IQoSScheduler, QoSManagerService>();
builder.Services.AddSingleton<AgentMeshService>();
builder.Services.AddSingleton<IPv8Plus.Abstractions.IAnsService>(
    sp => sp.GetRequiredService<AgentMeshService>());
builder.Services.AddSingleton<IPv8Plus.Abstractions.IAgentMesh>(
    sp => sp.GetRequiredService<AgentMeshService>());
builder.Services.AddHostedService<NrptCleanupService>();
// Phase 1 后续：DnsHijack / TunnelClient(gRPC) / WintunAdapter 注册于此
var host = builder.Build();
host.Run();
return 0;

static bool IsAdmin()
{
    using var identity = WindowsIdentity.GetCurrent();
    return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
}
