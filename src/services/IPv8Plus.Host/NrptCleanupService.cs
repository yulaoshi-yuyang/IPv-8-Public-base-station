using System.Diagnostics;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace IPv8Plus.Host;

/// <summary>
/// NRPT 清理（v9 §12.4：同步化进 IHostedService.StopAsync，替代 v7 的 ProcessExit）。
/// 停机时执行 cleanup-nrpt.ps1，确保 .ipv8.net 规则不残留。
/// </summary>
public sealed class NrptCleanupService : IHostedService
{
    private readonly ILogger<NrptCleanupService> _log;
    private readonly string _scriptPath;

    public NrptCleanupService(ILogger<NrptCleanupService> log, IOptions<ClientOptions> options)
    {
        _log = log;
        // 支持相对路径（相对仓库根/发布根）和绝对路径
        var configured = options.Value.NrptCleanupScriptPath;
        _scriptPath = Path.IsPathRooted(configured)
            ? configured
            : Path.Combine(AppContext.BaseDirectory, configured);
    }

    public Task StartAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public Task StopAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(_scriptPath))
        {
            _log.LogWarning("NRPT 清理脚本不存在: {Path}，跳过", _scriptPath);
            return Task.CompletedTask;
        }

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                // v9 修正：空格完整的参数串
                Arguments = $"-NoProfile -ExecutionPolicy Bypass -File \"{_scriptPath}\"",
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var proc = Process.Start(psi);
            proc?.WaitForExit();
            _log.LogInformation("NRPT 规则清理完成 (exit={Exit})", proc?.ExitCode);
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "NRPT 规则清理失败");
        }
        return Task.CompletedTask;
    }
}
