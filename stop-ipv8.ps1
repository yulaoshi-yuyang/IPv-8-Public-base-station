# ============================================================
# IPv8+ 一键终止：门户 + Cloudflare 隧道 + 清理防火墙（可选）
#
# 用法：
#   .\stop-ipv8.ps1               终止服务
#   .\stop-ipv8.ps1 -CleanFirewall 同时移除防火墙规则
#   .\stop-ipv8.ps1 -Status       只查看状态，不终止
# ============================================================

param(
    [switch]$CleanFirewall,
    [switch]$Status,
    [int]$PortalPort = 9001
)

$projectRoot = $PSScriptRoot
$logDir = Join-Path $projectRoot "deploy\portal\logs"
$pidFile = Join-Path $logDir "ipv8-all.pid"

function Write-Step { param([string]$Text, [string]$Color = "Cyan") Write-Host $Text -ForegroundColor $Color }
function Write-OK { param([string]$Text) Write-Host "  [OK] $Text" -ForegroundColor Green }
function Write-Warn { param([string]$Text) Write-Host "  [!] $Text" -ForegroundColor Yellow }

# ── 查看状态模式 ──────────────────────────────────────────────
if ($Status) {
    Write-Step "`n=== IPv8+ 服务状态 ===" "Cyan"

    # 门户进程
    $portalRunning = Get-NetTCPConnection -LocalPort $PortalPort -State Listen -ErrorAction SilentlyContinue
    if ($portalRunning) {
        Write-OK "门户: 运行中 (端口 $PortalPort, PID $($portalRunning.OwningProcess))"
    } else {
        Write-Warn "门户: 未运行"
    }

    # 隧道进程
    $cfProc = Get-Process cloudflared -ErrorAction SilentlyContinue
    if ($cfProc) {
        Write-OK "隧道: 运行中 (PID $($cfProc.Id))"
    } else {
        Write-Warn "隧道: 未运行"
    }

    # 防火墙规则
    $rules = @("IPv8-Portal-Inbound-$PortalPort", "IPv8-DNS-Inbound-5353", "IPv8-Cloudflared-Outbound")
    foreach ($r in $rules) {
        $rule = Get-NetFirewallRule -DisplayName $r -ErrorAction SilentlyContinue
        if ($rule) {
            Write-OK "防火墙: $rule 已启用"
        } else {
            Write-Warn "防火墙: $r 不存在"
        }
    }
    return
}

Write-Step "`n=== IPv8+ 一键终止 ===" "Cyan"
Write-Step "[1/3] 终止隧道进程..." "Yellow"

# 终止 cloudflared
$cfKilled = 0
Get-Process cloudflared -ErrorAction SilentlyContinue | ForEach-Object {
    Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
    $cfKilled++
}
if ($cfKilled -gt 0) {
    Write-OK "已终止 $cfKilled 个 cloudflared 进程"
} else {
    Write-Warn "无 cloudflared 进程在运行"
}

# ── 终止门户 ──────────────────────────────────────────────────
Write-Step "[2/3] 终止门户进程..." "Yellow"

$portalKilled = 0
Get-NetTCPConnection -LocalPort $PortalPort -State Listen -ErrorAction SilentlyContinue | ForEach-Object {
    $procId = $_.OwningProcess
    if ($procId -gt 4) {
        $p = Get-Process -Id $procId -ErrorAction SilentlyContinue
        if ($p -and $p.ProcessName -in @("powershell","pwsh","python","node")) {
            Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
            $portalKilled++
        }
    }
}
if ($portalKilled -gt 0) {
    Write-OK "已终止 $portalKilled 个门户进程"
} else {
    Write-Warn "无门户进程在运行"
}

Start-Sleep 2

# ── 清理防火墙（可选）─────────────────────────────────────────
Write-Step "[3/3] 防火墙规则..." "Yellow"

$rules = @("IPv8-Portal-Inbound-$PortalPort", "IPv8-DNS-Inbound-5353", "IPv8-Cloudflared-Outbound")
if ($CleanFirewall) {
    foreach ($r in $rules) {
        $rule = Get-NetFirewallRule -DisplayName $r -ErrorAction SilentlyContinue
        if ($rule) {
            Remove-NetFirewallRule -DisplayName $r -ErrorAction SilentlyContinue
            Write-OK "已移除防火墙规则: $r"
        }
    }
} else {
    foreach ($r in $rules) {
        $rule = Get-NetFirewallRule -DisplayName $r -ErrorAction SilentlyContinue
        if ($rule) {
            Write-OK "保留防火墙规则: $r（下次启动可直接复用）"
        }
    }
}

# 清理 PID 文件
if (Test-Path $pidFile) {
    Remove-Item $pidFile -Force -ErrorAction SilentlyContinue
}

Write-Step "`n═══════════════════════════════════════════════════════" "Green"
Write-Step "  IPv8+ 服务已全部终止" "Green"
Write-Step "═══════════════════════════════════════════════════════`n" "Green"
