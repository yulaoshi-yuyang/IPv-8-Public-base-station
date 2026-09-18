# ============================================================
# IPv8+ 网站 一键结束
# 按 PID 记录 + 端口占用双重定位，结束门户与隧道进程
#
# 用法：
#   .\stop-website.ps1                  结束门户网站（默认端口 9001）
#   .\stop-website.ps1 -PortalPort 9002 指定端口
#   .\stop-website.ps1 -IncludeTunnel   同时结束 cloudflared 隧道
#   .\stop-website.ps1 -Status          只查看运行状态，不做任何结束动作
#
# 注意：本脚本只结束进程，不会删除 DHCP 地址分配等运行数据。
# ============================================================

param(
    [int]$PortalPort = 9001,
    [switch]$IncludeTunnel,
    [switch]$Status
)

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$logDir    = Join-Path $scriptDir "logs"
$pidFile   = Join-Path $logDir "website.pid"

# 受保护的系统进程 PID：HttpListener 走 http.sys 内核驱动，
# 端口连接的 OwningProcess 会显示为 System(4)，绝不能对其执行结束操作。
$ProtectedPids = @(0, 4)

function Write-Step {
    param([string]$Text, [string]$Color = "Cyan")
    Write-Host $Text -ForegroundColor $Color
}

function Test-SafePid {
    param([int]$ProcId)
    if ($ProcId -le 4) { return $false }
    if ($ProtectedPids -contains $ProcId) { return $false }
    $p = Get-Process -Id $ProcId -ErrorAction SilentlyContinue
    if (-not $p) { return $false }
    # 只允许结束 PowerShell 与隧道进程，避免端口归属误判波及无关程序
    if ($p.ProcessName -notin @("powershell","pwsh","cloudflared")) { return $false }
    return $true
}

# 收集与本网站相关的进程 PID（去重）
function Get-WebsitePids {
    param([bool]$WantTunnel)
    $found = New-Object System.Collections.Generic.List[int]

    # 1) 启动脚本记录的 PID
    if (Test-Path $pidFile) {
        Get-Content $pidFile -ErrorAction SilentlyContinue |
            Where-Object { $_ -match '^\d+$' } |
            ForEach-Object {
                $procId = [int]$_
                if ((Test-SafePid $procId) -and (-not $found.Contains($procId))) {
                    $found.Add($procId)
                }
            }
    }

    # 2) 命令行里跑着 ipv8-portal.ps1 的 PowerShell 进程（最可靠的识别方式）
    try {
        Get-CimInstance Win32_Process -Filter "Name='powershell.exe' OR Name='pwsh.exe'" -ErrorAction Stop |
            Where-Object { $_.CommandLine -and $_.CommandLine -match 'ipv8-portal\.ps1' } |
            ForEach-Object {
                $procId = [int]$_.ProcessId
                if ((Test-SafePid $procId) -and (-not $found.Contains($procId))) { $found.Add($procId) }
            }
    } catch {}

    # 3) 监听门户端口的进程（排除 http.sys 归属的 System）
    Get-NetTCPConnection -LocalPort $PortalPort -State Listen -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty OwningProcess -Unique |
        ForEach-Object {
            $procId = [int]$_
            if ((Test-SafePid $procId) -and (-not $found.Contains($procId))) { $found.Add($procId) }
        }

    # 4) 隧道进程（仅在指定时）
    if ($WantTunnel) {
        Get-Process cloudflared -ErrorAction SilentlyContinue |
            ForEach-Object {
                if (-not $found.Contains([int]$_.Id)) { $found.Add([int]$_.Id) }
            }
    }

    return @($found)
}

# ---------- 状态查看 ----------
$pids = Get-WebsitePids $IncludeTunnel

if ($Status) {
    Write-Step "=== IPv8+ 网站 运行状态 ==="
    if ($pids.Count -eq 0) {
        Write-Step "  未运行（无相关进程，端口 $PortalPort 空闲）" "Green"
    } else {
        Write-Step "  运行中，相关进程：" "Yellow"
        foreach ($procId in $pids) {
            $p = Get-Process -Id $procId -ErrorAction SilentlyContinue
            if ($p) {
                $up = ""
                try { $up = "，已运行 $([math]::Round(((Get-Date) - $p.StartTime).TotalMinutes,1)) 分钟" } catch {}
                Write-Step "    PID=$procId  $($p.ProcessName)$up"
            }
        }
    }
    $tun = @(Get-Process cloudflared -ErrorAction SilentlyContinue)
    Write-Step "  隧道进程 cloudflared: $(if ($tun.Count -gt 0) { "$($tun.Count) 个 (PID: $(($tun | ForEach-Object Id) -join ', '))" } else { '未运行' })"
    exit 0
}

# ---------- 结束服务 ----------
Write-Step "=== IPv8+ 网站 一键结束 ==="

if ($pids.Count -eq 0) {
    Write-Step "[i] 没有发现运行中的网站进程，端口 $PortalPort 已空闲" "Green"
    if (Test-Path $pidFile) { Remove-Item $pidFile -Force -ErrorAction SilentlyContinue }
    exit 0
}

Write-Step "[1/3] 目标进程: $($pids -join ', ')"

# 先温和请求退出，给 HttpListener / DNS runspace 收尾机会
foreach ($procId in $pids) {
    try {
        $p = Get-Process -Id $procId -ErrorAction Stop
        if (-not $p.HasExited) { $p.CloseMainWindow() | Out-Null }
    } catch {}
}
Start-Sleep -Milliseconds 1200

# 仍存活的强制结束
$stopped = @()
foreach ($procId in $pids) {
    $p = Get-Process -Id $procId -ErrorAction SilentlyContinue
    if (-not $p) { $stopped += $procId; continue }
    try {
        Stop-Process -Id $procId -Force -ErrorAction Stop
        $stopped += $procId
    } catch {
        Write-Step "      PID=$procId 结束失败：$($_.Exception.Message)" "Red"
    }
}
Start-Sleep -Milliseconds 800

# ---------- 复核 ----------
Write-Step "[2/3] 复核结果..." "Yellow"
$leftover = Get-WebsitePids $IncludeTunnel
if ($leftover.Count -eq 0) {
    Write-Step "      全部已结束" "Green"
} else {
    Write-Step "      仍有残留进程: $($leftover -join ', ')（可能需要管理员权限）" "Yellow"
}

$stillListening = @(Get-NetTCPConnection -LocalPort $PortalPort -State Listen -ErrorAction SilentlyContinue)
if ($stillListening.Count -eq 0) {
    Write-Step "      端口 $PortalPort 已释放" "Green"
} else {
    Write-Step "      端口 $PortalPort 仍被占用" "Yellow"
}

# ---------- 清理 PID 记录 ----------
Write-Step "[3/3] 清理运行记录..." "Yellow"
if (Test-Path $pidFile) { Remove-Item $pidFile -Force -ErrorAction SilentlyContinue }
Write-Step "      完成" "Green"

Write-Step ""
if ($leftover.Count -eq 0 -and $stillListening.Count -eq 0) {
    Write-Step "=== 网站已停止 ===" "Green"
    exit 0
} else {
    Write-Step "=== 停止未完成，请检查上面的残留提示 ===" "Yellow"
    exit 2
}
