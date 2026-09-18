# ============================================================
# IPv8+ 网站 一键启动
# 后台启动门户网站（HTTP + DNS + DHCP），并做健康检查
#
# 用法：
#   .\start-website.ps1                  默认启动（HTTP 9001 / DNS 5353）
#   .\start-website.ps1 -PortalPort 9002 换端口启动
#   .\start-website.ps1 -WithTunnel      同时启动 cloudflared 隧道
#   .\start-website.ps1 -Force           先结束已有实例再启动
#
# 结束服务请运行：.\stop-website.ps1
# ============================================================

param(
    [int]$PortalPort = 9001,
    [int]$DnsPort = 5353,
    [switch]$WithTunnel,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

$scriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path (Split-Path $scriptDir)

$portalScript = Join-Path $scriptDir  "ipv8-portal.ps1"
$cloudflared  = Join-Path $projectRoot "tools\cloudflared\cloudflared.exe"

$logDir = Join-Path $scriptDir "logs"
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }

$stamp    = Get-Date -Format "yyyyMMdd-HHmmss"
$pidFile  = Join-Path $logDir "website.pid"
$portalLog = Join-Path $logDir "portal-$stamp.log"
$tunnelLog = Join-Path $logDir "tunnel-$stamp.log"

function Write-Step {
    param([string]$Text, [string]$Color = "Cyan")
    Write-Host $Text -ForegroundColor $Color
}

function Test-PortBusy {
    param([int]$Port)
    $conn = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
    return [bool]$conn
}

# ---------- 0. 前置检查 ----------
Write-Step "=== IPv8+ 网站 一键启动 ==="

if (-not (Test-Path $portalScript)) {
    Write-Step "[X] 找不到门户脚本：$portalScript" "Red"
    exit 1
}

# 已在运行则不重复启动（除非 -Force）
$runningPids = @()
if (Test-Path $pidFile) {
    $runningPids = @(Get-Content $pidFile -ErrorAction SilentlyContinue |
                     Where-Object { $_ -match '^\d+$' } |
                     ForEach-Object { [int]$_ })
}
$alivePids = @($runningPids | Where-Object { Get-Process -Id $_ -ErrorAction SilentlyContinue })

if (($alivePids.Count -gt 0 -or (Test-PortBusy $PortalPort)) -and -not $Force) {
    Write-Step "[!] 网站可能已在运行" "Yellow"
    if ($alivePids.Count -gt 0) { Write-Step "    已记录进程 PID: $($alivePids -join ', ')" "Gray" }
    Write-Step "    如需重启，请先执行 stop-website.ps1，或加 -Force 参数" "Gray"
    exit 1
}

# ---------- 1. 清理旧实例 ----------
if ($Force) {
    Write-Step "[1/4] 清理已有实例..." "Yellow"
    foreach ($p in $runningPids) {
        Stop-Process -Id $p -Force -ErrorAction SilentlyContinue
    }
    Get-NetTCPConnection -LocalPort $PortalPort -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty OwningProcess -Unique |
        ForEach-Object { Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue }
    Get-Process cloudflared -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Write-Step "      完成" "Green"
} else {
    Write-Step "[1/4] 无需清理" "Gray"
}

# ---------- 2. cloudflared 隧道（可选） ----------
Write-Step "[2/4] 启动外网隧道..." "Yellow"
$tunnelPid = $null
if ($WithTunnel) {
    if (Test-Path $cloudflared) {
        $tunnelProc = Start-Process -FilePath $cloudflared `
            -ArgumentList @("tunnel","run","--protocol","quic") `
            -WindowStyle Hidden -PassThru `
            -RedirectStandardOutput $tunnelLog -RedirectStandardError "$tunnelLog.err"
        $tunnelPid = $tunnelProc.Id
        Write-Step "      cloudflared PID=$tunnelPid，日志：$tunnelLog" "Green"
    } else {
        Write-Step "      跳过：未找到 $cloudflared" "Yellow"
    }
} else {
    Write-Step "      跳过（未指定 -WithTunnel）" "Gray"
}

# ---------- 3. 后台启动门户 ----------
Write-Step "[3/4] 启动门户网站（HTTP $PortalPort / DNS $DnsPort）..." "Yellow"

function Get-ParentPid {
    param([int]$ChildPid)
    try {
        $p = Get-CimInstance Win32_Process -Filter "ProcessId=$ChildPid" -ErrorAction Stop
        if ($p -and $p.ParentProcessId) { return [int]$p.ParentProcessId }
    } catch {}
    return $null
}

try {
    $portalProc = Start-Process -FilePath "powershell.exe" `
        -ArgumentList @(
            "-NoProfile",
            "-ExecutionPolicy","Bypass",
            "-File","`"$portalScript`"",
            "-HttpPort",$PortalPort,
            "-DnsPort",$DnsPort
        ) `
        -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput $portalLog -RedirectStandardError "$portalLog.err"
} catch {
    Write-Step "      启动失败：$($_.Exception.Message)" "Red"
    exit 1
}

$portalPid   = $portalProc.Id
$launcherPid = Get-ParentPid $portalPid

# 记录需要结束的进程（倒序即为停止顺序）
$trackPids = @($portalPid)
if ($launcherPid -and $launcherPid -ne $PID) { $trackPids += $launcherPid }
if ($tunnelPid) { $trackPids += $tunnelPid }
Set-Content -Path $pidFile -Value ($trackPids -join "`r`n") -Encoding ASCII

Write-Step "      门户 PID=$portalPid，日志：$portalLog" "Green"

# ---------- 4. 健康检查 ----------
Write-Step "[4/4] 等待服务就绪..." "Yellow"
$ready = $false
for ($i = 0; $i -lt 20; $i++) {
    Start-Sleep -Milliseconds 800

    # 进程已退出说明启动失败，直接报错，不要傻等
    if (-not (Get-Process -Id $portalPid -ErrorAction SilentlyContinue)) {
        Write-Step "      门户进程已退出，启动失败" "Red"
        $errLog = "$portalLog.err"
        if ((Test-Path $portalLog) -and (Get-Item $portalLog).Length -gt 0) {
            Write-Step "      --- 日志摘要 ---" "Gray"
            Get-Content $portalLog -Tail 15 -ErrorAction SilentlyContinue |
                ForEach-Object { Write-Step "      $_" "Gray" }
        }
        if ((Test-Path $errLog) -and (Get-Item $errLog).Length -gt 0) {
            Write-Step "      --- 错误输出 ---" "Gray"
            Get-Content $errLog -Tail 15 -ErrorAction SilentlyContinue |
                ForEach-Object { Write-Step "      $_" "Red" }
        }
        Remove-Item $pidFile -Force -ErrorAction SilentlyContinue
        exit 1
    }

    try {
        $resp = Invoke-WebRequest -Uri "http://127.0.0.1:$PortalPort/api/status" `
                    -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop
        if ($resp.StatusCode -eq 200) { $ready = $true; break }
    } catch {
        # 继续等待
    }
}

if (-not $ready) {
    Write-Step "      超时：15 秒内未通过健康检查，请查看日志 $portalLog" "Yellow"
    exit 2
}

Write-Step ""
Write-Step "=== 启动成功 ===" "Green"
Write-Step "  进程 PID : $($trackPids -join ', ')"
Write-Step "  本地访问 : http://127.0.0.1:$PortalPort"
Write-Step "  DNS 服务 : 127.0.0.1:$DnsPort (UDP)"
if ($tunnelPid) { Write-Step "  外网隧道 : cloudflared PID=$tunnelPid" }
Write-Step "  运行日志 : $portalLog"
Write-Step ""
Write-Step "结束服务：.\stop-website.ps1" "Gray"
exit 0
