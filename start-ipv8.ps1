# ============================================================
# IPv8+ 一键启动：门户 + Cloudflare 隧道 + 防火墙规则
#
# 流程：
#   0. 清理旧进程（端口 9001 + cloudflared）
#   1. 配置防火墙（放行 9001 入站 + cloudflared 出站）
#   2. 启动门户网站（HTTP 9001 + DNS + DHCP）
#   3. 等待门户 HTTP 200 响应
#   4. 启动 cloudflared 隧道（QUIC 协议，指向 ipv8.yulaoshi.xyz）
#   5. 验证隧道连通
#
# 用法：
#   .\start-ipv8.ps1                 前台运行（Ctrl+C 停止）
#   .\start-ipv8.ps1 -Background    后台运行
# ============================================================

param(
    [switch]$Background,
    [int]$PortalPort = 9001,
    [switch]$InstallAutoStart,
    [switch]$RemoveAutoStart
)

# -- 开机自启管理（独立入口，执行后直接退出，不进入启动流程）--
$taskName = "IPv8-AutoStart"

if ($InstallAutoStart -or $RemoveAutoStart) {
    $scriptPath = $MyInvocation.MyCommand.Path

    if ($InstallAutoStart) {
        $action = New-ScheduledTaskAction -Execute "powershell.exe" `
            -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`" -Background" `
            -WorkingDirectory $PSScriptRoot

        $trigger = New-ScheduledTaskTrigger -AtLogOn
        $trigger.Delay = "PT30S"   # 登录后延迟 30 秒启动

        # 注意：RestartInterval 系统硬限制最小 1 分钟（PT1M），30 秒会被拒绝
        $settings = New-ScheduledTaskSettingsSet `
            -StartWhenAvailable `
            -RestartCount 3 `
            -RestartInterval (New-TimeSpan -Minutes 1) `
            -AllowStartIfOnBatteries `
            -DontStopIfGoingOnBatteries `
            -ExecutionTimeLimit (New-TimeSpan -Seconds 0) `
            -MultipleInstances IgnoreNew

        $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" `
            -LogonType Interactive -RunLevel Limited

        try {
            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
                -Settings $settings -Principal $principal -Force -ErrorAction Stop | Out-Null
        } catch {
            Write-Host "[X] 注册失败：$_" -ForegroundColor Red
            exit 1
        }

        Write-Host "[OK] 已注册开机自启任务：$taskName" -ForegroundColor Green
        Write-Host "  登录后 30 秒自动启动，失败每 1 分钟重试（最多 3 次，系统最小间隔）"
        Write-Host "  查看：Get-ScheduledTask -TaskName $taskName"
        exit 0
    }

    if ($RemoveAutoStart) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
            Write-Host "[X] 移除失败" -ForegroundColor Red
            exit 1
        }
        Write-Host "[OK] 已移除开机自启任务：$taskName" -ForegroundColor Green
        exit 0
    }
}

$ErrorActionPreference = "Stop"
$projectRoot = $PSScriptRoot
$portalScript = Join-Path $projectRoot "deploy\portal\ipv8-portal.ps1"
$cloudflared = Join-Path $projectRoot "tools\cloudflared\cloudflared.exe"
$tunnelConfig = Join-Path $projectRoot "tools\cloudflared\config.yml"
$logDir = Join-Path $projectRoot "deploy\portal\logs"
$pidFile = Join-Path $logDir "ipv8-all.pid"

if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }

function Write-Step { param([string]$Text, [string]$Color = "Cyan") Write-Host $Text -ForegroundColor $Color }
function Write-OK { param([string]$Text) Write-Host "  [OK] $Text" -ForegroundColor Green }
function Write-Warn { param([string]$Text) Write-Host "  [!] $Text" -ForegroundColor Yellow }
function Write-Fail { param([string]$Text) Write-Host "  [X] $Text" -ForegroundColor Red }

# -- 0. 清理旧进程 --
Write-Step "`n=== IPv8+ 一键启动 ===" "Cyan"
Write-Step "[0/5] 清理旧进程..." "Yellow"

# 杀端口占用
Get-NetTCPConnection -LocalPort $PortalPort -State Listen -ErrorAction SilentlyContinue | ForEach-Object {
    if ($_.OwningProcess -gt 4) {
        $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        if ($p -and $p.ProcessName -in @("powershell","pwsh","python","node")) {
            Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue
        }
    }
}

# 杀旧 cloudflared
Get-Process cloudflared -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep 2
Write-OK "旧进程已清理"

# -- 检查管理员权限 --
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# -- 1. 防火墙规则 --
Write-Step "[1/5] 配置防火墙规则..." "Yellow"

if ($isAdmin) {
    # 入站：放行 9001（门户端口）
    $inboundRule = "IPv8-Portal-Inbound-$PortalPort"
    $existingIn = Get-NetFirewallRule -DisplayName $inboundRule -ErrorAction SilentlyContinue
    if (-not $existingIn) {
        New-NetFirewallRule -DisplayName $inboundRule -Direction Inbound -Protocol TCP -LocalPort $PortalPort -Action Allow -Profile Any | Out-Null
        Write-OK "入站规则已创建：TCP $PortalPort（放行）"
    } else {
        Write-OK "入站规则已存在：TCP $PortalPort"
    }

    # 入站：放行 UDP 5353（DNS）
    $dnsRule = "IPv8-DNS-Inbound-5353"
    $existingDns = Get-NetFirewallRule -DisplayName $dnsRule -ErrorAction SilentlyContinue
    if (-not $existingDns) {
        New-NetFirewallRule -DisplayName $dnsRule -Direction Inbound -Protocol UDP -LocalPort 5353 -Action Allow -Profile Any | Out-Null
        Write-OK "入站规则已创建：UDP 5353（DNS）"
    } else {
        Write-OK "入站规则已存在：UDP 5353"
    }

    # 出站：放行 cloudflared（QUIC UDP 443 + HTTPS TCP 443）
    $outboundRule = "IPv8-Cloudflared-Outbound"
    $existingOut = Get-NetFirewallRule -DisplayName $outboundRule -ErrorAction SilentlyContinue
    if (-not $existingOut) {
        New-NetFirewallRule -DisplayName $outboundRule -Direction Outbound -Program $cloudflared -Action Allow -Profile Any | Out-Null
        Write-OK "出站规则已创建：cloudflared（QUIC + HTTPS）"
    } else {
        Write-OK "出站规则已存在：cloudflared"
    }
} else {
    Write-Warn "非管理员模式，跳过防火墙配置（防火墙规则需管理员权限）"
    Write-Host "  如需配置防火墙，请右键 -> 以管理员身份运行" -ForegroundColor DarkGray
}

# -- 2. 启动门户 --
Write-Step "[2/5] 启动门户网站（端口 $PortalPort）..." "Yellow"

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$portalLog = Join-Path $logDir "portal-$stamp.log"

if ($Background) {
    $portalProc = Start-Process -FilePath "powershell" `
        -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$portalScript`" -HttpPort $PortalPort" `
        -WindowStyle Hidden -PassThru
    $portalPid = $portalProc.Id
} else {
    $portalProc = Start-Process -FilePath "powershell" `
        -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$portalScript`" -HttpPort $PortalPort" `
        -WindowStyle Minimized -PassThru
    $portalPid = $portalProc.Id
}

Write-OK "门户进程已启动 (PID: $portalPid)"

# -- 3. 等待 HTTP 200 --
Write-Step "[3/5] 等待门户就绪..." "Yellow"

$ready = $false
for ($i = 0; $i -lt 30; $i++) {
    Start-Sleep 1
    try {
        $resp = Invoke-WebRequest -Uri "http://127.0.0.1:$PortalPort" -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop
        if ($resp.StatusCode -eq 200) {
            $ready = $true
            break
        }
    } catch {
        # 还没就绪，继续等
    }
    Write-Host "." -NoNewline
}

if ($ready) {
    Write-OK "门户已就绪 (HTTP 200)"
} else {
    Write-Fail "门户 30 秒内未就绪，仍继续启动隧道..."
}

# -- 4. 启动 cloudflared 隧道 --
Write-Step "[4/5] 启动 Cloudflare 隧道..." "Yellow"

if (-not (Test-Path $cloudflared)) {
    Write-Fail "cloudflared.exe 不存在: $cloudflared"
    Write-Warn "跳过隧道启动，门户仍可局域网访问"
} elseif (-not (Test-Path $tunnelConfig)) {
    Write-Fail "隧道配置文件不存在: $tunnelConfig"
    Write-Warn "跳过隧道启动"
} else {
    $tunnelArgs = "tunnel --config `"$tunnelConfig`" run --protocol quic"

    # cloudflared 在网络未就绪时（如开机自启早期，DNS 解析 argotunnel.com 超时）会
    # 直接退出，因此启动后检测到进程退出就重启，最多 3 次，间隔 10 秒。
    # 每次尝试用独立日志文件，避免重启时覆盖前一次失败的证据。
    $tunnelOk = $false
    $tunnelPid = 0
    for ($attempt = 1; $attempt -le 3 -and -not $tunnelOk; $attempt++) {
        $tunnelLog = Join-Path $logDir "tunnel-$stamp-attempt$attempt.log"
        $tunnelErr = Join-Path $logDir "tunnel-$stamp-attempt$attempt-err.log"
        if ($attempt -gt 1) {
            Write-Warn "隧道进程已退出（第 $($attempt-1) 次，多为开机早期 DNS 未就绪），10 秒后重启..."
            Start-Sleep 10
        }
        $tunnelProc = Start-Process -FilePath $cloudflared `
            -ArgumentList $tunnelArgs `
            -WindowStyle Hidden -PassThru -RedirectStandardOutput $tunnelLog -RedirectStandardError $tunnelErr
        $tunnelPid = $tunnelProc.Id
        Write-OK "隧道进程已启动 (PID: $tunnelPid)"
        Write-Host "  日志: $tunnelLog" -ForegroundColor DarkGray

        # -- 5. 验证隧道 --
        Write-Step "[5/5] 验证隧道连通..." "Yellow"
        Start-Sleep 5

        for ($i = 0; $i -lt 12; $i++) {
            if ($tunnelProc.HasExited) { break }   # 进程已死，别傻等，回到重启
            try {
                $resp = Invoke-WebRequest -Uri "https://ipv8.yulaoshi.xyz" -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
                if ($resp.StatusCode -eq 200) {
                    $tunnelOk = $true
                    break
                }
            } catch {
                # 隧道还在连接中
            }
            Start-Sleep 2
            Write-Host "." -NoNewline
        }
    }

    if ($tunnelOk) {
        Write-OK "隧道连通: https://ipv8.yulaoshi.xyz -> 127.0.0.1:$PortalPort"
    } else {
        # 设计意图：隧道失败不抛错、不 exit 1。门户已起来是主目标，
        # 隧道是"尽力而为"——计划任务的 -RestartCount 仅在非零退出时触发，
        # 若此处 exit 1 会导致整个服务（含门户）被每分钟重启，得不偿失。
        # 隧道自身已有 3 次重启循环兜底。
        Write-Warn "隧道仍未连通（重试 3 次），请检查 deploy\portal\logs\ 下 tunnel 日志后手动运行 start-ipv8.ps1"
    }

    # 记录 PID
    "$portalPid`n$tunnelPid" | Set-Content -Path $pidFile -Encoding UTF8
}

# -- 完成 --
Write-Step "`n=======================================================" "Green"
Write-Step "  IPv8+ 服务已启动" "Green"
Write-Step "=======================================================" "Green"
Write-Host "`n  门户地址:   http://127.0.0.1:$PortalPort"
Write-Host "  外网地址:   https://ipv8.yulaoshi.xyz"
Write-Host "  防火墙:     入站 TCP $PortalPort + UDP 5353 已放行"
Write-Host "  隧道协议:   QUIC (UDP 443 出站)"
Write-Host "`n  终止服务:   .\stop-ipv8.ps1  或双击 一键终止.bat"
Write-Host "=======================================================`n" -ForegroundColor Green

if (-not $Background) {
    Write-Host "门户在前台运行，按 Ctrl+C 或运行 stop-ipv8.ps1 终止。" -ForegroundColor DarkGray
}
