param(
    [switch]$InstallAsService,
    [int]$PortalPort = 9001
)

# ============================================================
# IPv8+ Portal + Tunnel (hidden mode)
# Delegates to start-website.ps1, which starts the portal and
# cloudflared tunnel in HIDDEN windows:
#   - No console window stays on screen (safe to close this one)
#   - Output goes to deploy\portal\logs\portal-*.log / tunnel-*.log
#   - PID recorded in logs\website.pid
# Stop everything with:  .\stop-website.ps1 -IncludeTunnel
# ============================================================

$scriptDir = $PSScriptRoot
$starter = Join-Path $scriptDir "start-website.ps1"

Write-Host "=== IPv8+ Portal + Tunnel (hidden mode) ===" -ForegroundColor Cyan

# -Force keeps the original start-all behavior: always clean up
# old instances / port 9001 listeners before starting.
# -WithTunnel starts cloudflared (QUIC) alongside the portal.
& $starter -PortalPort $PortalPort -WithTunnel -Force

Write-Host ""
Write-Host "You can close this window now. Portal keeps running in background." -ForegroundColor Green
Write-Host "View logs:   deploy\portal\logs\" -ForegroundColor Gray
Write-Host "Stop server: .\stop-website.ps1 -IncludeTunnel" -ForegroundColor Gray
