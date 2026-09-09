param(
    [switch]$InstallAsService,
    [int]$PortalPort = 9001
)

$scriptDir = $PSScriptRoot
$projectRoot = Split-Path (Split-Path $scriptDir)
$cloudflared = Join-Path $projectRoot "tools\cloudflared\cloudflared.exe"
$portal = Join-Path $scriptDir "ipv8-portal.ps1"

Write-Host "=== IPv8+ Portal + Tunnel ===" -ForegroundColor Cyan

# Step 0: Kill everything on the port
Write-Host "[0/3] Cleaning up..." -ForegroundColor Yellow
Get-NetTCPConnection -LocalPort $PortalPort -ErrorAction SilentlyContinue | ForEach-Object {
    Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue
}
Get-Process cloudflared -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep 3
Write-Host "  Done" -ForegroundColor Green

# Step 1: Start cloudflared in background (non-blocking)
Write-Host "[1/3] Starting cloudflared tunnel (QUIC)..." -ForegroundColor Yellow
if (Test-Path $cloudflared) {
    $tunnelJob = Start-Job -ScriptBlock {
        param($cf)
        & $cf tunnel run --protocol quic 2>&1
    } -ArgumentList $cloudflared
    Write-Host "  Tunnel started (background job)" -ForegroundColor Green
} else {
    Write-Host "  WARNING: cloudflared not found, skipping tunnel" -ForegroundColor Yellow
}

# Step 2: Wait a moment for tunnel to connect
Start-Sleep 2

# Step 3: Start portal in foreground (this keeps the script alive)
Write-Host "[2/3] Starting portal on port $PortalPort..." -ForegroundColor Yellow
Write-Host "[3/3] Portal running. Press Ctrl+C to stop.`n" -ForegroundColor Green

# Run portal directly in this process (not Start-Process)
& $portal -HttpPort $PortalPort
