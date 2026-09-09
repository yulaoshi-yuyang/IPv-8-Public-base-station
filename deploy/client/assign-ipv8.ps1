$ipv8Addr = "fd00:8918::1"
$prefix = 64

Write-Host "=== Assign IPv8 Address ===" -ForegroundColor Cyan

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "Need admin! Re-launching..." -ForegroundColor Yellow
    Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Wait
    exit
}

Write-Host "[1/2] Assigning $ipv8Addr/$prefix to WLAN..."
netsh interface ipv6 add address "WLAN" $ipv8Addr/$prefix
if ($LASTEXITCODE -eq 0) {
    Write-Host "  OK" -ForegroundColor Green
} else {
    Write-Host "  Failed (might already exist)" -ForegroundColor Yellow
}

$eth = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.Name -ne "WLAN" } | Select-Object -First 1
if ($eth) {
    Write-Host "[2/2] Assigning to $($eth.Name)..."
    netsh interface ipv6 add address $eth.Name $ipv8Addr/$prefix 2>$null
}

Write-Host "`n=== Result ===" -ForegroundColor Cyan
Get-NetIPAddress | Where-Object { $_.IPAddress -like "fd00:*" } | Select-Object IPAddress, PrefixLength, InterfaceAlias | Format-Table -AutoSize

Write-Host "Done. Open Settings > Network > WiFi to see the address." -ForegroundColor Green
Read-Host "Press Enter to close"
