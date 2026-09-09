#requires -RunAsAdministrator
# IPv8 full setup: proper address + DNS resolver + NRPT
# Does NOT change DHCP/auto mode - only adds IPv8 address

$ipv8Addr = "fb14:0000:0000:0001:0001:0000:0001:0000"
$nrptNs = ".ipv8.net"
$dnsServer = "127.0.0.1"

Write-Host "=== IPv8 Full Setup ===" -ForegroundColor Cyan

# 1. Remove the fake fd00:8918::1
Write-Host "[1/5] Removing fake IPv8 address (fd00:8918::1)..."
netsh interface ipv6 delete address "WLAN" "fd00:8918::1" 2>$null
if ($LASTEXITCODE -eq 0) { Write-Host "  Removed" -ForegroundColor Green }
else { Write-Host "  Not found (ok)" -ForegroundColor Yellow }

# 2. Assign real IPv8 address (fb14 prefix = IPv8 identifier)
Write-Host "[2/5] Assigning real IPv8 address: $ipv8Addr"
netsh interface ipv6 add address "WLAN" $ipv8Addr/64
if ($LASTEXITCODE -eq 0) { Write-Host "  OK" -ForegroundColor Green }
else { Write-Host "  Failed" -ForegroundColor Red }

# 3. Setup NRPT: .ipv8.net DNS goes to local resolver, NOT external DNS
Write-Host "[3/5] Setting up NRPT rule for $nrptNs -> $dnsServer..."
$existing = Get-DnsClientNrptRule | Where-Object { $_.Namespace -eq $nrptNs }
if ($existing) {
    Write-Host "  NRPT rule already exists, skipping" -ForegroundColor Yellow
} else {
    Add-DnsClientNrptRule -Namespace $nrptNs -NameServers $dnsServer
    Write-Host "  NRPT rule added" -ForegroundColor Green
}

# 4. Verify address is visible
Write-Host "[4/5] Verifying IPv8 address..."
$found = Get-NetIPAddress -InterfaceAlias "WLAN" | Where-Object { $_.IPAddress -like "fb14:*" }
if ($found) {
    Write-Host "  IPv8 address visible:" -ForegroundColor Green
    $found | Select-Object IPAddress, PrefixLength, InterfaceAlias | Format-Table -AutoSize
} else {
    Write-Host "  IPv8 address NOT found" -ForegroundColor Red
}

# 5. Show NRPT
Write-Host "[5/5] Current NRPT rules:"
Get-DnsClientNrptRule | Select-Object Namespace, NameServers | Format-Table -AutoSize

Write-Host "`n=== DONE ===" -ForegroundColor Green
Write-Host "IPv8 address: $ipv8Addr"
Write-Host "DNS: .ipv8.net queries now go to local resolver (127.0.0.1)"
Write-Host "WiFi still uses DHCP for IPv4/IPv6 - IPv8 is additive"
Read-Host "Press Enter to close"
