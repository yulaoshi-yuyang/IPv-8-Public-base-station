<#
  notun-selftest.ps1 - prove the --no-tun datapath end-to-end on ONE host over
  real UDP loopback, WITHOUT admin and WITHOUT loading wintun. This is the
  fallback validation for machines where security software blocks adapter
  creation: it exercises the tunnel core (auth handshake + AEAD seal/open +
  synthetic echo byte-verify) across a real UDP socket.
  Pure ASCII (PS 5.1 GBK parsing hazard).
#>
param(
    [string]$Exe = '',
    [int]$NtSize = 64
)
$ErrorActionPreference = 'Stop'
# Source-of-truth policy: prefer the freshly-built workspace binary
# (target\release) over any copied exe next to this script, so a stale
# copy can never masquerade as current code. Copy-only fallback for
# machines that have the peer pack but no repo.
if (-not $Exe) {
    $fresh = Join-Path (Split-Path $PSScriptRoot -Parent) 'target\release\ipv8-node.exe'
    $local = Join-Path $PSScriptRoot 'ipv8-node.exe'
    $Exe = if (Test-Path $fresh) { $fresh } else { $local }
}
$log = Join-Path $env:TEMP 'ipv8-notun-selftest'
New-Item -ItemType Directory -Force -Path $log | Out-Null
$la = Join-Path $log 'A.out'; $lb = Join-Path $log 'B.out'
Remove-Item $la, $lb, (Join-Path $log 'A.err'), (Join-Path $log 'B.err') -ErrorAction SilentlyContinue
$addrA = '0000fb140000000a0001000001000000'
$addrB = '0000fb140000000b0001000001000000'
$ca = 'C4' * 32
if (-not (Test-Path $Exe)) { Write-Host "missing $Exe"; exit 1 }

# B: passive responder, no-tun (no wintun.dll touched, no elevation)
$pb = Start-Process $Exe -PassThru -WindowStyle Hidden `
      -RedirectStandardOutput $lb -RedirectStandardError (Join-Path $log 'B.err') `
      -ArgumentList @('--self',$addrB,'--peer-addr',$addrA,'--peer-ip','127.0.0.1',
                      '--udp-port','45801','--peer-port','45800','--no-tun','--learn-peer',
                      '--nt-size',"$NtSize",
                      '--auth','--ca-seed',$ca,'--ed-seed',('B0'*32))
# A: initiator, no-tun, injects synthetic packets after Established
$pa = Start-Process $Exe -PassThru -WindowStyle Hidden `
      -RedirectStandardOutput $la -RedirectStandardError (Join-Path $log 'A.err') `
      -ArgumentList @('--self',$addrA,'--peer-addr',$addrB,'--peer-ip','127.0.0.1',
                      '--udp-port','45800','--peer-port','45801','--no-tun','--initiate','--nt-size',"$NtSize",
                      '--auth','--ca-seed',$ca,'--ed-seed',('A1'*32))

$ok = $false; $atxt = ''
$deadline = (Get-Date).AddSeconds(40)
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 2
    $atxt = Get-Content $la -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
    if ($atxt -and $atxt -match 'ECHO_OK #(\d+)') { $ok = $true; break }
    if ($pa.HasExited -or $pb.HasExited) { break }
}
Write-Host '==================== A (initiator) tail ===================='
Get-Content $la -Encoding UTF8 -Tail 12 -ErrorAction SilentlyContinue
Write-Host '==================== B (responder) tail ===================='
Get-Content $lb -Encoding UTF8 -Tail 6 -ErrorAction SilentlyContinue
Write-Host '==================== A.err (if any) ======================'
Get-Content (Join-Path $log 'A.err') -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
Write-Host '==================== B.err (if any) ======================'
Get-Content (Join-Path $log 'B.err') -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
Stop-Process -Id $pa.Id,$pb.Id -Force -ErrorAction SilentlyContinue

if ($ok) {
    $m = [regex]::Match($atxt, 'ECHO_OK #(\d+)')
    Write-Host "SELFTEST RESULT: PASS (cross-UDP no-tun tunnel echoed + byte-verified, count=$($m.Groups[1].Value))"
    exit 0
} else {
    Write-Host 'SELFTEST RESULT: FAIL'
    exit 1
}
