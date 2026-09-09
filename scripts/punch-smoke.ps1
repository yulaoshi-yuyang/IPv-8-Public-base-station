# ADR-026 level-2 punch smoke test (same-machine, --no-tun, loopback UDP).
# Trick: initiator's configured peer entry points to a DEAD port; the tunnel
# can only establish via the candidate learned through Resolver rendezvous.
# Pure ASCII (PS 5.1 rule).
$ErrorActionPreference = 'Stop'
$exe = Join-Path $PSScriptRoot '..\target\smoke\release\ipv8-node.exe'
$zexe = Join-Path $PSScriptRoot '..\target\smoke\release\ipv8-resolver.exe'
$log = Join-Path $env:TEMP 'ipv8-punch-smoke'
New-Item -ItemType Directory -Force -Path $log | Out-Null
Remove-Item (Join-Path $log '*.log') -ErrorAction SilentlyContinue

$addrA = '0000fb140000000a0001000001000000'
$addrB = '0000fb140000000b0001000001000000'

# 1) resolver
$pz = Start-Process $zexe -ArgumentList @('--addr','127.0.0.1:7080') -PassThru -WindowStyle Hidden `
      -RedirectStandardOutput (Join-Path $log 'resolver.log') -RedirectStandardError (Join-Path $log 'resolver.err')
Start-Sleep -Seconds 2

# 2) responder B (passive, binds real UDP 45703)
$pb = Start-Process $exe -ArgumentList @(
  '--self',$addrB,'--peer-addr',$addrA,'--peer-ip','127.0.0.1','--udp-port','45703','--peer-port','45702',
  '--no-tun','--punch','--resolver','http://127.0.0.1:7080','--ed-seed',('B0'*32)) -PassThru -WindowStyle Hidden `
  -RedirectStandardOutput (Join-Path $log 'B.log') -RedirectStandardError (Join-Path $log 'B.err')

# 3) initiator A (active; static entry 127.0.0.2:45799 = DEAD on purpose)
$pa = Start-Process $exe -ArgumentList @(
  '--self',$addrA,'--peer-addr',$addrB,'--peer-ip','127.0.0.2','--peer-port','45799','--udp-port','45702',
  '--initiate','--no-tun','--punch','--resolver','http://127.0.0.1:7080','--ed-seed',('A1'*32)) -PassThru -WindowStyle Hidden `
  -RedirectStandardOutput (Join-Path $log 'A.log') -RedirectStandardError (Join-Path $log 'A.err')

$verdict = 'FAIL'
try {
  $deadline = (Get-Date).AddSeconds(60)
  while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 3
    $a = Get-Content (Join-Path $log 'A.log') -Raw -ErrorAction SilentlyContinue
    $b = Get-Content (Join-Path $log 'B.log') -Raw -ErrorAction SilentlyContinue
    if ($a -match 'Established' -and $a -match 'ECHO_OK' -and $b -match 'Established') { $verdict = 'PASS'; break }
  }
  # pull key evidence lines
  Select-String -Path (Join-Path $log 'A.log') -Pattern 'punch|Established|ECHO_OK' | Select-Object -First 12 | ForEach-Object { Write-Host ("A| " + $_.Line) }
  Select-String -Path (Join-Path $log 'B.log') -Pattern 'punch|Established|learn-peer' | Select-Object -First 12 | ForEach-Object { Write-Host ("B| " + $_.Line) }
}
finally {
  foreach ($p in @($pz,$pb,$pa)) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
}
Write-Host "PUNCH-SMOKE: $verdict"
if ($verdict -eq 'PASS') { exit 0 } else { exit 1 }
