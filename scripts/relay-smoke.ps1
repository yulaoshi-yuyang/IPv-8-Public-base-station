# ADR-026 level-3 relay e2e smoke (same machine, loopback WS).
# Topology: relay <- nodeB(echo) , relay <- nodeA(initiator).
# A and B NEVER talk directly - every frame crosses the relay table lookup.
# PASS = A prints "PASS" (3 byte-exact echoes) + relay stats forwarded>0.
# Pure ASCII (PS 5.1 rule).
$ErrorActionPreference = 'Stop'
$exe = Join-Path $PSScriptRoot '..\target\smoke\release\ipv8-ws-node.exe'
$log = Join-Path $env:TEMP 'ipv8-relay-smoke'
New-Item -ItemType Directory -Force -Path $log | Out-Null
Remove-Item (Join-Path $log '*.log') -ErrorAction SilentlyContinue

$ca = 'C4' * 32
$addrA = '0000fb140000000a0001000001000000'
$addrB = '0000fb140000000b0001000001000000'
$seedA = 'A1' * 32
$seedB = 'B0' * 32

# 1) relay
$pr = Start-Process $exe -ArgumentList @('relay','--listen','127.0.0.1:9100','--ca-seed',$ca) -PassThru -WindowStyle Hidden `
      -RedirectStandardOutput (Join-Path $log 'relay.log') -RedirectStandardError (Join-Path $log 'relay.err')
Start-Sleep -Seconds 2

# 2) B = echo side (registers, answers echoes; must be up BEFORE A times out)
$pb = Start-Process $exe -ArgumentList @('relay-node','--url','ws://127.0.0.1:9100','--ca-seed',$ca,
      '--addr',$addrB,'--peer',$addrA,'--seed',$seedB) -PassThru -WindowStyle Hidden `
      -RedirectStandardOutput (Join-Path $log 'B.log') -RedirectStandardError (Join-Path $log 'B.err')
Start-Sleep -Seconds 2

# 3) A = initiator (handshake through relay, 3 inject/echo rounds, 90s cap)
$pa = Start-Process $exe -ArgumentList @('relay-node','--url','ws://127.0.0.1:9100','--ca-seed',$ca,
      '--addr',$addrA,'--peer',$addrB,'--seed',$seedA,'--initiate','--until','3') -PassThru -WindowStyle Hidden `
      -RedirectStandardOutput (Join-Path $log 'A.log') -RedirectStandardError (Join-Path $log 'A.err')

$verdict = 'FAIL'
try {
  $deadline = (Get-Date).AddSeconds(100)
  while ((Get-Date) -lt $deadline) {
    if ($pa.HasExited) { break }
    Start-Sleep -Seconds 2
  }
  $a = Get-Content (Join-Path $log 'A.log') -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
  $r = Get-Content (Join-Path $log 'relay.log') -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
  if ($a) { ($a -split "`r?`n") | ForEach-Object { Write-Host "A| $_" } }
  if ($r) { ($r -split "`r?`n") | Select-Object -Last 6 | ForEach-Object { Write-Host "R| $_" } }
  $ae = Get-Content (Join-Path $log 'A.err') -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
  if ($ae) { Write-Host "A(err)| $ae" }
  if ($a -match 'PASS' -and $r -match 'forwarded=([1-9])') { $verdict = 'PASS' }
}
finally {
  foreach ($p in @($pr,$pb,$pa)) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
}
Write-Host "RELAY-SMOKE: $verdict"
if ($verdict -eq 'PASS') { exit 0 } else { exit 1 }
