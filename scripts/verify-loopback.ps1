<#
  Phase 1/2 loopback verification (Plan A): two ipv8-node instances on this host.
    topology:  IPv8Plus-A (TUN) -- Engine -- UDP 127.0.0.1:45701 <-> 45702 -- Engine -- IPv8Plus-B (TUN)
  What it proves: real wintun adapters, handshake over real UDP, and IP packets
  actually traversing seal -> wire -> open in BOTH directions (engine counters).

  Traffic model: two /32 host routes pin synthetic dsts to each TUN:
    ping 10.100.0.32 (/32 via IPv8Plus-A): request enters TUN-A -> A seals -> UDP ->
      B opens -> writes TUN-B -> non-local dst, client Windows won't forward -> dies.
      Counters: A.sealed+ and B.delivered+
    ping 10.100.0.33 (/32 via IPv8Plus-B): symmetric -> B.sealed+ and A.delivered+
  Cross-adapter ping RTT is short-circuited on a single machine (both .1/.2 are local),
  so pass/fail = the four engine counters growing, not ping replies.

  Auto-elevates via UAC. Usage:  powershell -File .\verify-loopback.ps1 [-Keep] [-Auth] [-Zone] [-Fragment] [-Fallback]
    -Auth : run BOTH nodes in Phase-2 certificate-authenticated handshake mode
            (default: shared preloaded CA seed = trust anchor; verification-only).
    -Zone : implies -Auth; starts a LOCAL ipv8-zoneserver and BOTH nodes enroll
            over gRPC for their certs/trust-anchor (CA private key never reaches
            the node side) - the production trust path.
    -Fragment : implies -Auth; TUN interface MTU 4000 > engine IPv8+ cap 1432 and
            ping -l 3000 drives real IPv8+ fragmentation (frags_sent/reassembled).
    -Fallback : node --fallback; A's main entry points at a DEAD UDP port so the
            FallbackManager must time out and cascade to the ALT entry (B's real
            port) before establishing - proves v9 S11 degradation path.

  NOTE: keep this file pure ASCII - Windows PowerShell 5.1 parses it as ANSI/GBK and
  non-ASCII comment bytes break statement structure.
#>
param([switch]$Keep, [switch]$Auth, [switch]$Zone, [switch]$Fragment, [switch]$Fallback)
if ($Zone) { $Auth = $true }
if ($Fragment) { $Auth = $true }

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
          ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$logDir  = Join-Path $env:TEMP 'ipv8-loopback'
$resFile = Join-Path $logDir 'result.txt'

if (-not $isAdmin) {
    New-Item -ItemType Directory -Force -Path $logDir | Out-Null
    Remove-Item $resFile -ErrorAction SilentlyContinue
    Write-Host "[verify] not elevated - requesting UAC (click Yes)..."
    $childArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    if ($Keep) { $childArgs += '-Keep' }
    if ($Auth) { $childArgs += '-Auth' }
    if ($Zone) { $childArgs += '-Zone' }
    if ($Fragment) { $childArgs += '-Fragment' }
    if ($Fallback) { $childArgs += '-Fallback' }
    try {
        $null = Start-Process powershell.exe -Verb RunAs -ArgumentList $childArgs -WindowStyle Hidden
    } catch {
        Write-Host "[verify] elevation canceled/failed: $($_.Exception.Message)"
        exit 1
    }
    # -Wait is unreliable with -Verb RunAs (returns at broker exit); poll for the
    # verdict line which the child writes BEFORE its cleanup phase.
    $deadline = (Get-Date).AddSeconds(300)
    $content = $null
    while ((Get-Date) -lt $deadline) {
        $content = Get-Content $resFile -Encoding UTF8 -Raw -ErrorAction SilentlyContinue
        if ($content -and $content -match 'RESULT:') { break }
        Start-Sleep -Milliseconds 600
    }
    if ($content -and $content -match 'RESULT:') {
        ($content -split "`r?`n") | ForEach-Object { Write-Host $_ }
        if ($content -match 'RESULT: PASS') { exit 0 } else { exit 1 }
    }
    Write-Host "[verify] no verdict from elevated instance (UAC denied / crash). Dir: $logDir"
    exit 1
}

# ============================ elevated ============================
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
Remove-Item $resFile -ErrorAction SilentlyContinue
$script:firstWrite = $true
function Report($msg) {
    Write-Host $msg
    if ($script:firstWrite) {
        Set-Content -Path $resFile -Value $msg -Encoding UTF8
        $script:firstWrite = $false
    } else {
        Add-Content -Path $resFile -Value $msg -Encoding UTF8
    }
}

$root  = Split-Path $PSScriptRoot -Parent
$exe   = Join-Path $root 'target\release\ipv8-node.exe'
$zexe  = Join-Path $root 'target\release\ipv8-zoneserver.exe'
$dll   = Join-Path $root 'deploy\client\wintun.dll'
$addrA = '0000fb140000000a0001000001000000'   # ASN 64500 / host 10 / dev 1 / sec 1
$addrB = '0000fb140000000b0001000001000000'   # ASN 64500 / host 11 / dev 1 / sec 1
$dstViaA = '10.100.0.32'
$dstViaB = '10.100.0.33'

$la  = Join-Path $logDir 'a.log';  $lb  = Join-Path $logDir 'b.log'
$lae = Join-Path $logDir 'a.err';  $lbe = Join-Path $logDir 'b.err'

function Get-Stats($log) {
    $line = Select-String -Path $log -Encoding UTF8 `
        -Pattern '\[stats\] epoch=(\d+) sealed=(\d+) delivered=(\d+) dropped=(\d+) frags_sent=(\d+) frags_reassembled=(\d+)' |
        Select-Object -Last 1
    if (-not $line) { return [pscustomobject]@{ sealed = 0; delivered = 0; dropped = 0; frags_sent = 0; frags_reassembled = 0 } }
    $m = $line.Matches[0]
    [pscustomobject]@{
        sealed    = [int]$m.Groups[2].Value
        delivered = [int]$m.Groups[3].Value
        dropped   = [int]$m.Groups[4].Value
        frags_sent = [int]$m.Groups[5].Value
        frags_reassembled = [int]$m.Groups[6].Value
    }
}

function Wait-Established($log, $errLog, $proc, $name, $timeoutSec = 40) {
    $deadline = (Get-Date).AddSeconds($timeoutSec)
    while ((Get-Date) -lt $deadline) {
        if ($proc.HasExited) {
            $err = Get-Content $errLog -Raw -ErrorAction SilentlyContinue
            throw "node $name exited early (code $($proc.ExitCode)). stderr: $err"
        }
        if ((Get-Content $log -Encoding UTF8 -ErrorAction SilentlyContinue) -match 'Established') {
            Report "[verify] node $name Established"
            return
        }
        Start-Sleep -Milliseconds 400
    }
    throw "node $name not Established within ${timeoutSec}s; see $log / $errLog"
}

$pa = $null
$pb = $null
$pz = $null   # local zoneserver process (Zone mode)
$code = 1
try {
    if (-not (Test-Path $exe)) { throw "missing $exe - run: cargo build --release -p ipv8-wintun-node" }
    # Staleness guard: newest source file vs built exe.
    $newestSrc = Get-ChildItem -LiteralPath (Join-Path $root 'src') -Recurse -Include *.rs,Cargo.toml -File -ErrorAction SilentlyContinue |
                 Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($newestSrc -and $newestSrc.LastWriteTime -gt (Get-Item $exe).LastWriteTime) {
        Write-Host "[verify] WARNING: source newer than $exe (touched $($newestSrc.Name)) - run: cargo build --release -p ipv8-wintun-node -p ipv8-zoneserver"
    }
    if (-not (Test-Path (Join-Path (Split-Path $exe) 'wintun.dll'))) { Copy-Item $dll (Split-Path $exe) -Force }
    Remove-Item $la, $lb, $lae, $lbe -ErrorAction SilentlyContinue

    # Idempotent preamble: kill stale nodes + stale pinned routes.
    # wintun adapters are reused via Adapter::open, never deleted (Remove-NetAdapter
    # is not exported in Windows PowerShell 5.1; the adapter is harmless to leave).
    Get-Process ipv8-node -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    foreach ($d in @($dstViaA, $dstViaB)) {
        Get-NetRoute -DestinationPrefix "$d/32" -ErrorAction SilentlyContinue |
            Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
    }
    Start-Sleep -Milliseconds 300

    $argA = @('--self', $addrA, '--peer-addr', $addrB, '--peer-ip', '127.0.0.1',
              '--tun-ip', '10.100.0.1', '--tun-prefix', '10',
              '--udp-port', '45701', '--peer-port', '45702',
              '--adapter-name', 'IPv8Plus-A', '--initiate')
    $argB = @('--self', $addrB, '--peer-addr', $addrA, '--peer-ip', '127.0.0.1',
              '--tun-ip', '10.100.0.2', '--tun-prefix', '10',
              '--udp-port', '45702', '--peer-port', '45701',
              '--adapter-name', 'IPv8Plus-B')
    if ($Fragment) {
        # IPv8+ fragmentation field test: TUN interface MTU 4000 lets big ping
        # packets enter TUN whole; engine cap stays 1432 so the tunnel layer
        # splits them (IPv6-style) instead of Windows IP-fragmenting.
        $argA += @('--tun-mtu', '4000')
        $argB += @('--tun-mtu', '4000')
        Report "[verify] FRAGMENT mode: tun-mtu=4000 > engine mtu=1432"
    }
    if ($Fallback) {
        # v9 S11 field test: A's MAIN entry points at a dead UDP port; the
        # FallbackManager must time out (8s handshake), exhaust the retry
        # budget, cascade to the ALT entry (= B's real port), then establish.
        # B stays passive on its normal port and is also the alt for symmetry.
        $argA += @('--fallback', '--alt-ip', '127.0.0.1', '--alt-port', '45702')
        $argB += @('--fallback', '--alt-ip', '127.0.0.1', '--alt-port', '45701')
        $i = [Array]::IndexOf($argA, '--peer-port')
        if ($i -ge 0) { $argA[$i + 1] = '45799' }  # dead main entry for A
        Report "[verify] FALLBACK mode: A main=45799(dead) alt=45702(B) - expect cascade"
    }

    # Auth material:
    #  -Zone  -> local ipv8-zoneserver; nodes enroll over gRPC (production trust path)
    #  else   -> shared preloaded CA seed (verification-only convenience)
    # A/B always use distinct Ed private-key seeds.
    $pz = $null
    if ($Auth) {
        $edSeedA = 'A1' * 32
        $edSeedB = 'B0' * 32
        if ($Zone) {
            if (-not (Test-Path $zexe)) { throw "missing $zexe - run: cargo build --release -p ipv8-zoneserver" }
            $zl  = Join-Path $logDir 'zone.log'
            $zle = Join-Path $logDir 'zone.err'
            Remove-Item $zl, $zle -ErrorAction SilentlyContinue
            $zport = 7070
            Report "[verify] starting local ZoneServer on 127.0.0.1:$zport (fixed CA seed, deterministic)"
            $pz = Start-Process $zexe -ArgumentList @('--addr', "127.0.0.1:$zport", '--ca-seed', ('C4' * 32), '--jwt-seed', ('2A' * 32)) `
                  -PassThru -WindowStyle Hidden -RedirectStandardOutput $zl -RedirectStandardError $zle
            # wait until the gRPC port accepts (server prints 'listening on ...')
            $listening = $false
            $deadline = (Get-Date).AddSeconds(15)
            while ((Get-Date) -lt $deadline -and -not $listening) {
                if ($pz.HasExited) { throw "zoneserver exited early; see $zl / $zle" }
                $listening = (Get-Content $zl -Raw -ErrorAction SilentlyContinue) -match 'listening on'
                if (-not $listening) { Start-Sleep -Milliseconds 300 }
            }
            if (-not $listening) { throw "zoneserver not listening within 15s; see $zl" }
            Report "[verify] ZoneServer up; nodes will enroll for certs + trust anchor"
            # cert persistence: each node caches its issued cert; a restart must
            # reload it OFFLINE (verified below by killing the ZoneServer too).
            $script:certA = Join-Path $logDir 'a.cert'
            $script:certB = Join-Path $logDir 'b.cert'
            Remove-Item $script:certA, $script:certB -ErrorAction SilentlyContinue
            $argA += @('--auth', '--zone', "http://127.0.0.1:$zport", '--ed-seed', $edSeedA, '--cert-cache', $script:certA)
            $argB += @('--auth', '--zone', "http://127.0.0.1:$zport", '--ed-seed', $edSeedB, '--cert-cache', $script:certB)
            Report "[verify] AUTHENTICATED mode via ZoneServer enrollment (CA private key stays server-side)"
        } else {
            $caSeed = 'C4' * 32
            $argA += @('--auth', '--ca-seed', $caSeed, '--ed-seed', $edSeedA)
            $argB += @('--auth', '--ca-seed', $caSeed, '--ed-seed', $edSeedB)
            Report "[verify] AUTHENTICATED mode (preloaded shared CA seed, verification-only)"
        }
    }

    Report "[verify] starting node A (initiator) + node B (responder)..."
    $pa = Start-Process $exe -ArgumentList $argA -PassThru -WindowStyle Hidden `
          -RedirectStandardOutput $la -RedirectStandardError $lae
    $pb = Start-Process $exe -ArgumentList $argB -PassThru -WindowStyle Hidden `
          -RedirectStandardOutput $lb -RedirectStandardError $lbe

    $estTimeout = if ($Fallback) { 75 } else { 40 }
    Wait-Established $la $lae $pa 'A' $estTimeout
    Wait-Established $lb $lbe $pb 'B' $estTimeout

    # Pin one synthetic dst per adapter so traffic is forced INTO each TUN
    New-NetRoute -DestinationPrefix "$dstViaA/32" -InterfaceAlias 'IPv8Plus-A' -NextHop '0.0.0.0' | Out-Null
    New-NetRoute -DestinationPrefix "$dstViaB/32" -InterfaceAlias 'IPv8Plus-B' -NextHop '0.0.0.0' | Out-Null
    Start-Sleep -Seconds 1
    $baseA = Get-Stats $la
    $baseB = Get-Stats $lb

    Report "[verify] driving traffic: ping $dstViaA (into TUN-A), ping $dstViaB (into TUN-B)"
    $pingSize = if ($Fragment) { '3000' } else { '32' }
    $null = & ping -n 4 -w 800 -l $pingSize $dstViaA 2>&1
    $null = & ping -n 4 -w 800 -l $pingSize $dstViaB 2>&1
    Start-Sleep -Seconds 7   # >= 2 stats ticks

    $finA = Get-Stats $la
    $finB = Get-Stats $lb
    $dA_seal  = $finA.sealed    - $baseA.sealed
    $dA_deliv = $finA.delivered - $baseA.delivered
    $dB_seal  = $finB.sealed    - $baseB.sealed
    $dB_deliv = $finB.delivered - $baseB.delivered
    Report ("  node A: sealed +{0}  delivered +{1}  dropped {2}" -f $dA_seal, $dA_deliv, $finA.dropped)
    Report ("  node B: sealed +{0}  delivered +{1}  dropped {2}" -f $dB_seal, $dB_deliv, $finB.dropped)

    $growth = ($dA_seal -gt 0) -and ($dA_deliv -gt 0) -and ($dB_seal -gt 0) -and ($dB_deliv -gt 0)
    $clean  = ($finA.dropped -eq 0) -and ($finB.dropped -eq 0)

    # ---- Zone mode: cert persistence check --------------------------------
    # Kill BOTH nodes and the ZoneServer, restart the nodes with --cert-cache.
    # Success REQUIRES an offline cache hit: the zone URL is unreachable now,
    # so a MISS means the node dies trying to re-enroll. Then traffic must flow
    # again (fresh authenticated handshake from cached certs, both directions).
    if ($Zone) {
        Report "[verify] cert-cache restart: killing A + B + ZoneServer, restarting nodes offline"
        Stop-Process -Id $pa.Id -Force -ErrorAction SilentlyContinue
        Stop-Process -Id $pb.Id -Force -ErrorAction SilentlyContinue
        if ($pz) { Stop-Process -Id $pz.Id -Force -ErrorAction SilentlyContinue; $pz = $null }
        Start-Sleep -Seconds 2
        $la2 = Join-Path $logDir 'a2.log'; $lae2 = Join-Path $logDir 'a2.err'
        $lb2 = Join-Path $logDir 'b2.log'; $lbe2 = Join-Path $logDir 'b2.err'
        $pa = Start-Process $exe -ArgumentList $argA -PassThru -WindowStyle Hidden `
              -RedirectStandardOutput $la2 -RedirectStandardError $lae2
        $pb = Start-Process $exe -ArgumentList $argB -PassThru -WindowStyle Hidden `
              -RedirectStandardOutput $lb2 -RedirectStandardError $lbe2
        Wait-Established $la2 $lae2 $pa 'A-offline'
        Wait-Established $lb2 $lbe2 $pb 'B-offline'
        $la2txt = Get-Content $la2 -Raw -ErrorAction SilentlyContinue
        $lb2txt = Get-Content $lb2 -Raw -ErrorAction SilentlyContinue
        $cache_hit = ($la2txt -match '\[cert-cache\] HIT') -and ($lb2txt -match '\[cert-cache\] HIT')
        if ($cache_hit) { Report "[verify] cert-cache HIT on both nodes (ZoneServer down - reload was offline)" }
        else { Report "[verify] cert-cache HIT missing on restart logs" }
        $growth = $growth -and $cache_hit
        # second round of traffic through the reloaded identities
        $rbaseA = Get-Stats $la2
        $rbaseB = Get-Stats $lb2
        $null = & ping -n 4 -w 800 -l $pingSize $dstViaA 2>&1
        $null = & ping -n 4 -w 800 -l $pingSize $dstViaB 2>&1
        Start-Sleep -Seconds 7
        $rfinA = Get-Stats $la2
        $rfinB = Get-Stats $lb2
        $r_ok = (($rfinA.sealed - $rbaseA.sealed) -gt 0) -and (($rfinA.delivered - $rbaseA.delivered) -gt 0) -and
                (($rfinB.sealed - $rbaseB.sealed) -gt 0) -and (($rfinB.delivered - $rbaseB.delivered) -gt 0)
        Report ("  restart round: A sealed +{0} delivered +{1} | B sealed +{2} delivered +{3} | dropped {4}/{5}" -f `
            ($rfinA.sealed - $rbaseA.sealed), ($rfinA.delivered - $rbaseA.delivered),
            ($rfinB.sealed - $rbaseB.sealed), ($rfinB.delivered - $rbaseB.delivered),
            $rfinA.dropped, $rfinB.dropped)
        $growth = $growth -and $r_ok
        $clean = $clean -and (($rfinA.dropped -eq 0) -and ($rfinB.dropped -eq 0))
    }

    # Fragment mode: big ping packets must have been split by the IPv8+ layer
    # (engine cap 1432 < tun-mtu 4000). A's frags_sent counts A's outbound
    # splits; B's frags_reassembled proves the peer reassembled them.
    $dA_frag_sent = $finA.frags_sent - $baseA.frags_sent
    $dA_frag_asm  = $finA.frags_reassembled - $baseA.frags_reassembled
    $dB_frag_sent = $finB.frags_sent - $baseB.frags_sent
    $dB_frag_asm  = $finB.frags_reassembled - $baseB.frags_reassembled
    if ($Fragment) {
        Report ("  node A: frags_sent +{0} frags_reassembled +{1}" -f $dA_frag_sent, $dA_frag_asm)
        Report ("  node B: frags_sent +{0} frags_reassembled +{1}" -f $dB_frag_sent, $dB_frag_asm)
        $frag_ok = ($dA_frag_sent -gt 0) -and ($dA_frag_asm -gt 0) -and
                   ($dB_frag_sent -gt 0) -and ($dB_frag_asm -gt 0)
        $growth = $growth -and $frag_ok
    }
    if ($growth -and $clean) {
        Report "[verify] wintun + handshake + seal/open traffic traversed the tunnel in BOTH directions"
        Report "RESULT: PASS"
        $code = 0
    } elseif ($growth) {
        Report "[verify] counters grew but AEAD/replay drops observed (should be 0 on loopback)"
        Report "RESULT: FAIL"
        $code = 1
    } else {
        Report ("[verify] not all four counters grew (A sealed={0} deliv={1} | B sealed={2} deliv={3})" -f `
            $dA_seal, $dA_deliv, $dB_seal, $dB_deliv)
        Report "RESULT: FAIL"
        $code = 1
    }
}
catch {
    Report "[verify] ERROR: $($_.Exception.Message)"
    Report "RESULT: FAIL"
    $code = 1
}
finally {
    # Cleanup AFTER the verdict line is already on disk.
    if ($pa) { Stop-Process -Id $pa.Id -Force -ErrorAction SilentlyContinue }
    if ($pb) { Stop-Process -Id $pb.Id -Force -ErrorAction SilentlyContinue }
    if ($pz) { Stop-Process -Id $pz.Id -Force -ErrorAction SilentlyContinue }
    foreach ($d in @($dstViaA, $dstViaB)) {
        Get-NetRoute -DestinationPrefix "$d/32" -ErrorAction SilentlyContinue |
            Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
    }
    if (-not $Keep) {
        Add-Content -Path $resFile -Value "[verify] cleanup: processes stopped, routes removed (wintun adapters reused next run)" -Encoding UTF8
    } else {
        Add-Content -Path $resFile -Value "[verify] routes kept (-Keep)" -Encoding UTF8
    }
}
exit $code
