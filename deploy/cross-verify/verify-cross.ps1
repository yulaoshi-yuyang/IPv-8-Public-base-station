<#
  Cross-machine verification (roadmap gap: loopback short-circuits RTT):
    TWO physical hosts on a LAN, one wintun adapter each, REAL UDP between them.
    Because the peer tunnel IP is not local on this host, ping replies become
    genuine end-to-end evidence that loopback could never produce.

  Usage (LAN example: A=192.168.1.11, B=192.168.1.12):
    Host A (initiator):  powershell -File .\verify-cross.ps1 -Role A -PeerIp 192.168.1.12
    Host B (responder):  powershell -File .\verify-cross.ps1 -Role B -PeerIp 192.168.1.11
    Start B first (or simultaneously); A keeps retrying handshake within budget.

  CROSS-NAT topology (one host on global IPv6, the other deep inside a
  large intranet / CGNAT - the two are NOT on the same LAN):
    The intranet host cannot receive inbound, so it MUST be the initiator.
    The v6 host is the passive responder and learns the intranet host's REAL
    post-NAT entry from the first valid frame (--learn-peer). Requirement: the
    intranet host must have some IPv6 path (native v6 or NAT64) to reach the
    v6 host; pure-v4 <-> pure-v6 with no translation is unreachable at IP
    layer (use the ws-node/cloudflared relay for that case instead).
      Intranet host: -Role A -PeerIp <v6 host's global IPv6>
      v6 host:       -Role B -PeerIp <its own global IPv6, placeholder> -LearnPeer
    -LearnPeer forces -PeerIp to be IPv6 (pins the node's dual-stack :: bind;
    the actual peer entry is irrelevant there - it is learned from the wire).

  Modes (must be IDENTICAL on both hosts):
    (default)  authenticated handshake, shared preloaded CA seed - verification-only
    -NoTun     ZERO-DRIVER mode: no wintun.dll, no adapter, no admin. The node
               runs on a plain user token; synthetic echo packets (initiator
               injects every 5s, responder byte-echoes) drive the tunnel over
               REAL UDP instead of ping-into-TUN. Use when security software
               blocks virtual-adapter creation (wintun driver install denied).
               Evidence = ECHO_OK byte-exact verify + engine counters.
               Caveat: inbound UDP $UdpPort must still be allowed by the host
               firewall - run once elevated (auto-rule) or whitelist manually.
    -Zone      host A runs ipv8-zoneserver on 0.0.0.0:7070; BOTH nodes enroll over
               the network for certs + trust anchor (production trust path; the CA
               private key never leaves host A)
    -Fragment  tun-mtu 4000 > engine IPv8+ cap 1432 and ping -l 3000 drives real
               IPv8+ fragmentation across the wire

  Pass criteria (per host, engine counters - same authority as loopback suite):
    Established + sealed>0 + delivered>0 + dropped==0
    Ping replies (TTL=) are reported additionally as true cross-machine RTT.

  Files expected next to this script (peer pack): ipv8-node.exe, wintun.dll;
  -Zone on host A additionally needs ipv8-zoneserver.exe.

  Auto-elevates via UAC. Exit code 0 = PASS.
  NOTE: keep this file pure ASCII - Windows PowerShell 5.1 parses it as ANSI/GBK
  and non-ASCII bytes break statement structure.
#>
param(
    [Parameter(Mandatory = $true)][ValidateSet('A', 'B')][string]$Role,
    [Parameter(Mandatory = $true)][string]$PeerIp,
    [switch]$Zone,
    [switch]$Fragment,
    [switch]$Keep,
    [switch]$LearnPeer,
    [switch]$NoTun,
    [ValidateSet('A', 'B')][string]$ZoneHost = 'A',
    [int]$UdpPort = 45700,
    [int]$ZonePort = 7070
)

# -PeerIp accepts an IPv4 OR IPv6 literal (cross-NAT topology: responder side
# typically has a global v6; initiator may sit behind CGNAT with v6 only).
$ipObj = $null
if (-not [System.Net.IPAddress]::TryParse($PeerIp, [ref]$ipObj)) {
    Write-Host "[cross] -PeerIp is not a valid IPv4/IPv6 literal: $PeerIp"
    exit 1
}
$peerIsV6 = $ipObj.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6
$peerHost = if ($peerIsV6) { "[$PeerIp]" } else { $PeerIp }
# -LearnPeer must bind the DUAL-STACK (::) socket: the intranet peer's real
# exit address may be v4 (NAT44) or v6 (NAT64/6rd) - only learnable from the
# first frame. A v6 -PeerIp placeholder on that side forces the :: bind.
if ($LearnPeer -and -not $peerIsV6) {
    Write-Host "[cross] -LearnPeer requires -PeerIp to be an IPv6 literal (any, e.g. this host's own global v6 - it only pins the dual-stack bind; the real peer entry is learned from the first frame)."
    exit 1
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
          ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$logDir  = Join-Path $env:TEMP 'ipv8-cross'
$resFile = Join-Path $logDir 'result.txt'

if ((-not $isAdmin) -and (-not $NoTun)) {
    New-Item -ItemType Directory -Force -Path $logDir | Out-Null
    Remove-Item $resFile -ErrorAction SilentlyContinue
    Write-Host "[cross] not elevated - requesting UAC (click Yes)..."
    $childArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"",
                   '-Role', $Role, '-PeerIp', $PeerIp,
                   '-UdpPort', "$UdpPort", '-ZonePort', "$ZonePort")
    if ($Keep)      { $childArgs += '-Keep' }
    if ($Zone)      { $childArgs += @('-Zone', '-ZoneHost', $ZoneHost) }
    if ($Fragment)  { $childArgs += '-Fragment' }
    if ($LearnPeer) { $childArgs += '-LearnPeer' }
    if ($NoTun)     { $childArgs += '-NoTun' }
    try {
        $null = Start-Process powershell.exe -Verb RunAs -ArgumentList $childArgs -WindowStyle Hidden
    } catch {
        Write-Host "[cross] elevation canceled/failed: $($_.Exception.Message)"
        exit 1
    }
    # -Wait is unreliable with -Verb RunAs; poll the verdict the child writes
    # BEFORE cleanup (same pattern as verify-loopback.ps1).
    $deadline = (Get-Date).AddSeconds(300)
    $content = $null
    while ((Get-Date) -lt $deadline) {
        $content = Get-Content $resFile -Encoding UTF8 -Raw -ErrorAction SilentlyContinue
        if ($content -and $content -match 'RESULT:') { break }
        Start-Sleep -Milliseconds 600
    }
    if ($content -and $content -match 'RESULT:') {
        ($content -split "`r?`n") | ForEach-Object { Write-Host $_ }
        Remove-Item $resFile -Force -ErrorAction SilentlyContinue   # leave no temp behind
        if ($content -match 'RESULT: PASS') { exit 0 } else { exit 1 }
    }
    Write-Host "[cross] no verdict from elevated instance (UAC denied / crash). Dir: $logDir"
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

$exe   = Join-Path $PSScriptRoot 'ipv8-node.exe'
$zexe  = Join-Path $PSScriptRoot 'ipv8-zoneserver.exe'
$dll   = Join-Path $PSScriptRoot 'wintun.dll'

# Staleness guard: if this pack sits inside the repo and a newer build exists
# under target\release, warn that we are about to verify an OLD binary. On a
# peer machine (no repo) the pack itself is the source of truth.
$_repoRel = Join-Path (Split-Path $PSScriptRoot -Parent) 'target\release\ipv8-node.exe'
if ((Test-Path $_repoRel) -and (Test-Path $exe)) {
    if ((Get-Item $_repoRel).LastWriteTime -gt (Get-Item $exe).LastWriteTime) {
        Write-Host "[cross] WARNING: pack exe at $exe is OLDER than $_repoRel"
        Write-Host "[cross]          rebuild the pack: powershell -File scripts\make-peer-pack.ps1"
    }
}

# Identity plan (same ASN/64500 family as loopback; host octet = role)
$addrSelf = if ($Role -eq 'A') { 'fb140000000a00010000010000000000' } else { 'fb140000000b00010000010000000000' }
$addrPeer = if ($Role -eq 'A') { 'fb140000000b00010000010000000000' } else { 'fb140000000a00010000010000000000' }
$tunSelf  = if ($Role -eq 'A') { '100.64.0.1' } else { '100.64.0.2' }
$tunPeer  = if ($Role -eq 'A') { '100.64.0.2' } else { '100.64.0.1' }
$edSeed   = if ($Role -eq 'A') { 'A1' * 32 } else { 'B0' * 32 }

$log  = Join-Path $logDir 'node.log'
$lerr = Join-Path $logDir 'node.err'

function Get-Stats($file) {
    $line = Select-String -Path $file -Encoding UTF8 `
        -Pattern '\[stats\] epoch=(\d+) sealed=(\d+) delivered=(\d+) dropped=(\d+) frags_sent=(\d+) frags_reassembled=(\d+)' |
        Select-Object -Last 1
    if (-not $line) { return [pscustomobject]@{ sealed = 0; delivered = 0; dropped = 0; frags_sent = 0; frags_reassembled = 0; echo_ok = 0; echo_bad = 0 } }
    $m = $line.Matches[0]
    # echo_ok/echo_bad only exist on --no-tun builds' stats line; tolerate absence.
    $l2 = $line.Line
    $eok = 0; $ebad = 0
    if ($l2 -match 'echo_ok=(\d+)')  { $eok  = [int]$Matches[1] }
    if ($l2 -match 'echo_bad=(\d+)') { $ebad = [int]$Matches[1] }
    [pscustomobject]@{
        sealed            = [int]$m.Groups[2].Value
        delivered         = [int]$m.Groups[3].Value
        dropped           = [int]$m.Groups[4].Value
        frags_sent        = [int]$m.Groups[5].Value
        frags_reassembled = [int]$m.Groups[6].Value
        echo_ok           = $eok
        echo_bad          = $ebad
    }
}

$pn = $null   # node process
$pz = $null   # zoneserver (host A only)
$code = 1
try {
    if (-not (Test-Path $exe)) { throw "missing $exe - copy the peer pack (ipv8-node.exe + wintun.dll + this script) here" }
    if (-not $NoTun -and -not (Test-Path $dll)) { throw "missing $dll next to ipv8-node.exe (or run with -NoTun)" }
    Remove-Item $log, $lerr -ErrorAction SilentlyContinue

    # Preamble: stale instances + firewall (inbound UDP is the cross-machine gate).
    Get-Process ipv8-node -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Get-Process ipv8-zoneserver -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 300
    $family = if ($peerIsV6) { 'IPv6' } else { 'IPv4' }
    $ports = @($UdpPort)
    if ($Zone -and $Role -eq $ZoneHost) {
        New-NetFirewallRule -Name "ipv8-cross-zone-$ZonePort" -DisplayName "IPv8+ cross verify zone TCP $ZonePort" `
            -Direction Inbound -Action Allow -Protocol TCP -LocalPort $ZonePort -Profile Any `
            -ErrorAction SilentlyContinue | Out-Null
    }
    foreach ($p in $ports) {
        New-NetFirewallRule -Name "ipv8-cross-udp-$p-$family" -DisplayName "IPv8+ cross verify UDP $p ($family)" `
            -Direction Inbound -Action Allow -Protocol UDP -LocalPort $p -Profile Any `
            -ErrorAction SilentlyContinue | Out-Null
    }
    Report "[cross] role=$Role  self-tun=$tunSelf  peer=$PeerIp (tun $tunPeer)  udp=$UdpPort"

    # Port pre-flight: the stale-process cleanup above cannot kill elevated
    # (RunAs) leftovers when this run is non-elevated - the node then dies with
    # a bare "10048 AddrInUse" and no clue who holds the port (hit 2x on
    # 2026-09-09). Detect the owner HERE and name it + the exact fix. Degrades
    # silently on hosts where the cmdlet is unavailable (falls back to 10048).
    $portGuard = $true
    try { $null = Get-Command Get-NetUDPEndpoint -ErrorAction Stop } catch { $portGuard = $false }
    if ($portGuard) {
        foreach ($spec in @(
            @{ Port = $UdpPort;  Proto = 'UDP'; Conn = { Get-NetUDPEndpoint -LocalPort $UdpPort -ErrorAction SilentlyContinue } },
            @{ Port = $ZonePort; Proto = 'TCP'; Conn = { Get-NetTCPConnection -LocalPort $ZonePort -State Listen -ErrorAction SilentlyContinue } }
        )) {
            if ($spec.Proto -eq 'TCP' -and -not ($Zone -and $Role -eq $ZoneHost)) { continue }
            foreach ($ep in @(& $spec.Conn)) {
                $op = $ep.OwningProcess
                if (-not $op) { continue }
                $oname = (Get-Process -Id $op -ErrorAction SilentlyContinue).ProcessName
                if (-not $oname) { $oname = 'unknown' }
                if ($oname -like 'ipv8*') {
                    throw "$($spec.Proto) port $($spec.Port) is still held by a leftover $oname (PID $op). That process was started elevated, so this run cannot stop it. Fix: run this same command ONCE from an 'Run as administrator' PowerShell (auto-cleanup), or kill it directly: taskkill /PID $op /F"
                }
                throw "$($spec.Proto) port $($spec.Port) is in use by '$oname' (PID $op), which is not an ipv8 process. Close that app, or re-run with a different -UdpPort (currently $UdpPort)."
            }
        }
        Report "[cross] port pre-flight OK: UDP $UdpPort free"
    }

    # Pre-flight (initiator only): do we even have a route to the peer family?
    # Catches "no IPv6 egress" (WSAENETUNREACH/10051) before wasting a run.
    # NOTE: must NOT grep ping stdout for 'TTL=' - IPv6 echo replies carry no
    # TTL field at all, so the old check could never pass on v6 (false FAIL
    # observed 2026-09-09 with working 35ms v6 connectivity). Test-Connection
    # returns objects: locale/codepage proof; StatusCode 0 = real reply.
    if ($Role -eq 'A') {
        $replies = @(Test-Connection -ComputerName $PeerIp -Count 2 -ErrorAction SilentlyContinue |
                     Where-Object { $_.StatusCode -eq 0 })
        $pr = $replies.Count
        if ($pr -eq 0) {
            # fallback: native ping exit code (0 = at least one reply)
            $null = & ping -6 -n 2 -w 1500 $PeerIp
            if ($LASTEXITCODE -eq 0) { $pr = 1 }
        }
        if ($pr -eq 0) {
            $why = if ($peerIsV6) { 'this host has no working IPv6 route to that address (run: ping -6 ' + $PeerIp + ' to confirm)' } else { 'that IPv4 is unreachable from this host' }
            throw "pre-flight failed: cannot reach peer $PeerIp - $why. Fix connectivity first (enable IPv6 on this machine, or use a reachable address family)."
        }
        Report "[cross] pre-flight OK: peer reachable ($pr/2 ICMP replies)"
    }

    $argList = @('--self', $addrSelf, '--peer-addr', $addrPeer, '--peer-ip', $PeerIp,
                 '--tun-ip', $tunSelf, '--udp-port', "$UdpPort", '--peer-port', "$UdpPort",
                 '--adapter-name', 'IPv8Plus',
                 # RIO Auto 在部分 Win11 24H2/25H2 上 create() 静默挂起（无任何输出），
                 # 跨机验证不依赖该性能线，强制标准 UDP 数据面保功能。
                 '--rio', 'off')
    if ($Role -eq 'A') { $argList += '--initiate' }
    # LearnPeer rides on the PASSIVE responder: it learns the intranet peer's
    # real post-NAT entry from the first valid frame and replies there.
    # The initiator side already knows the peer (global v6) - no learning needed.
    if ($LearnPeer) { $argList += '--learn-peer'; Report "[cross] LEARN-PEER mode: real peer entry learned from first frame (NAT/CGNAT friendly)" }

    if ($Zone) {
        if ($Role -eq $ZoneHost) {
            if (-not (Test-Path $zexe)) { throw "missing $zexe (needed on host $ZoneHost for -Zone)" }
            $zl = Join-Path $logDir 'zone.log'; $zle = Join-Path $logDir 'zone.err'
            Remove-Item $zl, $zle -ErrorAction SilentlyContinue
            Report "[cross] host ${ZoneHost}: starting ZoneServer on 0.0.0.0:$ZonePort (CA key stays here)"
            $pz = Start-Process $zexe -ArgumentList @('--addr', "0.0.0.0:$ZonePort", '--ca-seed', ('C4' * 32), '--jwt-seed', ('2A' * 32)) `
                  -PassThru -WindowStyle Hidden -RedirectStandardOutput $zl -RedirectStandardError $zle
            $ok = $false; $deadline = (Get-Date).AddSeconds(15)
            while ((Get-Date) -lt $deadline -and -not $ok) {
                if ($pz.HasExited) { throw "zoneserver exited early; see $zl / $zle" }
                $ok = (Get-Content $zl -Raw -ErrorAction SilentlyContinue) -match 'listening on'
                if (-not $ok) { Start-Sleep -Milliseconds 300 }
            }
            if (-not $ok) { throw "zoneserver not listening within 15s; see $zl" }
            $argList += @('--auth', '--zone', "http://127.0.0.1:$ZonePort")
        } else {
            Report "[cross] host ${Role}: enrolling against http://${peerHost}:$ZonePort"
            $argList += @('--auth', '--zone', "http://${peerHost}:$ZonePort")
        }
        $argList += @('--ed-seed', $edSeed, '--cert-cache', (Join-Path $logDir 'node.cert'))
        Remove-Item (Join-Path $logDir 'node.cert') -ErrorAction SilentlyContinue
        Report "[cross] AUTHENTICATED via ZoneServer enrollment (production trust path)"
    } else {
        $argList += @('--auth', '--ca-seed', ('C4' * 32), '--ed-seed', $edSeed)
        Report "[cross] AUTHENTICATED (preloaded shared CA seed, verification-only)"
    }
    if ($Fragment) { $argList += @('--tun-mtu', '4000'); Report "[cross] FRAGMENT mode: tun-mtu=4000 > engine mtu=1432" }

    if ($NoTun) {
        # Zero-driver path: no wintun.dll, no adapter. The node itself needs NO
        # admin; only an inbound firewall allowance does. If we're not elevated,
        # the New-NetFirewallRule above silently no-ops -> tell the user the
        # one-liner escape hatch instead of failing mysteriously.
        $ntSize = if ($Fragment) { '3000' } else { '64' }
        $argList += @('--no-tun', '--nt-size', $ntSize)
        Report "[cross] NO-TUN mode: zero-driver (synthetic $ntSize-byte echo over real UDP), no admin required for the node"
        if (-not $isAdmin) {
            Report "[cross] NOTE not-elevated: if no ECHO_OK shows within ~40s, inbound UDP $UdpPort is likely blocked. Fix = run this same command once in an 'Run as administrator' PowerShell (auto-adds the rule), or allow ipv8-node.exe / UDP $UdpPort inbound in Windows Firewall + your security suite."
        }
    }

    Report "[cross] starting node ($Role)..."
    $pn = Start-Process $exe -ArgumentList $argList -PassThru -WindowStyle Hidden `
          -RedirectStandardOutput $log -RedirectStandardError $lerr

    # Wait for Established (Zone enrollment rides the LAN: give it slack).
    $timeout = if ($Zone) { 120 } else { 60 }
    $deadline = (Get-Date).AddSeconds($timeout)
    $est = $false
    while ((Get-Date) -lt $deadline -and -not $est) {
        if ($pn.HasExited) {
            # node writes UTF-8 directly; PS 5.1 default (ANSI/GBK) reading is
            # exactly what mojibakes the Chinese fatal-error line in terminals.
            $errTxt = Get-Content $lerr -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
            throw "node exited early. stderr: $errTxt"
        }
        $est = (Get-Content $log -Encoding UTF8 -ErrorAction SilentlyContinue) -match 'Established'
        if (-not $est) { Start-Sleep -Milliseconds 400 }
    }
    if (-not $est) { throw "node not Established within ${timeout}s; check the peer host runs the same mode, and LAN UDP $UdpPort is open. See $log / $lerr" }
    Report "[cross] node $Role Established (authenticated handshake over real LAN UDP)"

    $base = Get-Stats $log

    $replies = 0; $rtt = $null
    if ($NoTun) {
        # No TUN to ping into: initiator self-verifies byte-exact echo, responder's
        # counters move as it receives/echoes. Poll until evidence or ~25s (inject/5s).
        Report "[cross] NO-TUN traffic: waiting for synthetic echo across real UDP"
        $tdeadline = (Get-Date).AddSeconds(25)
        while ((Get-Date) -lt $tdeadline) {
            Start-Sleep -Seconds 3
            if ($pn.HasExited) {
                $ex = Get-Content $lerr -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
                throw "node exited during no-tun traffic. stderr: $ex"
            }
            $cur = Get-Stats $log
            if ($Role -eq 'A') { if (($cur.echo_ok - $base.echo_ok) -gt 0) { break } }
            else { if ((($cur.sealed - $base.sealed) -gt 0) -and (($cur.delivered - $base.delivered) -gt 0)) { break } }
        }
        Start-Sleep -Seconds 3   # >= 2 stats ticks after trigger
    } else {
        # Both hosts ping the PEER tunnel IP: requests go out through our engine,
        # replies come back through theirs -> TTL= lines are true cross-machine RTT.
        $size = if ($Fragment) { '3000' } else { '32' }
        Report "[cross] driving traffic: ping $tunPeer -n 4 -l $size"
        $pingOut = & ping -n 4 -w 1000 -l $size $tunPeer
        $replies = @($pingOut | Select-String -Pattern 'TTL=').Count
        $rtt = ($pingOut | Select-String -Pattern '(\d+)ms' | Select-Object -First 1)
        Start-Sleep -Seconds 5   # >= 2 stats ticks
    }

    $fin = Get-Stats $log
    $ds = $fin.sealed - $base.sealed
    $dd = $fin.delivered - $base.delivered
    Report ("  counters: sealed +{0}  delivered +{1}  dropped {2}" -f $ds, $dd, $fin.dropped)
    if ($rtt) { Report ("  cross-machine RTT evidence: replies $replies/4, e.g. {0}" -f $rtt.Matches[0].Value) }
    elseif (-not $NoTun) { Report "  cross-machine RTT evidence: replies $replies/4 (counters remain the authority)" }

    $okCounters = ($ds -gt 0) -and ($dd -gt 0) -and ($fin.dropped -eq 0)
    if ($NoTun) {
        $dok = $fin.echo_ok - $base.echo_ok
        $dbad = $fin.echo_bad - $base.echo_bad
        if ($Role -eq 'A') {
            Report ("  no-tun echo: ECHO_OK +{0}  ECHO_BAD +{1}" -f $dok, $dbad)
            $okCounters = $okCounters -and ($dok -gt 0) -and ($dbad -eq 0)
        } else {
            Report ("  no-tun responder: delivered +{0}  sealed +{1} (echoed initiator packets back)" -f $dd, $ds)
        }
    }
    if ($Fragment) {
        $fs  = $fin.frags_sent - $base.frags_sent
        $fa  = $fin.frags_reassembled - $base.frags_reassembled
        Report ("  fragmentation: frags_sent +{0}  frags_reassembled +{1}" -f $fs, $fa)
        $okCounters = $okCounters -and ($fs -gt 0) -and ($fa -gt 0)
    }
    if ($okCounters) {
        Report "[cross] tunnel carried real cross-machine traffic in BOTH directions"
        Report "RESULT: PASS"
        $code = 0
    } else {
        Report "[cross] counter check failed (sealed/delivered growth or dropped!=0)"
        Report "RESULT: FAIL"
        $code = 1
    }
}
catch {
    Report "[cross] ERROR: $($_.Exception.Message)"
    Report "RESULT: FAIL"
    $code = 1
}
finally {
    if ($pn) { Stop-Process -Id $pn.Id -Force -ErrorAction SilentlyContinue }
    if ($pz) { Stop-Process -Id $pz.Id -Force -ErrorAction SilentlyContinue }
    if (-not $Keep) {
        # Self-cleaning: fold the full node/zone logs into result.txt (the ONE
        # file the non-elevated parent reads), then wipe every other temp
        # artifact (node.log/err, node.cert, zone.log/err). Nothing accumulates
        # in %TEMP% across runs; -Keep opts out for debugging.
        foreach ($lf in @($log, $lerr, (Join-Path $logDir 'zone.log'), (Join-Path $logDir 'zone.err'))) {
            if (Test-Path $lf) {
                $t = Get-Content $lf -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
                if ($t) {
                    Add-Content -Path $resFile -Value "----- $(Split-Path $lf -Leaf) -----" -Encoding UTF8
                    Add-Content -Path $resFile -Value $t -Encoding UTF8
                }
            }
        }
        Add-Content -Path $resFile -Value "[cross] cleanup: processes stopped, temp files removed (wintun adapter + firewall rule kept for next run)" -Encoding UTF8
        Get-ChildItem -LiteralPath $logDir -File -Exclude 'result.txt' -ErrorAction SilentlyContinue |
            Remove-Item -Force -ErrorAction SilentlyContinue
    } else {
        Add-Content -Path $resFile -Value "[cross] -Keep: node left running, logs kept in $logDir" -Encoding UTF8
    }
}
exit $code
