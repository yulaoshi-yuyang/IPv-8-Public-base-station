# IPv8+ Address Allocation Manager
# Manages IPv8 address pool, assigns addresses to connecting clients

$allocations = @{}
$nextClient = 2  # Start from 2 (1 = server)
$lock = [System.Threading.Mutex]::new($false, "IPv8AllocLock")

# ---------- 持久化（门户重启不丢分配记录） ----------
$allocStoreFile = Join-Path $PSScriptRoot "ipv8-allocations.json"

function Save-Allocations {
    $lock.WaitOne() | Out-Null
    try {
        # 必须把字典键(client_num)一并存档：只存 Values 的话恢复时无键可用，
        # 所有记录会挤到 key 0 互相覆盖
        $records = @()
        foreach ($e in $allocations.GetEnumerator()) {
            $rec = $e.Value.Clone()
            $rec.client_num = $e.Key
            $records += $rec
        }
        $snap = @{ next_client = $nextClient; records = $records }
        $json = $snap | ConvertTo-Json -Depth 6 -Compress
        # 原子写：先写临时文件再替换，防写一半崩溃损坏存档
        $tmp = "$allocStoreFile.tmp"
        [System.IO.File]::WriteAllText($tmp, $json, [System.Text.Encoding]::UTF8)
        Move-Item $tmp $allocStoreFile -Force
    } catch {
        Write-Host "  [dhcp] save allocations failed: $_" -ForegroundColor Yellow
    } finally {
        $lock.ReleaseMutex()
    }
}

function Load-Allocations {
    if (-not (Test-Path $allocStoreFile)) { return }
    try {
        $snap = Get-Content $allocStoreFile -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($r in @($snap.records)) {
            if (-not $r.client_ip) { continue }
            if (-not $r.client_num) { continue }
            $rec = @{
                ipv8_address   = $r.ipv8_address
                ipv8_canonical = $r.ipv8_canonical
                tun_ip         = $r.tun_ip
                client_ip      = $r.client_ip
                client_name    = $r.client_name
                fingerprint    = $r.fingerprint
                assigned_at    = $r.assigned_at
                last_seen      = $r.last_seen
                status         = "$(if ($r.status -eq 'active') { 'stale' } else { $r.status })"
                registered     = [bool]$r.registered
                visa_exists    = [bool]$r.visa_exists
                ca_exists      = [bool]$r.ca_exists
            }
            if (-not $rec.assigned_at) { $rec.assigned_at = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss") }
            if (-not $rec.last_seen)   { $rec.last_seen   = $rec.assigned_at }
            $allocations[[int]$r.client_num] = $rec
        }
        if ($snap.next_client -gt $script:nextClient) { $script:nextClient = [int]$snap.next_client }
        Write-Host "  [dhcp] restored $(@($allocations.Keys).Count) allocations from disk" -ForegroundColor Green
    } catch {
        Write-Host "  [dhcp] load allocations failed (starting fresh): $_" -ForegroundColor Yellow
    }
}

Load-Allocations

function Get-ServerIPv6 {
    try {
        $addrs = Get-NetIPAddress -AddressFamily IPv6 -ErrorAction Stop |
            Where-Object { $_.IPAddress -notlike "fe80::*" -and $_.IPAddress -notlike "::1" -and $_.PrefixOrigin -eq "RouterAdvertisement" }
        if ($addrs) { return ($addrs | Select-Object -First 1).IPAddress }
    } catch {}
    return $null
}

function Allocate-IPv8Address {
    param([string]$clientIp, [string]$clientName = "")

    $lock.WaitOne() | Out-Null
    try {
        # Check if already allocated
        $existing = $allocations.Values | Where-Object { $_.client_ip -eq $clientIp }
        if ($existing) {
            return $existing
        }

        # Generate unique address based on client IP hash
        # ASN = 0xfb14 (fixed protocol prefix)
        # HostID = hash of client IP → unique per machine
        # DeviceID = sequential counter
        # CapTag = 0x0001 (standard)
        # SecLevel = 1
        # 必须用 $script: 前缀：函数内裸变量赋值（含 ++）只改函数局部副本，
        # 会导致所有客户端拿到相同的 DeviceID/tun_ip 并互相覆盖记录
        $clientNum = $script:nextClient
        $script:nextClient++

        # Derive unique HostID from client IP (deterministic, unique)
        $hashBytes = [System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($clientIp))
        $hostId = [BitConverter]::ToUInt32($hashBytes, 0)  # First 4 bytes as HostID

        # Construct IPv8 address in colon format: fb14:0000:HOSTID:DEVID:0001:0001:0000
        # Wire format: ASN(4) HostID(4) DeviceID(2) CapTag(2) SecLevel(1) Reserved(3)
        $asnBytes = [BitConverter]::GetBytes([uint32]0x0000fb14)
        $hostBytes = [BitConverter]::GetBytes($hostId)
        $devBytes = [BitConverter]::GetBytes([uint16]$clientNum)
        $capBytes = [BitConverter]::GetBytes([uint16]0x0001)
        $secByte = [byte]1

        # Build 16-byte wire format (big-endian)
        $wire = [byte[]]::new(16)
        $wire[0] = 0x00; $wire[1] = 0x00; $wire[2] = 0xfb; $wire[3] = 0x14  # ASN
        $wire[4] = $hashBytes[0]; $wire[5] = $hashBytes[1]; $wire[6] = $hashBytes[2]; $wire[7] = $hashBytes[3]  # HostID
        # DeviceID(2B)：低字节 + 高字节（clientNum > 255 时 [byte] 直接转换会抛异常）
        $wire[8] = [byte](($clientNum -shr 8) -band 0xFF); $wire[9] = [byte]($clientNum -band 0xFF)
        $wire[10] = 0x00; $wire[11] = 0x01  # CapTag
        $wire[12] = $secByte  # SecLevel
        $wire[13] = 0; $wire[14] = 0; $wire[15] = 0  # Reserved

        # Convert to colon format: 8 groups of 4 hex
        $groups = @()
        for ($i = 0; $i -lt 16; $i += 2) {
            $groups += ("{0:x2}{1:x2}" -f $wire[$i], $wire[$i+1])
        }
        $ipv8Display = $groups -join ":"

        # Canonical 32-hex string (for protocol use)
        $canonical = ($wire | ForEach-Object { "{0:x2}" -f $_ }) -join ""

        $record = @{
            ipv8_address = $ipv8Display
            ipv8_canonical = $canonical
            tun_ip = "100.64.0.$(if (($clientNum -band 0xFF) -in 0,255) { 254 } else { $clientNum -band 0xFF })"
            client_ip = $clientIp
            client_name = if ($clientName) { $clientName } else { "client-$clientNum" }
            assigned_at = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            last_seen = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            status = "active"
            registered = $false
        }

        $allocations[$clientNum] = $record
        Save-Allocations   # Mutex 同线程可重入，嵌套取锁安全
        return $record
    }
    finally {
        $lock.ReleaseMutex()
    }
}

function Get-AllAllocations {
    $lock.WaitOne() | Out-Null
    try {
        return $allocations.Values | Sort-Object { $_.assigned_at }
    }
    finally {
        $lock.ReleaseMutex()
    }
}

function Register-Client {
    param(
        [string]$clientIp,
        [string]$ipv8Addr = "",
        [string]$hostname = "",
        [string]$fingerprint = "",
        [bool]$visaExists = $false,
        [bool]$caExists = $false
    )

    $lock.WaitOne() | Out-Null
    try {
        # Check if already registered by client_ip
        $existing = $allocations.Values | Where-Object { $_.client_ip -eq $clientIp }
        if ($existing) {
            # Update existing record
            $existing.last_seen = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            $existing.status = "active"
            if ($ipv8Addr) { $existing.ipv8_address = $ipv8Addr }
            if ($hostname) { $existing.client_name = $hostname }
            if ($fingerprint) { $existing.fingerprint = $fingerprint }
            $existing.visa_exists = $visaExists
            $existing.ca_exists = $caExists
            $existing.registered = $true
            return $existing
        }

        # New registration
        # 必须用 $script: 前缀：函数内裸变量赋值（含 ++）只改函数局部副本，
        # 会导致所有客户端拿到相同的 DeviceID/tun_ip 并互相覆盖记录
        $clientNum = $script:nextClient
        $script:nextClient++

        # Derive HostID from client IP hash
        $hashBytes = [System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($clientIp))
        $hostId = [BitConverter]::ToUInt32($hashBytes, 0)

        # Build 16-byte wire format
        $wire = [byte[]]::new(16)
        $wire[0] = 0x00; $wire[1] = 0x00; $wire[2] = 0xfb; $wire[3] = 0x14
        $wire[4] = $hashBytes[0]; $wire[5] = $hashBytes[1]; $wire[6] = $hashBytes[2]; $wire[7] = $hashBytes[3]
        # DeviceID(2B)：低字节 + 高字节（与 Allocate-IPv8Address 保持一致）
        $wire[8] = [byte](($clientNum -shr 8) -band 0xFF); $wire[9] = [byte]($clientNum -band 0xFF)
        $wire[10] = 0x00; $wire[11] = 0x01
        $wire[12] = 1; $wire[13] = 0; $wire[14] = 0; $wire[15] = 0

        $groups = @()
        for ($i = 0; $i -lt 16; $i += 2) {
            $groups += ("{0:x2}{1:x2}" -f $wire[$i], $wire[$i+1])
        }
        $ipv8Display = $groups -join ":"
        $canonical = ($wire | ForEach-Object { "{0:x2}" -f $_ }) -join ""

        # Use provided IPv8 address if given, otherwise auto-generated
        $finalAddr = if ($ipv8Addr) { $ipv8Addr } else { $ipv8Display }
        $finalName = if ($hostname) { $hostname } else { "client-$clientNum" }

        $record = @{
            ipv8_address = $finalAddr
            ipv8_canonical = $canonical
            tun_ip = "100.64.0.$(if (($clientNum -band 0xFF) -in 0,255) { 254 } else { $clientNum -band 0xFF })"
            client_ip = $clientIp
            client_name = $finalName
            fingerprint = $fingerprint
            assigned_at = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            last_seen = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            status = "active"
            registered = $true
            visa_exists = $visaExists
            ca_exists = $caExists
        }

        $allocations[$clientNum] = $record
        Save-Allocations   # Mutex 同线程可重入，嵌套取锁安全
        return $record
    }
    finally {
        $lock.ReleaseMutex()
    }
}

function Update-Heartbeat {
    param([string]$clientIp)

    $lock.WaitOne() | Out-Null
    try {
        $existing = $allocations.Values | Where-Object { $_.client_ip -eq $clientIp }
        if ($existing) {
            $existing.last_seen = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            $existing.status = "active"
            return $true
        }
        return $false
    }
    finally {
        $lock.ReleaseMutex()
    }
}

function Cleanup-StaleClients {
    param([int]$timeoutSeconds = 300)

    $lock.WaitOne() | Out-Null
    try {
        $now = Get-Date
        foreach ($a in $allocations.Values) {
            if ($a.status -eq "active" -and $a.last_seen) {
                $lastSeen = [DateTime]::Parse($a.last_seen)
                $elapsed = ($now - $lastSeen).TotalSeconds
                if ($elapsed -gt $timeoutSeconds) {
                    $a.status = "stale"
                }
            }
        }
    }
    finally {
        $lock.ReleaseMutex()
    }
}

function Probe-ClientAlive {
    param([string]$clientIp, [int]$port = 9100, [int]$timeoutMs = 2000)

    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $result = $tcp.BeginConnect($clientIp, $port, $null, $null)
        $success = $result.AsyncWaitHandle.WaitOne($timeoutMs, $false)
        if ($success -and $tcp.Connected) {
            $tcp.Close()
            return $true
        }
        $tcp.Close()
        return $false
    } catch {
        return $false
    }
}

function Release-IPv8Address {
    param([string]$clientIp)
    
    $lock.WaitOne() | Out-Null
    try {
        $existing = $allocations.Values | Where-Object { $_.client_ip -eq $clientIp }
        if ($existing) {
            $existing.status = "released"
            $existing.released_at = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            Save-Allocations
        }
    }
    finally {
        $lock.ReleaseMutex()
    }
}

function Get-ClientConfig {
    param([object]$alloc)
    
    $serverIPv6 = Get-ServerIPv6
    
    # Generate client config that auto-connects to this server
    $config = @"
# IPv8+ Client Auto-Config
# Auto-generated by IPv8+ Portal
# Do not edit - this file is regenerated on each connection

server_ipv8 = $($alloc.ipv8_address -replace ':','')
server_ipv6 = $serverIPv6
server_domain = ipv8.yulaoshi.xyz
server_udp_port = 45700

client_ipv8 = $($alloc.ipv8_address)
client_tun_ip = $($alloc.tun_ip)
client_tun_ipv6 = fd14::$($($alloc.tun_ip -split '\.')[-1])
client_tun_prefix = 10

adapter_name = IPv8Plus
mtu = 1432

# GeoIP info
country = China
province = Jiangxi
city = Jiujiang
isp = China Mobile
asn = AS9808
"@
    return $config
}

function Build-ClientLauncher {
    param([object]$alloc)
    
    $serverIPv6 = Get-ServerIPv6
    if (-not $serverIPv6) { $serverIPv6 = "ipv8.yulaoshi.xyz" }
    
    $selfHex = ($alloc.ipv8_address -replace ':','').PadRight(32, '0').Substring(0, 32)
    
    # Server address is fb14:...000a... (server = node A)
    $peerHex = "0000fb140000000a0001000001000000"
    
    # TUN IPv6 (ULA fd14::/64) 与 tun_ip 末位一一对应，老 allocation 文件
    # 没有 tun_ipv6 字段也能工作：tun_ip 始终存在。例：100.64.0.12 -> fd14::12
    $tunIpv6 = 'fd14::' + (($alloc.tun_ip -split '\.')[-1])
    
    $psScript = @"
# IPv8+ Auto-Connect Client
# Generated by IPv8+ Portal - yulaoshi.xyz
# Just run this script as Administrator - it handles everything else.

`$exe = Join-Path `$PSScriptRoot 'ipv8-node.exe'
`$dll = Join-Path `$PSScriptRoot 'wintun.dll'

if (-not (Test-Path `$exe)) {
    Write-Host "ERROR: ipv8-node.exe not found. Download it from https://ipv8.yulaoshi.xyz" -ForegroundColor Red
    Read-Host "Press Enter to close"
    exit 1
}

# Auto-elevate
`$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not `$isAdmin) {
    Write-Host "Requesting admin privileges..." -ForegroundColor Yellow
    Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"`$PSCommandPath`"" -Wait
    exit
}

Write-Host "=== IPv8+ Client Starting ===" -ForegroundColor Cyan
Write-Host "Server: $serverIPv6 (ipv8.yulaoshi.xyz)" -ForegroundColor Green
Write-Host "Your IPv8: $($alloc.ipv8_compact)" -ForegroundColor Green
Write-Host "Your TUN IP: $($alloc.tun_ip)" -ForegroundColor Green
Write-Host "Your TUN IPv6: $tunIpv6" -ForegroundColor Green
Write-Host ""

# Copy wintun.dll if missing
if (-not (Test-Path `$dll) -and (Test-Path (Join-Path `$PSScriptRoot '..\wintun.dll'))) {
    Copy-Item (Join-Path `$PSScriptRoot '..\wintun.dll') `$dll -Force
}

# Firewall rule
New-NetFirewallRule -Name "IPv8Plus-Client" -DisplayName "IPv8+ Client UDP 45700" `
    -Direction Inbound -Action Allow -Protocol UDP -LocalPort 45700 -Profile Any `
    -ErrorAction SilentlyContinue | Out-Null

# Start ipv8-node with auto-config
`$args = @(
    '--self', '$selfHex',
    '--peer-addr', '$peerHex',
    '--peer-ip', '$serverIPv6',
    '--peer-port', '45700',
    '--udp-port', '45700',
    '--tun-ip', '$($alloc.tun_ip)',
    '--tun-ipv6', '$tunIpv6',
    '--tun-prefix', '10',
    '--adapter-name', 'IPv8Plus',
    '--initiate',
    '--auth',
    '--ca-seed', 'C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4'
)

Write-Host "Connecting to server..." -ForegroundColor Yellow
& `$exe @args
"@
    return $psScript
}
