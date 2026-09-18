# ============================================================
# IPv8+ Portal — 门户网站服务
# HTTP + DNS + DHCP 三合一，前端资源来自 ui\ 目录（模板化渲染）
#
# 直接运行：  .\ipv8-portal.ps1
# 后台运行：  .\start-website.ps1   结束：.\stop-website.ps1
# ============================================================

param(
    [int]$HttpPort = 9001,
    [string]$DownloadDir = "",
    [int]$DnsPort = 5353
)

$ErrorActionPreference = "Continue"

if (-not $DownloadDir) {
    $projectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $DownloadDir = Join-Path $projectRoot "deploy\cross-verify"
} else {
    $projectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
}

# 兜底地址：本机签证不可读时才使用（正常情况下应从签证文件派生真实地址）
$ipv8SelfFallback = "fb14:0000:0000:0001:0001:0000:0100:0000"
$ipv8Self  = $ipv8SelfFallback
$domain    = "ipv8.yulaoshi.xyz"
$uiDir     = Join-Path $PSScriptRoot "ui"
$geoipFile = Join-Path $PSScriptRoot "ipv8-geoip.json"
$dhcpFile  = Join-Path $PSScriptRoot "ipv8-dhcp.ps1"

# Dot-source DHCP module
. $dhcpFile

# ---------- 本机签证信息（真实 IPv8 地址的唯一来源） ----------
# visa.bin 布局: MAGIC "IP8V"(4) + version(1) + machine_id(32) + ipv8_addr(16, 偏移37) + ...
function Get-LocalVisaInfo {
    $info = @{ exists = $false; addr = $null; caExists = $false }
    $visaPath = Join-Path $env:USERPROFILE ".ipv8\visa.bin"
    $caPath   = Join-Path $env:USERPROFILE ".ipv8\ca.pub"
    $info.caExists = Test-Path $caPath
    if (Test-Path $visaPath) {
        try {
            $bytes = [System.IO.File]::ReadAllBytes($visaPath)
            if ($bytes.Length -ge 53 -and
                $bytes[0] -eq 0x49 -and $bytes[1] -eq 0x50 -and
                $bytes[2] -eq 0x38 -and $bytes[3] -eq 0x56 -and
                $bytes[4] -eq 1) {
                $groups = @()
                for ($i = 37; $i -lt 53; $i += 2) {
                    # 必须先转 [int]：PowerShell 的 -shl 会保持左操作数类型，
                    # [byte] -shl 8 会被截回字节导致高 8 位丢失（fb14 错成 0014）
                    $groups += ('{0:x4}' -f (([int]$bytes[$i] -shl 8) -bor [int]$bytes[$i + 1]))
                }
                $info.exists = $true
                $info.addr = ($groups -join ':')
            }
        } catch {
            Write-Host "  read visa failed: $_" -ForegroundColor Yellow
        }
    }
    return $info
}

$localVisa0 = Get-LocalVisaInfo
if ($localVisa0.exists -and $localVisa0.addr) { $ipv8Self = $localVisa0.addr }

# ---------- 版本号单一来源（模板与 /api/ping8-version 共用） ----------
function Get-Ping8Version {
    $version = 3
    $verFile = Join-Path $DownloadDir "ping8-version.txt"
    if (Test-Path $verFile) {
        $v = (Get-Content $verFile -Raw -ErrorAction SilentlyContinue)
        if ($v) { $v = $v.Trim() }
        if ($v -match '^\d+$') { $version = [int]$v }
    } else {
        $exePath = Join-Path $DownloadDir "ping8.exe"
        if (-not (Test-Path $exePath)) { $exePath = Join-Path $projectRoot "ping8.exe" }
        if (Test-Path $exePath) {
            $ver = (Get-Item $exePath).VersionInfo
            if ($ver.ProductVersion -match '^\d+$') { $version = [int]$ver.ProductVersion }
        }
    }
    return $version
}
$ping8Version = Get-Ping8Version

Write-Host "=== IPv8+ Portal Starting ===" -ForegroundColor Cyan

# ---------- 前端资源检查 ----------
$templateFile = Join-Path $uiDir "portal.html"
$cssFile      = Join-Path $uiDir "theme.css"
$jsFiles      = @(
    Join-Path $uiDir "portal.js"
    Join-Path $uiDir "docs-data.js"
    Join-Path $uiDir "topology.js"
    Join-Path $uiDir "wizard.js"
)

foreach ($f in @($templateFile, $cssFile) + $jsFiles) {
    if (-not (Test-Path $f)) {
        Write-Host "FATAL: missing UI asset: $f" -ForegroundColor Red
        exit 1
    }
}
Write-Host "UI assets loaded from $uiDir" -ForegroundColor Green

# ---------- GeoIP ----------
$geoip = $null
$geoipCount = 0
if (Test-Path $geoipFile) {
    $geoip = Get-Content $geoipFile -Raw -Encoding UTF8 | ConvertFrom-Json
    $geoipCount = @($geoip.records).Count
    Write-Host "GeoIP database loaded: $geoipCount records" -ForegroundColor Green
} else {
    Write-Host "WARNING: GeoIP database not found at $geoipFile" -ForegroundColor Yellow
}

# ---------- 清理旧门户实例 ----------
# 仅结束此前运行的 ipv8-portal.ps1，不影响其他 PowerShell 窗口
try {
    Get-CimInstance Win32_Process -Filter "Name='powershell.exe' OR Name='pwsh.exe'" -ErrorAction Stop |
        Where-Object { $_.ProcessId -ne $PID -and $_.CommandLine -and $_.CommandLine -match 'ipv8-portal\.ps1' } |
        ForEach-Object {
            try { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue } catch {}
        }
} catch {}
Start-Sleep -Milliseconds 500

# ============ DNS Server ============
try {
    $udpClient = New-Object System.Net.Sockets.UdpClient
    $udpClient.ExclusiveAddressUse = $false
    $udpClient.Client.SetSocketOption("Socket", "ReuseAddress", $true)
    $udpClient.Client.Bind((New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Loopback, $DnsPort)))
    Write-Host "DNS resolver on UDP $DnsPort" -ForegroundColor Green

    $dnsRunspace = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()
    $dnsRunspace.Open()
    $dnsPS = [System.Management.Automation.PowerShell]::Create()
    $dnsPS.Runspace = $dnsRunspace
    $dnsPS.AddScript({
        param($udp)
        while ($true) {
            try {
                $remoteEP = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
                $data = $udp.Receive([ref]$remoteEP)
                if ($data.Length -ge 12) {
                    $qname = ""
                    $off = 12
                    while ($off -lt $data.Length) {
                        $ll = $data[$off]
                        if ($ll -eq 0) { $off++; break }
                        $off++
                        $label = [System.Text.Encoding]::ASCII.GetString($data, $off, $ll)
                        $qname += $label + "."
                        $off += $ll
                    }
                    $off += 4
                    $qt = [BitConverter]::ToUInt16([byte[]]@($data[$off-3], $data[$off-4]), 0)
                    # DNS 域名大小写不敏感（EndsWith 默认区分大小写会导致部分查询无响应）
                    if ($qname.EndsWith(".ipv8.net.", [StringComparison]::OrdinalIgnoreCase)) {
                        $resp = New-Object System.Collections.Generic.List[byte]
                        $resp.Add($data[0]); $resp.Add($data[1])
                        $resp.Add(0x85); $resp.Add(0x80)
                        $resp.AddRange([byte[]]@(0,1,0,1,0,0,0,0))
                        $resp.AddRange($data[12..($off-1)])
                        if ($qt -eq 28) {
                            $resp.AddRange([byte[]]@(0xC0,0x0C))
                            $resp.AddRange([byte[]]@(0,28,0,1,0,0,0,60))
                            $resp.AddRange([byte[]](0,16))
                            $resp.AddRange([byte[]](0xfb,0x14,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x01,0x00,0x00))
                        } else {
                            $resp[8] = 0; $resp[9] = 0
                        }
                        $rb = $resp.ToArray()
                        $udp.Send($rb, $rb.Length, $remoteEP) | Out-Null
                    }
                }
            } catch {}
        }
    }).AddParameter("udp", $udpClient) | Out-Null
    $dnsHandle = $dnsPS.BeginInvoke()
    Write-Host "  DNS resolver started" -ForegroundColor Green
} catch {
    Write-Host "  DNS resolver failed: $_" -ForegroundColor Yellow
}

# ============ HTTP Server ============
function Start-HttpListener {
    param([int]$Port)
    $l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $Port)
    $l.Start()
    return $l
}

try {
    $listener = Start-HttpListener $HttpPort
    Write-Host "HTTP on http://127.0.0.1:$HttpPort" -ForegroundColor Green
} catch {
    # 端口被占用：只结束占用该端口的用户进程，避开 System(4) 等内核进程
    Get-NetTCPConnection -LocalPort $HttpPort -State Listen -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty OwningProcess -Unique |
        Where-Object { $_ -gt 4 } |
        ForEach-Object { Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue }
    Start-Sleep 1
    try {
        $listener = Start-HttpListener $HttpPort
        Write-Host "HTTP on http://127.0.0.1:$HttpPort (retry OK)" -ForegroundColor Green
    } catch {
        Write-Host "FATAL: cannot bind port $HttpPort : $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

Write-Host "Download dir: $DownloadDir`n" -ForegroundColor Gray

# ============ 工具函数 ============
function Get-ServerIPv6 {
    try {
        $addrs = Get-NetIPAddress -AddressFamily IPv6 -ErrorAction Stop |
            Where-Object {
                $_.IPAddress -notlike "fe80::*" -and
                $_.IPAddress -notlike "::1" -and
                $_.IPAddress -notlike "fd*" -and
                $_.IPAddress -notlike "fc*" -and
                $_.PrefixOrigin -ne "WellKnown" -and
                $_.SuffixOrigin -ne "Link"
            } | Sort-Object -Property IPAddress -Descending
        if ($addrs) {
            $globalAddrs = $addrs | Where-Object { $_.IPAddress -match "^[0-9a-f]{4}:" -and $_.IPAddress -notmatch "^fd[0-9a-f]" -and $_.IPAddress -notmatch "^fc[0-9a-f]" }
            if ($globalAddrs) { return ($globalAddrs | Select-Object -First 1).IPAddress }
            return ($addrs | Select-Object -First 1).IPAddress
        }
    } catch {}
    return $null
}

function Get-ServerIPv4 {
    try {
        $addr = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object {
                $_.IPAddress -notlike "127.*" -and
                $_.IPAddress -notlike "169.*" -and
                $_.IPAddress -notlike "100.64.*" -and
                $_.PrefixOrigin -ne "WellKnown"
            } | Select-Object -First 1
        if ($addr) { return $addr.IPAddress }
    } catch {}
    return $null
}

function Ipv8ToBytes {
    param([string]$addr)
    $parts = $addr -split "::"
    if ($parts.Count -eq 2) {
        $left = $parts[0] -split ":" | Where-Object { $_ }
        $right = $parts[1] -split ":" | Where-Object { $_ }
        $missing = 8 - $left.Count - $right.Count
        $mid = @("0000") * $missing
        $all = @($left) + $mid + @($right)
    } else {
        $all = ($addr -split ":") | Where-Object { $_ }
        while ($all.Count -lt 8) { $all += "0000" }
    }
    $hex = ""
    foreach ($p in $all) {
        $p = $p.PadLeft(4, "0")
        $hex += $p
    }
    $hex = $hex.PadRight(32, "0").Substring(0, 32)
    $bytes = New-Object byte[] 16
    for ($i = 0; $i -lt 32; $i += 2) {
        $bytes[$i/2] = [Convert]::ToByte($hex.Substring($i, 2), 16)
    }
    return $bytes
}

function CompareBytes {
    param([byte[]]$a, [byte[]]$b)
    for ($i = 0; $i -lt 16; $i++) {
        if ($a[$i] -lt $b[$i]) { return -1 }
        if ($a[$i] -gt $b[$i]) { return 1 }
    }
    return 0
}

function Lookup-GeoIP {
    param([string]$ip)
    if (-not $geoip) { return $null }
    $ipBytes = Ipv8ToBytes $ip
    foreach ($r in $geoip.records) {
        $startBytes = Ipv8ToBytes $r.range_start
        $endBytes = Ipv8ToBytes $r.range_end
        $afterStart = (CompareBytes $ipBytes $startBytes) -ge 0
        $beforeEnd = (CompareBytes $ipBytes $endBytes) -le 0
        if ($afterStart -and $beforeEnd) { return $r }
    }
    return $null
}

function Get-NodeStats {
    # Cleanup stale clients first (no heartbeat for 2 minutes)
    Cleanup-StaleClients -timeoutSeconds 120

    $stats = @{ uptime = 0; sealed = 0; delivered = 0; dropped = 0; clients = 0 }
    try {
        $node = Get-Process ipv8-node -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($node) {
            $stats.uptime = [math]::Round(((Get-Date) - $node.StartTime).TotalSeconds)
        }
    } catch {}
    $allocs = @(Get-AllAllocations)
    $stats.clients = @($allocs | Where-Object { $_.status -eq "active" }).Count
    return $stats
}

# HTML 转义，防止客户端名等外部数据破坏页面结构
function ConvertTo-HtmlText {
    param([string]$s)
    if ($null -eq $s) { return "" }
    return $s.Replace("&","&amp;").Replace("<","&lt;").Replace(">","&gt;").Replace('"',"&quot;").Replace("'","&#39;")
}

# ---------- Landing page (template render) ----------
function Build-LandingPage {
    $html = [System.IO.File]::ReadAllText($templateFile, [System.Text.Encoding]::UTF8)

    # Only placeholders that actually exist in the template; live data comes from AJAX
    $map = @{
        "{{DOMAIN}}"    = $domain
        "{{IPV8_SELF}}" = $ipv8Self
        "{{VERSION}}"   = "$ping8Version"
        "{{YEAR}}"      = (Get-Date).Year.ToString()
    }
    foreach ($k in $map.Keys) {
        $html = $html.Replace($k, $map[$k])
    }
    return $html
}

# ---------- 子域名节点页 ----------
function Build-NodePage {
    param([string]$subdomain, $matched)

    $tpl = @'
<!DOCTYPE html>
<html lang="zh-CN" data-theme="__THEME__">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>__SUB__ - IPv8+ Node</title>
<link rel="stylesheet" href="/ui/theme.css">
</head>
<body>
<div class="node-page">
  <div class="node-card">
    <h1>__SUB__</h1>
    <div class="node-domain">__SUB__.ipv8.yulaoshi.xyz</div>
    <div class="node-rows">
      <div class="node-row"><span class="k">IPv8 地址</span><span class="v">__IPV8__</span></div>
      <div class="node-row"><span class="k">TUN IP</span><span class="v">__TUN__</span></div>
      <div class="node-row"><span class="k">分配时间</span><span class="v">__TIME__</span></div>
      <div class="node-row"><span class="k">状态</span><span class="v"><span class="badge badge-ok">__STATUS__</span></span></div>
    </div>
    <p style="color:var(--text-muted);font-size:.88rem;margin-bottom:20px">此客户端已连接到 IPv8+ 网络</p>
    <a href="https://ipv8.yulaoshi.xyz" class="btn">返回主门户</a>
  </div>
</div>
<script>
(function(){try{var t=localStorage.getItem('ipv8-theme');if(t){document.documentElement.setAttribute('data-theme',t);}}catch(e){}})();
</script>
</body>
</html>
'@
    $tpl = $tpl.Replace("__THEME__", "night").Replace("__SUB__", (ConvertTo-HtmlText $subdomain))
    $tpl = $tpl.Replace("__IPV8__", (ConvertTo-HtmlText $matched.ipv8_full))
    $tpl = $tpl.Replace("__TUN__", (ConvertTo-HtmlText $matched.tun_ip))
    $tpl = $tpl.Replace("__TIME__", (ConvertTo-HtmlText $matched.assigned_at))
    $tpl = $tpl.Replace("__STATUS__", (ConvertTo-HtmlText $matched.status))
    return $tpl
}

function Build-NodeNotFoundPage {
    param([string]$subdomain)
    $tpl = @'
<!DOCTYPE html>
<html lang="zh-CN" data-theme="night">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IPv8+ Node Not Found</title>
<link rel="stylesheet" href="/ui/theme.css">
</head>
<body>
<div class="node-page">
  <div class="node-card">
    <h1 style="color:var(--danger)">节点未找到</h1>
    <div class="node-domain">__SUB__.ipv8.yulaoshi.xyz</div>
    <p style="color:var(--text-muted);font-size:.92rem;line-height:1.75;margin-bottom:24px">
      子域名 <strong style="color:var(--text)">__SUB__</strong> 没有对应的 IPv8+ 客户端。<br>
      请确认该客户端已连接并成功注册地址。
    </p>
    <a href="https://ipv8.yulaoshi.xyz" class="btn">返回主门户</a>
  </div>
</div>
<script>
(function(){try{var t=localStorage.getItem('ipv8-theme');if(t){document.documentElement.setAttribute('data-theme',t);}}catch(e){}})();
</script>
</body>
</html>
'@
    return $tpl.Replace("__SUB__", (ConvertTo-HtmlText $subdomain))
}

# ---------- 响应输出（TcpListener 版本） ----------
# $response 是一个 hashtable，包含 stream（NetworkStream）和 extraHeaders（hashtable）
function Send-Bytes {
    param($response, [byte[]]$bytes, [string]$contentType, [int]$statusCode = 200)
    try {
        $statusText = switch ($statusCode) {
            200 { "OK" }
            206 { "Partial Content" }
            400 { "Bad Request" }
            404 { "Not Found" }
            416 { "Range Not Satisfiable" }
            500 { "Internal Server Error" }
            default { "OK" }
        }
        $extra = $response.extraHeaders
        $extraStr = ""
        if ($extra) {
            foreach ($k in $extra.Keys) {
                $extraStr += "$k`: $($extra[$k])`r`n"
            }
        }
        $header = "HTTP/1.1 $statusCode $statusText`r`nContent-Type: $contentType`r`nContent-Length: $($bytes.Length)`r`nCache-Control: no-cache`r`nConnection: close`r`n$extraStr`r`n"
        $headerBytes = [System.Text.Encoding]::UTF8.GetBytes($header)
        $response.stream.Write($headerBytes, 0, $headerBytes.Length)
        $response.stream.Write($bytes, 0, $bytes.Length)
    } catch {
        Write-Host "  Send-Bytes error: $_" -ForegroundColor Red
    }
}

function Send-Html {
    param($response, [string]$html, [int]$statusCode = 200)
    Send-Bytes $response ([System.Text.Encoding]::UTF8.GetBytes($html)) "text/html; charset=utf-8" $statusCode
}

function Send-Json {
    param($response, $obj)
    if ($obj -is [System.Array] -or ($obj -is [System.Collections.IEnumerable] -and $obj -isnot [string] -and $obj -isnot [hashtable])) {
        $obj = @($obj)
    }
    $json = $obj | ConvertTo-Json -Depth 10 -Compress
    if ([string]::IsNullOrEmpty($json)) {
        $isList = ($obj -is [System.Array]) -or
                  (($obj -is [System.Collections.IEnumerable]) -and ($obj -isnot [string]) -and ($obj -isnot [hashtable]))
        $json = if ($isList) { "[]" } else { "null" }
    }
    Send-Bytes $response ([System.Text.Encoding]::UTF8.GetBytes($json)) "application/json; charset=utf-8"
}

function Get-RequestJson {
    param($bodyStr)
    try {
        if ($bodyStr) { return ($bodyStr | ConvertFrom-Json) }
    } catch {}
    return $null
}

# ============ Request Loop (TcpListener 版本) ============
while ($true) {
    try {
        $tcpClient = $listener.AcceptTcpClient()
        $tcpClient.ReceiveTimeout = 10000
        $tcpClient.SendTimeout = 30000
        $stream = $tcpClient.GetStream()

        # 构造 $response 对象（必须在读 body 之前，否则 413 等早期错误引用不到 $response）
        $response = @{
            stream = $stream
            extraHeaders = @{}
        }

        # 读取 HTTP 请求
        $ms = New-Object System.IO.MemoryStream
        $buf = New-Object byte[] 8192
        $headerEnd = -1
        while ($stream.DataAvailable -or $tcpClient.Available -gt 0 -or $ms.Length -eq 0) {
            $n = $stream.Read($buf, 0, $buf.Length)
            if ($n -le 0) { break }
            $ms.Write($buf, 0, $n)
            $allBytes = $ms.ToArray()
            $headerStr = [System.Text.Encoding]::ASCII.GetString($allBytes)
            $headerEnd = $headerStr.IndexOf("`r`n`r`n")
            if ($headerEnd -ge 0) { break }
            if ($ms.Length -gt 1048576) { break }
        }

        if ($headerEnd -lt 0) {
            $tcpClient.Close(); continue
        }

        $allBytes = $ms.ToArray()
        $headerStr = [System.Text.Encoding]::ASCII.GetString($allBytes, 0, $headerEnd)
        $headerLines = $headerStr -split "`r`n"

        # 解析请求行（畸形请求直接断开）
        $reqLine = $headerLines[0] -split " "
        if ($reqLine.Count -lt 2 -or [string]::IsNullOrEmpty($reqLine[1])) {
            try { $stream.Close(); $tcpClient.Close() } catch {}
            continue
        }
        $method = $reqLine[0]
        $reqPath = $reqLine[1]

        # 解析 headers
        $headers = @{}
        for ($i = 1; $i -lt $headerLines.Count; $i++) {
            $idx = $headerLines[$i].IndexOf(":")
            if ($idx -gt 0) {
                $hname = $headerLines[$i].Substring(0, $idx).Trim()
                $hval = $headerLines[$i].Substring($idx + 1).Trim()
                $headers[$hname] = $hval
            }
        }

        # 解析 path 和 query
        $path = $reqPath
        $queryString = ""
        $qIdx = $path.IndexOf("?")
        if ($qIdx -ge 0) {
            $queryString = $path.Substring($qIdx + 1)
            $path = $path.Substring(0, $qIdx)
        }

        # 解析 query params
        $queryParams = @{}
        if ($queryString) {
            foreach ($pair in ($queryString -split "&")) {
                $kv = $pair -split "=", 2
                if ($kv.Count -eq 2) {
                    $queryParams[[uri]::UnescapeDataString($kv[0])] = [uri]::UnescapeDataString($kv[1])
                }
            }
        }

        # 读取请求体（上限 1MB，防超大 Content-Length 内存耗尽）
        $bodyStr = ""
        $contentLength = 0
        # 只接受纯数字 Content-Length，畸形值按 0 处理（[int] 强转非数字会抛异常中断连接）
        if ($headers.ContainsKey("Content-Length") -and "$($headers['Content-Length'])" -match '^\d{1,10}$') {
            $contentLength = [int]$headers["Content-Length"]
        }
        if ($contentLength -gt 1048576) {
            Send-Html $response "413: body too large" 400
            try { $stream.Close(); $tcpClient.Close() } catch {}
            continue
        }
        if ($contentLength -gt 0) {
            $bodyStart = $headerEnd + 4
            $bodyBytes = New-Object byte[] $contentLength
            $alreadyRead = $allBytes.Length - $bodyStart
            if ($alreadyRead -gt 0) {
                [Array]::Copy($allBytes, $bodyStart, $bodyBytes, 0, [Math]::Min($alreadyRead, $contentLength))
            }
            while ($alreadyRead -lt $contentLength) {
                $n = $stream.Read($bodyBytes, $alreadyRead, $contentLength - $alreadyRead)
                if ($n -le 0) { break }
                $alreadyRead += $n
            }
            $bodyStr = [System.Text.Encoding]::UTF8.GetString($bodyBytes)
        }

        # 构造一个模拟的 $request 对象，兼容旧代码
        $remoteIp = ($tcpClient.Client.RemoteEndPoint -as [System.Net.IPEndPoint]).Address.ToString()
        $request = @{
            HttpMethod = $method
            Url = @{ AbsolutePath = $path }
            Headers = $headers
            QueryString = $queryParams
            InputStream = $null
            ContentLength64 = $contentLength
            HasEntityBody = ($contentLength -gt 0)
            RemoteEndPoint = @{ Address = @{ ToString = $remoteIp } }
            BodyString = $bodyStr
            RemoteIP = $remoteIp
        }

        # ---------- 路由分发 ----------
        # ---------- 静态前端资源 ----------
        if ($path -match "^/ui/([A-Za-z0-9_\-\.]+)$") {
            $asset = $Matches[1]
            # 防目录穿越：仅允许 ui 目录下的白名单文件
            $allowed = @{
                "theme.css"   = "text/css; charset=utf-8"
                "portal.js"   = "application/javascript; charset=utf-8"
                "docs-data.js"= "application/javascript; charset=utf-8"
                "topology.js" = "application/javascript; charset=utf-8"
                "wizard.js"   = "application/javascript; charset=utf-8"
            }
            if ($allowed.ContainsKey($asset)) {
                $assetPath = Join-Path $uiDir $asset
                if (Test-Path $assetPath -PathType Leaf) {
                    $bytes = [System.IO.File]::ReadAllBytes($assetPath)
                    Send-Bytes $response $bytes $allowed[$asset]
                } else {
                    Send-Html $response "404: asset missing" 404
                }
            } else {
                Send-Html $response "404: unknown asset" 404
            }
        }
        # ---------- 首页 / 子域名节点页 ----------
        elseif ($path -eq "/" -or $path -eq "") {
            $hostHeader = $request.Headers["Host"]
            $subdomain = $null
            if ($hostHeader -match "^([a-zA-Z0-9-]+)\.ipv8\.yulaoshi\.xyz") {
                $subdomain = $Matches[1]
            } elseif ($hostHeader -match "^([a-zA-Z0-9-]+)\.ipv8\.net") {
                $subdomain = $Matches[1]
            }
            if ($subdomain -and $subdomain -ne "www" -and $subdomain -ne "ipv8") {
                $allocs = @(Get-AllAllocations)
                $matched = $allocs | Where-Object { $_.client_name -eq $subdomain } | Select-Object -First 1
                if ($matched) {
                    Send-Html $response (Build-NodePage $subdomain $matched)
                } else {
                    Send-Html $response (Build-NodeNotFoundPage $subdomain) 404
                }
            } else {
                Send-Html $response (Build-LandingPage)
            }
        }
        # ---------- 文件下载 ----------
        elseif ($path -match "^/download/(.+)$") {
            $fileName = [uri]::UnescapeDataString($Matches[1])
            # 防目录穿越：拒绝任何路径分隔符与上跳
            if ($fileName -match '[\\/]' -or $fileName -match '\.\.' -or $fileName -match '^\.') {
                Send-Html $response "400: invalid file name" 400
            } else {
                $filePath = Join-Path $DownloadDir $fileName
                # 二次确认解析后的真实路径仍在下载目录内
                $fullDownload = [System.IO.Path]::GetFullPath($DownloadDir)
                $fullFile = [System.IO.Path]::GetFullPath($filePath)
                if ((Test-Path $filePath -PathType Leaf) -and $fullFile.StartsWith($fullDownload, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $fileBytes = [System.IO.File]::ReadAllBytes($filePath)
                    $fileLen = $fileBytes.Length
                    $response.extraHeaders["Content-Disposition"] = "attachment; filename=$fileName"
                    $response.extraHeaders["Accept-Ranges"] = "bytes"
                    $rangeHeader = $request.Headers["Range"]
                    if ($rangeHeader -and $rangeHeader -match "bytes=(\d+)-(\d*)") {
                        $start = [int64]$Matches[1]
                        $end = if ($Matches[2]) { [int64]$Matches[2] } else { $fileLen - 1 }
                        if ($end -ge $fileLen) { $end = $fileLen - 1 }
                        if ($start -le $end) {
                            $chunkLen = $end - $start + 1
                            $response.extraHeaders["Content-Range"] = "bytes $start-$end/$fileLen"
                            $chunk = New-Object byte[] $chunkLen
                            [Array]::Copy($fileBytes, $start, $chunk, 0, $chunkLen)
                            Send-Bytes $response $chunk "application/octet-stream" 206
                            Write-Host "  Sent (206): $fileName [$start-$end] ($chunkLen bytes)" -ForegroundColor Cyan
                        } else {
                            $response.extraHeaders["Content-Range"] = "bytes */$fileLen"
                            Send-Bytes $response (New-Object byte[] 0) "application/octet-stream" 416
                            Write-Host "  Range not satisfiable: $fileName [$start-$end] (len $fileLen)" -ForegroundColor Yellow
                        }
                    } else {
                        Send-Bytes $response $fileBytes "application/octet-stream"
                        Write-Host "  Sent (200): $fileName ($fileLen bytes)" -ForegroundColor Cyan
                    }
                } else {
                    Send-Html $response "404: $([uri]::EscapeDataString($fileName))" 404
                }
            }
        }
        # ---------- API ----------
        elseif ($path -eq "/api/geoip") {
            $queryIp = $request.QueryString["ip"]
            if (-not $queryIp) {
                $gv = Get-LocalVisaInfo
                $queryIp = if ($gv.exists -and $gv.addr) { $gv.addr } else { $ipv8Self }
            }
            $record = Lookup-GeoIP $queryIp
            $result = if ($record) {
                @{ip=$queryIp;version="IPv8+";country=$record.country;province=$record.province;city=$record.city;district=$record.district;zipcode=$record.zipcode;areacode=$record.areacode;isp=$record.isp;asn=$record.asn;organization=$record.organization;latitude=$record.latitude;longitude=$record.longitude;purpose=$record.purpose;operator=$record.operator;network_type=$record.network_type;notes=$record.notes}
            } else {
                @{ip=$queryIp;version="IPv8+";error="Not in database";country="-";province="-";city="-";district="-";zipcode="-";areacode="-";isp="-";asn="-";organization="-";latitude="-";longitude="-";purpose="-";operator="-";network_type="-";notes="-"}
            }
            Send-Json $response $result
            Write-Host "  GeoIP: $queryIp -> $($record.city)" -ForegroundColor Cyan
        }
        elseif ($path -eq "/api/stats") {
            Send-Json $response (Get-NodeStats)
        }
        elseif ($path -eq "/api/clients") {
            $all = @(Get-AllAllocations)
            $active = @($all | Where-Object { $_.status -eq "active" })
            Send-Json $response @{total=$all.Count; active=$active.Count}
        }
        elseif ($path -eq "/api/register" -and $method -eq "POST") {
            try {
                $bodyStr = $request.BodyString
                Write-Host "  [register] body: $bodyStr" -ForegroundColor DarkGray
                $bodyObj = $bodyStr | ConvertFrom-Json

                $clientIp = $request.RemoteIP
                if ($bodyObj.client_ip) { $clientIp = $bodyObj.client_ip }

                $ipv8Addr = if ($bodyObj.ipv8_addr) { $bodyObj.ipv8_addr } else { "" }
                $hostname = if ($bodyObj.hostname) { $bodyObj.hostname } else { "" }
                $fingerprint = if ($bodyObj.fingerprint) { $bodyObj.fingerprint } else { "" }
                $visaExists = if ($bodyObj.visa_exists) { [bool]$bodyObj.visa_exists } else { $false }
                $caExists = if ($bodyObj.ca_exists) { [bool]$bodyObj.ca_exists } else { $false }

                $alloc = Register-Client -clientIp $clientIp -ipv8Addr $ipv8Addr -hostname $hostname -fingerprint $fingerprint -visaExists $visaExists -caExists $caExists

                if ($null -eq $alloc) {
                    Write-Host "  [register] ERROR: Register-Client returned null" -ForegroundColor Red
                    Send-Json $response @{ok=$false;error="Register-Client returned null"}
                } else {
                    Write-Host "  [register] OK: $hostname ($clientIp) -> $($alloc.ipv8_address)" -ForegroundColor Green
                    Send-Json $response @{ok=$true;ipv8_address=$alloc.ipv8_address;client_name=$alloc.client_name}
                }
            } catch {
                Write-Host "  [register] EXCEPTION: $_" -ForegroundColor Red
                Send-Json $response @{ok=$false;error=$_.Exception.Message}
            }
        }
        elseif ($path -eq "/api/heartbeat") {
            $clientIp = $request.QueryString["ip"]
            if (-not $clientIp) { $clientIp = $request.RemoteIP }
            $updated = Update-Heartbeat -clientIp $clientIp
            Send-Json $response @{ok=$updated;ip=$clientIp}
        }
        elseif ($path -eq "/api/probe-clients") {
            $allocs = @(Get-AllAllocations | Where-Object { $_.status -eq "active" })
            $results = @()
            foreach ($a in $allocs) {
                $alive = Probe-ClientAlive -clientIp $a.client_ip -port 9100 -timeoutMs 2000
                if ($alive) {
                    $a.last_seen = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                    $a.status = "active"
                    $results += @{ip=$a.client_ip;name=$a.client_name;alive=$true}
                } else {
                    $results += @{ip=$a.client_ip;name=$a.client_name;alive=$false}
                }
            }
            Cleanup-StaleClients -timeoutSeconds 120
            $activeCount = @(Get-AllAllocations | Where-Object { $_.status -eq "active" }).Count
            Send-Json $response @{probed=$results.Count;results=$results;active=$activeCount}
            Write-Host "  Probed $($results.Count) clients, $activeCount active" -ForegroundColor Cyan
        }
        elseif ($path -eq "/api/allocate" -and $method -eq "POST") {
            $bodyObj = Get-RequestJson $request.BodyString
            if (-not $bodyObj -or -not $bodyObj.client_ip) {
                Send-Json $response @{error="missing or invalid client_ip"}
                continue
            }
            $alloc = Allocate-IPv8Address $bodyObj.client_ip $bodyObj.client_name
            Send-Json $response $alloc
            Write-Host "  Allocated: $($alloc.ipv8_address) to $($bodyObj.client_ip)" -ForegroundColor Green
        }
        elseif ($path -eq "/api/ping8-version") {
            Send-Json $response @{ version = $ping8Version }
            Write-Host "  Version check: v$ping8Version" -ForegroundColor Green
        }
        elseif ($path -eq "/api/client-package") {
            # 只返回 ping8.exe 文件，不再创建分配记录
            # 客户端注册由 ping8 auto → POST /api/register 处理
            $clientIp = $request.QueryString["ip"]
            if (-not $clientIp) { $clientIp = $request.RemoteIP }

            $srcExe = Join-Path $DownloadDir "ping8.exe"
            if (-not (Test-Path $srcExe)) {
                $srcExe = Join-Path $projectRoot "ping8.exe"
            }
            if (-not (Test-Path $srcExe)) {
                Send-Json $response @{error="ping8.exe not found"}
                continue
            }

            $exeBytes = [System.IO.File]::ReadAllBytes($srcExe)
            $exeLen = $exeBytes.Length
            $response.extraHeaders["Content-Disposition"] = "attachment; filename=ping8.exe"
            $response.extraHeaders["Accept-Ranges"] = "bytes"
            $rangeHeader = $request.Headers["Range"]
            if ($rangeHeader -and $rangeHeader -match "bytes=(\d+)-(\d*)") {
                $start = [int64]$Matches[1]
                $end = if ($Matches[2]) { [int64]$Matches[2] } else { $exeLen - 1 }
                if ($end -ge $exeLen) { $end = $exeLen - 1 }
                if ($start -le $end -and $start -lt $exeLen) {
                    $chunkLen = $end - $start + 1
                    $response.extraHeaders["Content-Range"] = "bytes $start-$end/$exeLen"
                    $chunk = New-Object byte[] $chunkLen
                    [Array]::Copy($exeBytes, $start, $chunk, 0, $chunkLen)
                    Send-Bytes $response $chunk "application/octet-stream" 206
                    Write-Host "  Client exe sent (206) [$start-$end] ($chunkLen bytes) to $clientIp" -ForegroundColor Green
                } else {
                    $response.extraHeaders["Content-Range"] = "bytes */$exeLen"
                    Send-Bytes $response (New-Object byte[] 0) "application/octet-stream" 416
                    Write-Host "  Client exe range not satisfiable [$start-$end] (len $exeLen)" -ForegroundColor Yellow
                }
            } else {
                Send-Bytes $response $exeBytes "application/octet-stream"
                Write-Host "  Client exe sent ($exeLen bytes) to $clientIp" -ForegroundColor Green
            }
        }
        elseif ($path -eq "/api/resolve") {
            $hostname = $request.QueryString["host"]
            if (-not $hostname) { $hostname = "portal.ipv8.net" }
            $resolvedIp = $null
            if ($hostname -eq "portal.ipv8.net" -or $hostname -eq "ipv8.yulaoshi.xyz") {
                $resolvedIp = Get-ServerIPv6
                if (-not $resolvedIp) { $resolvedIp = Get-ServerIPv4 }
            }
            foreach ($a in @(Get-AllAllocations)) {
                if ($a.client_name -and "$($a.client_name).ipv8.net" -eq $hostname) {
                    $resolvedIp = $a.client_ip
                    break
                }
            }
            if (-not $resolvedIp) { $resolvedIp = "127.0.0.1" }
            Send-Json $response @{host=$hostname;ip=$resolvedIp}
        }
        elseif ($path -eq "/api/firewall" -or $path -eq "/api/firewall/rules" -or $path -eq "/api/firewall/stats") {
            # ===== 只读展示：服务器与防火墙状态 =====
            # 门户不管理用户规则，只展示节点自身状态 + 已连接客户端签证信息

            $action = $request.QueryString["action"]

            # open/close 仍然保留（节点自身端口管理）
            if ($action -eq "open") {
                $ports = @(45801, 45800, 9001, 5353)
                $result = @()
                foreach ($port in $ports) {
                    foreach ($proto in @("UDP","TCP")) {
                        $ruleName = "IPv8+ Port $port $proto"
                        if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
                            try {
                                New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol $proto -LocalPort $port -Action Allow -Profile Any -ErrorAction Stop | Out-Null
                                $result += "OK $ruleName"
                            } catch {
                                $result += "FAIL $ruleName : $($_.Exception.Message)"
                            }
                        }
                    }
                }
                Send-Json $response @{action="open";result=$result}
                Write-Host "  Firewall: open standard ports" -ForegroundColor Green
            }
            elseif ($action -eq "close") {
                Get-NetFirewallRule -DisplayName "IPv8+*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
                Send-Json $response @{action="close";result="All IPv8+ port rules removed"}
                Write-Host "  Firewall: all port rules removed" -ForegroundColor Yellow
            }
            else {
                # 默认：只读展示
                $rawRules = @(Get-NetFirewallRule -DisplayName "IPv8+*" -ErrorAction SilentlyContinue)
                $winRules = @()
                foreach ($r in $rawRules) {
                    $winRules += @{
                        DisplayName = $r.DisplayName
                        Enabled = [bool]$r.Enabled
                        Direction = [int]$r.Direction
                        Profile = [string]$r.Profile
                    }
                }

                # 收集已连接客户端的统计信息（不暴露详细信息）
                # 注意：此处变量名不能叫 $allocations —— 会遮蔽 DHCP 模块的同名哈希表，
                # 导致后续分配/注册/存档全部作用在数组上而静默损坏
                Cleanup-StaleClients -timeoutSeconds 120
                $allocList = @(Get-AllAllocations)
                $activeCount = @($allocList | Where-Object { $_.status -eq "active" }).Count
                $withVisa = @($allocList | Where-Object { $_.status -eq "active" -and $_.visa_exists }).Count

                # 节点自身签证状态
                $visaPath = Join-Path $env:USERPROFILE ".ipv8\visa.bin"
                $lv = Get-LocalVisaInfo
                $visaExists = $lv.exists
                $visaAddr = $lv.addr
                $caExists = $lv.caExists

                # 防火墙概况
                $winActive = 0
                foreach ($r in $winRules) {
                    if ($r.Enabled) { $winActive++ }
                }

                $nodeIpv6 = Get-ServerIPv6
                if (-not $nodeIpv6) { $nodeIpv6 = "未检测到" }

                Send-Json $response @{
                    winRules = $winRules
                    winTotal = $winRules.Count
                    winActive = $winActive
                    clientCount = $activeCount
                    clientsWithVisa = $withVisa
                    visa = @{
                        exists = $visaExists
                        addr = $visaAddr
                        caExists = $caExists
                        path = $visaPath
                    }
                    node = @{
                        domain = $domain
                        ipv8 = $ipv8Self
                        ipv6 = $nodeIpv6
                        dns = "127.0.0.1:$DnsPort"
                        version = "IPv8+ v$ping8Version"
                    }
                }
                Write-Host "  Server info displayed: $activeCount clients, $($winRules.Count) FW rules" -ForegroundColor Cyan
            }
        }
        elseif ($path -eq "/api/status") {
            $ipv6 = Get-ServerIPv6
            $stats = Get-NodeStats
            $sv = Get-LocalVisaInfo
            $selfAddr = if ($sv.exists -and $sv.addr) { $sv.addr } else { $ipv8Self }
            Send-Json $response @{domain=$domain;ipv8=$selfAddr;ipv6=$ipv6;status="online";dns="127.0.0.1:$DnsPort";clients=$stats.clients;visa=@{exists=$sv.exists;addr=$sv.addr};ca_exists=$sv.caExists}
        }
        elseif ($path -eq "/api/my-ip") {
            Send-Json $response @{ipv6=(Get-ServerIPv6);ipv4=(Get-ServerIPv4)}
        }
        elseif ($path -eq "/api/cross-test") {
            $peerIp = $request.QueryString["ip"]
            $peerPort = $request.QueryString["port"]
            if (-not $peerPort) { $peerPort = "45801" }
            if (-not $peerIp) {
                Send-Json $response @{error="missing ip parameter"}
                continue
            }

            $ping8Exe = Join-Path $projectRoot "target\release\ping8.exe"
            if (-not (Test-Path $ping8Exe)) { $ping8Exe = Join-Path $DownloadDir "ping8.exe" }
            if (-not (Test-Path $ping8Exe)) {
                Send-Json $response @{error="ping8.exe not found"}
                continue
            }

            $script:crossTestStart = Get-Date

            $argList = @("trust","request",$peerIp,$peerPort)

            if ($script:crossTestJob -and $script:crossTestJob.State -eq "Running") {
                Send-Json $response @{error="a trust request is already running"}
                continue
            }

            # 输出重定向到临时文件（Start-Job 内 Start-Process 不带重定向时输出会丢失）
            $outFile = Join-Path $env:TEMP "ipv8-cross-stdout.txt"
            $errFile = Join-Path $env:TEMP "ipv8-cross-stderr.txt"
            Remove-Item $outFile, $errFile -Force -ErrorAction SilentlyContinue

            $script:crossTestJob = Start-Job -ScriptBlock {
                param($exe,$a,$outF,$errF)
                $p = Start-Process $exe -ArgumentList $a -NoNewWindow -Wait -PassThru `
                     -RedirectStandardOutput $outF -RedirectStandardError $errF
                return @{exitcode=$p.ExitCode}
            } -ArgumentList $ping8Exe,$argList,$outFile,$errFile

            Send-Json $response @{status="running";message="信任请求已发送，等待对端确认"}
            Write-Host "  Trust request sent: $peerIp`:$peerPort" -ForegroundColor Cyan
        }
        elseif ($path -eq "/api/cross-test-status") {
            $status = "idle"
            $output = ""
            $elapsed = 0
            $outFile = Join-Path $env:TEMP "ipv8-cross-stdout.txt"
            $errFile = Join-Path $env:TEMP "ipv8-cross-stderr.txt"
            if ($script:crossTestJob) {
                $elapsed = [math]::Round(((Get-Date) - $script:crossTestStart).TotalSeconds)
                if ($script:crossTestJob.State -eq "Completed") {
                    $result = Receive-Job $script:crossTestJob
                    Remove-Job $script:crossTestJob -Force
                    $script:crossTestJob = $null
                    $output = Get-Content $outFile -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
                    $errOut = Get-Content $errFile -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
                    if ($errOut) { $output = "$output`n$errOut" }
                    $exitCode = if ($result -and $result.exitcode -ne $null) { [int]$result.exitcode } else { -1 }
                    # ping8 trust request：0 = 对端同意，非 0 = 超时/拒绝
                    if ($exitCode -eq 0) { $status = "pass" } else { $status = "fail" }
                } elseif ($script:crossTestJob.State -eq "Running") {
                    $status = "running"
                    if (Test-Path $outFile) { $output = Get-Content $outFile -Raw -Encoding UTF8 -ErrorAction SilentlyContinue }
                }
            }
            Send-Json $response @{status=$status;output=$output;elapsed=$elapsed}
        }
        else {
            Send-Html $response "404" 404
        }

        # 关闭连接
        try { $stream.Close(); $tcpClient.Close() } catch {}
    } catch {
        Write-Host "Error: $_" -ForegroundColor Red
        try { $stream.Close(); $tcpClient.Close() } catch {}
    }
}
