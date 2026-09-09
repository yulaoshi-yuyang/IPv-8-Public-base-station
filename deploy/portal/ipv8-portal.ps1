param(
    [int]$HttpPort = 9001,
    [string]$DownloadDir = "",
    [int]$DnsPort = 5353
)

if (-not $DownloadDir) {
    $scriptDir = $PSScriptRoot
    $projectRoot = Split-Path $scriptDir -Parent
    $projectRoot = Split-Path $projectRoot -Parent
    $DownloadDir = Join-Path $projectRoot "deploy\cross-verify"
}

$ipv8Self = "fb14:0000:0000:0001:0001:0000:0001:0000"
$geoipFile = Join-Path $PSScriptRoot "ipv8-geoip.json"
$dhcpFile = Join-Path $PSScriptRoot "ipv8-dhcp.ps1"

# Dot-source DHCP module
. $dhcpFile

Write-Host "=== IPv8+ Portal Starting ===" -ForegroundColor Cyan

# Load GeoIP database
$geoip = $null
if (Test-Path $geoipFile) {
    $geoip = Get-Content $geoipFile -Raw -Encoding UTF8 | ConvertFrom-Json
    Write-Host "GeoIP database loaded: $($geoip.records.Count) records" -ForegroundColor Green
} else {
    Write-Host "WARNING: GeoIP database not found at $geoipFile" -ForegroundColor Yellow
}

# Kill old portal processes
Get-Process powershell -ErrorAction SilentlyContinue | Where-Object { $_.Id -ne $PID -and $_.StartTime -gt (Get-Date).AddHours(-1) } | ForEach-Object {
    try { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue } catch {}
}
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
                    if ($qname.EndsWith(".ipv8.net.")) {
                        $resp = New-Object System.Collections.Generic.List[byte]
                        $resp.Add($data[0]); $resp.Add($data[1])
                        $resp.Add(0x85); $resp.Add(0x80)
                        $resp.AddRange([byte[]]@(0,1,0,1,0,0,0,0))
                        $resp.AddRange($data[12..($off-1)])
                        if ($qt -eq 28) {
                            $resp.AddRange([byte[]]@(0xC0,0x0C))
                            $resp.AddRange([byte[]]@(0,28,0,1,0,0,0,60))
                            $resp.AddRange([byte[]](0,16))
                            $resp.AddRange([byte[]]@(0xfb,0x14,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x01,0x00,0x00))
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
try {
    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add("http://127.0.0.1:$HttpPort/")
    $listener.Start()
    Write-Host "HTTP on http://127.0.0.1:$HttpPort" -ForegroundColor Green
} catch {
    Get-NetTCPConnection -LocalPort $HttpPort -ErrorAction SilentlyContinue | ForEach-Object {
        Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep 1
    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add("http://127.0.0.1:$HttpPort/")
    $listener.Start()
    Write-Host "HTTP on http://127.0.0.1:$HttpPort (retry OK)" -ForegroundColor Green
}

Write-Host "Download dir: $DownloadDir`n" -ForegroundColor Gray

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
    $stats = @{ uptime = 0; sealed = 0; delivered = 0; dropped = 0; clients = 0 }
    try {
        $node = Get-Process ipv8-node -ErrorAction SilentlyContinue
        if ($node) {
            $stats.uptime = [math]::Round(((Get-Date) - $node.StartTime).TotalSeconds)
        }
    } catch {}
    $allocs = Get-AllAllocations
    $stats.clients = @($allocs | Where-Object { $_.status -eq "active" }).Count
    return $stats
}

function Build-LandingPage {
    $ipv6 = Get-ServerIPv6
    if (-not $ipv6) { $ipv6 = "(detecting...)" }

    $files = @()
    if (Test-Path $DownloadDir) {
        Get-ChildItem $DownloadDir -File | Where-Object { $_.Extension -in '.exe','.dll','.ps1','.md','.zip' } | ForEach-Object {
            $sizeKB = [math]::Round($_.Length / 1KB, 1)
            if ($sizeKB -gt 1024) { $sizeStr = "$([math]::Round($sizeKB/1024,1)) MB" } else { $sizeStr = "$sizeKB KB" }
            $files += "<tr><td><a href=""/download/$($_.Name)"">$($_.Name)</a></td><td>$sizeStr</td><td>$($_.Extension)</td></tr>"
        }
    }
    if ($files.Count -eq 0) { $files = @("<tr><td colspan=3>暂无文件</td></tr>") }
    $filesHtml = $files -join "`n"

    $stats = Get-NodeStats
    $allocs = Get-AllAllocations
    $clientsHtml = ""
    if ($allocs -and $allocs.Count -gt 0) {
        $clientsHtml = "<table><tr><th>IPv8 地址</th><th>TUN IP</th><th>Client</th><th>分配时间</th><th>状态</th></tr>"
        foreach ($a in $allocs) {
            $clientsHtml += "<tr><td class='mono'>$($a.ipv8_compact)</td><td class='mono'>$($a.tun_ip)</td><td>$($a.client_name)</td><td>$($a.assigned_at)</td><td><span class='badge'>$($a.status)</span></td></tr>"
        }
        $clientsHtml += "</table>"
    } else {
        $clientsHtml = "<p style='color:#666;text-align:center;padding:20px'>暂无客户端连接</p>"
    }

    $html = @"
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IPv8+ Portal</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#0a0e27;color:#e0e0e0;min-height:100vh}
.container{max-width:960px;margin:0 auto;padding:40px 20px}
.header{text-align:center;margin-bottom:40px}
.header h1{font-size:2.8em;background:linear-gradient(135deg,#00d4ff,#7b2ff7);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.header p{color:#888;margin-top:8px;font-size:1.1em}
.card{background:#141831;border:1px solid #1e2444;border-radius:12px;padding:24px;margin-bottom:20px}
.card h2{color:#00d4ff;margin-bottom:12px;font-size:1.3em}
.info-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.info-item{background:#0a0e27;padding:12px 16px;border-radius:8px;border:1px solid #1e2444}
.info-item .label{color:#666;font-size:0.85em;margin-bottom:4px}
.info-item .value{color:#00d4ff;font-family:monospace;font-size:1.05em;word-break:break-all}
table{width:100%;border-collapse:collapse}
th{text-align:left;color:#666;padding:8px 12px;border-bottom:1px solid #1e2444;font-size:0.85em}
td{padding:10px 12px;border-bottom:1px solid #0d1224}
td a{color:#00d4ff;text-decoration:none}
td a:hover{text-decoration:underline}
.badge{display:inline-block;background:#1a3a2a;color:#4caf50;padding:2px 10px;border-radius:4px;font-size:0.8em}
.footer{text-align:center;color:#444;margin-top:30px;font-size:0.85em}
.btn{display:inline-block;background:linear-gradient(135deg,#00d4ff,#7b2ff7);color:#fff;padding:12px 32px;border-radius:8px;text-decoration:none;font-weight:bold;font-size:1.1em;border:none;cursor:pointer}
.btn:hover{opacity:0.9}
.btn-sm{padding:8px 20px;font-size:0.9em}
.center{text-align:center}
.code{background:#0a0e27;padding:12px;border-radius:6px;font-family:monospace;color:#4caf50;border:1px solid #1e2444;word-break:break-all}
.mono{font-family:monospace;color:#00d4ff}
.search-box{display:flex;gap:8px;margin-bottom:16px}
.search-box input{flex:1;padding:12px 16px;background:#0a0e27;border:1px solid #1e2444;border-radius:8px;color:#e0e0e0;font-family:monospace;font-size:1em}
.search-box input:focus{outline:none;border-color:#00d4ff}
.stats-row{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:16px}
.stat-box{text-align:center;background:#0a0e27;padding:16px;border-radius:8px;border:1px solid #1e2444}
.stat-box .stat-value{font-size:2em;color:#00d4ff;font-weight:bold}
.stat-box .stat-label{color:#666;font-size:0.85em;margin-top:4px}
.tab-bar{display:flex;gap:4px;margin-bottom:16px;border-bottom:1px solid #1e2444}
.tab{padding:10px 20px;color:#666;cursor:pointer;border-bottom:2px solid transparent;font-size:0.95em}
.tab.active{color:#00d4ff;border-bottom-color:#00d4ff}
.tab:hover{color:#aaa}
</style>
</head>
<body>
<div class="container">
<div class="header">
<h1>IPv8+ Portal</h1>
<p>yulaoshi.xyz IPv8+ Service Node</p>
<span class="badge">ONLINE</span>
<span class="badge" style="background:#2a1a3a;color:#7b2ff7">DNS</span>
<span class="badge" style="background:#1a2a3a;color:#4fa3ff">GEOIP</span>
<span class="badge" style="background:#2a3a1a;color:#a3ff4f">DHCP</span>
</div>

<div class="card">
<h2>仪表盘</h2>
<div class="stats-row">
<div class="stat-box"><div class="stat-value" id="statClients">$($stats.clients)</div><div class="stat-label">客户端数</div></div>
<div class="stat-box"><div class="stat-value" id="statUptime">$($stats.uptime)s</div><div class="stat-label">运行时长</div></div>
<div class="stat-box"><div class="stat-value" id="statSealed">$($stats.sealed)</div><div class="stat-label">加密包数</div></div>
<div class="stat-box"><div class="stat-value" id="statDelivered">$($stats.delivered)</div><div class="stat-label">送达包数</div></div>
</div>
</div>

<div class="tab-bar">
<div class="tab active" onclick="showTab('geoip')">GeoIP 查询</div>
<div class="tab" onclick="showTab('clients')">已连接客户端</div>
<div class="tab" onclick="showTab('download')">Downloads</div>
<div class="tab" onclick="showTab('cross')">Cross-Machine Test</div>
</div>

<div id="tab-geoip" class="card tab-content">
<h2>IPv8 GeoIP 查询</h2>
<p style="color:#aaa;margin-bottom:12px">输入任意 IPv8 地址查询归属地、运营商、ASN 等信息</p>
<div class="search-box">
<input type="text" id="geoInput" placeholder="Enter IPv8 地址, e.g. fb14::1" value="" placeholder="Enter IPv8 地址 to query...">
<button class="btn btn-sm" onclick="lookupGeo()">查询</button>
</div>
<div id="geoResult"></div>
</div>

<div id="tab-clients" class="card tab-content" style="display:none">
<h2>已连接客户端</h2>
<p style="color:#aaa;margin-bottom:12px">由 DHCP 系统自动分配的 IPv8 地址</p>
$clientsHtml
</div>

<div id="tab-download" class="card tab-content" style="display:none">
<h2>客户端下载</h2>
<table><tr><th>文件</th><th>大小</th><th>类型</th></tr>$filesHtml</table>
<div class="center" style="margin-top:16px">
<a href="/api/client-package" class="btn">下载自动连接客户端 (ZIP)</a>
</div>
</div>

<div id="tab-cross" class="card tab-content" style="display:none">
<h2>跨机真网测试</h2>
<p style="color:#aaa;margin-bottom:12px">直接在网页上发起测试，本机作为 A 端（主动），对端作为 B 端（被动等待）</p>
<div style="background:#0a0e27;padding:16px;border-radius:8px;border:1px solid #1e2444;margin-bottom:12px">
<p style="color:#4caf50;margin-bottom:8px">输入<strong>对端机器</strong>的 IP 地址（不是本机 IP），点击开始测试：</p>
<div class="search-box">
<input type="text" id="crossPeerIp" placeholder="输入对端 IP，例如 2409:8938::1 或 192.168.1.12" value="" style="flex:1">
<input type="number" id="crossPeerPort" placeholder="端口" value="45801" style="width:100px">
<button class="btn btn-sm" onclick="startCrossTest()" id="crossStartBtn">开始测试</button>
</div>
<div id="crossMyIp" style="margin-top:8px;padding:8px;background:#0d1224;border-radius:6px;border:1px solid #1e2444"></div>
<div id="crossStatus" style="margin-top:8px"></div>
<div id="crossResult" style="margin-top:8px"></div>
</div>
<div style="background:#0a0e27;padding:12px;border-radius:8px;border:1px solid #1e2444;margin-top:12px">
<p style="color:#888;font-size:0.85em">说明：本机作为 A 端主动发起连接，对端需要先运行 B 端（被动等待模式）。每台机器有自己的公网 IPv6，互不相同。端口默认 45801，两台机器可以共用一个端口。</p>
</div>
</div>

<div class="card">
<h2>服务器信息</h2>
<div class="info-grid">
<div class="info-item"><div class="label">域名</div><div class="value">ipv8.yulaoshi.xyz</div></div>
<div class="info-item"><div class="label">IPv8 域名</div><div class="value">portal.ipv8.net</div></div>
<div class="info-item"><div class="label">公网 IPv6</div><div class="value">$ipv6</div></div>
<div class="info-item"><div class="label">IPv8 地址</div><div class="value">$ipv8Self</div></div>
<div class="info-item"><div class="label">协议</div><div class="value">IPv8+ Phase 5</div></div>
<div class="info-item"><div class="label">DNS / DHCP</div><div class="value">127.0.0.1:$DnsPort / Auto</div></div>
</div>
</div>

<div class="card">
<h2>防火墙管理</h2>
<p style="color:#aaa;margin-bottom:12px">放行外部用户连接请求，让外部可以访问 IPv8+ 服务</p>
<div style="display:flex;gap:8px;margin-bottom:12px">
<button class="btn btn-sm" onclick="firewallAction('open')">放行端口</button>
<button class="btn btn-sm" onclick="firewallAction('close')">关闭所有规则</button>
<button class="btn btn-sm" onclick="firewallAction('status')">查看状态</button>
</div>
<div id="firewallResult" style="margin-top:8px"></div>
</div>

<div class="footer">IPv8+ 协议 | yulaoshi.xyz 2026</div>
</div>

<script>
function showTab(name) {
document.querySelectorAll('.tab-content').forEach(e => e.style.display='none');
document.querySelectorAll('.tab').forEach(e => e.classList.remove('active'));
document.getElementById('tab-'+name).style.display='';
event.target.classList.add('active');
}
function lookupGeo() {
var input=document.getElementById('geoInput').value.trim();
var r=document.getElementById('geoResult');
r.innerHTML='<div style="color:#666;padding:8px">Querying...</div>';
fetch('/api/geoip?ip='+encodeURIComponent(input)).then(r=>r.json()).then(d=>{
if(d.error){r.innerHTML='<div style="color:#f44;padding:8px">'+d.error+'</div>';return}
var rows=[['IP 地址',d.ip],['版本','IPv8+'],['国家',d.country],['省份',d.province],['城市',d.city],['区县',d.district],['邮编',d.zipcode],['区号',d.areacode],['ISP',d.isp],['ASN',d.asn],['组织',d.organization],['纬度',d.latitude],['经度',d.longitude],['用途',d.purpose],['操作者',d.operator],['网络类型',d.network_type],['备注',d.notes]];
var h='<table style="width:100%">';
rows.forEach(function(row){var v=row[1]||'';var c=v&&v!=='-'?'':' empty';h+='<tr><td style="color:#666;width:120px;font-size:0.9em">'+row[0]+'</td><td style="color:'+(c?'#444':'#00d4ff')+';font-family:monospace">'+(v||'-')+'</td></tr>'});
h+='</table>';r.innerHTML=h;
}).catch(e=>{r.innerHTML='<div style="color:#f44;padding:8px">Error: '+e+'</div>'});
}
window.onload=function(){setInterval(updateStats,5000);loadMyIp();};
function loadMyIp(){
fetch('/api/my-ip').then(r=>r.json()).then(d=>{
var box=document.getElementById('crossMyIp');
var html='<div style="color:#666;font-size:0.85em;margin-bottom:4px">本机 IP（告诉对端用这个连你）：</div>';
html+='<div style="display:flex;gap:12px;flex-wrap:wrap">';
if(d.ipv6){html+='<span style="color:#00d4ff;font-family:monospace">IPv6: '+d.ipv6+'</span>';}
if(d.ipv4){html+='<span style="color:#888;font-family:monospace">IPv4: '+d.ipv4+'</span>';}
if(!d.ipv6&&!d.ipv4){html+='<span style="color:#f44">未检测到公网 IP</span>';}
html+='</div>';
box.innerHTML=html;
}).catch(()=>{document.getElementById('crossMyIp').innerHTML='<span style="color:#666">获取 IP 失败</span>';});
}
function startCrossTest(){
var ip=document.getElementById('crossPeerIp').value.trim();
var port=document.getElementById('crossPeerPort').value.trim()||'45801';
var btn=document.getElementById('crossStartBtn');
var st=document.getElementById('crossStatus');
var rs=document.getElementById('crossResult');
btn.disabled=true;btn.textContent='测试中...';
st.innerHTML='<div style="color:#00d4ff;padding:8px">正在启动测试... 对端 '+ip+':'+port+'</div>';
rs.innerHTML='';
fetch('/api/cross-test?ip='+encodeURIComponent(ip)+'&port='+port).then(r=>r.json()).then(d=>{
if(d.status==='running'){
st.innerHTML='<div style="color:#ff9800;padding:8px">测试运行中... 等待结果</div>';
var t=setInterval(function(){
fetch('/api/cross-test-status').then(r=>r.json()).then(s=>{
if(s.status==='running'){
st.innerHTML='<div style="color:#ff9800;padding:8px">测试运行中... '+s.elapsed+'s</div>';
if(s.output){rs.innerHTML='<pre style="color:#4caf50;font-family:monospace;font-size:0.9em;white-space:pre-wrap">'+s.output+'</pre>';}
}else if(s.status==='pass'){
st.innerHTML='<div style="color:#4caf50;padding:8px;font-size:1.2em">✅ 测试通过 PASS</div>';
if(s.output){rs.innerHTML='<pre style="color:#4caf50;font-family:monospace;font-size:0.9em;white-space:pre-wrap">'+s.output+'</pre>';}
btn.disabled=false;btn.textContent='开始测试';
clearInterval(t);
}else if(s.status==='fail'){
st.innerHTML='<div style="color:#f44;padding:8px;font-size:1.2em">❌ 测试失败 FAIL</div>';
if(s.output){rs.innerHTML='<pre style="color:#f88;font-family:monospace;font-size:0.9em;white-space:pre-wrap">'+s.output+'</pre>';}
btn.disabled=false;btn.textContent='开始测试';
clearInterval(t);
}else if(s.status==='idle'){
st.innerHTML='<div style="color:#666;padding:8px">测试已结束</div>';
btn.disabled=false;btn.textContent='开始测试';
clearInterval(t);
}
}).catch(()=>{});
},2000);
}else if(d.error){
st.innerHTML='<div style="color:#f44;padding:8px">错误: '+d.error+'</div>';
btn.disabled=false;btn.textContent='开始测试';
}
}).catch(e=>{
st.innerHTML='<div style="color:#f44;padding:8px">请求失败: '+e+'</div>';
btn.disabled=false;btn.textContent='开始测试';
});
}
function updateStats(){fetch('/api/stats').then(r=>r.json()).then(d=>{document.getElementById('statClients').textContent=d.clients;document.getElementById('statUptime').textContent=d.uptime+'s';document.getElementById('statSealed').textContent=d.sealed;document.getElementById('statDelivered').textContent=d.delivered;}).catch(()=>{});}
function firewallAction(action){
var box=document.getElementById('firewallResult');
box.innerHTML='<div style="color:#666;padding:8px">正在执行...</div>';
fetch('/api/firewall?action='+action).then(r=>r.json()).then(d=>{
var h='<div style="color:#4caf50;padding:8px;margin-bottom:8px">'+(d.result||[]).join('<br>')+'</div>';
if(d.rules&&d.rules.length>0){
h+='<table><tr><th>规则名称</th><th>方向</th><th>状态</th></tr>';
d.rules.forEach(function(r){h+='<tr><td style="color:#00d4ff;font-family:monospace">'+r.DisplayName+'</td><td>'+(r.Direction==1?'入站':'出站')+'</td><td>'+(r.Enabled?'<span style="color:#4caf50">启用</span>':'<span style="color:#f44">禁用</span>')+'</td></tr>';});
h+='</table>';
}
box.innerHTML=h;
}).catch(e=>{box.innerHTML='<div style="color:#f44;padding:8px">错误: '+e+'</div>';});
}
</script>
</body>
</html>
"@
    return $html
}

# ============ Request Loop ============
while ($listener.IsListening) {
    try {
        $context = $listener.GetContext()
        $request = $context.Request
        $response = $context.Response
        $path = $request.Url.AbsolutePath
        $method = $request.HttpMethod

        if ($path -eq "/" -or $path -eq "") {
            $hostHeader = $request.Headers["Host"]
            $subdomain = $null
            if ($hostHeader -match "^([a-zA-Z0-9-]+)\.ipv8\.yulaoshi\.xyz") {
                $subdomain = $Matches[1]
            } elseif ($hostHeader -match "^([a-zA-Z0-9-]+)\.ipv8\.net") {
                $subdomain = $Matches[1]
            }
            if ($subdomain -and $subdomain -ne "www" -and $subdomain -ne "ipv8") {
                $allocs = Get-AllAllocations
                $matched = $allocs | Where-Object { $_.client_name -eq $subdomain }
                if ($matched) {
                    $html = @"
<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><title>$subdomain - IPv8+ Node</title>
<style>body{font-family:system-ui;background:#0a0e27;color:#e0e0e0;text-align:center;padding:60px 20px}
h1{color:#00d4ff;font-size:2.5em}.info{color:#888;margin:20px 0;line-height:1.8}
.mono{font-family:monospace;color:#00d4ff}.badge{display:inline-block;background:#1a3a2a;color:#4caf50;padding:4px 16px;border-radius:4px;margin:4px}
</style></head><body>
<h1>$subdomain.ipv8.yulaoshi.xyz</h1>
<div class="info">IPv8 地址: <span class="mono">$($matched.ipv8_full)</span><br>
TUN IP: <span class="mono">$($matched.tun_ip)</span><br>
分配时间: $($matched.assigned_at)<br>
状态: <span class="badge">$($matched.status)</span></div>
<p style="color:#666">此客户端已连接到 IPv8+ 网络</p>
</body></html>
"@
                } else {
                    $html = @"
<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><title>IPv8+ Node Not Found</title>
<style>body{font-family:system-ui;background:#0a0e27;color:#e0e0e0;text-align:center;padding:60px 20px}
h1{color:#f44}.info{color:#888;margin:20px 0}</style></head><body>
<h1>IPv8 节点未找到</h1><div class="info">子域名 <b>$subdomain</b> 没有对应的 IPv8+ 客户端<br>请确认客户端已连接并注册</div>
<p><a href="https://ipv8.yulaoshi.xyz" style="color:#00d4ff">返回主门户</a></p>
</body></html>
"@
                }
                $buffer = [System.Text.Encoding]::UTF8.GetBytes($html)
                $response.ContentType = "text/html; charset=utf-8"
                $response.ContentLength64 = $buffer.Length
                $response.OutputStream.Write($buffer, 0, $buffer.Length)
            } else {
                $html = Build-LandingPage
                $buffer = [System.Text.Encoding]::UTF8.GetBytes($html)
                $response.ContentType = "text/html; charset=utf-8"
                $response.ContentLength64 = $buffer.Length
                $response.OutputStream.Write($buffer, 0, $buffer.Length)
            }
        }
        elseif ($path -match "^/download/(.+)$") {
            $fileName = $Matches[1]
            $filePath = Join-Path $DownloadDir $fileName
            if (Test-Path $filePath -PathType Leaf) {
                $fileBytes = [System.IO.File]::ReadAllBytes($filePath)
                $fileLen = $fileBytes.Length
                $response.AddHeader("Content-Disposition", "attachment; filename=$fileName")
                $response.AddHeader("Accept-Ranges", "bytes")
                $response.ContentType = "application/octet-stream"
                $rangeHeader = $request.Headers["Range"]
                if ($rangeHeader -and $rangeHeader -match "bytes=(\d+)-(\d*)") {
                    $start = [int64]$Matches[1]
                    $end = if ($Matches[2]) { [int64]$Matches[2] } else { $fileLen - 1 }
                    if ($end -ge $fileLen) { $end = $fileLen - 1 }
                    $chunkLen = $end - $start + 1
                    $response.StatusCode = 206
                    $response.AddHeader("Content-Range", "bytes $start-$end/$fileLen")
                    $response.ContentLength64 = $chunkLen
                    $response.OutputStream.Write($fileBytes, $start, $chunkLen)
                    Write-Host "  Sent (206): $fileName [$start-$end] ($chunkLen bytes)" -ForegroundColor Cyan
                } else {
                    $response.ContentLength64 = $fileLen
                    $response.OutputStream.Write($fileBytes, 0, $fileLen)
                    Write-Host "  Sent (200): $fileName ($fileLen bytes)" -ForegroundColor Cyan
                }
            } else {
                $response.StatusCode = 404
                $buffer = [System.Text.Encoding]::UTF8.GetBytes("404: $fileName")
                $response.OutputStream.Write($buffer, 0, $buffer.Length)
            }
        }
        elseif ($path -eq "/api/geoip") {
            $queryIp = $request.QueryString["ip"]
            if (-not $queryIp) { $queryIp = $ipv8Self }
            $record = Lookup-GeoIP $queryIp
            $result = if ($record) {
                @{ip=$queryIp;version="IPv8+";country=$record.country;province=$record.province;city=$record.city;district=$record.district;zipcode=$record.zipcode;areacode=$record.areacode;isp=$record.isp;asn=$record.asn;organization=$record.organization;latitude=$record.latitude;longitude=$record.longitude;purpose=$record.purpose;operator=$record.operator;network_type=$record.network_type;notes=$record.notes}
            } else {
                @{ip=$queryIp;version="IPv8+";error="Not in database";country="-";province="-";city="-";district="-";zipcode="-";areacode="-";isp="-";asn="-";organization="-";latitude="-";longitude="-";purpose="-";operator="-";network_type="-";notes="-"}
            }
            $json = $result | ConvertTo-Json
            $buffer = [System.Text.Encoding]::UTF8.GetBytes($json)
            $response.ContentType = "application/json; charset=utf-8"
            $response.ContentLength64 = $buffer.Length
            $response.OutputStream.Write($buffer, 0, $buffer.Length)
            Write-Host "  GeoIP: $queryIp -> $($record.city)" -ForegroundColor Cyan
        }
        elseif ($path -eq "/api/stats") {
            $stats = Get-NodeStats
            $json = $stats | ConvertTo-Json
            $buffer = [System.Text.Encoding]::UTF8.GetBytes($json)
            $response.ContentType = "application/json; charset=utf-8"
            $response.ContentLength64 = $buffer.Length
            $response.OutputStream.Write($buffer, 0, $buffer.Length)
        }
        elseif ($path -eq "/api/clients") {
            $allocs = Get-AllAllocations
            $json = $allocs | ConvertTo-Json
            $buffer = [System.Text.Encoding]::UTF8.GetBytes($json)
            $response.ContentType = "application/json; charset=utf-8"
            $response.ContentLength64 = $buffer.Length
            $response.OutputStream.Write($buffer, 0, $buffer.Length)
        }
        elseif ($path -eq "/api/allocate" -and $method -eq "POST") {
            $body = New-Object System.IO.StreamReader $request.InputStream
            $bodyStr = $body.ReadToEnd()
            $bodyObj = $bodyStr | ConvertFrom-Json
            $clientIp = $bodyObj.client_ip
            $clientName = $bodyObj.client_name
            $alloc = Allocate-IPv8Address $clientIp $clientName
            $json = $alloc | ConvertTo-Json
            $buffer = [System.Text.Encoding]::UTF8.GetBytes($json)
            $response.ContentType = "application/json; charset=utf-8"
            $response.ContentLength64 = $buffer.Length
            $response.OutputStream.Write($buffer, 0, $buffer.Length)
            Write-Host "  Allocated: $($alloc.ipv8_compact) to $clientIp" -ForegroundColor Green
        }
        elseif ($path -eq "/api/client-package") {
            $clientIp = $request.QueryString["ip"]
            if (-not $clientIp) { $clientIp = $request.RemoteEndPoint.Address.ToString() }
            $alloc = Allocate-IPv8Address $clientIp
            $launcherScript = Build-ClientLauncher $alloc

            $tempDir = Join-Path $env:TEMP "ipv8-client-package"
            New-Item -ItemType Directory -Force -Path $tempDir | Out-Null
            $launcherPath = Join-Path $tempDir "start-ipv8-client.ps1"
            [System.IO.File]::WriteAllText($launcherPath, $launcherScript, [System.Text.Encoding]::UTF8)

            # Copy node exe and dll
            $srcExe = Join-Path $DownloadDir "ipv8-node.exe"
            $srcDll = Join-Path $DownloadDir "wintun.dll"
            if (Test-Path $srcExe) { Copy-Item $srcExe $tempDir -Force }
            if (Test-Path $srcDll) { Copy-Item $srcDll $tempDir -Force }

            # Create ZIP
            $zipPath = Join-Path $env:TEMP "ipv8-client-auto.zip"
            if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
            Compress-Archive -Path "$tempDir\*" -DestinationPath $zipPath -Force

            $zipBytes = [System.IO.File]::ReadAllBytes($zipPath)
            $zipLen = $zipBytes.Length
            $response.ContentType = "application/zip"
            $response.AddHeader("Content-Disposition", "attachment; filename=ipv8-client-auto.zip")
            $response.AddHeader("Accept-Ranges", "bytes")
            $rangeHeader = $request.Headers["Range"]
            if ($rangeHeader -and $rangeHeader -match "bytes=(\d+)-(\d*)") {
                $start = [int64]$Matches[1]
                $end = if ($Matches[2]) { [int64]$Matches[2] } else { $zipLen - 1 }
                if ($end -ge $zipLen) { $end = $zipLen - 1 }
                $chunkLen = $end - $start + 1
                $response.StatusCode = 206
                $response.AddHeader("Content-Range", "bytes $start-$end/$zipLen")
                $response.ContentLength64 = $chunkLen
                $response.OutputStream.Write($zipBytes, $start, $chunkLen)
                Write-Host "  Client package sent (206) [$start-$end] ($chunkLen bytes)" -ForegroundColor Green
            } else {
                $response.ContentLength64 = $zipLen
                $response.OutputStream.Write($zipBytes, 0, $zipLen)
                Write-Host "  Client package sent ($zipLen bytes)" -ForegroundColor Green
            }

            Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
        }
        elseif ($path -eq "/api/resolve") {
            $hostname = $request.QueryString["host"]
            if (-not $hostname) { $hostname = "portal.ipv8.net" }
            $resolvedIp = $null
            if ($hostname -eq "portal.ipv8.net" -or $hostname -eq "ipv8.yulaoshi.xyz") {
                $resolvedIp = Get-ServerIPv6
                if (-not $resolvedIp) { $resolvedIp = Get-ServerIPv4 }
            }
            $allocs = Get-AllAllocations
            foreach ($a in $allocs) {
                if ($a.client_name -and "$($a.client_name).ipv8.net" -eq $hostname) {
                    $resolvedIp = $a.client_ip
                    break
                }
            }
            if (-not $resolvedIp) { $resolvedIp = "127.0.0.1" }
            $json = @{host=$hostname;ip=$resolvedIp} | ConvertTo-Json
            $buffer = [System.Text.Encoding]::UTF8.GetBytes($json)
            $response.ContentType = "application/json; charset=utf-8"
            $response.ContentLength64 = $buffer.Length
            $response.OutputStream.Write($buffer, 0, $buffer.Length)
        }
        elseif ($path -eq "/api/firewall") {
            $action = $request.QueryString["action"]
            if (-not $action) { $action = "status" }
            $rules = @()
            $existingRules = Get-NetFirewallRule -DisplayName "IPv8+*" -ErrorAction SilentlyContinue
            if ($action -eq "open") {
                $ports = @(45801, 45800, 9001, 5353)
                foreach ($port in $ports) {
                    $ruleName = "IPv8+ Port $port UDP"
                    if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
                        New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol UDP -LocalPort $port -Action Allow -Profile Any | Out-Null
                    }
                    $ruleName = "IPv8+ Port $port TCP"
                    if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
                        New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP -LocalPort $port -Action Allow -Profile Any | Out-Null
                    }
                }
                $rules += "Firewall rules opened for ports: $($ports -join ', ')"
            } elseif ($action -eq "close") {
                Get-NetFirewallRule -DisplayName "IPv8+*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
                $rules += "All IPv8+ firewall rules removed"
            }
            $current = Get-NetFirewallRule -DisplayName "IPv8+*" -ErrorAction SilentlyContinue
            $rules += "Current rules: $($current.Count)"
            $json = @{action=$action;result=$rules;rules=@($current | Select-Object DisplayName,Enabled,Direction)} | ConvertTo-Json -Depth 3
            $buffer = [System.Text.Encoding]::UTF8.GetBytes($json)
            $response.ContentType = "application/json; charset=utf-8"
            $response.ContentLength64 = $buffer.Length
            $response.OutputStream.Write($buffer, 0, $buffer.Length)
            Write-Host "  Firewall: $action" -ForegroundColor Cyan
        }
        elseif ($path -eq "/api/status") {
            $ipv6 = Get-ServerIPv6
            $stats = Get-NodeStats
            $json = @{domain="ipv8.yulaoshi.xyz";ipv8=$ipv8Self;ipv6=$ipv6;status="online";dns="127.0.0.1:$DnsPort";clients=$stats.clients} | ConvertTo-Json
            $buffer = [System.Text.Encoding]::UTF8.GetBytes($json)
            $response.ContentType = "application/json; charset=utf-8"
            $response.ContentLength64 = $buffer.Length
            $response.OutputStream.Write($buffer, 0, $buffer.Length)
        }
        elseif ($path -eq "/api/my-ip") {
            $ipv6 = Get-ServerIPv6
            $ipv4 = Get-ServerIPv4
            $json = @{ipv6=$ipv6;ipv4=$ipv4} | ConvertTo-Json
            $buffer = [System.Text.Encoding]::UTF8.GetBytes($json)
            $response.ContentType = "application/json; charset=utf-8"
            $response.ContentLength64 = $buffer.Length
            $response.OutputStream.Write($buffer, 0, $buffer.Length)
        }
        elseif ($path -eq "/api/cross-test") {
            $peerIp = $request.QueryString["ip"]
            $peerPort = $request.QueryString["port"]
            if (-not $peerPort) { $peerPort = "45801" }
            if (-not $peerIp) {
                $json = '{"error":"missing ip parameter"}'
                $buffer = [System.Text.Encoding]::UTF8.GetBytes($json)
                $response.ContentType = "application/json; charset=utf-8"
                $response.ContentLength64 = $buffer.Length
                $response.OutputStream.Write($buffer, 0, $buffer.Length)
                $response.Close()
                continue
            }
            $script:crossTestOutput = ""
            $script:crossTestStatus = "running"
            $script:crossTestStart = Get-Date
            $nodeExe = Join-Path $projectRoot "target\release\ipv8-node.exe"
            if (-not (Test-Path $nodeExe)) {
                $nodeExe = Join-Path $DownloadDir "ipv8-node.exe"
            }
            if (-not (Test-Path $nodeExe)) {
                $json = '{"error":"ipv8-node.exe not found"}'
                $buffer = [System.Text.Encoding]::UTF8.GetBytes($json)
                $response.ContentType = "application/json; charset=utf-8"
                $response.ContentLength64 = $buffer.Length
                $response.OutputStream.Write($buffer, 0, $buffer.Length)
                $response.Close()
                continue
            }
            $selfAddr = "0000fb140000000a0001000001000000"
            $peerAddr = "0000fb140000000b0001000001000000"
            $udpPort = Get-Random -Minimum 46000 -Maximum 46999
            $argList = @("--self",$selfAddr,"--peer-addr",$peerAddr,"--peer-ip",$peerIp,"--peer-port",$peerPort,"--udp-port",$udpPort,"--tun-ip","10.100.0.1","--tun-prefix","10","--adapter-name","IPv8Plus","--initiate","--no-tun","--nt-size","16")
            $script:crossTestJob = Start-Job -ScriptBlock {
                param($exe,$a)
                $p = Start-Process $exe -ArgumentList $a -NoNewWindow -Wait -PassThru -RedirectStandardOutput "$env:TEMP\ipv8-cross-stdout.txt" -RedirectStandardError "$env:TEMP\ipv8-cross-stderr.txt"
                $out = Get-Content "$env:TEMP\ipv8-cross-stdout.txt" -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
                $err = Get-Content "$env:TEMP\ipv8-cross-stderr.txt" -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
                return @{stdout=$out;stderr=$err;exitcode=$p.ExitCode}
            } -ArgumentList $nodeExe,$argList
            $json = '{"status":"running"}'
            $buffer = [System.Text.Encoding]::UTF8.GetBytes($json)
            $response.ContentType = "application/json; charset=utf-8"
            $response.ContentLength64 = $buffer.Length
            $response.OutputStream.Write($buffer, 0, $buffer.Length)
            Write-Host "  Cross-test started: $peerIp`:$peerPort" -ForegroundColor Cyan
        }
        elseif ($path -eq "/api/cross-test-status") {
            $status = "idle"
            $output = ""
            $elapsed = 0
            if ($script:crossTestJob) {
                $elapsed = [math]::Round(((Get-Date) - $script:crossTestStart).TotalSeconds)
                if ($script:crossTestJob.State -eq "Completed") {
                    $result = Receive-Job $script:crossTestJob
                    Remove-Job $script:crossTestJob -Force
                    $script:crossTestJob = $null
                    $output = $result.stdout
                    if ($result.stderr) { $output += "`n" + $result.stderr }
                    if ($result.exitcode -eq 0 -and $output -match "PASS") {
                        $status = "pass"
                    } else {
                        $status = "fail"
                    }
                } elseif ($script:crossTestJob.State -eq "Running") {
                    $status = "running"
                    $tmpFile = "$env:TEMP\ipv8-cross-stdout.txt"
                    if (Test-Path $tmpFile) {
                        $output = Get-Content $tmpFile -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
                    }
                }
            }
            $json = @{status=$status;output=$output;elapsed=$elapsed} | ConvertTo-Json
            $buffer = [System.Text.Encoding]::UTF8.GetBytes($json)
            $response.ContentType = "application/json; charset=utf-8"
            $response.ContentLength64 = $buffer.Length
            $response.OutputStream.Write($buffer, 0, $buffer.Length)
        }
        else {
            $response.StatusCode = 404
            $buffer = [System.Text.Encoding]::UTF8.GetBytes("404")
            $response.OutputStream.Write($buffer, 0, $buffer.Length)
        }
        $response.Close()
    } catch {
        Write-Host "Error: $_" -ForegroundColor Red
    }
}
