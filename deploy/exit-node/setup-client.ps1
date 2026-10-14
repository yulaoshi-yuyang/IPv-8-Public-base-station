# 是什么：IPv8+ exit-node 客户侧一次性配置（普通 mesh 节点，整机 v4 默认经 exit 出网）
# 输入：-ExitTunIp exit 的 100.64 地址；-ExitPublicIp exit 外层 IP；-Metric 路由跃点（默认 5）；-Undo 撤销
# 输出：0.0.0.0/0 经隧道（仅活动库，重启自动消失）+ 防递归 /32 pin（持久）
#Requires -RunAsAdministrator
param(
    [Parameter(Mandatory = $true)][string]$ExitTunIp,
    [Parameter(Mandatory = $true)][string]$ExitPublicIp,
    [int]$Metric = 5,
    [string]$WintunAlias = "IPv8Plus",
    [switch]$Undo
)
$ErrorActionPreference = "Stop"

if ($Undo) {
    Remove-NetRoute -DestinationPrefix "0.0.0.0/0" -InterfaceAlias $WintunAlias -Confirm:$false -ErrorAction SilentlyContinue
    Remove-NetRoute -DestinationPrefix "$ExitPublicIp/32" -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "已撤销：隧道默认路由 + $ExitPublicIp/32 pin"
    return
}

$tun = Get-NetAdapter -Name $WintunAlias -ErrorAction SilentlyContinue
if (-not $tun -or $tun.Status -ne 'Up') { throw "wintun 适配器 $WintunAlias 不存在或未 Up——先启动 ipv8-node" }

# 前置：隧道本身得通，否则配了默认路由就是自我断网
$pingOk = @(Test-Connection -ComputerName $ExitTunIp -Count 3 -ErrorAction SilentlyContinue).Count
if ($pingOk -eq 0) { throw "隧道内 ping $ExitTunIp 不通（0/3）——先确认节点握手成功" }
Write-Host "隧道连通：ping $ExitTunIp $pingOk/3"

# 防路由递归 pin：节点外层 UDP 到 exit 必须走物理出口，否则默认路由进隧道后把隧道自己也套进去。
# Find-NetRoute 命中默认路由 → 经物理网关加 /32 持久 pin；命中更具体路由（如 on-link LAN）→ 外层本就不经隧道，跳过
$r = Find-NetRoute -RemoteIPAddress $ExitPublicIp -ErrorAction Stop | Select-Object -First 1
if ($r.DestinationPrefix -eq '0.0.0.0/0') {
    Remove-NetRoute -DestinationPrefix "$ExitPublicIp/32" -Confirm:$false -ErrorAction SilentlyContinue
    New-NetRoute -DestinationPrefix "$ExitPublicIp/32" -InterfaceIndex $r.InterfaceIndex -NextHop $r.NextHop -RouteMetric 1 | Out-Null
    Write-Host "已加防递归 pin：$ExitPublicIp/32 via $($r.NextHop)（持久，重启后外层仍通）"
} else {
    Write-Host "$ExitPublicIp 走 $($r.DestinationPrefix)（比默认路由具体），外层天然不经隧道，跳过 pin"
}

# 隧道默认路由：仅写活动库（重启/网卡重建自动消失，防启动黑洞），幂等先删后加
Remove-NetRoute -DestinationPrefix "0.0.0.0/0" -InterfaceAlias $WintunAlias -Confirm:$false -ErrorAction SilentlyContinue
New-NetRoute -DestinationPrefix "0.0.0.0/0" -InterfaceAlias $WintunAlias -NextHop $ExitTunIp -RouteMetric $Metric -PolicyStore ActiveStore | Out-Null
Write-Host "默认路由已指向 $ExitTunIp（metric $Metric，仅活动库）"
Write-Host "client 侧配置完成——整机 v4 默认经 exit 出网"
