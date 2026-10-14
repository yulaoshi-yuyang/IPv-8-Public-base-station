# 是什么：IPv8+ exit-node 出口侧一次性配置（Windows Server 云机）
# 输入：-ShapeKbps 出向整形速率 kbps（默认 2800，0=跳过）；-Undo 撤销全部
# 输出：IPv4 转发开启 + WinNAT(mesh 段 MASQUERADE 出公网) + QoS 出向整形；幂等
#Requires -RunAsAdministrator
param(
    [int]$ShapeKbps = 2800,
    [string]$NatName = "IPv8Exit",
    [string]$MeshPrefix = "100.64.0.0/10",
    [switch]$Undo
)
$ErrorActionPreference = "Stop"

if ($Undo) {
    Remove-NetQosPolicy -Name "IPv8ExitShape-Down", "IPv8ExitShape-Up" -Confirm:$false -ErrorAction SilentlyContinue
    Remove-NetNat -Name $NatName -Confirm:$false -ErrorAction SilentlyContinue
    # 撤销转发=关掉所有处于 Enabled 的接口。云机专职 exit，无"原本就开"的第三方用途；
    # 若未来一机多职，这里要改成只关记录过的接口
    Get-NetIPInterface -AddressFamily IPv4 | Where-Object { $_.Forwarding -eq 'Enabled' } |
        Set-NetIPInterface -Forwarding Disabled -ErrorAction SilentlyContinue
    Write-Host "已撤销：QoS 整形 / WinNAT($NatName) / IPv4 转发"
    return
}

# 1. IPv4 转发：Set-NetIPInterface 即时生效免重启，替代注册表 IPEnableRouter（要重启）。
#    wintun 入向 + 上行出向都要开；云机专职 exit，直接全接口开
Get-NetIPInterface -AddressFamily IPv4 | Set-NetIPInterface -Forwarding Enabled
$fwdCount = @(Get-NetIPInterface -AddressFamily IPv4 | Where-Object Forwarding -eq 'Enabled').Count
Write-Host "IPv4 转发已启用：$fwdCount 个接口（免重启）"

# 2. WinNAT：mesh 段源地址 MASQUERADE 出公网（Tailscale exit-node 同语义）
#    未验证项：WinNAT 对 wintun 源流量的 NAT 未在云机实测过。若 NAT 不生效，
#    fallback = RRAS（Install-WindowsFeature RemoteAccess + NAT 角色），换实现不换语义
$nat = Get-NetNat -Name $NatName -ErrorAction SilentlyContinue
if ($nat -and $nat.InternalIPInterfaceAddressPrefix -ne $MeshPrefix) {
    Remove-NetNat -Name $NatName -Confirm:$false
    $nat = $null
}
if (-not $nat) {
    New-NetNat -Name $NatName -InternalIPInterfaceAddressPrefix $MeshPrefix | Out-Null
    Write-Host "WinNAT 已创建：$NatName（内部前缀 $MeshPrefix）"
} else {
    Write-Host "WinNAT 已存在且前缀匹配，跳过"
}

# 3. QoS 出向整形：云机 3M 峰值要保隧道信令，legacy v4 数据流压到阈值内、超额 TCP 自降速。
#    Down = 回包进隧道（dst=mesh）；Up = 客户流量出公网（src=mesh）。
#    默认 2800kbps ≈ 3M 留信令余量；-ShapeKbps 0 跳过（实验室/不测速场景）
if ($ShapeKbps -gt 0) {
    $bps = [uint64]$ShapeKbps * 1000
    Remove-NetQosPolicy -Name "IPv8ExitShape-Down", "IPv8ExitShape-Up" -Confirm:$false -ErrorAction SilentlyContinue
    New-NetQosPolicy -Name "IPv8ExitShape-Down" -IPDstPrefixMatchCondition $MeshPrefix -ThrottleRateActionBitsPerSecond $bps | Out-Null
    New-NetQosPolicy -Name "IPv8ExitShape-Up"   -IPSrcPrefixMatchCondition $MeshPrefix -ThrottleRateActionBitsPerSecond $bps | Out-Null
    Write-Host "QoS 整形：双向各 ${ShapeKbps}kbps"
} else {
    Write-Host "ShapeKbps=0，跳过 QoS 整形"
}
Write-Host "exit-node 出口侧配置完成"
