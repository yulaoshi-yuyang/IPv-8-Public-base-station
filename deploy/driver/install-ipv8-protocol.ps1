#Requires -RunAsAdministrator
<#
.SYNOPSIS
    安装 IPv8 NDIS 协议驱动
.DESCRIPTION
    将 "Internet 协议版本 8 (TCP/IPv8)" 安装到系统中，
    使其出现在网络适配器属性的协议列表中（与 IPv4/IPv6 并列）。
.NOTES
    需要管理员权限运行。
    驱动需要先编译生成 ipv8proto.sys 和 ipv8proto.inf。
    未签名的驱动需要开启测试模式（bcdedit /set testsigning on）。
#>

param(
    [string]$DriverPath = "."
)

$ErrorActionPreference = "Stop"

Write-Host "=== IPv8 Protocol Driver Installer ===" -ForegroundColor Cyan
Write-Host ""

# --- 检查管理员权限 ---
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
    Write-Error "需要管理员权限运行此脚本"
    exit 1
}

# --- 查找驱动文件 ---
$infPath = Join-Path $DriverPath "ipv8proto.inf"
$sysPath = Join-Path $DriverPath "ipv8proto.sys"

if (-not (Test-Path $infPath))
{
    Write-Error "找不到 INF 文件: $infPath"
    exit 1
}

if (-not (Test-Path $sysPath))
{
    Write-Error "找不到 SYS 文件: $sysPath"
    Write-Host "提示：请先用 Visual Studio + WDK 编译驱动项目" -ForegroundColor Yellow
    exit 1
}

Write-Host "[1/5] 驱动文件检查通过" -ForegroundColor Green
Write-Host "  INF: $infPath"
Write-Host "  SYS: $sysPath"

# --- 复制到驱动目录 ---
$driversDir = Join-Path $env:SystemRoot "System32\drivers"
$sysDest = Join-Path $driversDir "ipv8proto.sys"

Write-Host ""
Write-Host "[2/5] 复制驱动文件到系统目录..." -ForegroundColor Yellow
Copy-Item $sysPath $sysDest -Force
Write-Host "  已复制到: $sysDest" -ForegroundColor Green

# --- 安装协议驱动 ---
Write-Host ""
Write-Host "[3/5] 安装 NDIS 协议驱动..." -ForegroundColor Yellow

try
{
    # 使用 netcfg 安装协议
    $netcfgResult = & netcfg.exe -v -l $infPath -c p -i ms_ag1 2>&1
    $exitCode = $LASTEXITCODE

    Write-Host $netcfgResult

    if ($exitCode -ne 0)
    {
        throw "netcfg 安装失败，退出码: $exitCode"
    }
}
catch
{
    Write-Error "安装失败: $_"
    Write-Host ""
    Write-Host "常见原因：" -ForegroundColor Yellow
    Write-Host "  1. 驱动未签名 → 开启测试模式: bcdedit /set testsigning on"
    Write-Host "  2. INF 格式错误 → 检查 inf 文件语法"
    Write-Host "  3. 已安装过 → 先运行 uninstall-ipv8-protocol.ps1"
    exit 1
}

Write-Host "  协议驱动安装成功" -ForegroundColor Green

# --- 绑定到所有物理网卡 ---
Write-Host ""
Write-Host "[4/5] 绑定到网络适配器..." -ForegroundColor Yellow

$adapters = Get-NetAdapter -Physical | Where-Object { $_.Status -eq "Up" }

if ($adapters.Count -eq 0)
{
    Write-Warning "没有找到活动的物理网卡，跳过自动绑定"
}
else
{
    foreach ($adapter in $adapters)
    {
        try
        {
            # 尝试启用 IPv8 协议绑定
            Enable-NetAdapterBinding -Name $adapter.Name -ComponentID ms_ag1 -ErrorAction Stop
            Write-Host "  已绑定到: $($adapter.Name)" -ForegroundColor Green
        }
        catch
        {
            Write-Warning "  绑定 $($adapter.Name) 失败: $_"
        }
    }
}

# --- 验证 ---
Write-Host ""
Write-Host "[5/5] 验证安装..." -ForegroundColor Yellow

$found = $false
$adaptersAll = Get-NetAdapter -Physical -ErrorAction SilentlyContinue
foreach ($adapter in $adaptersAll)
{
    $binding = Get-NetAdapterBinding -Name $adapter.Name -ComponentID ms_ag1 -ErrorAction SilentlyContinue
    if ($binding)
    {
        Write-Host "  $($adapter.Name): $($binding.Enabled)"
        $found = $true
    }
}

if ($found)
{
    Write-Host ""
    Write-Host "=== 安装成功 ===" -ForegroundColor Green
    Write-Host ""
    Write-Host "现在你可以："
    Write-Host "  1. 打开 网络连接 → 右键网卡 → 属性"
    Write-Host "  2. 看到 'Internet 协议版本 8 (TCP/IPv8)' 在列表中"
    Write-Host "  3. 可以勾选/取消勾选来启用或禁用"
    Write-Host ""
    Write-Host "如果没看到，尝试重启电脑或刷新网络连接。" -ForegroundColor Yellow
}
else
{
    Write-Warning "未找到 IPv8 协议绑定，可能需要重启后生效"
}
