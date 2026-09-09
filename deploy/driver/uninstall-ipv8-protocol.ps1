#Requires -RunAsAdministrator
<#
.SYNOPSIS
    卸载 IPv8 NDIS 协议驱动
.DESCRIPTION
    从系统中移除 "Internet 协议版本 8 (TCP/IPv8)" 协议驱动。
.NOTES
    需要管理员权限运行。
#>

$ErrorActionPreference = "Stop"

Write-Host "=== IPv8 Protocol Driver Uninstaller ===" -ForegroundColor Cyan
Write-Host ""

# --- 检查管理员权限 ---
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
    Write-Error "需要管理员权限运行此脚本"
    exit 1
}

# --- 检查是否已安装 ---
Write-Host "[1/4] 检查 IPv8 协议驱动状态..." -ForegroundColor Yellow

$installed = $false
$adapters = Get-NetAdapter -Physical -ErrorAction SilentlyContinue
foreach ($adapter in $adapters)
{
    $binding = Get-NetAdapterBinding -Name $adapter.Name -ComponentID ms_ag1 -ErrorAction SilentlyContinue
    if ($binding)
    {
        Write-Host "  找到绑定: $($adapter.Name) - Enabled=$($binding.Enabled)"
        $installed = $true
    }
}

if (-not $installed)
{
    Write-Warning "未检测到 IPv8 协议驱动，可能已经卸载了"
}

# --- 解除所有绑定 ---
Write-Host ""
Write-Host "[2/4] 解除所有适配器绑定..." -ForegroundColor Yellow

foreach ($adapter in $adapters)
{
    try
    {
        Disable-NetAdapterBinding -Name $adapter.Name -ComponentID ms_ag1 -ErrorAction Stop
        Write-Host "  已解绑: $($adapter.Name)" -ForegroundColor Green
    }
    catch
    {
        # 可能本来就没绑定，忽略
    }
}

# --- 卸载协议驱动 ---
Write-Host ""
Write-Host "[3/4] 卸载 NDIS 协议驱动..." -ForegroundColor Yellow

try
{
    $result = & netcfg.exe -u ms_ag1 2>&1
    $exitCode = $LASTEXITCODE
    Write-Host $result

    if ($exitCode -ne 0)
    {
        Write-Warning "netcfg 卸载返回码 $exitCode（可能已经卸载了）"
    }
    else
    {
        Write-Host "  协议驱动卸载成功" -ForegroundColor Green
    }
}
catch
{
    Write-Warning "卸载过程出错: $_"
}

# --- 清理驱动文件 ---
Write-Host ""
Write-Host "[4/4] 清理驱动文件..." -ForegroundColor Yellow

$sysPath = Join-Path $env:SystemRoot "System32\drivers\ipv8proto.sys"
if (Test-Path $sysPath)
{
    try
    {
        Remove-Item $sysPath -Force -ErrorAction Stop
        Write-Host "  已删除: $sysPath" -ForegroundColor Green
    }
    catch
    {
        Write-Warning "  删除驱动文件失败: $_"
        Write-Host "  重启后再删也可以" -ForegroundColor Yellow
    }
}
else
{
    Write-Host "  驱动文件不存在，跳过"
}

Write-Host ""
Write-Host "=== 卸载完成 ===" -ForegroundColor Green
Write-Host ""
Write-Host "建议重启电脑以确保完全清理干净。" -ForegroundColor Yellow
