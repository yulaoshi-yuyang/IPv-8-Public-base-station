#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Phase 5A 驱动卸载（停驱动 → 反注册属性页 COM → netcfg 移除协议组件
    → 清残留服务，需提权）。
.NOTES
    幂等：未安装时给出提示但不报错。
#>
$ErrorActionPreference = 'Continue'

$clsid     = '{7E5F3A9C-1D64-4B2E-9C38-A50F8E2D6B71}'
$propDll   = Join-Path $env:SystemRoot 'System32\ipv8prop.dll'
$regSvr    = Join-Path $env:SystemRoot 'System32\regsvr32.exe'
$clsidRoot = 'HKLM:\SOFTWARE\Classes\CLSID'

# ---- 1) 先停驱动（释放文件占用，确保 netcfg 可干净移除）----
$svc = Get-Service -Name IPv8Proto -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq 'Running') {
    Write-Host '停止驱动 IPv8Proto...'
    sc.exe stop IPv8Proto | Out-Null
    Start-Sleep -Milliseconds 500
}

# ---- 2) 反注册属性页 COM（必须趁 dll 还在，netcfg 卸载前做）----
Write-Host '== 反注册属性页 COM ==' -ForegroundColor Cyan
if (Test-Path $propDll) {
    & $regSvr /u /s $propDll
    Write-Host '已调用 ipv8prop.dll 反注册。'
} else {
    Write-Host 'ipv8prop.dll 已不在 System32，改用注册表兜底清理。'
}
# 兜底：dll 缺失或反注册失败时直接删 CLSID 键（先子键后主键）
$clsidKey = Join-Path $clsidRoot $clsid
Remove-Item -Path (Join-Path $clsidKey 'InprocServer32') -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path $clsidKey -Recurse -Force -ErrorAction SilentlyContinue

# ---- 3) netcfg 移除协议组件 ----
Write-Host '== netcfg 卸载 IPv8Proto ==' -ForegroundColor Cyan
netcfg -u IPv8Proto
if ($LASTEXITCODE -ne 0) {
    Write-Warning "netcfg 卸载返回 $LASTEXITCODE（组件可能本就未安装）"
}

# ---- 4) 残留服务清理（netcfg 正常时会一并删除）----
$svc = Get-Service -Name IPv8Proto -ErrorAction SilentlyContinue
if ($svc) {
    Write-Host '清理残留服务 IPv8Proto...'
    sc.exe delete IPv8Proto | Out-Null
}

# ---- 5) 跨语言校验 ----
Write-Host ''
$still = (netcfg -q IPv8Proto 2>&1 | Out-String)
$code  = $LASTEXITCODE
if (($code -eq 0) -and ($still -notmatch 'not installed|尚未安装|未安装')) {
    Write-Warning '组件仍显示已安装，可能需要重启后重试。'
} else {
    Write-Host '卸载完成：IPv8Proto 已移除。' -ForegroundColor Green
}
