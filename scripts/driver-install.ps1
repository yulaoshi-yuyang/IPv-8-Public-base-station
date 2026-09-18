#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Phase 5A 驱动安装（netcfg 协议组件安装，需提权）。
.NOTES
    幂等：已安装则先卸载再装。前置：测试签名模式（bcdedit /set testsigning on）。
#>
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$dist = Join-Path $root 'dist\driver'
$inf  = Join-Path $dist 'ipv8proto.inf'

if (-not (Test-Path $inf)) { throw "未找到 $inf —— 请先运行 scripts\driver-pack.ps1" }

# 测试签名模式检查（加载未 WHQL 签名内核驱动的前提）
$ts = (bcdedit /enum "{current}" | Select-String 'testsigning\s+Yes')
if (-not $ts) {
    Write-Warning '当前未开启测试签名模式。未 WHQL 签名的驱动可能无法加载：'
    Write-Warning '  bcdedit /set testsigning on  （重启生效，需关闭 Secure Boot）'
}

# ---- 测试证书导入受信根/受信发布者（验证签名的前提）----
$cer = Join-Path $dist 'ipv8test.cer'
if (Test-Path $cer) {
    Write-Host '导入测试证书到受信根与受信发布者...'
    certutil -addstore -f Root $cer | Out-Null
    certutil -addstore -f TrustedPublisher $cer | Out-Null
}

# ---- 已安装则先卸载（幂等重装）----
# 未安装判定必须跨语言：英文 "... is not installed." / 中文 "... 尚未安装。"，
# 且 netcfg -q 未安装时退出码非 0。三者任一命中即视为未安装。
for ($i = 0; $i -lt 3; $i++) {
    $q = (netcfg -q IPv8Proto 2>&1 | Out-String)
    $code = $LASTEXITCODE
    if (($code -ne 0) -or ($q -match 'not installed|尚未安装|未安装')) { break }
    Write-Host "卸载 IPv8Proto（第 $($i+1) 次）..."
    netcfg -u IPv8Proto 2>&1 | Out-Host
    Start-Sleep -Seconds 1
}

# ---- 停止并删除残留服务（上次半途安装可能留下 STOPPED 服务）----
sc.exe query IPv8Proto 2>&1 | Out-Null
if ($LASTEXITCODE -eq 0) {
    Write-Host '停止并删除残留服务 IPv8Proto...'
    sc.exe stop IPv8Proto 2>&1 | Out-Null
    sc.exe delete IPv8Proto 2>&1 | Out-Null
    Start-Sleep -Seconds 1
}

# ---- 删除 ROOT 枚举的幽灵设备节点 ----
# 失败的 netcfg 安装会留下 ROOT\IPV8PROTO\0000 设备节点；它存在时再次安装会在
# 设备创建/注册阶段返回 0x800700b7 (ERROR_ALREADY_EXISTS)。必须先删掉。
$rootEnum = 'HKLM:\SYSTEM\CurrentControlSet\Enum\ROOT\IPV8PROTO'
if (Test-Path $rootEnum) {
    Get-ChildItem $rootEnum -ErrorAction SilentlyContinue | ForEach-Object {
        $iid = "ROOT\IPV8PROTO\$($_.PSChildName)"
        Write-Host "删除幽灵设备节点 $iid ..."
        pnputil /remove-device $iid 2>&1 | Out-Host
    }
    Start-Sleep -Seconds 1
}

# ---- 清理 netcfg 组件注册表残骸（Class 键下 IPv8 子键）----
$classKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e975-e325-11ce-bfc1-08002be10318}'
if (Test-Path $classKey) {
    Get-ChildItem $classKey -ErrorAction SilentlyContinue | ForEach-Object {
        $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        if (($props.DriverDesc -match 'IPv8') -or ($props.ComponentId -match 'ipv8proto')) {
            Remove-Item $_.PSPath -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "  清理 Class 注册表残骸: $($_.PSChildName)"
        }
    }
}

# ---- 删除 DriverStore 中所有 ipv8proto 驱动包 ----
# 状态机逐行解析：记录最近一个 oemXX.inf，若同一块 Original Name 为 ipv8proto.inf 则删除。
# 这样能同时清掉旧硬件 ID（ms_ag1 / oem110）与新包，跨语言字段名也安全。
Write-Host '清理 DriverStore 旧版 ipv8proto 包...'
$enumLines = pnputil /enum-drivers 2>&1
$curOem = $null
$removeOems = New-Object System.Collections.Generic.List[string]
foreach ($line in $enumLines) {
    if ($line -match '(?i)(oem\d+\.inf)') { $curOem = $Matches[1] }
    if (($line -match '(?i)ipv8proto\.inf') -and $curOem -and (-not $removeOems.Contains($curOem))) {
        $removeOems.Add($curOem)
    }
}
foreach ($oemInf in $removeOems) {
    Write-Host "  删除 $oemInf ..."
    pnputil /delete-driver $oemInf /uninstall /force 2>&1 | Out-Host
}

# ---- 最终确认：netcfg 应认为组件未安装（跨语言）----
$finalCheck = (netcfg -q IPv8Proto 2>&1 | Out-String)
$finalCode = $LASTEXITCODE
if (($finalCode -eq 0) -and ($finalCheck -notmatch 'not installed|尚未安装|未安装')) {
    Write-Warning 'netcfg 仍认为 IPv8Proto 已安装；如本次安装失败，请重启后再运行本脚本。'
}

# ---- 安装协议组件 ----
Write-Host '== netcfg 安装 IPv8Proto ==' -ForegroundColor Cyan
netcfg -l $inf -c p -i IPv8Proto
if ($LASTEXITCODE -ne 0) { throw "netcfg 安装失败，退出码 $LASTEXITCODE" }

# ---- 注册属性页 COM 服务器 ----
# INF 的 HKR 写不进 HKCR\CLSID；ncpa.cpl 仅当 CLSID 注册了 InprocServer32
# 才启用适配器属性里的"属性(R)"按钮。DLL 已由 INF 复制到 System32。
# regsvr32 必须 /s 静默，否则即使成功也会弹消息框卡住自动化。
$propDll = Join-Path $env:SystemRoot 'System32\ipv8prop.dll'
$regSvr  = Join-Path $env:SystemRoot 'System32\regsvr32.exe'
if (Test-Path $propDll) {
    & $regSvr /s $propDll
    if ($LASTEXITCODE -eq 0) {
        Write-Host '属性页 COM 已注册（ipv8prop.dll）' -ForegroundColor Green
    } else {
        Write-Warning "属性页 COM 注册失败（退出码 $LASTEXITCODE），属性按钮可能为灰色"
    }
} else {
    Write-Warning "未找到 $propDll，跳过属性页注册"
}

# ---- 校验 ----
Write-Host ''
Write-Host '== 服务状态 ==' -ForegroundColor Cyan
sc.exe query IPv8Proto
Write-Host ''
Write-Host '安装完成。查看驱动状态：ping8 driver' -ForegroundColor Green
Write-Host '适配器属性列表应出现"Internet 协议版本 8 (TCP/IPv8)"（打开网络连接 → 属性）'
