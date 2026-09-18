#Requires -Version 5.1
<#
.SYNOPSIS
    Phase 5B 驱动打包：构建 sys + 属性页 dll + release 版 ping8.exe
    → dist/driver/（inf2cat + 测试签名 best-effort），并生成整目录可拷贝的
    便携 安装.ps1 / 卸载.ps1（自定位 $PSScriptRoot，无仓库依赖）。
.NOTES
    无需提权。重复执行幂等（覆盖产物）。
#>
$ErrorActionPreference = 'Stop'
$root   = Split-Path -Parent $PSScriptRoot
$drv    = Join-Path $root 'src\driver\ipv8proto'
$prop   = Join-Path $root 'src\driver\ipv8prop'
$dist   = Join-Path $root 'dist\driver'
$msbuild = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe'

if (-not (Test-Path $msbuild)) { throw "未找到 MSBuild，请安装 VS2022 BuildTools" }

Write-Host '== 构建内核驱动 ipv8proto.sys ==' -ForegroundColor Cyan
& $msbuild "$drv\ipv8proto.vcxproj" /p:Configuration=Release /p:Platform=x64 /v:m /nologo
if ($LASTEXITCODE -ne 0) { throw "驱动构建失败" }

Write-Host '== 构建属性页 ipv8prop.dll ==' -ForegroundColor Cyan
& $msbuild "$prop\ipv8prop.vcxproj" /p:Configuration=Release /p:Platform=x64 /v:m /nologo
if ($LASTEXITCODE -ne 0) { throw "属性页构建失败" }

Write-Host '== 构建 release 版 ping8.exe ==' -ForegroundColor Cyan
$cargo = Get-Command cargo.exe -ErrorAction SilentlyContinue
if (-not $cargo) {
    $cargoBin = Join-Path $env:USERPROFILE '.cargo\bin\cargo.exe'
    if (Test-Path $cargoBin) { $cargo = Get-Item $cargoBin }
}
if (-not $cargo) { throw '未找到 cargo.exe（需 Rust 工具链）' }
& $cargo.Source build --release -p ipv8-client
if ($LASTEXITCODE -ne 0) { throw 'ping8.exe 构建失败' }

New-Item -ItemType Directory -Force -Path $dist | Out-Null
Copy-Item "$drv\bin\x64\Release\ipv8proto.sys" $dist -Force
Copy-Item "$prop\bin\x64\Release\ipv8prop.dll" $dist -Force
$ping8 = Join-Path $root 'target\release\ping8.exe'
if (-not (Test-Path $ping8)) { throw "未找到构建产物 $ping8" }
Copy-Item $ping8 $dist -Force

# INF 含中文：源文件以 UTF-8 维护，发布时转 UTF-16 LE BOM（SetupAPI/netcfg 标准编码），
# 否则 DevDesc 等字符串会按 ANSI 解析成乱码。
$infSrc = Join-Path $drv 'ipv8proto.inf'
$infDst = Join-Path $dist 'ipv8proto.inf'
$infText = [System.IO.File]::ReadAllText($infSrc, (New-Object System.Text.UTF8Encoding($false)))
[System.IO.File]::WriteAllText($infDst, $infText, (New-Object System.Text.UnicodeEncoding($false, $true)))
Write-Host 'INF 已转换为 UTF-16 LE BOM'

# ---- inf2cat（硬门禁：失败即中止，防止签出 catalog 哈希陈旧的假包）----
$inf2cat = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\bin\*\Inf2Cat.exe' -Recurse -ErrorAction SilentlyContinue |
    Sort-Object FullName -Descending | Select-Object -First 1
if ($inf2cat) {
    & $inf2cat.FullName /driver:$dist /os:10_X64
    if ($LASTEXITCODE -ne 0) {
        throw 'inf2cat 失败：缺少有效 catalog，netcfg 安装必被 DriverStore 拒绝（0xE000024B）。常见原因：DriverVer 日期晚于当前 UTC 日期。'
    }
} else {
    throw '未找到 Inf2Cat.exe（无法生成 catalog，驱动包不可安装）'
}

# ---- signtool 测试签名（best-effort）----
$signtool = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe' -ErrorAction SilentlyContinue |
    Sort-Object FullName -Descending | Select-Object -First 1
if ($signtool) {
    $cert = Get-ChildItem Cert:\CurrentUser\My -ErrorAction SilentlyContinue |
        Where-Object { $_.Subject -like '*IPv8 Test*' } |
        Sort-Object NotAfter -Descending | Select-Object -First 1
    if (-not $cert) {
        Write-Host '创建代码签名测试证书 CN=IPv8 Test...'
        $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=IPv8 Test' `
            -CertStoreLocation Cert:\CurrentUser\My
        if ($cert) {
            Write-Host "证书指纹: $($cert.Thumbprint)"
        }
    }
    if ($cert) {
        # 导出公钥证书供提权安装脚本导入受信根/受信发布者
        $cerPath = Join-Path $dist 'ipv8test.cer'
        [System.IO.File]::WriteAllBytes($cerPath, $cert.Export('Cert'))
        foreach ($f in 'ipv8proto.sys', 'ipv8prop.dll', 'ipv8proto.cat') {
            $p = Join-Path $dist $f
            if (Test-Path $p) {
                & $signtool.FullName sign /n 'IPv8 Test' /fd SHA256 $p
                if ($LASTEXITCODE -ne 0) { Write-Warning "签名失败：$f（继续）" }
            }
        }
    } else {
        Write-Warning '无法创建测试证书（跳过签名）'
    }
} else {
    Write-Warning '未找到 signtool（跳过签名）'
}

Write-Host ''
Write-Host '== 生成便携 安装.ps1 / 卸载.ps1（自定位，可随整目录拷贝）==' -ForegroundColor Cyan

# 含中文且要在 PowerShell 5.1 上运行：必须写 UTF-8 BOM，否则按 ANSI 解析乱码。
$utf8Bom = New-Object System.Text.UTF8Encoding($true)

# 安装脚本内容为字面文本（单引号 here-string，不在打包期插值）。
$installPs1 = @'
#Requires -Version 5.1
<#
.SYNOPSIS
    IPv8+ 便携安装（netcfg 协议组件，需提权）。整目录可拷贝到其它电脑。
.NOTES
    幂等：已安装则先卸载再装。前置：测试签名模式（bcdedit /set testsigning on，重启）。
    所有文件均取自本脚本所在目录，不依赖源码仓库。
#>
$ErrorActionPreference = 'Stop'
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw '请以管理员身份运行：在管理员 PowerShell 中执行本脚本' }
$dist = $PSScriptRoot
$inf  = Join-Path $dist 'ipv8proto.inf'

if (-not (Test-Path $inf)) { throw "未找到 $inf —— 安装包不完整" }

# 测试签名模式检查（加载未 WHQL 签名内核驱动的前提）
$ts = (bcdedit /enum "{current}" | Select-String 'testsigning\s+Yes')
if (-not $ts) {
    Write-Warning '当前未开启测试签名模式。未 WHQL 签名的驱动可能无法加载：'
    Write-Warning '  bcdedit /set testsigning on  （重启生效，需关闭 Secure Boot）'
}

# ---- 测试证书导入受信根/受信发布者 ----
$cer = Join-Path $dist 'ipv8test.cer'
if (Test-Path $cer) {
    Write-Host '导入测试证书到受信根与受信发布者...'
    certutil -addstore -f Root $cer | Out-Null
    certutil -addstore -f TrustedPublisher $cer | Out-Null
}

# ---- 已安装则先卸载（幂等重装，跨语言判定）----
for ($i = 0; $i -lt 3; $i++) {
    $q = (netcfg -q IPv8Proto 2>&1 | Out-String)
    $code = $LASTEXITCODE
    if (($code -ne 0) -or ($q -match 'not installed|尚未安装|未安装')) { break }
    Write-Host "卸载 IPv8Proto（第 $($i+1) 次）..."
    netcfg -u IPv8Proto 2>&1 | Out-Host
    Start-Sleep -Seconds 1
}

# ---- 停止并删除残留服务 ----
sc.exe query IPv8Proto 2>&1 | Out-Null
if ($LASTEXITCODE -eq 0) {
    Write-Host '停止并删除残留服务 IPv8Proto...'
    sc.exe stop IPv8Proto 2>&1 | Out-Null
    sc.exe delete IPv8Proto 2>&1 | Out-Null
    Start-Sleep -Seconds 1
}

# ---- 删除 ROOT 枚举的幽灵设备节点（否则重装报 0x800700b7）----
$rootEnum = 'HKLM:\SYSTEM\CurrentControlSet\Enum\ROOT\IPV8PROTO'
if (Test-Path $rootEnum) {
    Get-ChildItem $rootEnum -ErrorAction SilentlyContinue | ForEach-Object {
        $iid = "ROOT\IPV8PROTO\$($_.PSChildName)"
        Write-Host "删除幽灵设备节点 $iid ..."
        pnputil /remove-device $iid 2>&1 | Out-Host
    }
    Start-Sleep -Seconds 1
}

# ---- 清理 netcfg 组件注册表残骸 ----
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

# ---- 安装协议组件 ----
Write-Host '== netcfg 安装 IPv8Proto ==' -ForegroundColor Cyan
netcfg -l $inf -c p -i IPv8Proto
if ($LASTEXITCODE -ne 0) { throw "netcfg 安装失败，退出码 $LASTEXITCODE" }

# ---- 注册属性页 COM 服务器 ----
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

# ---- 立即启动（inf 已配 AUTO_START；此处当次生效免重启）----
Write-Host '启动 IPv8Proto 服务...' -ForegroundColor Cyan
sc.exe start IPv8Proto | Out-Null
Start-Sleep -Seconds 2

Write-Host ''
Write-Host '== 服务状态 ==' -ForegroundColor Cyan
sc.exe query IPv8Proto
Write-Host ''
Write-Host '安装完成。本目录下可用：.\ping8.exe l2 bindings' -ForegroundColor Green
Write-Host '双机直连测试：机器A  .\ping8.exe l2 peek --if any --count 0'
Write-Host '              机器B  .\ping8.exe l2 send --if <N> --text IPV8-L2-PING'
'@

$uninstallPs1 = @'
#Requires -Version 5.1
<#
.SYNOPSIS
    IPv8+ 便携卸载（停驱动 → 反注册属性页 COM → netcfg 移除协议组件
    → 清残留服务，需提权）。幂等。
#>
$ErrorActionPreference = 'Continue'
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw '请以管理员身份运行：在管理员 PowerShell 中执行本脚本' }

$clsid     = '{7E5F3A9C-1D64-4B2E-9C38-A50F8E2D6B71}'
$propDll   = Join-Path $env:SystemRoot 'System32\ipv8prop.dll'
$regSvr    = Join-Path $env:SystemRoot 'System32\regsvr32.exe'
$clsidRoot = 'HKLM:\SOFTWARE\Classes\CLSID'

# ---- 1) 先停驱动（释放文件占用）----
$svc = Get-Service -Name IPv8Proto -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq 'Running') {
    Write-Host '停止驱动 IPv8Proto...'
    sc.exe stop IPv8Proto | Out-Null
    Start-Sleep -Milliseconds 500
}

# ---- 2) 反注册属性页 COM ----
Write-Host '== 反注册属性页 COM ==' -ForegroundColor Cyan
if (Test-Path $propDll) {
    & $regSvr /u /s $propDll
    Write-Host '已调用 ipv8prop.dll 反注册。'
} else {
    Write-Host 'ipv8prop.dll 已不在 System32，改用注册表兜底清理。'
}
$clsidKey = Join-Path $clsidRoot $clsid
Remove-Item -Path (Join-Path $clsidKey 'InprocServer32') -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path $clsidKey -Recurse -Force -ErrorAction SilentlyContinue

# ---- 3) netcfg 移除协议组件 ----
Write-Host '== netcfg 卸载 IPv8Proto ==' -ForegroundColor Cyan
netcfg -u IPv8Proto
if ($LASTEXITCODE -ne 0) {
    Write-Warning "netcfg 卸载返回 $LASTEXITCODE（组件可能本就未安装）"
}

# ---- 4) 残留服务清理 ----
$svc = Get-Service -Name IPv8Proto -ErrorAction SilentlyContinue
if ($svc) {
    Write-Host '清理残留服务 IPv8Proto...'
    sc.exe delete IPv8Proto | Out-Null
}

# ---- 5) 删除 DriverStore 中的 ipv8proto 驱动包 ----
# netcfg -u 只摘组件不删包，不清理则 oem*.inf 永久残留（重装时由安装脚本兜底，卸载应自身干净）。
Write-Host '清理 DriverStore 中的 ipv8proto 包...' -ForegroundColor Cyan
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

# ---- 6) 删除残留二进制（netcfg 不保证回收 CopyFiles）----
foreach ($f in (Join-Path $env:SystemRoot 'System32\drivers\ipv8proto.sys'),
              (Join-Path $env:SystemRoot 'System32\ipv8prop.dll')) {
    if (Test-Path $f) {
        try {
            Remove-Item $f -Force -ErrorAction Stop
            Write-Host "  已删除 $f"
        } catch {
            Write-Warning "  $f 暂无法删除（可能待重启回收）：$($_.Exception.Message)"
        }
    }
}

# ---- 7) 跨语言校验 ----
Write-Host ''
$still = (netcfg -q IPv8Proto 2>&1 | Out-String)
$code  = $LASTEXITCODE
if (($code -eq 0) -and ($still -notmatch 'not installed|尚未安装|未安装')) {
    Write-Warning '组件仍显示已安装，可能需要重启后重试。'
} else {
    Write-Host '卸载完成：IPv8Proto 已移除。' -ForegroundColor Green
}
'@

[System.IO.File]::WriteAllText((Join-Path $dist '安装.ps1'), $installPs1, $utf8Bom)
[System.IO.File]::WriteAllText((Join-Path $dist '卸载.ps1'), $uninstallPs1, $utf8Bom)

Write-Host ''
Write-Host "打包完成：$dist" -ForegroundColor Green
Get-ChildItem $dist | Format-Table Name, Length -AutoSize
Write-Host '便携分发：把整个目录拷到第二台电脑，右键 安装.ps1 → 使用 PowerShell 运行（管理员）'
