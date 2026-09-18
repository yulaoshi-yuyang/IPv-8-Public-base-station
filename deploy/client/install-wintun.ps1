# deploy/client/install-wintun.ps1
# wintun 安装 + MTU 设置（v9：MTU 1432 在此钉死，防 OS 发 1500 包超隧道开销）
#Requires -RunAsAdministrator

param(
    [string]$AdapterName = "IPv8Plus",
    [int]$Mtu = 1432,
    # 部署参数（spec §10.4：禁止硬编码公共实例；下载源由调用方提供）
    [string]$WintunDllSource = ""
)

if ([string]::IsNullOrWhiteSpace($WintunDllSource)) {
    Write-Error "必须通过 -WintunDllSource 指定 wintun.dll 的本地路径或官方下载地址"
    exit 1
}

$dllDir = Join-Path $env:ProgramFiles "IPv8Plus\bin"
New-Item -ItemType Directory -Force -Path $dllDir | Out-Null

if ($WintunDllSource -match '^https?://') {
    Invoke-WebRequest -Uri $WintunDllSource -OutFile (Join-Path $dllDir "wintun.dll") -UseBasicParsing
} else {
    Copy-Item -LiteralPath $WintunDllSource -Destination (Join-Path $dllDir "wintun.dll") -Force
}

# 创建虚拟网卡（设备生命周期也可由 Host 启动时经 WintunDevice 完成；此处预装验证权限）
Write-Host "wintun.dll 已就绪: $(Join-Path $dllDir 'wintun.dll')"

# MTU：待适配器存在后设置（首次由 Host 创建设备后重跑本脚本即可生效）
$adapter = Get-NetAdapter -Name $AdapterName -ErrorAction SilentlyContinue
if ($adapter) {
    Set-NetIPInterface -InterfaceIndex $adapter.ifIndex -Nl Mtu $Mtu
    Write-Host "已将 $AdapterName MTU 设置为 $Mtu"
} else {
    Write-Host "适配器 '$AdapterName' 尚不存在，MTU 将在 Host 首次创建设备后由本脚本二次执行设置"
}
