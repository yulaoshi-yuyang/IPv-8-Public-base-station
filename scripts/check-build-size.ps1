# check-build-size.ps1 - 检查构建产物体积
# 用法：仓库任意目录运行；自动以本脚本上级（仓库根）为基准。
$ErrorActionPreference = "SilentlyContinue"
$root = Split-Path -Parent $PSScriptRoot

Write-Host "=== 构建产物体积检查 ===" -ForegroundColor Cyan
Write-Host ""

# Rust target
$rustSize = 0
$targetDir = Join-Path $root "target"
if (Test-Path $targetDir) {
    $rustSize = (Get-ChildItem -Recurse -File $targetDir | Measure-Object -Property Length -Sum).Sum
}
Write-Host "Rust target:     " -NoNewline
Write-Host "$('{0,8:N2}' -f ($rustSize/1GB)) GB" -ForegroundColor $(if ($rustSize/1GB -gt 5) { "Red" } else { "Green" })

# VS 工程 bin/obj（C# 服务 + C++ WDK 驱动）
$csSize = 0
$csDirs = Get-ChildItem -Path $root -Recurse -Directory -Include bin,obj |
    Where-Object { $_.FullName -notmatch "\\target\\" -and $_.FullName -notmatch "\\artifacts\\" -and $_.FullName -notmatch "\\.trae\\" }
foreach ($dir in $csDirs) {
    $size = (Get-ChildItem -Recurse -File $dir.FullName | Measure-Object -Property Length -Sum).Sum
    $csSize += $size
}
Write-Host "VS bin/obj:      " -NoNewline
Write-Host "$('{0,8:N2}' -f ($csSize/1GB)) GB" -ForegroundColor $(if ($csSize/1GB -gt 2) { "Red" } else { "Green" })

# artifacts
$artSize = 0
$artDir = Join-Path $root "artifacts"
if (Test-Path $artDir) {
    $artSize = (Get-ChildItem -Recurse -File $artDir | Measure-Object -Property Length -Sum).Sum
}
Write-Host "artifacts:       " -NoNewline
Write-Host "$('{0,8:N2}' -f ($artSize/1GB)) GB" -ForegroundColor $(if ($artSize/1GB -gt 2) { "Red" } else { "Green" })

# TestResults
$testSize = 0
$testDirs = Get-ChildItem -Path $root -Recurse -Directory -Include TestResults
foreach ($dir in $testDirs) {
    $size = (Get-ChildItem -Recurse -File $dir.FullName | Measure-Object -Property Length -Sum).Sum
    $testSize += $size
}
Write-Host "TestResults:     " -NoNewline
Write-Host "$('{0,8:N2}' -f ($testSize/1MB)) MB" -ForegroundColor Green

# 总计
$total = $rustSize + $csSize + $artSize + $testSize
Write-Host ""
Write-Host "合计:            " -NoNewline
Write-Host "$('{0,8:N2}' -f ($total/1GB)) GB" -ForegroundColor $(if ($total/1GB -gt 8) { "Red" } elseif ($total/1GB -gt 5) { "Yellow" } else { "Green" })

if ($total/1GB -gt 8) {
    Write-Host ""
    Write-Warning "构建产物已超过 8GB，建议运行 scripts\clean-build.ps1 清理"
}
