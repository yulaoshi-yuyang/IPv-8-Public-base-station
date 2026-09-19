# clean-build.ps1 - 清理所有构建产物
# 用法：仓库任意目录运行；自动以本脚本上级（仓库根）为基准。
$ErrorActionPreference = "SilentlyContinue"
$root = Split-Path -Parent $PSScriptRoot

Write-Host "=== IPv8+ 构建清理脚本 ===" -ForegroundColor Cyan
Write-Host ""

$totalFreed = 0

# 1. Rust target
$targetDir = Join-Path $root "target"
if (Test-Path $targetDir) {
    $size = (Get-ChildItem -Recurse -File $targetDir | Measure-Object -Property Length -Sum).Sum
    Remove-Item -Recurse -Force $targetDir
    $totalFreed += $size
    Write-Host "[OK] 删除 target/  (" -NoNewline -ForegroundColor Green
    Write-Host "$('{0:N2}' -f ($size/1GB)) GB" -NoNewline -ForegroundColor Yellow
    Write-Host ")"
} else {
    Write-Host "[--] target/ 不存在，跳过" -ForegroundColor Gray
}

# 2. VS 工程 bin/obj（C# 服务 + C++ WDK 驱动）
$csDirs = Get-ChildItem -Path $root -Recurse -Directory -Include bin,obj |
    Where-Object { $_.FullName -notmatch "\\target\\" -and $_.FullName -notmatch "\\artifacts\\" -and $_.FullName -notmatch "\\.trae\\" }
foreach ($dir in $csDirs) {
    $size = (Get-ChildItem -Recurse -File $dir.FullName | Measure-Object -Property Length -Sum).Sum
    Remove-Item -Recurse -Force $dir.FullName
    $totalFreed += $size
    $relPath = $dir.FullName.Replace($root, "").TrimStart("\")
    Write-Host "[OK] 删除 $relPath  (" -NoNewline -ForegroundColor Green
    Write-Host "$('{0:N2}' -f ($size/1MB)) MB" -NoNewline -ForegroundColor Yellow
    Write-Host ")"
}

# 3. TestResults
$testDirs = Get-ChildItem -Path $root -Recurse -Directory -Include TestResults
foreach ($dir in $testDirs) {
    $size = (Get-ChildItem -Recurse -File $dir.FullName | Measure-Object -Property Length -Sum).Sum
    Remove-Item -Recurse -Force $dir.FullName
    $totalFreed += $size
    $relPath = $dir.FullName.Replace($root, "").TrimStart("\")
    Write-Host "[OK] 删除 $relPath  (" -NoNewline -ForegroundColor Green
    Write-Host "$('{0:N2}' -f ($size/1MB)) MB" -NoNewline -ForegroundColor Yellow
    Write-Host ")"
}

# 4. artifacts (统一输出目录)
$artDir = Join-Path $root "artifacts"
if (Test-Path $artDir) {
    $size = (Get-ChildItem -Recurse -File $artDir | Measure-Object -Property Length -Sum).Sum
    Remove-Item -Recurse -Force $artDir
    $totalFreed += $size
    Write-Host "[OK] 删除 artifacts/  (" -NoNewline -ForegroundColor Green
    Write-Host "$('{0:N2}' -f ($size/1GB)) GB" -NoNewline -ForegroundColor Yellow
    Write-Host ")"
}

Write-Host ""
Write-Host "=== 清理完成 ===" -ForegroundColor Cyan
Write-Host "释放空间: " -NoNewline
Write-Host "$('{0:N2}' -f ($totalFreed/1GB)) GB" -ForegroundColor Yellow
