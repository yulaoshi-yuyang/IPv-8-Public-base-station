# clean-build.ps1 - 清理所有构建产物
$ErrorActionPreference = "SilentlyContinue"

Write-Host "=== IPv8+ 构建清理脚本 ===" -ForegroundColor Cyan
Write-Host ""

$totalFreed = 0

# 1. Rust target
if (Test-Path "target") {
    $size = (Get-ChildItem -Recurse -File target | Measure-Object -Property Length -Sum).Sum
    Remove-Item -Recurse -Force "target"
    $totalFreed += $size
    Write-Host "[OK] 删除 target/  (" -NoNewline -ForegroundColor Green
    Write-Host "$('{0:N2}' -f ($size/1GB)) GB" -NoNewline -ForegroundColor Yellow
    Write-Host ")"
} else {
    Write-Host "[--] target/ 不存在，跳过" -ForegroundColor Gray
}

# 2. C# bin/obj
$csDirs = Get-ChildItem -Recurse -Directory -Include bin,obj | Where-Object { $_.FullName -notmatch "\\target\\" -and $_.FullName -notmatch "\\artifacts\\" }
foreach ($dir in $csDirs) {
    $size = (Get-ChildItem -Recurse -File $dir.FullName | Measure-Object -Property Length -Sum).Sum
    Remove-Item -Recurse -Force $dir.FullName
    $totalFreed += $size
    $relPath = $dir.FullName.Replace((Get-Location).Path, "").TrimStart("\")
    Write-Host "[OK] 删除 $relPath  (" -NoNewline -ForegroundColor Green
    Write-Host "$('{0:N2}' -f ($size/1MB)) MB" -NoNewline -ForegroundColor Yellow
    Write-Host ")"
}

# 3. TestResults
$testDirs = Get-ChildItem -Recurse -Directory -Include TestResults
foreach ($dir in $testDirs) {
    $size = (Get-ChildItem -Recurse -File $dir.FullName | Measure-Object -Property Length -Sum).Sum
    Remove-Item -Recurse -Force $dir.FullName
    $totalFreed += $size
    $relPath = $dir.FullName.Replace((Get-Location).Path, "").TrimStart("\")
    Write-Host "[OK] 删除 $relPath  (" -NoNewline -ForegroundColor Green
    Write-Host "$('{0:N2}' -f ($size/1MB)) MB" -NoNewline -ForegroundColor Yellow
    Write-Host ")"
}

# 4. artifacts (统一输出目录)
if (Test-Path "artifacts") {
    $size = (Get-ChildItem -Recurse -File artifacts | Measure-Object -Property Length -Sum).Sum
    Remove-Item -Recurse -Force "artifacts"
    $totalFreed += $size
    Write-Host "[OK] 删除 artifacts/  (" -NoNewline -ForegroundColor Green
    Write-Host "$('{0:N2}' -f ($size/1GB)) GB" -NoNewline -ForegroundColor Yellow
    Write-Host ")"
}

Write-Host ""
Write-Host "=== 清理完成 ===" -ForegroundColor Cyan
Write-Host "释放空间: " -NoNewline
Write-Host "$('{0:N2}' -f ($totalFreed/1GB)) GB" -ForegroundColor Yellow
