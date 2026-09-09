<#
  make-peer-pack.ps1 - single source of truth for the cross-verify peer pack.

  Rebuilds the release binaries from the workspace and refreshes
  deploy\cross-verify\ (scripts + exes + wintun.dll) plus the distributable
  deploy\ipv8-cross-verify.zip. Run this instead of hand-copying files:
  copied exes are what caused pack/repo drift in the first place.

  Usage (repo root or anywhere):
    powershell -File scripts\make-peer-pack.ps1
  Skip the cargo build step (pack the current target\release as-is):
    powershell -File scripts\make-peer-pack.ps1 -SkipBuild

  Pure ASCII (PS 5.1 GBK parsing hazard).
#>
param(
    [switch]$SkipBuild,
    # Absolute or repo-relative dir holding ipv8-node.exe + ipv8-zoneserver.exe.
    # Use when target\release is locked by running nodes (e.g. build with
    #   cargo build --release -p ipv8-wintun-node -p ipv8-zoneserver --target-dir target\pack
    #   powershell -File scripts\make-peer-pack.ps1 -SourceDir target\pack\release
    [string]$SourceDir = ''
)
$ErrorActionPreference = 'Stop'
$root  = Split-Path $PSScriptRoot -Parent
$rel   = if ($SourceDir) {
    if ([System.IO.Path]::IsPathRooted($SourceDir)) { $SourceDir } else { Join-Path $root $SourceDir }
} else {
    Join-Path $root 'target\release'
}
$pack  = Join-Path $root 'deploy\cross-verify'
$zip   = Join-Path $root 'deploy\ipv8-cross-verify.zip'

if (-not $SkipBuild -and -not $SourceDir) {
    Write-Host '[pack] cargo build --release -p ipv8-wintun-node -p ipv8-zoneserver'
    Push-Location $root
    try {
        cargo build --release -p ipv8-wintun-node -p ipv8-zoneserver
        if ($LASTEXITCODE -ne 0) {
            Write-Host '[pack] build failed (file locked by running nodes?). Retry:'
            Write-Host '[pack]   cargo build --release -p ipv8-wintun-node -p ipv8-zoneserver --target-dir target\pack'
            Write-Host '[pack]   powershell -File scripts\make-peer-pack.ps1 -SourceDir target\pack\release'
            throw "cargo build failed (exit $LASTEXITCODE)"
        }
    } finally { Pop-Location }
}

foreach ($f in @('ipv8-node.exe', 'ipv8-zoneserver.exe')) {
    if (-not (Test-Path (Join-Path $rel $f))) { throw "missing $rel\$f - build first (drop -SkipBuild)" }
}

Write-Host '[pack] refreshing deploy\cross-verify from authoritative sources'
Copy-Item -LiteralPath (Join-Path $rel 'ipv8-node.exe')       -Destination (Join-Path $pack 'ipv8-node.exe') -Force
Copy-Item -LiteralPath (Join-Path $rel 'ipv8-zoneserver.exe') -Destination (Join-Path $pack 'ipv8-zoneserver.exe') -Force
Copy-Item -LiteralPath (Join-Path $root 'scripts\verify-cross.ps1')   -Destination (Join-Path $pack 'verify-cross.ps1') -Force
Copy-Item -LiteralPath (Join-Path $root 'scripts\notun-selftest.ps1') -Destination (Join-Path $pack 'notun-selftest.ps1') -Force
# doctor.ps1 exists only inside the pack (pack-local triage tool) - leave it as is.
# wintun.dll: keep the pack copy in sync with the authoritative deploy\client copy.
Copy-Item -LiteralPath (Join-Path $root 'deploy\client\wintun.dll') -Destination (Join-Path $pack 'wintun.dll') -Force

Write-Host '[pack] regenerating deploy\ipv8-cross-verify.zip'
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path (Join-Path $pack '*') -DestinationPath $zip

Write-Host '[pack] done. Pack contents:'
Get-ChildItem -LiteralPath $pack -File | ForEach-Object { '  {0,9:N0} KB  {1}' -f ($_.Length / 1KB), $_.Name }
Write-Host ("[pack] zip: {0:N0} KB" -f ((Get-Item -LiteralPath $zip).Length / 1KB))
