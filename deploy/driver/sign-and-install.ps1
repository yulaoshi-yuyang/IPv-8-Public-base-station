# IPv8 Driver Sign and Install Script
# Run as Administrator

$ErrorActionPreference = "Stop"

# Derive paths from script location - go up 3 levels from deploy\driver -> project root
$scriptDir = $PSScriptRoot
$projectRoot = Split-Path $scriptDir -Parent          # -> deploy
$projectRoot = Split-Path $projectRoot -Parent          # -> project root
# NOTE: driver source archived to archive\ipv8-ndis-protocol (ADR-024: kernel
# data plane rejected). This script is kept only for forensic/rebuild use.
$srcSys = Join-Path $projectRoot "archive\ipv8-ndis-protocol\bin\x64\Release\ipv8proto.sys"
$srcInf = Join-Path $projectRoot "archive\ipv8-ndis-protocol\bin\x64\Release\ipv8proto.inf"

# Use ASCII-only temp path
$staging = Join-Path $env:TEMP "IPv8Driver"
New-Item -ItemType Directory -Path $staging -Force | Out-Null

$sysFile = "$staging\ipv8proto.sys"
$infFile = "$staging\ipv8proto.inf"
$signtool = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe"
$inf2cat = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x86\Inf2Cat.exe"

Write-Host "=== IPv8 Driver Sign and Install ==="
Write-Host "  Source SYS: $srcSys"
Write-Host "  Source INF: $srcInf"
Write-Host "  Staging: $staging"

if (-not (Test-Path $srcSys)) {
    Write-Host "ERROR: Cannot find ipv8proto.sys at $srcSys" -ForegroundColor Red
    Write-Host "Make sure you built the driver first."
    exit 1
}

# Copy to ASCII path
Copy-Item $srcSys $sysFile -Force
Copy-Item $srcInf $infFile -Force
Write-Host "  Files staged OK"

# Step 1: Create test certificate
Write-Host ""
Write-Host "[1/5] Creating test certificate..."
$cert = New-SelfSignedCertificate -Subject "CN=IPv8TestSign" -Type CodeSigningCert -KeyUsage DigitalSignature -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 -CertStoreLocation "Cert:\CurrentUser\My" -NotAfter (Get-Date).AddYears(5)
if (-not $cert) { Write-Host "Failed to create certificate" -ForegroundColor Red; exit 1 }
Write-Host "  Certificate: $($cert.Thumbprint)"

$tp = New-Object System.Security.Cryptography.X509Certificates.X509Store("TrustedPublisher", "LocalMachine")
$tp.Open("ReadWrite"); $tp.Add($cert); $tp.Close()
$root = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
$root.Open("ReadWrite"); $root.Add($cert); $root.Close()
Write-Host "  Certificate installed to TrustedPublisher and Root"

# Step 2: Sign the .sys file
Write-Host ""
Write-Host "[2/5] Signing driver..."
& $signtool sign /sha1 $cert.Thumbprint /fd SHA256 $sysFile 2>&1 | Write-Host
if ($LASTEXITCODE -ne 0) { Write-Host "Sign failed: $LASTEXITCODE" -ForegroundColor Red; exit 1 }
Write-Host "  Driver signed OK"

# Step 3: Update INF for catalog
Write-Host ""
Write-Host "[3/5] Updating INF for catalog..."
$infContent = Get-Content $infFile -Raw
if ($infContent -notmatch "CatalogFile") {
    $infContent = $infContent -replace "PnpLockdown = 1", "PnpLockdown = 1`r`nCatalogFile = ipv8proto.cat"
    Set-Content $infFile -Value $infContent -Encoding ASCII
}
Write-Host "  INF updated OK"

# Step 4: Generate catalog file
Write-Host ""
Write-Host "[4/5] Generating catalog file..."
& $inf2cat /driver:$staging /os:10_x64 2>&1 | Write-Host
$catFile = "$staging\ipv8proto.cat"
if (Test-Path $catFile) {
    & $signtool sign /sha1 $cert.Thumbprint /fd SHA256 $catFile 2>&1 | Write-Host
    Write-Host "  Catalog signed OK"
} else {
    Write-Host "  Warning: No catalog file generated"
}

# Step 5: Install
Write-Host ""
Write-Host "[5/5] Installing driver..."
Copy-Item $sysFile "$env:SystemRoot\System32\drivers\ipv8proto.sys" -Force
& netcfg -v -l $infFile -c p -i ms_ag1 2>&1 | Write-Host
$exitCode = $LASTEXITCODE

if ($exitCode -eq 0) {
    Write-Host ""
    Write-Host "=== INSTALL SUCCESS ===" -ForegroundColor Green
    Write-Host "Open ncpa.cpl -> right-click adapter -> Properties"
    Write-Host "Look for 'Internet Protocol Version 8 (TCP/IPv8)'"
} else {
    Write-Host ""
    Write-Host "Install failed: 0x$($exitCode.ToString('X'))" -ForegroundColor Red
}
