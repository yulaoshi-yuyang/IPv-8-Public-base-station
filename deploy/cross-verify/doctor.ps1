<#
  doctor.ps1 - one-shot environment check for "Failed to create adapter".
  Run on the machine where verify-cross.ps1 failed (admin rights recommended):

      powershell -File .\doctor.ps1

  It checks the 4 usual suspects and prints verdicts. Send this output back
  if the fix column doesn't apply to you. Keep this file pure ASCII.
#>
$ErrorActionPreference = 'SilentlyContinue'

function Check($name, $ok, $detail, $fix) {
    $tag = if ($ok) { 'OK  ' } else { 'FAIL' }
    Write-Host ("[{0}] {1}" -f $tag, $name) -NoNewline
    if ($detail) { Write-Host ("   ({0})" -f $detail) } else { Write-Host '' }
    if (-not $ok -and $fix) { Write-Host ("       -> {0}" -f $fix) -ForegroundColor Yellow }
    return -not $ok
}

$anyBad = $false

# 1) Admin rights (creating a virtual NIC needs the full token, not just "is admin")
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$pr = New-Object Security.Principal.WindowsPrincipal($id)
$admin = $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$elev = ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -and $admin
$bad = Check 'ELEVATION' $admin '(need: run PowerShell as Administrator)' `
    'Right-click PowerShell -> Run as administrator, then re-run verify-cross.ps1 (script self-elevates only on the loopback host; on some machines UAC filtering breaks it - manual admin is the sure fix)'
$anyBad = $anyBad -or $bad

# 2) The three services Windows uses to actually create a device + register it.
#    Corporates / "tuning tools" love to disable them -> WintunCreateAdapter dies.
foreach ($svc in @(
    @{ n = 'RasMan';   label = 'Remote Access Connection Manager' },
    @{ n = 'TapiSrv';  label = 'Telephony' },
    @{ n = 'PlugPlay'; label = 'Plug and Play' }
)) {
    $s = Get-Service -Name $svc.n
    $running = ($s.Status -eq 'Running')
    $fixTxt = 'sc config ' + $svc.n + ' start= demand ; sc start ' + $svc.n + '   (or enable it in services.msc)'
    $bad = Check ("SERVICE {0}" -f $svc.n) $running ("{0} = {1}" -f $svc.label, $(if ($s) { $s.Status } else { 'MISSING' })) $fixTxt
    $anyBad = $anyBad -or $bad
}

# 3) Corporate device-install policy blocking new network devices (big intranet machines often have this)
$polPaths = @(
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions',
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\Deny'
)
$polHit = $null
foreach ($p in $polPaths) {
    if (Test-Path $p) {
        $props = Get-ItemProperty -Path $p
        $en = $props.'DenyDeviceInstallation'
        if ($en) { $polHit = "$p (DenyDeviceInstallation=$en)" }
        if ($p -like '*\Deny') {
            $kids = Get-ChildItem -Path $p
            if ($kids) { $polHit = "$p (has $($kids.Count) deny rule(s))" }
        }
    }
}
$bad = Check 'DEVICE-INSTALL-POLICY' (-not $polHit) $polHit `
    'Group policy blocks installing new network devices - ask IT to allow Wintun (WireGuard LLC signed driver), or test on a non-managed machine'
$anyBad = $anyBad -or $bad

# 4) Stale/conflicting wintun driver already in the driver store (old WireGuard/WARP/Tailscale/VPN leftovers)
$drv = pnputil /enum-drivers 2>&1 | Out-String
$hasWintun = $drv -match '(?m)^\s*Original Name:\s*wintun\.inf'
$storeNote = if ($hasWintun) { 'wintun.inf found in driver store - version below matters' } else { 'no wintun driver pre-installed (normal for first run)' }
$ver = $null
if ($hasWintun) {
    $m = [regex]::Match($drv, '(?ms)Original Name:\s*wintun\.inf.*?Driver Version:\s*(\S+)')
    if (-not $m.Success) { $m = [regex]::Match($drv, '(?ms)Driver Version:\s*(\S+).*?Original Name:\s*wintun\.inf') }
    if ($m.Success) { $ver = $m.Groups[1].Value }
}
# NOTE: old-driver presence alone is not fatal (Wintun republishes), but a version
# SKEW between the store driver and our bundled wintun.dll (0.14.1) causes exactly
# this "Failed to create adapter" on some machines -> report both sides.
$dllVer = $null
$dllPath = Join-Path $PSScriptRoot 'wintun.dll'
if (Test-Path $dllPath) { $dllVer = (Get-Item $dllPath).VersionInfo.FileVersion }
$bad = Check 'WINTUN-DRIVER-STORE' $true "$storeNote  store=$ver dll=$dllVer" ''
if ($hasWintun -and $ver) {
    Write-Host '       NOTE: if all other checks pass yet the node still fails, a leftover wintun driver from another VPN can be the cause:' -ForegroundColor Yellow
    Write-Host '             uninstall other VPN apps first, or pnputil /delete-driver <wintun oemN.inf> /uninstall (admin), then retry' -ForegroundColor Yellow
}
$anyBad = $anyBad -or $bad

# 5) Third-party security suites known to intercept virtual NIC creation (heuristic: running AV processes)
$avs = Get-Process 2>&1 | Where-Object { $_.ProcessName -match 'HipsTray|hhs|hwsus|360|Huorong|usysdiag|QQPCTray|TSrv|kxetray|ksafe|STP|ESSvcfg|mcui|mcsupd|MsMpEng' } | Select-Object -ExpandProperty ProcessName -Unique
$bad = Check 'SECURITY-SOFTWARE' (-not $avs) ($(if ($avs) { $avs -join ',' } else { 'none obvious' })) `
    'A security suite is running; if the steps above pass but the node still fails, whitelist the folder or temporarily exit it, then retry'
$anyBad = $anyBad -or $bad

# 6) Stale Wintun devices actually registered in PnP (the classic cause of a
#    bare "Failed to create adapter": an existing device that is disabled or
#    in error state makes WintunCreateAdapter return NULL with no useful code).
$pnpWintun = @()
try {
    $pnpWintun = @(Get-PnpDevice -Class Net -ErrorAction SilentlyContinue |
        Where-Object { $_.FriendlyName -match 'Wintun' -or $_.InstanceId -match 'WINTUN' })
} catch { }
$staleBad = @($pnpWintun | Where-Object { $_.Status -ne 'OK' })
$staleNote = if ($pnpWintun.Count -eq 0) { 'no Wintun device registered' } else { ($pnpWintun | ForEach-Object { '{0}=[{1}]' -f $_.FriendlyName, $_.Status }) -join '; ' }
$bad = Check 'WINTUN-PNP-DEVICE' ($staleBad.Count -eq 0) $staleNote `
    'Wintun device exists but is Disabled/Error. Fix: Win+X -> Device Manager -> Network adapters -> right-click "Wintun Userspace Tunnel" -> Enable (if greyed out: Uninstall, tick "delete the driver", then re-run). 360 users: also trust the extracted folder or exit 360 first.'
$anyBad = $anyBad -or $bad

Write-Host ''
if ($anyBad) {
    Write-Host 'VERDICT: problems found above (FAIL lines) - fix them, then re-run verify-cross.ps1.'
} else {
    Write-Host 'VERDICT: environment looks clean. Re-run verify-cross.ps1 - the new ipv8-node.exe now'
    Write-Host '         prints the exact Win32 error code (e.g. "WintunCreateAdapter failed: 0x....").'
    Write-Host '         Send that line back for a targeted diagnosis.'
}
exit $(if ($anyBad) { 1 } else { 0 })
