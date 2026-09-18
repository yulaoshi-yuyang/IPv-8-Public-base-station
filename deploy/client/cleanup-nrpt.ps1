# deploy/client/cleanup-nrpt.ps1
# ★ v9：PowerShell 语法完整修正版（$ 前缀、空格、插值、-ErrorAction 全名）
#Requires -RunAsAdministrator

$rules = Get-DnsClientNrptRule | Where-Object {
    $_.Namespace -eq ".ipv8.net"
}
foreach ($rule in $rules) {
    try {
        Remove-DnsClientNrptRule -Name $rule.Name -ErrorAction SilentlyContinue
        Write-Host "已清理 NRPT 规则: $($rule.Name)"
    } catch {
        Write-Warning "清理失败: $_"
    }
}
