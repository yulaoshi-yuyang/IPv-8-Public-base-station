# deploy/client/setup-nrpt.ps1
# 一条命令把 .ipv8.net 的 DNS 查询引到本地代理（v9 §10）
#Requires -RunAsAdministrator

param(
    [string]$NamespaceRoot = ".ipv8.net",
    [string]$NameServer = "127.0.0.1"
)

$existing = Get-DnsClientNrptRule | Where-Object { $_.Namespace -eq $NamespaceRoot }
if ($existing) {
    Write-Host "NRPT 规则已存在: $($existing.Name)，跳过创建"
    exit 0
}

Add-DnsClientNrptRule -Namespace $NamespaceRoot -NameServers $NameServer
Write-Host "已添加 NRPT 规则: $NamespaceRoot -> $NameServer"
