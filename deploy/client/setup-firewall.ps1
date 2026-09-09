param(
    [Parameter(Position=0)]
    [ValidateSet("open","close","status")]
    [string]$Action = "open"
)

Write-Host "=== IPv8+ Firewall Management ===" -ForegroundColor Cyan

switch ($Action) {
    "open" {
        Write-Host "[Opening firewall ports for IPv8+...]" -ForegroundColor Yellow
        $ports = @(45801, 45800, 9001, 5353)
        foreach ($port in $ports) {
            foreach ($proto in @("UDP","TCP")) {
                $ruleName = "IPv8+ Port $port $proto"
                $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
                if (-not $existing) {
                    New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol $proto -LocalPort $port -Action Allow -Profile Any | Out-Null
                    Write-Host "  Created: $ruleName" -ForegroundColor Green
                } else {
                    Write-Host "  Exists:  $ruleName" -ForegroundColor Gray
                }
            }
        }
        Write-Host "`nDone. External users can now connect on ports: $($ports -join ', ')" -ForegroundColor Green
    }
    "close" {
        Write-Host "[Removing all IPv8+ firewall rules...]" -ForegroundColor Yellow
        $rules = Get-NetFirewallRule -DisplayName "IPv8+*" -ErrorAction SilentlyContinue
        if ($rules) {
            $rules | Remove-NetFirewallRule -ErrorAction SilentlyContinue
            Write-Host "  Removed $($rules.Count) rules" -ForegroundColor Green
        } else {
            Write-Host "  No IPv8+ rules found" -ForegroundColor Gray
        }
    }
    "status" {
        Write-Host "[Current IPv8+ firewall rules:]" -ForegroundColor Yellow
        $rules = Get-NetFirewallRule -DisplayName "IPv8+*" -ErrorAction SilentlyContinue
        if ($rules) {
            $rules | Format-Table DisplayName, Direction, Enabled -AutoSize
            Write-Host "Total: $($rules.Count) rules" -ForegroundColor Green
        } else {
            Write-Host "  No IPv8+ rules found. Run: setup-firewall.ps1 open" -ForegroundColor Yellow
        }
    }
}
