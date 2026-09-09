# IPv8+ System Tray Monitor
# Shows IPv8 address in system tray, always visible
# Right-click for menu, double-click for full status

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$notify = New-Object System.Windows.Forms.NotifyIcon
$notify.Icon = [System.Drawing.SystemIcons]::Information
$notify.Visible = $true
$notify.Text = "IPv8+ Monitor"

$ipv8Self = "fb14:0000:0000:0001:0001:0000:0001:0000"
$ipv8Compact = "fb14::1"

function Get-Status {
    $node = Get-Process ipv8-node -ErrorAction SilentlyContinue
    $running = $null -ne $node
    $uptime = ""
    if ($running) {
        $uptime = "$([math]::Round(((Get-Date) - $node.StartTime).TotalSeconds))s"
    }
    return @{ running = $running; uptime = $uptime }
}

function Update-Tray {
    $status = Get-Status
    $running = $status.running
    if ($running) {
        $notify.Icon = [System.Drawing.SystemIcons]::Information
        $notify.Text = "IPv8+ Online | $ipv8Compact"
    } else {
        $notify.Icon = [System.Drawing.SystemIcons]::Warning
        $notify.Text = "IPv8+ Offline | Not running"
    }
}

function Show-StatusForm {
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "IPv8+ Status"
    $form.Size = New-Object System.Drawing.Size(420, 480)
    $form.StartPosition = "CenterScreen"
    $form.BackColor = [System.Drawing.Color]::FromArgb(10, 14, 39)
    $form.FormBorderStyle = "FixedDialog"
    $form.MaximizeBox = $false

    $title = New-Object System.Windows.Forms.Label
    $title.Text = "IPv8+ Protocol Status"
    $title.Font = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Bold)
    $title.ForeColor = [System.Drawing.Color]::FromArgb(0, 212, 255)
    $title.Location = New-Object System.Drawing.Point(20, 20)
    $title.Size = New-Object System.Drawing.Size(360, 35)
    $form.Controls.Add($title)

    $status = Get-Status
    $y = 70
    $rows = @(
        @("IPv8 Address", $ipv8Compact),
        @("IPv8 Full", $ipv8Self),
        @("Protocol", "IPv8+ Phase 5"),
        @("Adapter", "IPv8Plus (wintun)"),
        @("TUN IP", "100.64.0.1/10"),
        @("Domain", "ipv8.yulaoshi.xyz"),
        @("DNS", "portal.ipv8.net (127.0.0.1:5353)"),
        @("Node Status", if ($status.running) { "ONLINE ($($status.uptime))" } else { "OFFLINE" }),
        @("GeoIP", "China / Jiangxi / Jiujiang"),
        @("ISP", "China Mobile (AS9808)"),
        @("Operator", "yulaoshi")
    )

    foreach ($row in $rows) {
        $label = New-Object System.Windows.Forms.Label
        $label.Text = $row[0]
        $label.ForeColor = [System.Drawing.Color]::FromArgb(102, 102, 102)
        $label.Font = New-Object System.Drawing.Font("Segoe UI", 9)
        $label.Location = New-Object System.Drawing.Point(20, $y)
        $label.Size = New-Object System.Drawing.Size(120, 20)
        $form.Controls.Add($label)

        $value = New-Object System.Windows.Forms.Label
        $value.Text = $row[1]
        $value.ForeColor = [System.Drawing.Color]::FromArgb(0, 212, 255)
        $value.Font = New-Object System.Drawing.Font("Consolas", 9)
        $value.Location = New-Object System.Drawing.Point(150, $y)
        $value.Size = New-Object System.Drawing.Size(240, 20)
        $form.Controls.Add($value)

        $y += 28
    }

    $btn = New-Object System.Windows.Forms.Button
    $btn.Text = "Close"
    $btn.Location = New-Object System.Drawing.Point(160, $y + 10)
    $btn.Size = New-Object System.Drawing.Size(100, 30)
    $btn.Add_Click({ $form.Close() })
    $form.Controls.Add($btn)

    $form.ShowDialog() | Out-Null
}

# Context menu
$menu = New-Object System.Windows.Forms.ContextMenuStrip

$menuItemStatus = New-Object System.Windows.Forms.ToolStripMenuItem
$menuItemStatus.Text = "Show IPv8+ Status"
$menuItemStatus.Add_Click({ Show-StatusForm })
$menu.Items.Add($menuItemStatus) | Out-Null

$menuItemSep1 = New-Object System.Windows.Forms.ToolStripSeparator
$menu.Items.Add($menuItemSep1) | Out-Null

$menuItemIp = New-Object System.Windows.Forms.ToolStripMenuItem
$menuItemIp.Text = "IPv8: $ipv8Compact"
$menuItemIp.Enabled = $false
$menu.Items.Add($menuItemIp) | Out-Null

$menuItemSep2 = New-Object System.Windows.Forms.ToolStripSeparator
$menu.Items.Add($menuItemSep2) | Out-Null

$menuItemExit = New-Object System.Windows.Forms.ToolStripMenuItem
$menuItemExit.Text = "Exit"
$menuItemExit.Add_Click({
    $notify.Visible = $false
    [System.Windows.Forms.Application]::Exit()
})
$menu.Items.Add($menuItemExit) | Out-Null

$notify.ContextMenuStrip = $menu

# Double-click shows status
$notify.Add_DoubleClick({ Show-StatusForm })

# Balloon on startup
$notify.ShowBalloonTip(3000, "IPv8+ Monitor", "IPv8 Address: $ipv8Compact`nDomain: ipv8.yulaoshi.xyz", [System.Windows.Forms.ToolTipIcon]::Info)

# Update loop every 10 seconds
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 10000
$timer.Add_Tick({ Update-Tray })
$timer.Start()

Update-Tray

# Keep alive
[System.Windows.Forms.Application]::Run()
