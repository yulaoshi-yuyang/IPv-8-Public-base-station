' IPv8+ one-click START - runs completely hidden (no console window)
' Double-click this file. It launches start-ipv8.ps1 -Background silently.
' On failure a message box is shown. Success = no window at all.
Option Explicit

Dim shell, fso, scriptDir, ps1, cmd, rc
Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")

scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)
ps1 = scriptDir & "\start-ipv8.ps1"

If Not fso.FileExists(ps1) Then
    MsgBox "start-ipv8.ps1 not found:" & vbCrLf & ps1, 16, "IPv8+ Start"
    WScript.Quit 1
End If

' 0 = hidden window, True = wait for completion and get exit code
' -Background makes the portal child process hidden too (otherwise minimized)
cmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File """ & ps1 & """ -Background"
rc = shell.Run(cmd, 0, True)

If rc <> 0 Then
    MsgBox "IPv8+ start failed (exit code " & rc & ")." & vbCrLf & _
           "Check logs in deploy\portal\logs\", 16, "IPv8+ Start"
    WScript.Quit rc
End If
