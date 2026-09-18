' IPv8+ one-click STOP - runs completely hidden (no console window)
' Double-click this file. It stops portal + cloudflared silently.
' On failure a message box is shown.
Option Explicit

Dim shell, fso, scriptDir, ps1, cmd, rc
Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")

scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)
ps1 = scriptDir & "\stop-ipv8.ps1"

If Not fso.FileExists(ps1) Then
    MsgBox "stop-ipv8.ps1 not found:" & vbCrLf & ps1, 16, "IPv8+ Stop"
    WScript.Quit 1
End If

' 0 = hidden window, True = wait for completion and get exit code
cmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File """ & ps1 & """"
rc = shell.Run(cmd, 0, True)

If rc <> 0 Then
    MsgBox "IPv8+ stop failed (exit code " & rc & ").", 16, "IPv8+ Stop"
    WScript.Quit rc
End If
