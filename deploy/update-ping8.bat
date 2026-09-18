@echo off
echo Updating ping8.exe...
copy /Y "D:\代码\IPV 8\target\release\ping8.exe" "C:\Windows\System32\ping8.exe"
if %errorlevel% equ 0 (
    echo SUCCESS: ping8.exe updated
) else (
    echo FAILED: error %errorlevel%
)
timeout /t 3 >nul
