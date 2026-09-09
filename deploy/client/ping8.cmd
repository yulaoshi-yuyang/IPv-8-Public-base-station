@echo off
setlocal enabledelayedexpansion

if "%~1"=="" (
  echo.
  echo Usage: ping8 [address] [count]
  echo.
  echo Example: ping8 fb14::1
  echo Example: ping8 portal.ipv8.net
  echo Example: ping8 8.8.8.8
  echo.
  echo If address looks like IPv8, tests local tunnel.
  echo If address is an IP, tests cross-machine tunnel.
  exit /b 1
)

set TARGET=%~1
set COUNT=4
if not "%~2"=="" set COUNT=%~2

set PROJECT_DIR=%~dp0..\..
set NODE_EXE=%PROJECT_DIR%\target\release\ipv8-node.exe

if not exist "%NODE_EXE%" (
  echo ERROR: ipv8-node.exe not found
  exit /b 1
)

echo Pinging %TARGET% with IPv8+ Protocol...
echo.

REM Check if target is localhost / 127.0.0.1 / fb14 - do local self-test
if "%TARGET%"=="fb14::1" goto local_test
if "%TARGET%"=="127.0.0.1" goto local_test
if "%TARGET%"=="localhost" goto local_test
if "%TARGET%"=="portal.ipv8.net" goto resolve_domain

REM Check if target contains :: (IPv6 or IPv8 compact)
echo %TARGET% | findstr "::" >nul
if %errorlevel%==0 goto local_test

REM Otherwise treat as remote IP
goto remote_test

:local_test
echo [Mode] Local self-test (A + B on same machine)
echo.

REM Start B node in background
echo Starting B node (responder)...
start /b "" "%NODE_EXE%" --self 0000fb140000000b0001000001000000 --peer-addr 0000fb140000000a0001000001000000 --peer-ip 127.0.0.1 --peer-port 46124 --udp-port 45801 --tun-ip 10.100.0.2 --tun-prefix 10 --no-tun --nt-size %COUNT% > "%TEMP%\ping8-b.log" 2>&1

REM Wait for B to bind
timeout /t 1 /nobreak >nul

REM Run A node
echo Starting A node (initiator)...
"%NODE_EXE%" --self 0000fb140000000a0001000001000000 --peer-addr 0000fb140000000b0001000001000000 --peer-ip 127.0.0.1 --peer-port 45801 --udp-port 46124 --tun-ip 10.100.0.1 --tun-prefix 10 --adapter-name IPv8Plus --initiate --no-tun --nt-size %COUNT%

REM Kill B node
taskkill /fi "imagename eq ipv8-node.exe" /f >nul 2>&1

echo.
echo --- B node output ---
type "%TEMP%\ping8-b.log" 2>nul
del "%TEMP%\ping8-b.log" >nul 2>&1
echo.
echo Ping8 complete.
exit /b 0

:resolve_domain
echo Resolving %TARGET%...
for /f "tokens=*" %%i in ('powershell -NoProfile -Command "try{$r=Invoke-WebRequest 'http://127.0.0.1:9001/api/resolve?host=%TARGET%' -UseBasicParsing -TimeoutSec 3;$j=$r.Content^|ConvertFrom-Json;Write-Output $j.ip}catch{Write-Output ''}"') do set RESOLVED_IP=%%i
if "%RESOLVED_IP%"=="" (
  echo Failed to resolve %TARGET%
  exit /b 1
)
echo Resolved to: %RESOLVED_IP%
echo.
echo [Mode] Remote tunnel test (connecting to %RESOLVED_IP%)
echo.
"%NODE_EXE%" --self 0000fb140000000a0001000001000000 --peer-addr 0000fb140000000b0001000001000000 --peer-ip %RESOLVED_IP% --peer-port 45801 --udp-port 46124 --tun-ip 10.100.0.1 --tun-prefix 10 --adapter-name IPv8Plus --initiate --no-tun --nt-size %COUNT%
echo.
echo Ping8 complete.
exit /b 0

:remote_test
echo.
echo [Mode] Remote tunnel test (connecting to %TARGET%)
echo.
"%NODE_EXE%" --self 0000fb140000000a0001000001000000 --peer-addr 0000fb140000000b0001000001000000 --peer-ip %TARGET% --peer-port 45801 --udp-port 46124 --tun-ip 10.100.0.1 --tun-prefix 10 --adapter-name IPv8Plus --initiate --no-tun --nt-size %COUNT%
echo.
echo Ping8 complete.
exit /b 0
