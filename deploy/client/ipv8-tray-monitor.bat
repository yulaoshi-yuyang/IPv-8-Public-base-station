@echo off
cd /d "d:\代码\IPV 8"
powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "deploy\client\ipv8-tray-monitor.ps1"
