@echo off
title Stop AIOps Platform Services
cd /d "%~dp0"
echo ===================================================
echo Stopping All AIOps Platform Services...
echo ===================================================

echo Closing Collector UI, Collector Daemon, and SaaS Server...

powershell -Command "Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like '*run_collector.py*' -or $_.CommandLine -like '*saas_service*main.py*' -or $_.CommandLine -like '*run_ui.py*' -or $_.Name -eq 'collector.exe' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }"

echo.
echo All services have been stopped.
timeout /t 2 >nul
