@echo off
title AIOps Platform Launcher
cd /d "%~dp0"
echo ===================================================
echo Launching Complete Privacy-First AIOps Observability Platform
echo 1. Central SaaS Ingestion Service & Dashboard
echo 2. Edge Telemetry Collector Daemon
echo 3. Collector Control Center Desktop UI
echo ===================================================

start "SaaS Backend & Dashboard" cmd /k "start_saas_dashboard.bat"
timeout /t 2 /nobreak >nul
start "Edge Collector Daemon" cmd /k "start_collector.bat"
timeout /t 2 /nobreak >nul
start "Collector Control Center UI" cmd /k "start_collector_ui.bat"

echo All services launched in separate windows!
