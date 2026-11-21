@echo off
title AIOps SaaS Ingestion Service & Dashboard
cd /d "%~dp0"
echo ===================================================
echo Starting SaaS Platform & Observability Dashboard...
echo Dashboard URL: http://localhost:8000/dashboard
echo ===================================================
timeout /t 2 /nobreak >nul
start "" "http://localhost:8000/dashboard"
python saas_service/main.py
pause
