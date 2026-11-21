@echo off
title AIOps Collector Control Center
cd /d "%~dp0"
echo ===================================================
echo Launching Collector Control Center Desktop UI...
echo ===================================================
python run_ui.py
pause
