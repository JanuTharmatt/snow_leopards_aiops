@echo off
title AIOps Edge Telemetry Collector Daemon
cd /d "%~dp0"
echo ===================================================
echo Starting Unified Edge Collector Daemon...
echo - Telemetry Sampling (every 5s)
echo - Egress Worker (streaming to SaaS)
echo - Fleet Heartbeat (every 30s)
echo ===================================================
python run_collector.py
pause
