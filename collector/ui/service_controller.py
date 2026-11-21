"""
Collector Service Controller for Local Control Center.
Manages the independent Collector background process.
Guarantees that the Collector Service runs autonomously and remains fully operational
whether the UI is minimized, closed, or never launched.
"""

from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Any, Dict, Optional

import psutil

# Base directories
COLLECTOR_DIR = Path(__file__).resolve().parent.parent
PID_FILE_PATH = COLLECTOR_DIR / "collector.pid"
STATUS_FILE_PATH = COLLECTOR_DIR / "service_status.json"

logger = logging.getLogger("AIOps.ServiceController")


class CollectorServiceController:
    """
    Manages starting, stopping, and monitoring the decoupled Collector service daemon.
    Uses detached subprocess spawning on Windows so the collector process outlives the UI.
    """

    def __init__(self, collector_dir: Optional[Path] = None):
        self.collector_dir = collector_dir or COLLECTOR_DIR
        self.pid_file = self.collector_dir / "collector.pid"
        self.status_file = self.collector_dir / "service_status.json"

    def get_service_status(self) -> Dict[str, Any]:
        """
        Inspects process existence and returns real-time service health.
        """
        pid = self._read_pid()
        is_running = False
        uptime_seconds = 0
        cpu_percent = 0.0
        memory_mb = 0.0

        if pid and psutil.pid_exists(pid):
            try:
                proc = psutil.Process(pid)
                # Verify it is actually a python or collector process
                cmdline = " ".join(proc.cmdline()).lower()
                if "python" in proc.name().lower() or "collector" in cmdline:
                    is_running = True
                    uptime_seconds = int(time.time() - proc.create_time())
                    cpu_percent = round(proc.cpu_percent(interval=None), 1)
                    memory_mb = round(proc.memory_info().rss / (1024 * 1024), 1)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                is_running = False

        status_text = "ONLINE" if is_running else "STOPPED"
        return {
            "is_running": is_running,
            "pid": pid if is_running else None,
            "status": status_text,
            "uptime_seconds": uptime_seconds,
            "cpu_percent": cpu_percent,
            "memory_mb": memory_mb,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        }

    def start_service(self) -> bool:
        """
        Spawns the Collector daemon as an independent, detached Windows process.
        """
        status = self.get_service_status()
        if status["is_running"]:
            logger.info(f"Collector service is already running (PID: {status['pid']}).")
            return True

        is_frozen = getattr(sys, 'frozen', False)
        if is_frozen:
            cmd = [sys.executable, "--service", "--interval", "5"]
            working_dir = Path(sys.executable).parent
        else:
            collector_script = self.collector_dir / "collector.py"
            python_exe = sys.executable
            cmd = [python_exe, str(collector_script), "--daemon", "--interval", "5"]
            working_dir = self.collector_dir

        # Flags for independent detached process on Windows
        DETACHED_PROCESS = 0x00000008
        CREATE_NEW_PROCESS_GROUP = 0x00000200
        flags = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP

        try:
            # Launch collector in background loop mode
            proc = subprocess.Popen(
                cmd,
                cwd=str(working_dir),
                creationflags=flags,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                close_fds=True
            )
            self._write_pid(proc.pid)
            logger.info(f"Started detached Collector Service with PID: {proc.pid}")
            time.sleep(0.5)
            return True
        except Exception as exc:
            logger.error(f"Failed to start Collector Service: {exc}")
            return False

    def stop_service(self) -> bool:
        """
        Terminates the detached collector process cleanly.
        """
        pid = self._read_pid()
        if not pid or not psutil.pid_exists(pid):
            self._clear_pid()
            return True

        try:
            proc = psutil.Process(pid)
            proc.terminate()
            proc.wait(timeout=3)
            self._clear_pid()
            logger.info(f"Terminated Collector Service (PID: {pid})")
            return True
        except Exception:
            try:
                proc.kill()
                self._clear_pid()
                return True
            except Exception as exc:
                logger.error(f"Failed to kill process {pid}: {exc}")
                return False

    def restart_service(self) -> bool:
        """Restarts the collector service."""
        self.stop_service()
        time.sleep(1)
        return self.start_service()

    def _read_pid(self) -> Optional[int]:
        if self.pid_file.exists():
            try:
                content = self.pid_file.read_text().strip()
                if content:
                    return int(content)
            except Exception:
                pass
        return None

    def _write_pid(self, pid: int) -> None:
        try:
            self.pid_file.write_text(str(pid))
        except Exception:
            pass

    def _clear_pid(self) -> None:
        if self.pid_file.exists():
            try:
                self.pid_file.unlink()
            except Exception:
                pass


service_controller = CollectorServiceController()
