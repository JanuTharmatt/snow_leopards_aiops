"""
Control Center UI & Standalone Collector Daemon Launcher.
PyInstaller Entrypoint for collector.exe.
Guarantees clean execution on fresh Windows installations without Python installed.
"""

import argparse
import logging
import os
from pathlib import Path
import sys
import threading
import time

# Handle PyInstaller frozen bundle execution path
if getattr(sys, 'frozen', False):
    bundle_dir = Path(getattr(sys, '_MEIPASS', sys.executable)).resolve()
    if bundle_dir.is_file():
        bundle_dir = bundle_dir.parent
    for p in [bundle_dir, bundle_dir / "collector", bundle_dir / "collector" / "ui", bundle_dir / "ui"]:
        if p.exists() and str(p) not in sys.path:
            sys.path.insert(0, str(p))
else:
    root_dir = Path(__file__).resolve().parent
    collector_dir = root_dir / "collector"
    for p in [root_dir, collector_dir, collector_dir / "ui"]:
        if p.exists() and str(p) not in sys.path:
            sys.path.insert(0, str(p))

# Ensure collector config is importable
try:
    from collector.config import config, load_collector_config
except (ImportError, ModuleNotFoundError):
    try:
        from config import config, load_collector_config
    except (ImportError, ModuleNotFoundError):
        pass


def run_daemon_service(interval: int = 5):
    """
    Runs the unified background collection, egress, and heartbeat loops.
    Allows collector.exe to run autonomously as a detached background daemon
    on external Windows machines without Python installed.
    """
    try:
        from collector.collector import PipelineProcessor
        from collector.egress_worker import EgressWorker
        from collector.heartbeat_service import HeartbeatService
    except (ImportError, ModuleNotFoundError):
        from collector import PipelineProcessor
        from egress_worker import EgressWorker
        from heartbeat_service import HeartbeatService

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
    )
    logger = logging.getLogger("AIOps.CollectorService")
    logger.info("Starting standalone Collector Daemon Service...")
    logger.info(f"Tenant: {config.saas.tenant_id} | Collector: {config.saas.collector_id} | Cloud: {config.saas.saas_url}")

    stop_event = threading.Event()
    processor = PipelineProcessor()
    egress_worker = EgressWorker(poll_interval=2.0)
    heartbeat_service = HeartbeatService(interval_seconds=15)

    def collector_loop():
        while not stop_event.is_set():
            try:
                processor.run_collection_cycle()
            except Exception as e:
                logger.error(f"Collector cycle error: {e}")
            stop_event.wait(interval)

    def egress_loop():
        while not stop_event.is_set():
            try:
                egress_worker.process_pending_batch()
            except Exception as e:
                logger.error(f"Egress transmission error: {e}")
            stop_event.wait(2.0)

    def heartbeat_loop():
        while not stop_event.is_set():
            try:
                heartbeat_service.send_heartbeat(status="ONLINE")
            except Exception as e:
                logger.error(f"Heartbeat delivery error: {e}")
            stop_event.wait(15)

    threads = [
        threading.Thread(target=collector_loop, name="CollectorThread", daemon=True),
        threading.Thread(target=egress_loop, name="EgressThread", daemon=True),
        threading.Thread(target=heartbeat_loop, name="HeartbeatThread", daemon=True),
    ]
    for t in threads:
        t.start()

    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        stop_event.set()
        logger.info("Collector service shut down.")


def main():
    parser = argparse.ArgumentParser(description="Privacy-First AIOps — Collector Control Center")
    parser.add_argument("--minimized", action="store_true", help="Launch directly into Windows System Tray")
    parser.add_argument("--service", action="store_true", help="Run as detached background collector service daemon")
    parser.add_argument("--daemon", action="store_true", help="Run as detached background collector service daemon")
    parser.add_argument("--interval", type=int, default=5, help="Collection interval in seconds")
    args = parser.parse_args()

    # If launched as background service daemon
    if args.service or args.daemon:
        run_daemon_service(interval=args.interval)
        return

    # Normal execution: Launch Desktop GUI Control Center
    try:
        from ui.app import launch_app
    except (ImportError, ModuleNotFoundError):
        try:
            from collector.ui.app import launch_app
        except (ImportError, ModuleNotFoundError):
            import ui.app as app_mod
            launch_app = app_mod.launch_app

    launch_app(start_minimized=args.minimized)


if __name__ == "__main__":
    main()
