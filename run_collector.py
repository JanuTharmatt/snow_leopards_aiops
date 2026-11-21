"""
Unified Edge Collector Service Launcher.
Orchestrates:
1. Telemetry Collection Loop (PipelineProcessor) -> Samples metrics & buffers sanitized payloads to SQLite.
2. Egress Worker (EgressWorker) -> Reads PENDING payloads & transmits to SaaS with JWT Auth.
3. Heartbeat Service (HeartbeatService) -> Emits periodic liveness heartbeats to SaaS.

Usage:
    python run_collector.py
"""

import argparse
import logging
from pathlib import Path
import sys
import threading
import time

ROOT_DIR = Path(__file__).resolve().parent
COLLECTOR_DIR = ROOT_DIR / "collector"

if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))
if str(COLLECTOR_DIR) not in sys.path:
    sys.path.insert(0, str(COLLECTOR_DIR))

try:
    from collector.collector import PipelineProcessor
    from collector.egress_worker import EgressWorker
    from collector.heartbeat_service import HeartbeatService
    from collector.config import config
except (ImportError, ModuleNotFoundError):
    from collector import PipelineProcessor
    from egress_worker import EgressWorker
    from heartbeat_service import HeartbeatService
    from config import config

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ"
)
logger = logging.getLogger("AIOps.UnifiedCollector")


class UnifiedCollectorRunner:
    """Manages the lifecycle of collection, egress, and heartbeat worker threads."""

    def __init__(self, interval: int = 5, egress_poll_interval: float = 2.0, heartbeat_interval: int = 30):
        self.interval = interval
        self.egress_poll_interval = egress_poll_interval
        self.heartbeat_interval = heartbeat_interval
        self.stop_event = threading.Event()

        self.processor = PipelineProcessor()
        self.egress_worker = EgressWorker(poll_interval=self.egress_poll_interval)
        self.heartbeat_service = HeartbeatService(interval_seconds=self.heartbeat_interval)

    def _run_collector_loop(self):
        logger.info(f"Collector loop started (sampling every {self.interval}s)")
        iteration = 0
        while not self.stop_event.is_set():
            try:
                iteration += 1
                pid, payload, _ = self.processor.run_collection_cycle()
                logger.info(f"[Collector] Cycle #{iteration} buffered payload [{pid}] (Status: PENDING)")
            except Exception as exc:
                logger.error(f"[Collector] Error during collection cycle: {exc}")
            
            # Sleep with interruptible stop_event
            self.stop_event.wait(self.interval)

    def _run_egress_loop(self):
        logger.info(f"Egress transmission worker started (polling every {self.egress_poll_interval}s)")
        while not self.stop_event.is_set():
            try:
                counts = self.egress_worker.process_pending_batch()
                if counts["total"] > 0:
                    logger.info(f"[Egress] Transmitted: {counts['sent']} sent, {counts['retried']} retrying, {counts['dead_letter']} dlq")
            except Exception as exc:
                logger.error(f"[Egress] Error during egress transmission: {exc}")
            
            self.stop_event.wait(self.egress_poll_interval)

    def _run_heartbeat_loop(self):
        logger.info(f"Heartbeat service started (pulsing every {self.heartbeat_interval}s)")
        while not self.stop_event.is_set():
            try:
                self.heartbeat_service.send_heartbeat(status="ONLINE")
            except Exception as exc:
                logger.error(f"[Heartbeat] Error delivering heartbeat: {exc}")
            
            self.stop_event.wait(self.heartbeat_interval)

    def start(self):
        logger.info("==================================================================")
        logger.info("Starting Privacy-First AIOps Unified Edge Collector Daemon")
        logger.info(f"Tenant ID: {config.saas.tenant_id} | Collector ID: {config.saas.collector_id}")
        logger.info(f"SaaS Endpoint: {config.saas.saas_url}")
        logger.info("==================================================================")

        threads = [
            threading.Thread(target=self._run_collector_loop, name="CollectorThread", daemon=True),
            threading.Thread(target=self._run_egress_loop, name="EgressThread", daemon=True),
            threading.Thread(target=self._run_heartbeat_loop, name="HeartbeatThread", daemon=True),
        ]

        for t in threads:
            t.start()

        try:
            while True:
                time.sleep(1.0)
        except KeyboardInterrupt:
            logger.info("Shutdown signal received. Stopping worker threads...")
            self.stop_event.set()
            try:
                self.heartbeat_service.send_heartbeat(status="SHUTDOWN")
            except Exception:
                pass
            logger.info("Collector daemon safely stopped.")


def main():
    parser = argparse.ArgumentParser(description="Privacy-First AIOps Unified Collector Daemon")
    parser.add_argument("--interval", type=int, default=5, help="Telemetry collection interval (default: 5s)")
    parser.add_argument("--egress-interval", type=float, default=2.0, help="Egress poll interval (default: 2.0s)")
    parser.add_argument("--heartbeat-interval", type=int, default=30, help="Heartbeat pulse interval (default: 30s)")
    args = parser.parse_args()

    runner = UnifiedCollectorRunner(
        interval=args.interval,
        egress_poll_interval=args.egress_interval,
        heartbeat_interval=args.heartbeat_interval
    )
    runner.start()


if __name__ == "__main__":
    main()
