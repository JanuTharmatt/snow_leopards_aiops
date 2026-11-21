"""
Collector Service and Pipeline Orchestrator for Privacy-First AIOps Observability Platform.

Stage 1 Capabilities:
- Real-time host telemetry (psutil + ping3 every 5s)
- Failed-login event counting
- Website / API availability HTTP checks
- Simulator mode for load / incident testing
- Local raw-vs-redacted audit viewer
- Single payload-builder chokepoint integration (Allow-List -> Redaction -> Local Audit -> EgressPayload)
- Local SQLite buffer persistence (unsent_payloads) without raw data.
"""

import argparse
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import sys
import time
from typing import Any, Dict, List, Optional, Tuple, Union

import ping3
import psutil
import requests

if __package__ is None or __package__ == "":
    collector_dir = str(Path(__file__).resolve().parent)
    if collector_dir not in sys.path:
        sys.path.insert(0, collector_dir)

try:
    from .buffer_manager import LocalBufferManager, buffer_manager
    from .config import config
    from .metadata_engine import MetadataEngine, metadata_engine
    from .models import EgressPayload, LocalAuditRecord, RawSystemMetrics
    from .payload_builder import LOCAL_AUDIT_LOG_PATH, build_egress_payload
    from .security_pipeline import SecurityPipeline, security_pipeline
except (ImportError, ValueError):
    from buffer_manager import LocalBufferManager, buffer_manager
    from config import config
    from metadata_engine import MetadataEngine, metadata_engine
    from models import EgressPayload, LocalAuditRecord, RawSystemMetrics
    from payload_builder import LOCAL_AUDIT_LOG_PATH, build_egress_payload
    from security_pipeline import SecurityPipeline, security_pipeline

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ"
)
logger = logging.getLogger("AIOps.Collector")


class SystemCollector:
    """
    Hardware, Network, and Availability Telemetry Collector.
    Polls host metrics using psutil, ping3, and requests.
    """

    def __init__(
        self,
        target_host: Optional[str] = None,
        timeout: Optional[float] = None,
        website_url: Optional[str] = None
    ):
        self.target_host = target_host or config.telemetry.ping_target
        self.timeout = timeout or config.telemetry.ping_timeout_seconds
        self.website_url = website_url or config.telemetry.website_check_url
        self.failed_logins_counter: int = 0
        psutil.cpu_percent(interval=None)

    def get_cpu_usage(self) -> float:
        """Returns CPU usage percentage across all cores."""
        return round(psutil.cpu_percent(interval=0.1), 1)

    def get_memory_usage(self) -> float:
        """Returns RAM usage percentage."""
        return round(psutil.virtual_memory().percent, 1)

    def get_disk_usage(self) -> float:
        """Returns storage disk usage percentage for active drive."""
        try:
            drive_root = Path.cwd().anchor or "."
            return round(psutil.disk_usage(drive_root).percent, 1)
        except Exception:
            return round(psutil.disk_usage(".").percent, 1)

    def get_network_usage(self) -> Dict[str, int]:
        """Returns raw network I/O counters."""
        net = psutil.net_io_counters()
        return {
            "bytes_sent": net.bytes_sent,
            "bytes_recv": net.bytes_recv,
            "packets_sent": net.packets_sent,
            "packets_recv": net.packets_recv,
        }

    def get_network_quality(self, probes: int = 4) -> Tuple[float, float]:
        """
        Measures real network latency (ms) and packet loss percentage (0-100%).
        Feature A: Real Packet Loss Monitoring via burst ICMP probes.
        """
        successful_latencies: List[float] = []
        for _ in range(probes):
            try:
                res = ping3.ping(self.target_host, unit="ms", timeout=self.timeout)
                if res is not None and res is not False:
                    successful_latencies.append(float(res))
            except Exception as exc:
                logger.debug(f"ping3 probe failed: {exc}")
            time.sleep(0.05)

        if not successful_latencies:
            return float(config.telemetry.fallback_latency_ms), 100.0

        avg_latency = round(sum(successful_latencies) / len(successful_latencies), 1)
        loss_pct = round(((probes - len(successful_latencies)) / probes) * 100.0, 1)
        return avg_latency, loss_pct

    def get_latency(self) -> float:
        """Measures ping latency in ms via ping3 with safe fallback."""
        lat, _ = self.get_network_quality(probes=1)
        return lat

    def check_website_availability(self) -> Dict[str, Any]:
        """
        Website / API availability check.
        Reports status code, availability boolean, and response latency without exposing raw endpoints.
        """
        try:
            start = time.perf_counter()
            resp = requests.get(self.website_url, timeout=2.0)
            elapsed_ms = round((time.perf_counter() - start) * 1000, 1)
            return {
                "status_code": resp.status_code,
                "is_available": resp.status_code < 400,
                "response_time_ms": elapsed_ms
            }
        except Exception as exc:
            return {
                "status_code": 0,
                "is_available": False,
                "error": "UNREACHABLE"
            }

    def register_failed_login(self, count: int = 1) -> None:
        """Increments failed auth event count."""
        self.failed_logins_counter += count

    def reset_failed_logins(self) -> int:
        """Returns and resets failed auth event count for current cycle."""
        count = self.failed_logins_counter
        self.failed_logins_counter = 0
        return count

    def collect(self) -> RawSystemMetrics:
        """Gathers a complete snapshot of host metrics including packet loss."""
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        latency, packet_loss = self.get_network_quality()
        return RawSystemMetrics(
            cpu=self.get_cpu_usage(),
            memory=self.get_memory_usage(),
            disk=self.get_disk_usage(),
            latency=latency,
            packet_loss=packet_loss,
            timestamp=now_utc,
            network=self.get_network_usage(),
            failed_logins=self.reset_failed_logins(),
            website_status=self.check_website_availability()
        )


class PipelineProcessor:
    """
    Orchestrates the Single Chokepoint Pipeline:
    Raw Data -> Payload Builder Chokepoint (Allow-List -> Redact -> Local Audit -> Hash) -> Local SQLite Buffer
    """

    def __init__(
        self,
        collector: Optional[SystemCollector] = None,
        buffer: Optional[LocalBufferManager] = None,
        audit_log_path: Optional[Path] = None
    ):
        self.collector = collector or SystemCollector()
        self.buffer = buffer or buffer_manager
        self.audit_log_path = audit_log_path

    def process_record(
        self,
        raw_data: Union[str, Dict[str, Any], RawSystemMetrics]
    ) -> Tuple[str, EgressPayload, LocalAuditRecord]:
        """
        Executes single chokepoint pipeline.
        Guarantees raw_data is kept ONLY in local audit log and never enters SQLite buffer.
        """
        egress_payload, audit_record = build_egress_payload(
            raw_data,
            audit_log_path=self.audit_log_path
        )
        payload_id = self.buffer.store_payload(egress_payload)
        logger.info(f"Buffered sanitized payload [id={payload_id}] to SQLite (raw_data excluded)")
        return payload_id, egress_payload, audit_record

    def run_collection_cycle(self) -> Tuple[str, EgressPayload, LocalAuditRecord]:
        """Collects live metrics and pushes through the chokepoint."""
        metrics = self.collector.collect()
        return self.process_record(metrics)

    def start_loop(self, interval_seconds: Optional[int] = None, max_iterations: Optional[int] = None) -> None:
        """Continuous collection loop with immediate real-time egress synchronization to SaaS."""
        interval = interval_seconds or config.telemetry.interval_seconds
        iteration = 0
        logger.info(f"Starting AIOps Collector loop (Interval: {interval}s)...")

        # Lazy-load egress worker and heartbeat service for automatic transmission
        egress = None
        heartbeat = None
        try:
            from .egress_worker import EgressWorker
            from .heartbeat_service import HeartbeatService
            egress = EgressWorker(buffer=self.buffer, poll_interval=2.0)
            heartbeat = HeartbeatService(interval_seconds=15)
        except (ImportError, ValueError):
            try:
                from egress_worker import EgressWorker
                from heartbeat_service import HeartbeatService
                egress = EgressWorker(buffer=self.buffer, poll_interval=2.0)
                heartbeat = HeartbeatService(interval_seconds=15)
            except Exception as e:
                logger.warning(f"Could not initialize egress worker: {e}")

        try:
            while True:
                iteration += 1
                logger.info(f"--- Cycle #{iteration} ---")
                pid, payload, audit = self.run_collection_cycle()
                logger.info(f"Buffered Payload {pid} (SHA-256: {payload.sha256[:12]}..., Status: PENDING)")

                # Immediate real-time data synchronization to SaaS
                if egress:
                    try:
                        sent_count = egress.process_pending_batch()
                        if sent_count > 0:
                            logger.info(f"Real-time sync: transmitted {sent_count} payload(s) to SaaS Cloud ({config.saas.saas_url})")
                    except Exception as eg_err:
                        logger.warning(f"Real-time transmission error (queued for replay): {eg_err}")

                # Heartbeat delivery
                if heartbeat and iteration % 3 == 0:
                    try:
                        heartbeat.send_heartbeat(status="ONLINE")
                    except Exception:
                        pass

                if max_iterations and iteration >= max_iterations:
                    logger.info(f"Reached max iterations ({max_iterations}). Exiting loop.")
                    break

                time.sleep(interval)
        except KeyboardInterrupt:
            logger.info("Collector loop stopped by operator.")


def run_simulator(mode: str, processor: PipelineProcessor) -> None:
    """Simulator mode for generating synthetic stress / fault telemetry without host load."""
    logger.info(f"Running in SIMULATOR mode: {mode}")
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    if mode == "cpu_spike":
        synthetic = {
            "cpu": 96.5,
            "memory": 62.0,
            "disk": 51.0,
            "latency": 15.0,
            "timestamp": now_utc,
            "failed_logins": 0
        }
    elif mode == "memory_leak":
        synthetic = {
            "cpu": 45.0,
            "memory": 92.4,
            "disk": 51.0,
            "latency": 18.0,
            "timestamp": now_utc,
            "failed_logins": 0
        }
    elif mode == "auth_failure":
        synthetic = {
            "cpu": 42.0,
            "memory": 58.0,
            "disk": 45.0,
            "latency": 12.0,
            "timestamp": now_utc,
            "failed_logins": 15  # Spiked failed auth events
        }
    elif mode == "ddos_flood":
        synthetic = {
            "cpu": 62.0,
            "memory": 54.0,
            "disk": 40.0,
            "latency": 240.0,
            "packet_loss": 25.0,
            "timestamp": now_utc,
            "failed_logins": 0
        }
    elif mode == "slowloris":
        synthetic = {
            "cpu": 24.0,
            "memory": 42.0,
            "disk": 38.0,
            "latency": 320.0,
            "packet_loss": 0.0,
            "timestamp": now_utc,
            "failed_logins": 0
        }
    elif mode == "payment_failure":
        synthetic = "Payment Failed: gateway timeout after retry attempt"
    else:
        logger.error(f"Unknown simulator mode: {mode}")
        return

    pid, payload, audit = processor.process_record(synthetic)
    print(f"\n[SIMULATOR RESULT] Simulated '{mode}' successfully.")
    print("Buffered Payload ID:", pid)
    print("Transmittable Egress Payload (No raw data):")
    print(json.dumps(payload.model_dump(), indent=2))


def display_local_audit_log(limit: int = 5) -> None:
    """Local Raw-vs-Redacted View: Inspects local audit file on host without transmission."""
    if not LOCAL_AUDIT_LOG_PATH.exists():
        print(f"No local audit records found at {LOCAL_AUDIT_LOG_PATH}")
        return

    records: List[Dict[str, Any]] = []
    with open(LOCAL_AUDIT_LOG_PATH, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                try:
                    records.append(json.loads(line.strip()))
                except Exception:
                    pass

    print(f"\n=======================================================")
    print(f"LOCAL RAW-VS-REDACTED VIEW (Host Machine Perimeter)")
    print(f"File: {LOCAL_AUDIT_LOG_PATH} | Total Records: {len(records)}")
    print(f"SECURITY GUARANTEE: Raw data stays exclusively in this file.")
    print(f"=======================================================")

    display_subset = records[-limit:]
    for i, r in enumerate(display_subset, 1):
        print(f"\n--- Entry #{i} [Payload ID: {r.get('payload_id')}] ---")
        print(f"Timestamp: {r.get('timestamp')}")
        print(f"[RAW INPUT DATA (LOCAL ONLY)]:")
        print(json.dumps(r.get("raw_data"), indent=2))
        print(f"[REDACTED & ALLOW-LISTED DATA (TRANSMISSION READY)]:")
        print(json.dumps(r.get("redacted_data"), indent=2))
        if r.get("dropped_fields"):
            print(f"Dropped Unallowed Fields: {r.get('dropped_fields')}")
        if r.get("scrubbed_detections"):
            print(f"Scrubbed PII/Credentials: {r.get('scrubbed_detections')}")


def main():
    parser = argparse.ArgumentParser(description="Privacy-First AIOps Observability Collector (Stage 1)")
    parser.add_argument("--collect-only", action="store_true", help="Print raw collected system telemetry once")
    parser.add_argument("--run-once", action="store_true", help="Run 1 telemetry collection and pipeline cycle")
    parser.add_argument("--daemon", action="store_true", help="Run continuous collection loop every 5s")
    parser.add_argument("--iterations", type=int, default=None, help="Limit number of collection cycles")
    parser.add_argument("--interval", type=int, default=5, help="Collection interval in seconds (default: 5)")
    parser.add_argument("--test-pii", action="store_true", help="Execute verification test with sensitive log input")
    parser.add_argument("--view-buffer", action="store_true", help="Display all unsent payloads from local SQLite buffer")
    parser.add_argument("--view-local-audit", action="store_true", help="Display Local Raw-vs-Redacted View from local audit log")
    parser.add_argument("--simulate", type=str, choices=["cpu_spike", "memory_leak", "auth_failure", "ddos_flood", "slowloris", "payment_failure"],
                        help="Run simulator mode with synthetic stress/fault scenarios")

    args = parser.parse_args()
    processor = PipelineProcessor()

    if args.view_local_audit:
        display_local_audit_log()
        return

    if args.simulate:
        run_simulator(args.simulate, processor)
        return

    if args.collect_only:
        collector = SystemCollector()
        metrics = collector.collect()
        print("\n--- Raw Collected Telemetry ---")
        clean_view = {
            "cpu": metrics.cpu,
            "memory": metrics.memory,
            "disk": metrics.disk,
            "latency": metrics.latency,
            "failed_logins": metrics.failed_logins,
            "timestamp": metrics.timestamp
        }
        print(json.dumps(clean_view, indent=2))
        return

    if args.test_pii:
        print("\n--- Testing Security Pipeline & Metadata Engine with User Sample ---")
        sample_log = "User: Manik Sharma\nPassword: abc123\nAPI_KEY: abc-xyz-123\n\nPayment Failed"
        print("Input:\n", sample_log)
        pid, payload, audit = processor.process_record(sample_log)
        print("\nExpected Redacted Output (in transmission payload):")
        print(payload.data.get("message"))
        print("\nGenerated Metadata:")
        print(json.dumps(payload.metadata, indent=2))
        print("\nBuffered Egress Payload ID:", pid)
        print("SHA-256 Checksum:", payload.sha256)
        print("Source Timezone:", payload.source_timezone)
        print("Source ID Hash:", payload.source_id_hash)
        return

    if args.view_buffer:
        stats = processor.buffer.get_buffer_stats()
        print(f"\n--- Local Buffer Status (DB: {stats['db_path']}) ---")
        print(f"Total: {stats['total_payloads']} | Pending: {stats['pending_unsent']} | Sent: {stats['sent_payloads']}")
        payloads = processor.buffer.get_unsent_payloads(limit=10)
        print(f"\nShowing {len(payloads)} unsent payloads:")
        for p in payloads:
            print(f"\n[Payload ID]: {p['payload_id']} (Status: {p['status']})")
            print(json.dumps(p["payload_json"], indent=2))
        return

    if args.run_once:
        pid, payload, audit = processor.run_collection_cycle()
        print("\n--- Pipeline Execution Result ---")
        print("Buffered Payload ID:", pid)
        print(json.dumps(payload.model_dump(), indent=2))
        return

    processor.start_loop(interval_seconds=args.interval, max_iterations=args.iterations or (1 if not args.daemon else None))


if __name__ == "__main__":
    main()
