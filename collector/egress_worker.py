"""
Egress Worker Module.
Transmits buffered metadata payloads from local SQLite buffer to the SaaS Ingestion Service over HTTPS.
Workflow:
PENDING -> Transmit -> Success (200 OK) -> SENT
Failure (5xx/Timeout) -> Retry with Exponential Backoff
Permanent Failure (400/Max Retries) -> DEAD_LETTER
"""

import argparse
import json
import logging
import os
from pathlib import Path
import sys
import time
from typing import Any, Dict, List, Optional
import requests

if __package__ is None or __package__ == "":
    collector_dir = str(Path(__file__).resolve().parent)
    if collector_dir not in sys.path:
        sys.path.insert(0, collector_dir)

try:
    from .buffer_manager import LocalBufferManager, buffer_manager
    from .config import config
    from .auth_client import CollectorAuthClient, auth_client
except (ImportError, ValueError):
    from buffer_manager import LocalBufferManager, buffer_manager
    from config import config
    from auth_client import CollectorAuthClient, auth_client

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [EgressWorker] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ"
)
logger = logging.getLogger("AIOps.EgressWorker")


class EgressWorker:
    """
    Background worker that reliably delivers buffered payloads to the SaaS platform.
    Ensures zero data loss and handles offline mode gracefully.
    """

    def __init__(
        self,
        buffer: Optional[LocalBufferManager] = None,
        saas_url: Optional[str] = None,
        collector_key: Optional[str] = None,
        poll_interval: Optional[float] = None,
        max_retries: Optional[int] = None,
        auth_client_instance: Optional[CollectorAuthClient] = None
    ):
        self.buffer = buffer or buffer_manager
        self.saas_url = (saas_url or config.saas.saas_url).rstrip("/")
        self.ingest_url = f"{self.saas_url}{config.saas.ingest_endpoint}"
        self.collector_key = collector_key or config.saas.collector_key
        self.poll_interval = poll_interval or config.saas.worker_poll_interval
        self.max_retries = max_retries or config.saas.max_retries_before_dlq
        self.auth_client = auth_client_instance or CollectorAuthClient(
            saas_url=self.saas_url,
            collector_id=config.saas.collector_id,
            collector_secret=config.saas.collector_secret,
            legacy_key=self.collector_key
        )

    def transmit_single_payload(self, item: Dict[str, Any], custom_session: Optional[Any] = None) -> str:
        """
        Attempts to transmit a single payload to the SaaS endpoint using dynamic JWT authentication.
        Automatically refreshes token if expired or rejected with HTTP 401.
        Returns:
            "SENT" if accepted or acknowledged duplicate
            "RETRY" if transient network or server error
            "DEAD_LETTER" if fatal client error (e.g. 400 Bad Request) or exceeded retries
        """
        payload_id = item["payload_id"]
        payload_data = item["payload_json"]
        retry_count = item.get("retry_count", 0)

        client = custom_session or requests

        try:
            headers = self.auth_client.get_auth_headers(custom_session=client)
        except Exception as auth_exc:
            err_msg = f"Failed to acquire JWT token: {str(auth_exc)}"
            logger.warning(f"Authentication acquisition failed for [{payload_id}]: {err_msg}. Will retry.")
            self.buffer.mark_as_failed(payload_id, error=err_msg)
            return "RETRY"

        post_kwargs = {"timeout": 5.0}
        if (client is requests or isinstance(client, requests.Session)) and config.saas.verify_ssl:
            post_kwargs["verify"] = config.saas.ca_cert_path if config.saas.ca_cert_path and Path(config.saas.ca_cert_path).exists() else True

        try:
            response = client.post(
                self.ingest_url,
                json=payload_data,
                headers=headers,
                **post_kwargs
            )

            # Auto-Refresh on 401: Token expired or revoked
            if response.status_code == 401:
                logger.warning(f"JWT expired/rejected (HTTP 401) for [{payload_id}]. Refreshing token via Collector Secret...")
                try:
                    refreshed_headers = self.auth_client.get_auth_headers(force_refresh=True, custom_session=client)
                    response = client.post(
                        self.ingest_url,
                        json=payload_data,
                        headers=refreshed_headers,
                        **post_kwargs
                    )
                except Exception as refresh_exc:
                    err_msg = f"Token refresh attempt failed: {str(refresh_exc)}"
                    logger.error(err_msg)
                    self.buffer.mark_as_failed(payload_id, error=err_msg)
                    return "RETRY"

            # Success or Idempotent Duplicate
            if response.status_code == 200:
                resp_json = response.json()
                is_duplicate = resp_json.get("duplicate", False)
                if is_duplicate:
                    logger.info(f"Payload [{payload_id}] recognized as duplicate by SaaS. Marking SENT.")
                else:
                    logger.info(f"Payload [{payload_id}] successfully ingested by SaaS. Marking SENT.")
                self.buffer.mark_as_sent(payload_id)
                return "SENT"

            # Fatal Client Error (e.g. 400 Checksum Mismatch, 422 Invalid Schema) -> DEAD_LETTER
            elif response.status_code in (400, 422):
                err_msg = f"HTTP {response.status_code}: {response.text}"
                logger.error(f"Payload [{payload_id}] rejected by SaaS ({err_msg}). Moving to DEAD_LETTER.")
                self.buffer.mark_as_dead_letter(payload_id, reason=err_msg)
                return "DEAD_LETTER"

            # Unrecoverable 401 after retry
            elif response.status_code == 401:
                err_msg = f"HTTP 401 Unauthorized: Invalid credentials or token rejected"
                logger.error(f"Payload [{payload_id}] unauthorized after token refresh. Moving to DEAD_LETTER.")
                self.buffer.mark_as_dead_letter(payload_id, reason=err_msg)
                return "DEAD_LETTER"

            # Server error (5xx)
            else:
                err_msg = f"HTTP {response.status_code}: {response.text}"
                logger.warning(f"Transmission error for [{payload_id}] ({err_msg}). Will retry.")
                new_retries = self.buffer.mark_as_failed(payload_id, error=err_msg)
                if new_retries >= self.max_retries:
                    logger.error(f"Payload [{payload_id}] exceeded max retries ({new_retries}/{self.max_retries}). Moving to DEAD_LETTER.")
                    self.buffer.mark_as_dead_letter(payload_id, reason=f"Max retries exceeded: {err_msg}")
                    return "DEAD_LETTER"
                return "RETRY"

        except requests.exceptions.RequestException as exc:
            err_msg = f"Network connection error: {str(exc)}"
            logger.warning(f"Backend offline / unreachable for [{payload_id}]. Will replay when online. ({err_msg})")
            new_retries = self.buffer.mark_as_failed(payload_id, error=err_msg)
            if new_retries >= self.max_retries:
                logger.error(f"Payload [{payload_id}] exceeded max retries during network outages. Moving to DEAD_LETTER.")
                self.buffer.mark_as_dead_letter(payload_id, reason=f"Max retries exceeded during outage: {err_msg}")
                return "DEAD_LETTER"
            return "RETRY"

    def process_pending_batch(self, batch_size: int = 50, custom_session: Optional[Any] = None) -> Dict[str, int]:
        """
        Fetches up to batch_size PENDING payloads and transmits them sequentially.
        Returns summary counts.
        """
        pending = self.buffer.get_unsent_payloads(limit=batch_size)
        if not pending:
            return {"sent": 0, "retried": 0, "dead_letter": 0, "total": 0}

        counts = {"sent": 0, "retried": 0, "dead_letter": 0, "total": len(pending)}
        for item in pending:
            res = self.transmit_single_payload(item, custom_session=custom_session)
            if res == "SENT":
                counts["sent"] += 1
            elif res == "DEAD_LETTER":
                counts["dead_letter"] += 1
            elif res == "RETRY":
                counts["retried"] += 1
                time.sleep(0.1)

        return counts

    def run_worker_loop(self, max_cycles: Optional[int] = None) -> None:
        """Continuous egress synchronization worker loop with exponential backoff."""
        logger.info(f"Starting Egress Worker. Target SaaS: {self.ingest_url}")
        cycles = 0
        backoff_seconds = 1.0

        try:
            while True:
                cycles += 1
                counts = self.process_pending_batch()
                if counts["total"] > 0:
                    logger.info(f"Batch processed: {counts['sent']} sent, {counts['dead_letter']} dead-letter, {counts['retried']} retrying.")
                    if counts["sent"] > 0:
                        backoff_seconds = 1.0  # Reset backoff on successful delivery
                    elif counts["retried"] > 0:
                        backoff_seconds = min(backoff_seconds * 2.0, 30.0)
                else:
                    backoff_seconds = 1.0

                if max_cycles and cycles >= max_cycles:
                    logger.info(f"Completed {max_cycles} sync cycles. Stopping worker.")
                    break

                sleep_time = self.poll_interval if counts["retried"] == 0 else backoff_seconds
                time.sleep(sleep_time)

        except KeyboardInterrupt:
            logger.info("Egress Worker stopped by operator.")


def main():
    parser = argparse.ArgumentParser(description="AIOps Egress Transmission Worker (Phase 2)")
    parser.add_argument("--run-once", action="store_true", help="Process one pending batch and exit")
    parser.add_argument("--daemon", action="store_true", help="Run continuous background egress worker loop")
    parser.add_argument("--saas-url", type=str, default=None, help="SaaS ingestion service base URL")
    parser.add_argument("--key", type=str, default=None, help="Collector API key override")
    parser.add_argument("--interval", type=float, default=2.0, help="Poll interval in seconds")
    parser.add_argument("--view-dlq", action="store_true", help="View dead-letter queue records")

    args = parser.parse_args()
    worker = EgressWorker(
        saas_url=args.saas_url,
        collector_key=args.key,
        poll_interval=args.interval
    )

    if args.view_dlq:
        dlq = worker.buffer.get_dead_letter_payloads()
        print(f"\n--- DEAD LETTER QUEUE (Total: {len(dlq)}) ---")
        for item in dlq:
            print(f"[Payload ID: {item['payload_id']}] Retries: {item['retry_count']} | Reason: {item['failure_reason']}")
            print(json.dumps(item["payload_json"], indent=2))
        return

    if args.run_once:
        counts = worker.process_pending_batch()
        print(f"\n[Batch Result] Sent: {counts['sent']} | Retried: {counts['retried']} | Dead-Letter: {counts['dead_letter']} | Total: {counts['total']}")
        return

    worker.run_worker_loop()


if __name__ == "__main__":
    main()
