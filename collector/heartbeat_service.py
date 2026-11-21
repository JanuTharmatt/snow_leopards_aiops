"""
Heartbeat Service Module.
Sends periodic liveness heartbeats from the Edge Collector to the SaaS Platform.
Runs every 30 seconds (configurable) to update the SaaS Collector Registry.
Payload schema:
{
  "collector_id": "COLL-001",
  "version": "1.0.0",
  "status": "ONLINE",
  "timestamp": "UTC"
}
"""

import argparse
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import sys
import time
from typing import Any, Dict, Optional
import requests

if __package__ is None or __package__ == "":
    collector_dir = str(Path(__file__).resolve().parent)
    if collector_dir not in sys.path:
        sys.path.insert(0, collector_dir)

try:
    from .config import config
    from .auth_client import CollectorAuthClient, auth_client
except (ImportError, ValueError):
    from config import config
    from auth_client import CollectorAuthClient, auth_client

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [HeartbeatService] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ"
)
logger = logging.getLogger("AIOps.HeartbeatService")


class HeartbeatService:
    """Sends periodic heartbeats to SaaS for fleet monitoring and liveness tracking."""

    def __init__(
        self,
        saas_url: Optional[str] = None,
        collector_key: Optional[str] = None,
        collector_id: Optional[str] = None,
        version: str = "1.0.0",
        interval_seconds: Optional[int] = None,
        auth_client_instance: Optional[CollectorAuthClient] = None
    ):
        self.saas_url = (saas_url or config.saas.saas_url).rstrip("/")
        self.heartbeat_url = f"{self.saas_url}{config.saas.heartbeat_endpoint}"
        self.collector_key = collector_key or config.saas.collector_key
        self.collector_id = collector_id or config.saas.collector_id
        self.version = version
        self.interval_seconds = interval_seconds or config.saas.heartbeat_interval
        self.auth_client = auth_client_instance or CollectorAuthClient(
            saas_url=self.saas_url,
            collector_id=self.collector_id,
            collector_secret=config.saas.collector_secret,
            legacy_key=self.collector_key
        )

    def build_heartbeat_payload(self, status: str = "ONLINE") -> Dict[str, str]:
        """Constructs standardized heartbeat payload."""
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        return {
            "collector_id": self.collector_id,
            "version": self.version,
            "status": status,
            "timestamp": now_utc
        }

    def send_heartbeat(self, status: str = "ONLINE", custom_session: Optional[Any] = None) -> bool:
        """
        Sends one heartbeat to the SaaS endpoint.
        Returns True if acknowledged, False if unreachable or rejected.
        """
        payload = self.build_heartbeat_payload(status=status)
        client = custom_session or requests

        try:
            headers = self.auth_client.get_auth_headers(custom_session=client)
        except Exception:
            headers = {
                "Content-Type": "application/json",
                "X-Collector-Key": self.collector_key
            }

        post_kwargs = {"timeout": 5.0}
        if (client is requests or isinstance(client, requests.Session)) and config.saas.verify_ssl:
            post_kwargs["verify"] = config.saas.ca_cert_path if config.saas.ca_cert_path and Path(config.saas.ca_cert_path).exists() else True

        try:
            resp = client.post(
                self.heartbeat_url,
                json=payload,
                headers=headers,
                **post_kwargs
            )

            # Auto-Refresh on 401
            if resp.status_code == 401:
                try:
                    refreshed_headers = self.auth_client.get_auth_headers(force_refresh=True, custom_session=client)
                    resp = client.post(
                        self.heartbeat_url,
                        json=payload,
                        headers=refreshed_headers,
                        **post_kwargs
                    )
                except Exception:
                    pass

            if resp.status_code == 200:
                logger.info(f"Heartbeat acknowledged by SaaS: {payload['collector_id']} status={status}")
                return True
            else:
                logger.warning(f"Heartbeat rejected: HTTP {resp.status_code} ({resp.text})")
                return False

        except requests.exceptions.RequestException as exc:
            logger.warning(f"Failed to deliver heartbeat to SaaS ({self.heartbeat_url}): {exc}")
            return False

    def start_heartbeat_loop(self, max_pulses: Optional[int] = None) -> None:
        """Runs the continuous heartbeat loop (every 30 seconds)."""
        logger.info(f"Starting Heartbeat Service (Interval: {self.interval_seconds}s). Destination: {self.heartbeat_url}")
        pulse = 0
        try:
            while True:
                pulse += 1
                self.send_heartbeat(status="ONLINE")
                if max_pulses and pulse >= max_pulses:
                    logger.info(f"Completed {max_pulses} pulses. Stopping heartbeat service.")
                    break
                time.sleep(self.interval_seconds)
        except KeyboardInterrupt:
            logger.info("Heartbeat Service stopped by operator. Sending SHUTDOWN pulse...")
            self.send_heartbeat(status="SHUTDOWN")


def main():
    parser = argparse.ArgumentParser(description="AIOps Edge Heartbeat Service (Phase 2)")
    parser.add_argument("--send-once", action="store_true", help="Send a single heartbeat pulse and exit")
    parser.add_argument("--daemon", action="store_true", help="Run continuous heartbeat loop every 30s")
    parser.add_argument("--interval", type=int, default=30, help="Heartbeat interval in seconds (default: 30)")
    parser.add_argument("--saas-url", type=str, default=None, help="SaaS ingestion base URL")
    parser.add_argument("--key", type=str, default=None, help="Collector API key override")

    args = parser.parse_args()
    service = HeartbeatService(
        saas_url=args.saas_url,
        collector_key=args.key,
        interval_seconds=args.interval
    )

    if args.send_once:
        success = service.send_heartbeat()
        print(f"\n[Heartbeat Result] Acknowledged: {success}")
        return

    service.start_heartbeat_loop()


if __name__ == "__main__":
    main()
