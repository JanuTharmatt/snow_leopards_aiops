"""
Fleet Watchdog & Outage State Machine.
Phase 3 Task F:
Monitors collector freshness against the 60-second offline threshold.
Manages the 4 distinct health states:
- Healthy
- Degraded
- Critical
- Stale/Offline
Triggers outage alerts when collectors go silent, and handles automatic recovery when buffered payloads drain.
"""

from datetime import datetime, timezone
import logging
import time
from typing import Any, Dict, List, Optional

try:
    from .storage import storage_service
except (ImportError, ValueError):
    from saas_service.services.storage import storage_service

logger = logging.getLogger("AIOps.FleetWatchdog")


class FleetWatchdog:
    """Monitors collector liveness and enforces the 4-health-state model."""

    def __init__(self, stale_threshold_seconds: float = 60.0):
        self.stale_threshold_seconds = stale_threshold_seconds

    def check_fleet_freshness(self) -> List[Dict[str, Any]]:
        """
        Inspects all collectors in the registry.
        Transitions any silent collector (> 60s) to 'Stale/Offline' and generates an outage alert.
        """
        now = datetime.now(timezone.utc)
        collectors = storage_service.get_all_collectors()
        stale_nodes = []

        for c in collectors:
            cid = c["collector_id"]
            tenant_id = c["tenant_id"]
            last_seen_str = c.get("last_seen", "")

            try:
                # Handle both 'Z' and offset ISO formats
                if last_seen_str.endswith("Z"):
                    last_seen_dt = datetime.fromisoformat(last_seen_str[:-1] + "+00:00")
                else:
                    last_seen_dt = datetime.fromisoformat(last_seen_str)
                
                if last_seen_dt.tzinfo is None:
                    last_seen_dt = last_seen_dt.replace(tzinfo=timezone.utc)

                elapsed = (now - last_seen_dt).total_seconds()
            except Exception:
                elapsed = self.stale_threshold_seconds + 1.0

            if elapsed > self.stale_threshold_seconds:
                stale_nodes.append(c)
                if c.get("status") != "Stale/Offline":
                    logger.warning(f"Collector [{cid}] is STALE ({int(elapsed)}s since last seen). Marking 'Stale/Offline'.")
                    storage_service.update_collector_status(cid, "Stale/Offline")
                    
                    alert_id = f"OUTAGE-{cid}-{int(time.time())}"
                    storage_service.store_alert(
                        alert_id=alert_id,
                        collector_id=cid,
                        tenant_id=tenant_id,
                        alert_type="COLLECTOR_OUTAGE",
                        severity="CRITICAL",
                        diagnosis=f"Outage detected: Collector '{cid}' has not reported telemetry or heartbeats for {int(elapsed)}s (exceeded {int(self.stale_threshold_seconds)}s SLA threshold).",
                        metrics={"elapsed_seconds": round(elapsed, 1), "threshold_seconds": self.stale_threshold_seconds}
                    )

        return stale_nodes

    def on_collector_activity(self, collector_id: str, new_status: str = "Healthy") -> None:
        """
        Invoked upon receiving telemetry or heartbeat from a collector.
        Cleans up active outage alerts and restores health state.
        """
        storage_service.resolve_alerts(collector_id, alert_type="COLLECTOR_OUTAGE")
        storage_service.update_collector_status(collector_id, new_status)


watchdog = FleetWatchdog()
