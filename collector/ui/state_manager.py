"""
State Manager for Collector Control Center.
Queries local SQLite buffer (database.db) and local audit vault (local_audit.jsonl).
Aggregates telemetry, queue status, egress proofs, and security statistics.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import time
from typing import Any, Dict, List, Optional
import requests

try:
    from ..config import config
    from ..models import ALLOWED_METRIC_FIELDS
except (ImportError, ValueError):
    from config import config
    from models import ALLOWED_METRIC_FIELDS

COLLECTOR_DIR = Path(__file__).resolve().parent.parent
DB_PATH = COLLECTOR_DIR / "database.db"
AUDIT_LOG_PATH = COLLECTOR_DIR / "local_audit.jsonl"


class CollectorStateManager:
    """Provides unified read-only querying of edge state for the Control Center UI."""

    def __init__(self, db_path: Optional[Path] = None, audit_path: Optional[Path] = None):
        self.db_path = db_path or DB_PATH
        self.audit_path = audit_path or AUDIT_LOG_PATH

    def get_queue_statistics(self) -> Dict[str, int]:
        """Reads real-time queue counts from SQLite 'unsent_payloads' table."""
        if not self.db_path.exists():
            return {"total": 0, "pending": 0, "sent": 0, "failed": 0, "dead_letter": 0}

        try:
            with sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True, timeout=2.0) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT 
                        COUNT(*) as total,
                        SUM(CASE WHEN status = 'PENDING' THEN 1 ELSE 0 END) as pending,
                        SUM(CASE WHEN status = 'SENT' THEN 1 ELSE 0 END) as sent,
                        SUM(CASE WHEN status = 'FAILED' THEN 1 ELSE 0 END) as failed,
                        SUM(CASE WHEN status = 'DEAD_LETTER' THEN 1 ELSE 0 END) as dead_letter
                    FROM unsent_payloads
                """)
                row = cursor.fetchone()
                return {
                    "total": row[0] or 0,
                    "pending": row[1] or 0,
                    "sent": row[2] or 0,
                    "failed": row[3] or 0,
                    "dead_letter": row[4] or 0
                }
        except Exception:
            return {"total": 0, "pending": 0, "sent": 0, "failed": 0, "dead_letter": 0}

    def get_recent_payloads(self, limit: int = 15) -> List[Dict[str, Any]]:
        """Retrieves recent records from unsent_payloads table."""
        if not self.db_path.exists():
            return []

        try:
            with sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True, timeout=2.0) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute("""
                    SELECT payload_id, timestamp, status, retry_count, failure_reason, payload_json
                    FROM unsent_payloads
                    ORDER BY timestamp DESC
                    LIMIT ?
                """, (limit,))
                rows = cursor.fetchall()

            results = []
            for r in rows:
                try:
                    p_json = json.loads(r["payload_json"])
                except Exception:
                    p_json = {}
                results.append({
                    "payload_id": r["payload_id"],
                    "timestamp": r["timestamp"],
                    "status": r["status"],
                    "retry_count": r["retry_count"],
                    "failure_reason": r["failure_reason"],
                    "sha256": p_json.get("sha256", "N/A"),
                    "data_type": p_json.get("data_type", "METRICS")
                })
            return results
        except Exception:
            return []

    def get_audit_records(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Reads raw vs redacted audit records from local_audit.jsonl."""
        if not self.audit_path.exists():
            return []

        records = []
        try:
            with open(self.audit_path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        try:
                            records.append(json.loads(line.strip()))
                        except Exception:
                            pass
            return records[-limit:]
        except Exception:
            return []

    def get_security_statistics(self) -> Dict[str, int]:
        """
        Feature 9: Aggregates total removed passwords, emails, API keys, and credit cards
        across all local audit records.
        """
        stats = {
            "passwords_removed": 0,
            "emails_removed": 0,
            "api_keys_removed": 0,
            "credit_cards_removed": 0,
            "names_removed": 0,
            "fields_dropped": 0,
            "total_scrubbed_events": 0
        }

        if not self.audit_path.exists():
            return stats

        try:
            with open(self.audit_path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        try:
                            entry = json.loads(line.strip())
                            detections = entry.get("scrubbed_detections", [])
                            dropped = entry.get("dropped_fields", [])

                            stats["fields_dropped"] += len(dropped)
                            stats["total_scrubbed_events"] += len(detections)

                            for d in detections:
                                d_upper = d.upper()
                                if "PASSWORD" in d_upper:
                                    stats["passwords_removed"] += 1
                                elif "EMAIL" in d_upper:
                                    stats["emails_removed"] += 1
                                elif "API_KEY" in d_upper or "KEY" in d_upper:
                                    stats["api_keys_removed"] += 1
                                elif "CREDIT_CARD" in d_upper or "CARD" in d_upper:
                                    stats["credit_cards_removed"] += 1
                                elif "NAME" in d_upper:
                                    stats["names_removed"] += 1
                        except Exception:
                            pass
        except Exception:
            pass

        return stats

    def check_saas_connectivity(self) -> Dict[str, Any]:
        """Pings the SaaS health endpoint to determine connectivity status."""
        health_url = f"{config.saas.saas_url.rstrip('/')}/health"
        start = time.perf_counter()
        try:
            resp = requests.get(health_url, timeout=1.5)
            latency_ms = round((time.perf_counter() - start) * 1000, 1)
            is_healthy = resp.status_code == 200 and resp.json().get("status") == "healthy"
            return {
                "is_connected": is_healthy,
                "status_code": resp.status_code,
                "latency_ms": latency_ms,
                "endpoint": health_url
            }
        except Exception as exc:
            return {
                "is_connected": False,
                "status_code": 0,
                "latency_ms": 0.0,
                "error": str(exc),
                "endpoint": health_url
            }

    def get_last_transmission_time(self) -> str:
        """Finds timestamp of latest successfully SENT payload."""
        if not self.db_path.exists():
            return "None"

        try:
            with sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True, timeout=2.0) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT timestamp FROM unsent_payloads 
                    WHERE status = 'SENT' 
                    ORDER BY timestamp DESC LIMIT 1
                """)
                row = cursor.fetchone()
                return row[0] if row else "None"
        except Exception:
            return "None"


state_manager = CollectorStateManager()
