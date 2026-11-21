"""
Local Buffer Module for Privacy-First AIOps Observability Platform.
Manages SQLite-backed local persistence for unsent telemetry payloads.
Feature 9: Supports status values PENDING, SENT, FAILED, DEAD_LETTER.
GUARANTEE: raw_data is NEVER stored in this database. Only sanitized, hashed EgressPayloads are stored.
"""

from contextlib import contextmanager
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional, Union
import uuid

try:
    from .config import config
    from .models import BufferStatus, EgressPayload, UnsentPayload
except (ImportError, ValueError):
    from config import config
    from models import BufferStatus, EgressPayload, UnsentPayload


class LocalBufferManager:
    """
    SQLite-backed local storage engine for telemetry payloads awaiting transmission.
    """

    def __init__(self, db_path: Optional[Union[str, Path]] = None):
        self.db_path = Path(db_path) if db_path else config.database.db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_database()

    @contextmanager
    def _get_connection(self):
        conn = sqlite3.connect(
            str(self.db_path),
            timeout=config.database.timeout_seconds,
            check_same_thread=False
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        try:
            yield conn
        finally:
            conn.close()

    def _init_database(self) -> None:
        """
        Initializes the 'unsent_payloads' table matching exact architectural specifications:
        Columns:
        - payload_id (TEXT PRIMARY KEY)
        - timestamp (TEXT NOT NULL)
        - payload_json (TEXT NOT NULL)
        - status (TEXT NOT NULL DEFAULT 'PENDING')
        - retry_count (INTEGER DEFAULT 0)
        - failure_reason (TEXT DEFAULT NULL)
        """
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS unsent_payloads (
                    payload_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'PENDING',
                    retry_count INTEGER DEFAULT 0,
                    failure_reason TEXT DEFAULT NULL
                );
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_unsent_status_ts 
                ON unsent_payloads(status, timestamp);
            """)
            conn.commit()

    def store_payload(self, egress_payload: EgressPayload) -> str:
        """
        Stores a sanitized EgressPayload into the local SQLite buffer with status PENDING.
        Enforces that raw_data is NEVER present in the buffered payload.
        """
        if not isinstance(egress_payload, EgressPayload):
            raise TypeError(f"Only EgressPayload instances may be buffered. Got {type(egress_payload)}")

        payload_dict = egress_payload.model_dump()

        if "raw_data" in payload_dict or "raw_input" in payload_dict:
            raise ValueError("SECURITY VIOLATION: raw_data detected in egress payload! Rejected from buffer.")

        payload_json = json.dumps(payload_dict)
        pid = egress_payload.payload_id
        ts = egress_payload.timestamp

        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO unsent_payloads (payload_id, timestamp, payload_json, status, retry_count)
                VALUES (?, ?, ?, 'PENDING', 0)
                """,
                (pid, ts, payload_json)
            )
            conn.commit()

        return pid

    def get_unsent_payloads(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Retrieves pending payloads from the buffer ordered by timestamp.
        """
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT payload_id, timestamp, payload_json, status, retry_count, failure_reason
                FROM unsent_payloads
                WHERE status = 'PENDING'
                ORDER BY timestamp ASC
                LIMIT ?
                """,
                (limit,)
            )
            rows = cursor.fetchall()

        results = []
        for row in rows:
            results.append({
                "payload_id": row["payload_id"],
                "timestamp": row["timestamp"],
                "payload_json": json.loads(row["payload_json"]),
                "status": row["status"],
                "retry_count": row["retry_count"],
                "failure_reason": row["failure_reason"]
            })
        return results

    def get_payload_by_id(self, payload_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a single payload by ID."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT payload_id, timestamp, payload_json, status, retry_count, failure_reason
                FROM unsent_payloads
                WHERE payload_id = ?
                """,
                (payload_id,)
            )
            row = cursor.fetchone()

        if row:
            return {
                "payload_id": row["payload_id"],
                "timestamp": row["timestamp"],
                "payload_json": json.loads(row["payload_json"]),
                "status": row["status"],
                "retry_count": row["retry_count"],
                "failure_reason": row["failure_reason"]
            }
        return None

    def mark_as_sent(self, payload_id: str) -> bool:
        """Marks a payload as SENT after successful SaaS ingestion."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                UPDATE unsent_payloads
                SET status = 'SENT', failure_reason = NULL
                WHERE payload_id = ?
                """,
                (payload_id,)
            )
            conn.commit()
            return cursor.rowcount > 0

    def mark_as_failed(self, payload_id: str, error: str = "") -> int:
        """Increments retry count and sets status to FAILED or PENDING for retry."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                UPDATE unsent_payloads
                SET retry_count = retry_count + 1, failure_reason = ?
                WHERE payload_id = ?
                """,
                (error, payload_id)
            )
            conn.commit()

            cursor = conn.execute("SELECT retry_count FROM unsent_payloads WHERE payload_id = ?", (payload_id,))
            row = cursor.fetchone()
            return row["retry_count"] if row else 1

    def mark_as_dead_letter(self, payload_id: str, reason: str = "") -> bool:
        """
        Feature 9: Moves payload to DEAD_LETTER after repeated failures or invalid schema.
        Prevents retrying forever.
        """
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                UPDATE unsent_payloads
                SET status = 'DEAD_LETTER', failure_reason = ?
                WHERE payload_id = ?
                """,
                (reason, payload_id)
            )
            conn.commit()
            return cursor.rowcount > 0

    def get_dead_letter_payloads(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieves payloads in DEAD_LETTER status."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT payload_id, timestamp, payload_json, status, retry_count, failure_reason
                FROM unsent_payloads
                WHERE status = 'DEAD_LETTER'
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (limit,)
            )
            rows = cursor.fetchall()

        return [
            {
                "payload_id": row["payload_id"],
                "timestamp": row["timestamp"],
                "payload_json": json.loads(row["payload_json"]),
                "status": row["status"],
                "retry_count": row["retry_count"],
                "failure_reason": row["failure_reason"]
            }
            for row in rows
        ]

    def get_buffer_stats(self) -> Dict[str, Any]:
        """Returns counts by status (PENDING, SENT, FAILED, DEAD_LETTER, total)."""
        with self._get_connection() as conn:
            cursor = conn.execute("""
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
            "db_path": str(self.db_path),
            "total_payloads": row["total"] or 0,
            "pending": row["pending"] or 0,
            "sent": row["sent"] or 0,
            "failed": row["failed"] or 0,
            "dead_letter": row["dead_letter"] or 0
        }

    def clear_all(self) -> int:
        """Wipes all records from the table."""
        with self._get_connection() as conn:
            cursor = conn.execute("DELETE FROM unsent_payloads")
            conn.commit()
            return cursor.rowcount


buffer_manager = LocalBufferManager()
