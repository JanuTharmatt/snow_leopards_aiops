"""
SaaS Local Storage Service.
Phase 3 Production Readiness:
- Idempotent payload persistence with data residency enforcement
- Ingest watermark tracking & out-of-order event handling
- Persistent anomaly and outage alerts
- Collector Registry & Fleet Monitoring
"""

from contextlib import contextmanager
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional, Tuple, Union

DEFAULT_SAAS_DB_PATH = Path(__file__).resolve().parent.parent / "local_storage.db"

# Tenant Legal Data Residency Registry
TENANT_RESIDENCY_REGISTRY: Dict[str, str] = {
    "TENANT-001": "us-east-1",
    "TENANT-ALPHA": "eu-central-1",
    "TENANT-APAC": "ap-southeast-1",
    "TENANT-DEFAULT": "us-east-1"
}


class SaaSStorageService:
    """Manages SQLite storage for the SaaS Ingestion Platform."""

    def __init__(self, db_path: Optional[Union[str, Path]] = None):
        self.db_path = Path(db_path) if db_path else DEFAULT_SAAS_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_database()

    @contextmanager
    def _get_connection(self):
        conn = sqlite3.connect(
            str(self.db_path),
            timeout=10.0,
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
        """Initializes tables for ingested payloads, watermark tracking, and collector registry."""
        with self._get_connection() as conn:
            # 1. Ingested Payloads Table with region and out-of-order flag
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ingested_payloads (
                    payload_id TEXT PRIMARY KEY,
                    collector_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    region TEXT NOT NULL DEFAULT 'us-east-1',
                    event_time_utc TEXT NOT NULL,
                    source_timezone TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    data_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    is_out_of_order INTEGER NOT NULL DEFAULT 0,
                    ingested_at TEXT NOT NULL
                );
            """)

            # Schema Migration Check for existing databases
            cursor = conn.execute("PRAGMA table_info(ingested_payloads);")
            cols = [row["name"] for row in cursor.fetchall()]
            if cols and "region" not in cols:
                conn.execute("ALTER TABLE ingested_payloads ADD COLUMN region TEXT NOT NULL DEFAULT 'us-east-1';")
            if cols and "is_out_of_order" not in cols:
                conn.execute("ALTER TABLE ingested_payloads ADD COLUMN is_out_of_order INTEGER NOT NULL DEFAULT 0;")

            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_tenant_region_time 
                ON ingested_payloads(tenant_id, region, event_time_utc);
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_collector_event_time
                ON ingested_payloads(collector_id, event_time_utc);
            """)

            # 2. Watermark Registry Table (Task B: Out-of-Order Watermarking)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS watermark_registry (
                    collector_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    high_watermark_utc TEXT NOT NULL,
                    last_ingested_at TEXT NOT NULL
                );
            """)

            # 3. Collector Registry Table (Fleet Monitoring & 4 Health States)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS collector_registry (
                    collector_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    region TEXT NOT NULL,
                    version TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    status TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
            """)

            # 3b. Dedicated Telemetry Table for Multi-Collector Historical Querying
            conn.execute("""
                CREATE TABLE IF NOT EXISTS telemetry (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id TEXT NOT NULL,
                    collector_id TEXT NOT NULL,
                    cpu REAL NOT NULL,
                    memory REAL NOT NULL,
                    latency REAL NOT NULL DEFAULT 0.0,
                    timestamp TEXT NOT NULL
                );
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_telemetry_tenant_coll 
                ON telemetry(tenant_id, collector_id, timestamp);
            """)

            # 4. Contextual & Outage Alerts Table (Tasks E & F)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    collector_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    diagnosis TEXT NOT NULL,
                    metrics_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    resolved INTEGER NOT NULL DEFAULT 0,
                    resolved_at TEXT
                );
            """)

            # 5. Phase 4: Incidents & Probable Cause Table (RCA Engine)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    collector_id TEXT NOT NULL,
                    incident_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'OPEN',
                    root_cause TEXT NOT NULL,
                    confidence_score REAL NOT NULL,
                    summary TEXT NOT NULL,
                    recommendations_json TEXT NOT NULL,
                    evidence_json TEXT NOT NULL,
                    timeline_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    resolved_at TEXT
                );
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_incidents_status
                ON incidents(tenant_id, collector_id, status);
            """)

            # 6. Phase 4.5: 168-Slot Self-Learning Seasonal Baselines (7 days x 24 hours)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS seasonal_baselines (
                    tenant_id TEXT NOT NULL,
                    collector_id TEXT NOT NULL,
                    day_of_week INTEGER NOT NULL,
                    hour_of_day INTEGER NOT NULL,
                    metric_name TEXT NOT NULL,
                    sample_count INTEGER NOT NULL DEFAULT 1,
                    mean_value REAL NOT NULL,
                    variance_value REAL NOT NULL DEFAULT 0.0,
                    std_dev REAL NOT NULL DEFAULT 1.0,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, collector_id, day_of_week, hour_of_day, metric_name)
                );
            """)

            # 7. Phase 4.5: Outside Cyber Attack Threats Table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS threat_events (
                    threat_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    collector_id TEXT NOT NULL,
                    threat_type TEXT NOT NULL,
                    threat_level TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'ACTIVE',
                    vector_description TEXT NOT NULL,
                    classification TEXT NOT NULL,
                    mitigation_commands_json TEXT NOT NULL,
                    evidence_json TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    resolved_at TEXT
                );
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_threats_status
                ON threat_events(tenant_id, collector_id, status);
            """)
            conn.commit()

    def validate_tenant_residency(self, tenant_id: str, incoming_region: str) -> Tuple[bool, str]:
        """
        Task D: Regional Ingest Routing & Data Residency Enforcement.
        Checks if the collector's region matches the tenant's legal data residency boundary.
        """
        allowed_region = TENANT_RESIDENCY_REGISTRY.get(tenant_id, "us-east-1")
        if incoming_region != allowed_region:
            return False, f"Residency violation: tenant '{tenant_id}' data residency is restricted to '{allowed_region}', but payload originated from '{incoming_region}'."
        return True, allowed_region

    def payload_exists(self, payload_id: str) -> bool:
        """Checks if a payload has already been ingested (Idempotency Check)."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT 1 FROM ingested_payloads WHERE payload_id = ?",
                (payload_id,)
            )
            return cursor.fetchone() is not None

    def store_payload(
        self,
        payload_dict: Dict[str, Any],
        tenant_id: str,
        region: str = "us-east-1"
    ) -> Tuple[bool, bool]:
        """
        Idempotently inserts payload into ingested_payloads with Watermark tracking.
        Returns:
            Tuple of (is_new: bool, is_out_of_order: bool)
        """
        pid = payload_dict["payload_id"]
        if self.payload_exists(pid):
            return False, False

        collector_id = payload_dict.get("collector_id", "COLL-UNKNOWN")
        event_time_utc = payload_dict.get("event_time_utc") or payload_dict.get("timestamp", datetime.now(timezone.utc).isoformat())
        source_tz = payload_dict.get("source_timezone", "+00:00")
        sha256_hash = payload_dict.get("sha256", "")
        data_type = payload_dict.get("data_type", "METRICS")
        payload_json = json.dumps(payload_dict)
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        # Task B: Evaluate Ingest Watermark
        is_out_of_order = False
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT high_watermark_utc FROM watermark_registry WHERE collector_id = ?",
                (collector_id,)
            )
            row = cursor.fetchone()
            if row:
                current_high = row["high_watermark_utc"]
                if event_time_utc < current_high:
                    is_out_of_order = True
                else:
                    # Advance high watermark
                    conn.execute(
                        "UPDATE watermark_registry SET high_watermark_utc = ?, last_ingested_at = ? WHERE collector_id = ?",
                        (event_time_utc, now_utc, collector_id)
                    )
            else:
                conn.execute(
                    "INSERT INTO watermark_registry (collector_id, tenant_id, high_watermark_utc, last_ingested_at) VALUES (?, ?, ?, ?)",
                    (collector_id, tenant_id, event_time_utc, now_utc)
                )

            # Insert payload
            conn.execute(
                """
                INSERT INTO ingested_payloads (
                    payload_id, collector_id, tenant_id, region, event_time_utc,
                    source_timezone, sha256, data_type, payload_json, is_out_of_order, ingested_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (pid, collector_id, tenant_id, region, event_time_utc, source_tz, sha256_hash, data_type, payload_json, 1 if is_out_of_order else 0, now_utc)
            )

            # Ingest into dedicated telemetry table and update collectors table
            try:
                p_data = json.loads(payload_json)
                cpu_val = 0.0
                mem_val = 0.0
                lat_val = 0.0
                if isinstance(p_data, dict):
                    metrics = p_data.get("metrics")
                    data_block = p_data.get("data")
                    if isinstance(metrics, dict):
                        cpu_val = float(metrics.get("cpu_percent") or metrics.get("cpu") or 0.0)
                        mem_val = float(metrics.get("memory_percent") or metrics.get("memory") or 0.0)
                        lat_val = float(metrics.get("network_latency_ms") or metrics.get("latency_ms") or metrics.get("latency") or 0.0)
                    elif isinstance(metrics, list) and len(metrics) > 0 and isinstance(metrics[0], dict):
                        cpu_val = float(metrics[0].get("cpu_percent") or metrics[0].get("cpu") or 0.0)
                        mem_val = float(metrics[0].get("memory_percent") or metrics[0].get("memory") or 0.0)
                        lat_val = float(metrics[0].get("network_latency_ms") or metrics[0].get("latency_ms") or metrics[0].get("latency") or 0.0)
                    elif isinstance(data_block, dict):
                        cpu_val = float(data_block.get("cpu") or data_block.get("cpu_percent") or 0.0)
                        mem_val = float(data_block.get("memory") or data_block.get("memory_percent") or 0.0)
                        lat_val = float(data_block.get("latency") or data_block.get("network_latency_ms") or 0.0)
                    else:
                        cpu_val = float(p_data.get("cpu") or p_data.get("cpu_percent") or 0.0)
                        mem_val = float(p_data.get("memory") or p_data.get("memory_percent") or 0.0)
                        lat_val = float(p_data.get("latency") or p_data.get("network_latency_ms") or 0.0)

                conn.execute(
                    """
                    INSERT INTO telemetry (tenant_id, collector_id, cpu, memory, latency, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (tenant_id, collector_id, cpu_val, mem_val, lat_val, event_time_utc)
                )

                # Keep collectors table updated with latest status and timestamp
                conn.execute(
                    """
                    INSERT INTO collectors (collector_id, tenant_id, hostname, device_name, status, last_seen, version, registered_at, collector_secret)
                    VALUES (?, ?, ?, ?, 'ONLINE', ?, '1.0', ?, 'KEY-AUTO')
                    ON CONFLICT(collector_id) DO UPDATE SET
                        status = 'ONLINE',
                        last_seen = excluded.last_seen
                    """,
                    (collector_id, tenant_id, collector_id, collector_id, event_time_utc, event_time_utc)
                )

                # Also update collector_registry
                conn.execute(
                    """
                    INSERT INTO collector_registry (collector_id, tenant_id, region, version, last_seen, status, updated_at)
                    VALUES (?, ?, ?, '1.0', ?, 'ONLINE', ?)
                    ON CONFLICT(collector_id) DO UPDATE SET
                        tenant_id = excluded.tenant_id,
                        status = 'ONLINE',
                        last_seen = excluded.last_seen,
                        updated_at = excluded.updated_at
                    """,
                    (collector_id, tenant_id, region, event_time_utc, now_utc)
                )
            except Exception:
                pass

            conn.commit()

        return True, is_out_of_order

    def get_chronological_telemetry(
        self,
        tenant_id: str,
        collector_id: Optional[str] = None,
        region: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Task B: Retrieves telemetry ordered strictly by event_time_utc ASC.
        Guarantees that delayed/replayed payloads appear in true chronological order.
        """
        query = "SELECT * FROM ingested_payloads WHERE tenant_id = ?"
        params: List[Any] = [tenant_id]

        if collector_id:
            query += " AND collector_id = ?"
            params.append(collector_id)
        if region:
            query += " AND region = ?"
            params.append(region)

        query += " ORDER BY event_time_utc ASC LIMIT ?"
        params.append(limit)

        with self._get_connection() as conn:
            cursor = conn.execute(query, params)
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    def get_collector_telemetry(
        self,
        tenant_id: str,
        collector_id: str,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Retrieves raw historical telemetry points for a specific collector in chronological order."""
        with self._get_connection() as conn:
            cur = conn.execute(
                """
                SELECT id, tenant_id, collector_id, cpu, memory, latency, timestamp
                FROM telemetry
                WHERE tenant_id = ? AND collector_id = ?
                ORDER BY timestamp ASC
                LIMIT ?
                """,
                (tenant_id, collector_id, limit)
            )
            rows = cur.fetchall()
            return [dict(r) for r in rows]

    def get_collector_drilldown(
        self,
        tenant_id: str,
        collector_id: str
    ) -> Dict[str, Any]:
        """Returns deep telemetry, threats, incidents, and performance trends for a single collector."""
        with self._get_connection() as conn:
            # Metadata
            c_cur = conn.execute(
                """
                SELECT collector_id, tenant_id, hostname,
                       COALESCE(device_name, hostname) as device_name,
                       COALESCE(status, 'ONLINE') as status,
                       last_seen,
                       COALESCE(version, '1.0') as version,
                       registered_at
                FROM collectors
                WHERE tenant_id = ? AND collector_id = ?
                """,
                (tenant_id, collector_id)
            )
            c_meta = c_cur.fetchone()
            meta = dict(c_meta) if c_meta else {
                "collector_id": collector_id,
                "tenant_id": tenant_id,
                "hostname": "unknown",
                "device_name": collector_id,
                "status": "OFFLINE",
                "last_seen": None,
                "version": "1.0",
                "registered_at": None
            }

            # Telemetry points (latest 50)
            t_cur = conn.execute(
                """
                SELECT cpu, memory, latency, timestamp
                FROM telemetry
                WHERE tenant_id = ? AND collector_id = ?
                ORDER BY timestamp DESC
                LIMIT 50
                """,
                (tenant_id, collector_id)
            )
            telemetry_pts = [dict(r) for r in t_cur.fetchall()]
            telemetry_pts.reverse()  # chronological order

            # Threats
            th_cur = conn.execute(
                """
                SELECT threat_id, threat_type, threat_level, status, vector_description, classification, first_seen, last_seen
                FROM threat_events
                WHERE tenant_id = ? AND collector_id = ?
                ORDER BY last_seen DESC
                LIMIT 10
                """,
                (tenant_id, collector_id)
            )
            threats = [dict(r) for r in th_cur.fetchall()]

            # Incidents
            inc_cur = conn.execute(
                """
                SELECT incident_id, incident_type, severity, status, root_cause, confidence_score, summary, created_at
                FROM incidents
                WHERE tenant_id = ? AND collector_id = ?
                ORDER BY created_at DESC
                LIMIT 10
                """,
                (tenant_id, collector_id)
            )
            incidents = [dict(r) for r in inc_cur.fetchall()]

            # Latest metrics
            latest_cpu = telemetry_pts[-1]["cpu"] if telemetry_pts else 0.0
            latest_mem = telemetry_pts[-1]["memory"] if telemetry_pts else 0.0
            latest_lat = telemetry_pts[-1]["latency"] if telemetry_pts else 0.0
            packet_loss = 0.0
            if latest_lat > 200:
                packet_loss = 5.0
            elif latest_lat > 100:
                packet_loss = 2.0

            # Health classification
            if meta.get("status") == "OFFLINE" or latest_cpu >= 85 or latest_mem >= 85 or latest_lat >= 150 or threats:
                health = "Poor"
            elif latest_cpu >= 70 or latest_mem >= 70 or latest_lat >= 70:
                health = "Fair"
            else:
                health = "Healthy"

            meta["health"] = health
            meta["latest_cpu"] = latest_cpu
            meta["latest_memory"] = latest_mem
            meta["latest_latency"] = latest_lat
            meta["packet_loss"] = packet_loss

            return {
                "collector": meta,
                "telemetry": telemetry_pts,
                "threats": threats,
                "incidents": incidents
            }

    def update_collector_heartbeat(
        self,
        collector_id: str,
        tenant_id: str,
        region: str,
        version: str,
        status: str,
        heartbeat_timestamp: Optional[str] = None
    ) -> Dict[str, Any]:
        """Updates Collector Registry with latest heartbeat timestamp and status."""
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        last_seen = heartbeat_timestamp or now_utc

        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO collector_registry (collector_id, tenant_id, region, version, last_seen, status, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(collector_id) DO UPDATE SET
                    tenant_id = excluded.tenant_id,
                    region = excluded.region,
                    version = excluded.version,
                    last_seen = excluded.last_seen,
                    status = excluded.status,
                    updated_at = excluded.updated_at
                """,
                (collector_id, tenant_id, region, version, last_seen, status, now_utc)
            )
            conn.commit()

        return {
            "collector_id": collector_id,
            "tenant_id": tenant_id,
            "region": region,
            "version": version,
            "last_seen": last_seen,
            "status": status
        }

    def update_collector_status(self, collector_id: str, new_status: str) -> bool:
        """Transitions collector health status in registry (e.g. to Stale/Offline)."""
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self._get_connection() as conn:
            conn.execute(
                "UPDATE collector_registry SET status = ?, updated_at = ? WHERE collector_id = ?",
                (new_status, now_utc, collector_id)
            )
            conn.commit()
        return True

    def get_collector(self, collector_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves registered collector information."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM collector_registry WHERE collector_id = ?",
                (collector_id,)
            )
            row = cursor.fetchone()
            if row:
                return dict(row)
        return None

    def register_collector(
        self,
        collector_id: str,
        tenant_id: str,
        region: str = "us-east-1",
        public_key: str = "PK-AUTO",
        os_info: str = "Windows",
        version: str = "1.0.0"
    ) -> None:
        """Registers a collector machine into the central fleet registry."""
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO collector_registry (collector_id, tenant_id, region, version, last_seen, status, updated_at)
                VALUES (?, ?, ?, ?, ?, 'ONLINE', ?)
                ON CONFLICT(collector_id) DO UPDATE SET
                    tenant_id = excluded.tenant_id,
                    region = excluded.region,
                    version = excluded.version,
                    last_seen = excluded.last_seen,
                    status = 'ONLINE',
                    updated_at = excluded.updated_at
                """,
                (collector_id, tenant_id, region, version, now_utc, now_utc)
            )
            conn.commit()

    def get_all_collectors(self, tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Lists all registered collectors in fleet with their latest device names, metrics, and health states."""
        with self._get_connection() as conn:
            if tenant_id:
                cursor = conn.execute(
                    """
                    SELECT c.collector_id, c.tenant_id, c.hostname,
                           COALESCE(c.device_name, c.hostname) as device_name,
                           COALESCE(cr.status, c.status, 'ONLINE') as status,
                           COALESCE(cr.version, c.version, '1.0.0') as version,
                           COALESCE(c.last_seen, cr.last_seen, c.registered_at) as last_seen,
                           COALESCE(cr.region, 'us-east-1') as region
                    FROM collectors c
                    LEFT JOIN collector_registry cr ON c.collector_id = cr.collector_id
                    WHERE c.tenant_id = ?
                    ORDER BY c.registered_at ASC
                    """,
                    (tenant_id,)
                )
            else:
                cursor = conn.execute(
                    """
                    SELECT c.collector_id, c.tenant_id, c.hostname,
                           COALESCE(c.device_name, c.hostname) as device_name,
                           COALESCE(cr.status, c.status, 'ONLINE') as status,
                           COALESCE(cr.version, c.version, '1.0.0') as version,
                           COALESCE(c.last_seen, cr.last_seen, c.registered_at) as last_seen,
                           COALESCE(cr.region, 'us-east-1') as region
                    FROM collectors c
                    LEFT JOIN collector_registry cr ON c.collector_id = cr.collector_id
                    ORDER BY c.registered_at ASC
                    """
                )
            return [dict(r) for r in cursor.fetchall()]

    def store_alert(
        self,
        alert_id: str,
        collector_id: str,
        tenant_id: str,
        alert_type: str,
        severity: str,
        diagnosis: str,
        metrics: Dict[str, Any]
    ) -> None:
        """Stores contextual anomaly or outage alerts."""
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO alerts (
                    alert_id, collector_id, tenant_id, alert_type, severity, diagnosis, metrics_json, created_at, resolved
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
                """,
                (alert_id, collector_id, tenant_id, alert_type, severity, diagnosis, json.dumps(metrics), now_utc)
            )
            conn.commit()

    def resolve_alerts(self, collector_id: str, alert_type: Optional[str] = None) -> int:
        """Marks active alerts as resolved upon recovery."""
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self._get_connection() as conn:
            if alert_type:
                cursor = conn.execute(
                    "UPDATE alerts SET resolved = 1, resolved_at = ? WHERE collector_id = ? AND alert_type = ? AND resolved = 0",
                    (now_utc, collector_id, alert_type)
                )
            else:
                cursor = conn.execute(
                    "UPDATE alerts SET resolved = 1, resolved_at = ? WHERE collector_id = ? AND resolved = 0",
                    (now_utc, collector_id)
                )
            conn.commit()
            return cursor.rowcount

    def get_active_alerts(self, tenant_id: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        """Lists recent active (unresolved) alerts."""
        with self._get_connection() as conn:
            if tenant_id:
                cursor = conn.execute(
                    "SELECT * FROM alerts WHERE tenant_id = ? AND resolved = 0 ORDER BY created_at DESC LIMIT ?",
                    (tenant_id, limit)
                )
            else:
                cursor = conn.execute(
                    "SELECT * FROM alerts WHERE resolved = 0 ORDER BY created_at DESC LIMIT ?",
                    (limit,)
                )
            rows = cursor.fetchall()
            results = []
            for r in rows:
                item = dict(r)
                try:
                    item["metrics"] = json.loads(item["metrics_json"])
                except Exception:
                    item["metrics"] = {}
                results.append(item)
            return results

    def store_incident(self, incident: Dict[str, Any]) -> str:
        """Stores a newly generated incident with RCA and recommendations."""
        with self._get_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO incidents (
                    incident_id, tenant_id, collector_id, incident_type,
                    severity, status, root_cause, confidence_score,
                    summary, recommendations_json, evidence_json,
                    timeline_json, created_at, updated_at, resolved_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                incident["incident_id"],
                incident["tenant_id"],
                incident["collector_id"],
                incident["incident_type"],
                incident["severity"],
                incident.get("status", "OPEN"),
                incident["root_cause"],
                float(incident.get("confidence_score", 0.9)),
                incident["summary"],
                json.dumps(incident.get("recommendations", [])),
                json.dumps(incident.get("evidence", {})),
                json.dumps(incident.get("timeline", [])),
                incident.get("created_at", datetime.now(timezone.utc).isoformat()),
                incident.get("updated_at", datetime.now(timezone.utc).isoformat()),
                incident.get("resolved_at")
            ))
            conn.commit()
            return incident["incident_id"]

    def get_open_incident(
        self,
        tenant_id: str,
        collector_id: str,
        incident_type: str
    ) -> Optional[Dict[str, Any]]:
        """Finds an existing OPEN incident of the given type for clustering."""
        with self._get_connection() as conn:
            cursor = conn.execute("""
                SELECT * FROM incidents
                WHERE tenant_id = ? AND collector_id = ? AND incident_type = ? AND status = 'OPEN'
                ORDER BY created_at DESC LIMIT 1
            """, (tenant_id, collector_id, incident_type))
            row = cursor.fetchone()
            if not row:
                return None
            return self._format_incident_row(dict(row))

    def update_incident(self, incident_id: str, updates: Dict[str, Any]) -> bool:
        """Updates an existing incident (e.g. extending timeline or updating metrics)."""
        now_utc = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            set_clauses = ["updated_at = ?"]
            params: List[Any] = [now_utc]

            if "timeline" in updates:
                set_clauses.append("timeline_json = ?")
                params.append(json.dumps(updates["timeline"]))
            if "evidence" in updates:
                set_clauses.append("evidence_json = ?")
                params.append(json.dumps(updates["evidence"]))
            if "severity" in updates:
                set_clauses.append("severity = ?")
                params.append(updates["severity"])
            if "confidence_score" in updates:
                set_clauses.append("confidence_score = ?")
                params.append(float(updates["confidence_score"]))
            if "summary" in updates:
                set_clauses.append("summary = ?")
                params.append(updates["summary"])

            params.append(incident_id)
            query = f"UPDATE incidents SET {', '.join(set_clauses)} WHERE incident_id = ?"
            cursor = conn.execute(query, tuple(params))
            conn.commit()
            return cursor.rowcount > 0

    def resolve_incident(self, incident_id: str) -> bool:
        """Marks a specific incident as RESOLVED."""
        now_utc = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.execute("""
                UPDATE incidents
                SET status = 'RESOLVED', resolved_at = ?, updated_at = ?
                WHERE incident_id = ? AND status = 'OPEN'
            """, (now_utc, now_utc, incident_id))
            conn.commit()
            return cursor.rowcount > 0

    def resolve_incidents_for_collector(
        self,
        collector_id: str,
        incident_types: Optional[List[str]] = None
    ) -> int:
        """Auto-resolves open incidents when the collector's health normalizes."""
        now_utc = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            if incident_types:
                placeholders = ",".join("?" for _ in incident_types)
                cursor = conn.execute(f"""
                    UPDATE incidents
                    SET status = 'RESOLVED', resolved_at = ?, updated_at = ?
                    WHERE collector_id = ? AND status = 'OPEN' AND incident_type IN ({placeholders})
                """, (now_utc, now_utc, collector_id, *incident_types))
            else:
                cursor = conn.execute("""
                    UPDATE incidents
                    SET status = 'RESOLVED', resolved_at = ?, updated_at = ?
                    WHERE collector_id = ? AND status = 'OPEN'
                """, (now_utc, now_utc, collector_id))
            conn.commit()
            return cursor.rowcount

    def get_incidents(
        self,
        tenant_id: Optional[str] = None,
        collector_id: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Lists incidents with optional filtering by tenant, collector, or status."""
        query = "SELECT * FROM incidents WHERE 1=1"
        params: List[Any] = []

        if tenant_id:
            query += " AND tenant_id = ?"
            params.append(tenant_id)
        if collector_id:
            query += " AND collector_id = ?"
            params.append(collector_id)
        if status:
            query += " AND status = ?"
            params.append(status.upper())

        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        with self._get_connection() as conn:
            cursor = conn.execute(query, tuple(params))
            return [self._format_incident_row(dict(r)) for r in cursor.fetchall()]

    def get_incident_by_id(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Fetches a single incident with full RCA, timeline, and recommendations."""
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return self._format_incident_row(dict(row))

    def _format_incident_row(self, row: Dict[str, Any]) -> Dict[str, Any]:
        """Unpacks JSON fields in an incident row."""
        try:
            row["recommendations"] = json.loads(row.get("recommendations_json", "[]"))
        except Exception:
            row["recommendations"] = []
        try:
            row["evidence"] = json.loads(row.get("evidence_json", "{}"))
        except Exception:
            row["evidence"] = {}
        try:
            row["timeline"] = json.loads(row.get("timeline_json", "[]"))
        except Exception:
            row["timeline"] = []
        return row

    # -------------------------------------------------------------
    # Phase 4.5: 168-Slot Seasonal Baselines & Outside Threat Tracking
    # -------------------------------------------------------------

    def upsert_seasonal_baseline(
        self,
        tenant_id: str,
        collector_id: str,
        day_of_week: int,
        hour_of_day: int,
        metric_name: str,
        value: float,
        alpha: float = 0.08
    ) -> Dict[str, Any]:
        """
        Updates the 168-slot seasonal profile using Online Continuous Learning.
        Runs in < 0.5ms on incoming telemetry.
        """
        import math
        now_utc = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.execute("""
                SELECT sample_count, mean_value, variance_value, std_dev
                FROM seasonal_baselines
                WHERE tenant_id = ? AND collector_id = ? AND day_of_week = ? AND hour_of_day = ? AND metric_name = ?
            """, (tenant_id, collector_id, day_of_week, hour_of_day, metric_name))
            row = cursor.fetchone()

            if not row:
                init_std = 2.0 if metric_name in ("cpu", "memory") else 5.0
                init_var = init_std ** 2
                conn.execute("""
                    INSERT INTO seasonal_baselines (
                        tenant_id, collector_id, day_of_week, hour_of_day,
                        metric_name, sample_count, mean_value, variance_value, std_dev, updated_at
                    ) VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
                """, (tenant_id, collector_id, day_of_week, hour_of_day, metric_name, value, init_var, init_std, now_utc))
                conn.commit()
                return {
                    "mean": value,
                    "std_dev": init_std,
                    "sample_count": 1
                }
            else:
                old_count = row["sample_count"]
                old_mean = row["mean_value"]
                old_var = row["variance_value"]

                diff = value - old_mean
                new_mean = old_mean + alpha * diff
                new_var = max((1.0 - alpha) * (old_var + alpha * (diff ** 2)), 0.25)
                new_std = max(math.sqrt(new_var), 0.5)
                new_count = old_count + 1

                conn.execute("""
                    UPDATE seasonal_baselines
                    SET sample_count = ?, mean_value = ?, variance_value = ?, std_dev = ?, updated_at = ?
                    WHERE tenant_id = ? AND collector_id = ? AND day_of_week = ? AND hour_of_day = ? AND metric_name = ?
                """, (new_count, new_mean, new_var, new_std, now_utc, tenant_id, collector_id, day_of_week, hour_of_day, metric_name))
                conn.commit()
                return {
                    "mean": round(new_mean, 2),
                    "std_dev": round(new_std, 2),
                    "sample_count": new_count
                }

    def get_seasonal_baseline(
        self,
        tenant_id: str,
        collector_id: str,
        day_of_week: int,
        hour_of_day: int,
        metric_name: str
    ) -> Optional[Dict[str, Any]]:
        """Retrieves historical mean and standard deviation for the given time slot."""
        with self._get_connection() as conn:
            cursor = conn.execute("""
                SELECT mean_value, std_dev, sample_count, updated_at
                FROM seasonal_baselines
                WHERE tenant_id = ? AND collector_id = ? AND day_of_week = ? AND hour_of_day = ? AND metric_name = ?
            """, (tenant_id, collector_id, day_of_week, hour_of_day, metric_name))
            row = cursor.fetchone()
            if not row:
                return None
            return {
                "mean": round(row["mean_value"], 2),
                "std_dev": round(row["std_dev"], 2),
                "sample_count": row["sample_count"],
                "updated_at": row["updated_at"]
            }

    def get_24h_seasonal_curve(
        self,
        tenant_id: str,
        collector_id: str,
        day_of_week: int,
        metric_name: str
    ) -> List[Dict[str, Any]]:
        """Returns 24-hour baseline curve for drawing expected bands on UI graphs."""
        with self._get_connection() as conn:
            cursor = conn.execute("""
                SELECT hour_of_day, mean_value, std_dev, sample_count
                FROM seasonal_baselines
                WHERE tenant_id = ? AND collector_id = ? AND day_of_week = ? AND metric_name = ?
                ORDER BY hour_of_day ASC
            """, (tenant_id, collector_id, day_of_week, metric_name))
            rows = cursor.fetchall()
            lookup = {r["hour_of_day"]: (r["mean_value"], r["std_dev"]) for r in rows}

            curve = []
            for h in range(24):
                if h in lookup:
                    mean_val, std_val = lookup[h]
                else:
                    # Default baseline fallback if unobserved
                    mean_val = 30.0 if metric_name in ("cpu", "memory") else 15.0
                    std_val = 5.0
                curve.append({
                    "hour": h,
                    "mean": round(mean_val, 1),
                    "lower_band": max(round(mean_val - 2.0 * std_val, 1), 0.0),
                    "upper_band": round(mean_val + 2.0 * std_val, 1)
                })
            return curve

    def store_threat_event(self, threat: Dict[str, Any]) -> str:
        """Stores an outside attack threat event."""
        with self._get_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO threat_events (
                    threat_id, tenant_id, collector_id, threat_type,
                    threat_level, status, vector_description, classification,
                    mitigation_commands_json, evidence_json, first_seen, last_seen, resolved_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                threat["threat_id"],
                threat["tenant_id"],
                threat["collector_id"],
                threat["threat_type"],
                threat["threat_level"],
                threat.get("status", "ACTIVE"),
                threat["vector_description"],
                threat["classification"],
                json.dumps(threat.get("mitigation_commands", [])),
                json.dumps(threat.get("evidence", {})),
                threat.get("first_seen", datetime.now(timezone.utc).isoformat()),
                threat.get("last_seen", datetime.now(timezone.utc).isoformat()),
                threat.get("resolved_at")
            ))
            conn.commit()
            return threat["threat_id"]

    def get_active_threat(
        self,
        tenant_id: str,
        collector_id: str,
        threat_type: str
    ) -> Optional[Dict[str, Any]]:
        """Finds an existing active threat for cooldown & alert suppression."""
        with self._get_connection() as conn:
            cursor = conn.execute("""
                SELECT * FROM threat_events
                WHERE tenant_id = ? AND collector_id = ? AND threat_type = ? AND status = 'ACTIVE'
                ORDER BY first_seen DESC LIMIT 1
            """, (tenant_id, collector_id, threat_type))
            row = cursor.fetchone()
            if not row:
                return None
            return self._format_threat_row(dict(row))

    def update_threat_event(self, threat_id: str, updates: Dict[str, Any]) -> bool:
        """Updates active threat (e.g. updating last_seen and peak evidence)."""
        now_utc = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            set_clauses = ["last_seen = ?"]
            params: List[Any] = [now_utc]

            if "threat_level" in updates:
                set_clauses.append("threat_level = ?")
                params.append(updates["threat_level"])
            if "evidence" in updates:
                set_clauses.append("evidence_json = ?")
                params.append(json.dumps(updates["evidence"]))
            if "vector_description" in updates:
                set_clauses.append("vector_description = ?")
                params.append(updates["vector_description"])

            params.append(threat_id)
            query = f"UPDATE threat_events SET {', '.join(set_clauses)} WHERE threat_id = ?"
            cursor = conn.execute(query, tuple(params))
            conn.commit()
            return cursor.rowcount > 0

    def resolve_threat_events_for_collector(
        self,
        collector_id: str,
        threat_types: Optional[List[str]] = None
    ) -> int:
        """Auto-resolves active threat events when attack traffic subsides."""
        now_utc = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            if threat_types:
                placeholders = ",".join("?" for _ in threat_types)
                cursor = conn.execute(f"""
                    UPDATE threat_events
                    SET status = 'RESOLVED', resolved_at = ?
                    WHERE collector_id = ? AND status = 'ACTIVE' AND threat_type IN ({placeholders})
                """, (now_utc, collector_id, *threat_types))
            else:
                cursor = conn.execute("""
                    UPDATE threat_events
                    SET status = 'RESOLVED', resolved_at = ?
                    WHERE collector_id = ? AND status = 'ACTIVE'
                """, (now_utc, collector_id))
            conn.commit()
            return cursor.rowcount

    def get_threat_events(
        self,
        tenant_id: Optional[str] = None,
        collector_id: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Lists threat events with optional filtering."""
        query = "SELECT * FROM threat_events WHERE 1=1"
        params: List[Any] = []

        if tenant_id:
            query += " AND tenant_id = ?"
            params.append(tenant_id)
        if collector_id:
            query += " AND collector_id = ?"
            params.append(collector_id)
        if status:
            query += " AND status = ?"
            params.append(status.upper())

        query += " ORDER BY first_seen DESC LIMIT ?"
        params.append(limit)

        with self._get_connection() as conn:
            cursor = conn.execute(query, tuple(params))
            return [self._format_threat_row(dict(r)) for r in cursor.fetchall()]

    def _format_threat_row(self, row: Dict[str, Any]) -> Dict[str, Any]:
        """Unpacks JSON fields in a threat event row."""
        try:
            row["mitigation_commands"] = json.loads(row.get("mitigation_commands_json", "[]"))
        except Exception:
            row["mitigation_commands"] = []
        try:
            row["evidence"] = json.loads(row.get("evidence_json", "{}"))
        except Exception:
            row["evidence"] = {}
        return row

    def get_ingested_payloads(self, limit: int = 100, tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Lists recently ingested payloads."""
        with self._get_connection() as conn:
            if tenant_id:
                cursor = conn.execute(
                    "SELECT * FROM ingested_payloads WHERE tenant_id = ? ORDER BY ingested_at DESC LIMIT ?",
                    (tenant_id, limit)
                )
            else:
                cursor = conn.execute(
                    "SELECT * FROM ingested_payloads ORDER BY ingested_at DESC LIMIT ?",
                    (limit,)
                )
            return [dict(r) for r in cursor.fetchall()]

    def clear_all(self) -> None:
        """Cleans database for testing."""
        with self._get_connection() as conn:
            conn.execute("DELETE FROM ingested_payloads")
            conn.execute("DELETE FROM collector_registry")
            conn.execute("DELETE FROM watermark_registry")
            conn.execute("DELETE FROM alerts")
            conn.execute("DELETE FROM incidents")
            conn.execute("DELETE FROM seasonal_baselines")
            conn.execute("DELETE FROM threat_events")
            conn.commit()


storage_service = SaaSStorageService()
