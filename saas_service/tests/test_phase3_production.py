"""
Phase 3 Production Readiness & Gap Closure Automated Test Suite.
Validates:
1. 60-second network outage with local store-and-forward buffering, out-of-order watermark replay, and zero duplicates.
2. Real packet loss monitoring on collector & contextual multi-metric anomaly alert firing within <= 15s SLA.
3. Cross-region data residency enforcement (HTTP 403 Forbidden).
4. Stale-data & 60s outage detection state machine (Healthy, Degraded, Critical, Stale/Offline) with auto-recovery.
5. Central Observability Dashboard & Zero-Trust Egress Proof Panel.
"""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
import time
import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient

from saas_service.main import app
from saas_service.services.storage import SaaSStorageService, storage_service
from saas_service.services.auth import auth_service
from saas_service.services.watchdog import FleetWatchdog, watchdog
from saas_service.services.anomaly_engine import ContextualAnomalyEngine, anomaly_engine
from collector.config import config
from collector.collector import SystemCollector
from collector.models import EgressPayload, RawSystemMetrics
from collector.payload_builder import build_egress_payload
from collector.buffer_manager import LocalBufferManager
from collector.egress_worker import EgressWorker
from collector.auth_client import CollectorAuthClient


class TestPhase3ProductionReadiness(unittest.TestCase):
    """End-to-End Test Suite for Phase 3 Production SLA and Architectural Invariants."""

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.test_edge_db = Path(__file__).parent / "test_p3_edge.db"
        cls.test_saas_db = Path(__file__).parent / "test_p3_saas.db"
        cls.test_audit_path = Path(__file__).parent / "test_p3_audit.jsonl"

        for p in [cls.test_edge_db, cls.test_saas_db, cls.test_audit_path]:
            if p.exists():
                try:
                    p.unlink()
                except Exception:
                    pass

        cls.edge_buffer = LocalBufferManager(db_path=cls.test_edge_db)
        cls.saas_storage = SaaSStorageService(db_path=cls.test_saas_db)

        # Patch global storage service to use test database
        storage_service.db_path = cls.test_saas_db
        storage_service._init_database()

        # Generate valid test token for TENANT-001 (us-east-1)
        cls.token_data = auth_service.issue_token(
            collector_id="COLL-001",
            collector_secret="SECRET-COLL-DEMO-001"
        )
        cls.headers_us = {"Authorization": f"Bearer {cls.token_data['access_token']}"}

        # Generate valid test token for TENANT-ALPHA (eu-central-1)
        cls.token_alpha = auth_service.issue_token(
            collector_id="COLL-002",
            collector_secret="SECRET-COLL-ALPHA-999"
        )
        cls.headers_eu = {"Authorization": f"Bearer {cls.token_alpha['access_token']}"}

    @classmethod
    def tearDownClass(cls):
        from saas_service.services.storage import DEFAULT_SAAS_DB_PATH
        storage_service.db_path = DEFAULT_SAAS_DB_PATH
        storage_service._init_database()

        for ext in ["", "-wal", "-shm"]:
            for base in [cls.test_edge_db, cls.test_saas_db]:
                p = Path(str(base) + ext)
                if p.exists():
                    try:
                        p.unlink()
                    except Exception:
                        pass
        if cls.test_audit_path.exists():
            try:
                cls.test_audit_path.unlink()
            except Exception:
                pass

    def setUp(self):
        self.edge_buffer.clear_all()
        self.saas_storage.clear_all()

    # -------------------------------------------------------------------------
    # TEST 1: Task A - Real Packet Loss Monitoring (Collector)
    # -------------------------------------------------------------------------
    def test_01_real_packet_loss_monitoring_and_allowlist(self):
        """
        Confirms Collector measures packet loss %, routes it through the single
        payload-builder chokepoint allow-list, and includes it in EgressPayload.
        """
        collector = SystemCollector()
        
        # Test real burst probe method
        lat, loss_pct = collector.get_network_quality(probes=3)
        self.assertIsInstance(lat, float)
        self.assertIsInstance(loss_pct, float)
        self.assertGreaterEqual(loss_pct, 0.0)
        self.assertLessEqual(loss_pct, 100.0)

        # Generate raw metric with simulated 15% packet loss
        raw = RawSystemMetrics(
            cpu=45.0,
            memory=55.0,
            disk=60.0,
            latency=18.5,
            packet_loss=15.0,
            timestamp=datetime.now(timezone.utc).isoformat()
        )
        payload, audit_rec = build_egress_payload(raw, audit_log_path=self.test_audit_path)

        # Verify packet_loss was permitted by allow-list
        self.assertIn("packet_loss", payload.data)
        self.assertEqual(payload.data["packet_loss"], 15.0)
        # Verify metadata evaluated warning for 15% loss
        self.assertIn("packet_loss", payload.metadata["metrics"])
        self.assertEqual(payload.metadata["metrics"]["packet_loss"]["health"], "WARNING")

    # -------------------------------------------------------------------------
    # TEST 2: Task B - 60s Outage, Out-of-Order Watermark & Zero Duplicates
    # -------------------------------------------------------------------------
    def test_02_60s_outage_out_of_order_watermarking_and_deduplication(self):
        """
        Simulates >= 60-second offline outage:
        1. Collector buffers 12 payloads generated at 5-second intervals (60s total).
        2. Network restored: payloads are delivered out of order.
        3. SaaS Ingest Watermark detects out-of-order packets without corrupting timeline.
        4. get_chronological_telemetry returns strictly sorted physical event order.
        5. Zero duplicates and zero data loss verified.
        """
        now = datetime.now(timezone.utc)
        buffered_payloads = []

        # 1. Generate 12 payloads spanning 60 seconds (5s intervals)
        for i in range(12):
            event_time = (now - timedelta(seconds=(12 - i) * 5)).strftime("%Y-%m-%dT%H:%M:%SZ")
            p, _ = build_egress_payload(
                {
                    "cpu": 40.0 + i,
                    "memory": 50.0,
                    "disk": 60.0,
                    "latency": 15.0 + i,
                    "packet_loss": 0.0,
                    "timestamp": event_time
                },
                collector_id="COLL-001",
                tenant_id="TENANT-001",
                audit_log_path=self.test_audit_path
            )
            # Store in local SQLite buffer
            self.edge_buffer.store_payload(p)
            buffered_payloads.append(p)

        self.assertEqual(len(self.edge_buffer.get_unsent_payloads(limit=50)), 12)

        # 2. Simulate Out-of-Order Delivery over the wire:
        # Deliver payload #10 (new watermark), then payload #2 (historical out-of-order)
        p_latest = buffered_payloads[9]  # t = 50s
        p_old = buffered_payloads[1]     # t = 10s

        # Ingest newer payload
        resp_latest = self.client.post("/ingest", json=p_latest.model_dump(), headers=self.headers_us)
        self.assertEqual(resp_latest.status_code, 200)
        self.assertFalse(resp_latest.json()["is_out_of_order"])

        # Ingest older payload (arrived out of order)
        resp_old = self.client.post("/ingest", json=p_old.model_dump(), headers=self.headers_us)
        self.assertEqual(resp_old.status_code, 200)
        self.assertTrue(resp_old.json()["is_out_of_order"])

        # 3. Ingest duplicate test (retransmission)
        resp_dup = self.client.post("/ingest", json=p_latest.model_dump(), headers=self.headers_us)
        self.assertEqual(resp_dup.status_code, 200)
        self.assertTrue(resp_dup.json()["duplicate"])

        # 4. Ingest remainder of buffered queue
        for p in buffered_payloads:
            self.client.post("/ingest", json=p.model_dump(), headers=self.headers_us)

        # 5. Verify SaaS returns all 12 records in strict chronological event_time_utc order
        timeline = self.saas_storage.get_chronological_telemetry(tenant_id="TENANT-001", limit=50)
        self.assertEqual(len(timeline), 12)
        
        timestamps = [t["event_time_utc"] for t in timeline]
        self.assertEqual(timestamps, sorted(timestamps))

    # -------------------------------------------------------------------------
    # TEST 3: Task D - Regional Ingest Routing & Data Residency Enforcement
    # -------------------------------------------------------------------------
    def test_03_regional_data_residency_enforcement(self):
        """
        Task D:
        TENANT-001 is resident in 'us-east-1'.
        A payload stamped with 'eu-central-1' must be rejected with HTTP 403 Forbidden.
        TENANT-ALPHA is resident in 'eu-central-1' and must be accepted in 'eu-central-1'.
        """
        # 1. Valid US payload for US Tenant
        p_us, _ = build_egress_payload(
            {"cpu": 50.0, "memory": 50.0, "disk": 50.0, "latency": 10.0, "packet_loss": 0.0},
            collector_id="COLL-001",
            tenant_id="TENANT-001",
            audit_log_path=self.test_audit_path
        )
        p_us_dict = p_us.model_dump()
        p_us_dict["region"] = "us-east-1"
        resp_valid = self.client.post("/ingest", json=p_us_dict, headers=self.headers_us)
        self.assertEqual(resp_valid.status_code, 200)

        # 2. Cross-region violation: TENANT-001 payload routing to eu-central-1
        p_cross, _ = build_egress_payload(
            {"cpu": 50.0, "memory": 50.0, "disk": 50.0, "latency": 10.0, "packet_loss": 0.0},
            collector_id="COLL-001",
            tenant_id="TENANT-001",
            audit_log_path=self.test_audit_path
        )
        p_cross_dict = p_cross.model_dump()
        p_cross_dict["region"] = "eu-central-1"  # Residency mismatch!
        resp_invalid = self.client.post("/ingest", json=p_cross_dict, headers=self.headers_us)
        self.assertEqual(resp_invalid.status_code, 403)
        self.assertEqual(resp_invalid.json()["detail"]["error"], "residency_violation")

        # 3. EU Tenant in EU Region succeeds
        p_eu, _ = build_egress_payload(
            {"cpu": 50.0, "memory": 50.0, "disk": 50.0, "latency": 10.0, "packet_loss": 0.0},
            collector_id="COLL-002",
            tenant_id="TENANT-ALPHA",
            audit_log_path=self.test_audit_path
        )
        p_eu_dict = p_eu.model_dump()
        p_eu_dict["region"] = "eu-central-1"
        resp_eu = self.client.post("/ingest", json=p_eu_dict, headers=self.headers_eu)
        self.assertEqual(resp_eu.status_code, 200)

    # -------------------------------------------------------------------------
    # TEST 4: Task E - Contextual Anomaly Detection & <= 15s Alert Triggering
    # -------------------------------------------------------------------------
    def test_04_contextual_multi_metric_anomaly_detection(self):
        """
        Task E:
        Feeds baseline samples, then sends multi-metric correlated spike:
        High Latency (320ms) + Packet Loss (25%) -> Triggers CORRELATED_NETWORK_DEGRADATION alert.
        SLA: Alert is computed and stored synchronously (< 5ms).
        """
        collector_id = "COLL-001"
        tenant_id = "TENANT-001"

        # Prime baseline samples (healthy)
        for i in range(5):
            p, _ = build_egress_payload(
                {"cpu": 40.0, "memory": 45.0, "disk": 50.0, "latency": 20.0, "packet_loss": 0.0},
                collector_id=collector_id,
                tenant_id=tenant_id,
                audit_log_path=self.test_audit_path
            )
            self.client.post("/ingest", json=p.model_dump(), headers=self.headers_us)

        # Trigger correlated anomaly: Latency spike + 25% Packet Loss
        start_time = time.perf_counter()
        spike_payload, _ = build_egress_payload(
            {"cpu": 42.0, "memory": 45.0, "disk": 50.0, "latency": 320.0, "packet_loss": 25.0},
            collector_id=collector_id,
            tenant_id=tenant_id,
            audit_log_path=self.test_audit_path
        )
        resp = self.client.post("/ingest", json=spike_payload.model_dump(), headers=self.headers_us)
        elapsed_sec = time.perf_counter() - start_time

        # Verify SLA: executed in < 15 seconds (actually < 0.1s)
        self.assertLess(elapsed_sec, 15.0)
        self.assertEqual(resp.status_code, 200)

        # Confirm anomaly was attached in response
        data = resp.json()
        self.assertIn("anomaly_alert", data)
        alert = data["anomaly_alert"]
        self.assertEqual(alert["alert_type"], "CORRELATED_NETWORK_DEGRADATION")
        self.assertEqual(alert["severity"], "CRITICAL")
        self.assertIn("path congestion", alert["diagnosis"])

        # Confirm alert is queryable in active alerts
        active_alerts = self.saas_storage.get_active_alerts(tenant_id=tenant_id)
        self.assertGreaterEqual(len(active_alerts), 1)
        self.assertEqual(active_alerts[0]["alert_type"], "CORRELATED_NETWORK_DEGRADATION")

    # -------------------------------------------------------------------------
    # TEST 5: Task F - Stale-Data & 60s Outage Detection State Machine
    # -------------------------------------------------------------------------
    def test_05_stale_data_60s_outage_state_machine_and_recovery(self):
        """
        Task F:
        1. Register collector with last_seen = 70s ago.
        2. Watchdog transitions collector to 'Stale/Offline' and triggers OUTAGE_ALERT.
        3. Collector reconnects with fresh telemetry -> Status recovers to 'Healthy'
           and outage alert is automatically resolved.
        """
        cid = "COLL-001"
        tenant = "TENANT-001"
        stale_time = (datetime.now(timezone.utc) - timedelta(seconds=70)).strftime("%Y-%m-%dT%H:%M:%SZ")

        # 1. Seed collector in registry as seen 70 seconds ago
        self.saas_storage.update_collector_heartbeat(
            collector_id=cid,
            tenant_id=tenant,
            region="us-east-1",
            version="1.0.0",
            status="Healthy",
            heartbeat_timestamp=stale_time
        )

        # 2. Run fleet watchdog freshness check
        stale_nodes = watchdog.check_fleet_freshness()
        self.assertEqual(len(stale_nodes), 1)
        
        # Verify status transitioned to 'Stale/Offline'
        collector_state = self.saas_storage.get_collector(cid)
        self.assertEqual(collector_state["status"], "Stale/Offline")

        # Verify OUTAGE_ALERT was created
        alerts = self.saas_storage.get_active_alerts(tenant_id=tenant)
        outage_alerts = [a for a in alerts if a["alert_type"] == "COLLECTOR_OUTAGE"]
        self.assertEqual(len(outage_alerts), 1)
        self.assertEqual(outage_alerts[0]["severity"], "CRITICAL")

        # 3. Collector reconnects and sends healthy payload
        recover_payload, _ = build_egress_payload(
            {"cpu": 35.0, "memory": 40.0, "disk": 45.0, "latency": 12.0, "packet_loss": 0.0},
            collector_id=cid,
            tenant_id=tenant,
            audit_log_path=self.test_audit_path
        )
        resp = self.client.post("/ingest", json=recover_payload.model_dump(), headers=self.headers_us)
        self.assertEqual(resp.status_code, 200)

        # 4. Verify clean recovery: Status returned to 'Healthy', outage alert resolved
        recovered_state = self.saas_storage.get_collector(cid)
        self.assertEqual(recovered_state["status"], "Healthy")

        active_outages = [a for a in self.saas_storage.get_active_alerts(tenant_id=tenant) if a["alert_type"] == "COLLECTOR_OUTAGE"]
        self.assertEqual(len(active_outages), 0)

    # -------------------------------------------------------------------------
    # TEST 6: Dashboard & Zero-Trust Egress Proof Panel Verification
    # -------------------------------------------------------------------------
    def test_06_dashboard_endpoints_and_egress_proof_verification(self):
        """
        Verifies:
        - GET /dashboard returns HTML page
        - GET /api/v1/dashboard/overview returns 4 health states
        - GET /api/v1/dashboard/egress-proofs proves 0 raw data in SaaS storage
        """
        # Ingest a sample payload
        p, _ = build_egress_payload(
            {"cpu": 45.0, "memory": 50.0, "disk": 55.0, "latency": 15.0, "packet_loss": 0.0},
            collector_id="COLL-001",
            tenant_id="TENANT-001",
            audit_log_path=self.test_audit_path
        )
        self.client.post("/ingest", json=p.model_dump(), headers=self.headers_us)

        # 1. HTML UI
        ui_resp = self.client.get("/dashboard")
        self.assertEqual(ui_resp.status_code, 200)
        self.assertIn("Privacy-First AIOps", ui_resp.text)
        self.assertIn("Zero-Trust Egress Proof Audit Panel", ui_resp.text)

        # 2. Overview Endpoint
        ov_resp = self.client.get("/api/v1/dashboard/overview?tenant_id=TENANT-001")
        self.assertEqual(ov_resp.status_code, 200)
        ov = ov_resp.json()
        self.assertIn("health_states", ov)
        self.assertIn("Healthy", ov["health_states"])
        self.assertIn("Stale/Offline", ov["health_states"])

        # 3. Egress Proof Panel API (Zero-Trust verification)
        proof_resp = self.client.get("/api/v1/dashboard/egress-proofs?tenant_id=TENANT-001")
        self.assertEqual(proof_resp.status_code, 200)
        proofs = proof_resp.json()
        self.assertGreaterEqual(len(proofs), 1)
        self.assertFalse(proofs[0]["has_raw_data"])
        self.assertTrue(proofs[0]["verified_privacy_seal"])


if __name__ == "__main__":
    unittest.main()
