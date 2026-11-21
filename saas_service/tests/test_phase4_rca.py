"""
Phase 4 Test Suite: Probable Cause Engine (Rule-based Explainable AIOps).
Verifies:
1. Deterministic Root Cause Analysis (RCA) for Network Link Degradation
2. Progressive Memory Leak detection with timeline reconstruction
3. Brute-Force Authentication Surge diagnosis
4. Storage I/O Exhaustion diagnosis & WAL checkpoint runbooks
5. Cascading Multi-Resource Starvation diagnosis
6. Incident clustering (deduplication of open incidents) & auto-resolution upon telemetry recovery
7. REST APIs (/incidents, /incidents/{id}, /resolve) & Dashboard overview stats
"""

import hashlib
import json
import os
from pathlib import Path
import sys
import unittest
import uuid

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from fastapi.testclient import TestClient
from saas_service.main import app
from saas_service.services.storage import storage_service
from saas_service.services.auth import auth_service
from saas_service.services.checksum import checksum_service
from saas_service.services.rca_engine import rca_engine


class TestPhase4ProbableCauseEngine(unittest.TestCase):
    """Phase 4 Verification Suite for Explainable AIOps & Probable Cause Engine."""

    def setUp(self):
        storage_service._init_database()
        storage_service.clear_all()
        rca_engine.node_history.clear()
        rca_engine.healthy_cycles.clear()
        self.client = TestClient(app)
        self.tenant_id = "TENANT-001"
        self.collector_id = "COLL-001"
        self.region = "us-east-1"
        self.token_data = auth_service.issue_token(
            collector_id=self.collector_id,
            collector_secret="SECRET-COLL-DEMO-001",
            expires_in=3600
        )
        self.headers = {
            "Authorization": f"Bearer {self.token_data['access_token']}",
            "Content-Type": "application/json"
        }

    def _create_payload(
        self,
        cpu: float = 25.0,
        memory: float = 40.0,
        disk: float = 30.0,
        latency: float = 12.0,
        packet_loss: float = 0.0,
        failed_logins: int = 0,
        event_time_utc: str = "2026-11-21T02:00:00Z"
    ):
        data = {
            "cpu": cpu,
            "memory": memory,
            "disk": disk,
            "latency": latency,
            "packet_loss": packet_loss,
            "failed_logins": failed_logins,
            "timestamp": event_time_utc
        }

        p = {
            "payload_id": str(uuid.uuid4()),
            "collector_id": self.collector_id,
            "tenant_id": self.tenant_id,
            "region": self.region,
            "event_time_utc": event_time_utc,
            "source_timezone": "UTC",
            "data_type": "METRICS",
            "data": data,
            "metadata": {"system_health": "Healthy"},
            "version": "1.0.0"
        }
        p["sha256"] = checksum_service.calculate_sha256(p)
        return p

    def test_01_network_link_degradation_rca(self):
        """Test 1: Packet Loss + High Latency triggers NETWORK_LINK_DEGRADATION with >= 0.88 confidence."""
        payload = self._create_payload(
            latency=160.0,
            packet_loss=12.0,
            event_time_utc="2026-11-21T02:01:00Z"
        )
        resp = self.client.post("/ingest", json=payload, headers=self.headers)
        self.assertEqual(resp.status_code, 200)

        # Check incident in storage
        incidents = storage_service.get_incidents(tenant_id=self.tenant_id, status="OPEN")
        self.assertEqual(len(incidents), 1)
        inc = incidents[0]

        self.assertEqual(inc["incident_type"], "NETWORK_LINK_DEGRADATION")
        self.assertGreaterEqual(inc["confidence_score"], 0.88)
        self.assertIn("Upstream transport-layer network congestion", inc["root_cause"])
        self.assertTrue(any("traceroute" in r.lower() or "mtr" in r.lower() for r in inc["recommendations"]))
        self.assertEqual(len(inc["timeline"]), 1)
        self.assertEqual(inc["timeline"][0]["phase"], "Incident Triggered")

    def test_02_memory_leak_progressive_growth_rca(self):
        """Test 2: Monotonic RAM growth triggers MEMORY_LEAK_EXHAUSTION with reconstructed timeline."""
        # Baseline samples
        for i, ram in enumerate([60.0, 75.0, 86.0, 93.0]):
            p = self._create_payload(
                memory=ram,
                event_time_utc=f"2026-11-21T02:02:0{i}Z"
            )
            resp = self.client.post("/ingest", json=p, headers=self.headers)
            self.assertEqual(resp.status_code, 200)

        incidents = storage_service.get_incidents(tenant_id=self.tenant_id, status="OPEN")
        self.assertEqual(len(incidents), 1)
        inc = incidents[0]

        self.assertEqual(inc["incident_type"], "MEMORY_LEAK_EXHAUSTION")
        self.assertEqual(inc["severity"], "CRITICAL")
        self.assertGreaterEqual(inc["confidence_score"], 0.90)
        self.assertIn("memory leak", inc["root_cause"].lower())
        self.assertTrue(any("heap" in r.lower() for r in inc["recommendations"]))
        # Verify chronological timeline shows escalation
        self.assertGreaterEqual(len(inc["timeline"]), 3)
        self.assertEqual(inc["timeline"][-1]["phase"], "Ongoing Degradation")

    def test_03_brute_force_auth_attack_rca(self):
        """Test 3: Surge in failed logins triggers BRUTE_FORCE_AUTH_ATTACK with security runbooks."""
        payload = self._create_payload(
            failed_logins=15,
            event_time_utc="2026-11-21T02:03:00Z"
        )
        resp = self.client.post("/ingest", json=payload, headers=self.headers)
        self.assertEqual(resp.status_code, 200)

        incidents = storage_service.get_incidents(tenant_id=self.tenant_id, status="OPEN")
        self.assertEqual(len(incidents), 1)
        inc = incidents[0]

        self.assertEqual(inc["incident_type"], "BRUTE_FORCE_AUTH_ATTACK")
        self.assertEqual(inc["severity"], "CRITICAL")
        self.assertGreaterEqual(inc["confidence_score"], 0.95)
        self.assertIn("credential stuffing", inc["root_cause"].lower())
        self.assertTrue(any("rate-limiting" in r.lower() for r in inc["recommendations"]))

    def test_04_storage_io_exhaustion_rca(self):
        """Test 4: Disk >= 88% triggers STORAGE_IO_EXHAUSTION with disk purge runbooks."""
        payload = self._create_payload(
            disk=91.5,
            event_time_utc="2026-11-21T02:04:00Z"
        )
        resp = self.client.post("/ingest", json=payload, headers=self.headers)
        self.assertEqual(resp.status_code, 200)

        incidents = storage_service.get_incidents(tenant_id=self.tenant_id, status="OPEN")
        self.assertEqual(len(incidents), 1)
        inc = incidents[0]

        self.assertEqual(inc["incident_type"], "STORAGE_IO_EXHAUSTION")
        self.assertGreaterEqual(inc["confidence_score"], 0.90)
        self.assertIn("filesystem capacity exhaustion", inc["root_cause"].lower())
        self.assertTrue(any("purge" in r.lower() or "wal" in r.lower() for r in inc["recommendations"]))

    def test_05_cascading_multi_resource_starvation_rca(self):
        """Test 5: CPU + Memory + Latency triggers CASCADING_RESOURCE_STARVATION with 97% confidence."""
        payload = self._create_payload(
            cpu=95.0,
            memory=88.0,
            latency=180.0,
            event_time_utc="2026-11-21T02:05:00Z"
        )
        resp = self.client.post("/ingest", json=payload, headers=self.headers)
        self.assertEqual(resp.status_code, 200)

        incidents = storage_service.get_incidents(tenant_id=self.tenant_id, status="OPEN")
        self.assertEqual(len(incidents), 1)
        inc = incidents[0]

        self.assertEqual(inc["incident_type"], "CASCADING_RESOURCE_STARVATION")
        self.assertEqual(inc["severity"], "CRITICAL")
        self.assertGreaterEqual(inc["confidence_score"], 0.95)
        self.assertIn("Cascading multi-resource bottleneck", inc["root_cause"])
        self.assertTrue(any("scale" in r.lower() or "throttle" in r.lower() for r in inc["recommendations"]))

    def test_06_incident_clustering_and_auto_resolution(self):
        """Test 6: Repeated anomalies cluster under single incident; healthy telemetry auto-resolves."""
        # 1. Trigger incident
        p1 = self._create_payload(disk=90.0, event_time_utc="2026-11-21T02:06:01Z")
        self.client.post("/ingest", json=p1, headers=self.headers)

        open_inc = storage_service.get_incidents(tenant_id=self.tenant_id, status="OPEN")
        self.assertEqual(len(open_inc), 1)
        orig_id = open_inc[0]["incident_id"]

        # 2. Trigger again - should cluster into same incident rather than create a duplicate
        p2 = self._create_payload(disk=92.0, event_time_utc="2026-11-21T02:06:06Z")
        self.client.post("/ingest", json=p2, headers=self.headers)

        open_inc_2 = storage_service.get_incidents(tenant_id=self.tenant_id, status="OPEN")
        self.assertEqual(len(open_inc_2), 1)
        self.assertEqual(open_inc_2[0]["incident_id"], orig_id)
        self.assertEqual(len(open_inc_2[0]["timeline"]), 2)

        # 3. Simulate recovery (3 consecutive healthy telemetry cycles)
        for i in range(3):
            p_healthy = self._create_payload(disk=45.0, event_time_utc=f"2026-11-21T02:07:0{i}Z")
            self.client.post("/ingest", json=p_healthy, headers=self.headers)

        # 4. Verify incident auto-resolved
        open_after = storage_service.get_incidents(tenant_id=self.tenant_id, status="OPEN")
        self.assertEqual(len(open_after), 0)

        resolved_inc = storage_service.get_incidents(tenant_id=self.tenant_id, status="RESOLVED")
        self.assertEqual(len(resolved_inc), 1)
        self.assertEqual(resolved_inc[0]["incident_id"], orig_id)
        self.assertIsNotNone(resolved_inc[0]["resolved_at"])

    def test_07_dashboard_incident_rest_apis(self):
        """Test 7: Verify GET /incidents, GET /incidents/{id}, and POST /resolve."""
        # Trigger incident
        payload = self._create_payload(latency=180.0, packet_loss=15.0)
        self.client.post("/ingest", json=payload, headers=self.headers)

        # List incidents
        list_resp = self.client.get(f"/api/v1/dashboard/incidents?tenant_id={self.tenant_id}")
        self.assertEqual(list_resp.status_code, 200)
        incidents = list_resp.json()
        self.assertEqual(len(incidents), 1)
        inc_id = incidents[0]["incident_id"]

        # Get detail
        detail_resp = self.client.get(f"/api/v1/dashboard/incidents/{inc_id}")
        self.assertEqual(detail_resp.status_code, 200)
        detail = detail_resp.json()
        self.assertEqual(detail["incident_id"], inc_id)
        self.assertIn("timeline", detail)
        self.assertIn("recommendations", detail)

        # Overview count
        ov_resp = self.client.get(f"/api/v1/dashboard/overview?tenant_id={self.tenant_id}")
        self.assertEqual(ov_resp.status_code, 200)
        self.assertEqual(ov_resp.json()["active_incidents_count"], 1)

        # Manual resolve
        resolve_resp = self.client.post(f"/api/v1/dashboard/incidents/{inc_id}/resolve")
        self.assertEqual(resolve_resp.status_code, 200)
        self.assertEqual(resolve_resp.json()["status"], "RESOLVED")

        # Verify now resolved
        detail_after = self.client.get(f"/api/v1/dashboard/incidents/{inc_id}").json()
        self.assertEqual(detail_after["status"], "RESOLVED")


if __name__ == "__main__":
    unittest.main()
