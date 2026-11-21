"""
Phase 4.5 Test Suite: Self-Learning Seasonal Baselines & Outside Cyber Attack Detection.
Verifies:
1. 168-Slot Matrix Online Continuous Learning (EMA with Dynamic Variance)
2. Monday Busy Traffic vs Sunday Idle Free Servers (Benign vs Worrying Fluctuation Advisory)
3. Outside Brute-Force / Credential Stuffing Attack detection with mitigation scripts
4. Outside Volumetric Network DDoS Flood detection
5. Outside Slowloris Connection Starvation detection
6. Alert Fatigue Suppression & Auto-Resolution upon attack subside
7. REST APIs (/seasonal-baseline, /threats, /threats/{id}/resolve)
"""

from datetime import datetime, timezone
import json
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
from saas_service.services.seasonal_engine import seasonal_engine
from saas_service.services.threat_engine import threat_engine


class TestPhase45SeasonalThreats(unittest.TestCase):
    """Phase 4.5 Verification Suite for Seasonal Profiling and Outside Attack Detection."""

    def setUp(self):
        storage_service._init_database()
        storage_service.clear_all()
        threat_engine.calm_cycles.clear()
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
        event_time_utc: str = "2026-11-23T10:00:00Z"  # 2026-11-23 is a Monday
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

    def test_01_seasonal_matrix_online_learning(self):
        """Test 1: Online Continuous Learning updates 168-slot profile dynamically."""
        # Monday 10:00 AM (Day 0, Hour 10)
        p1 = self._create_payload(cpu=50.0, event_time_utc="2026-11-23T10:00:00Z")
        resp1 = self.client.post("/ingest", json=p1, headers=self.headers)
        self.assertEqual(resp1.status_code, 200)

        base1 = storage_service.get_seasonal_baseline(
            tenant_id=self.tenant_id,
            collector_id=self.collector_id,
            day_of_week=0,
            hour_of_day=10,
            metric_name="cpu"
        )
        self.assertIsNotNone(base1)
        self.assertEqual(base1["sample_count"], 1)
        self.assertEqual(base1["mean"], 50.0)

        # Second observation updates mean via EMA
        p2 = self._create_payload(cpu=60.0, event_time_utc="2026-11-23T10:05:00Z")
        self.client.post("/ingest", json=p2, headers=self.headers)

        base2 = storage_service.get_seasonal_baseline(
            tenant_id=self.tenant_id,
            collector_id=self.collector_id,
            day_of_week=0,
            hour_of_day=10,
            metric_name="cpu"
        )
        self.assertEqual(base2["sample_count"], 2)
        # Expected EMA: 50.0 + 0.08 * (60.0 - 50.0) = 50.8
        self.assertAlmostEqual(base2["mean"], 50.8, places=1)

    def test_02_monday_busy_vs_sunday_idle_advisory(self):
        """Test 2: Evaluates benign Monday morning business traffic vs worrying Sunday off-peak surge."""
        # 1. Seed Monday 10:00 AM with a high-traffic business baseline (mean ~78%)
        for _ in range(5):
            p_mon = self._create_payload(cpu=78.0, event_time_utc="2026-11-23T10:00:00Z")
            self.client.post("/ingest", json=p_mon, headers=self.headers)

        # An 80% CPU reading on Monday 10:00 AM should be classified as BENIGN (normal workday business load)
        p_mon_test = self._create_payload(cpu=80.0, event_time_utc="2026-11-23T10:30:00Z")
        resp_mon = self.client.post("/ingest", json=p_mon_test, headers=self.headers).json()
        fluctuations = resp_mon.get("seasonal_fluctuations", [])
        cpu_fluc = next((f for f in fluctuations if f["metric_name"] == "cpu"), None)
        self.assertIsNotNone(cpu_fluc)
        self.assertFalse(cpu_fluc["is_worrying"])
        self.assertIn("EXPECTED_WEEKDAY_PEAK", cpu_fluc["classification"])

        # 2. Seed Sunday 03:00 AM with an idle server baseline (mean ~15%)
        # 2026-11-22 is Sunday
        for _ in range(5):
            p_sun = self._create_payload(cpu=15.0, event_time_utc="2026-11-22T03:00:00Z")
            self.client.post("/ingest", json=p_sun, headers=self.headers)

        # An 80% CPU reading on Sunday 03:00 AM is WORRYING (abnormal off-peak surge)
        p_sun_test = self._create_payload(cpu=80.0, event_time_utc="2026-11-22T03:30:00Z")
        resp_sun = self.client.post("/ingest", json=p_sun_test, headers=self.headers).json()
        fluctuations_sun = resp_sun.get("seasonal_fluctuations", [])
        cpu_fluc_sun = next((f for f in fluctuations_sun if f["metric_name"] == "cpu"), None)
        self.assertIsNotNone(cpu_fluc_sun)
        self.assertTrue(cpu_fluc_sun["is_worrying"])
        self.assertEqual(cpu_fluc_sun["classification"], "WORRYING_OFFPEAK_SURGE")

    def test_03_outside_brute_force_attack_detection(self):
        """Test 3: Detects outside brute force attack and generates firewall mitigation commands."""
        payload = self._create_payload(failed_logins=12)
        resp = self.client.post("/ingest", json=payload, headers=self.headers)
        self.assertEqual(resp.status_code, 200)

        threats = storage_service.get_threat_events(tenant_id=self.tenant_id, status="ACTIVE")
        self.assertEqual(len(threats), 1)
        th = threats[0]
        self.assertEqual(th["threat_type"], "OUTSIDE_BRUTE_FORCE_FLOOD")
        self.assertEqual(th["threat_level"], "CRITICAL")
        self.assertIn("credential stuffing", th["vector_description"].lower())
        self.assertTrue(any("firewall" in cmd.lower() or "iptables" in cmd.lower() for cmd in th["mitigation_commands"]))

    def test_04_outside_volumetric_ddos_detection(self):
        """Test 4: Detects volumetric DDoS flood with upstream link saturation."""
        payload = self._create_payload(
            latency=220.0,
            packet_loss=25.0,
            cpu=45.0  # Low CPU proves network capacity saturation, not CPU lockup
        )
        resp = self.client.post("/ingest", json=payload, headers=self.headers)
        self.assertEqual(resp.status_code, 200)

        threats = storage_service.get_threat_events(tenant_id=self.tenant_id, status="ACTIVE")
        self.assertEqual(len(threats), 1)
        th = threats[0]
        self.assertEqual(th["threat_type"], "VOLUMETRIC_DDOS_FLOOD")
        self.assertEqual(th["threat_level"], "CRITICAL")
        self.assertTrue(any("bgp" in cmd.lower() or "scrubbing" in cmd.lower() or "syncookies" in cmd.lower() for cmd in th["mitigation_commands"]))

    def test_05_outside_slowloris_detection(self):
        """Test 5: Detects Slowloris connection pool exhaustion attack."""
        payload = self._create_payload(
            latency=260.0,
            cpu=22.0,
            packet_loss=0.0
        )
        resp = self.client.post("/ingest", json=payload, headers=self.headers)
        self.assertEqual(resp.status_code, 200)

        threats = storage_service.get_threat_events(tenant_id=self.tenant_id, status="ACTIVE")
        self.assertEqual(len(threats), 1)
        th = threats[0]
        self.assertEqual(th["threat_type"], "SLOWLORIS_CONNECTION_STARVATION")
        self.assertEqual(th["threat_level"], "HIGH")
        self.assertTrue(any("nginx" in cmd.lower() or "keepalive" in cmd.lower() for cmd in th["mitigation_commands"]))

    def test_06_alert_fatigue_suppression_and_auto_resolution(self):
        """Test 6: Repeat attacks update ongoing threat (no fatigue spam); calm cycles auto-resolve."""
        # 1. Trigger initial attack
        p1 = self._create_payload(failed_logins=8)
        self.client.post("/ingest", json=p1, headers=self.headers)

        threats1 = storage_service.get_threat_events(tenant_id=self.tenant_id, status="ACTIVE")
        self.assertEqual(len(threats1), 1)
        orig_id = threats1[0]["threat_id"]

        # 2. Ongoing attack: verify same threat_id is updated rather than creating duplicate records
        p2 = self._create_payload(failed_logins=15)
        self.client.post("/ingest", json=p2, headers=self.headers)

        threats2 = storage_service.get_threat_events(tenant_id=self.tenant_id, status="ACTIVE")
        self.assertEqual(len(threats2), 1)
        self.assertEqual(threats2[0]["threat_id"], orig_id)
        self.assertEqual(threats2[0]["threat_level"], "CRITICAL")  # Escalated

        # 3. Attack subsides: 3 consecutive clean cycles
        for _ in range(3):
            p_clean = self._create_payload(failed_logins=0, latency=15.0, packet_loss=0.0)
            self.client.post("/ingest", json=p_clean, headers=self.headers)

        # 4. Threat is auto-resolved
        active_after = storage_service.get_threat_events(tenant_id=self.tenant_id, status="ACTIVE")
        self.assertEqual(len(active_after), 0)

        resolved_after = storage_service.get_threat_events(tenant_id=self.tenant_id, status="RESOLVED")
        self.assertEqual(len(resolved_after), 1)
        self.assertEqual(resolved_after[0]["threat_id"], orig_id)

    def test_07_dashboard_threat_and_seasonal_apis(self):
        """Test 7: Verify GET /seasonal-baseline, GET /threats, and POST /threats/{id}/resolve."""
        # Seed seasonal baseline
        self.client.post("/ingest", json=self._create_payload(cpu=40.0), headers=self.headers)

        # Fetch 24-hour seasonal baseline curve
        curve_resp = self.client.get(
            f"/api/v1/dashboard/seasonal-baseline?tenant_id={self.tenant_id}&collector_id={self.collector_id}&day_of_week=0&metric_name=cpu"
        )
        self.assertEqual(curve_resp.status_code, 200)
        curve = curve_resp.json()
        self.assertEqual(len(curve), 24)
        self.assertIn("lower_band", curve[10])
        self.assertIn("upper_band", curve[10])

        # Trigger attack
        self.client.post("/ingest", json=self._create_payload(failed_logins=10), headers=self.headers)

        # List threats
        threats_resp = self.client.get(f"/api/v1/dashboard/threats?tenant_id={self.tenant_id}")
        self.assertEqual(threats_resp.status_code, 200)
        threats = threats_resp.json()
        self.assertEqual(len(threats), 1)
        th_id = threats[0]["threat_id"]

        # Manual resolve
        resolve_resp = self.client.post(f"/api/v1/dashboard/threats/{th_id}/resolve")
        self.assertEqual(resolve_resp.status_code, 200)
        self.assertEqual(resolve_resp.json()["status"], "RESOLVED")


if __name__ == "__main__":
    unittest.main()
