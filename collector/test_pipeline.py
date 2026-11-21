"""
Comprehensive Verification Test Suite for Privacy-First AIOps Observability Platform (Stage 1).
Validates:
1. Single payload-builder chokepoint & strict allow-list enforcement (non-allowed fields dropped).
2. Seeded fake password / API key / email never appear in egress payload or buffer.
3. Local SQLite buffer persistence & survival across restarts.
4. Cryptographic SHA-256 egress hash verification.
5. Invariant check: raw_data is strictly absent from SQLite buffer 'unsent_payloads'.
6. Local raw-vs-redacted audit log integrity.
7. Telemetry collection metrics & 4 health states.
"""

import gc
import json
from pathlib import Path
import sqlite3
import unittest
from datetime import datetime

from collector.config import config
from collector.models import (
    EgressPayload,
    HealthStatus,
    LogEventMetadata,
    MetricMetadata,
    RawSystemMetrics,
    SeverityLevel,
)
from collector.security_pipeline import SecurityPipeline
from collector.metadata_engine import MetadataEngine
from collector.buffer_manager import LocalBufferManager
from collector.collector import SystemCollector, PipelineProcessor
from collector.payload_builder import build_egress_payload


class TestPhase1Stage1Verification(unittest.TestCase):
    """Unit and Integration tests asserting all Stage 1 security and functional invariants."""

    @classmethod
    def setUpClass(cls):
        cls.test_db_path = Path(__file__).parent / "test_database.db"
        cls.test_audit_path = Path(__file__).parent / "test_local_audit.jsonl"
        if cls.test_db_path.exists():
            cls.test_db_path.unlink()
        if cls.test_audit_path.exists():
            cls.test_audit_path.unlink()

        cls.buffer = LocalBufferManager(db_path=cls.test_db_path)
        cls.security = SecurityPipeline()
        cls.metadata = MetadataEngine()
        cls.collector = SystemCollector()
        cls.processor = PipelineProcessor(
            collector=cls.collector,
            buffer=cls.buffer,
            audit_log_path=cls.test_audit_path
        )

    @classmethod
    def tearDownClass(cls):
        gc.collect()
        for p in [cls.test_db_path, cls.test_audit_path]:
            if p.exists():
                try:
                    p.unlink()
                except Exception:
                    pass
        for ext in ["-wal", "-shm"]:
            aux = cls.test_db_path.with_name(cls.test_db_path.name + ext)
            if aux.exists():
                try:
                    aux.unlink()
                except Exception:
                    pass

    # -------------------------------------------------------------------------
    # TEST 1: Strict Allow-List Enforcement (Single Chokepoint)
    # -------------------------------------------------------------------------
    def test_allow_list_drops_non_allowed_fields(self):
        """
        Confirms the single payload-builder chokepoint strictly enforces an allow-list.
        Non-allowed fields (e.g. injected environment secrets, rogue tokens) MUST be dropped.
        """
        raw_telemetry_with_rogue_fields = {
            "cpu": 55.4,
            "memory": 68.0,
            "disk": 42.1,
            "latency": 15.0,
            "unauthorized_secret_key": "SUPER_SECRET_TOKEN_999",
            "internal_ip_address": "192.168.1.100",
            "host_environment_dump": "AWS_SECRET_ACCESS_KEY=abcd1234efgh"
        }

        payload, audit = build_egress_payload(
            raw_telemetry_with_rogue_fields,
            audit_log_path=self.test_audit_path
        )

        # Assert rogue fields are completely dropped from the egress payload
        self.assertNotIn("unauthorized_secret_key", payload.data)
        self.assertNotIn("internal_ip_address", payload.data)
        self.assertNotIn("host_environment_dump", payload.data)
        self.assertNotIn("SUPER_SECRET_TOKEN_999", json.dumps(payload.model_dump()))

        # Assert allowed fields are retained
        self.assertEqual(payload.data["cpu"], 55.4)
        self.assertEqual(payload.data["memory"], 68.0)

        # Assert dropped fields were tracked in the local audit record
        self.assertIn("unauthorized_secret_key", audit.dropped_fields)
        self.assertIn("internal_ip_address", audit.dropped_fields)

    # -------------------------------------------------------------------------
    # TEST 2: Seeded Fake Passwords, API Keys, Emails Never Leak
    # -------------------------------------------------------------------------
    def test_seeded_secrets_never_leak_in_payload_or_buffer(self):
        """
        Asserts that seeded fake passwords, API keys, and emails NEVER appear in the egress payload or SQLite buffer.
        """
        fake_password = "MyFakeSuperSecretPassword123!"
        fake_api_key = "sk-live-fake-api-key-9988776655"
        fake_email = "victim.user@restricted-domain.com"
        fake_card = "4111-2222-3333-4444"

        raw_log = (
            f"User: Alice Developer\n"
            f"Password: {fake_password}\n"
            f"API_KEY: {fake_api_key}\n"
            f"Email: {fake_email}\n"
            f"Card: {fake_card}\n\n"
            f"Payment Failed"
        )

        pid, payload, audit = self.processor.process_record(raw_log)
        payload_dump = json.dumps(payload.model_dump())

        # Check payload does NOT contain secrets
        self.assertNotIn(fake_password, payload_dump)
        self.assertNotIn(fake_api_key, payload_dump)
        self.assertNotIn(fake_email, payload_dump)
        self.assertNotIn(fake_card, payload_dump)
        self.assertNotIn("Alice Developer", payload_dump)

        # Check SQLite database does NOT contain secrets
        conn = sqlite3.connect(str(self.test_db_path))
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT payload_json FROM unsent_payloads WHERE payload_id = ?", (pid,))
            row = cursor.fetchone()
            db_json = row[0]
            self.assertNotIn(fake_password, db_json)
            self.assertNotIn(fake_api_key, db_json)
            self.assertNotIn(fake_email, db_json)
            self.assertNotIn(fake_card, db_json)
            self.assertNotIn("Alice Developer", db_json)
        finally:
            conn.close()

    # -------------------------------------------------------------------------
    # TEST 3: Raw Data Is Strictly Excluded from Buffer
    # -------------------------------------------------------------------------
    def test_raw_data_never_stored_in_unsent_payloads_buffer(self):
        """
        Strict check: unsent_payloads in SQLite must store ONLY sanitized EgressPayload.
        raw_data must NOT exist in the buffer table.
        """
        raw_sensitive = "User: Bob\nPassword: pwd\n\nDatabase Connection Lost"
        pid, payload, audit = self.processor.process_record(raw_sensitive)

        conn = sqlite3.connect(str(self.test_db_path))
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT payload_json FROM unsent_payloads WHERE payload_id = ?", (pid,))
            stored_str = cursor.fetchone()[0]
            stored_dict = json.loads(stored_str)

            # Invariant assertions
            self.assertNotIn("raw_data", stored_dict)
            self.assertNotIn("raw_input", stored_dict)
            self.assertIn("sha256", stored_dict)
            self.assertIn("source_timezone", stored_dict)
            self.assertIn("source_id_hash", stored_dict)
        finally:
            conn.close()

    # -------------------------------------------------------------------------
    # TEST 4: Queue Survives Restart
    # -------------------------------------------------------------------------
    def test_queue_survives_restart(self):
        """
        Tests that payloads persisted to SQLite survive full service shutdown and restart.
        """
        test_payload, _ = build_egress_payload(
            {"cpu": 72.1, "memory": 65.0, "disk": 50.0, "latency": 14.0},
            audit_log_path=self.test_audit_path
        )
        test_buf = LocalBufferManager(db_path=self.test_db_path)
        pid = test_buf.store_payload(test_payload)

        # Simulate service shutdown & garbage collection
        del test_buf
        gc.collect()

        # Restart buffer manager from on-disk SQLite file
        restarted_buffer = LocalBufferManager(db_path=self.test_db_path)
        recovered = restarted_buffer.get_payload_by_id(pid)

        self.assertIsNotNone(recovered)
        self.assertEqual(recovered["payload_id"], pid)
        self.assertEqual(recovered["status"], "PENDING")
        self.assertEqual(recovered["payload_json"]["data"]["cpu"], 72.1)

    # -------------------------------------------------------------------------
    # TEST 5: Egress SHA-256 Hash Matches Payload Body
    # -------------------------------------------------------------------------
    def test_egress_hash_matches_payload_content(self):
        """
        Verifies cryptographic checksum validation.
        """
        payload, _ = build_egress_payload(
            {"cpu": 82.5, "memory": 77.0, "disk": 60.0, "latency": 22.0},
            audit_log_path=self.test_audit_path
        )
        self.assertTrue(payload.verify_checksum())
        self.assertEqual(len(payload.sha256), 64)  # Valid SHA-256 hex length

    # -------------------------------------------------------------------------
    # TEST 6: User Canonical Sample (Payment Failed)
    # -------------------------------------------------------------------------
    def test_canonical_user_example(self):
        """
        Input:
          User: Manik Sharma
          Password: abc123
          API_KEY: abc-xyz-123

          Payment Failed
        Expected Output:
          Payment Failed (event: PAYMENT_FAILURE, severity: HIGH)
        """
        sample_input = (
            "User: Manik Sharma\n"
            "Password: abc123\n"
            "API_KEY: abc-xyz-123\n\n"
            "Payment Failed"
        )
        pid, payload, audit = self.processor.process_record(sample_input)

        self.assertEqual(payload.data.get("message"), "Payment Failed")
        self.assertEqual(payload.metadata.get("event"), "PAYMENT_FAILURE")
        self.assertEqual(payload.metadata.get("severity"), "HIGH")

    # -------------------------------------------------------------------------
    # TEST 7: CPU Threshold Canonical Sample (CPU=95)
    # -------------------------------------------------------------------------
    def test_cpu_95_threshold(self):
        """
        Input: CPU=95
        Output:
          metric_type: CPU, value: 95, health: POOR, severity: HIGH
        """
        result = self.metadata.process("CPU=95")
        self.assertEqual(result["metric_type"], "CPU")
        self.assertEqual(result["value"], 95)
        self.assertEqual(result["health"], "POOR")
        self.assertEqual(result["severity"], "HIGH")

    # -------------------------------------------------------------------------
    # TEST 8: Local Audit Log Preserves Raw-vs-Redacted for Host Operator
    # -------------------------------------------------------------------------
    def test_local_audit_log_written_locally(self):
        """
        Asserts that local_audit.jsonl is written with raw vs redacted details.
        """
        sample = "User: Admin\nPassword: pwd\n\nCache Eviction Warning"
        _, _, audit = self.processor.process_record(sample)

        self.assertTrue(self.test_audit_path.exists())
        with open(self.test_audit_path, "r", encoding="utf-8") as f:
            lines = [json.loads(line) for line in f if line.strip()]

        matched = [l for l in lines if l["audit_id"] == audit.audit_id]
        self.assertEqual(len(matched), 1)
        self.assertIn("Admin", str(matched[0]["raw_data"]))
        self.assertNotIn("Admin", str(matched[0]["redacted_data"]))


if __name__ == "__main__":
    unittest.main()
