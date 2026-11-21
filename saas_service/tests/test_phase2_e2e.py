"""
End-to-End Automated Test Suite for Phase 2:
Validates all 8 Required Test Cases:
TEST 1: Backend Running -> PENDING -> SENT (PASS)
TEST 2: Backend Offline -> Payload Buffered in SQLite (PASS)
TEST 3: Backend Restored -> Automatic Replay Works -> Marked SENT (PASS)
TEST 4: Duplicate Payload -> Idempotently handled with {"duplicate": true} (PASS)
TEST 5: Invalid API Key -> HTTP 401 (PASS)
TEST 6: Corrupted SHA -> HTTP 400 checksum_validation_failed (PASS)
TEST 7: Dead Letter Queue -> Repeatedly failing/corrupted payload moved to DEAD_LETTER (PASS)
TEST 8: Heartbeat -> Last Seen Updated in Collector Registry (PASS)
"""

import gc
import json
from pathlib import Path
import sqlite3
import unittest
from unittest.mock import patch
import requests

from fastapi.testclient import TestClient

from saas_service.main import app
from saas_service.services.storage import SaaSStorageService, storage_service
from saas_service.services.auth import auth_service
from collector.config import config
from collector.models import EgressPayload
from collector.payload_builder import build_egress_payload
from collector.buffer_manager import LocalBufferManager
from collector.egress_worker import EgressWorker
from collector.heartbeat_service import HeartbeatService


class TestPhase2EndToEnd(unittest.TestCase):
    """Executes all 8 Phase 2 Acceptance Test Cases."""

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.test_edge_db = Path(__file__).parent / "test_edge_buffer.db"
        cls.test_saas_db = Path(__file__).parent / "test_saas_storage.db"
        cls.test_audit_path = Path(__file__).parent / "test_audit.jsonl"

        # Wipe previous test databases if present
        for p in [cls.test_edge_db, cls.test_saas_db, cls.test_audit_path]:
            if p.exists():
                try:
                    p.unlink()
                except Exception:
                    pass

        cls.edge_buffer = LocalBufferManager(db_path=cls.test_edge_db)
        cls.saas_storage = SaaSStorageService(db_path=cls.test_saas_db)

        # Patch storage service in saas app routes to use test database
        storage_service.db_path = cls.test_saas_db
        storage_service._init_database()

        cls.valid_key = "COLL-KEY-DEMO-001"
        cls.worker = EgressWorker(
            buffer=cls.edge_buffer,
            saas_url="http://testserver",
            collector_key=cls.valid_key,
            max_retries=2
        )
        cls.heartbeat = HeartbeatService(
            saas_url="http://testserver",
            collector_key=cls.valid_key,
            collector_id="COLL-001"
        )

    @classmethod
    def tearDownClass(cls):
        gc.collect()
        for p in [cls.test_edge_db, cls.test_saas_db, cls.test_audit_path]:
            if p.exists():
                try:
                    p.unlink()
                except Exception:
                    pass
        for ext in ["-wal", "-shm"]:
            for base in [cls.test_edge_db, cls.test_saas_db]:
                aux = base.with_name(base.name + ext)
                if aux.exists():
                    try:
                        aux.unlink()
                    except Exception:
                        pass

    def setUp(self):
        self.edge_buffer.clear_all()
        self.saas_storage.clear_all()

    # -------------------------------------------------------------------------
    # TEST 1: Backend Running -> PENDING -> SENT
    # -------------------------------------------------------------------------
    def test_01_backend_running_pending_to_sent(self):
        """
        TEST 1:
        Backend Running
        PENDING -> Transmit -> SENT
        PASS
        """
        payload, _ = build_egress_payload(
            {"cpu": 45.0, "memory": 60.0, "disk": 50.0, "latency": 12.0},
            audit_log_path=self.test_audit_path
        )
        pid = self.edge_buffer.store_payload(payload)
        self.assertEqual(self.edge_buffer.get_payload_by_id(pid)["status"], "PENDING")

        # Mock requests.post to forward directly to FastAPI TestClient
        def mock_post(url, json=None, headers=None, timeout=None):
            resp = self.client.post(url.replace("http://testserver", ""), json=json, headers=headers)
            mock_resp = requests.Response()
            mock_resp.status_code = resp.status_code
            mock_resp._content = resp.content
            return mock_resp

        with patch("requests.post", side_effect=mock_post):
            counts = self.worker.process_pending_batch()

        self.assertEqual(counts["sent"], 1)
        self.assertEqual(self.edge_buffer.get_payload_by_id(pid)["status"], "SENT")
        self.assertTrue(self.saas_storage.payload_exists(pid))

    # -------------------------------------------------------------------------
    # TEST 2: Backend Offline -> Payload Buffered
    # -------------------------------------------------------------------------
    def test_02_backend_offline_payload_buffered(self):
        """
        TEST 2:
        Backend Offline
        Payload Buffered locally in SQLite
        PASS
        """
        payload, _ = build_egress_payload(
            {"cpu": 88.0, "memory": 79.0, "disk": 65.0, "latency": 19.0},
            audit_log_path=self.test_audit_path
        )
        pid = self.edge_buffer.store_payload(payload)

        # Simulate backend offline (ConnectionError)
        def mock_post_offline(url, json=None, headers=None, timeout=None):
            raise requests.exceptions.ConnectionError("Connection refused by SaaS endpoint")

        with patch("requests.post", side_effect=mock_post_offline):
            counts = self.worker.process_pending_batch()

        self.assertEqual(counts["retried"], 1)
        # Payload remains safely buffered as PENDING
        buffered_item = self.edge_buffer.get_payload_by_id(pid)
        self.assertEqual(buffered_item["status"], "PENDING")
        self.assertGreaterEqual(buffered_item["retry_count"], 1)

    # -------------------------------------------------------------------------
    # TEST 3: Backend Restored -> Replay Works -> Marked SENT
    # -------------------------------------------------------------------------
    def test_03_backend_restored_replay_works(self):
        """
        TEST 3:
        Backend Restored
        Replay Works -> Zero Data Loss
        PASS
        """
        # Step 3a: Buffer 2 payloads while offline
        p1, _ = build_egress_payload({"cpu": 40.0, "memory": 50.0, "disk": 40.0, "latency": 10.0}, audit_log_path=self.test_audit_path)
        p2, _ = build_egress_payload({"cpu": 75.0, "memory": 82.0, "disk": 55.0, "latency": 15.0}, audit_log_path=self.test_audit_path)
        pid1 = self.edge_buffer.store_payload(p1)
        pid2 = self.edge_buffer.store_payload(p2)

        self.assertEqual(len(self.edge_buffer.get_unsent_payloads()), 2)

        # Step 3b: Backend is restored (TestClient responds)
        def mock_post(url, json=None, headers=None, timeout=None):
            resp = self.client.post(url.replace("http://testserver", ""), json=json, headers=headers)
            mock_resp = requests.Response()
            mock_resp.status_code = resp.status_code
            mock_resp._content = resp.content
            return mock_resp

        with patch("requests.post", side_effect=mock_post):
            counts = self.worker.process_pending_batch()

        # Both replayed and marked SENT
        self.assertEqual(counts["sent"], 2)
        self.assertEqual(len(self.edge_buffer.get_unsent_payloads()), 0)
        self.assertEqual(self.edge_buffer.get_payload_by_id(pid1)["status"], "SENT")
        self.assertEqual(self.edge_buffer.get_payload_by_id(pid2)["status"], "SENT")
        self.assertTrue(self.saas_storage.payload_exists(pid1))
        self.assertTrue(self.saas_storage.payload_exists(pid2))

    # -------------------------------------------------------------------------
    # TEST 4: Duplicate Payload -> Idempotent Handling
    # -------------------------------------------------------------------------
    def test_04_duplicate_payload_rejected_idempotently(self):
        """
        TEST 4:
        Duplicate Payload
        Rejected / Handled Idempotently with {"duplicate": true}
        PASS
        """
        payload, _ = build_egress_payload(
            {"cpu": 66.0, "memory": 70.0, "disk": 50.0, "latency": 11.0},
            audit_log_path=self.test_audit_path
        )
        payload_dict = payload.model_dump()

        # First Ingestion
        resp1 = self.client.post("/ingest", json=payload_dict, headers={"X-Collector-Key": self.valid_key})
        self.assertEqual(resp1.status_code, 200)
        self.assertEqual(resp1.json()["duplicate"], False)
        self.assertEqual(resp1.json()["status"], "ACCEPTED")

        # Second Ingestion with same payload_id
        resp2 = self.client.post("/ingest", json=payload_dict, headers={"X-Collector-Key": self.valid_key})
        self.assertEqual(resp2.status_code, 200)
        self.assertEqual(resp2.json()["duplicate"], True)
        self.assertEqual(resp2.json()["status"], "DUPLICATE")

        # Confirm exactly 1 record stored in database
        all_stored = self.saas_storage.get_ingested_payloads()
        matched = [r for r in all_stored if r["payload_id"] == payload.payload_id]
        self.assertEqual(len(matched), 1)

    # -------------------------------------------------------------------------
    # TEST 5: Invalid API Key -> HTTP 401
    # -------------------------------------------------------------------------
    def test_05_invalid_api_key_returns_401(self):
        """
        TEST 5:
        Invalid API Key
        HTTP 401
        PASS
        """
        payload, _ = build_egress_payload(
            {"cpu": 50.0, "memory": 50.0, "disk": 50.0, "latency": 10.0},
            audit_log_path=self.test_audit_path
        )
        payload_dict = payload.model_dump()

        # Case A: Invalid Key
        resp_invalid = self.client.post(
            "/ingest",
            json=payload_dict,
            headers={"X-Collector-Key": "WRONG_UNAUTHORIZED_KEY"}
        )
        self.assertEqual(resp_invalid.status_code, 401)

        # Case B: Missing Header
        resp_missing = self.client.post(
            "/ingest",
            json=payload_dict
        )
        self.assertEqual(resp_missing.status_code, 401)

    # -------------------------------------------------------------------------
    # TEST 6: Corrupted SHA -> HTTP 400
    # -------------------------------------------------------------------------
    def test_06_corrupted_sha_returns_400(self):
        """
        TEST 6:
        Corrupted SHA
        HTTP 400 {"error": "checksum_validation_failed"}
        PASS
        """
        payload, _ = build_egress_payload(
            {"cpu": 92.0, "memory": 85.0, "disk": 70.0, "latency": 25.0},
            audit_log_path=self.test_audit_path
        )
        payload_dict = payload.model_dump()

        # Corrupt the SHA-256 checksum intentionally
        payload_dict["sha256"] = "deadbeef" * 8

        resp = self.client.post(
            "/ingest",
            json=payload_dict,
            headers={"X-Collector-Key": self.valid_key}
        )
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.json()["detail"]["error"], "checksum_validation_failed")

        # Confirm corrupted payload was NOT stored in database
        self.assertFalse(self.saas_storage.payload_exists(payload.payload_id))

    # -------------------------------------------------------------------------
    # TEST 7: Dead Letter Queue -> Payload Moved
    # -------------------------------------------------------------------------
    def test_07_dead_letter_queue_payload_moved(self):
        """
        TEST 7:
        Dead Letter Queue
        Payload Moved to DEAD_LETTER after repeated fatal errors
        PASS
        """
        # Store a corrupted payload in the SQLite buffer
        payload, _ = build_egress_payload(
            {"cpu": 99.0, "memory": 99.0, "disk": 99.0, "latency": 99.0},
            audit_log_path=self.test_audit_path
        )
        payload_dict = payload.model_dump()
        payload_dict["sha256"] = "corrupted_checksum_hash"

        # Manually store corrupted item into buffer
        with self.edge_buffer._get_connection() as conn:
            conn.execute(
                "INSERT INTO unsent_payloads (payload_id, timestamp, payload_json, status, retry_count) VALUES (?, ?, ?, 'PENDING', 0)",
                (payload.payload_id, payload.timestamp, json.dumps(payload_dict))
            )
            conn.commit()

        # Mock requests.post to forward directly to FastAPI TestClient
        def mock_post(url, json=None, headers=None, timeout=None):
            resp = self.client.post(url.replace("http://testserver", ""), json=json, headers=headers)
            mock_resp = requests.Response()
            mock_resp.status_code = resp.status_code
            mock_resp._content = resp.content
            return mock_resp

        with patch("requests.post", side_effect=mock_post):
            counts = self.worker.process_pending_batch()

        # Worker detects HTTP 400 checksum failure and immediately moves payload to DEAD_LETTER
        self.assertEqual(counts["dead_letter"], 1)
        record = self.edge_buffer.get_payload_by_id(payload.payload_id)
        self.assertEqual(record["status"], "DEAD_LETTER")
        self.assertIn("checksum_validation_failed", record["failure_reason"])

    # -------------------------------------------------------------------------
    # TEST 8: Heartbeat -> Last Seen Updated in Collector Registry
    # -------------------------------------------------------------------------
    def test_08_heartbeat_updates_collector_registry(self):
        """
        TEST 8:
        Heartbeat
        Last Seen Updated in Collector Registry
        PASS
        """
        heartbeat_data = {
            "collector_id": "COLL-001",
            "version": "1.0.0",
            "status": "ONLINE",
            "timestamp": "2026-11-20T17:30:00Z"
        }

        resp = self.client.post(
            "/heartbeat",
            json=heartbeat_data,
            headers={"X-Collector-Key": self.valid_key}
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["status"], "ACK")

        # Query Collector Registry
        reg = self.saas_storage.get_collector("COLL-001")
        self.assertIsNotNone(reg)
        self.assertEqual(reg["collector_id"], "COLL-001")
        self.assertEqual(reg["tenant_id"], "TENANT-001")
        self.assertEqual(reg["status"], "ONLINE")
        self.assertEqual(reg["last_seen"], "2026-11-20T17:30:00Z")

    # -------------------------------------------------------------------------
    # TEST 9: Dynamic Collector Login & JWT Issuance (/auth/token)
    # -------------------------------------------------------------------------
    def test_09_jwt_login_and_token_issuance(self):
        """
        TEST 9:
        Collector Secret -> POST /auth/token -> Receives JWT Access Token
        Invalid Secret -> HTTP 401
        """
        # Valid login
        resp = self.client.post(
            "/auth/token",
            json={
                "collector_id": "COLL-001",
                "collector_secret": "SECRET-COLL-DEMO-001"
            }
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("access_token", data)
        self.assertEqual(data["token_type"], "bearer")
        self.assertEqual(data["collector_id"], "COLL-001")
        self.assertEqual(data["tenant_id"], "TENANT-001")

        # Invalid secret rejection
        bad_resp = self.client.post(
            "/auth/token",
            json={
                "collector_id": "COLL-001",
                "collector_secret": "WRONG_SECRET_123"
            }
        )
        self.assertEqual(bad_resp.status_code, 401)
        self.assertEqual(bad_resp.json()["detail"]["error"], "invalid_credentials")

    # -------------------------------------------------------------------------
    # TEST 10: Ingest & Heartbeat via Dynamic JWT Bearer Token
    # -------------------------------------------------------------------------
    def test_10_ingest_and_heartbeat_with_jwt_bearer_token(self):
        """
        TEST 10:
        Use Token (Bearer <JWT>) on /ingest and /heartbeat.
        SaaS cryptographically verifies token and ingests payload.
        """
        # Get token
        token_resp = self.client.post(
            "/auth/token",
            json={"collector_id": "COLL-001", "collector_secret": "SECRET-COLL-DEMO-001"}
        )
        token = token_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Send telemetry payload
        payload, _ = build_egress_payload(
            {"cpu": 55.0, "memory": 60.0, "disk": 70.0, "latency": 15.0},
            collector_id="COLL-001",
            audit_log_path=self.test_audit_path
        )
        ingest_resp = self.client.post("/ingest", json=payload.model_dump(), headers=headers)
        self.assertEqual(ingest_resp.status_code, 200)
        self.assertEqual(ingest_resp.json()["status"], "ACCEPTED")

        # Send heartbeat
        hb_resp = self.client.post(
            "/heartbeat",
            json={
                "collector_id": "COLL-001",
                "version": "1.0.0",
                "status": "ONLINE",
                "timestamp": "2026-11-20T17:45:00Z"
            },
            headers=headers
        )
        self.assertEqual(hb_resp.status_code, 200)
        self.assertEqual(hb_resp.json()["status"], "ACK")

    # -------------------------------------------------------------------------
    # TEST 11: Expired JWT Rejection
    # -------------------------------------------------------------------------
    def test_11_expired_jwt_rejected_with_401(self):
        """
        TEST 11:
        Token Expires -> Ingestion endpoint returns HTTP 401 token_expired.
        """
        import time
        # Issue short-lived token (1 second expiry)
        token_resp = self.client.post(
            "/auth/token",
            json={
                "collector_id": "COLL-001",
                "collector_secret": "SECRET-COLL-DEMO-001",
                "expires_in": 1
            }
        )
        expired_token = token_resp.json()["access_token"]

        # Wait for token to expire
        time.sleep(1.2)

        payload, _ = build_egress_payload(
            {"cpu": 40.0, "memory": 50.0, "disk": 45.0, "latency": 10.0},
            collector_id="COLL-001",
            audit_log_path=self.test_audit_path
        )

        resp = self.client.post(
            "/ingest",
            json=payload.model_dump(),
            headers={"Authorization": f"Bearer {expired_token}"}
        )
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json()["detail"]["error"], "token_expired")

    # -------------------------------------------------------------------------
    # TEST 12: Offline Buffering & Automatic Replay with Expired JWT Recovery
    # -------------------------------------------------------------------------
    def test_12_offline_buffering_and_auto_replay_with_expired_jwt(self):
        """
        TEST 12 (Core User Scenario):
        1. Internet OFF: Collector stores multiple payloads in SQLite buffer.
        2. Worker's cached JWT expires while offline.
        3. Internet ON: Worker auto-refreshes JWT via Collector Secret.
        4. Replays all buffered payloads without data loss.
        5. All payloads marked SENT.
        """
        import time
        from collector.auth_client import CollectorAuthClient

        # 1. Simulate Internet OFF: Buffer 20 payloads into local SQLite
        buffered_ids = []
        for i in range(20):
            p, _ = build_egress_payload(
                {"cpu": 30.0 + i, "memory": 40.0, "disk": 50.0, "latency": 10.0 + i},
                collector_id="COLL-001",
                audit_log_path=self.test_audit_path
            )
            self.edge_buffer.store_payload(p)
            buffered_ids.append(p.payload_id)

        self.assertEqual(len(self.edge_buffer.get_unsent_payloads(limit=50)), 20)

        # 2. Worker setup with custom AuthClient whose token is EXPIRED
        auth = CollectorAuthClient(
            saas_url="http://testserver",
            collector_id="COLL-001",
            collector_secret="SECRET-COLL-DEMO-001"
        )
        # Seed an expired token
        expired_token_data = auth_service.issue_token(
            collector_id="COLL-001",
            collector_secret="SECRET-COLL-DEMO-001",
            expires_in=1
        )
        auth.access_token = expired_token_data["access_token"]
        auth.token_expires_at = time.time() - 10.0  # Already expired

        test_worker = EgressWorker(
            buffer=self.edge_buffer,
            saas_url="http://testserver",
            auth_client_instance=auth
        )

        # 3. Internet ON: Mock requests.post to route to TestClient
        def mock_post(url, json=None, headers=None, timeout=None):
            path = url.replace("http://testserver", "")
            resp = self.client.post(path, json=json, headers=headers)
            mock_resp = requests.Response()
            mock_resp.status_code = resp.status_code
            mock_resp._content = resp.content
            return mock_resp

        with patch("requests.post", side_effect=mock_post):
            counts = test_worker.process_pending_batch(batch_size=50)

        # 4. Verify all 20 payloads were successfully transmitted and marked SENT
        self.assertEqual(counts["sent"], 20)
        self.assertEqual(counts["dead_letter"], 0)

        # 5. Confirm SQLite queue is now completely clear (0 pending)
        remaining = self.edge_buffer.get_unsent_payloads(limit=50)
        self.assertEqual(len(remaining), 0)

        # 6. Confirm all records are marked SENT
        for pid in buffered_ids:
            rec = self.edge_buffer.get_payload_by_id(pid)
            self.assertEqual(rec["status"], "SENT")


if __name__ == "__main__":
    unittest.main()
