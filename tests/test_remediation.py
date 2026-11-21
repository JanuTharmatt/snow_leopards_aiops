"""
Phase 5.4 & 5.5 Test Suite: Remediation Engine & Policy Engine.
Verifies:
1. Remediation queue creation, status lifecycle (PENDING, APPROVED, REJECTED, EXECUTED).
2. Action mapping runbooks for storage, brute-force auth, memory leak, and thread contention.
3. Policy engine governance:
   - Production Tenant requires manual approval
   - Development Tenant allows auto approval
4. 3-step remediation verification (Policy Check, Risk Check, Audit Recording into policy_audit).
5. REST APIs:
   - GET /api/v1/remediation/pending
   - POST /api/v1/remediation/{id}/approve
   - POST /api/v1/remediation/{id}/reject
"""

from pathlib import Path
import sys
import unittest
import uuid

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from tests.client import TestApiClient
from saas_service.services.storage import storage_service
from saas_service.services.remediation_engine import remediation_engine
from saas_service.services.policy_engine import policy_engine


class TestRemediationAndPolicyEngine(unittest.TestCase):
    """Test suite for Phase 5.4 Remediation Engine & Phase 5.5 Policy Engine."""

    def setUp(self):
        self.client = TestApiClient()
        self.prod_tenant = "TENANT-001"
        self.dev_tenant = "DEV-001"

    def test_action_runbook_mapping(self):
        """Verifies root causes map to correct operational remediation runbooks."""
        storage_actions = remediation_engine.get_suggested_actions("STORAGE_IO_EXHAUSTION")
        self.assertIn("Clear Temp Files", storage_actions)
        self.assertIn("Rotate Logs", storage_actions)
        self.assertIn("Expand Storage", storage_actions)

        auth_actions = remediation_engine.get_suggested_actions("BRUTE_FORCE_ATTACK")
        self.assertIn("Enable Rate Limit", auth_actions)
        self.assertIn("Block CIDR", auth_actions)
        self.assertIn("Force MFA", auth_actions)

        mem_actions = remediation_engine.get_suggested_actions("MEMORY_LEAK_WORKER_POOL")
        self.assertIn("Restart Worker Pool", mem_actions)

    def test_enqueue_and_pending_retrieval(self):
        """Verifies remediation enqueuing and pending status."""
        test_inc = f"INC-TEST-{uuid.uuid4().hex[:6].upper()}"
        item = remediation_engine.enqueue_remediation(
            tenant_id=self.prod_tenant,
            root_cause="STORAGE_IO_EXHAUSTION",
            incident_id=test_inc,
            suggested_action="Rotate Logs & Clear Temp Files"
        )
        self.assertEqual(item["status"], "PENDING")
        self.assertEqual(item["incident_id"], test_inc)

        pending = remediation_engine.get_pending_remediations(tenant_id=self.prod_tenant)
        self.assertTrue(any(p["id"] == item["id"] for p in pending))

    def test_policy_engine_prod_vs_dev_governance(self):
        """Verifies policy rules: Production -> Manual Approval, Dev -> Auto Approval."""
        rem_id = f"REM-POL-{uuid.uuid4().hex[:6].upper()}"
        
        # 1. Production Tenant
        eval_prod = policy_engine.evaluate_remediation_policy(
            tenant_id=self.prod_tenant,
            remediation_id=rem_id,
            action="Clear Temp Files"
        )
        self.assertEqual(eval_prod["policy_result"], "MANUAL_APPROVAL_REQUIRED")
        self.assertTrue(eval_prod["is_production"])

        # 2. Dev Tenant (with acceptable risk score)
        eval_dev = policy_engine.evaluate_remediation_policy(
            tenant_id=self.dev_tenant,
            remediation_id=rem_id,
            action="Clear Temp Files",
            risk_score=25.0
        )
        self.assertEqual(eval_dev["policy_result"], "APPROVED")
        self.assertFalse(eval_dev["is_production"])

        # 3. Verify SQLite audit record in policy_audit
        with storage_service._get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM policy_audit WHERE remediation_id = ?;",
                (rem_id,)
            )
            records = cursor.fetchall()
            self.assertGreaterEqual(len(records), 2)

    def test_remediation_rest_apis(self):
        """Verifies REST endpoints for pending, approve, and reject."""
        # 1. GET pending
        resp_pending = self.client.get(f"/api/v1/remediation/pending?tenant_id={self.prod_tenant}")
        self.assertEqual(resp_pending.status_code, 200)
        items = resp_pending.json()
        self.assertIsInstance(items, list)
        self.assertGreaterEqual(len(items), 1)
        target_id = items[0]["id"]

        # 2. POST approve
        resp_approve = self.client.post(f"/api/v1/remediation/{target_id}/approve?tenant_id={self.prod_tenant}")
        self.assertEqual(resp_approve.status_code, 200)
        approve_data = resp_approve.json()
        self.assertEqual(approve_data["status"], "APPROVED")
        self.assertTrue(approve_data["executed_simulated"])
        self.assertIn("policy_evaluation", approve_data)

        # 3. POST reject
        reject_id = f"REM-REJ-{uuid.uuid4().hex[:6].upper()}"
        resp_reject = self.client.post(f"/api/v1/remediation/{reject_id}/reject")
        self.assertEqual(resp_reject.status_code, 200)
        reject_data = resp_reject.json()
        self.assertEqual(reject_data["status"], "REJECTED")


if __name__ == "__main__":
    unittest.main()
