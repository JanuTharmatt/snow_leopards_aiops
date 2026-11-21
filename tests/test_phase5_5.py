"""
Unit Test Suite for Phase 5.5: Multi-Tenant Onboarding, Tenant Isolation & Demo Laboratory.
Uses in-memory synchronous routing for deterministic, deadlock-free execution on Windows.
"""

import json
import unittest
from fastapi import HTTPException

from saas_service.services.tenant_service import tenant_service
from saas_service.services.auth import auth_service
from saas_service.services.firestore_storage import firestore_storage
from saas_service.routes.auth import (
    register_new_tenant,
    login_tenant_user,
    register_collector_endpoint,
    reset_password_endpoint,
    RegisterTenantRequest,
    LoginTenantRequest,
    RegisterCollectorRequest,
    ResetPasswordRequest
)
from saas_service.routes.dashboard import check_tenant_access
from saas_service.routes.phase5 import check_phase5_tenant_access
from saas_service.routes.demo_lab import generate_demo_incident, IncidentGenerateRequest
from collector.onboarding import is_onboarded, load_collector_config, save_collector_config


class TestPhase55MultiTenantOnboarding(unittest.TestCase):
    """Rigorous verification of Phase 5.5 deliverables."""

    def test_01_register_new_tenant(self):
        """Test automatic tenant provisioning and user account creation."""
        email = f"judge_test_{tenant_service.generate_tenant_id()}@snowleopards.ai"
        req = RegisterTenantRequest(
            tenant_name="Judge Evaluators Corp",
            email=email,
            password="EvaluationPassword123!"
        )
        data = register_new_tenant(req)
        self.assertEqual(data["status"], "success")
        self.assertTrue(data["tenant_id"].startswith("tenant_"))
        self.assertTrue(data["collector_id"].startswith("COL-"))
        self.assertTrue(len(data["access_token"]) > 20)

    def test_02_login_tenant_user(self):
        """Test authenticating a tenant user with email and password."""
        email = f"judge_login_{tenant_service.generate_tenant_id()}@snowleopards.ai"
        reg_req = RegisterTenantRequest(
            tenant_name="Acme High-Performance Fleet",
            email=email,
            password="StrongSecret2026!"
        )
        reg_data = register_new_tenant(reg_req)
        created_tenant_id = reg_data["tenant_id"]

        # Login
        login_req = LoginTenantRequest(
            email=email,
            password="StrongSecret2026!"
        )
        data = login_tenant_user(login_req)
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["tenant_id"], created_tenant_id)
        self.assertTrue(len(data["access_token"]) > 20)

    def test_03_register_collector_endpoint(self):
        """Test collector self-registration workflow from collector.exe."""
        email = f"judge_node_{tenant_service.generate_tenant_id()}@snowleopards.ai"
        req = RegisterCollectorRequest(
            hostname="JUDGE-LAPTOP-01",
            tenant_name="Judge Node Fleet",
            email=email,
            password="NodePassword999!"
        )
        data = register_collector_endpoint(req)
        self.assertTrue(data["collector_id"].startswith("COL-"))
        self.assertTrue(data["tenant_id"].startswith("tenant_"))
        self.assertTrue(data["collector_secret"].startswith("SECRET-"))
        self.assertTrue(len(data["access_token"]) > 20)

    def test_04_reset_password_endpoint(self):
        """Test password reset instructions dispatch."""
        req = ResetPasswordRequest(email="evaluator@demo.com")
        res = reset_password_endpoint(req)
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["email"], "evaluator@demo.com")

    def test_05_strict_tenant_isolation_enforcement(self):
        """
        CRITICAL TEST: Multi-Tenant Isolation Enforcement.
        If Tenant A presents their token and attempts to access Tenant B's data,
        the request MUST be rejected with HTTP 403 Forbidden.
        """
        # 1. Register Tenant A
        res_a = tenant_service.register_tenant(
            email=f"tenant_a_{tenant_service.generate_tenant_id()}@demo.com",
            password="PasswordAAA!",
            tenant_name="Tenant Alpha Corp"
        )
        tenant_a_id = res_a["tenant_id"]
        token_a = res_a["access_token"]

        # 2. Register Tenant B
        res_b = tenant_service.register_tenant(
            email=f"tenant_b_{tenant_service.generate_tenant_id()}@demo.com",
            password="PasswordBBB!",
            tenant_name="Tenant Beta Corp"
        )
        tenant_b_id = res_b["tenant_id"]

        # 3. Accessing own data with own token -> succeeds
        verified_tenant = check_tenant_access(
            requested_tenant=tenant_a_id,
            authorization=f"Bearer {token_a}"
        )
        self.assertEqual(verified_tenant, tenant_a_id)

        # 4. Accessing foreign tenant with Tenant A token -> MUST RAISE HTTP 403
        with self.assertRaises(HTTPException) as ctx:
            check_tenant_access(
                requested_tenant=tenant_b_id,
                authorization=f"Bearer {token_a}"
            )
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertIn("Tenant isolation violation", ctx.exception.detail)

        # 5. Check Phase 5 API isolation check
        with self.assertRaises(HTTPException) as ctx5:
            check_phase5_tenant_access(
                requested_tenant=tenant_b_id,
                authorization=f"Bearer {token_a}"
            )
        self.assertEqual(ctx5.exception.status_code, 403)

    def test_06_demo_laboratory_incident_generators(self):
        """Test triggering all 5 live incident patterns in Demo Laboratory."""
        incident_types = ["cpu_spike", "memory_leak", "brute_force", "ddos_flood", "slowloris"]
        for inc_type in incident_types:
            req = IncidentGenerateRequest(
                incident_type=inc_type,
                tenant_id="TENANT-001"
            )
            data = generate_demo_incident(req)
            self.assertTrue(data["success"])
            self.assertEqual(data["incident_type"], inc_type)
            self.assertIn("diagnosis", data)
            self.assertIn("root_cause", data)
            self.assertTrue(len(data["runbook"]) > 0)

    def test_07_firestore_storage_graceful_fallback(self):
        """Test that firestore storage service gracefully handles absence of GCP keys without crashing."""
        self.assertFalse(firestore_storage.is_cloud_active())
        res = firestore_storage.save_tenant("tenant_test_123", "Test Org", "usr_123")
        # Returns False when running offline in SQLite mode, without raising any exception
        self.assertFalse(res)


if __name__ == "__main__":
    unittest.main()
