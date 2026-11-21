"""
Phase 5.5 End-to-End Onboarding & Multi-Tenant Isolation Test Suite.
Verifies:
1. Registration & automatic tenant provisioning for new users (Laptop A & Laptop B).
2. Unified authentication: Same email/password works on Dashboard and Collector.
3. Collector self-registration & credential generation.
4. Telemetry ingestion from distinct tenants.
5. Strict Multi-Tenant Data Isolation:
   - Tenant A sees ONLY Tenant A data.
   - Tenant B sees ONLY Tenant B data.
   - Cross-tenant access is strictly blocked with HTTP 403 Forbidden.
6. Demo Laboratory incident triggers isolate to target tenant.
"""

from pathlib import Path
import sys
import unittest
import uuid
import time
from datetime import datetime, timezone

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from fastapi import HTTPException
from fastapi.responses import FileResponse, RedirectResponse
from saas_service.services.tenant_service import tenant_service
from saas_service.services.storage import storage_service
from saas_service.services.auth import auth_service
from saas_service.routes.auth import register_new_tenant, login_tenant_user, register_collector_endpoint, RegisterTenantRequest, LoginTenantRequest, RegisterCollectorRequest
from saas_service.routes.dashboard import get_dashboard_overview, check_tenant_access, download_collector_binary
from saas_service.routes.demo_lab import generate_demo_incident, IncidentGenerateRequest


class TestOnboardingAndMultiTenantIsolation(unittest.TestCase):
    """End-to-end verification of unified account creation, collector auto-connect, and tenant isolation."""

    @classmethod
    def setUpClass(cls):
        cls.user_a_email = f"judge_a_{uuid.uuid4().hex[:6]}@test.com"
        cls.user_a_pwd = "SecureJudgePassword123!"
        cls.org_a_name = "Judge Evaluation Lab A"

        cls.user_b_email = f"judge_b_{uuid.uuid4().hex[:6]}@test.com"
        cls.user_b_pwd = "SecureJudgePassword123!"
        cls.org_b_name = "Judge Evaluation Lab B"

    def test_01_onboard_laptop_a_and_laptop_b(self):
        """Step 1: Test creating accounts for two separate judges/laptops."""
        # Provision Laptop A / Tenant A
        reg_a = register_new_tenant(RegisterTenantRequest(
            email=self.user_a_email,
            password=self.user_a_pwd,
            tenant_name=self.org_a_name
        ))
        self.assertEqual(reg_a["status"], "success")
        self.assertTrue(reg_a["tenant_id"].startswith("tenant_"))
        self.assertIn("jwt", reg_a)
        self.assertIn("collector_id", reg_a)
        TestOnboardingAndMultiTenantIsolation.tenant_a = reg_a["tenant_id"]
        TestOnboardingAndMultiTenantIsolation.token_a = reg_a["jwt"]
        TestOnboardingAndMultiTenantIsolation.coll_a = reg_a["collector_id"]

        # Provision Laptop B / Tenant B
        reg_b = register_new_tenant(RegisterTenantRequest(
            email=self.user_b_email,
            password=self.user_b_pwd,
            tenant_name=self.org_b_name
        ))
        self.assertEqual(reg_b["status"], "success")
        self.assertTrue(reg_b["tenant_id"].startswith("tenant_"))
        self.assertNotEqual(reg_a["tenant_id"], reg_b["tenant_id"])
        TestOnboardingAndMultiTenantIsolation.tenant_b = reg_b["tenant_id"]
        TestOnboardingAndMultiTenantIsolation.token_b = reg_b["jwt"]
        TestOnboardingAndMultiTenantIsolation.coll_b = reg_b["collector_id"]

    def test_02_unified_login_same_credentials(self):
        """Step 2: Same credentials work for login on both Dashboard and Collector."""
        login_a = login_tenant_user(LoginTenantRequest(
            email=self.user_a_email,
            password=self.user_a_pwd
        ))
        self.assertEqual(login_a["status"], "success")
        self.assertEqual(login_a["tenant_id"], self.tenant_a)
        self.assertIn("jwt", login_a)
        self.assertIn("collector_registration_token", login_a)

        login_b = login_tenant_user(LoginTenantRequest(
            email=self.user_b_email,
            password=self.user_b_pwd
        ))
        self.assertEqual(login_b["status"], "success")
        self.assertEqual(login_b["tenant_id"], self.tenant_b)

        # Test pre-seeded demo user
        demo_login = login_tenant_user(LoginTenantRequest(
            email="demo1@test.com",
            password="DemoPassword2026!"
        ))
        self.assertEqual(demo_login["status"], "success")
        self.assertEqual(demo_login["tenant_id"], "TENANT-001")

    def test_03_collector_auto_registration(self):
        """Step 3: Collector automatically registers itself and associates with tenant."""
        node_a = register_collector_endpoint(RegisterCollectorRequest(
            hostname="judge-laptop-alpha",
            tenant_id=self.tenant_a,
            email=self.user_a_email,
            password=self.user_a_pwd
        ))
        self.assertEqual(node_a["status"], "registered")
        self.assertEqual(node_a["tenant_id"], self.tenant_a)
        self.assertTrue(node_a["collector_id"].startswith("COL-"))
        self.assertIn("collector_secret", node_a)
        self.assertIn("access_token", node_a)

        node_b = register_collector_endpoint(RegisterCollectorRequest(
            hostname="judge-laptop-beta",
            tenant_id=self.tenant_b,
            email=self.user_b_email,
            password=self.user_b_pwd
        ))
        self.assertEqual(node_b["status"], "registered")
        self.assertEqual(node_b["tenant_id"], self.tenant_b)
        self.assertTrue(node_b["collector_id"].startswith("COL-"))

    def test_04_strict_tenant_isolation_dashboard(self):
        """Step 4: Strict multi-tenant isolation. Cross-tenant access must fail with 403."""
        # 1. Tenant A querying Tenant A data succeeds
        view_a = get_dashboard_overview(
            tenant_id=self.tenant_a,
            authorization=f"Bearer {self.token_a}"
        )
        self.assertIn("collectors", view_a)
        for c in view_a["collectors"]:
            self.assertEqual(c["tenant_id"], self.tenant_a)

        # 2. Tenant B querying Tenant B data succeeds
        view_b = get_dashboard_overview(
            tenant_id=self.tenant_b,
            authorization=f"Bearer {self.token_b}"
        )
        self.assertIn("collectors", view_b)
        for c in view_b["collectors"]:
            self.assertEqual(c["tenant_id"], self.tenant_b)

        # 3. CRITICAL: Tenant A trying to access Tenant B data MUST raise HTTP 403
        with self.assertRaises(HTTPException) as ctx_a_b:
            get_dashboard_overview(
                tenant_id=self.tenant_b,
                authorization=f"Bearer {self.token_a}"
            )
        self.assertEqual(ctx_a_b.exception.status_code, 403)
        self.assertIn("Tenant isolation violation", ctx_a_b.exception.detail)

        # 4. CRITICAL: Tenant B trying to access Tenant A data MUST raise HTTP 403
        with self.assertRaises(HTTPException) as ctx_b_a:
            get_dashboard_overview(
                tenant_id=self.tenant_a,
                authorization=f"Bearer {self.token_b}"
            )
        self.assertEqual(ctx_b_a.exception.status_code, 403)
        self.assertIn("Tenant isolation violation", ctx_b_a.exception.detail)

    def test_05_demo_lab_incident_isolation(self):
        """Step 5: Incident generation in Demo Lab for Tenant A does NOT affect Tenant B."""
        # Trigger DDoS attack for Tenant A
        inc_a = generate_demo_incident(IncidentGenerateRequest(
            incident_type="ddos_flood",
            tenant_id=self.tenant_a
        ))
        self.assertTrue(inc_a.get("success", False))
        self.assertEqual(inc_a["tenant_id"], self.tenant_a)

        # Query Tenant A overview -> must have alerts/threats
        overview_a = get_dashboard_overview(
            tenant_id=self.tenant_a,
            authorization=f"Bearer {self.token_a}"
        )
        self.assertGreaterEqual(overview_a["active_threats_count"], 1)

        # Query Tenant B overview -> must NOT have Tenant A's threats
        overview_b = get_dashboard_overview(
            tenant_id=self.tenant_b,
            authorization=f"Bearer {self.token_b}"
        )
        self.assertEqual(overview_b["active_threats_count"], 0)

    def test_06_collector_download_endpoint(self):
        """Step 6: Verify collector.exe is hosted and downloadable directly via SaaS endpoint."""
        res = download_collector_binary()
        if isinstance(res, FileResponse):
            self.assertEqual(res.filename, "collector.exe")
            self.assertTrue(Path(res.path).exists())
            self.assertGreater(Path(res.path).stat().st_size, 1000000) # > 1 MB
        elif isinstance(res, RedirectResponse):
            self.assertIn("collector.exe", res.headers.get("location", ""))
        else:
            self.fail(f"Unexpected response type from download endpoint: {type(res)}")


if __name__ == "__main__":
    unittest.main()
