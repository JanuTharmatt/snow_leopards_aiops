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
from saas_service.routes.dashboard import (
    get_dashboard_overview, check_tenant_access, download_collector_binary,
    get_fleet_overview, get_fleet_collectors, get_fleet_collector_detail
)
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

    def test_07_multi_collector_fleet_monitoring(self):
        """
        Step 7: Enterprise Fleet Monitoring (Multi-Collector per Tenant Architecture).
        Verifies:
        1. Multiple collectors (Laptop A, Laptop B, Laptop C, Server D) provision under one Tenant.
        2. Telemetry ingested independently for each collector.
        3. Fleet overview aggregates Company name, online/offline count, and fleet health.
        4. Collector grid displays individual device status, CPU %, RAM %, Latency, and Health grading.
        5. Collector detail endpoint provides historical trends and incident/threat isolation.
        """
        import json
        fleet_email = f"admin_fleet_{uuid.uuid4().hex[:6]}@abccompany.com"
        fleet_pwd = "CompanySecure2026!"
        fleet_org = "ABC Company"

        # 1. Provision organization tenant
        reg = register_new_tenant(RegisterTenantRequest(
            email=fleet_email,
            password=fleet_pwd,
            tenant_name=fleet_org
        ))
        tenant_id = reg["tenant_id"]
        token = reg["jwt"]

        # 2. Register Collector A (Laptop A)
        col_a = register_collector_endpoint(RegisterCollectorRequest(
            hostname="LAPTOP-A",
            device_name="Laptop A",
            tenant_id=tenant_id,
            email=fleet_email,
            password=fleet_pwd
        ))
        cid_a = col_a["collector_id"]

        # 3. Register Collector B (Laptop B)
        col_b = register_collector_endpoint(RegisterCollectorRequest(
            hostname="LAPTOP-B",
            device_name="Laptop B",
            tenant_id=tenant_id,
            email=fleet_email,
            password=fleet_pwd
        ))
        cid_b = col_b["collector_id"]

        # 4. Register Collector C (Laptop C)
        col_c = register_collector_endpoint(RegisterCollectorRequest(
            hostname="LAPTOP-C",
            device_name="Laptop C",
            tenant_id=tenant_id,
            email=fleet_email,
            password=fleet_pwd
        ))
        cid_c = col_c["collector_id"]

        # Ingest telemetry for Laptop A (Healthy: CPU 40%, RAM 60%, Latency 22ms)
        now_a = datetime.now(timezone.utc).isoformat()
        storage_service.store_payload(
            payload_dict={
                "payload_id": f"pay_{uuid.uuid4().hex[:8]}",
                "collector_id": cid_a,
                "event_time_utc": now_a,
                "data_type": "system_metrics",
                "cpu": 40.0,
                "memory": 60.0,
                "latency": 22.0
            },
            tenant_id=tenant_id,
            region="us-east-1"
        )

        # Ingest telemetry for Laptop B (Fair: CPU 80%, RAM 70%, Latency 45ms)
        now_b = datetime.now(timezone.utc).isoformat()
        storage_service.store_payload(
            payload_dict={
                "payload_id": f"pay_{uuid.uuid4().hex[:8]}",
                "collector_id": cid_b,
                "event_time_utc": now_b,
                "data_type": "system_metrics",
                "cpu": 80.0,
                "memory": 70.0,
                "latency": 45.0
            },
            tenant_id=tenant_id,
            region="us-east-1"
        )

        # Ingest telemetry for Laptop C (Healthy: CPU 30%, RAM 50%, Latency 15ms)
        now_c = datetime.now(timezone.utc).isoformat()
        storage_service.store_payload(
            payload_dict={
                "payload_id": f"pay_{uuid.uuid4().hex[:8]}",
                "collector_id": cid_c,
                "event_time_utc": now_c,
                "data_type": "system_metrics",
                "cpu": 30.0,
                "memory": 50.0,
                "latency": 15.0
            },
            tenant_id=tenant_id,
            region="us-east-1"
        )

        # 5. Query Fleet Overview
        overview = get_fleet_overview(tenant_id=tenant_id, authorization=f"Bearer {token}")
        self.assertEqual(overview["tenant_id"], tenant_id)
        self.assertEqual(overview["tenant_name"], "ABC Company")
        # 1 default node created during tenant registration + 3 collectors = 4 collectors
        self.assertGreaterEqual(overview["total_collectors"], 3)
        self.assertGreaterEqual(overview["online_count"], 3)
        self.assertIn(overview["fleet_health"], ["Healthy", "Degraded"])

        # 6. Query Fleet Collectors List
        collectors = get_fleet_collectors(tenant_id=tenant_id, authorization=f"Bearer {token}")
        c_map = {c["collector_id"]: c for c in collectors}
        self.assertIn(cid_a, c_map)
        self.assertIn(cid_b, c_map)
        self.assertIn(cid_c, c_map)

        self.assertEqual(c_map[cid_a]["device_name"], "Laptop A")
        self.assertEqual(c_map[cid_a]["cpu"], 40.0)
        self.assertEqual(c_map[cid_a]["memory"], 60.0)
        self.assertEqual(c_map[cid_a]["health"], "Healthy")

        self.assertEqual(c_map[cid_b]["device_name"], "Laptop B")
        self.assertEqual(c_map[cid_b]["cpu"], 80.0)
        self.assertEqual(c_map[cid_b]["health"], "Fair")

        self.assertEqual(c_map[cid_c]["device_name"], "Laptop C")
        self.assertEqual(c_map[cid_c]["cpu"], 30.0)
        self.assertEqual(c_map[cid_c]["health"], "Healthy")

        # 7. Query Collector Detail Drilldown for Laptop B
        detail_b = get_fleet_collector_detail(collector_id=cid_b, tenant_id=tenant_id, authorization=f"Bearer {token}")
        self.assertEqual(detail_b["collector"]["collector_id"], cid_b)
        self.assertEqual(detail_b["collector"]["device_name"], "Laptop B")
        self.assertEqual(detail_b["collector"]["latest_cpu"], 80.0)
        self.assertEqual(detail_b["collector"]["latest_memory"], 70.0)
        self.assertGreaterEqual(len(detail_b["telemetry"]), 1)


if __name__ == "__main__":
    unittest.main()
