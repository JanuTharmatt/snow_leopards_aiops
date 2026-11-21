"""
Phase 5.1 Test Suite: Executive Reporting Service.
Verifies:
1. Weekly Report generation, schema fields, and SQLite persistence (weekly_reports).
2. Monthly Report generation, trend analysis, availability score, and SQLite persistence (monthly_reports).
3. Executive Summary generation with health status and action recommendations.
4. REST APIs:
   - GET /api/v1/reports/weekly
   - GET /api/v1/reports/monthly
   - GET /api/v1/reports/executive
"""

from pathlib import Path
import sys
import unittest

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from tests.client import TestApiClient
from saas_service.services.storage import storage_service
from saas_service.services.reporting_service import reporting_service


class TestExecutiveReportingService(unittest.TestCase):
    """Test suite for Phase 5.1 Executive Reporting Service & APIs."""

    def setUp(self):
        self.client = TestApiClient()
        self.tenant_id = "TENANT-001"

    def test_weekly_report_generation_and_fields(self):
        """Verifies Weekly Report contains all mandatory fields."""
        res = reporting_service.generate_weekly_report(tenant_id=self.tenant_id)
        self.assertEqual(res["tenant_id"], self.tenant_id)
        self.assertIn("generated_at", res)
        report = res["report"]
        
        # Verify required weekly report fields
        expected_fields = [
            "average_cpu",
            "average_memory",
            "average_latency",
            "average_packet_loss",
            "total_alerts",
            "total_incidents",
            "top_rca_category",
            "fleet_health_percentage"
        ]
        for field in expected_fields:
            self.assertIn(field, report, f"Missing required weekly report field: {field}")
            self.assertIsNotNone(report[field])

        # Verify SQLite table persistence
        with storage_service._get_connection() as conn:
            cursor = conn.execute(
                "SELECT report_id, report_type FROM weekly_reports WHERE tenant_id = ? ORDER BY generated_at DESC LIMIT 1;",
                (self.tenant_id,)
            )
            row = cursor.fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row["report_type"], "WEEKLY")

    def test_monthly_report_generation_and_fields(self):
        """Verifies Monthly Report contains all mandatory fields and trends."""
        res = reporting_service.generate_monthly_report(tenant_id=self.tenant_id)
        self.assertEqual(res["tenant_id"], self.tenant_id)
        self.assertIn("generated_at", res)
        report = res["report"]

        # Verify required monthly report fields
        expected_fields = [
            "resource_utilization_trends",
            "incident_growth_pct",
            "threat_growth_pct",
            "availability_score",
            "capacity_risk_level"
        ]
        for field in expected_fields:
            self.assertIn(field, report, f"Missing required monthly report field: {field}")

        trends = report["resource_utilization_trends"]
        self.assertIn("cpu", trends)
        self.assertIn("memory", trends)
        self.assertIn("disk", trends)

        # Verify SQLite table persistence
        with storage_service._get_connection() as conn:
            cursor = conn.execute(
                "SELECT report_id, report_type FROM monthly_reports WHERE tenant_id = ? ORDER BY generated_at DESC LIMIT 1;",
                (self.tenant_id,)
            )
            row = cursor.fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row["report_type"], "MONTHLY")

    def test_executive_summary_fields(self):
        """Verifies Executive Summary contains all high-level synthesis fields."""
        res = reporting_service.generate_executive_summary(tenant_id=self.tenant_id)
        self.assertEqual(res["tenant_id"], self.tenant_id)
        report = res["report"]

        expected_fields = [
            "overall_health",
            "most_common_root_cause",
            "critical_incidents",
            "top_risk",
            "recommended_action"
        ]
        for field in expected_fields:
            self.assertIn(field, report, f"Missing required executive summary field: {field}")
            self.assertTrue(len(str(report[field])) > 0)

    def test_reporting_rest_apis(self):
        """Verifies REST endpoints for Weekly, Monthly, and Executive reports."""
        # 1. Weekly API
        resp_wk = self.client.get(f"/api/v1/reports/weekly?tenant_id={self.tenant_id}")
        self.assertEqual(resp_wk.status_code, 200)
        data_wk = resp_wk.json()
        self.assertEqual(data_wk["tenant_id"], self.tenant_id)
        self.assertIn("average_cpu", data_wk["report"])

        # 2. Monthly API
        resp_mo = self.client.get(f"/api/v1/reports/monthly?tenant_id={self.tenant_id}")
        self.assertEqual(resp_mo.status_code, 200)
        data_mo = resp_mo.json()
        self.assertEqual(data_mo["tenant_id"], self.tenant_id)
        self.assertIn("availability_score", data_mo["report"])

        # 3. Executive API
        resp_ex = self.client.get(f"/api/v1/reports/executive?tenant_id={self.tenant_id}")
        self.assertEqual(resp_ex.status_code, 200)
        data_ex = resp_ex.json()
        self.assertEqual(data_ex["tenant_id"], self.tenant_id)
        self.assertIn("overall_health", data_ex["report"])


if __name__ == "__main__":
    unittest.main()
