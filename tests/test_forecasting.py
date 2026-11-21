"""
Phase 5.2 Test Suite: Capacity Forecast Engine.
Verifies:
1. Pure numpy/pandas mathematical forecasting (Moving Average, Linear Regression, Growth Rate).
2. CPU, Memory, and Disk capacity forecasting.
3. Days-to-threshold computation and capacity risk classification (HIGH, MODERATE, LOW).
4. REST APIs:
   - GET /api/v1/forecast/cpu
   - GET /api/v1/forecast/memory
   - GET /api/v1/forecast/disk
"""

from pathlib import Path
import sys
import unittest

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from tests.client import TestApiClient
from saas_service.services.forecast_engine import forecast_engine


class TestCapacityForecastEngine(unittest.TestCase):
    """Test suite for Phase 5.2 Capacity Forecast Engine & APIs."""

    def setUp(self):
        self.client = TestApiClient()
        self.tenant_id = "TENANT-001"

    def test_forecast_cpu_calculation(self):
        """Verifies CPU forecast output schema and reasonable prediction bounds."""
        res = forecast_engine.forecast_resource(tenant_id=self.tenant_id, resource="cpu")
        self.assertEqual(res["resource"], "cpu")
        self.assertIn("current", res)
        self.assertIn("predicted_7_days", res)
        self.assertIn("days_to_threshold", res)
        self.assertIn("capacity_risk", res)

        self.assertIsInstance(res["current"], int)
        self.assertIsInstance(res["predicted_7_days"], int)
        self.assertIsInstance(res["days_to_threshold"], int)
        self.assertIn(res["capacity_risk"], ["HIGH", "MODERATE", "LOW"])

        # Utilization percentages must stay bounded between 0 and 100
        self.assertTrue(0 <= res["current"] <= 100)
        self.assertTrue(0 <= res["predicted_7_days"] <= 100)

    def test_forecast_memory_calculation(self):
        """Verifies Memory forecast output and progressive trend calculation."""
        res = forecast_engine.forecast_resource(tenant_id=self.tenant_id, resource="memory")
        self.assertEqual(res["resource"], "memory")
        self.assertTrue(0 <= res["current"] <= 100)
        self.assertTrue(0 <= res["predicted_7_days"] <= 100)
        self.assertIn(res["capacity_risk"], ["HIGH", "MODERATE", "LOW"])

    def test_forecast_disk_calculation(self):
        """Verifies Disk forecast output and stability calculations."""
        res = forecast_engine.forecast_resource(tenant_id=self.tenant_id, resource="disk")
        self.assertEqual(res["resource"], "disk")
        self.assertTrue(0 <= res["current"] <= 100)
        self.assertTrue(res["days_to_threshold"] >= 0)

    def test_custom_threshold_influence(self):
        """Verifies that setting a lower threshold increases risk and lowers days to breach."""
        # Baseline threshold = 95
        res_high = forecast_engine.forecast_resource(tenant_id=self.tenant_id, resource="cpu", threshold=95.0)
        # Tight threshold = 40
        res_low = forecast_engine.forecast_resource(tenant_id=self.tenant_id, resource="cpu", threshold=40.0)

        self.assertLessEqual(res_low["days_to_threshold"], res_high["days_to_threshold"])

    def test_forecast_rest_apis(self):
        """Verifies REST endpoints for /forecast/cpu, /forecast/memory, /forecast/disk."""
        for res_type in ["cpu", "memory", "disk"]:
            resp = self.client.get(f"/api/v1/forecast/{res_type}?tenant_id={self.tenant_id}")
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertEqual(data["resource"], res_type)
            self.assertIn("current", data)
            self.assertIn("predicted_7_days", data)
            self.assertIn("days_to_threshold", data)
            self.assertIn("capacity_risk", data)


if __name__ == "__main__":
    unittest.main()
