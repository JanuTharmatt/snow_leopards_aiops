"""
Phase 5.3 Test Suite: Proactive Risk Engine.
Verifies:
1. Impending system failure prediction for:
   - MEMORY_EXHAUSTION (OOM)
   - DISK_EXHAUSTION
   - LATENCY_DEGRADATION
   - AUTH_ATTACK_ESCALATION
2. Probability calculations (0 to 100%) and estimated hours to failure.
3. Ranking and top_risk determination.
4. REST API:
   - GET /api/v1/risk-summary
"""

from pathlib import Path
import sys
import unittest

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from tests.client import TestApiClient
from saas_service.services.risk_engine import risk_engine


class TestProactiveRiskEngine(unittest.TestCase):
    """Test suite for Phase 5.3 Proactive Risk Engine & APIs."""

    def setUp(self):
        self.client = TestApiClient()
        self.tenant_id = "TENANT-001"

    def test_risk_evaluation_types_and_bounds(self):
        """Verifies all four failure risk categories are assessed with valid probabilities."""
        summary = risk_engine.evaluate_risks(tenant_id=self.tenant_id)
        self.assertEqual(summary["tenant_id"], self.tenant_id)
        self.assertIn("top_risk", summary)
        self.assertIn("risks", summary)

        risks = summary["risks"]
        risk_types = [r["risk"] for r in risks]
        
        expected_types = [
            "MEMORY_EXHAUSTION",
            "DISK_EXHAUSTION",
            "LATENCY_DEGRADATION",
            "AUTH_ATTACK_ESCALATION"
        ]
        for et in expected_types:
            self.assertIn(et, risk_types, f"Missing risk evaluation for: {et}")

        for r in risks:
            self.assertTrue(0 <= r["probability"] <= 100, f"Probability out of bounds: {r['probability']}")
            self.assertGreater(r["estimated_hours"], 0, f"Estimated hours must be positive: {r['estimated_hours']}")
            self.assertTrue(len(r.get("description", "")) > 0)

    def test_top_risk_selection(self):
        """Verifies top_risk reflects highest probability risk."""
        summary = risk_engine.evaluate_risks(tenant_id=self.tenant_id)
        top = summary["top_risk"]
        for r in summary["risks"]:
            self.assertLessEqual(r["probability"], top["probability"])

    def test_risk_summary_rest_api(self):
        """Verifies GET /api/v1/risk-summary returns matching format."""
        resp = self.client.get(f"/api/v1/risk-summary?tenant_id={self.tenant_id}")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["tenant_id"], self.tenant_id)
        self.assertIn("risk", data)
        self.assertIn("probability", data)
        self.assertIn("estimated_hours", data)
        self.assertIn("top_risk", data)
        self.assertIn("risks", data)


if __name__ == "__main__":
    unittest.main()
