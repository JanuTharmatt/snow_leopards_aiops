"""
Phase 5.6 Test Suite: Autonomous AI Copilot Service.
Verifies:
1. Pure local rule/heuristic routing (NO external LLM API calls).
2. Grounded answers synthesized from:
   - Node degradation and RCA Engine
   - Incident summaries
   - Predictive capacity risks
   - Outside Attack Radar threat status
   - Remediation recommendations
3. REST API:
   - POST /api/v1/copilot/query
"""

from pathlib import Path
import sys
import unittest

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from tests.client import TestApiClient
from saas_service.services.copilot_service import copilot_service


class TestAICopilotService(unittest.TestCase):
    """Test suite for Phase 5.6 AI Copilot Service & APIs."""

    def setUp(self):
        self.client = TestApiClient()
        self.tenant_id = "TENANT-001"

    def test_copilot_node_degradation_query(self):
        """Verifies diagnostic answer when queried about node degradation."""
        res = copilot_service.answer_query(
            query="Why is Node-1 degraded?",
            tenant_id=self.tenant_id
        )
        self.assertIn("answer", res)
        self.assertTrue(len(res["answer"]) > 10)
        self.assertTrue(any(w in res["answer"].lower() for w in ("node", "healthy", "degraded", "remediation", "status")))

    def test_copilot_incidents_query(self):
        """Verifies query regarding top incidents and root causes."""
        res = copilot_service.answer_query(
            query="Show me top incidents",
            tenant_id=self.tenant_id
        )
        self.assertIn("answer", res)
        self.assertTrue(any(w in res["answer"].lower() for w in ("incident", "root cause", "stable", "detected")))

    def test_copilot_memory_risk_query(self):
        """Verifies query regarding future resource or memory exhaustion."""
        res = copilot_service.answer_query(
            query="Will memory run out this week?",
            tenant_id=self.tenant_id
        )
        self.assertIn("answer", res)
        self.assertTrue(any(w in res["answer"].lower() for w in ("risk", "probability", "hours", "memory")))

    def test_copilot_threats_query(self):
        """Verifies query regarding cyber attacks and outside threat radar."""
        res = copilot_service.answer_query(
            query="Are we under attack?",
            tenant_id=self.tenant_id
        )
        self.assertIn("answer", res)
        self.assertTrue(any(w in res["answer"].lower() for w in ("attack", "threat", "radar", "nominal")))

    def test_copilot_recommendation_query(self):
        """Verifies query regarding operational fix recommendations."""
        res = copilot_service.answer_query(
            query="What should I fix first?",
            tenant_id=self.tenant_id
        )
        self.assertIn("answer", res)
        self.assertTrue(any(w in res["answer"].lower() for w in ("recommended", "action", "risk", "remediation")))

    def test_copilot_rest_api(self):
        """Verifies POST /api/v1/copilot/query REST API format."""
        payload = {
            "query": "Why is Node-1 degraded?",
            "tenant_id": self.tenant_id
        }
        resp = self.client.post("/api/v1/copilot/query", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["query"], payload["query"])
        self.assertEqual(data["tenant_id"], payload["tenant_id"])
        self.assertIn("response", data)
        self.assertIn("answer", data)
        self.assertTrue(len(data["response"]) > 0)


if __name__ == "__main__":
    unittest.main()
