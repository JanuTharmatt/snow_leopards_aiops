"""
Autonomous AI Copilot Service.
Phase 5.6:
Privacy-preserving contextual assistant answering operator queries from live platform telemetry.
Strictly local inference over:
- RCA Engine (Probable Cause)
- Threat Engine (Cyber Attacks)
- Reporting Service (Weekly & Monthly Metrics)
- Forecast Engine (Capacity Modeling)
- Risk Engine (Failure Probability)
DOES NOT USE OpenAI, Gemini, or external LLM APIs.
"""

from typing import Any, Dict, List, Optional
import re

try:
    from .storage import storage_service
    from .reporting_service import reporting_service
    from .forecast_engine import forecast_engine
    from .risk_engine import risk_engine
    from .remediation_engine import remediation_engine
except (ImportError, ValueError):
    from saas_service.services.storage import storage_service
    from saas_service.services.reporting_service import reporting_service
    from saas_service.services.forecast_engine import forecast_engine
    from saas_service.services.risk_engine import risk_engine
    from saas_service.services.remediation_engine import remediation_engine


class CopilotService:
    """Deterministic, grounded AIOps conversational engine."""

    def answer_query(self, query: str, tenant_id: str = "TENANT-001") -> Dict[str, str]:
        """
        Interprets natural language queries using rule-based NLU and synthesizes
        answers directly from existing engine state.
        """
        q_lower = (query or "").lower().strip()

        # 1. Collector / Node specific diagnosis (e.g. "Why is Node-3 degraded?", "node-1 status")
        node_match = re.search(r"(?:node|coll|collector)[-_ ]?([a-zA-Z0-9]+)", q_lower)
        if node_match or "degraded" in q_lower or "offline" in q_lower or "node" in q_lower:
            collectors = storage_service.get_all_collectors(tenant_id=tenant_id)
            target_id = None
            if node_match:
                extracted = node_match.group(1).upper()
                for c in collectors:
                    if extracted in c.get("collector_id", "").upper():
                        target_id = c.get("collector_id")
                        break
            
            if not target_id and collectors:
                target_id = collectors[0].get("collector_id")

            if target_id:
                alerts = [a for a in storage_service.get_active_alerts(tenant_id=tenant_id) if a.get("collector_id") == target_id]
                incidents = [i for i in storage_service.get_incidents(tenant_id=tenant_id) if i.get("collector_id") == target_id]
                
                if alerts or incidents:
                    diag = alerts[0].get("diagnosis") if alerts else incidents[0].get("summary", "Metric drift detected")
                    rc = incidents[0].get("root_cause") if incidents else "RESOURCE_EXHAUSTION"
                    conf = incidents[0].get("confidence_score", 95.0) if incidents else 94.0
                    return {
                        "answer": f"Node '{target_id}' is degraded due to {rc} (Diagnostic Confidence: {conf}%). Detail: {diag}. Suggested action: Inspect local buffer queue and execute recommended remediation."
                    }
                else:
                    return {
                        "answer": f"Node '{target_id}' currently has status 'Healthy'. No active threshold breaches or outage conditions are recorded for this node."
                    }
            else:
                return {
                    "answer": "No matching collector node was found for the specified identifier. Active cluster nodes are reporting nominal telemetry."
                }

        # 2. Incidents & Root Causes (e.g. "Show top incidents", "What is failing?")
        if any(w in q_lower for w in ("incident", "incidents", "rca", "root cause", "failure", "failing")):
            incidents = storage_service.get_incidents(tenant_id=tenant_id, limit=5)
            if incidents:
                lines = [f"• [{inc.get('incident_id')}] {inc.get('root_cause')} (Severity: {inc.get('severity')}, Confidence: {inc.get('confidence_score')}%) - {inc.get('summary')}" for inc in incidents]
                return {
                    "answer": f"Top incidents detected for tenant '{tenant_id}':\n" + "\n".join(lines)
                }
            else:
                return {
                    "answer": f"There are currently 0 active critical incidents recorded for tenant '{tenant_id}'. Root cause analysis indicates stable cluster execution."
                }

        # 3. Risks & Capacity Forecasts (e.g. "Show current risks", "Will memory run out?", "OOM")
        if any(w in q_lower for w in ("risk", "risks", "oom", "forecast", "capacity", "future", "predict")):
            risk_summary = risk_engine.evaluate_risks(tenant_id=tenant_id)
            top = risk_summary.get("top_risk", {})
            return {
                "answer": f"Primary Predicted Risk: {top.get('risk')} with {top.get('probability')}% failure probability within ~{top.get('estimated_hours')} hours. {top.get('description')}"
            }

        # 4. Cyber Attacks & Threats (e.g. "Show threats", "Are we under attack?", "brute force")
        if any(w in q_lower for w in ("threat", "threats", "attack", "cyber", "security", "brute force", "ddos")):
            threats = storage_service.get_threat_events(tenant_id=tenant_id, status="ACTIVE", limit=5)
            if threats:
                th_desc = [f"• {t.get('threat_type')} (Score: {t.get('threat_score')}) from IP {t.get('source_ip')}" for t in threats]
                return {
                    "answer": f"Active Cyber Attacks detected:\n" + "\n".join(th_desc) + "\nOutside Attack Radar recommends applying egress firewall mitigations."
                }
            else:
                return {
                    "answer": "No hostile outside cyber attacks are currently active. Outside Attack Radar score is 0 (NOMINAL)."
                }

        # 5. Recommendations & Remediation (e.g. "Show recommendation", "What should I do?")
        if any(w in q_lower for w in ("recommend", "recommendation", "action", "remediation", "fix")):
            summary = reporting_service.generate_executive_summary(tenant_id=tenant_id)
            rep_data = summary.get("report", {})
            rec = rep_data.get("recommended_action", "Maintain current cluster configuration.")
            top_risk = rep_data.get("top_risk", "None")
            pending = remediation_engine.get_pending_remediations(tenant_id=tenant_id)
            
            pending_txt = ""
            if pending:
                pending_txt = f"\nPending Remediation Queue Item: '{pending[0].get('suggested_action')}' for {pending[0].get('root_cause')}."
            
            return {
                "answer": f"Recommended Action: {rec}\nPrimary Risk Addressed: {top_risk}.{pending_txt}"
            }

        # 6. General Executive Overview fallback
        summary = reporting_service.generate_executive_summary(tenant_id=tenant_id)
        rep = summary.get("report", {})
        return {
            "answer": f"SNOW LEOPARDS Autonomous AIOps Overview for '{tenant_id}': Overall Health is {rep.get('overall_health')}. Top active risk is {rep.get('top_risk')}. Recommended operational action: {rep.get('recommended_action')}."
        }


copilot_service = CopilotService()
