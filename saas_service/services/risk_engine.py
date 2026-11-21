"""
Proactive Risk Engine.
Phase 5.3:
Predicts critical system failures before they occur by evaluating real-time trends:
- MEMORY_EXHAUSTION (OOM)
- DISK_EXHAUSTION
- LATENCY_DEGRADATION
- AUTH_ATTACK_ESCALATION
"""

from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional

try:
    from .storage import storage_service
    from .forecast_engine import forecast_engine
except (ImportError, ValueError):
    from saas_service.services.storage import storage_service
    from saas_service.services.forecast_engine import forecast_engine


class ProactiveRiskEngine:
    """Predictive failure engine calculating risk probabilities and estimated time-to-failure."""

    def evaluate_risks(self, tenant_id: str = "TENANT-001") -> Dict[str, Any]:
        """
        Analyzes live telemetry, incidents, and threat streams to forecast impending failures.
        Returns risk summary with probabilities and estimated hours until degradation.
        """
        now_utc = datetime.now(timezone.utc).isoformat()
        risks: List[Dict[str, Any]] = []

        # 1. Memory Exhaustion / OOM Risk
        mem_fc = forecast_engine.forecast_resource(tenant_id=tenant_id, resource="memory", threshold=95.0)
        curr_mem = mem_fc["current"]
        pred_mem = mem_fc["predicted_7_days"]
        days_to_mem = mem_fc["days_to_threshold"]

        if curr_mem >= 75 or pred_mem >= 88:
            mem_prob = min(98, int(curr_mem * 1.1))
            est_hrs = max(2, int(days_to_mem * 24 * 0.15)) if days_to_mem < 900 else 6
            risks.append({
                "risk": "MEMORY_EXHAUSTION",
                "probability": mem_prob,
                "estimated_hours": est_hrs,
                "description": f"RAM utilization is at {curr_mem}% and climbing. High risk of Linux OOM killer invocation."
            })
        else:
            risks.append({
                "risk": "MEMORY_EXHAUSTION",
                "probability": 28,
                "estimated_hours": 72,
                "description": f"Memory stable at {curr_mem}%. Normal garbage collection cycle."
            })

        # 2. Disk Exhaustion Risk
        disk_fc = forecast_engine.forecast_resource(tenant_id=tenant_id, resource="disk", threshold=90.0)
        curr_disk = disk_fc["current"]
        if curr_disk >= 70:
            disk_prob = min(95, int(curr_disk * 1.05))
            risks.append({
                "risk": "DISK_EXHAUSTION",
                "probability": disk_prob,
                "estimated_hours": max(4, int(disk_fc["days_to_threshold"] * 12)),
                "description": f"Persistent volume utilization at {curr_disk}%. Log rotation needed to prevent IO freeze."
            })
        else:
            risks.append({
                "risk": "DISK_EXHAUSTION",
                "probability": 18,
                "estimated_hours": 168,
                "description": f"Disk headroom healthy at {100 - curr_disk}% free space."
            })

        # 3. Latency Degradation Risk
        telemetry = storage_service.get_chronological_telemetry(tenant_id=tenant_id, limit=20)
        high_lat_count = 0
        latest_loss = 0.0
        for r in telemetry:
            try:
                pj = json.loads(r.get("payload_json", "{}"))
                d = pj.get("data", {})
                if float(d.get("latency_ms", d.get("latency", 0.0))) > 50.0:
                    high_lat_count += 1
                latest_loss = max(latest_loss, float(d.get("packet_loss_pct", d.get("packet_loss", 0.0))))
            except Exception:
                pass

        if high_lat_count >= 3 or latest_loss > 0.05:
            risks.append({
                "risk": "LATENCY_DEGRADATION",
                "probability": 84,
                "estimated_hours": 3,
                "description": "Correlated ingress queue latency spikes detected across node gateways."
            })
        else:
            risks.append({
                "risk": "LATENCY_DEGRADATION",
                "probability": 22,
                "estimated_hours": 48,
                "description": "Network transit and gateway latency performing within standard baseline."
            })

        # 4. Auth Attack Escalation Risk
        active_threats = storage_service.get_threat_events(tenant_id=tenant_id, status="ACTIVE", limit=20)
        if len(active_threats) > 0:
            max_score = max(int(t.get("threat_score", 50)) for t in active_threats)
            risks.append({
                "risk": "AUTH_ATTACK_ESCALATION",
                "probability": min(96, int(max_score * 1.1)),
                "estimated_hours": 1,
                "description": f"Active credential brute force or flood detected from {len(active_threats)} external vectors."
            })
        else:
            risks.append({
                "risk": "AUTH_ATTACK_ESCALATION",
                "probability": 12,
                "estimated_hours": 96,
                "description": "No hostile external authentication attacks currently escalating."
            })

        # Sort by probability descending to determine top risk
        risks.sort(key=lambda r: r["probability"], reverse=True)
        top = risks[0]

        return {
            "tenant_id": tenant_id,
            "evaluated_at": now_utc,
            "top_risk": top,
            "risk": top["risk"],
            "probability": top["probability"],
            "estimated_hours": top["estimated_hours"],
            "risks": risks
        }


risk_engine = ProactiveRiskEngine()
