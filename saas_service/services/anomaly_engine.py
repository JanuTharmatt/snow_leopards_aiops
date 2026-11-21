"""
Contextual Anomaly Detection Engine.
Phase 3 Task E:
Lightweight, explainable contextual anomaly detection operating within the <= 15s SLA.
Features:
- Rolling window statistical baseline (Z-score calculation)
- Multi-metric correlation (e.g. Latency + Packet Loss, CPU + Memory)
- Explainable diagnosis with root-cause recommendations
"""

from collections import deque
from datetime import datetime, timezone
import math
from typing import Any, Dict, List, Optional, Tuple
import uuid

try:
    from .storage import storage_service
except (ImportError, ValueError):
    from saas_service.services.storage import storage_service


class ContextualAnomalyEngine:
    """
    Evaluates real-time telemetry against statistical baselines and multi-metric correlations.
    """

    def __init__(self, window_size: int = 30):
        self.window_size = window_size
        # Collector ID -> metric_name -> deque of floats
        self.history: Dict[str, Dict[str, deque]] = {}

    def _get_history(self, collector_id: str, metric_name: str) -> deque:
        if collector_id not in self.history:
            self.history[collector_id] = {}
        if metric_name not in self.history[collector_id]:
            self.history[collector_id][metric_name] = deque(maxlen=self.window_size)
        return self.history[collector_id][metric_name]

    def compute_z_score(self, collector_id: str, metric_name: str, value: float) -> Tuple[float, float, float]:
        """
        Computes (z_score, mean, std) for the given metric value against rolling baseline.
        """
        hist = self._get_history(collector_id, metric_name)
        if len(hist) < 3:
            hist.append(value)
            return 0.0, value, 0.0

        mean = sum(hist) / len(hist)
        variance = sum((x - mean) ** 2 for x in hist) / len(hist)
        std = math.sqrt(variance)

        hist.append(value)

        if std < 0.001:
            return 0.0, mean, std

        z_score = (value - mean) / std
        return round(z_score, 2), round(mean, 2), round(std, 2)

    def analyze_telemetry_payload(
        self,
        payload: Dict[str, Any],
        tenant_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Synchronously evaluates payload for contextual multi-metric anomalies.
        Executes in < 5ms, easily fulfilling the <= 15s SLA.
        """
        data = payload.get("data", {})
        if not data or payload.get("data_type") != "METRICS":
            return None

        collector_id = payload.get("collector_id", "COLL-UNKNOWN")
        cpu = float(data.get("cpu", 0.0))
        memory = float(data.get("memory", 0.0))
        latency = float(data.get("latency", 0.0))
        packet_loss = float(data.get("packet_loss", 0.0))
        failed_logins = int(data.get("failed_logins", 0) or 0)

        # 1. Update rolling stats and compute Z-scores
        z_cpu, mean_cpu, _ = self.compute_z_score(collector_id, "cpu", cpu)
        z_lat, mean_lat, _ = self.compute_z_score(collector_id, "latency", latency)
        z_loss, mean_loss, _ = self.compute_z_score(collector_id, "packet_loss", packet_loss)

        anomaly_type: Optional[str] = None
        severity = "WARNING"
        diagnosis: Optional[str] = None

        # Pattern 1: Correlated Network Degradation (High Latency + Packet Loss)
        if (z_lat >= 2.0 or latency >= 150.0) and packet_loss >= 5.0:
            anomaly_type = "CORRELATED_NETWORK_DEGRADATION"
            severity = "CRITICAL" if (packet_loss >= 20.0 or latency >= 300.0) else "WARNING"
            diagnosis = (
                f"Multi-metric network degradation: Latency ({latency:.1f}ms, z={z_lat:+.1f}σ) "
                f"correlated with {packet_loss:.1f}% packet loss indicating path congestion or transport degradation."
            )

        # Pattern 2: Correlated Host Resource Saturation (High CPU + Memory)
        elif (z_cpu >= 2.5 or cpu >= 85.0) and memory >= 80.0:
            anomaly_type = "RESOURCE_SATURATION"
            severity = "CRITICAL" if (cpu >= 90.0 and memory >= 85.0) else "WARNING"
            diagnosis = (
                f"Multi-metric resource saturation: CPU ({cpu:.1f}%, z={z_cpu:+.1f}σ) "
                f"correlated with elevated Memory ({memory:.1f}%) indicating capacity exhaustion."
            )

        # Pattern 3: Auth Breach / Failed Login Surge
        elif failed_logins >= 5:
            anomaly_type = "AUTH_SURGE"
            severity = "CRITICAL" if failed_logins >= 10 else "WARNING"
            diagnosis = f"Security anomaly: Surge of {failed_logins} failed authentication events in cycle."

        if anomaly_type and diagnosis:
            alert_id = f"ANOM-{uuid.uuid4().hex[:12].upper()}"
            alert_data = {
                "alert_id": alert_id,
                "collector_id": collector_id,
                "tenant_id": tenant_id,
                "alert_type": anomaly_type,
                "severity": severity,
                "diagnosis": diagnosis,
                "metrics": {
                    "cpu": cpu,
                    "memory": memory,
                    "latency": latency,
                    "packet_loss": packet_loss,
                    "z_scores": {
                        "cpu": z_cpu,
                        "latency": z_lat,
                        "packet_loss": z_loss
                    }
                },
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            }

            # Persist alert
            storage_service.store_alert(
                alert_id=alert_id,
                collector_id=collector_id,
                tenant_id=tenant_id,
                alert_type=anomaly_type,
                severity=severity,
                diagnosis=diagnosis,
                metrics=alert_data["metrics"]
            )
            return alert_data
        else:
            # If healthy, resolve previous contextual anomalies
            storage_service.resolve_alerts(collector_id, alert_type="CORRELATED_NETWORK_DEGRADATION")
            storage_service.resolve_alerts(collector_id, alert_type="RESOURCE_SATURATION")
            return None


anomaly_engine = ContextualAnomalyEngine()
