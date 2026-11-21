"""
Self-Learning Seasonal Baseline & Fluctuation Advisory Engine.
Phase 4.5 Core:
- 168-Slot Matrix (7 Days x 24 Hours)
- Online Continuous Learning (Exponential Moving Average with Dynamic Variance)
- Differentiates expected business traffic (Monday peak) vs off-peak anomalies (Sunday night free servers)
- Fluctuation Classifier: Tells client whether changes are benign or worrying
"""

from datetime import datetime, timezone
import math
from typing import Any, Dict, List, Optional, Tuple

try:
    from .storage import storage_service
except (ImportError, ValueError):
    from saas_service.services.storage import storage_service


class SeasonalLearningEngine:
    """
    Self-learning time-of-week baseline model.
    Maintains 168 hourly slots per metric across the weekly cycle.
    """

    def __init__(self, learning_rate: float = 0.08):
        self.learning_rate = learning_rate

    def _parse_time_slot(self, timestamp_str: str) -> Tuple[int, int]:
        """Extracts (day_of_week [0=Monday, 6=Sunday], hour_of_day [0-23])."""
        try:
            # Handles ISO 8601 strings like "2026-11-21T02:00:00Z"
            clean_ts = timestamp_str.replace("Z", "+00:00")
            dt = datetime.fromisoformat(clean_ts)
            return dt.weekday(), dt.hour
        except Exception:
            now = datetime.now(timezone.utc)
            return now.weekday(), now.hour

    def update_and_evaluate_metric(
        self,
        tenant_id: str,
        collector_id: str,
        metric_name: str,
        value: float,
        timestamp_str: str
    ) -> Dict[str, Any]:
        """
        Updates the seasonal profile and computes the seasonal deviation.
        Returns: {mean, std_dev, z_score, is_benign, advisory}
        """
        day_of_week, hour_of_day = self._parse_time_slot(timestamp_str)

        # 1. Update baseline via online continuous learning
        stats = storage_service.upsert_seasonal_baseline(
            tenant_id=tenant_id,
            collector_id=collector_id,
            day_of_week=day_of_week,
            hour_of_day=hour_of_day,
            metric_name=metric_name,
            value=value,
            alpha=self.learning_rate
        )

        mean = stats["mean"]
        std = max(stats["std_dev"], 0.5)
        z_score = round((value - mean) / std, 2)

        # 2. Contextual Fluctuation Analysis
        day_names = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
        day_str = day_names[day_of_week]
        is_weekend = day_of_week in (5, 6)
        is_offpeak_hour = hour_of_day < 7 or hour_of_day > 21

        is_worrying = False
        classification = "BENIGN_NORMAL_FLUCTUATION"
        advisory = ""

        # Case A: Elevated on expected high-traffic weekday slot (e.g. Monday daytime)
        if not is_weekend and not is_offpeak_hour and mean >= 60.0:
            if z_score <= 2.2:
                classification = "EXPECTED_WEEKDAY_PEAK"
                advisory = (
                    f"Normal {day_str} business load: {metric_name} is at {value:.1f}%, "
                    f"which matches typical historical activity for {day_str} {hour_of_day:02d}:00 "
                    f"(baseline: {mean:.1f}% ± {std:.1f}%). No operator intervention needed."
                )
                is_worrying = False
            else:
                classification = "UNUSUAL_PEAK_SURGE"
                advisory = (
                    f"Unusual surge on {day_str} at {hour_of_day:02d}:00: {metric_name} is +{z_score:+.1f}σ "
                    f"above typical business baseline ({value:.1f}% vs historical {mean:.1f}%). Monitoring for escalation."
                )
                is_worrying = True

        # Case B: Elevated during off-peak or weekend (Sunday night idle servers)
        elif (is_weekend or is_offpeak_hour) and value >= 70.0 and z_score >= 2.5:
            classification = "WORRYING_OFFPEAK_SURGE"
            advisory = (
                f"Abnormal off-peak surge detected: {metric_name} is at {value:.1f}% during "
                f"{day_str} {hour_of_day:02d}:00 off-peak hours (+{z_score:+.1f}σ above baseline of {mean:.1f}%). "
                f"Suspicious activity or unmanaged compute load during idle window."
            )
            is_worrying = True

        # Case C: Calm / Expected Normal
        else:
            if abs(z_score) <= 2.0:
                classification = "BENIGN_NORMAL_BASELINE"
                advisory = (
                    f"{day_str} {hour_of_day:02d}:00 operating within expected seasonal band "
                    f"({value:.1f}% vs baseline {mean:.1f}%)."
                )
                is_worrying = False
            else:
                classification = "ELEVATED_VARIANCE"
                advisory = f"Elevated variance (+{z_score:+.1f}σ deviation from {day_str} baseline of {mean:.1f}%)."
                is_worrying = True

        return {
            "metric_name": metric_name,
            "value": value,
            "day_of_week": day_of_week,
            "hour_of_day": hour_of_day,
            "day_name": day_str,
            "mean": mean,
            "std_dev": std,
            "z_score": z_score,
            "is_worrying": is_worrying,
            "classification": classification,
            "advisory": advisory
        }

    def analyze_payload_fluctuations(
        self,
        payload: Dict[str, Any],
        tenant_id: str
    ) -> List[Dict[str, Any]]:
        """Analyzes all key metrics in payload for seasonal fluctuation advisory."""
        data = payload.get("data", {})
        if not data or payload.get("data_type") != "METRICS":
            return []

        collector_id = payload.get("collector_id", "COLL-UNKNOWN")
        ts = payload.get("event_time_utc") or datetime.now(timezone.utc).isoformat()

        results = []
        for metric in ["cpu", "memory", "latency", "packet_loss"]:
            if metric in data:
                res = self.update_and_evaluate_metric(
                    tenant_id=tenant_id,
                    collector_id=collector_id,
                    metric_name=metric,
                    value=float(data[metric]),
                    timestamp_str=ts
                )
                results.append(res)
        return results


seasonal_engine = SeasonalLearningEngine()
