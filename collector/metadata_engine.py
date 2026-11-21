"""
Metadata Engine Module for Privacy-First AIOps Observability Platform.
Converts raw/redacted data into canonical metadata using 4 health states:
HEALTHY, WARNING, CRITICAL, UNKNOWN.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union
import regex as re
from pydantic import BaseModel

try:
    from .config import config
    from .models import (
        HealthStatus,
        LogEventMetadata,
        MetricMetadata,
        RawSystemMetrics,
        SeverityLevel,
    )
except (ImportError, ValueError):
    from config import config
    from models import (
        HealthStatus,
        LogEventMetadata,
        MetricMetadata,
        RawSystemMetrics,
        SeverityLevel,
    )


class MetadataEngine:
    """
    Transforms unstructured logs and numerical telemetry into canonical metadata.
    Enforces the 4-state health model: HEALTHY, WARNING, CRITICAL, UNKNOWN.
    """

    METRIC_STRING_PATTERN = re.compile(
        r"^\s*([A-Za-z_]+)\s*[:=]\s*([0-9]+(?:\.[0-9]+)?)\s*%?\s*$",
        re.IGNORECASE
    )

    EVENT_RULES: List[Tuple[re.Pattern, str, SeverityLevel]] = [
        (re.compile(r"\b(?:payment\s+failed|payment\s+failure|transaction\s+declined|billing\s+error)\b", re.I),
         "PAYMENT_FAILURE", SeverityLevel.HIGH),
        (re.compile(r"\b(?:database\s+(?:connection\s+)?failed|db\s+error|query\s+timeout|deadlock\s+detected)\b", re.I),
         "DATABASE_ERROR", SeverityLevel.CRITICAL),
        (re.compile(r"\b(?:out\s+of\s+memory|oom\s+killed|disk\s+full|no\s+space\s+left)\b", re.I),
         "RESOURCE_EXHAUSTION", SeverityLevel.CRITICAL),
        (re.compile(r"\b(?:auth(?:entication)?\s+failed|unauthorized|invalid\s+token|access\s+denied|forbidden)\b", re.I),
         "AUTH_FAILURE", SeverityLevel.HIGH),
        (re.compile(r"\b(?:service\s+unavailable|upstream\s+connect\s+error|502\s+bad\s+gateway|503\s+service)\b", re.I),
         "UPSTREAM_OUTAGE", SeverityLevel.CRITICAL),
        (re.compile(r"\b(?:exception|traceback|panic|fatal|crash)\b", re.I),
         "APPLICATION_CRASH", SeverityLevel.CRITICAL),
        (re.compile(r"\b(?:error|fail(?:ed|ure)?)\b", re.I),
         "APPLICATION_ERROR", SeverityLevel.HIGH),
        (re.compile(r"\b(?:warn(?:ing)?|deprecated|slow)\b", re.I),
         "SYSTEM_WARNING", SeverityLevel.MEDIUM),
        (re.compile(r"\b(?:info|success|completed|started|healthy)\b", re.I),
         "SYSTEM_INFO", SeverityLevel.INFO),
    ]

    def __init__(self):
        self.thresholds = config.thresholds

    def evaluate_metric(self, metric_type: str, value: float, timestamp: Optional[str] = None) -> MetricMetadata:
        """
        Evaluates a single numeric metric against operational thresholds.
        Maps into 4 health states: HEALTHY, WARNING, CRITICAL, UNKNOWN.
        """
        metric_norm = metric_type.upper().strip()
        ts = timestamp or datetime.now(timezone.utc).isoformat()

        if metric_norm == "CPU":
            if value >= self.thresholds.cpu_critical:
                health = HealthStatus.CRITICAL
                severity = SeverityLevel.HIGH if value <= 98 else SeverityLevel.CRITICAL
            elif value >= self.thresholds.cpu_warning:
                health = HealthStatus.WARNING
                severity = SeverityLevel.MEDIUM
            elif value >= 0:
                health = HealthStatus.HEALTHY
                severity = SeverityLevel.INFO
            else:
                health = HealthStatus.UNKNOWN
                severity = SeverityLevel.LOW

        elif metric_norm in ("MEMORY", "MEM", "RAM"):
            metric_norm = "MEMORY"
            if value >= self.thresholds.memory_critical:
                health = HealthStatus.CRITICAL
                severity = SeverityLevel.HIGH
            elif value >= self.thresholds.memory_warning:
                health = HealthStatus.WARNING
                severity = SeverityLevel.MEDIUM
            elif value >= 0:
                health = HealthStatus.HEALTHY
                severity = SeverityLevel.INFO
            else:
                health = HealthStatus.UNKNOWN
                severity = SeverityLevel.LOW

        elif metric_norm in ("DISK", "STORAGE"):
            metric_norm = "DISK"
            if value >= self.thresholds.disk_critical:
                health = HealthStatus.CRITICAL
                severity = SeverityLevel.HIGH
            elif value >= self.thresholds.disk_warning:
                health = HealthStatus.WARNING
                severity = SeverityLevel.MEDIUM
            elif value >= 0:
                health = HealthStatus.HEALTHY
                severity = SeverityLevel.INFO
            else:
                health = HealthStatus.UNKNOWN
                severity = SeverityLevel.LOW

        elif metric_norm in ("LATENCY", "PING", "RTT"):
            metric_norm = "LATENCY"
            if value >= self.thresholds.latency_critical_ms:
                health = HealthStatus.CRITICAL
                severity = SeverityLevel.HIGH
            elif value >= self.thresholds.latency_warning_ms:
                health = HealthStatus.WARNING
                severity = SeverityLevel.MEDIUM
            elif value >= 0:
                health = HealthStatus.HEALTHY
                severity = SeverityLevel.INFO
            else:
                health = HealthStatus.UNKNOWN
                severity = SeverityLevel.LOW

        elif metric_norm in ("PACKET_LOSS", "LOSS", "PACKET_LOSS_PCT"):
            metric_norm = "PACKET_LOSS"
            if value >= self.thresholds.packet_loss_critical:
                health = HealthStatus.CRITICAL
                severity = SeverityLevel.CRITICAL
            elif value >= self.thresholds.packet_loss_warning:
                health = HealthStatus.WARNING
                severity = SeverityLevel.MEDIUM
            elif value >= 0:
                health = HealthStatus.HEALTHY
                severity = SeverityLevel.INFO
            else:
                health = HealthStatus.UNKNOWN
                severity = SeverityLevel.LOW

        else:
            health = HealthStatus.HEALTHY
            severity = SeverityLevel.INFO

        return MetricMetadata(
            metric_type=metric_norm,
            value=round(value, 2),
            health=health,
            severity=severity,
            timestamp=ts
        )

    def classify_log_event(self, log_text: str, timestamp: Optional[str] = None) -> LogEventMetadata:
        """
        Classifies an unstructured log text into a canonical event code and severity.
        """
        ts = timestamp or datetime.now(timezone.utc).isoformat()
        clean_text = log_text.strip()

        for pattern, event_code, severity in self.EVENT_RULES:
            if pattern.search(clean_text):
                return LogEventMetadata(
                    event=event_code,
                    severity=severity,
                    timestamp=ts,
                    details={"matched_sample": clean_text[:100]}
                )

        return LogEventMetadata(
            event="GENERAL_LOG",
            severity=SeverityLevel.INFO,
            timestamp=ts,
            details={"sample": clean_text[:100]}
        )

    def normalize_telemetry_batch_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalizes a sanitized telemetry dictionary into composite 4-state health metadata.
        """
        ts = data.get("timestamp") or datetime.now(timezone.utc).isoformat()
        cpu_val = float(data.get("cpu", 0.0))
        mem_val = float(data.get("memory", 0.0))
        disk_val = float(data.get("disk", 0.0))
        lat_val = float(data.get("latency", 0.0))
        loss_val = float(data.get("packet_loss", 0.0))

        cpu_meta = self.evaluate_metric("CPU", cpu_val, ts)
        mem_meta = self.evaluate_metric("MEMORY", mem_val, ts)
        disk_meta = self.evaluate_metric("DISK", disk_val, ts)
        latency_meta = self.evaluate_metric("LATENCY", lat_val, ts)
        loss_meta = self.evaluate_metric("PACKET_LOSS", loss_val, ts)

        healths = [cpu_meta.health, mem_meta.health, disk_meta.health, latency_meta.health, loss_meta.health]
        if HealthStatus.CRITICAL in healths:
            system_health = HealthStatus.CRITICAL
            overall_severity = SeverityLevel.HIGH
        elif HealthStatus.WARNING in healths:
            system_health = HealthStatus.WARNING
            overall_severity = SeverityLevel.MEDIUM
        elif HealthStatus.UNKNOWN in healths:
            system_health = HealthStatus.UNKNOWN
            overall_severity = SeverityLevel.LOW
        else:
            system_health = HealthStatus.HEALTHY
            overall_severity = SeverityLevel.INFO

        return {
            "system_health": system_health.value,
            "overall_severity": overall_severity.value,
            "timestamp": ts,
            "metrics": {
                "cpu": cpu_meta.model_dump(),
                "memory": mem_meta.model_dump(),
                "disk": disk_meta.model_dump(),
                "latency": latency_meta.model_dump(),
                "packet_loss": loss_meta.model_dump()
            }
        }

    def process(self, data: Union[str, Dict[str, Any], RawSystemMetrics]) -> Dict[str, Any]:
        """
        Main entry point for the Metadata Engine.
        """
        if isinstance(data, RawSystemMetrics):
            return self.normalize_telemetry_batch_dict(data.model_dump())

        if isinstance(data, dict):
            if "cpu" in data or "memory" in data or "disk" in data:
                return self.normalize_telemetry_batch_dict(data)

        if isinstance(data, str):
            text = data.strip()
            match = self.METRIC_STRING_PATTERN.match(text)
            if match:
                m_type = match.group(1)
                m_val = float(match.group(2))
                metric_meta = self.evaluate_metric(m_type, m_val)
                # POOR / CRITICAL threshold compatibility
                health_out = "POOR" if metric_meta.health == HealthStatus.CRITICAL else metric_meta.health.value
                return {
                    "metric_type": metric_meta.metric_type,
                    "value": int(metric_meta.value) if metric_meta.value.is_integer() else metric_meta.value,
                    "health": health_out,
                    "severity": metric_meta.severity.value
                }

            event_meta = self.classify_log_event(text)
            return {
                "event": event_meta.event,
                "severity": event_meta.severity.value,
                "timestamp": event_meta.timestamp
            }

        return {
            "event": "UNKNOWN_DATA",
            "severity": SeverityLevel.INFO.value,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }


metadata_engine = MetadataEngine()
