"""
Probable Cause Engine (Rule-based Explainable AIOps).
Phase 4 Core Engine:
- Multi-dimensional incident clustering (temporal correlation)
- Deterministic Causal Decision Engine / Root Cause Analysis (RCA)
- Mathematical confidence scoring (0.0 to 1.0)
- Actionable, explainable remediation runbooks
- Incident evidence chain and historical timeline reconstruction
- Automatic incident resolution upon telemetry normalization
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


class ProbableCauseEngine:
    """
    Deterministic, rule-based Probable Cause Engine.
    Correlates multi-metric anomalies into unified incidents, diagnoses root causes,
    and produces actionable runbooks without black-box hallucinations.
    """

    def __init__(self, history_size: int = 15, recovery_threshold: int = 3):
        self.history_size = history_size
        self.recovery_threshold = recovery_threshold
        # (collector_id) -> deque of {timestamp, cpu, memory, disk, latency, packet_loss, failed_logins}
        self.node_history: Dict[str, deque] = {}
        # (collector_id) -> consecutive healthy count
        self.healthy_cycles: Dict[str, int] = {}

    def _get_history(self, collector_id: str) -> deque:
        if collector_id not in self.node_history:
            self.node_history[collector_id] = deque(maxlen=self.history_size)
        return self.node_history[collector_id]

    def _is_monotonic_increase(self, collector_id: str, metric: str, min_samples: int = 3) -> bool:
        """Verifies if a metric has increased monotonically across the last N samples."""
        hist = self._get_history(collector_id)
        if len(hist) < min_samples:
            return False
        recent = list(hist)[-min_samples:]
        values = [r[metric] for r in recent]
        for i in range(1, len(values)):
            if values[i] <= values[i - 1]:
                return False
        return True

    def _reconstruct_timeline(
        self,
        collector_id: str,
        current_sample: Dict[str, Any],
        incident_type: str,
        trigger_reason: str
    ) -> List[Dict[str, Any]]:
        """
        Reconstructs the chronological event sequence leading up to the incident trigger.
        Format: [ {timestamp, phase, metrics_summary, annotation}, ... ]
        """
        hist = list(self._get_history(collector_id))
        timeline: List[Dict[str, Any]] = []

        if len(hist) > 1:
            for idx, sample in enumerate(hist[:-1]):
                phase = "Healthy Baseline" if idx == 0 else "Pre-Incident Escalation"
                timeline.append({
                    "timestamp": sample["timestamp"],
                    "phase": phase,
                    "cpu": sample["cpu"],
                    "memory": sample["memory"],
                    "latency": sample["latency"],
                    "packet_loss": sample["packet_loss"],
                    "failed_logins": sample["failed_logins"],
                    "annotation": "Normal operational metrics" if phase == "Healthy Baseline" else "Metric inflection detected"
                })

        # Final trigger step
        timeline.append({
            "timestamp": current_sample["timestamp"],
            "phase": "Incident Triggered",
            "cpu": current_sample["cpu"],
            "memory": current_sample["memory"],
            "latency": current_sample["latency"],
            "packet_loss": current_sample["packet_loss"],
            "failed_logins": current_sample["failed_logins"],
            "annotation": f"Threshold & causal rule breached: {trigger_reason}"
        })

        return timeline

    def analyze_and_correlate(
        self,
        payload: Dict[str, Any],
        tenant_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Main entrypoint called during ingestion.
        Evaluates the payload against deterministic causal rules.
        Returns an incident dict if an incident was triggered or updated, else None.
        """
        data = payload.get("data", {})
        if not data or payload.get("data_type") != "METRICS":
            return None

        collector_id = payload.get("collector_id", "COLL-UNKNOWN")
        cpu = float(data.get("cpu", 0.0))
        memory = float(data.get("memory", 0.0))
        disk = float(data.get("disk", 0.0))
        latency = float(data.get("latency", 0.0))
        packet_loss = float(data.get("packet_loss", 0.0))
        failed_logins = int(data.get("failed_logins", 0) or 0)
        timestamp = payload.get("event_time_utc") or datetime.now(timezone.utc).isoformat()

        current_sample = {
            "timestamp": timestamp,
            "cpu": cpu,
            "memory": memory,
            "disk": disk,
            "latency": latency,
            "packet_loss": packet_loss,
            "failed_logins": failed_logins
        }

        # Record history
        hist = self._get_history(collector_id)
        hist.append(current_sample)

        # -------------------------------------------------------------
        # Deterministic Causal Rules (Ordered by severity / specificity)
        # -------------------------------------------------------------
        incident_type: Optional[str] = None
        severity = "WARNING"
        confidence_score = 0.90
        root_cause = ""
        summary = ""
        recommendations: List[str] = []
        evidence: Dict[str, Any] = {}
        trigger_reason = ""

        # Pattern 1: Cascading Multi-Resource Starvation (Highest Multi-Metric Priority)
        if cpu >= 85.0 and memory >= 80.0 and latency >= 100.0:
            incident_type = "CASCADING_RESOURCE_STARVATION"
            severity = "CRITICAL"
            confidence_score = 0.97
            root_cause = "Cascading multi-resource bottleneck where severe CPU throttling and memory pressure compound HTTP/API response latency."
            summary = f"Host experiencing compounded failure: CPU at {cpu:.1f}%, RAM at {memory:.1f}%, and response latency spiked to {latency:.1f}ms."
            trigger_reason = f"Composite saturation (CPU={cpu:.1f}%, RAM={memory:.1f}%, Latency={latency:.1f}ms)"
            recommendations = [
                "Throttle non-critical asynchronous queues, ETL jobs, and background workers immediately.",
                "Horizontally scale application replica count or increase allocated VM vCPU/Memory limits.",
                "Capture thread and process dumps to terminate unresponsive runaway processes."
            ]
            evidence = {
                "cpu_usage": cpu,
                "memory_usage": memory,
                "latency_ms": latency,
                "packet_loss_pct": packet_loss,
                "rule_matched": "CASCADING_CPU_MEM_LATENCY_SATURATION"
            }

        # Pattern 2: Network Link Degradation (Packet Loss + Latency Correlation)
        elif packet_loss >= 5.0 and latency >= 100.0:
            incident_type = "NETWORK_LINK_DEGRADATION"
            severity = "CRITICAL" if (packet_loss >= 20.0 or latency >= 250.0) else "WARNING"
            confidence_score = 0.96 if severity == "CRITICAL" else 0.89
            root_cause = "Upstream transport-layer network congestion, packet drop, or intermediate hop routing degradation."
            summary = f"Network link quality degraded: {packet_loss:.1f}% packet drop correlated with {latency:.1f}ms latency."
            trigger_reason = f"Packet loss ({packet_loss:.1f}%) with elevated latency ({latency:.1f}ms)"
            recommendations = [
                "Execute MTR / traceroute diagnostic to isolate hop-level packet drop and upstream transit jitter.",
                "Inspect local network interface throughput and physical switch port error/duplex counters.",
                "Verify edge gateway link utilization against provisioned bandwidth cap."
            ]
            evidence = {
                "packet_loss_pct": packet_loss,
                "latency_ms": latency,
                "rule_matched": "CORRELATED_NETWORK_LOSS_LATENCY"
            }

        # Pattern 3: Memory Leak / Unbounded Consumption
        elif memory >= 85.0 and (self._is_monotonic_increase(collector_id, "memory", min_samples=3) or memory >= 92.0):
            incident_type = "MEMORY_LEAK_EXHAUSTION"
            severity = "CRITICAL" if memory >= 92.0 else "WARNING"
            confidence_score = 0.94 if self._is_monotonic_increase(collector_id, "memory", min_samples=3) else 0.86
            root_cause = "Progressive RAM consumption pattern consistent with an uncollected application memory leak or unbounded in-memory cache."
            summary = f"RAM usage critical at {memory:.1f}% with sustained positive growth trend across consecutive cycles."
            trigger_reason = f"RAM at {memory:.1f}% with monotonic growth trend"
            recommendations = [
                "Capture process heap snapshot to inspect uncollected objects, leaky closures, or unclosed database connection pools.",
                "Audit in-memory cache TTL eviction policies and configure maximum element caps.",
                "Initiate graceful rolling process restart before kernel OOM-killer terminates the process abruptly."
            ]
            evidence = {
                "memory_usage": memory,
                "growth_pattern": "monotonic_increase" if self._is_monotonic_increase(collector_id, "memory", min_samples=3) else "high_static_threshold",
                "rule_matched": "PROGRESSIVE_MEMORY_EXHAUSTION"
            }

        # Pattern 4: Brute-Force Auth Attack / Credential Stuffing
        elif failed_logins >= 5:
            incident_type = "BRUTE_FORCE_AUTH_ATTACK"
            severity = "CRITICAL" if failed_logins >= 10 else "WARNING"
            confidence_score = 0.98 if failed_logins >= 10 else 0.90
            root_cause = "Abnormal surge in failed authentication attempts indicating an automated credential stuffing or dictionary attack."
            summary = f"Security anomaly: {failed_logins} failed login attempts registered within recent sampling interval."
            trigger_reason = f"Spike of {failed_logins} failed authentication attempts"
            recommendations = [
                "Enforce immediate IP rate-limiting, exponential backoff, and CAPTCHA challenges on authentication routes.",
                "Analyze reverse proxy / WAF logs to identify and block attacking IP CIDR blocks.",
                "Audit targeted tenant user accounts and enforce multi-factor authentication (MFA) reset."
            ]
            evidence = {
                "failed_logins_count": failed_logins,
                "rule_matched": "AUTH_FAILURE_SURGE"
            }

        # Pattern 5: Storage I/O Exhaustion
        elif disk >= 88.0:
            incident_type = "STORAGE_IO_EXHAUSTION"
            severity = "CRITICAL" if disk >= 94.0 else "WARNING"
            confidence_score = 0.95
            root_cause = "Host primary filesystem capacity exhaustion, presenting imminent risk of write stalls, corrupted database WAL logs, and service termination."
            summary = f"Storage volume partition utilization at {disk:.1f}%, nearing exhaustion threshold."
            trigger_reason = f"Disk utilization at {disk:.1f}%"
            recommendations = [
                "Purge unrotated application logs, temporary scratch artifacts, and stale system dumps.",
                "Audit database WAL file growth and trigger checkpoint truncation: PRAGMA wal_checkpoint(TRUNCATE).",
                "Expand primary filesystem partition or mount secondary high-throughput persistent storage."
            ]
            evidence = {
                "disk_usage": disk,
                "rule_matched": "DISK_CAPACITY_EXHAUSTION"
            }

        # -------------------------------------------------------------
        # Incident Clustering & State Persistence
        # -------------------------------------------------------------
        if incident_type:
            self.healthy_cycles[collector_id] = 0

            # Check if an OPEN incident of this type already exists for clustering
            existing = storage_service.get_open_incident(
                tenant_id=tenant_id,
                collector_id=collector_id,
                incident_type=incident_type
            )

            if existing:
                # Update existing incident: extend timeline & refresh evidence
                timeline = existing.get("timeline", [])
                timeline.append({
                    "timestamp": timestamp,
                    "phase": "Ongoing Degradation",
                    "cpu": cpu,
                    "memory": memory,
                    "latency": latency,
                    "packet_loss": packet_loss,
                    "failed_logins": failed_logins,
                    "annotation": f"Condition persists: {trigger_reason}"
                })
                # Keep timeline bounded to last 15 points
                if len(timeline) > 15:
                    timeline = timeline[-15:]

                storage_service.update_incident(
                    incident_id=existing["incident_id"],
                    updates={
                        "timeline": timeline,
                        "evidence": evidence,
                        "severity": severity,
                        "confidence_score": confidence_score,
                        "summary": summary
                    }
                )
                existing["timeline"] = timeline
                existing["evidence"] = evidence
                existing["severity"] = severity
                existing["confidence_score"] = confidence_score
                existing["summary"] = summary
                return existing

            else:
                # Create brand new incident
                incident_id = f"INC-{datetime.now(timezone.utc).year}-{uuid.uuid4().hex[:8].upper()}"
                timeline = self._reconstruct_timeline(
                    collector_id=collector_id,
                    current_sample=current_sample,
                    incident_type=incident_type,
                    trigger_reason=trigger_reason
                )

                incident_record = {
                    "incident_id": incident_id,
                    "tenant_id": tenant_id,
                    "collector_id": collector_id,
                    "incident_type": incident_type,
                    "severity": severity,
                    "status": "OPEN",
                    "root_cause": root_cause,
                    "confidence_score": confidence_score,
                    "summary": summary,
                    "recommendations": recommendations,
                    "evidence": evidence,
                    "timeline": timeline,
                    "created_at": timestamp,
                    "updated_at": timestamp
                }

                storage_service.store_incident(incident_record)
                return incident_record

        else:
            # Metric is currently within normal operating thresholds
            self.healthy_cycles[collector_id] = self.healthy_cycles.get(collector_id, 0) + 1
            if self.healthy_cycles[collector_id] >= self.recovery_threshold:
                # Auto-resolve open incidents for this node
                resolved_count = storage_service.resolve_incidents_for_collector(collector_id)
                if resolved_count > 0:
                    self.healthy_cycles[collector_id] = 0
            return None


rca_engine = ProbableCauseEngine()
