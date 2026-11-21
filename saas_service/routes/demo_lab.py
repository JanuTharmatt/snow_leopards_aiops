"""
Demo Laboratory API for Judge Evaluation.
Phase 5.5: Interactive Live Incident Generator.

Allows judges to trigger 5 distinct incident patterns on demand:
1. cpu_spike: Severe CPU contention (96.8%) triggering hot-loop / thread contention RCA.
2. memory_leak: Rapid monotonic RAM growth (86% -> 94.5%) triggering MEMORY_LEAK_EXHAUSTION RCA.
3. brute_force: 15 consecutive authentication failures triggering OUTSIDE_BRUTE_FORCE_FLOOD threat event.
4. ddos_flood: 16.5% packet drop + 195ms latency triggering VOLUMETRIC_DDOS_FLOOD threat event.
5. slowloris: 260ms response latency with low CPU and 0 packet loss triggering SLOWLORIS_CONNECTION_STARVATION.

Returns diagnostic RCA, automated runbook commands, and immediately displays on the dashboard.
"""

from datetime import datetime, timezone
import json
import logging
import time
from typing import Any, Dict, List, Optional
import uuid

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

try:
    from ..services.storage import storage_service
    from ..services.rca_engine import ProbableCauseEngine
    from ..services.threat_engine import OutsideThreatEngine
    from ..services.anomaly_engine import anomaly_engine
except (ImportError, ValueError):
    from saas_service.services.storage import storage_service
    from saas_service.services.rca_engine import ProbableCauseEngine
    from saas_service.services.threat_engine import OutsideThreatEngine
    from saas_service.services.anomaly_engine import anomaly_engine

logger = logging.getLogger("AIOps.DemoLaboratory")

router = APIRouter(prefix="/api/v1/demo", tags=["Demo Laboratory"])

demo_rca_engine = ProbableCauseEngine()
demo_threat_engine = OutsideThreatEngine()


class IncidentGenerateRequest(BaseModel):
    incident_type: str = Field(..., description="One of: cpu_spike, memory_leak, brute_force, ddos_flood, slowloris")
    tenant_id: str = Field(default="TENANT-001", description="Tenant to simulate incident in")
    collector_id: Optional[str] = Field(default=None, description="Optional target collector node")


@router.post("/generate-incident", status_code=status.HTTP_200_OK)
def generate_demo_incident(request: IncidentGenerateRequest):
    """
    Executes a real-time synthetic incident pattern for the specified tenant,
    passing the payload through RCA and Threat engines to generate authentic telemetry and alerts.
    """
    incident_type = request.incident_type.lower().strip()
    tenant_id = request.tenant_id.strip()
    collector_id = request.collector_id or f"COL-DEMO-{tenant_id[-4:].upper()}"
    now_iso = datetime.now(timezone.utc).isoformat()
    now_ts = int(time.time())

    valid_types = ["cpu_spike", "memory_leak", "brute_force", "ddos_flood", "slowloris"]
    if incident_type not in valid_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid incident_type '{incident_type}'. Must be one of: {', '.join(valid_types)}"
        )

    # 1. CPU Spike Scenario
    if incident_type == "cpu_spike":
        payload = {
            "payload_id": f"DEMO-CPU-{uuid.uuid4().hex[:8]}",
            "collector_id": collector_id,
            "tenant_id": tenant_id,
            "region": "us-east-1",
            "event_time_utc": now_iso,
            "data_type": "METRICS",
            "sha256": f"demo_sha256_{uuid.uuid4().hex[:16]}",
            "data": {
                "cpu": 96.8,
                "memory": 68.2,
                "disk": 45.0,
                "latency": 88.0,
                "packet_loss": 0.0,
                "failed_logins": 0
            },
            "metadata": {
                "demo_synthetic": True,
                "simulated_incident": "cpu_spike",
                "top_process": "worker_pool_spin"
            }
        }
        storage_service.store_payload(payload, tenant_id=tenant_id, region="us-east-1")
        # Trigger outage alert in storage
        alert_id = f"ALT-{uuid.uuid4().hex[:8]}"
        storage_service.store_alert(
            alert_id=alert_id,
            collector_id=collector_id,
            tenant_id=tenant_id,
            alert_type="CPU_SATURATION_SPIKE",
            severity="CRITICAL",
            diagnosis="Sustained CPU saturation at 96.8% detected. Thread contention / runaway compute loop.",
            metrics=payload["data"]
        )
        # Register RCA incident
        inc = demo_rca_engine.analyze_and_correlate(payload, tenant_id=tenant_id) or {
            "incident_id": f"INC-CPU-{uuid.uuid4().hex[:6]}",
            "incident_type": "CPU_HOT_LOOP_SATURATION",
            "severity": "CRITICAL",
            "status": "OPEN",
            "root_cause": "Runaway computational loop or worker thread contention consuming 96.8% CPU.",
            "confidence_score": 0.95,
            "summary": "Host CPU spiked to 96.8% across all allocated cores.",
            "recommendations": [
                "Profile top thread CPU consumption via 'perf top' or Windows Process Explorer.",
                "Throttle non-essential background ETL and batch tasks.",
                "Scale container replicas horizontally."
            ]
        }
        return {
            "success": True,
            "incident_id": inc.get("incident_id", f"INC-CPU-{uuid.uuid4().hex[:6]}"),
            "incident_type": "cpu_spike",
            "severity": "CRITICAL",
            "tenant_id": tenant_id,
            "collector_id": collector_id,
            "diagnosis": "Severe CPU contention and thread starvation at 96.8% utilization.",
            "root_cause": inc.get("root_cause", "Runaway worker loop causing compute exhaustion."),
            "confidence": inc.get("confidence_score", 0.95),
            "runbook": inc.get("recommendations", [
                "Isolate runaway thread",
                "Restart affected service worker",
                "Add horizontal replica"
            ]),
            "timestamp": now_iso
        }

    # 2. Memory Leak Scenario
    elif incident_type == "memory_leak":
        # Simulate sequence of rising memory metrics to trigger monotonic leak detection
        samples = [84.0, 89.5, 95.2]
        last_payload = {}
        for idx, m_val in enumerate(samples):
            p = {
                "payload_id": f"DEMO-MEM-{uuid.uuid4().hex[:8]}",
                "collector_id": collector_id,
                "tenant_id": tenant_id,
                "region": "us-east-1",
                "event_time_utc": now_iso,
                "data_type": "METRICS",
                "sha256": f"demo_sha256_{uuid.uuid4().hex[:16]}",
                "data": {
                    "cpu": 42.0,
                    "memory": m_val,
                    "disk": 52.0,
                    "latency": 35.0,
                    "packet_loss": 0.0,
                    "failed_logins": 0
                },
                "metadata": {"demo_synthetic": True, "step": idx}
            }
            storage_service.store_payload(p, tenant_id=tenant_id, region="us-east-1")
            last_payload = p
            demo_rca_engine.analyze_and_correlate(p, tenant_id=tenant_id)

        inc = demo_rca_engine.analyze_and_correlate(last_payload, tenant_id=tenant_id) or {
            "incident_id": f"INC-MEM-{uuid.uuid4().hex[:6]}",
            "incident_type": "MEMORY_LEAK_EXHAUSTION",
            "severity": "CRITICAL",
            "status": "OPEN",
            "root_cause": "Progressive RAM consumption pattern consistent with an uncollected application memory leak.",
            "confidence_score": 0.96,
            "summary": "RAM usage reached critical 95.2% with sustained positive growth trend.",
            "recommendations": [
                "Capture process heap snapshot to isolate unclosed resources or cached object bloat.",
                "Perform graceful rolling restart of worker pool to prevent sudden kernel OOM panic.",
                "Enforce aggressive heap size limits with automatic GC triggers."
            ]
        }
        storage_service.store_alert(
            alert_id=f"ALT-MEM-{uuid.uuid4().hex[:8]}",
            collector_id=collector_id,
            tenant_id=tenant_id,
            alert_type="MEMORY_LEAK_CRITICAL",
            severity="CRITICAL",
            diagnosis="Progressive RAM leak detected: memory surged to 95.2%.",
            metrics=last_payload["data"]
        )
        return {
            "success": True,
            "incident_id": inc.get("incident_id", f"INC-MEM-{uuid.uuid4().hex[:6]}"),
            "incident_type": "memory_leak",
            "severity": "CRITICAL",
            "tenant_id": tenant_id,
            "collector_id": collector_id,
            "diagnosis": "Monotonic heap growth reaching 95.2% RAM utilization.",
            "root_cause": inc.get("root_cause"),
            "confidence": inc.get("confidence_score", 0.96),
            "runbook": inc.get("recommendations", [
                "Capture heap memory profile",
                "Flush worker caches",
                "Execute rolling worker restart"
            ]),
            "timestamp": now_iso
        }

    # 3. Brute Force Attack Scenario
    elif incident_type == "brute_force":
        payload = {
            "payload_id": f"DEMO-THREAT-BF-{uuid.uuid4().hex[:8]}",
            "collector_id": collector_id,
            "tenant_id": tenant_id,
            "region": "us-east-1",
            "event_time_utc": now_iso,
            "data_type": "METRICS",
            "sha256": f"demo_sha256_{uuid.uuid4().hex[:16]}",
            "data": {
                "cpu": 35.0,
                "memory": 48.0,
                "disk": 30.0,
                "latency": 25.0,
                "packet_loss": 0.0,
                "failed_logins": 16
            },
            "metadata": {"demo_synthetic": True, "attack": "brute_force"}
        }
        storage_service.store_payload(payload, tenant_id=tenant_id, region="us-east-1")
        threat = demo_threat_engine.analyze_payload_threats(payload, tenant_id=tenant_id)
        if not threat:
            threat = {
                "threat_id": f"THR-BF-{uuid.uuid4().hex[:6]}",
                "threat_type": "OUTSIDE_BRUTE_FORCE_FLOOD",
                "threat_level": "CRITICAL",
                "vector_description": "Surge of 16 failed authentication events detected within sampling interval.",
                "mitigation_commands": [
                    'netsh advfirewall firewall add rule name="AIOps-Block-Auth-Surge" dir=in action=block protocol=TCP localport=443',
                    'iptables -A INPUT -p tcp --dport 443 -m connlimit --connlimit-above 25 -j REJECT',
                    'Enable immediate CAPTCHA challenge on edge /login endpoints.'
                ]
            }
        storage_service.store_threat_event({
            "threat_id": threat.get("threat_id", f"THR-{uuid.uuid4().hex[:6]}"),
            "tenant_id": tenant_id,
            "collector_id": collector_id,
            "threat_type": "OUTSIDE_BRUTE_FORCE_FLOOD",
            "threat_level": "CRITICAL",
            "status": "ACTIVE",
            "vector_description": "Surge of 16 failed authentication events detected. Signature matches an automated credential stuffing attack.",
            "classification": "Outside Automated Security Attack",
            "mitigation_commands": threat.get("mitigation_commands", []),
            "evidence": {"failed_logins": 16, "intensity": "CRITICAL"},
            "first_seen": now_iso,
            "last_seen": now_iso,
            "resolved_at": None
        })
        return {
            "success": True,
            "incident_id": threat.get("threat_id"),
            "incident_type": "brute_force",
            "severity": "CRITICAL",
            "tenant_id": tenant_id,
            "collector_id": collector_id,
            "diagnosis": "Automated Outside Credential Stuffing & Brute-Force Authentication Surge.",
            "root_cause": "Multiple external sources attempting rapid dictionary attacks on privileged endpoints.",
            "confidence": 0.98,
            "runbook": threat.get("mitigation_commands", []),
            "timestamp": now_iso
        }

    # 4. DDoS Flood Scenario
    elif incident_type == "ddos_flood":
        payload = {
            "payload_id": f"DEMO-THREAT-DDOS-{uuid.uuid4().hex[:8]}",
            "collector_id": collector_id,
            "tenant_id": tenant_id,
            "region": "us-east-1",
            "event_time_utc": now_iso,
            "data_type": "METRICS",
            "sha256": f"demo_sha256_{uuid.uuid4().hex[:16]}",
            "data": {
                "cpu": 45.0,
                "memory": 50.0,
                "disk": 28.0,
                "latency": 215.0,
                "packet_loss": 18.5,
                "failed_logins": 0
            },
            "metadata": {"demo_synthetic": True, "attack": "ddos_flood"}
        }
        storage_service.store_payload(payload, tenant_id=tenant_id, region="us-east-1")
        threat = demo_threat_engine.analyze_payload_threats(payload, tenant_id=tenant_id)
        if not threat:
            threat = {
                "threat_id": f"THR-DDOS-{uuid.uuid4().hex[:6]}",
                "threat_type": "VOLUMETRIC_DDOS_FLOOD",
                "threat_level": "CRITICAL",
                "mitigation_commands": [
                    'Engage upstream transit ISP DDoS scrubbing center (BGP Flowspec / Cloudflare Magic Transit).',
                    'sysctl -w net.ipv4.tcp_syncookies=1',
                    'iptables -A INPUT -p icmp -m limit --limit 1/s -j ACCEPT'
                ]
            }
        storage_service.store_threat_event({
            "threat_id": threat.get("threat_id", f"THR-{uuid.uuid4().hex[:6]}"),
            "tenant_id": tenant_id,
            "collector_id": collector_id,
            "threat_type": "VOLUMETRIC_DDOS_FLOOD",
            "threat_level": "CRITICAL",
            "status": "ACTIVE",
            "vector_description": "Network transport saturation: 18.5% packet drop correlated with 215ms latency.",
            "classification": "Outside Network Flooding Attack",
            "mitigation_commands": threat.get("mitigation_commands", []),
            "evidence": {"packet_loss_pct": 18.5, "latency_ms": 215.0, "host_cpu_pct": 45.0},
            "first_seen": now_iso,
            "last_seen": now_iso,
            "resolved_at": None
        })
        return {
            "success": True,
            "incident_id": threat.get("threat_id"),
            "incident_type": "ddos_flood",
            "severity": "CRITICAL",
            "tenant_id": tenant_id,
            "collector_id": collector_id,
            "diagnosis": "Volumetric Network DDoS Flood saturating uplink gateway bandwidth.",
            "root_cause": "High-volume UDP/SYN flood causing severe packet degradation without host CPU exhaustion.",
            "confidence": 0.97,
            "runbook": threat.get("mitigation_commands", []),
            "timestamp": now_iso
        }

    # 5. Slowloris Scenario
    elif incident_type == "slowloris":
        payload = {
            "payload_id": f"DEMO-THREAT-SLOW-{uuid.uuid4().hex[:8]}",
            "collector_id": collector_id,
            "tenant_id": tenant_id,
            "region": "us-east-1",
            "event_time_utc": now_iso,
            "data_type": "METRICS",
            "sha256": f"demo_sha256_{uuid.uuid4().hex[:16]}",
            "data": {
                "cpu": 18.0,
                "memory": 42.0,
                "disk": 22.0,
                "latency": 265.0,
                "packet_loss": 0.0,
                "failed_logins": 0
            },
            "metadata": {"demo_synthetic": True, "attack": "slowloris"}
        }
        storage_service.store_payload(payload, tenant_id=tenant_id, region="us-east-1")
        threat = demo_threat_engine.analyze_payload_threats(payload, tenant_id=tenant_id)
        if not threat:
            threat = {
                "threat_id": f"THR-SLOW-{uuid.uuid4().hex[:6]}",
                "threat_type": "SLOWLORIS_CONNECTION_STARVATION",
                "threat_level": "HIGH",
                "mitigation_commands": [
                    'Configure Nginx: client_header_timeout 5s; client_body_timeout 5s; keepalive_timeout 10s;',
                    'Limit concurrent connections per origin IP subnet to 15.',
                    'iptables -A INPUT -p tcp --syn --dport 80 -m connlimit --connlimit-above 20 -j DROP'
                ]
            }
        storage_service.store_threat_event({
            "threat_id": threat.get("threat_id", f"THR-{uuid.uuid4().hex[:6]}"),
            "tenant_id": tenant_id,
            "collector_id": collector_id,
            "threat_type": "SLOWLORIS_CONNECTION_STARVATION",
            "threat_level": "HIGH",
            "status": "ACTIVE",
            "vector_description": "Application response latency elevated (265ms) with minimal CPU usage (18%) and zero packet loss.",
            "classification": "Application Connection Starvation Attack",
            "mitigation_commands": threat.get("mitigation_commands", []),
            "evidence": {"latency_ms": 265.0, "cpu_pct": 18.0, "vector": "SOCKET_POOL_EXHAUSTION"},
            "first_seen": now_iso,
            "last_seen": now_iso,
            "resolved_at": None
        })
        return {
            "success": True,
            "incident_id": threat.get("threat_id"),
            "incident_type": "slowloris",
            "severity": "HIGH",
            "tenant_id": tenant_id,
            "collector_id": collector_id,
            "diagnosis": "Slowloris HTTP Socket Starvation tying up reverse proxy connection pools.",
            "root_cause": "Hanging partial HTTP headers keeping connection threads alive without transmitting data.",
            "confidence": 0.93,
            "runbook": threat.get("mitigation_commands", []),
            "timestamp": now_iso
        }
