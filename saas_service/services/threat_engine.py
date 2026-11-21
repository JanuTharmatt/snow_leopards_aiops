"""
Outside Cyber Attack Detection Engine.
Phase 4.5 Core:
- Detects attacks originating from outside the network:
  1. Brute-Force / Credential Stuffing Floods
  2. Volumetric Network DDoS Floods
  3. Slowloris / HTTP Connection Exhaustion
- Generates copy-paste mitigation firewall & defensive runbooks
- Alert Suppression & Cooldown (tracks duration without alert fatigue spam)
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

try:
    from .storage import storage_service
except (ImportError, ValueError):
    from saas_service.services.storage import storage_service


class OutsideThreatEngine:
    """
    Analyzes sanitized telemetry for outside cyber attack signatures,
    calculates threat levels, and provides actionable defense scripts.
    """

    def __init__(self, recovery_threshold: int = 3):
        self.recovery_threshold = recovery_threshold
        # collector_id -> count of calm cycles
        self.calm_cycles: Dict[str, int] = {}

    def analyze_payload_threats(
        self,
        payload: Dict[str, Any],
        tenant_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Evaluates incoming payload against outside cyber attack patterns.
        Returns active threat event if detected, else None.
        """
        data = payload.get("data", {})
        if not data or payload.get("data_type") != "METRICS":
            return None

        collector_id = payload.get("collector_id", "COLL-UNKNOWN")
        cpu = float(data.get("cpu", 0.0))
        latency = float(data.get("latency", 0.0))
        packet_loss = float(data.get("packet_loss", 0.0))
        failed_logins = int(data.get("failed_logins", 0) or 0)
        timestamp = payload.get("event_time_utc") or datetime.now(timezone.utc).isoformat()

        threat_type: Optional[str] = None
        threat_level = "LOW"
        vector_description = ""
        classification = "BENIGN_TRAFFIC"
        mitigation_commands: List[str] = []
        evidence: Dict[str, Any] = {}

        # -------------------------------------------------------------
        # Attack Signature 1: Outside Brute-Force / Credential Stuffing Flood
        # -------------------------------------------------------------
        if failed_logins >= 5:
            threat_type = "OUTSIDE_BRUTE_FORCE_FLOOD"
            threat_level = "CRITICAL" if failed_logins >= 10 else "HIGH"
            classification = "Outside Automated Security Attack"
            vector_description = (
                f"Surge of {failed_logins} failed authentication events detected within sampling interval. "
                "Signature matches an automated credential stuffing, dictionary attack, or API key brute-force sweep."
            )
            mitigation_commands = [
                'netsh advfirewall firewall add rule name="AIOps-Block-Auth-Surge" dir=in action=block protocol=TCP localport=443',
                'iptables -A INPUT -p tcp --dport 443 -m connlimit --connlimit-above 25 -j REJECT',
                'Enable immediate CAPTCHA challenge and temporary account lockout on edge /login endpoints.'
            ]
            evidence = {
                "failed_logins_count": failed_logins,
                "vector": "AUTHENTICATION_FLOOD",
                "attack_intensity": "HIGH" if failed_logins >= 10 else "MODERATE"
            }

        # -------------------------------------------------------------
        # Attack Signature 2: Volumetric Network DDoS Flood
        # -------------------------------------------------------------
        elif packet_loss >= 12.0 and latency >= 150.0 and cpu <= 88.0:
            threat_type = "VOLUMETRIC_DDOS_FLOOD"
            threat_level = "CRITICAL"
            classification = "Outside Network Flooding Attack"
            vector_description = (
                f"Network transport saturation: {packet_loss:.1f}% packet drop correlated with {latency:.1f}ms latency. "
                "Low CPU indicates the bottleneck is uplink capacity saturation (DDoS packet flood) rather than host compute failure."
            )
            mitigation_commands = [
                'Engage upstream transit ISP DDoS scrubbing center (BGP Flowspec / Cloudflare Magic Transit).',
                'sysctl -w net.ipv4.tcp_syncookies=1',
                'iptables -A INPUT -p icmp -m limit --limit 1/s -j ACCEPT'
            ]
            evidence = {
                "packet_loss_pct": packet_loss,
                "latency_ms": latency,
                "host_cpu_pct": cpu,
                "vector": "UPLINK_BANDWIDTH_SATURATION"
            }

        # -------------------------------------------------------------
        # Attack Signature 3: Slowloris Connection Pool Starvation
        # -------------------------------------------------------------
        elif latency >= 220.0 and cpu <= 35.0 and packet_loss <= 2.0:
            threat_type = "SLOWLORIS_CONNECTION_STARVATION"
            threat_level = "HIGH"
            classification = "Application Connection Starvation Attack"
            vector_description = (
                f"Application response latency elevated ({latency:.1f}ms) with minimal CPU usage ({cpu:.1f}%) and zero packet loss. "
                "Signature indicates application worker thread/socket pool exhaustion from slow-read (Slowloris) HTTP clients."
            )
            mitigation_commands = [
                'Configure Nginx: client_header_timeout 5s; client_body_timeout 5s; keepalive_timeout 10s;',
                'Limit concurrent connections per origin IP subnet to 15.',
                'iptables -A INPUT -p tcp --syn --dport 80 -m connlimit --connlimit-above 20 -j DROP'
            ]
            evidence = {
                "latency_ms": latency,
                "host_cpu_pct": cpu,
                "vector": "SOCKET_POOL_EXHAUSTION"
            }

        # -------------------------------------------------------------
        # Alert Cooldown & State Tracking
        # -------------------------------------------------------------
        if threat_type:
            self.calm_cycles[collector_id] = 0

            # Check for existing active threat to suppress repetitive alert fatigue
            active = storage_service.get_active_threat(
                tenant_id=tenant_id,
                collector_id=collector_id,
                threat_type=threat_type
            )

            if active:
                # Update ongoing threat (update last_seen and peak metrics)
                storage_service.update_threat_event(
                    threat_id=active["threat_id"],
                    updates={
                        "threat_level": threat_level,
                        "vector_description": vector_description,
                        "evidence": evidence
                    }
                )
                active["threat_level"] = threat_level
                active["vector_description"] = vector_description
                active["evidence"] = evidence
                return active
            else:
                # Store new threat event
                threat_id = f"THREAT-{datetime.now(timezone.utc).year}-{uuid.uuid4().hex[:8].upper()}"
                threat_record = {
                    "threat_id": threat_id,
                    "tenant_id": tenant_id,
                    "collector_id": collector_id,
                    "threat_type": threat_type,
                    "threat_level": threat_level,
                    "status": "ACTIVE",
                    "vector_description": vector_description,
                    "classification": classification,
                    "mitigation_commands": mitigation_commands,
                    "evidence": evidence,
                    "first_seen": timestamp,
                    "last_seen": timestamp
                }
                storage_service.store_threat_event(threat_record)
                return threat_record

        else:
            # Clean cycle
            self.calm_cycles[collector_id] = self.calm_cycles.get(collector_id, 0) + 1
            if self.calm_cycles[collector_id] >= self.recovery_threshold:
                # Auto-resolve active threats for this collector
                resolved = storage_service.resolve_threat_events_for_collector(collector_id)
                if resolved > 0:
                    self.calm_cycles[collector_id] = 0
            return None


threat_engine = OutsideThreatEngine()
