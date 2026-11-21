"""
Ingestion Route.
Endpoint: POST /ingest
Validates API-Key, validates SHA-256 checksum, and performs idempotent storage.
"""

from typing import Any, Dict
from fastapi import APIRouter, Depends, HTTPException, status

try:
    from ..services.auth import auth_service
    from ..services.checksum import checksum_service
    from ..services.deduplication import deduplication_service
    from ..services.storage import storage_service
    from ..services.anomaly_engine import anomaly_engine
    from ..services.watchdog import watchdog
    from ..services.rca_engine import rca_engine
    from ..services.seasonal_engine import seasonal_engine
    from ..services.threat_engine import threat_engine
except (ImportError, ValueError):
    from saas_service.services.auth import auth_service
    from saas_service.services.checksum import checksum_service
    from saas_service.services.deduplication import deduplication_service
    from saas_service.services.storage import storage_service
    from saas_service.services.anomaly_engine import anomaly_engine
    from saas_service.services.watchdog import watchdog
    from saas_service.services.rca_engine import rca_engine
    from saas_service.services.seasonal_engine import seasonal_engine
    from saas_service.services.threat_engine import threat_engine

router = APIRouter(tags=["Ingestion"])


@router.post("/ingest", status_code=status.HTTP_200_OK)
def ingest_payload(
    payload: Dict[str, Any],
    auth_ctx: Dict[str, str] = Depends(auth_service.authenticate_request)
):
    """
    Ingests sanitized telemetry payloads from edge collectors.
    1. Authenticates X-Collector-Key
    2. Validates server-side SHA256 checksum
    3. Guarantees idempotency (returns {"duplicate": true} if already processed)
    """
    if "payload_id" not in payload:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "missing_payload_id", "message": "payload_id is required."}
        )

    # Attach tenant context resolved from authentication if not present
    tenant_id = auth_ctx["tenant_id"]
    if "tenant_id" not in payload:
        payload["tenant_id"] = tenant_id

    collector_id = payload.get("collector_id", auth_ctx["collector_id"])
    incoming_region = payload.get("region") or auth_ctx.get("region", "us-east-1")

    # Task D: Regional Ingest Routing & Legal Data Residency Validation
    is_valid_residency, residency_reason = storage_service.validate_tenant_residency(tenant_id, incoming_region)
    if not is_valid_residency:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "residency_violation", "message": residency_reason}
        )

    # Feature 3: Server-side SHA256 validation
    checksum_service.validate_payload_checksum(payload)

    # Feature 4 & Task B: Idempotent processing with Ingest Watermarking
    is_duplicate, response_data = deduplication_service.process_payload(
        payload,
        tenant_id=tenant_id,
        region=incoming_region
    )

    if not is_duplicate:
        # Task F: Update activity and restore health state
        metadata = payload.get("metadata", {})
        sys_health = metadata.get("system_health", "Healthy")
        if sys_health == "HEALTHY":
            target_health = "Healthy"
        elif sys_health in ("WARNING", "DEGRADED"):
            target_health = "Degraded"
        elif sys_health in ("CRITICAL", "POOR"):
            target_health = "Critical"
        else:
            target_health = "Healthy"

        storage_service.update_collector_heartbeat(
            collector_id=collector_id,
            tenant_id=tenant_id,
            region=incoming_region,
            version=payload.get("version", "1.0.0"),
            status=target_health
        )
        watchdog.on_collector_activity(collector_id, target_health)

        # Task E: Real-time Contextual Anomaly Detection
        anomaly = anomaly_engine.analyze_telemetry_payload(payload, tenant_id=tenant_id)
        if anomaly:
            response_data["anomaly_alert"] = anomaly

        # Phase 4: Probable Cause Engine (RCA) & Incident Correlation
        incident = rca_engine.analyze_and_correlate(payload, tenant_id=tenant_id)
        if incident:
            response_data["incident"] = {
                "incident_id": incident["incident_id"],
                "incident_type": incident["incident_type"],
                "severity": incident["severity"],
                "root_cause": incident["root_cause"],
                "confidence_score": incident["confidence_score"]
            }

        # Phase 4.5: Self-Learning Seasonal Profiler & Fluctuation Advisory
        fluctuations = seasonal_engine.analyze_payload_fluctuations(payload, tenant_id=tenant_id)
        if fluctuations:
            response_data["seasonal_fluctuations"] = fluctuations

        # Phase 4.5: Outside Cyber Attack Detection
        threat = threat_engine.analyze_payload_threats(payload, tenant_id=tenant_id)
        if threat:
            response_data["threat_event"] = {
                "threat_id": threat["threat_id"],
                "threat_type": threat["threat_type"],
                "threat_level": threat["threat_level"],
                "classification": threat["classification"]
            }

    return response_data
