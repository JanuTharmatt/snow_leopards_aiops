"""
Heartbeat Route.
Endpoint: POST /heartbeat
Tracks fleet monitoring, agent status, and updates last_seen in Collector Registry.
"""

from typing import Any, Dict, Optional
from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, Field

try:
    from ..services.auth import auth_service
    from ..services.storage import storage_service
except (ImportError, ValueError):
    from saas_service.services.auth import auth_service
    from saas_service.services.storage import storage_service

router = APIRouter(tags=["Heartbeat"])


class HeartbeatRequest(BaseModel):
    """
    Heartbeat payload matching exact specification:
    {
      "collector_id": "COLL-001",
      "version": "1.0.0",
      "status": "ONLINE",
      "timestamp": "UTC"
    }
    """
    collector_id: str = Field(..., description="Unique collector identifier")
    version: str = Field(default="1.0.0", description="Agent version string")
    status: str = Field(default="ONLINE", description="Collector status (ONLINE | DEGRADED | SHUTDOWN)")
    timestamp: str = Field(..., description="UTC ISO-8601 timestamp")


@router.post("/heartbeat", status_code=status.HTTP_200_OK)
def receive_heartbeat(
    request: HeartbeatRequest,
    auth_ctx: Dict[str, str] = Depends(auth_service.authenticate_request)
):
    """
    Receives periodic agent heartbeats and updates the Collector Registry.
    """
    tenant_id = auth_ctx["tenant_id"]
    region = auth_ctx.get("region", "us-east-1")

    registry_entry = storage_service.update_collector_heartbeat(
        collector_id=request.collector_id,
        tenant_id=tenant_id,
        region=region,
        version=request.version,
        status=request.status,
        heartbeat_timestamp=request.timestamp
    )

    return {
        "status": "ACK",
        "message": "Heartbeat registered successfully.",
        "collector": registry_entry
    }
