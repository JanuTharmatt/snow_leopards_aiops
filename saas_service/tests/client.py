"""
Phase 5 Test API Client.
In-memory synchronous HTTP test client for deterministic, deadlock-free
testing of Phase 5 REST APIs on Windows environments.
"""

from typing import Any, Dict, Optional
from urllib.parse import parse_qs, urlparse

from saas_service.routes.phase5 import (
    get_weekly_report,
    get_monthly_report,
    get_executive_summary,
    forecast_cpu,
    forecast_memory,
    forecast_disk,
    get_risk_summary,
    get_pending_remediations,
    approve_remediation,
    reject_remediation,
    copilot_query,
    CopilotQueryRequest
)


class ApiResponse:
    """Mock HTTP Response encapsulating status_code and JSON payload."""

    def __init__(self, status_code: int, data: Any):
        self.status_code = status_code
        self._data = data

    def json(self) -> Any:
        return self._data


class TestApiClient:
    """Synchronous in-memory API client dispatching requests to Phase 5 routers."""

    def get(self, url: str) -> ApiResponse:
        parsed = urlparse(url)
        path = parsed.path.rstrip("/")
        qs = parse_qs(parsed.query)

        tenant_id = qs.get("tenant_id", ["TENANT-001"])[0]
        threshold_val = qs.get("threshold", [None])[0]
        thresh = float(threshold_val) if threshold_val is not None else None

        # Normalize /api/v1 prefix
        if path.startswith("/api/v1"):
            path = path[len("/api/v1"):]

        if path == "/reports/weekly":
            return ApiResponse(200, get_weekly_report(tenant_id=tenant_id))
        elif path == "/reports/monthly":
            return ApiResponse(200, get_monthly_report(tenant_id=tenant_id))
        elif path == "/reports/executive":
            return ApiResponse(200, get_executive_summary(tenant_id=tenant_id))
        elif path == "/forecast/cpu":
            return ApiResponse(200, forecast_cpu(tenant_id=tenant_id, threshold=thresh))
        elif path == "/forecast/memory":
            return ApiResponse(200, forecast_memory(tenant_id=tenant_id, threshold=thresh))
        elif path == "/forecast/disk":
            return ApiResponse(200, forecast_disk(tenant_id=tenant_id, threshold=thresh))
        elif path == "/risk-summary":
            return ApiResponse(200, get_risk_summary(tenant_id=tenant_id))
        elif path == "/remediation/pending":
            return ApiResponse(200, get_pending_remediations(tenant_id=tenant_id))
        else:
            return ApiResponse(404, {"detail": f"Route not found: {path}"})

    def post(self, url: str, json: Optional[Dict[str, Any]] = None) -> ApiResponse:
        parsed = urlparse(url)
        path = parsed.path.rstrip("/")
        qs = parse_qs(parsed.query)
        tenant_id = qs.get("tenant_id", ["TENANT-001"])[0]

        # Normalize /api/v1 prefix
        if path.startswith("/api/v1"):
            path = path[len("/api/v1"):]

        if path == "/copilot/query":
            req_data = json or {}
            query_str = req_data.get("query", "")
            tid = req_data.get("tenant_id", tenant_id)
            req = CopilotQueryRequest(query=query_str, tenant_id=tid)
            return ApiResponse(200, copilot_query(req))
        elif path.startswith("/remediation/") and path.endswith("/approve"):
            parts = path.split("/")
            # /remediation/{id}/approve
            rem_id = parts[2]
            return ApiResponse(200, approve_remediation(remediation_id=rem_id, tenant_id=tenant_id))
        elif path.startswith("/remediation/") and path.endswith("/reject"):
            parts = path.split("/")
            # /remediation/{id}/reject
            rem_id = parts[2]
            return ApiResponse(200, reject_remediation(remediation_id=rem_id))
        else:
            return ApiResponse(404, {"detail": f"Route not found: {path}"})
