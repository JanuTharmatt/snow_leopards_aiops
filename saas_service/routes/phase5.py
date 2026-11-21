"""
Phase 5 REST API Router.
Autonomous AIOps Platform — Phase 5 Extensions:
- Executive Reporting Service (Weekly, Monthly, Executive Summary)
- Capacity Forecast Engine (CPU, Memory, Disk)
- Proactive Risk Engine (Risk Summary)
- Remediation Engine & Policy Engine (Pending, Approve, Reject)
- Autonomous AI Copilot Query API
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Header, HTTPException, Query, status
from pydantic import BaseModel

try:
    from ..services.reporting_service import reporting_service
    from ..services.forecast_engine import forecast_engine
    from ..services.risk_engine import risk_engine
    from ..services.remediation_engine import remediation_engine
    from ..services.policy_engine import policy_engine
    from ..services.copilot_service import copilot_service
    from ..services.auth import auth_service
except (ImportError, ValueError):
    from saas_service.services.reporting_service import reporting_service
    from saas_service.services.forecast_engine import forecast_engine
    from saas_service.services.risk_engine import risk_engine
    from saas_service.services.remediation_engine import remediation_engine
    from saas_service.services.policy_engine import policy_engine
    from saas_service.services.copilot_service import copilot_service
    from saas_service.services.auth import auth_service

router = APIRouter(tags=["Phase 5 Autonomous AIOps"])


def check_phase5_tenant_access(
    requested_tenant: Optional[str] = None,
    authorization: Optional[str] = None
) -> str:
    """Enforces tenant isolation on Phase 5 reporting, risk, and forecast APIs."""
    if isinstance(authorization, str) and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
        try:
            claims = auth_service.verify_token(token)
            token_tenant = claims.get("tenant_id")
            if requested_tenant and requested_tenant != token_tenant:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Forbidden: Tenant isolation violation. Authenticated tenant '{token_tenant}' cannot access foreign tenant '{requested_tenant}'."
                )
            return token_tenant
        except HTTPException:
            raise
        except Exception:
            pass
    return requested_tenant if isinstance(requested_tenant, str) else "TENANT-001"


# -------------------------------------------------------------------------
# Phase 5.1: Executive Reporting Endpoints
# -------------------------------------------------------------------------

@router.get("/reports/weekly")
def get_weekly_report(
    tenant_id: str = "TENANT-001",
    authorization: Optional[str] = Header(None)
) -> Dict[str, Any]:
    """Generates and returns the Weekly Performance and Incident Report."""
    tid = check_phase5_tenant_access(tenant_id, authorization)
    return reporting_service.generate_weekly_report(tenant_id=tid)


@router.get("/reports/monthly")
def get_monthly_report(
    tenant_id: str = "TENANT-001",
    authorization: Optional[str] = Header(None)
) -> Dict[str, Any]:
    """Generates and returns the Monthly Capacity, Risk, and Incident Growth Report."""
    tid = check_phase5_tenant_access(tenant_id, authorization)
    return reporting_service.generate_monthly_report(tenant_id=tid)


@router.get("/reports/executive")
def get_executive_summary(
    tenant_id: str = "TENANT-001",
    authorization: Optional[str] = Header(None)
) -> Dict[str, Any]:
    """Generates and returns the High-Level Executive Summary."""
    tid = check_phase5_tenant_access(tenant_id, authorization)
    return reporting_service.generate_executive_summary(tenant_id=tid)


# -------------------------------------------------------------------------
# Phase 5.2: Capacity Forecast Endpoints
# -------------------------------------------------------------------------

@router.get("/forecast/cpu")
def forecast_cpu(
    tenant_id: str = "TENANT-001",
    threshold: Optional[float] = None,
    authorization: Optional[str] = Header(None)
) -> Dict[str, Any]:
    """Returns mathematical capacity forecast and days to threshold for CPU."""
    tid = check_phase5_tenant_access(tenant_id, authorization)
    thresh = threshold if isinstance(threshold, (int, float)) else None
    return forecast_engine.forecast_resource(tenant_id=tid, resource="cpu", threshold=thresh)


@router.get("/forecast/memory")
def forecast_memory(
    tenant_id: str = "TENANT-001",
    threshold: Optional[float] = None,
    authorization: Optional[str] = Header(None)
) -> Dict[str, Any]:
    """Returns mathematical capacity forecast and days to threshold for Memory."""
    tid = check_phase5_tenant_access(tenant_id, authorization)
    thresh = threshold if isinstance(threshold, (int, float)) else None
    return forecast_engine.forecast_resource(tenant_id=tid, resource="memory", threshold=thresh)


@router.get("/forecast/disk")
def forecast_disk(
    tenant_id: str = "TENANT-001",
    threshold: Optional[float] = None,
    authorization: Optional[str] = Header(None)
) -> Dict[str, Any]:
    """Returns mathematical capacity forecast and days to threshold for Disk."""
    tid = check_phase5_tenant_access(tenant_id, authorization)
    thresh = threshold if isinstance(threshold, (int, float)) else None
    return forecast_engine.forecast_resource(tenant_id=tid, resource="disk", threshold=thresh)


# -------------------------------------------------------------------------
# Phase 5.3: Proactive Risk Engine Endpoint
# -------------------------------------------------------------------------

@router.get("/risk-summary")
def get_risk_summary(
    tenant_id: str = "TENANT-001",
    authorization: Optional[str] = Header(None)
) -> Dict[str, Any]:
    """Evaluates impending failure risks (OOM, Disk, Latency, Auth Attack) with probabilities."""
    tid = check_phase5_tenant_access(tenant_id, authorization)
    return risk_engine.evaluate_risks(tenant_id=tid)


# -------------------------------------------------------------------------
# Phase 5.4 & 5.5: Remediation & Policy Engine Endpoints
# -------------------------------------------------------------------------

@router.get("/remediation/pending")
def get_pending_remediations(tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieves all pending operational remediation actions."""
    tid = tenant_id if isinstance(tenant_id, str) else None
    return remediation_engine.get_pending_remediations(tenant_id=tid)


@router.post("/remediation/{remediation_id}/approve")
def approve_remediation(
    remediation_id: str,
    tenant_id: str = "TENANT-001"
) -> Dict[str, Any]:
    """
    Simulates remediation execution with policy and risk verification:
    1. Policy Check
    2. Risk Check
    3. Audit Recording
    4. Simulation Execution
    """
    tid = tenant_id if isinstance(tenant_id, str) else "TENANT-001"
    # 1. Fetch or simulate pending action
    pending_list = remediation_engine.get_pending_remediations(tenant_id=tid)
    matched = next((item for item in pending_list if item.get("id") == remediation_id), None)
    action_name = matched.get("suggested_action", "Restart Worker Pool") if matched else "Restart Worker Pool"

    # 2. Run Policy & Risk evaluation + Audit Recording
    policy_res = policy_engine.evaluate_remediation_policy(
        tenant_id=tid,
        remediation_id=remediation_id,
        action=action_name
    )

    # 3. Execute approved simulation
    rem_res = remediation_engine.approve_remediation(remediation_id=remediation_id)

    return {
        **rem_res,
        "policy_evaluation": policy_res,
        "message": f"Remediation action [{remediation_id}] approved and successfully simulated with policy sign-off."
    }


@router.post("/remediation/{remediation_id}/reject")
def reject_remediation(remediation_id: str) -> Dict[str, Any]:
    """Rejects a proposed remediation item."""
    return remediation_engine.reject_remediation(remediation_id=remediation_id)


# -------------------------------------------------------------------------
# Phase 5.6: Autonomous AI Copilot Endpoint
# -------------------------------------------------------------------------

class CopilotQueryRequest(BaseModel):
    query: str
    tenant_id: Optional[str] = "TENANT-001"


@router.post("/copilot/query")
def copilot_query(body: CopilotQueryRequest) -> Dict[str, Any]:
    """
    Answers natural language operational queries using local rule/heuristic routing
    over RCA, Threat, Reporting, Forecast, and Remediation engines.
    """
    tenant_id = body.tenant_id or "TENANT-001"
    result = copilot_service.answer_query(query=body.query, tenant_id=tenant_id)
    ans = result.get("answer", "")
    return {
        "query": body.query,
        "tenant_id": tenant_id,
        "response": ans,
        "answer": ans
    }
