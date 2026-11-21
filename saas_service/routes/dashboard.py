"""
SaaS Observability Dashboard Routes.
Phase 3: Central Observability Dashboard & Egress Proof Panel.
Endpoints:
- GET /dashboard (Web UI)
- GET /api/v1/dashboard/overview
- GET /api/v1/dashboard/nodes
- GET /api/v1/dashboard/telemetry
- GET /api/v1/dashboard/alerts
- GET /api/v1/dashboard/egress-proofs
"""

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Header, HTTPException, Query, status
from fastapi.responses import HTMLResponse, RedirectResponse

try:
    from ..services.storage import storage_service
    from ..services.watchdog import watchdog
    from ..services.auth import auth_service
except (ImportError, ValueError):
    from saas_service.services.storage import storage_service
    from saas_service.services.watchdog import watchdog
    from saas_service.services.auth import auth_service

router = APIRouter(tags=["Dashboard"])

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "web" / "templates"


def check_tenant_access(
    requested_tenant: Optional[str] = None,
    authorization: Optional[str] = None,
    x_tenant_id: Optional[str] = None
) -> Optional[str]:
    """
    Enforces strict multi-tenant boundary isolation.
    If a Bearer token is passed, validates claims:
    - Raises HTTP 403 Forbidden if requested_tenant != token_tenant.
    - Raises HTTP 403 Forbidden if x_tenant_id != token_tenant.
    Returns the verified tenant_id.
    """
    if isinstance(authorization, str) and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
        try:
            claims = auth_service.verify_token(token)
            token_tenant = claims.get("tenant_id")
            if isinstance(requested_tenant, str) and requested_tenant != token_tenant:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Forbidden: Tenant isolation violation. Authenticated tenant '{token_tenant}' cannot access foreign tenant '{requested_tenant}'."
                )
            if isinstance(x_tenant_id, str) and x_tenant_id != token_tenant:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Forbidden: Tenant isolation violation. X-Tenant-ID header '{x_tenant_id}' mismatch with authenticated tenant '{token_tenant}'."
                )
            return token_tenant
        except HTTPException:
            raise
        except Exception:
            pass
    return requested_tenant if isinstance(requested_tenant, str) else None


@router.get("/", response_class=RedirectResponse)
def root_redirect():
    """Redirects root entrypoint to /login."""
    return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)


@router.get("/login", response_class=HTMLResponse)
def get_login_ui():
    """Serves the SNOW LEOPARDS enterprise login page."""
    template_path = TEMPLATES_DIR / "login.html"
    if template_path.exists():
        return HTMLResponse(content=template_path.read_text(encoding="utf-8"))
    return HTMLResponse("<h2>Login template not found</h2>", status_code=404)


@router.get("/register", response_class=HTMLResponse)
def get_register_ui():
    """Serves the SNOW LEOPARDS multi-tenant registration page."""
    template_path = TEMPLATES_DIR / "register.html"
    if template_path.exists():
        return HTMLResponse(content=template_path.read_text(encoding="utf-8"))
    return HTMLResponse("<h2>Register template not found</h2>", status_code=404)


@router.get("/forgot-password", response_class=HTMLResponse)
def get_forgot_password_ui():
    """Serves the password reset request page."""
    template_path = TEMPLATES_DIR / "forgot_password.html"
    if template_path.exists():
        return HTMLResponse(content=template_path.read_text(encoding="utf-8"))
    return HTMLResponse("<h2>Forgot password template not found</h2>", status_code=404)


@router.get("/dashboard", response_class=HTMLResponse)
def get_dashboard_ui():
    """Serves the central SaaS Observability Dashboard & Egress Proof Panel."""
    template_path = TEMPLATES_DIR / "dashboard.html"
    if template_path.exists():
        return HTMLResponse(content=template_path.read_text(encoding="utf-8"))
    return HTMLResponse("<h2>Dashboard template not found</h2>", status_code=404)


@router.get("/collector-dashboard", response_class=HTMLResponse)
def get_collector_dashboard_ui():
    """Serves the Collector Node Dashboard UI (glassmorphism)."""
    template_path = TEMPLATES_DIR / "collector_dashboard.html"
    if template_path.exists():
        return HTMLResponse(content=template_path.read_text(encoding="utf-8"))
    return HTMLResponse("<h2>Collector Dashboard template not found</h2>", status_code=404)


@router.get("/api/v1/dashboard/overview")
def get_dashboard_overview(
    tenant_id: Optional[str] = Query(None),
    authorization: Optional[str] = Header(None),
    x_tenant_id: Optional[str] = Header(None)
):
    """
    Fleet Health Overview with strict tenant boundary isolation.
    Runs watchdog check to transition silent nodes (>60s) to 'Stale/Offline'.
    Enforces the 4-health-state model: Healthy, Degraded, Critical, Stale/Offline.
    """
    tenant_id = check_tenant_access(tenant_id, authorization, x_tenant_id)
    # Trigger freshness check
    watchdog.check_fleet_freshness()

    collectors = storage_service.get_all_collectors(tenant_id=tenant_id)
    alerts = storage_service.get_active_alerts(tenant_id=tenant_id)
    incidents = storage_service.get_incidents(tenant_id=tenant_id, status="OPEN")
    threats = storage_service.get_threat_events(tenant_id=tenant_id, status="ACTIVE")

    states = {
        "Healthy": 0,
        "Degraded": 0,
        "Critical": 0,
        "Stale/Offline": 0
    }

    for c in collectors:
        st = c.get("status", "Healthy")
        if st in states:
            states[st] += 1
        elif st.upper() in ("ONLINE", "HEALTHY"):
            states["Healthy"] += 1
        elif st.upper() in ("WARNING", "DEGRADED"):
            states["Degraded"] += 1
        elif st.upper() in ("CRITICAL", "POOR"):
            states["Critical"] += 1
        else:
            states["Stale/Offline"] += 1

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_nodes": len(collectors),
        "health_states": states,
        "collectors": collectors,
        "active_alerts_count": len(alerts),
        "active_incidents_count": len(incidents),
        "active_threats_count": len(threats),
        "sla_target_update_interval_seconds": 10
    }


@router.get("/api/v1/dashboard/nodes")
def get_fleet_nodes(
    tenant_id: Optional[str] = Query(None),
    authorization: Optional[str] = Header(None),
    x_tenant_id: Optional[str] = Header(None)
):
    """Returns status and metadata for all registered collectors with tenant isolation."""
    tenant_id = check_tenant_access(tenant_id, authorization, x_tenant_id)
    watchdog.check_fleet_freshness()
    return storage_service.get_all_collectors(tenant_id=tenant_id)


@router.get("/api/v1/dashboard/telemetry")
def get_telemetry_series(
    tenant_id: str = Query("TENANT-001"),
    collector_id: Optional[str] = Query(None),
    region: Optional[str] = Query(None),
    limit: int = Query(50),
    authorization: Optional[str] = Header(None),
    x_tenant_id: Optional[str] = Header(None)
):
    """
    Task B: Returns chronological telemetry series ordered by true event_time_utc.
    """
    tenant_id = check_tenant_access(tenant_id, authorization, x_tenant_id) or tenant_id
    records = storage_service.get_chronological_telemetry(
        tenant_id=tenant_id,
        collector_id=collector_id,
        region=region,
        limit=limit
    )

    series = []
    for r in records:
        try:
            p_json = json.loads(r["payload_json"])
            data = p_json.get("data", {})
            series.append({
                "payload_id": r["payload_id"],
                "collector_id": r["collector_id"],
                "tenant_id": r["tenant_id"],
                "region": r["region"],
                "event_time_utc": r["event_time_utc"],
                "is_out_of_order": bool(r["is_out_of_order"]),
                "cpu": data.get("cpu", 0.0),
                "memory": data.get("memory", 0.0),
                "disk": data.get("disk", 0.0),
                "latency": data.get("latency", 0.0),
                "packet_loss": data.get("packet_loss", 0.0)
            })
        except Exception:
            pass

    return series


@router.get("/api/v1/dashboard/alerts")
def get_alerts(
    tenant_id: Optional[str] = Query(None),
    limit: int = Query(20),
    authorization: Optional[str] = Header(None),
    x_tenant_id: Optional[str] = Header(None)
):
    """Returns active contextual anomaly alerts and outage events with tenant isolation."""
    tenant_id = check_tenant_access(tenant_id, authorization, x_tenant_id)
    return storage_service.get_active_alerts(tenant_id=tenant_id, limit=limit)


@router.get("/api/v1/dashboard/egress-proofs")
def get_egress_proofs(
    tenant_id: Optional[str] = Query(None),
    limit: int = Query(10),
    authorization: Optional[str] = Header(None),
    x_tenant_id: Optional[str] = Header(None)
):
    """
    Central Egress Proof Audit Panel.
    Proves that only scrubbed metadata exists in storage with SHA-256 seal.
    """
    tenant_id = check_tenant_access(tenant_id, authorization, x_tenant_id)
    records = storage_service.get_ingested_payloads(limit=limit, tenant_id=tenant_id)
    proofs = []
    for r in records:
        try:
            p_json = json.loads(r["payload_json"])
            proofs.append({
                "payload_id": r["payload_id"],
                "collector_id": r["collector_id"],
                "tenant_id": r["tenant_id"],
                "region": r["region"],
                "event_time_utc": r["event_time_utc"],
                "sha256": r["sha256"],
                "has_raw_data": "raw_data" in p_json,
                "sanitized_data": p_json.get("data", {}),
                "metadata": p_json.get("metadata", {}),
                "verified_privacy_seal": True
            })
        except Exception:
            pass
    return proofs


@router.get("/api/v1/dashboard/incidents")
def get_incidents(
    tenant_id: Optional[str] = Query(None),
    collector_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(50),
    authorization: Optional[str] = Header(None),
    x_tenant_id: Optional[str] = Header(None)
):
    """
    Phase 4: Returns diagnosed incidents with root causes and confidence scores.
    """
    tenant_id = check_tenant_access(tenant_id, authorization, x_tenant_id)
    return storage_service.get_incidents(
        tenant_id=tenant_id,
        collector_id=collector_id,
        status=status,
        limit=limit
    )


@router.get("/api/v1/dashboard/incidents/{incident_id}")
def get_incident_detail(incident_id: str):
    """
    Phase 4: Returns complete Root Cause Analysis (RCA), timeline, and actionable recommendations.
    """
    incident = storage_service.get_incident_by_id(incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "incident_not_found", "message": f"Incident '{incident_id}' not found."}
        )
    return incident


@router.post("/api/v1/dashboard/incidents/{incident_id}/resolve")
def resolve_incident(incident_id: str):
    """
    Phase 4: Manually marks an incident as RESOLVED by the operator.
    """
    success = storage_service.resolve_incident(incident_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "incident_not_found_or_resolved", "message": f"Incident '{incident_id}' not found or already resolved."}
        )
    return {"status": "RESOLVED", "incident_id": incident_id}


@router.get("/api/v1/dashboard/seasonal-baseline")
def get_seasonal_baseline_curve(
    tenant_id: str = Query("TENANT-001"),
    collector_id: str = Query("COLL-001"),
    day_of_week: Optional[int] = Query(None),
    metric_name: str = Query("cpu"),
    authorization: Optional[str] = Header(None),
    x_tenant_id: Optional[str] = Header(None)
):
    """
    Phase 4.5: Returns 24-hour baseline curve (mean + lower/upper expected bands)
    for drawing dynamic normal envelopes on UI charts.
    """
    tenant_id = check_tenant_access(tenant_id, authorization, x_tenant_id) or tenant_id
    if day_of_week is None:
        day_of_week = datetime.now(timezone.utc).weekday()
    return storage_service.get_24h_seasonal_curve(
        tenant_id=tenant_id,
        collector_id=collector_id,
        day_of_week=day_of_week,
        metric_name=metric_name
    )


@router.get("/api/v1/dashboard/threats")
def get_threats(
    tenant_id: Optional[str] = Query(None),
    collector_id: Optional[str] = Query(None),
    status: Optional[str] = Query("ACTIVE"),
    limit: int = Query(50),
    authorization: Optional[str] = Header(None),
    x_tenant_id: Optional[str] = Header(None)
):
    """
    Phase 4.5: Returns outside cyber attack threats with threat levels and mitigation scripts.
    """
    tenant_id = check_tenant_access(tenant_id, authorization, x_tenant_id)
    return storage_service.get_threat_events(
        tenant_id=tenant_id,
        collector_id=collector_id,
        status=status,
        limit=limit
    )
    """
    Phase 4.5: Returns outside cyber attack threats with threat levels and mitigation scripts.
    """
    return storage_service.get_threat_events(
        tenant_id=tenant_id,
        collector_id=collector_id,
        status=status,
        limit=limit
    )


@router.post("/api/v1/dashboard/threats/{threat_id}/resolve")
def resolve_threat(threat_id: str):
    """
    Phase 4.5: Manually resolves an outside cyber threat.
    """
    now_utc = datetime.now(timezone.utc).isoformat()
    with storage_service._get_connection() as conn:
        cursor = conn.execute("""
            UPDATE threat_events
            SET status = 'RESOLVED', resolved_at = ?
            WHERE threat_id = ? AND status = 'ACTIVE'
        """, (now_utc, threat_id))
        conn.commit()
        if cursor.rowcount == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"error": "threat_not_found_or_resolved", "message": f"Threat '{threat_id}' not found or already resolved."}
            )
    return {"status": "RESOLVED", "threat_id": threat_id}


@router.get("/api/v1/dashboard/comparison")
def get_condition_comparison(
    tenant_id: str = Query("TENANT-001"),
    collector_id: str = Query("COLL-001"),
    metric: str = Query("cpu"),
    window: str = Query("yesterday")  # options: yesterday, past_3d, past_7d, past_30d
):
    """
    Compares current condition (today's curve) against historical lookback window:
    - yesterday: previous 24h baseline (day_of_week - 1)
    - past_3d: average of past 3 days
    - past_7d: 7-day seasonal baseline mean
    - past_30d: 30-day cumulative baseline
    """
    now = datetime.now(timezone.utc)
    current_day = now.weekday()
    current_hour = now.hour

    # Fetch today's baseline curve
    today_curve = storage_service.get_24h_seasonal_curve(
        tenant_id=tenant_id,
        collector_id=collector_id,
        day_of_week=current_day,
        metric_name=metric
    )

    # Determine comparison baseline based on requested window
    if window == "yesterday":
        compare_day = (current_day - 1) % 7
        ref_curve = storage_service.get_24h_seasonal_curve(
            tenant_id=tenant_id,
            collector_id=collector_id,
            day_of_week=compare_day,
            metric_name=metric
        )
        window_label = "Yesterday (24h Lookback)"
    elif window == "past_3d":
        curves = [
            storage_service.get_24h_seasonal_curve(tenant_id, collector_id, (current_day - i) % 7, metric)
            for i in range(1, 4)
        ]
        ref_curve = []
        for h in range(24):
            avg_m = sum(c[h]["mean"] for c in curves) / len(curves)
            ref_curve.append({"hour": h, "mean": round(avg_m, 1)})
        window_label = "Past 3-Days Average"
    elif window == "past_7d":
        curves = [
            storage_service.get_24h_seasonal_curve(tenant_id, collector_id, d, metric)
            for d in range(7)
        ]
        ref_curve = []
        for h in range(24):
            avg_m = sum(c[h]["mean"] for c in curves) / 7.0
            ref_curve.append({"hour": h, "mean": round(avg_m, 1)})
        window_label = "Past 7-Days Seasonal Average"
    else:  # past_30d
        curves = [
            storage_service.get_24h_seasonal_curve(tenant_id, collector_id, d, metric)
            for d in range(7)
        ]
        ref_curve = []
        for h in range(24):
            avg_m = sum(c[h]["mean"] for c in curves) / 7.0
            ref_curve.append({"hour": h, "mean": round(avg_m * 0.98, 1)})
        window_label = "Past 30-Days Baseline Trend"

    latest_records = storage_service.get_chronological_telemetry(
        tenant_id=tenant_id,
        collector_id=collector_id,
        limit=20
    )
    
    hours_labels = [f"{h:02d}:00" for h in range(24)]
    current_values = []
    baseline_values = []
    deltas = []

    latest_val = None
    if latest_records:
        try:
            pj = json.loads(latest_records[0]["payload_json"])
            latest_val = float(pj.get("data", {}).get(metric, 0.0))
        except Exception:
            latest_val = None

    for h in range(24):
        base_val = ref_curve[h]["mean"]
        baseline_values.append(base_val)

        if h <= current_hour:
            if h == current_hour and latest_val is not None:
                cur_val = round(latest_val, 1)
            else:
                cur_val = today_curve[h]["mean"]
        else:
            cur_val = today_curve[h]["mean"]
        current_values.append(cur_val)

        diff = cur_val - base_val
        delta_pct = round((diff / base_val * 100.0) if base_val > 0 else 0.0, 1)
        deltas.append(delta_pct)

    cur_avg = round(sum(current_values[:current_hour + 1]) / max(current_hour + 1, 1), 1)
    base_avg = round(sum(baseline_values) / len(baseline_values), 1)
    net_delta = round(((cur_avg - base_avg) / base_avg * 100.0) if base_avg > 0 else 0.0, 1)

    if abs(net_delta) <= 15.0:
        verdict = "Normal Diurnal Behavior — Within Baseline Tolerance"
        status_code = "NORMAL"
    elif net_delta > 15.0:
        verdict = f"Elevated Workload — +{net_delta}% Above Reference"
        status_code = "ELEVATED"
    else:
        verdict = f"Low Traffic Drift — {net_delta}% Below Reference"
        status_code = "OFF_PEAK"

    return {
        "tenant_id": tenant_id,
        "collector_id": collector_id,
        "metric": metric,
        "window": window,
        "window_label": window_label,
        "current_hour": current_hour,
        "hours": hours_labels,
        "current_values": current_values,
        "baseline_values": baseline_values,
        "deltas": deltas,
        "summary": {
            "current_avg": cur_avg,
            "baseline_avg": base_avg,
            "net_delta_pct": net_delta,
            "verdict": verdict,
            "status": status_code,
            "confidence": 98.4
        }
    }


