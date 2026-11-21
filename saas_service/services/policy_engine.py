"""
Policy Engine.
Phase 5.5:
Enforces operational governance rules across multi-tenant remediation requests:
- Production Tenants -> Manual Approval required
- Development Tenants -> Auto Approval allowed
Ensures all remediation actions pass:
1. Policy Check
2. Risk Check
3. Audit Recording (into SQLite table: policy_audit)
"""

from datetime import datetime, timezone
import json
import sqlite3
from typing import Any, Dict, List, Optional
import uuid

try:
    from .storage import storage_service
except (ImportError, ValueError):
    from saas_service.services.storage import storage_service


class PolicyEngine:
    """Enforces environment-specific governance and risk audits on remediation actions."""

    def __init__(self):
        self._init_table()

    def _get_connection(self):
        return storage_service._get_connection()

    def _init_table(self) -> None:
        """Initializes the policy_audit table."""
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS policy_audit (
                    id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    remediation_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    policy_result TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    timestamp TEXT NOT NULL
                );
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_policy_audit_tenant
                ON policy_audit(tenant_id, timestamp);
            """)

    def is_production_tenant(self, tenant_id: str) -> bool:
        """Determines if a tenant is subject to strict Production governance."""
        t_upper = (tenant_id or "").upper()
        # TENANT-001 is designated as Production East, or any tenant containing PROD
        if "PROD" in t_upper or t_upper in ("TENANT-001", "TENANT-PRODUCTION"):
            return True
        return False

    def evaluate_remediation_policy(
        self,
        tenant_id: str,
        remediation_id: str,
        action: str,
        risk_score: Optional[float] = None
    ) -> Dict[str, Any]:
        """
        Executes:
        1. Policy Check (Prod vs Dev)
        2. Risk Check (Risk Score threshold)
        3. Audit Recording (Written to policy_audit table)
        """
        now_utc = datetime.now(timezone.utc).isoformat()
        audit_id = f"AUD-{uuid.uuid4().hex[:8].upper()}"

        # 1. Policy Check: Prod vs Dev
        is_prod = self.is_production_tenant(tenant_id)

        # 2. Risk Check
        score = float(risk_score) if risk_score is not None else (78.5 if is_prod else 32.0)
        
        if is_prod:
            policy_result = "MANUAL_APPROVAL_REQUIRED"
            reason = "Production Tenant policy mandates manual operator sign-off."
        else:
            if score >= 90.0:
                policy_result = "MANUAL_APPROVAL_REQUIRED"
                reason = f"High risk score ({score}) exceeds development auto-approval ceiling."
            else:
                policy_result = "APPROVED"
                reason = "Development Tenant eligible for autonomous remediation."

        # 3. Audit Recording
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO policy_audit (id, tenant_id, remediation_id, action, policy_result, risk_score, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?);
            """, (audit_id, tenant_id, remediation_id, action, policy_result, score, now_utc))
            conn.commit()

        return {
            "audit_id": audit_id,
            "tenant_id": tenant_id,
            "remediation_id": remediation_id,
            "action": action,
            "is_production": is_prod,
            "risk_score": score,
            "policy_result": policy_result,
            "reason": reason,
            "timestamp": now_utc
        }

    def get_audit_trail(self, tenant_id: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieves policy decision audit entries."""
        query = "SELECT * FROM policy_audit WHERE 1=1"
        params: List[Any] = []
        if tenant_id:
            query += " AND tenant_id = ?"
            params.append(tenant_id)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        with self._get_connection() as conn:
            cursor = conn.execute(query, tuple(params))
            return [dict(r) for r in cursor.fetchall()]


policy_engine = PolicyEngine()

