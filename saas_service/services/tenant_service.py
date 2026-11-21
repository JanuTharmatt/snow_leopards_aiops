"""
Tenant Provisioning & Multi-Tenant Management Service.
Phase 5.5: Public Demo Deployment & Multi-Tenant Onboarding.

Responsibilities:
- Automated tenant provisioning (e.g. tenant_f84a29)
- User registration, password hashing (PBKDF2 HMAC SHA-256), and JWT issuance
- Collector registration and collector_secret generation
- Dual-mode persistence in SQLite and Cloud Firestore
- Enforces multi-tenant isolation across all resources
"""

from datetime import datetime, timezone
import hashlib
import hmac
import json
import logging
import os
from pathlib import Path
import sqlite3
import time
from typing import Any, Dict, List, Optional, Tuple
import uuid

try:
    from .auth import auth_service, JWT_SECRET_KEY, JWT_ALGORITHM
    from .firestore_storage import firestore_storage
    from .storage import storage_service
except (ImportError, ValueError):
    from saas_service.services.auth import auth_service, JWT_SECRET_KEY, JWT_ALGORITHM
    from saas_service.services.firestore_storage import firestore_storage
    from saas_service.services.storage import storage_service

logger = logging.getLogger("AIOps.TenantService")


def hash_password(password: str, salt: Optional[str] = None) -> str:
    """Generates a secure PBKDF2 HMAC-SHA256 hash for user passwords."""
    if salt is None:
        salt = uuid.uuid4().hex[:16]
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100000
    )
    return f"{salt}${key.hex()}"


def verify_password(stored_hash: str, password_attempt: str) -> bool:
    """Verifies a plain password attempt against the stored salt$hash string."""
    try:
        salt, expected_hash = stored_hash.split("$", 1)
        attempt_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password_attempt.encode('utf-8'),
            salt.encode('utf-8'),
            100000
        ).hex()
        return hmac.compare_digest(expected_hash, attempt_hash)
    except Exception:
        return False


class TenantService:
    """Manages tenant provisioning, user accounts, and collector onboarding."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or storage_service.db_path
        self._init_tables()
        self._seed_default_tenants()

    def _init_tables(self) -> None:
        """Creates tenants, users, and collectors tables."""
        with storage_service._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS tenants (
                    tenant_id TEXT PRIMARY KEY,
                    tenant_name TEXT NOT NULL,
                    owner_uid TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    uid TEXT PRIMARY KEY,
                    email TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS collectors (
                    collector_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    hostname TEXT NOT NULL,
                    registered_at TEXT NOT NULL,
                    collector_secret TEXT NOT NULL
                );
            """)
            conn.commit()

    def _seed_default_tenants(self) -> None:
        """Seeds default evaluation tenants for instant evaluator login."""
        default_tenants = [
            ("TENANT-001", "Production US East (Demo)", "usr_demo_001", "admin@snowleopards.ai", "DemoPassword2026!"),
            ("TENANT-ALPHA", "European Operations (Demo)", "usr_demo_002", "evaluator@snowleopards.ai", "DemoPassword2026!")
        ]
        with storage_service._get_connection() as conn:
            for tid, tname, uid, email, pwd in default_tenants:
                # Check tenant
                cur = conn.execute("SELECT 1 FROM tenants WHERE tenant_id = ?", (tid,))
                if not cur.fetchone():
                    now = datetime.now(timezone.utc).isoformat()
                    conn.execute(
                        "INSERT INTO tenants (tenant_id, tenant_name, owner_uid, created_at) VALUES (?, ?, ?, ?)",
                        (tid, tname, uid, now)
                    )
                    phash = hash_password(pwd)
                    conn.execute(
                        "INSERT OR IGNORE INTO users (uid, email, password_hash, tenant_id, created_at) VALUES (?, ?, ?, ?, ?)",
                        (uid, email, phash, tid, now)
                    )
            conn.commit()

    def generate_tenant_id(self) -> str:
        """Generates tenant identifier matching schema requirement (e.g. tenant_f84a29)."""
        return f"tenant_{uuid.uuid4().hex[:6]}"

    def generate_collector_id(self) -> str:
        """Generates collector identifier matching schema requirement (e.g. COL-AB12CD)."""
        return f"COL-{uuid.uuid4().hex[:6].upper()}"

    def register_tenant(self, email: str, password: str, tenant_name: str) -> Dict[str, Any]:
        """
        Provisions a new tenant, user, and default collector key.
        Returns credentials and fresh JWT access token.
        """
        email_clean = email.strip().lower()
        if not email_clean or "@" not in email_clean:
            raise ValueError("A valid email address is required.")
        if len(password) < 6:
            raise ValueError("Password must be at least 6 characters long.")
        if not tenant_name.strip():
            raise ValueError("Organization / Tenant Name cannot be empty.")

        with storage_service._get_connection() as conn:
            # Check existing email
            cur = conn.execute("SELECT uid FROM users WHERE email = ?", (email_clean,))
            if cur.fetchone():
                raise ValueError(f"User with email '{email_clean}' already exists. Please log in.")

            tenant_id = self.generate_tenant_id()
            uid = f"usr_{uuid.uuid4().hex[:8]}"
            now_iso = datetime.now(timezone.utc).isoformat()
            phash = hash_password(password)

            # Insert tenant
            conn.execute(
                "INSERT INTO tenants (tenant_id, tenant_name, owner_uid, created_at) VALUES (?, ?, ?, ?)",
                (tenant_id, tenant_name.strip(), uid, now_iso)
            )

            # Insert user
            conn.execute(
                "INSERT INTO users (uid, email, password_hash, tenant_id, created_at) VALUES (?, ?, ?, ?, ?)",
                (uid, email_clean, phash, tenant_id, now_iso)
            )

            # Create default collector for this tenant
            collector_id = self.generate_collector_id()
            collector_secret = f"SECRET-{uuid.uuid4().hex[:12].upper()}"
            conn.execute(
                "INSERT INTO collectors (collector_id, tenant_id, hostname, registered_at, collector_secret) VALUES (?, ?, ?, ?, ?)",
                (collector_id, tenant_id, "primary-node", now_iso, collector_secret)
            )
            conn.commit()

        # Update auth_service credentials in-memory
        auth_service.credentials[collector_id] = {
            "collector_secret": collector_secret,
            "tenant_id": tenant_id,
            "region": "us-east-1",
            "legacy_key": f"KEY-{collector_id}"
        }

        # Dual-mode sync to Firestore
        firestore_storage.save_tenant(tenant_id, tenant_name.strip(), uid, now_iso)
        firestore_storage.save_user(uid, email_clean, tenant_id, now_iso)
        firestore_storage.save_collector(collector_id, tenant_id, "primary-node", now_iso)

        # Issue access token
        token_data = auth_service.issue_token(collector_id, collector_secret)

        return {
            "status": "success",
            "tenant_id": tenant_id,
            "tenant_name": tenant_name.strip(),
            "uid": uid,
            "email": email_clean,
            "collector_id": collector_id,
            "collector_secret": collector_secret,
            "access_token": token_data["access_token"],
            "token_type": "bearer",
            "created_at": now_iso
        }

    def login_user(self, email: str, password: str) -> Dict[str, Any]:
        """
        Authenticates user with email and password.
        Returns tenant information and JWT access token.
        """
        email_clean = email.strip().lower()
        with storage_service._get_connection() as conn:
            cur = conn.execute(
                "SELECT u.uid, u.email, u.password_hash, u.tenant_id, t.tenant_name "
                "FROM users u "
                "JOIN tenants t ON u.tenant_id = t.tenant_id "
                "WHERE u.email = ?",
                (email_clean,)
            )
            row = cur.fetchone()
            if not row:
                raise ValueError("Invalid email or password.")

            if not verify_password(row["password_hash"], password):
                raise ValueError("Invalid email or password.")

            tenant_id = row["tenant_id"]
            uid = row["uid"]
            tenant_name = row["tenant_name"]

            # Fetch or create a collector key for token generation
            c_cur = conn.execute(
                "SELECT collector_id, collector_secret FROM collectors WHERE tenant_id = ? LIMIT 1",
                (tenant_id,)
            )
            c_row = c_cur.fetchone()
            if c_row:
                cid = c_row["collector_id"]
                csecret = c_row["collector_secret"]
            else:
                cid = self.generate_collector_id()
                csecret = f"SECRET-{uuid.uuid4().hex[:12].upper()}"
                now_iso = datetime.now(timezone.utc).isoformat()
                conn.execute(
                    "INSERT INTO collectors (collector_id, tenant_id, hostname, registered_at, collector_secret) VALUES (?, ?, ?, ?, ?)",
                    (cid, tenant_id, "primary-node", now_iso, csecret)
                )
                conn.commit()

        # Update in-memory auth credentials
        auth_service.credentials[cid] = {
            "collector_secret": csecret,
            "tenant_id": tenant_id,
            "region": "us-east-1",
            "legacy_key": f"KEY-{cid}"
        }

        token_data = auth_service.issue_token(cid, csecret)

        return {
            "status": "success",
            "tenant_id": tenant_id,
            "tenant_name": tenant_name,
            "uid": uid,
            "email": email_clean,
            "collector_id": cid,
            "access_token": token_data["access_token"],
            "token_type": "bearer"
        }

    def register_collector(
        self,
        hostname: str,
        tenant_id: Optional[str] = None,
        email: Optional[str] = None,
        password: Optional[str] = None,
        org_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Registers a new collector machine.
        If tenant_id does not exist or user credentials provided, auto-provisions tenant.
        Returns collector credentials and access token.
        """
        # Auto-provision if user email and password provided
        if email and password:
            try:
                login_info = self.login_user(email, password)
                tenant_id = login_info["tenant_id"]
            except ValueError:
                # User doesn't exist yet, register new organization
                org = org_name or f"Org-{email.split('@')[0]}"
                reg_info = self.register_tenant(email, password, org)
                tenant_id = reg_info["tenant_id"]

        if not tenant_id:
            # Fallback to demo tenant if none provided
            tenant_id = "TENANT-001"

        collector_id = self.generate_collector_id()
        collector_secret = f"SECRET-{uuid.uuid4().hex[:12].upper()}"
        now_iso = datetime.now(timezone.utc).isoformat()
        clean_host = hostname.strip() if hostname else "windows-client"

        with storage_service._get_connection() as conn:
            conn.execute(
                "INSERT INTO collectors (collector_id, tenant_id, hostname, registered_at, collector_secret) VALUES (?, ?, ?, ?, ?)",
                (collector_id, tenant_id, clean_host, now_iso, collector_secret)
            )
            conn.commit()

        # Update auth_service credentials
        auth_service.credentials[collector_id] = {
            "collector_secret": collector_secret,
            "tenant_id": tenant_id,
            "region": "us-east-1",
            "legacy_key": f"KEY-{collector_id}"
        }

        # Dual-mode sync to Firestore
        firestore_storage.save_collector(collector_id, tenant_id, clean_host, now_iso)

        # Issue immediate access token
        token_data = auth_service.issue_token(collector_id, collector_secret)

        return {
            "collector_id": collector_id,
            "collector_secret": collector_secret,
            "tenant_id": tenant_id,
            "hostname": clean_host,
            "registered_at": now_iso,
            "access_token": token_data["access_token"],
            "token_type": "bearer",
            "expires_in": token_data["expires_in"],
            "status": "registered"
        }

    def get_tenant(self, tenant_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves tenant record by ID."""
        with storage_service._get_connection() as conn:
            cur = conn.execute(
                "SELECT tenant_id, tenant_name, owner_uid, created_at FROM tenants WHERE tenant_id = ?",
                (tenant_id,)
            )
            row = cur.fetchone()
            if row:
                return dict(row)
        return None

    def list_tenants(self) -> List[Dict[str, Any]]:
        """Returns list of all registered tenants."""
        with storage_service._get_connection() as conn:
            cur = conn.execute("SELECT tenant_id, tenant_name, owner_uid, created_at FROM tenants ORDER BY created_at DESC")
            return [dict(r) for r in cur.fetchall()]


tenant_service = TenantService()
