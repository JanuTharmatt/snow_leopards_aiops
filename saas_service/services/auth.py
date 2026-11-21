"""
Authentication Service for SaaS Ingestion.
Supports:
1. Dynamic JWT Token Authentication (Bearer <JWT>) via Collector Secret
2. /auth/token Login & Token Refresh Endpoint
3. Legacy API-Key Authentication (X-Collector-Key header)
4. Fast cryptographic stateless verification with explicit token expiration
"""

from datetime import datetime, timezone
import hashlib
import hmac
import json
import time
from typing import Any, Dict, Optional
from fastapi import Header, HTTPException, status
import jwt

# Default Registered Collector Credentials: collector_id -> {secret, tenant_id, region}
DEFAULT_COLLECTOR_CREDENTIALS: Dict[str, Dict[str, str]] = {
    "COLL-001": {
        "collector_secret": "SECRET-COLL-DEMO-001",
        "tenant_id": "TENANT-001",
        "region": "us-east-1",
        "legacy_key": "COLL-KEY-DEMO-001"
    },
    "COLL-002": {
        "collector_secret": "SECRET-COLL-ALPHA-999",
        "tenant_id": "TENANT-ALPHA",
        "region": "eu-central-1",
        "legacy_key": "COLL-KEY-ALPHA-999"
    }
}

JWT_SECRET_KEY = "AIOPS_JWT_SIGNING_KEY_2026_PRIVACY_SECURE"
JWT_ALGORITHM = "HS256"
DEFAULT_TOKEN_EXPIRY_SECONDS = 900  # 15 minutes


class AuthService:
    """Validates collector secrets, issues short-lived JWTs, and verifies incoming requests."""

    def __init__(
        self,
        credentials: Optional[Dict[str, Dict[str, str]]] = None,
        jwt_secret: str = JWT_SECRET_KEY,
        default_expiry: int = DEFAULT_TOKEN_EXPIRY_SECONDS
    ):
        self.credentials = credentials or DEFAULT_COLLECTOR_CREDENTIALS
        self.jwt_secret = jwt_secret
        self.default_expiry = default_expiry

    def authenticate_collector_credentials(self, collector_id: str, collector_secret: str) -> Dict[str, str]:
        """
        Validates collector_id and collector_secret.
        Returns collector metadata if valid, else raises HTTP 401.
        """
        creds = self.credentials.get(collector_id)
        if not creds or creds["collector_secret"] != collector_secret:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"error": "invalid_credentials", "message": "Invalid collector_id or collector_secret."}
            )
        return {
            "collector_id": collector_id,
            "tenant_id": creds["tenant_id"],
            "region": creds.get("region", "us-east-1")
        }

    def issue_token(
        self,
        collector_id: str,
        collector_secret: str,
        expires_in: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Verifies collector credentials and issues a signed, time-bounded JWT access token.
        """
        auth_meta = self.authenticate_collector_credentials(collector_id, collector_secret)
        ttl = expires_in if expires_in is not None else self.default_expiry
        now_ts = int(time.time())
        exp_ts = now_ts + ttl

        payload = {
            "sub": collector_id,
            "tenant_id": auth_meta["tenant_id"],
            "region": auth_meta["region"],
            "iat": now_ts,
            "exp": exp_ts,
            "token_type": "access_token"
        }

        token = jwt.encode(payload, self.jwt_secret, algorithm=JWT_ALGORITHM)
        return {
            "access_token": token,
            "token_type": "bearer",
            "expires_in": ttl,
            "expires_at": exp_ts,
            "collector_id": collector_id,
            "tenant_id": auth_meta["tenant_id"],
            "region": auth_meta["region"]
        }

    def verify_token(self, token: str) -> Dict[str, str]:
        """
        Verifies cryptographic integrity and expiration of incoming JWT.
        Returns authenticated claims.
        """
        try:
            claims = jwt.decode(token, self.jwt_secret, algorithms=[JWT_ALGORITHM])
            return {
                "collector_id": claims["sub"],
                "tenant_id": claims["tenant_id"],
                "region": claims.get("region", "us-east-1")
            }
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "error": "token_expired",
                    "message": "JWT token has expired. Please refresh token with collector secret."
                }
            )
        except jwt.InvalidTokenError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"error": "invalid_token", "message": f"JWT token verification failed: {str(exc)}"}
            )

    def authenticate_request(
        self,
        authorization: Optional[str] = Header(None, alias="Authorization"),
        x_collector_key: Optional[str] = Header(None, alias="X-Collector-Key")
    ) -> Dict[str, str]:
        """
        Unified FastAPI dependency:
        1. Checks for 'Authorization: Bearer <JWT>' (Primary, Dynamic)
        2. Falls back to 'X-Collector-Key' (Legacy static key)
        3. Raises 401 if missing or invalid.
        """
        # 1. Bearer JWT Token Check
        if authorization and authorization.lower().startswith("bearer "):
            token = authorization[7:].strip()
            return self.verify_token(token)

        # 2. Legacy API Key Check
        if x_collector_key:
            for cid, meta in self.credentials.items():
                if meta.get("legacy_key") == x_collector_key:
                    return {
                        "collector_id": cid,
                        "tenant_id": meta["tenant_id"],
                        "region": meta.get("region", "us-east-1")
                    }
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"error": "invalid_collector_key", "message": "Provided X-Collector-Key is invalid."}
            )

        # 3. Missing Auth
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "missing_authorization",
                "message": "Authorization header (Bearer <JWT>) or X-Collector-Key is required."
            }
        )

    # Alias for existing routes referencing authenticate_key
    authenticate_key = authenticate_request


auth_service = AuthService()
