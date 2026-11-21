"""
Collector Authentication Client.
Manages Dynamic JWT Token Lifecycle for Edge Collectors:
1. Performs login via collector_id and collector_secret
2. Caches and monitors token expiration
3. Transparently auto-refreshes tokens before expiration or on HTTP 401
4. Guarantees safe replay of buffered SQLite payloads after network reconnects
"""

import logging
import time
from typing import Any, Dict, Optional
import requests

try:
    from .config import config
except (ImportError, ValueError):
    from config import config

logger = logging.getLogger("AIOps.CollectorAuthClient")


class CollectorAuthClient:
    """Handles token acquisition, caching, and auto-refresh for the collector."""

    def __init__(
        self,
        saas_url: Optional[str] = None,
        collector_id: Optional[str] = None,
        collector_secret: Optional[str] = None,
        token_endpoint: Optional[str] = None,
        legacy_key: Optional[str] = None
    ):
        self.saas_url = (saas_url or config.saas.saas_url).rstrip("/")
        self.token_endpoint = token_endpoint or config.saas.token_endpoint
        self.token_url = f"{self.saas_url}{self.token_endpoint}"
        self.collector_id = collector_id or config.saas.collector_id
        self.collector_secret = collector_secret or config.saas.collector_secret
        self.legacy_key = legacy_key or config.saas.collector_key
        self.verify_ssl = config.saas.verify_ssl
        self.ca_cert_path = config.saas.ca_cert_path

        self.access_token: Optional[str] = None
        self.token_expires_at: float = 0.0

    def reload_credentials(
        self,
        saas_url: Optional[str] = None,
        collector_id: Optional[str] = None,
        collector_secret: Optional[str] = None
    ) -> None:
        """Reloads credentials after interactive login or config update."""
        self.saas_url = (saas_url or config.saas.saas_url).rstrip("/")
        self.token_url = f"{self.saas_url}{self.token_endpoint}"
        self.collector_id = collector_id or config.saas.collector_id
        self.collector_secret = collector_secret or config.saas.collector_secret
        self.access_token = None
        self.token_expires_at = 0.0

    def is_token_expired(self, buffer_seconds: float = 15.0) -> bool:
        """Returns True if cached token is missing or near expiration."""
        if not self.access_token:
            return True
        return time.time() >= (self.token_expires_at - buffer_seconds)

    def fetch_new_token(self, custom_session: Optional[Any] = None) -> str:
        """
        Authenticates with SaaS using collector_secret and obtains a fresh JWT.
        """
        client = custom_session or requests
        payload = {
            "collector_id": self.collector_id,
            "collector_secret": self.collector_secret
        }

        logger.info(f"Authenticating collector [{self.collector_id}] at {self.token_url}...")
        kwargs = {"timeout": 5.0}
        if (client is requests or isinstance(client, requests.Session)) and self.verify_ssl:
            kwargs["verify"] = self.ca_cert_path if self.ca_cert_path and Path(self.ca_cert_path).exists() else True

        resp = client.post(self.token_url, json=payload, **kwargs)

        if resp.status_code == 200:
            data = resp.json()
            self.access_token = data["access_token"]
            expires_in = data.get("expires_in", 900)
            self.token_expires_at = time.time() + expires_in
            logger.info(f"Successfully obtained new JWT for [{self.collector_id}] (valid for {expires_in}s)")
            return self.access_token
        else:
            err_text = resp.text
            logger.error(f"Failed to authenticate collector [{self.collector_id}]: HTTP {resp.status_code} - {err_text}")
            raise RuntimeError(f"Authentication failed (HTTP {resp.status_code}): {err_text}")

    def get_valid_token(self, force_refresh: bool = False, custom_session: Optional[Any] = None) -> str:
        """
        Returns a valid JWT token. Automatically refreshes if expired or forced.
        """
        if force_refresh or self.is_token_expired():
            return self.fetch_new_token(custom_session=custom_session)
        return self.access_token

    def get_auth_headers(self, force_refresh: bool = False, custom_session: Optional[Any] = None) -> Dict[str, str]:
        """
        Returns HTTP headers containing Bearer JWT and legacy fallback key.
        """
        token = self.get_valid_token(force_refresh=force_refresh, custom_session=custom_session)
        return {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
            "X-Collector-Key": self.legacy_key
        }

    def invalidate_token(self) -> None:
        """Forces next request to fetch a new token."""
        self.access_token = None
        self.token_expires_at = 0.0


# Default instance
auth_client = CollectorAuthClient()
