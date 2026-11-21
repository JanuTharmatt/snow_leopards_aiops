"""
Configuration Module for Privacy-First AIOps Observability Platform.
Provides settings for telemetry, security, local buffer, and SaaS transmission.
"""

from pathlib import Path
from typing import Any, Dict, Optional, Pattern
import regex as re
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DB_PATH = BASE_DIR / "database.db"
DEFAULT_AUDIT_LOG_PATH = BASE_DIR / "local_audit.jsonl"


class SaaSConnectionConfig(BaseModel):
    """Configuration for transmission to the SaaS Ingestion Platform."""
    saas_url: str = Field(default="http://localhost:8000", description="Base URL of SaaS Ingestion Service")
    ingest_endpoint: str = Field(default="/ingest", description="Ingestion endpoint path")
    heartbeat_endpoint: str = Field(default="/heartbeat", description="Heartbeat endpoint path")
    token_endpoint: str = Field(default="/auth/token", description="Token authentication endpoint path")
    collector_id: str = Field(default="COLL-001", description="Collector identifier")
    collector_secret: str = Field(default="SECRET-COLL-DEMO-001", description="Collector Secret Key for dynamic JWT authentication")
    collector_key: str = Field(default="COLL-KEY-DEMO-001", description="Legacy API Key sent via X-Collector-Key header")
    tenant_id: str = Field(default="TENANT-001", description="Tenant identifier")
    worker_poll_interval: float = Field(default=2.0, description="Egress worker loop sleep interval in seconds")
    max_retries_before_dlq: int = Field(default=3, description="Consecutive retries before moving to DEAD_LETTER")
    heartbeat_interval: int = Field(default=30, description="Heartbeat transmission interval in seconds")
    verify_ssl: bool = Field(default=False, description="Whether to verify TLS certificates (True in production)")
    ca_cert_path: Optional[str] = Field(default=None, description="Path to custom CA certificate for TLS verification")


class TelemetryConfig(BaseModel):
    """Configuration for system metrics collection."""
    interval_seconds: int = Field(default=5, description="Collection interval in seconds")
    ping_target: str = Field(default="8.8.8.8", description="Target host/IP for ping3 latency checks")
    ping_timeout_seconds: float = Field(default=2.0, description="Ping timeout threshold")
    fallback_latency_ms: float = Field(default=12.0, description="Default latency if ICMP raw sockets are restricted")
    website_check_url: str = Field(default="https://httpbin.org/status/200", description="URL for availability checks")


class ThresholdConfig(BaseModel):
    """Metric health and severity threshold configurations."""
    cpu_warning: float = 75.0
    cpu_critical: float = 90.0
    
    memory_warning: float = 75.0
    memory_critical: float = 85.0
    
    disk_warning: float = 80.0
    disk_critical: float = 90.0
    
    latency_warning_ms: float = 150.0
    latency_critical_ms: float = 300.0

    packet_loss_warning: float = 5.0
    packet_loss_critical: float = 20.0


class SecurityRegexConfig:
    """Pre-compiled regex patterns for detecting and redacting sensitive PII/secrets."""

    HEADER_LINE_PATTERNS: Dict[str, Pattern] = {
        "PASSWORD_LINE": re.compile(
            r"^[ \t]*(?:password|passwd|pwd|secret)[ \t]*[:=][^\r\n]*$",
            re.IGNORECASE | re.MULTILINE
        ),
        "API_KEY_LINE": re.compile(
            r"^[ \t]*(?:api[_-]?key|auth[_-]?token|bearer[_-]?token|client[_-]?secret|secret[_-]?key)[ \t]*[:=][^\r\n]*$",
            re.IGNORECASE | re.MULTILINE
        ),
        "NAME_LINE": re.compile(
            r"^[ \t]*(?:user|username|name|customer|account_holder|author)[ \t]*:[ \t]*[A-Za-z0-9_-]+(?:[ \t]+[A-Za-z0-9_-]+)*[^\r\n]*$",
            re.IGNORECASE | re.MULTILINE
        ),
    }

    INLINE_PATTERNS: Dict[str, Pattern] = {
        "EMAIL": re.compile(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
        ),
        "CREDIT_CARD": re.compile(
            r"\b(?:\d{4}[ -]?){3}\d{4}\b|\b\d{13,19}\b"
        ),
        "API_KEY": re.compile(
            r"(?i)\b(?:api[_-]?key|token|bearer)\s*[:=]\s*['\"]?([A-Za-z0-9_\-\.]{8,})['\"]?"
        ),
        "PASSWORD": re.compile(
            r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*['\"]?(\S+)['\"]?"
        ),
        "NAME": re.compile(
            r"(?i)\b(?:User|Name)\s*:\s*([A-Za-z0-9_-]+(?:\s+[A-Za-z0-9_-]+)*)"
        ),
    }


class DatabaseConfig(BaseModel):
    """Database connection and buffer settings."""
    db_path: Path = Field(default=DEFAULT_DB_PATH, description="Path to local SQLite buffer database")
    timeout_seconds: float = Field(default=10.0, description="SQLite lock timeout")


class AppConfig(BaseModel):
    """Unified application configuration."""
    saas: SaaSConnectionConfig = Field(default_factory=SaaSConnectionConfig)
    telemetry: TelemetryConfig = Field(default_factory=TelemetryConfig)
    thresholds: ThresholdConfig = Field(default_factory=ThresholdConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)


import json
import os
import sys

def get_collector_config_path() -> Path:
    """Returns persistent path to collector_config.json."""
    if getattr(sys, 'frozen', False):
        exe_dir = Path(sys.executable).parent
        return exe_dir / "collector_config.json"
    return BASE_DIR / "collector_config.json"


def load_collector_config(target_config: 'AppConfig') -> bool:
    """Loads stored tenant and collector credentials from collector_config.json."""
    cfg_file = get_collector_config_path()
    if not cfg_file.exists():
        # Also check current working directory
        cwd_file = Path.cwd() / "collector_config.json"
        if cwd_file.exists():
            cfg_file = cwd_file
        else:
            return False

    try:
        data = json.loads(cfg_file.read_text(encoding="utf-8"))
        if data.get("saas_url"):
            target_config.saas.saas_url = data["saas_url"]
        if data.get("tenant_id"):
            target_config.saas.tenant_id = data["tenant_id"]
        if data.get("collector_id"):
            target_config.saas.collector_id = data["collector_id"]
        if data.get("collector_secret") or data.get("collector_registration_token"):
            target_config.saas.collector_secret = data.get("collector_secret") or data.get("collector_registration_token")
        if data.get("collector_key"):
            target_config.saas.collector_key = data["collector_key"]
        return True
    except Exception:
        return False


def save_collector_config(data: Dict[str, Any]) -> Path:
    """Saves provisioned tenant and collector credentials to collector_config.json."""
    cfg_file = get_collector_config_path()
    try:
        cfg_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return cfg_file
    except Exception:
        # Fallback to local cwd
        cwd_file = Path.cwd() / "collector_config.json"
        cwd_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return cwd_file


config = AppConfig()
# Attempt auto-loading persisted credentials
load_collector_config(config)
