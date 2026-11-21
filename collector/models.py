"""
Data Models for Privacy-First AIOps Observability Platform.
Defines strictly-typed schemas for metrics, metadata, transmission payloads, and local audit records.
Feature 10: Includes collector_id, tenant_id, event_time_utc, and source_timezone for UTC & Global Readiness.
"""

from enum import Enum
import hashlib
import json
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field, ConfigDict


class HealthStatus(str, Enum):
    """Normalized 4 health states for telemetry."""
    HEALTHY = "HEALTHY"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


class SeverityLevel(str, Enum):
    """Normalized severity levels across metrics and events."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class BufferStatus(str, Enum):
    """Feature 9 Status values for SQLite buffer."""
    PENDING = "PENDING"
    SENT = "SENT"
    FAILED = "FAILED"
    DEAD_LETTER = "DEAD_LETTER"


ALLOWED_METRIC_FIELDS = {
    "cpu",
    "memory",
    "disk",
    "latency",
    "packet_loss",
    "network",
    "timestamp",
    "failed_logins",
    "website_status"
}

ALLOWED_EVENT_FIELDS = {
    "event",
    "severity",
    "timestamp",
    "message",
    "details"
}


class RawSystemMetrics(BaseModel):
    """Host telemetry gathered by Collector."""
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    cpu: float = Field(..., description="CPU percentage (0-100)")
    memory: float = Field(..., description="Memory percentage (0-100)")
    disk: float = Field(..., description="Disk percentage (0-100)")
    latency: float = Field(..., description="Ping latency in ms")
    packet_loss: Optional[float] = Field(default=0.0, description="Packet loss percentage (0-100)")
    timestamp: str = Field(..., description="UTC ISO-8601 timestamp")
    network: Optional[Dict[str, Any]] = Field(default=None, description="Network I/O bytes sent/recv")
    failed_logins: Optional[int] = Field(default=0, description="Count of failed auth events in cycle")
    website_status: Optional[Dict[str, Any]] = Field(default=None, description="HTTP availability status")


class MetricMetadata(BaseModel):
    """Canonical metric evaluation metadata."""
    metric_type: str
    value: float
    health: HealthStatus
    severity: SeverityLevel
    timestamp: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


class LogEventMetadata(BaseModel):
    """Canonical log event classification."""
    event: str
    severity: SeverityLevel
    timestamp: str
    details: Optional[Dict[str, Any]] = None


class EgressPayload(BaseModel):
    """
    Sanitized, cryptographically hashed transmission payload.
    Feature 10: Includes collector_id, tenant_id, event_time_utc, and source_timezone.
    GUARANTEE: raw_data, usernames, and raw IP addresses are NEVER included.
    """
    payload_id: str = Field(..., description="Unique UUIDv4 payload identifier")
    collector_id: str = Field(default="COLL-001", description="Collector identifier for fleet registry")
    tenant_id: str = Field(default="TENANT-001", description="Multi-tenant identifier")
    timestamp: str = Field(..., description="UTC ISO-8601 timestamp")
    event_time_utc: str = Field(..., description="Explicit UTC event time for global time ordering")
    source_timezone: str = Field(..., description="Source host local timezone offset (e.g. +05:30)")
    source_id_hash: str = Field(..., description="Anonymized SHA-256 hash of host/machine identifier")
    sha256: str = Field(..., description="Cryptographic SHA-256 checksum of payload content")
    data_type: str = Field(..., description="Data classification: METRICS | LOG_EVENT")
    data: Dict[str, Any] = Field(..., description="Allow-listed, PII-sanitized telemetry or event data")
    metadata: Dict[str, Any] = Field(..., description="Normalized health and severity metadata")

    def verify_checksum(self) -> bool:
        """Verifies if the sha256 checksum matches the canonical representation."""
        body = {
            "payload_id": self.payload_id,
            "collector_id": self.collector_id,
            "tenant_id": self.tenant_id,
            "timestamp": self.timestamp,
            "event_time_utc": self.event_time_utc,
            "source_timezone": self.source_timezone,
            "source_id_hash": self.source_id_hash,
            "data_type": self.data_type,
            "data": self.data,
            "metadata": self.metadata
        }
        computed = hashlib.sha256(json.dumps(body, sort_keys=True).encode("utf-8")).hexdigest()
        return computed.lower() == self.sha256.lower()


class LocalAuditRecord(BaseModel):
    """
    LOCAL-ONLY audit record for host operator inspection (Local Raw-vs-Redacted View).
    STORED EXCLUSIVELY ON LOCAL DISK. NEVER BUFFERED INTO UNSENT_PAYLOADS AND NEVER TRANSMITTED.
    """
    audit_id: str
    payload_id: str
    timestamp: str
    raw_data: Any
    redacted_data: Any
    dropped_fields: List[str]
    scrubbed_detections: List[str]
    metadata: Dict[str, Any]


class UnsentPayload(BaseModel):
    """Database model matching 'unsent_payloads' SQLite table."""
    payload_id: str
    timestamp: str
    payload_json: str
    status: str = "PENDING"
