"""
Single Payload-Builder Chokepoint Module.
ENFORCES THE ARCHITECTURAL SECURITY CONTRACT:
1. Strict allow-list FIRST: Any unrecognized or unauthorized field is dropped immediately.
2. Redaction SECOND: PII, credentials, API keys, emails, cards, and personal names are scrubbed.
3. Local audit log written from the same function: Appends raw vs redacted audit record to local disk only.
4. Cryptographic SHA-256 checksum, UTC timestamp, source timezone, collector_id, tenant_id, and hashed source ID attached.
GUARANTEE: raw_data is NEVER placed into the egress payload or SQLite buffer.
"""

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
from typing import Any, Dict, List, Optional, Tuple, Union
import uuid

try:
    from .config import config
    from .models import (
        ALLOWED_EVENT_FIELDS,
        ALLOWED_METRIC_FIELDS,
        EgressPayload,
        LocalAuditRecord,
        RawSystemMetrics,
    )
    from .security_pipeline import security_pipeline
    from .metadata_engine import metadata_engine
except (ImportError, ValueError):
    from config import config
    from models import (
        ALLOWED_EVENT_FIELDS,
        ALLOWED_METRIC_FIELDS,
        EgressPayload,
        LocalAuditRecord,
        RawSystemMetrics,
    )
    from security_pipeline import security_pipeline
    from metadata_engine import metadata_engine

LOCAL_AUDIT_LOG_PATH = Path(__file__).resolve().parent / "local_audit.jsonl"


def get_source_timezone() -> str:
    """Returns local timezone formatted as +HH:MM or -HH:MM (e.g. +05:30)."""
    local_tz = datetime.now().astimezone().strftime("%z")
    if local_tz and len(local_tz) == 5:
        return f"{local_tz[:3]}:{local_tz[3:]}"
    return "+00:00"


def get_anonymized_source_id(source_raw: Optional[str] = None) -> str:
    """Hashes source machine identity using SHA-256 so raw hostname/IP is never transmitted."""
    identifier = source_raw or platform.node() or "agent-default-node"
    return hashlib.sha256(identifier.encode("utf-8")).hexdigest()[:16]


def build_egress_payload(
    raw_input: Union[str, Dict[str, Any], RawSystemMetrics],
    source_raw: Optional[str] = None,
    audit_log_path: Optional[Path] = None,
    collector_id: Optional[str] = None,
    tenant_id: Optional[str] = None
) -> Tuple[EgressPayload, LocalAuditRecord]:
    """
    SINGLE CHOKEPOINT FOR PAYLOAD CREATION.
    All egress data MUST pass through this exact function before reaching the local buffer.
    """
    payload_id = str(uuid.uuid4())
    audit_id = str(uuid.uuid4())
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    source_tz = get_source_timezone()
    source_id_hash = get_anonymized_source_id(source_raw)
    cid = collector_id or config.saas.collector_id
    tid = tenant_id or config.saas.tenant_id

    dropped_fields: List[str] = []
    scrubbed_detections: List[str] = []

    # STEP 1: STRICT ALLOW-LIST FIRST
    if isinstance(raw_input, RawSystemMetrics):
        raw_dict = raw_input.model_dump()
        raw_representation = raw_dict.copy()
        data_type = "METRICS"
        filtered_data = {}
        for k, v in raw_dict.items():
            if k in ALLOWED_METRIC_FIELDS:
                filtered_data[k] = v
            else:
                dropped_fields.append(k)

    elif isinstance(raw_input, dict):
        raw_representation = raw_input.copy()
        if any(k in ALLOWED_METRIC_FIELDS for k in raw_input.keys()):
            data_type = "METRICS"
            allowed_set = ALLOWED_METRIC_FIELDS
        else:
            data_type = "LOG_EVENT"
            allowed_set = ALLOWED_EVENT_FIELDS

        filtered_data = {}
        for k, v in raw_input.items():
            if k in allowed_set:
                filtered_data[k] = v
            else:
                dropped_fields.append(k)

    elif isinstance(raw_input, str):
        raw_representation = raw_input
        data_type = "LOG_EVENT"
        filtered_data = {"message": raw_input}

    else:
        raw_representation = str(raw_input)
        data_type = "LOG_EVENT"
        filtered_data = {"message": str(raw_input)}

    # STEP 2: REDACTION SECOND
    sanitized_data, detections = security_pipeline.process(filtered_data)
    scrubbed_detections.extend(detections)

    # Generate metadata from sanitized data
    if data_type == "METRICS":
        meta = metadata_engine.normalize_telemetry_batch_dict(sanitized_data)
    else:
        log_text = sanitized_data.get("message", "") if isinstance(sanitized_data, dict) else str(sanitized_data)
        meta = metadata_engine.process(log_text)

    # STEP 3: LOCAL AUDIT LOG WRITTEN FROM THE SAME FUNCTION
    audit_record = LocalAuditRecord(
        audit_id=audit_id,
        payload_id=payload_id,
        timestamp=now_utc,
        raw_data=raw_representation,
        redacted_data=sanitized_data,
        dropped_fields=dropped_fields,
        scrubbed_detections=scrubbed_detections,
        metadata=meta
    )

    dest_audit_file = audit_log_path or LOCAL_AUDIT_LOG_PATH
    try:
        dest_audit_file.parent.mkdir(parents=True, exist_ok=True)
        with open(dest_audit_file, "a", encoding="utf-8") as f:
            f.write(audit_record.model_dump_json() + "\n")
    except Exception:
        pass

    event_time_utc = sanitized_data.get("timestamp") if (isinstance(sanitized_data, dict) and sanitized_data.get("timestamp")) else now_utc

    # STEP 4: COMPUTE CRYPTOGRAPHIC HASH & CONSTRUCT EGRESS PAYLOAD
    canonical_body = {
        "payload_id": payload_id,
        "collector_id": cid,
        "tenant_id": tid,
        "timestamp": event_time_utc,
        "event_time_utc": event_time_utc,
        "source_timezone": source_tz,
        "source_id_hash": source_id_hash,
        "data_type": data_type,
        "data": sanitized_data,
        "metadata": meta
    }
    canonical_json = json.dumps(canonical_body, sort_keys=True)
    payload_hash = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

    egress_payload = EgressPayload(
        payload_id=payload_id,
        collector_id=cid,
        tenant_id=tid,
        timestamp=event_time_utc,
        event_time_utc=event_time_utc,
        source_timezone=source_tz,
        source_id_hash=source_id_hash,
        sha256=payload_hash,
        data_type=data_type,
        data=sanitized_data,
        metadata=meta
    )

    return egress_payload, audit_record
