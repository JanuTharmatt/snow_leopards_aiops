"""
Server-Side Checksum Validation Service.
Recalculates SHA-256 digests over incoming payload bodies and verifies cryptographic integrity.
"""

import hashlib
import json
from typing import Any, Dict
from fastapi import HTTPException, status


class ChecksumService:
    """Verifies that received payloads have not been corrupted or tampered with in transit."""

    @staticmethod
    def calculate_sha256(payload_dict: Dict[str, Any]) -> str:
        """
        Calculates SHA-256 over canonical body excluding the 'sha256' field itself.
        """
        # Canonical body elements
        canonical_keys = [
            "payload_id",
            "collector_id",
            "tenant_id",
            "timestamp",
            "event_time_utc",
            "source_timezone",
            "source_id_hash",
            "data_type",
            "data",
            "metadata"
        ]
        body = {k: payload_dict[k] for k in canonical_keys if k in payload_dict}
        canonical_json = json.dumps(body, sort_keys=True)
        return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

    @classmethod
    def validate_payload_checksum(cls, payload_dict: Dict[str, Any]) -> None:
        """
        Compares received sha256 with recalculation.
        Raises HTTP 400 if validation fails.
        """
        received_sha = payload_dict.get("sha256")
        if not received_sha:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "checksum_validation_failed", "message": "Missing sha256 field."}
            )

        computed_sha = cls.calculate_sha256(payload_dict)
        if received_sha.lower() != computed_sha.lower():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "checksum_validation_failed", "message": "Payload SHA-256 does not match body."}
            )


checksum_service = ChecksumService()
