"""
Deduplication and Idempotency Service.
Guarantees zero duplicate records upon network retries or worker reconnects.
"""

from typing import Any, Dict, Tuple
try:
    from .storage import storage_service
except (ImportError, ValueError):
    from saas_service.services.storage import storage_service


class DeduplicationService:
    """Handles idempotent payload ingestion."""

    @staticmethod
    def process_payload(payload_dict: Dict[str, Any], tenant_id: str, region: str = "us-east-1") -> Tuple[bool, Dict[str, Any]]:
        """
        Processes an incoming payload idempotently with region and watermark awareness.

        Returns:
            Tuple of (is_duplicate: bool, response_dict: Dict[str, Any])
        """
        payload_id = payload_dict["payload_id"]

        # Check if payload was already ingested
        if storage_service.payload_exists(payload_id):
            return True, {
                "status": "DUPLICATE",
                "duplicate": True,
                "payload_id": payload_id,
                "message": "Payload already ingested. Skipping duplicate storage."
            }

        # Store new payload
        is_new, is_out_of_order = storage_service.store_payload(payload_dict, tenant_id=tenant_id, region=region)
        return False, {
            "status": "ACCEPTED",
            "duplicate": False,
            "is_out_of_order": is_out_of_order,
            "payload_id": payload_id,
            "message": "Payload ingested successfully."
        }


deduplication_service = DeduplicationService()
