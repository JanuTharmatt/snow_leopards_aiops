"""
Healthcheck route.
Endpoint: GET /health
"""

from fastapi import APIRouter

router = APIRouter(tags=["Health"])


@router.get("/health")
def healthcheck():
    """
    Standard health check endpoint.
    Returns:
        {"status": "healthy"}
    """
    return {"status": "healthy"}
