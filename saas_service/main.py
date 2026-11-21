"""
Privacy-First AIOps Observability Platform — SaaS Ingestion Service.
FastAPI Application Entrypoint.
"""

import sys
from pathlib import Path

# Ensure root directory is on sys.path when invoked directly as python saas_service/main.py
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

try:
    from saas_service.routes.health import router as health_router
    from saas_service.routes.ingest import router as ingest_router
    from saas_service.routes.heartbeat import router as heartbeat_router
    from saas_service.routes.auth import router as auth_router
    from saas_service.routes.dashboard import router as dashboard_router
    from saas_service.routes.phase5 import router as phase5_router
    from saas_service.routes.demo_lab import router as demo_lab_router
except (ImportError, ValueError):
    from .routes.health import router as health_router
    from .routes.ingest import router as ingest_router
    from .routes.heartbeat import router as heartbeat_router
    from .routes.auth import router as auth_router
    from .routes.dashboard import router as dashboard_router
    from .routes.phase5 import router as phase5_router
    from .routes.demo_lab import router as demo_lab_router

app = FastAPI(
    title="SNOW LEOPARDS — Autonomous AIOps & Observability Cloud",
    description="Tier-2 SaaS Ingestion Service for secure metadata ingestion, authentication, SHA256 verification, and fleet heartbeat monitoring.",
    version="2.0.0"
)

# Mount static files for official logos and web assets
static_dir = ROOT_DIR / "saas_service" / "web" / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routes for both root and /api/v1 prefixes
app.include_router(health_router)
app.include_router(ingest_router)
app.include_router(heartbeat_router)
app.include_router(auth_router)
app.include_router(dashboard_router)
app.include_router(phase5_router)
app.include_router(demo_lab_router)

# Also mount under /api/v1 for standard API versioning
app.include_router(health_router, prefix="/api/v1")
app.include_router(ingest_router, prefix="/api/v1")
app.include_router(heartbeat_router, prefix="/api/v1")
app.include_router(auth_router, prefix="/api/v1")
app.include_router(dashboard_router, prefix="/api/v1")
app.include_router(phase5_router, prefix="/api/v1")
app.include_router(demo_lab_router, prefix="/api/v1")


if __name__ == "__main__":
    import os
    import uvicorn

    ssl_enabled = os.environ.get("AIOPS_SSL_ENABLED", "0").lower() in ("1", "true", "yes")
    certs_dir = ROOT_DIR / "certs"
    ssl_key = certs_dir / "server.key"
    ssl_cert = certs_dir / "server.crt"

    if ssl_enabled and ssl_key.exists() and ssl_cert.exists():
        print(f"[AIOps.SaaS] Starting with TLS / HTTPS enforcement on port 8000...")
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=8000,
            ssl_keyfile=str(ssl_key),
            ssl_certfile=str(ssl_cert)
        )
    else:
        print("[AIOps.SaaS] Starting on http://0.0.0.0:8000 (Set AIOPS_SSL_ENABLED=1 for HTTPS)...")
        uvicorn.run(app, host="0.0.0.0", port=8000)
