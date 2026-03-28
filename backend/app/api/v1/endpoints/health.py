"""
ironclad/app/api/v1/endpoints/health.py
Liveness and readiness probe endpoints.

Used by:
  • systemd / Docker HEALTHCHECK
  • Load balancers (confirm 200 before routing traffic)
  • Monitoring tools (Prometheus blackbox exporter, etc.)
"""

from __future__ import annotations

import platform
import time
from datetime import datetime, timezone

from fastapi import APIRouter
from pydantic import BaseModel

from app.config import get_settings
from app.services.payload_service import get_registry

router = APIRouter(prefix="/health", tags=["Health"])

_START_TIME = time.monotonic()
settings = get_settings()


class LivenessResponse(BaseModel):
    status: str
    timestamp: datetime


class ReadinessResponse(BaseModel):
    status: str
    timestamp: datetime
    uptime_seconds: float
    app_name: str
    app_version: str
    environment: str
    python_version: str
    registered_scanners: int


@router.get(
    "/liveness",
    response_model=LivenessResponse,
    summary="Liveness probe",
    description="Returns 200 if the process is alive. No heavy checks.",
)
async def liveness() -> LivenessResponse:
    return LivenessResponse(
        status="alive",
        timestamp=datetime.now(timezone.utc),
    )


@router.get(
    "/readiness",
    response_model=ReadinessResponse,
    summary="Readiness probe",
    description=(
        "Returns 200 when the application is fully initialised and ready to serve "
        "traffic. Checks scanner registry and core config."
    ),
)
async def readiness() -> ReadinessResponse:
    return ReadinessResponse(
        status="ready",
        timestamp=datetime.now(timezone.utc),
        uptime_seconds=round(time.monotonic() - _START_TIME, 2),
        app_name=settings.APP_NAME,
        app_version=settings.APP_VERSION,
        environment=settings.APP_ENV,
        python_version=platform.python_version(),
        registered_scanners=len(get_registry()),
    )
