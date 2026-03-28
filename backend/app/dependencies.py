"""
ironclad/app/dependencies.py
FastAPI dependency providers — injected into endpoint handlers via Depends().

Centralising dependencies here keeps endpoint code clean and makes it trivial
to swap implementations (e.g., real API key store vs. env var) without
touching route handlers.
"""

from __future__ import annotations

import time
from typing import Annotated
from uuid import uuid4

from fastapi import Depends, Header, HTTPException, Request, status

from app.config import Settings, get_settings
from app.logger import logger


# ── Settings injection ────────────────────────────────────────────────────────

def settings_dep() -> Settings:
    return get_settings()

SettingsDep = Annotated[Settings, Depends(settings_dep)]


# ── API key authentication ────────────────────────────────────────────────────

async def verify_api_key(
    request: Request,
    settings: SettingsDep,
    x_ironclad_key: Annotated[str | None, Header()] = None,
) -> None:
    """
    Validate the X-Ironclad-Key header.

    In Phase 2 this can be swapped for JWT verification or an async
    DB lookup with zero changes to endpoint signatures.
    """
    if x_ironclad_key is None:
        logger.warning(
            "API key missing",
            path=request.url.path,
            client=request.client.host if request.client else "unknown",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing required header: X-Ironclad-Key",
        )

    if x_ironclad_key != settings.API_KEY:
        logger.warning(
            "Invalid API key presented",
            path=request.url.path,
            client=request.client.host if request.client else "unknown",
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API key.",
        )


AuthDep = Annotated[None, Depends(verify_api_key)]


# ── Request ID ────────────────────────────────────────────────────────────────

def request_id() -> str:
    """Generate a per-request trace ID injected into log context."""
    return str(uuid4())

RequestIdDep = Annotated[str, Depends(request_id)]
