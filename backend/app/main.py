"""
ironclad/app/main.py
Project Ironclad — FastAPI application entrypoint.

Startup sequence:
  1. Configure structured logging (must be first).
  2. Load and validate settings.
  3. Discover and register scanner modules.
  4. Mount middleware (CORS, request timing, global error handling).
  5. Register API routers.
  6. Expose the ASGI `app` object for uvicorn / gunicorn.

Run locally:
    uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload

Run in production (headless Ubuntu):
    gunicorn app.main:app -k uvicorn.workers.UvicornWorker \
        --workers 4 --bind 0.0.0.0:8080 \
        --access-logfile - --error-logfile -
"""

from __future__ import annotations

import time
import traceback
from contextlib import asynccontextmanager
from typing import AsyncIterator
from uuid import uuid4

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.v1.router import api_router
from app.config import get_settings
from app.logger import configure_logging, logger
from app.models.common import ErrorDetail, ErrorResponse, Meta
from app.services.payload_service import _discover_scanners

# ── Bootstrap ─────────────────────────────────────────────────────────────────
# Logging MUST be configured before any other module emits a log record.
configure_logging()
settings = get_settings()


# ── Lifespan (replaces deprecated on_event handlers) ─────────────────────────

@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    # ── Startup ──────────────────────────────────────────────────────────────
    logger.info(
        "Starting up",
        app=settings.APP_NAME,
        version=settings.APP_VERSION,
        env=settings.APP_ENV,
        host=settings.HOST,
        port=settings.PORT,
    )
    _discover_scanners()
    logger.info("Application ready")

    yield   # ← application runs here

    # ── Shutdown ─────────────────────────────────────────────────────────────
    logger.info("Shutting down gracefully", app=settings.APP_NAME)


# ── Application factory ───────────────────────────────────────────────────────

def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description=(
            "Project Ironclad — Infrastructure Security & Auditing API.\n\n"
            "Submit Dockerfiles, shell scripts, and configuration artifacts for "
            "automated security analysis. All endpoints (except /health/*) require "
            "the `X-Ironclad-Key` header."
        ),
        docs_url="/docs" if settings.DEBUG else None,     # Disable Swagger in prod
        redoc_url="/redoc" if settings.DEBUG else None,
        openapi_url="/openapi.json" if settings.DEBUG else None,
        lifespan=lifespan,
    )

    # ── Middleware ────────────────────────────────────────────────────────────

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def request_logging_middleware(request: Request, call_next):
        """Attach a request ID, log entry/exit, and measure latency."""
        request_id = str(uuid4())
        request.state.request_id = request_id
        start = time.perf_counter()

        logger.info(
            "Request started",
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            client=request.client.host if request.client else "unknown",
        )

        response = await call_next(request)

        elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
        logger.info(
            "Request completed",
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            duration_ms=elapsed_ms,
        )

        response.headers["X-Request-ID"] = request_id
        response.headers["X-Response-Time-ms"] = str(elapsed_ms)
        return response

    # ── Exception handlers ────────────────────────────────────────────────────

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        """Convert Pydantic validation errors into the standard ErrorResponse envelope."""
        errors = exc.errors()
        first = errors[0] if errors else {}
        field = ".".join(str(loc) for loc in first.get("loc", [])) or None

        logger.warning(
            "Request validation failed",
            path=request.url.path,
            errors=errors,
        )

        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=ErrorResponse(
                meta=Meta(),
                error=ErrorDetail(
                    code="validation_error",
                    message=first.get("msg", "Request body is invalid."),
                    field=field,
                    context={"all_errors": errors},
                ),
            ).model_dump(mode="json"),
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(
        request: Request, exc: Exception
    ) -> JSONResponse:
        """
        Catch-all for unhandled exceptions.
        Logs the full traceback server-side; returns a sanitised 500 to the caller
        so internal details are never leaked.
        """
        logger.error(
            "Unhandled exception",
            path=request.url.path,
            method=request.method,
            error=str(exc),
            traceback=traceback.format_exc(),
        )

        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=ErrorResponse(
                meta=Meta(),
                error=ErrorDetail(
                    code="internal_server_error",
                    message=(
                        "An unexpected error occurred. The incident has been logged. "
                        "Please contact the Ironclad administrator."
                    ),
                ),
            ).model_dump(mode="json"),
        )

    # ── Routers ───────────────────────────────────────────────────────────────

    app.include_router(api_router, prefix=settings.API_V1_PREFIX)

    return app


app = create_app()
