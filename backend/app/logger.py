"""
ironclad/app/logger.py
Structured, rotating, JSON-capable logger built on loguru.
Designed to run headless on Ubuntu — no colour codes in file output,
machine-parseable JSON for shipping to Loki / Elastic / Splunk.
"""

import sys
import os
from pathlib import Path

from loguru import logger as _logger

from app.config import get_settings


def _build_log_format(serialize: bool) -> str:
    """Return a human-friendly format for stderr; JSON is handled by loguru's serialize flag."""
    if serialize:
        return "{message}"   # loguru renders the full JSON record when serialize=True
    return (
        "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
        "<level>{level: <8}</level> | "
        "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | "
        "{message}"
    )


def configure_logging() -> None:
    """
    Called once at startup. Removes loguru's default handler and installs:
      • stderr  — human-readable (non-serialized) at configured level
      • logfile — JSON-serialized, rotating, retained per config
    """
    settings = get_settings()

    _logger.remove()   # Drop the default coloured stderr sink

    # ── stderr sink (always present — systemd / journald will capture it) ──────
    _logger.add(
        sys.stderr,
        level=settings.LOG_LEVEL,
        format=_build_log_format(serialize=False),
        colorize=False,          # headless-safe; no ANSI escape codes
        backtrace=True,
        diagnose=settings.DEBUG,
    )

    # ── file sink ─────────────────────────────────────────────────────────────
    log_path = Path(settings.LOG_DIR)
    log_path.mkdir(parents=True, exist_ok=True)

    _logger.add(
        log_path / settings.LOG_FILE,
        level=settings.LOG_LEVEL,
        rotation=settings.LOG_ROTATION,
        retention=settings.LOG_RETENTION,
        compression="gz",
        serialize=settings.LOG_SERIALIZE,   # JSON lines
        enqueue=True,                        # thread-safe async logging
        backtrace=True,
        diagnose=False,                      # never leak local vars to disk
    )

    _logger.info(
        "Logging configured",
        app=settings.APP_NAME,
        version=settings.APP_VERSION,
        env=settings.APP_ENV,
        log_level=settings.LOG_LEVEL,
        log_file=str(log_path / settings.LOG_FILE),
    )


# Re-export the configured logger for import throughout the app
logger = _logger
