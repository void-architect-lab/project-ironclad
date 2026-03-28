"""
ironclad/app/config.py
Centralised settings management via pydantic-settings.
Values are read from environment variables or a .env file.
"""

from functools import lru_cache
from typing import List

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Application ────────────────────────────────────────────────────────────
    APP_NAME: str = "Project Ironclad"
    APP_VERSION: str = "0.1.0"
    APP_ENV: str = "production"          # production | development | testing
    DEBUG: bool = False

    # ── Server ─────────────────────────────────────────────────────────────────
    HOST: str = "0.0.0.0"
    PORT: int = 8080
    WORKERS: int = 4                     # For gunicorn/uvicorn multi-process

    # ── API ────────────────────────────────────────────────────────────────────
    API_V1_PREFIX: str = "/api/v1"
    ALLOWED_ORIGINS: List[str] = ["*"]   # Tighten in production

    # ── Payload limits ─────────────────────────────────────────────────────────
    MAX_PAYLOAD_SIZE_BYTES: int = 5 * 1024 * 1024   # 5 MB hard cap
    ALLOWED_PAYLOAD_TYPES: List[str] = [
        "dockerfile",
        "bash",
        "yaml",
        "json",
        "toml",
        "nginx_conf",
        "raw",
    ]

    # ── Logging ────────────────────────────────────────────────────────────────
    LOG_LEVEL: str = "INFO"
    LOG_DIR: str = "logs"
    LOG_FILE: str = "ironclad.log"
    LOG_ROTATION: str = "10 MB"
    LOG_RETENTION: str = "30 days"
    LOG_SERIALIZE: bool = True           # JSON lines for log-shipping pipelines

    # ── Security ───────────────────────────────────────────────────────────────
    API_KEY_HEADER: str = "X-Ironclad-Key"
    API_KEY: str = "CHANGEME_BEFORE_DEPLOY"   # Override via env

    @field_validator("APP_ENV")
    @classmethod
    def validate_env(cls, v: str) -> str:
        allowed = {"production", "development", "testing"}
        if v not in allowed:
            raise ValueError(f"APP_ENV must be one of {allowed}")
        return v

    @field_validator("LOG_LEVEL")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        allowed = {"TRACE", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if v.upper() not in allowed:
            raise ValueError(f"LOG_LEVEL must be one of {allowed}")
        return v.upper()


@lru_cache
def get_settings() -> Settings:
    """Cached singleton — safe to call anywhere."""
    return Settings()
