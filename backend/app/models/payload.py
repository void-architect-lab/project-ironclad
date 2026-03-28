"""
ironclad/app/models/payload.py
Pydantic models for payload ingestion — the primary data contract
between callers and the scanning pipeline.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator, model_validator


class PayloadType(str, Enum):
    DOCKERFILE = "dockerfile"
    BASH = "bash"
    YAML = "yaml"
    JSON = "json"
    TOML = "toml"
    NGINX_CONF = "nginx_conf"
    RAW = "raw"


class ScanPriority(str, Enum):
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


class PayloadSubmission(BaseModel):
    """
    Inbound payload submitted for scanning.

    `content` carries the raw text of the artifact (Dockerfile, shell script, etc.).
    Scanners are resolved dynamically from `payload_type` — callers should
    always supply an explicit type rather than relying on 'raw'.
    """

    payload_type: PayloadType = Field(
        ...,
        description="Artifact type; determines which scanner modules are engaged.",
    )
    content: str = Field(
        ...,
        min_length=1,
        description="Raw text content of the artifact to be scanned.",
    )
    filename: Optional[str] = Field(
        default=None,
        max_length=255,
        description="Original filename, for audit trail only.",
    )
    priority: ScanPriority = Field(
        default=ScanPriority.NORMAL,
        description="Scan queue priority hint.",
    )
    tags: list[str] = Field(
        default_factory=list,
        description="Arbitrary caller-supplied tags for grouping / filtering results.",
    )
    metadata: Optional[dict[str, Any]] = Field(
        default=None,
        description="Freeform caller metadata stored alongside the scan record.",
    )

    @field_validator("content")
    @classmethod
    def content_must_not_be_whitespace_only(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Payload content must not be empty or whitespace-only.")
        return v

    @field_validator("tags")
    @classmethod
    def sanitise_tags(cls, tags: list[str]) -> list[str]:
        cleaned = [t.strip().lower() for t in tags if t.strip()]
        if len(cleaned) > 20:
            raise ValueError("Maximum of 20 tags allowed per payload.")
        return cleaned

    @field_validator("filename")
    @classmethod
    def sanitise_filename(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        # Block path traversal
        forbidden = {"../", "./", "/", "\\"}
        for seq in forbidden:
            if seq in v:
                raise ValueError(f"Filename must not contain '{seq}'.")
        return v

    model_config = {"str_strip_whitespace": True}


class PayloadAck(BaseModel):
    """
    Immediate acknowledgement returned upon successful ingestion.
    The `scan_id` is the correlation handle for polling / webhook callbacks.
    """

    scan_id: UUID = Field(default_factory=uuid4, description="Unique scan job identifier.")
    status: str = Field(default="queued", description="Initial lifecycle state.")
    payload_type: PayloadType
    priority: ScanPriority
    queued_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    message: str = Field(default="Payload accepted. Scan job enqueued.")
