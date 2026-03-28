"""
ironclad/app/models/common.py
Shared response envelope models used across all endpoints.
Provides consistent API contract regardless of the scanner module responding.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Generic, Optional, TypeVar
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

DataT = TypeVar("DataT")


class Meta(BaseModel):
    """Request-scoped metadata attached to every response."""
    request_id: UUID = Field(default_factory=uuid4, description="Unique request trace ID")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of the response",
    )
    api_version: str = Field(default="v1")


class SuccessResponse(BaseModel, Generic[DataT]):
    """Standard success envelope."""
    success: bool = True
    meta: Meta = Field(default_factory=Meta)
    data: DataT


class ErrorDetail(BaseModel):
    """Machine-readable error descriptor."""
    code: str = Field(description="Snake-case error code, e.g. 'payload_too_large'")
    message: str = Field(description="Human-readable explanation")
    field: Optional[str] = Field(default=None, description="Offending field, if applicable")
    context: Optional[dict[str, Any]] = Field(default=None, description="Extra diagnostic info")


class ErrorResponse(BaseModel):
    """Standard error envelope — never leaks stack traces to callers."""
    success: bool = False
    meta: Meta = Field(default_factory=Meta)
    error: ErrorDetail
