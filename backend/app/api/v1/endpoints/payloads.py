"""
ironclad/app/api/v1/endpoints/payloads.py
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Request, status
from fastapi.responses import JSONResponse

from app.dependencies import AuthDep, RequestIdDep
from app.logger import logger
from app.models.common import ErrorDetail, ErrorResponse, Meta, SuccessResponse
from app.models.payload import PayloadAck, PayloadSubmission
from app.services import payload_service
from app.services.payload_service import (
    PayloadTooLargeError,
    ScanNotFoundError,
    UnsupportedPayloadTypeError,
)

router = APIRouter(prefix="/payloads", tags=["Payloads"])


@router.post(
    "/submit",
    response_model=SuccessResponse[PayloadAck],
    status_code=status.HTTP_202_ACCEPTED,
    summary="Submit an artifact for scanning",
    responses={
        202: {"description": "Payload accepted and scanned."},
        400: {"model": ErrorResponse, "description": "Validation error."},
        401: {"model": ErrorResponse, "description": "Missing API key."},
        403: {"model": ErrorResponse, "description": "Invalid API key."},
        413: {"model": ErrorResponse, "description": "Payload exceeds size limit."},
    },
)
async def submit_payload(
    request: Request,
    submission: PayloadSubmission,
    _auth: AuthDep,
    request_id: RequestIdDep,
) -> SuccessResponse[PayloadAck]:
    logger.info(
        "Payload submission received",
        request_id=request_id,
        payload_type=submission.payload_type,
        priority=submission.priority,
        client=request.client.host if request.client else "unknown",
    )

    try:
        ack = await payload_service.ingest_payload(submission)
    except PayloadTooLargeError as exc:
        logger.warning("Payload rejected — too large", request_id=request_id, error=str(exc))
        return JSONResponse(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            content=ErrorResponse(
                meta=Meta(),
                error=ErrorDetail(code="payload_too_large", message=str(exc)),
            ).model_dump(mode="json"),
        )
    except UnsupportedPayloadTypeError as exc:
        logger.warning("Payload rejected — unsupported type", request_id=request_id, error=str(exc))
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=ErrorResponse(
                meta=Meta(),
                error=ErrorDetail(
                    code="unsupported_payload_type",
                    message=str(exc),
                    field="payload_type",
                ),
            ).model_dump(mode="json"),
        )

    return SuccessResponse[PayloadAck](data=ack)


@router.get(
    "/{scan_id}",
    summary="Retrieve scan results by scan ID",
    response_model=SuccessResponse[dict],
    responses={
        200: {"description": "Scan record returned."},
        401: {"model": ErrorResponse, "description": "Missing API key."},
        403: {"model": ErrorResponse, "description": "Invalid API key."},
        404: {"model": ErrorResponse, "description": "Scan ID not found."},
    },
)
async def get_scan_result(
    scan_id: UUID,
    _auth: AuthDep,
    request_id: RequestIdDep,
) -> SuccessResponse[dict]:
    logger.info("Scan result requested", request_id=request_id, scan_id=str(scan_id))

    try:
        result = payload_service.get_scan_result(str(scan_id))
    except ScanNotFoundError as exc:
        logger.warning("Scan ID not found", request_id=request_id, scan_id=str(scan_id))
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content=ErrorResponse(
                meta=Meta(),
                error=ErrorDetail(
                    code="scan_not_found",
                    message=str(exc),
                    field="scan_id",
                ),
            ).model_dump(mode="json"),
        )

    return SuccessResponse[dict](data=result)


@router.get(
    "/types",
    summary="List accepted payload types",
)
async def list_payload_types(_auth: AuthDep) -> SuccessResponse[dict]:
    from app.config import get_settings
    s = get_settings()
    return SuccessResponse(data={"allowed_payload_types": s.ALLOWED_PAYLOAD_TYPES})
