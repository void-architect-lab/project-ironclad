"""
ironclad/app/services/payload_service.py
"""

from __future__ import annotations

import importlib
import pkgutil
from uuid import UUID

from app.config import get_settings
from app.logger import logger
from app.models.payload import PayloadAck, PayloadSubmission
from app.scanners.base_scanner import BaseScanner, ScanResult

settings = get_settings()

_SCANNER_REGISTRY: list[BaseScanner] = []
_SCAN_RESULTS: dict[str, dict] = {}   # scan_id (str) → serialised result payload


def _discover_scanners() -> None:
    import app.scanners as scanners_pkg
    for _finder, module_name, _is_pkg in pkgutil.iter_modules(scanners_pkg.__path__):
        if module_name.startswith("_") or module_name == "base_scanner":
            continue
        try:
            module = importlib.import_module(f"app.scanners.{module_name}")
            for attr_name in dir(module):
                obj = getattr(module, attr_name)
                if (
                    isinstance(obj, type)
                    and issubclass(obj, BaseScanner)
                    and obj is not BaseScanner
                    and not getattr(obj, "__abstractmethods__", None)
                ):
                    instance = obj()
                    _SCANNER_REGISTRY.append(instance)
                    logger.info(
                        "Scanner registered",
                        scanner_id=instance.scanner_id,
                        version=instance.scanner_version,
                    )
        except Exception as exc:
            logger.error("Failed to load scanner module", module=module_name, error=str(exc))
    logger.info("Scanner discovery complete", total_scanners=len(_SCANNER_REGISTRY))


def get_registry() -> list[BaseScanner]:
    return list(_SCANNER_REGISTRY)


class PayloadTooLargeError(Exception):
    pass


class UnsupportedPayloadTypeError(Exception):
    pass


class ScanNotFoundError(Exception):
    pass


def _enforce_payload_limits(submission: PayloadSubmission) -> None:
    size = len(submission.content.encode("utf-8"))
    if size > settings.MAX_PAYLOAD_SIZE_BYTES:
        raise PayloadTooLargeError(
            f"Payload size {size} bytes exceeds limit of {settings.MAX_PAYLOAD_SIZE_BYTES} bytes."
        )
    if submission.payload_type.value not in settings.ALLOWED_PAYLOAD_TYPES:
        raise UnsupportedPayloadTypeError(
            f"Payload type '{submission.payload_type}' is not enabled on this instance."
        )


async def ingest_payload(submission: PayloadSubmission) -> PayloadAck:
    _enforce_payload_limits(submission)

    ack = PayloadAck(
        payload_type=submission.payload_type,
        priority=submission.priority,
    )

    scan_id_str = str(ack.scan_id)

    # Persist initial queued state immediately so GET can return 'queued' before scan completes
    _SCAN_RESULTS[scan_id_str] = {
        "scan_id": scan_id_str,
        "status": "queued",
        "payload_type": submission.payload_type.value,
        "priority": submission.priority.value,
        "queued_at": ack.queued_at.isoformat(),
        "findings": [],
        "scanner_results": [],
        "summary": None,
    }

    logger.info(
        "Payload ingested",
        scan_id=scan_id_str,
        payload_type=submission.payload_type,
        priority=submission.priority,
        content_bytes=len(submission.content.encode("utf-8")),
        tags=submission.tags,
    )

    # Run scanners synchronously for now; swap for queue.enqueue() in Phase 4
    results = await _run_scanners(ack.scan_id, submission)
    _store_results(scan_id_str, results, submission)

    return ack


def _store_results(
    scan_id_str: str,
    results: list[ScanResult],
    submission: PayloadSubmission,
) -> None:
    """Serialise ScanResults and update the in-memory store."""
    from datetime import datetime, timezone

    all_findings = []
    scanner_summaries = []

    for result in results:
        serialised_findings = [
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity.value,
                "description": f.description,
                "line_number": f.line_number,
                "column": f.column,
                "snippet": f.snippet,
                "remediation": f.remediation,
                "references": f.references,
                "extra": f.extra,
            }
            for f in result.findings
        ]
        all_findings.extend(serialised_findings)
        scanner_summaries.append({
            "scanner_id": result.scanner_id,
            "scanner_version": result.scanner_version,
            "finding_count": result.finding_count,
            "passed": result.passed,
            "errors": result.errors,
            "metadata": result.metadata,
        })

    severity_counts: dict[str, int] = {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
    for f in all_findings:
        sev = f["severity"]
        if sev in severity_counts:
            severity_counts[sev] += 1

    overall_passed = all(r.passed for r in results) if results else True

    _SCAN_RESULTS[scan_id_str] = {
        "scan_id": scan_id_str,
        "status": "completed",
        "payload_type": submission.payload_type.value,
        "priority": submission.priority.value,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "findings": all_findings,
        "scanner_results": scanner_summaries,
        "summary": {
            "total_findings": len(all_findings),
            "passed": overall_passed,
            "severity_counts": severity_counts,
            "scanners_run": len(results),
        },
    }

    logger.info(
        "Scan results stored",
        scan_id=scan_id_str,
        total_findings=len(all_findings),
        passed=overall_passed,
    )


def get_scan_result(scan_id: str) -> dict:
    """
    Retrieve a stored scan result by scan_id string.
    Raises ScanNotFoundError if the scan_id is unknown.
    """
    result = _SCAN_RESULTS.get(scan_id)
    if result is None:
        raise ScanNotFoundError(f"No scan record found for id '{scan_id}'.")
    return result


async def _run_scanners(scan_id: UUID, submission: PayloadSubmission) -> list[ScanResult]:
    results: list[ScanResult] = []
    eligible = [s for s in _SCANNER_REGISTRY if s.can_handle(submission.payload_type.value)]
    logger.debug(
        "Running scanner pipeline",
        scan_id=str(scan_id),
        eligible_scanners=[s.scanner_id for s in eligible],
    )
    for scanner in eligible:
        try:
            result = await scanner.scan(scan_id, submission.content)
            results.append(result)
            logger.info(
                "Scanner completed",
                scan_id=str(scan_id),
                scanner_id=scanner.scanner_id,
                findings=result.finding_count,
                passed=result.passed,
            )
        except Exception as exc:
            logger.error(
                "Scanner raised an exception",
                scan_id=str(scan_id),
                scanner_id=scanner.scanner_id,
                error=str(exc),
            )
    return results
