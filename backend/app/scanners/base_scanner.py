"""
ironclad/app/scanners/base_scanner.py
Abstract base class for all Ironclad scanner modules.

Every scanner dropped into the `scanners/` directory MUST subclass
`BaseScanner` and implement `scan()`. The orchestration layer in
`payload_service.py` discovers and calls scanners through this interface,
ensuring zero coupling between the API layer and scanning logic.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional
from uuid import UUID


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Finding:
    """A single issue surfaced by a scanner."""

    rule_id: str                       # e.g. "DF001", "SH042"
    title: str
    severity: Severity
    description: str
    line_number: Optional[int] = None
    column: Optional[int] = None
    snippet: Optional[str] = None      # Offending code fragment (sanitised)
    remediation: Optional[str] = None  # Actionable fix guidance
    references: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanResult:
    """Aggregated output of one scanner pass over one payload."""

    scan_id: UUID
    scanner_id: str                    # e.g. "dockerfile_linter"
    scanner_version: str
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        """True when there are zero HIGH or CRITICAL findings."""
        critical_severities = {Severity.HIGH, Severity.CRITICAL}
        return not any(f.severity in critical_severities for f in self.findings)

    @property
    def finding_count(self) -> int:
        return len(self.findings)


class BaseScanner(abc.ABC):
    """
    All scanner modules must inherit from this class.

    Lifecycle:
        1. `payload_service` instantiates the scanner.
        2. `can_handle()` is checked — if False, the scanner is skipped.
        3. `scan()` is called; must return a `ScanResult`.
        4. Results are aggregated and returned via the API.
    """

    #: Unique, stable identifier for this scanner (used in result attribution).
    scanner_id: str = NotImplemented

    #: SemVer string of the scanner implementation.
    scanner_version: str = "0.0.0"

    #: Human-readable name for reporting.
    display_name: str = NotImplemented

    @abc.abstractmethod
    def can_handle(self, payload_type: str) -> bool:
        """
        Return True if this scanner can process the given payload type.
        Called before `scan()` to allow scanners to self-select.
        """

    @abc.abstractmethod
    async def scan(self, scan_id: UUID, content: str, **kwargs: Any) -> ScanResult:
        """
        Execute the scan and return a populated ScanResult.

        Args:
            scan_id:  Correlation ID from the originating PayloadAck.
            content:  Raw text of the artifact.
            **kwargs: Optional scanner-specific configuration.

        Returns:
            ScanResult with zero or more Findings.
        """

    def __repr__(self) -> str:
        return f"<Scanner id={self.scanner_id!r} version={self.scanner_version!r}>"
