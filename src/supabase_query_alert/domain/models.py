"""Core domain models for query analysis and alerting."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    """Alert severity levels, ordered for comparison (higher value = higher severity)."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3


@dataclass(frozen=True, slots=True)
class QueryMetadata:
    """Optional metadata associated with a query."""

    timestamp: datetime | None = None
    user_id: str | None = None
    duration_ms: float | None = None
    source: str | None = None


@dataclass(frozen=True, slots=True)
class Query:
    """A database query with optional metadata."""

    sql: str
    metadata: QueryMetadata | None = None


@dataclass(frozen=True, slots=True)
class Finding:
    """An individual finding from an analyzer."""

    analyzer_name: str
    severity: Severity
    message: str
    details: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class Alert:
    """An alert aggregating multiple findings for a query."""

    query: Query
    findings: tuple[Finding, ...] = field(default_factory=tuple)
    timestamp: datetime = field(default_factory=datetime.now)

    @property
    def severity(self) -> Severity:
        """Return the highest severity among all findings."""
        if not self.findings:
            return Severity.LOW
        return max(finding.severity for finding in self.findings)
