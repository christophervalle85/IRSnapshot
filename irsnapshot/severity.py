"""Analyst review priorities, independent of collection completeness."""

from enum import StrEnum


class Severity(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Explicit display order; severity strings are not alphabetically sorted."""
        return _RANK[self]


_RANK = {severity: rank for rank, severity in enumerate(Severity)}
