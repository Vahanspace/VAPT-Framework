"""Severity model and CVSS v3.1 base-score mapping.

Severities are ordered so findings can be sorted and aggregated. The mapping from a
CVSS base score to a severity band follows the FIRST CVSS v3.1 qualitative rating scale.
"""
from __future__ import annotations

from enum import Enum
from functools import total_ordering


@total_ordering
class Severity(Enum):
    INFORMATIONAL = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __lt__(self, other: "Severity") -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.value < other.value

    @property
    def label(self) -> str:
        return self.name.capitalize()

    @classmethod
    def from_string(cls, value: str) -> "Severity":
        if value is None:
            raise ValueError("severity string is required")
        key = str(value).strip().upper()
        aliases = {
            "INFO": cls.INFORMATIONAL,
            "INFORMATIONAL": cls.INFORMATIONAL,
            "NONE": cls.INFORMATIONAL,
            "LOW": cls.LOW,
            "MEDIUM": cls.MEDIUM,
            "MED": cls.MEDIUM,
            "HIGH": cls.HIGH,
            "CRITICAL": cls.CRITICAL,
            "CRIT": cls.CRITICAL,
        }
        if key not in aliases:
            raise ValueError(f"unknown severity: {value!r}")
        return aliases[key]


def severity_from_cvss(score: float) -> Severity:
    """Map a CVSS v3.1 base score (0.0-10.0) to a qualitative severity band."""
    if score is None:
        raise ValueError("cvss score is required")
    score = float(score)
    if not 0.0 <= score <= 10.0:
        raise ValueError(f"cvss score out of range 0.0-10.0: {score}")
    if score == 0.0:
        return Severity.INFORMATIONAL
    if score < 4.0:
        return Severity.LOW
    if score < 7.0:
        return Severity.MEDIUM
    if score < 9.0:
        return Severity.HIGH
    return Severity.CRITICAL
