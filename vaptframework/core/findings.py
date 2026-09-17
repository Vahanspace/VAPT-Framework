"""Finding data model and register.

A Finding is a single confirmed or suspected security issue produced by a scanner or by
manual testing. The FindingsRegister aggregates findings, de-duplicates them by a stable
fingerprint, and produces severity roll-ups used by the report and the xlsx dashboard.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Iterable, Optional

from .severity import Severity


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass
class Finding:
    title: str
    severity: Severity
    module: str
    description: str = ""
    platform: str = "Web/API/Mobile"
    test_id: Optional[str] = None          # link to VAPT-### test case
    cvss: Optional[float] = None
    cwe: Optional[str] = None              # e.g. "CWE-89"
    owasp: Optional[str] = None            # e.g. "API1:2023"
    location: str = ""                     # file:line, URL, endpoint
    evidence_ref: str = ""                 # path/reference into the evidence store
    remediation: str = ""
    status: str = "Open"                   # Open | Retest | Closed | False Positive
    confidence: str = "Medium"            # Low | Medium | High
    source: str = ""                       # scanner name / "manual"
    discovered_at: str = field(default_factory=_utcnow_iso)
    finding_id: Optional[str] = None

    def __post_init__(self) -> None:
        if isinstance(self.severity, str):
            self.severity = Severity.from_string(self.severity)
        if not self.title or not self.title.strip():
            raise ValueError("Finding.title is required")
        if not self.module or not self.module.strip():
            raise ValueError("Finding.module is required")
        if self.finding_id is None:
            self.finding_id = self.fingerprint()[:12].upper()

    def fingerprint(self) -> str:
        """Stable content hash used for de-duplication."""
        basis = "|".join(
            [
                (self.title or "").strip().lower(),
                (self.module or "").strip().lower(),
                (self.location or "").strip().lower(),
                (self.cwe or "").strip().lower(),
            ]
        )
        return hashlib.sha256(basis.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.label
        return d


class FindingsRegister:
    def __init__(self) -> None:
        self._by_fp: dict[str, Finding] = {}

    def add(self, finding: Finding) -> bool:
        """Add a finding. Returns False if a duplicate (same fingerprint) already exists."""
        fp = finding.fingerprint()
        if fp in self._by_fp:
            return False
        self._by_fp[fp] = finding
        return True

    def extend(self, findings: Iterable[Finding]) -> int:
        return sum(1 for f in findings if self.add(f))

    def __len__(self) -> int:
        return len(self._by_fp)

    def __iter__(self):
        return iter(sorted(self._by_fp.values(), key=lambda f: (-f.severity.value, f.module, f.title)))

    @property
    def findings(self) -> list[Finding]:
        return list(iter(self))

    def counts_by_severity(self) -> dict[str, int]:
        counts = {s.label: 0 for s in sorted(Severity, reverse=True)}
        for f in self._by_fp.values():
            counts[f.severity.label] += 1
        return counts

    def open_count(self) -> int:
        return sum(1 for f in self._by_fp.values() if f.status.lower() == "open")

    def to_json(self, indent: int = 2) -> str:
        return json.dumps([f.to_dict() for f in self], indent=indent)
