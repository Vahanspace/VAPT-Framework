"""The engine — central guardrail enforcement and orchestration.

Scanners never decide on their own whether they may run. The engine does, uniformly:

    PASSIVE scanner        -> runs (operates on local source/captured data)
    ACTIVE scanner         -> runs ONLY if authorization.active_allowed() and targets exist
    destructive scanner    -> runs ONLY if authorization.destructive_allowed()
    kill switch engaged     -> nothing active runs
    ScopeViolation raised   -> that scanner is marked failed-safe, others continue

Every decision (run / skip + reason) is recorded so the report can show exactly what was and
was not exercised — a skipped active suite is never silently reported as "passed".
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from .authorization import AuthorizationError
from .findings import FindingsRegister
from .ratelimit import TestingHalted
from .scope import ScopeViolation
from ..scanners.base import Category, ScanContext, ScanResult, Scanner


@dataclass
class RunReport:
    started_at: str
    finished_at: str = ""
    results: list[ScanResult] = field(default_factory=list)
    register: FindingsRegister = field(default_factory=FindingsRegister)

    @property
    def executed(self) -> list[str]:
        return [r.scanner for r in self.results if r.ran]

    @property
    def skipped(self) -> dict[str, str]:
        return {r.scanner: r.reason for r in self.results if not r.ran}

    def summary(self) -> dict:
        return {
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "scanners_executed": self.executed,
            "scanners_skipped": self.skipped,
            "total_findings": len(self.register),
            "by_severity": self.register.counts_by_severity(),
        }


class Engine:
    def __init__(self, ctx: ScanContext) -> None:
        self.ctx = ctx

    def _gate(self, scanner: Scanner) -> tuple[bool, str]:
        """Return (allowed, reason_if_not)."""
        # Kill switch first.
        thr = self.ctx.throttle
        if thr is not None and getattr(thr, "kill_switch", None) is not None and thr.kill_switch.engaged():
            return False, "kill switch engaged"

        if scanner.category is Category.PASSIVE:
            if not self.ctx.source_roots:
                return False, "no source_roots configured for passive analysis"
            return True, ""

        # ACTIVE
        if not self.ctx.targets:
            return False, "no in-scope targets configured (active scan requires an authorized target)"
        try:
            self.ctx.authorization.assert_active_allowed()
        except AuthorizationError as exc:
            return False, f"active testing not authorized: {exc}"
        if scanner.destructive:
            try:
                self.ctx.authorization.assert_destructive_allowed()
            except AuthorizationError as exc:
                return False, f"destructive testing not authorized: {exc}"
        return True, ""

    def run(self, scanners: list[Scanner]) -> RunReport:
        report = RunReport(started_at=datetime.now(timezone.utc).replace(microsecond=0).isoformat())
        for scanner in scanners:
            allowed, reason = self._gate(scanner)
            if not allowed:
                report.results.append(ScanResult(scanner=scanner.name, ran=False, reason=reason))
                continue
            result = ScanResult(scanner=scanner.name, ran=True)
            if scanner.required_tool and not scanner.tool_available():
                result.notes.append(f"optional tool '{scanner.required_tool}' not installed; ran in degraded mode")
            try:
                findings = scanner.scan(self.ctx)
                result.findings = findings
                report.register.extend(findings)
            except TestingHalted as exc:
                result.ran = False
                result.reason = f"halted: {exc}"
            except ScopeViolation as exc:
                result.ran = False
                result.reason = f"scope violation (failed safe): {exc}"
            except Exception as exc:  # noqa: BLE001 - a scanner crash must not abort the run
                result.notes.append(f"scanner error: {type(exc).__name__}: {exc}")
            report.results.append(result)
        report.finished_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        return report
