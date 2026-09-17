"""Pre-flight readiness check for the dynamic round.

Runs before any active testing and produces a go/no-go with actionable reasons. It never
sends traffic — it only inspects the assembled run configuration for the conditions the
guardrails require, so an operator gets a single clear checklist instead of discovering
gaps mid-run.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..scanners.base import Category


@dataclass
class Check:
    ok: bool
    level: str      # "blocker" | "warn" | "info"
    message: str


@dataclass
class PreflightReport:
    checks: list[Check] = field(default_factory=list)

    def add(self, ok, level, message):
        self.checks.append(Check(ok, level, message))

    @property
    def blockers(self):
        return [c for c in self.checks if not c.ok and c.level == "blocker"]

    @property
    def go(self) -> bool:
        return not self.blockers

    def render(self) -> str:
        icon = {"blocker": "X", "warn": "!", "info": "i"}
        lines = []
        for c in self.checks:
            mark = "OK " if c.ok else icon.get(c.level, "?") + "  "
            lines.append(f"[{mark}] {c.message}")
        lines.append("")
        lines.append("PREFLIGHT: GO" if self.go else f"PREFLIGHT: NO-GO ({len(self.blockers)} blocker(s))")
        return "\n".join(lines)


def preflight(run_config, scanners) -> PreflightReport:
    ctx = run_config.context
    rep = PreflightReport()
    wants_active = any(s.category is Category.ACTIVE for s in scanners)

    # Scope
    rep.add(bool(ctx.scope.scope.allowed_hosts), "warn" if not wants_active else "blocker",
            f"Scope allowlist has {len(ctx.scope.scope.allowed_hosts)} host(s)")
    rep.add(not (ctx.scope.scope.environment == "production" and not ctx.scope.scope.allow_production),
            "blocker", f"Environment is '{ctx.scope.scope.environment}' (production requires allow_production)")

    if wants_active:
        # Targets
        rep.add(bool(ctx.targets), "blocker", f"{len(ctx.targets)} active target(s) configured")
        for t in ctx.targets:
            rep.add(ctx.scope.is_in_scope(t), "blocker", f"Target in scope: {t}")
        # Authorization
        reason = ctx.authorization.reason_invalid()
        rep.add(reason is None, "blocker", f"Authorization valid: {reason or 'signed and in-date'}")
        rep.add(ctx.authorization.allow_active_testing, "blocker",
                "Active testing authorized (allow_active_testing)")
        rep.add(True, "info",
                f"Destructive testing: {'ENABLED' if ctx.authorization.allow_destructive else 'disabled (default)'}")
        # Credentials referenced by api_tests
        needed = set()
        for spec in ctx.options.get("api_tests", []):
            for key in ("attacker_identity", "forbidden_identity"):
                if spec.get(key):
                    needed.add(spec[key])
        missing = sorted(needed - set(ctx.credentials or {}))
        rep.add(not missing, "warn",
                f"Credentials present for referenced identities"
                + (f"; MISSING: {', '.join(missing)}" if missing else ""))
        # Kill switch reachability
        ks = getattr(ctx.throttle, "kill_switch", None)
        rep.add(ks is not None, "warn", f"Kill switch configured: {getattr(ks, 'stop_file', 'none')}")
        rep.add(True, "info", f"Rate limit: {ctx.throttle.bucket.rate}/s burst {int(ctx.throttle.bucket.capacity)}")
    else:
        rep.add(bool(ctx.source_roots), "blocker",
                f"{len(ctx.source_roots)} source root(s) for static analysis")

    return rep
