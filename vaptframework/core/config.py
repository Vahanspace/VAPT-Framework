"""Load a run configuration (YAML) into the objects the engine needs.

A run config binds together: scope, authorization, targets, source roots, throttle settings,
evidence/report output, and which scanner suites to enable. It is the single artifact an
operator edits per engagement.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

import yaml

from .authorization import Authorization
from .ratelimit import KillSwitch, Throttle, TokenBucket
from .scope import Scope, ScopeGuard
from ..scanners.base import ScanContext


@dataclass
class RunConfig:
    context: ScanContext
    suites: list[str]
    evidence_dir: str
    report_dir: str
    meta: dict = field(default_factory=dict)


DEFAULT_SUITES = ["secrets", "sast", "sca", "config-audit", "dast", "api"]


def load_run_config(path: str) -> RunConfig:
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}

    scope = Scope.from_dict(data.get("scope", {}))
    guard = ScopeGuard(scope)
    authz = Authorization.from_dict(data.get("authorization", {}))

    rl = data.get("rate_limit", {})
    bucket = TokenBucket(
        rate_per_sec=float(rl.get("requests_per_second", 2)),
        burst=int(rl.get("burst", 4)),
    )
    stop_file = data.get("kill_switch_file", os.path.join(os.getcwd(), "STOP_TESTING"))
    throttle = Throttle(bucket, KillSwitch(stop_file=stop_file))

    evidence_dir = data.get("evidence_dir", "evidence")
    report_dir = data.get("report_dir", "reports")

    # source_roots can live under scope or top-level
    source_roots = data.get("source_roots") or scope.source_roots or []
    source_roots = [os.path.abspath(os.path.expanduser(p)) for p in source_roots]

    # options.api_tests may be supplemented from an external JSON file (generated inventory)
    options = dict(data.get("options", {}))
    tests_file = options.pop("api_tests_file", None)
    if tests_file:
        tf = os.path.join(os.path.dirname(os.path.abspath(path)), tests_file) \
            if not os.path.isabs(tests_file) else tests_file
        if os.path.exists(tf):
            import json as _json
            with open(tf, "r", encoding="utf-8") as fh:
                loaded = _json.load(fh)
            existing = options.get("api_tests") or []
            options["api_tests"] = list(existing) + list(loaded)

    # Substitute the ${TARGET} placeholder in api_tests urls with the first configured target.
    targets = data.get("targets", [])
    if targets and options.get("api_tests"):
        base = str(targets[0]).rstrip("/")
        for spec in options["api_tests"]:
            if isinstance(spec.get("url"), str):
                spec["url"] = spec["url"].replace("${TARGET}", base)

    ctx = ScanContext(
        scope=guard,
        authorization=authz,
        throttle=throttle,
        targets=data.get("targets", []),
        source_roots=source_roots,
        evidence_dir=evidence_dir,
        options=options,
        credentials=data.get("credentials", {}),
    )
    return RunConfig(
        context=ctx,
        suites=data.get("suites", DEFAULT_SUITES),
        evidence_dir=evidence_dir,
        report_dir=report_dir,
        meta=data.get("meta", {}),
    )


def build_scanners(suites: list[str]):
    from ..scanners.secrets import SecretScanner
    from ..scanners.sast import SastScanner
    from ..scanners.sca import ScaScanner
    from ..scanners.config_audit import ConfigAuditScanner
    from ..scanners.dast import DastScanner
    from ..scanners.api import ApiScanner

    registry = {
        "secrets": SecretScanner, "sast": SastScanner, "sca": ScaScanner,
        "config-audit": ConfigAuditScanner, "dast": DastScanner, "api": ApiScanner,
    }
    return [registry[s]() for s in suites if s in registry]
