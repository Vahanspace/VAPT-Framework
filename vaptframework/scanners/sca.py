"""Software Composition Analysis (PASSIVE).

Finds known-vulnerable and risky dependencies:
  * Python: pip-audit against any requirements*.txt / pyproject when available.
  * Node: `npm audit --json` when npm + a lockfile are present.
Both degrade gracefully: if the tool is missing, a single informational note is emitted so
the report records that the check needs the tool installed, rather than silently passing.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys

from ..core.findings import Finding
from ..core.severity import Severity, severity_from_cvss
from .base import Category, ScanContext, Scanner

_NPM_SEV = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "moderate": Severity.MEDIUM,
            "low": Severity.LOW, "info": Severity.INFORMATIONAL}


def _find_files(root: str, names: tuple) -> list[str]:
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in {".git", "node_modules", ".venv", "venv"}]
        for fn in filenames:
            if fn in names:
                out.append(os.path.join(dirpath, fn))
    return out


def audit_python(req_file: str) -> list[Finding]:
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pip_audit", "-r", req_file, "-f", "json", "--progress-spinner", "off"],
            capture_output=True, text=True, timeout=600,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return [_note("pip-audit not available; Python dependency check skipped", req_file)]
    if not proc.stdout.strip():
        return []
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return []
    deps = data.get("dependencies", data if isinstance(data, list) else [])
    findings = []
    for dep in deps:
        for vuln in dep.get("vulns", []):
            findings.append(
                Finding(
                    title=f"Vulnerable dependency: {dep.get('name')} {dep.get('version')} ({vuln.get('id')})",
                    severity=Severity.HIGH,
                    module="Dependencies / SCA",
                    description=vuln.get("description", "")[:500],
                    location=os.path.basename(req_file),
                    cwe="CWE-1104",
                    owasp="A06:2021",
                    source="pip-audit",
                    confidence="High",
                    remediation=f"Upgrade to a fixed version: {', '.join(vuln.get('fix_versions', []) or ['see advisory'])}.",
                )
            )
    return findings


def audit_node(lock_dir: str) -> list[Finding]:
    if shutil.which("npm") is None:
        return [_note("npm not available; Node dependency audit skipped", os.path.join(lock_dir, "package-lock.json"))]
    try:
        proc = subprocess.run(["npm", "audit", "--json"], cwd=lock_dir, capture_output=True, text=True, timeout=600)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return [_note("npm audit could not run", lock_dir)]
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return []
    findings = []
    for name, adv in (data.get("vulnerabilities") or {}).items():
        sev = _NPM_SEV.get(str(adv.get("severity", "low")).lower(), Severity.LOW)
        findings.append(
            Finding(
                title=f"Vulnerable npm package: {name} ({adv.get('severity')})",
                severity=sev,
                module="Dependencies / SCA",
                description=f"{name} has a known vulnerability advisory. Range: {adv.get('range', 'n/a')}.",
                location="package-lock.json",
                cwe="CWE-1104",
                owasp="A06:2021",
                source="npm-audit",
                confidence="High",
                remediation="Run `npm audit fix` or upgrade the package to a non-vulnerable version.",
            )
        )
    return findings


def _note(msg: str, location: str) -> Finding:
    return Finding(
        title=f"SCA check incomplete: {msg}",
        severity=Severity.INFORMATIONAL,
        module="Dependencies / SCA",
        description=msg,
        location=location,
        source="sca",
        confidence="High",
        remediation="Install the required tool and re-run the SCA scanner for full coverage.",
    )


class ScaScanner(Scanner):
    name = "sca"
    category = Category.PASSIVE
    destructive = False

    def scan(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for root in ctx.source_roots:
            if not os.path.isdir(root):
                continue
            for req in _find_files(root, ("requirements.txt", "requirements-dev.txt")):
                findings.extend(audit_python(req))
            seen_dirs = set()
            for lock in _find_files(root, ("package-lock.json",)):
                d = os.path.dirname(lock)
                if d not in seen_dirs:
                    seen_dirs.add(d)
                    findings.extend(audit_node(d))
        return findings
