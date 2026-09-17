"""Secret scanner (PASSIVE).

Native, dependency-free regex detection of hard-coded secrets in source. Runs entirely on
local files — never touches the target — so it is always safe to run. Findings point at
``file:line`` and the matched secret value is redacted in the evidence.
"""
from __future__ import annotations

import math
import os
import re
from dataclasses import dataclass

from ..core.findings import Finding
from ..core.severity import Severity
from .base import Category, ScanContext, Scanner


@dataclass
class SecretRule:
    id: str
    description: str
    pattern: re.Pattern
    severity: Severity
    cwe: str = "CWE-798"


_RULES = [
    SecretRule("aws-access-key", "AWS Access Key ID", re.compile(r"AKIA[0-9A-Z]{16}"), Severity.CRITICAL),
    SecretRule("aws-secret-key", "AWS Secret Access Key",
               re.compile(r"(?i)aws.{0,20}?(secret|key).{0,3}['\"][0-9a-zA-Z/+]{40}['\"]"), Severity.CRITICAL),
    SecretRule("private-key", "Private key block",
               re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"), Severity.CRITICAL),
    SecretRule("google-api-key", "Google API key", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), Severity.HIGH),
    SecretRule("slack-token", "Slack token", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,48}"), Severity.HIGH),
    SecretRule("stripe-key", "Stripe secret key", re.compile(r"sk_(live|test)_[0-9a-zA-Z]{24,}"), Severity.CRITICAL),
    SecretRule("razorpay-key", "Razorpay key secret", re.compile(r"rzp_(live|test)_[0-9A-Za-z]{14,}"), Severity.HIGH),
    SecretRule("jwt", "Hard-coded JWT", re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"), Severity.MEDIUM),
    SecretRule("generic-secret", "Generic assigned secret/password",
               re.compile(r"(?i)(password|passwd|secret|api[_-]?key|token|access[_-]?key)\s*[:=]\s*['\"][^'\"\s]{8,}['\"]"),
               Severity.HIGH),
    SecretRule("firebase-db", "Firebase DB URL", re.compile(r"https://[a-z0-9-]+\.firebaseio\.com"), Severity.LOW),
]

# Filenames / content that are placeholders, not real leaks.
_PLACEHOLDER_HINTS = re.compile(r"(?i)(example|sample|placeholder|dummy|your[_-]?|xxxx|changeme|<[^>]+>|\bREPLACE\b)")

_SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build",
              ".next", ".expo", "coverage", ".idea", ".vscode"}
_SCAN_EXT = {".py", ".js", ".jsx", ".ts", ".tsx", ".json", ".env", ".yaml", ".yml",
             ".properties", ".xml", ".gradle", ".plist", ".sh", ".ps1", ".txt", ".md", ".ini", ".conf", ".cfg", ".java", ".kt"}


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def redact(secret: str) -> str:
    s = secret.strip("'\"")
    if len(s) <= 8:
        return "***"
    return f"{s[:3]}...{s[-2:]} ({len(s)} chars)"


def scan_text(text: str, location: str = "") -> list[Finding]:
    findings: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if len(line) > 4000:
            continue
        for rule in _RULES:
            for m in rule.pattern.finditer(line):
                matched = m.group(0)
                if _PLACEHOLDER_HINTS.search(line):
                    continue
                # For the noisy generic rule, require some entropy in the value.
                if rule.id == "generic-secret":
                    val = matched.split("=")[-1].split(":")[-1]
                    if _shannon_entropy(val.strip(" '\"")) < 2.5:
                        continue
                loc = f"{location}:{lineno}" if location else f"line {lineno}"
                findings.append(
                    Finding(
                        title=f"Hard-coded secret: {rule.description}",
                        severity=rule.severity,
                        module="Secrets Management",
                        description=(f"A value matching '{rule.description}' ({rule.id}) appears in source. "
                                     f"Redacted match: {redact(matched)}. Hard-coded credentials must be moved to a "
                                     "secret manager / environment variables and rotated."),
                        location=loc,
                        cwe=rule.cwe,
                        owasp="A07:2021 / API8",
                        source="secrets",
                        confidence="Medium",
                        remediation="Remove the secret from source, rotate it, and load it from a secret store or env var at runtime.",
                    )
                )
    return findings


class SecretScanner(Scanner):
    name = "secrets"
    category = Category.PASSIVE
    destructive = False

    def scan(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for root in ctx.source_roots:
            if not os.path.isdir(root):
                continue
            for dirpath, dirnames, filenames in os.walk(root):
                dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
                for fn in filenames:
                    ext = os.path.splitext(fn)[1].lower()
                    if ext not in _SCAN_EXT and not fn.startswith(".env"):
                        continue
                    fpath = os.path.join(dirpath, fn)
                    try:
                        if os.path.getsize(fpath) > 2_000_000:
                            continue
                        with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                            text = fh.read()
                    except OSError:
                        continue
                    rel = os.path.relpath(fpath, root)
                    findings.extend(scan_text(text, location=rel))
        return findings
