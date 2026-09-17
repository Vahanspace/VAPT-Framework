"""Static Application Security Testing (PASSIVE).

Two engines, both offline and safe:
  1. Bandit for Python (invoked as a module; parsed from JSON) when available.
  2. A native, dependency-free rule set of high-signal source patterns that also covers
     JavaScript/TypeScript/JSX and config, which Bandit does not.

Everything runs on local files only; nothing here touches the target.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass

from ..core.findings import Finding
from ..core.severity import Severity
from .base import Category, ScanContext, Scanner

_SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build",
              ".next", ".expo", "coverage", ".idea", ".vscode", "migrations"}


@dataclass
class CodeRule:
    id: str
    description: str
    pattern: re.Pattern
    severity: Severity
    cwe: str
    owasp: str
    exts: tuple
    remediation: str


_NATIVE_RULES = [
    CodeRule("js-eval", "Use of eval() on dynamic input",
             re.compile(r"\beval\s*\("), Severity.HIGH, "CWE-95", "A03:2021",
             (".js", ".jsx", ".ts", ".tsx"), "Avoid eval(); use safe parsers / explicit dispatch."),
    CodeRule("react-dangerous-html", "React dangerouslySetInnerHTML",
             re.compile(r"dangerouslySetInnerHTML"), Severity.MEDIUM, "CWE-79", "A03:2021",
             (".js", ".jsx", ".ts", ".tsx"), "Sanitize HTML (e.g. DOMPurify) or render as text."),
    CodeRule("node-child-process-concat", "Shell command built from a variable",
             re.compile(r"(exec|execSync)\s*\(\s*[`\"'][^`\"']*\$\{"), Severity.HIGH, "CWE-78", "A03:2021",
             (".js", ".ts"), "Use execFile with an argument array; never interpolate input into a shell string."),
    CodeRule("tls-verify-off-node", "TLS certificate verification disabled",
             re.compile(r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0"),
             Severity.HIGH, "CWE-295", "A02:2021", (".js", ".ts", ".env"),
             "Never disable TLS verification; fix the certificate chain instead."),
    CodeRule("py-verify-off", "requests called with verify=False",
             re.compile(r"verify\s*=\s*False"), Severity.HIGH, "CWE-295", "A02:2021",
             (".py",), "Do not disable TLS verification; pin/trust the correct CA."),
    CodeRule("py-subprocess-shell", "subprocess with shell=True",
             re.compile(r"subprocess\.(run|call|Popen|check_output)\([^)]*shell\s*=\s*True"),
             Severity.HIGH, "CWE-78", "A03:2021", (".py",),
             "Pass args as a list and avoid shell=True with untrusted input."),
    CodeRule("py-debug-true", "Framework debug mode enabled",
             re.compile(r"(?i)\bdebug\s*=\s*True"), Severity.MEDIUM, "CWE-489", "A05:2021",
             (".py",), "Disable debug in production; it leaks stack traces and enables consoles."),
    CodeRule("sql-fstring", "SQL built via f-string/format/concatenation",
             re.compile(r"(?i)(execute|executemany|cursor\.execute)\s*\(\s*f?['\"].*(select|insert|update|delete).*(\{|%s?\s*%|\+)"),
             Severity.CRITICAL, "CWE-89", "A03:2021", (".py",),
             "Use parameterized queries / ORM bindings; never build SQL from strings."),
    CodeRule("weak-hash", "Weak hash algorithm (MD5/SHA1)",
             re.compile(r"(?i)hashlib\.(md5|sha1)\s*\(|createHash\(\s*['\"](md5|sha1)['\"]"),
             Severity.MEDIUM, "CWE-327", "A02:2021", (".py", ".js", ".ts"),
             "Use SHA-256+ for integrity and bcrypt/argon2/scrypt for passwords."),
    CodeRule("cors-wildcard", "CORS allows any origin",
             re.compile(r"(?i)(access-control-allow-origin['\"]?\s*[:=]\s*['\"]\*)|allow_origins\s*=\s*\[?\s*['\"]\*['\"]"),
             Severity.MEDIUM, "CWE-942", "A05:2021", (".py", ".js", ".ts"),
             "Restrict CORS to an explicit origin allowlist; avoid '*' with credentials."),
    CodeRule("jwt-no-verify", "JWT decoded without signature verification",
             re.compile(r"(?i)jwt\.decode\([^)]*verify\s*=\s*False|verify_signature['\"]?\s*:\s*false"),
             Severity.HIGH, "CWE-347", "A02:2021", (".py", ".js", ".ts"),
             "Always verify JWT signatures and the algorithm allowlist."),
    CodeRule("insecure-random-token", "Math.random used for security value",
             re.compile(r"(?i)(token|secret|otp|nonce|password).{0,20}Math\.random\("),
             Severity.MEDIUM, "CWE-330", "A02:2021", (".js", ".ts"),
             "Use a CSPRNG (crypto.randomBytes / secrets module) for security tokens."),
]


def scan_text_native(text: str, filename: str) -> list[Finding]:
    ext = os.path.splitext(filename)[1].lower()
    findings: list[Finding] = []
    lines = text.splitlines()
    for rule in _NATIVE_RULES:
        if ext not in rule.exts:
            continue
        for lineno, line in enumerate(lines, start=1):
            if line.lstrip().startswith(("#", "//", "*")):
                continue
            if rule.pattern.search(line):
                findings.append(
                    Finding(
                        title=rule.description,
                        severity=rule.severity,
                        module="SAST / Code",
                        description=f"{rule.description} ({rule.id}). Pattern matched in source.",
                        location=f"{filename}:{lineno}",
                        cwe=rule.cwe,
                        owasp=rule.owasp,
                        source="sast-native",
                        confidence="Medium",
                        remediation=rule.remediation,
                    )
                )
    return findings


_BANDIT_SEVERITY = {"LOW": Severity.LOW, "MEDIUM": Severity.MEDIUM, "HIGH": Severity.HIGH}


def run_bandit(root: str) -> list[Finding]:
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "bandit", "-r", root, "-f", "json", "-q",
             "--exclude", ",".join(os.path.join(root, d) for d in _SKIP_DIRS)],
            capture_output=True, text=True, timeout=600,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    if not proc.stdout.strip():
        return []
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return []
    findings: list[Finding] = []
    for r in data.get("results", []):
        sev = _BANDIT_SEVERITY.get(r.get("issue_severity", "LOW"), Severity.LOW)
        rel = os.path.relpath(r.get("filename", ""), root)
        findings.append(
            Finding(
                title=f"Bandit: {r.get('test_name','issue')} — {r.get('issue_text','')[:120]}",
                severity=sev,
                module="SAST / Code",
                description=r.get("issue_text", ""),
                location=f"{rel}:{r.get('line_number', 0)}",
                cwe=f"CWE-{r.get('issue_cwe', {}).get('id')}" if r.get("issue_cwe") else "",
                owasp="A03:2021",
                source="bandit",
                confidence=r.get("issue_confidence", "Medium").capitalize(),
                remediation="Review the Bandit finding and apply the secure alternative.",
            )
        )
    return findings


class SastScanner(Scanner):
    name = "sast"
    category = Category.PASSIVE
    destructive = False

    def scan(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for root in ctx.source_roots:
            if not os.path.isdir(root):
                continue
            findings.extend(run_bandit(root))
            for dirpath, dirnames, filenames in os.walk(root):
                dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
                for fn in filenames:
                    ext = os.path.splitext(fn)[1].lower()
                    if ext not in (".py", ".js", ".jsx", ".ts", ".tsx", ".env"):
                        continue
                    fpath = os.path.join(dirpath, fn)
                    try:
                        if os.path.getsize(fpath) > 2_000_000:
                            continue
                        with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                            text = fh.read()
                    except OSError:
                        continue
                    findings.extend(scan_text_native(text, os.path.relpath(fpath, root)))
        return findings
