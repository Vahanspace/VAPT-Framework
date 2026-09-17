"""Security header / response configuration audit.

Has two modes:
  * PASSIVE: evaluate a dict of already-captured response headers (unit-testable, no network).
  * ACTIVE:  when targets + authorization are present, perform a single throttled GET per
    target and evaluate the live headers. The active path is gated by the engine.

This scanner is registered as ACTIVE because it can issue a request; the header-evaluation
logic itself is pure and reused by the DAST scanner.
"""
from __future__ import annotations

from ..core.findings import Finding
from ..core.severity import Severity
from .base import Category, ScanContext, Scanner

# header -> (severity, why, remediation)
_EXPECTED_HEADERS = {
    "strict-transport-security": (Severity.MEDIUM, "HSTS not set; downgrade/MITM risk on HTTPS.",
                                  "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'."),
    "content-security-policy": (Severity.MEDIUM, "No CSP; increases XSS blast radius.",
                                "Define a restrictive Content-Security-Policy."),
    "x-content-type-options": (Severity.LOW, "MIME sniffing not disabled.",
                               "Set 'X-Content-Type-Options: nosniff'."),
    "x-frame-options": (Severity.LOW, "Clickjacking protection missing (or use CSP frame-ancestors).",
                        "Set 'X-Frame-Options: DENY' or CSP 'frame-ancestors'."),
    "referrer-policy": (Severity.LOW, "Referrer policy not set; may leak URLs.",
                        "Set 'Referrer-Policy: no-referrer' or 'strict-origin-when-cross-origin'."),
}

_LEAKY_HEADERS = {"server", "x-powered-by", "x-aspnet-version"}


def evaluate_headers(headers: dict, location: str) -> list[Finding]:
    lower = {str(k).lower(): str(v) for k, v in headers.items()}
    findings: list[Finding] = []
    for name, (sev, why, fix) in _EXPECTED_HEADERS.items():
        if name not in lower:
            findings.append(Finding(
                title=f"Missing security header: {name}",
                severity=sev, module="Web Security / Config",
                description=why, location=location, cwe="CWE-693", owasp="A05:2021",
                source="config", confidence="High", remediation=fix,
            ))
    for name in _LEAKY_HEADERS:
        if name in lower and lower[name].strip():
            findings.append(Finding(
                title=f"Verbose header discloses technology: {name}: {lower[name][:60]}",
                severity=Severity.LOW, module="Web Security / Config",
                description="Server/framework version disclosure aids targeted attacks.",
                location=location, cwe="CWE-200", owasp="A05:2021",
                source="config", confidence="High",
                remediation=f"Remove or generalize the '{name}' response header.",
            ))
    # cookie flags
    set_cookie = lower.get("set-cookie", "")
    if set_cookie:
        sc = set_cookie.lower()
        if "httponly" not in sc:
            findings.append(_cookie_finding("HttpOnly", location))
        if "secure" not in sc:
            findings.append(_cookie_finding("Secure", location))
        if "samesite" not in sc:
            findings.append(_cookie_finding("SameSite", location))
    return findings


def _cookie_finding(flag: str, location: str) -> Finding:
    return Finding(
        title=f"Session cookie missing {flag} flag",
        severity=Severity.MEDIUM, module="Session Management",
        description=f"Set-Cookie is missing the {flag} attribute.",
        location=location, cwe="CWE-1004" if flag == "HttpOnly" else "CWE-614",
        owasp="A05:2021", source="config", confidence="High",
        remediation=f"Set the {flag} attribute on session cookies.",
    )


class ConfigAuditScanner(Scanner):
    name = "config-audit"
    category = Category.ACTIVE      # can issue a GET; gated by the engine
    destructive = False

    def scan(self, ctx: ScanContext) -> list[Finding]:
        import requests  # local import; only needed on the active path

        findings: list[Finding] = []
        for target in ctx.targets:
            ctx.scope.assert_in_scope(target)          # defence in depth
            if ctx.throttle:
                ctx.throttle.gate()
            try:
                resp = requests.get(target, timeout=15, allow_redirects=True)
            except requests.RequestException as exc:
                findings.append(Finding(
                    title="Target unreachable during config audit",
                    severity=Severity.INFORMATIONAL, module="Web Security / Config",
                    description=str(exc), location=target, source="config", confidence="High",
                ))
                continue
            findings.extend(evaluate_headers(dict(resp.headers), location=target))
        return findings
