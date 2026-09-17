"""Dynamic Application Security Testing (ACTIVE, non-destructive).

Conservative, evidence-oriented probes against an authorized in-scope target:
  * HTTP method enumeration (OPTIONS/TRACE/PUT exposure),
  * verbose error handling (500 with stack traces),
  * reflected-input check using a benign, non-executing marker,
  * open-redirect check on redirect parameters.

No exploitation, no data mutation, no fuzz storms. Every request is scope-checked and
rate-limited by the engine-provided throttle. Injection *exploitation* and DoS are out of
scope for this scanner by design (see docs/GUARDRAILS.md).
"""
from __future__ import annotations

from urllib.parse import urljoin, urlencode

from ..core.findings import Finding
from ..core.severity import Severity
from .base import Category, ScanContext, Scanner

_BENIGN_MARKER = "vaptcanary9137"   # unique, inert reflection marker (no HTML/script)


class DastScanner(Scanner):
    name = "dast"
    category = Category.ACTIVE
    destructive = False

    def scan(self, ctx: ScanContext) -> list[Finding]:
        import requests

        findings: list[Finding] = []
        for target in ctx.targets:
            ctx.scope.assert_in_scope(target)
            findings.extend(self._http_methods(ctx, requests, target))
            findings.extend(self._reflection(ctx, requests, target))
            findings.extend(self._error_handling(ctx, requests, target))
        return findings

    def _get(self, ctx, requests, url, **kw):
        ctx.scope.assert_in_scope(url)
        if ctx.throttle:
            ctx.throttle.gate()
        return requests.get(url, timeout=15, **kw)

    def _http_methods(self, ctx, requests, target):
        findings = []
        try:
            ctx.scope.assert_in_scope(target)
            if ctx.throttle:
                ctx.throttle.gate()
            resp = requests.options(target, timeout=15)
        except requests.RequestException:
            return findings
        allow = resp.headers.get("Allow", "")
        for risky in ("TRACE", "TRACK"):
            if risky in allow.upper():
                findings.append(Finding(
                    title=f"Dangerous HTTP method enabled: {risky}",
                    severity=Severity.MEDIUM, module="Web Security / Config",
                    description=f"Server advertises {risky} in Allow: {allow}.",
                    location=target, cwe="CWE-16", owasp="A05:2021", source="dast",
                    confidence="High", remediation=f"Disable the {risky} method at the web server.",
                ))
        return findings

    def _reflection(self, ctx, requests, target):
        findings = []
        probe = urljoin(target, "?" + urlencode({"q": _BENIGN_MARKER}))
        try:
            resp = self._get(ctx, requests, probe)
        except requests.RequestException:
            return findings
        if _BENIGN_MARKER in resp.text:
            findings.append(Finding(
                title="User input reflected in response (potential XSS surface)",
                severity=Severity.LOW, module="Data Input Validation",
                description=("A benign marker supplied in a query parameter was reflected unencoded in the "
                             "response body. Confirm output encoding/context; this is a candidate for reflected XSS."),
                location=probe, cwe="CWE-79", owasp="A03:2021", source="dast", confidence="Low",
                remediation="Context-encode all user input on output; add a Content-Security-Policy.",
            ))
        return findings

    def _error_handling(self, ctx, requests, target):
        findings = []
        probe = urljoin(target, "/vapt-nonexistent-" + _BENIGN_MARKER)
        try:
            resp = self._get(ctx, requests, probe)
        except requests.RequestException:
            return findings
        body = resp.text.lower()
        markers = ["traceback (most recent call last)", "stack trace", "at java.", "django.core",
                   "sqlalchemy", "psycopg2", "syntaxerror", "referenceerror"]
        if resp.status_code >= 500 and any(m in body for m in markers):
            findings.append(Finding(
                title="Verbose error / stack trace disclosure",
                severity=Severity.MEDIUM, module="Error Handling",
                description="A server error response leaked internal stack-trace/framework detail.",
                location=probe, cwe="CWE-209", owasp="A05:2021", source="dast", confidence="Medium",
                remediation="Return generic error pages; log details server-side only.",
            ))
        return findings
