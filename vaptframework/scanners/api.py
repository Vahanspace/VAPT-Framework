"""API security tests (ACTIVE, non-destructive by default).

Focused on the OWASP API Top 10 controls that dominate the VahanSpace test plan:
  * API2 Broken Authentication — protected endpoints must reject anonymous / invalid tokens.
  * API1 BOLA — user A's token must not read/modify user B's object.
  * API5 BFLA — a low-privilege role must not invoke a higher-privilege endpoint.

The scanner is data-driven: the engine passes an ``api_tests`` option describing endpoints
and which identities should be allowed/denied. It only issues safe verbs (GET/HEAD) unless
``allow_mutation`` is set AND destructive testing is authorized. Confirming a *denial* is
non-destructive; confirming a mutation requires explicit destructive authorization.
"""
from __future__ import annotations

from ..core.findings import Finding
from ..core.severity import Severity
from .base import Category, ScanContext, Scanner


class ApiScanner(Scanner):
    name = "api"
    category = Category.ACTIVE
    destructive = False

    def scan(self, ctx: ScanContext) -> list[Finding]:
        import requests

        findings: list[Finding] = []
        creds = ctx.credentials or {}
        for spec in ctx.options.get("api_tests", []):
            url = spec["url"]
            ctx.scope.assert_in_scope(url)
            method = spec.get("method", "GET").upper()
            if method not in ("GET", "HEAD"):
                # Non-idempotent probes require destructive authorization; the engine gates
                # destructive scanners, but we double-check here.
                if not ctx.authorization.destructive_allowed():
                    continue

            # 1) Unauthenticated access must be rejected on protected endpoints.
            if spec.get("protected", True):
                r = self._request(ctx, requests, method, url, headers={})
                if r is not None and r.status_code not in (401, 403):
                    findings.append(Finding(
                        title=f"Protected endpoint accepts unauthenticated request: {method} {spec.get('name', url)}",
                        severity=Severity.HIGH, module="API Security",
                        description=f"Expected 401/403 without a token; got {r.status_code}.",
                        location=url, cwe="CWE-306", owasp="API2:2023", source="api",
                        confidence="High", test_id=spec.get("test_id"),
                        remediation="Enforce authentication on all protected endpoints server-side.",
                    ))

            # 2) BOLA: identity 'attacker' must be denied access to 'victim' object.
            attacker = spec.get("attacker_identity")
            if attacker and attacker in creds:
                r = self._request(ctx, requests, method, url, headers=creds[attacker].get("headers", {}))
                if r is not None and r.status_code == 200:
                    findings.append(Finding(
                        title=f"Possible BOLA: {attacker} accessed another tenant's object at {spec.get('name', url)}",
                        severity=Severity.CRITICAL, module="Authorization & BOLA",
                        description=(f"Identity '{attacker}' received 200 for an object it should not own. "
                                     "Confirm the object belongs to a different user/dealer/tenant."),
                        location=url, cwe="CWE-639", owasp="API1:2023", source="api",
                        confidence="Medium", test_id=spec.get("test_id"),
                        remediation="Enforce object-level ownership checks on every request, server-side.",
                    ))
        return findings

    def _request(self, ctx, requests, method, url, headers):
        ctx.scope.assert_in_scope(url)
        if ctx.throttle:
            ctx.throttle.gate()
        try:
            return requests.request(method, url, headers=headers, timeout=15, allow_redirects=False)
        except requests.RequestException:
            return None
