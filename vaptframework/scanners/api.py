"""API security tests (ACTIVE, non-destructive by default).

Covers the OWASP API Top 10 controls that dominate the VahanSpace test plan. Each spec
declares a ``check``:

  * ``unauth`` (API2) — a protected endpoint must reject an anonymous request (401/403).
  * ``bfla``   (API5) — a low-privilege identity must be denied a privileged endpoint.
  * ``bola``   (API1) — an attacker identity must not read another tenant's object.

Only idempotent verbs (GET/HEAD) run unless ``allow_mutation`` is set AND destructive
testing is authorized. Confirming a *denial* is non-destructive; confirming a mutation is
not. Every request is scope-checked and rate-limited by the engine-provided throttle.
"""
from __future__ import annotations

from ..core.findings import Finding
from ..core.severity import Severity
from .base import Category, ScanContext, Scanner

_DENY_CODES = (401, 403)


class ApiScanner(Scanner):
    name = "api"
    category = Category.ACTIVE
    destructive = False

    def scan(self, ctx: ScanContext) -> list[Finding]:
        import requests

        findings: list[Finding] = []
        creds = ctx.credentials or {}
        for spec in ctx.options.get("api_tests", []):
            url = spec.get("url")
            if not url:
                continue
            ctx.scope.assert_in_scope(url)
            method = spec.get("method", "GET").upper()
            check = spec.get("check")

            # Back-compat: infer check from legacy fields.
            if not check:
                check = "bola" if spec.get("attacker_identity") else "unauth"

            if method not in ("GET", "HEAD") and not ctx.authorization.destructive_allowed():
                continue  # mutating probe needs destructive authorization

            if check == "unauth" and spec.get("protected", True):
                f = self._unauth(ctx, requests, method, url, spec)
                if f:
                    findings.append(f)
            elif check == "bfla":
                f = self._bfla(ctx, requests, method, url, spec, creds)
                if f:
                    findings.append(f)
            elif check == "bola":
                f = self._bola(ctx, requests, method, url, spec, creds)
                if f:
                    findings.append(f)
        return findings

    # -- individual checks ---------------------------------------------------
    def _unauth(self, ctx, requests, method, url, spec):
        r = self._request(ctx, requests, method, url, {})
        if r is not None and r.status_code not in _DENY_CODES:
            return Finding(
                title=f"Protected endpoint accepts unauthenticated request: {method} {spec.get('name', url)}",
                severity=Severity.HIGH, module="API Security",
                description=f"Expected 401/403 without a token; got {r.status_code}. "
                            f"Endpoint auth level: {spec.get('auth_required','?')}.",
                location=url, cwe="CWE-306", owasp="API2:2023", source="api",
                confidence="High", test_id=spec.get("test_id"),
                remediation="Enforce authentication on all protected endpoints server-side.",
            )
        return None

    def _bfla(self, ctx, requests, method, url, spec, creds):
        who = spec.get("forbidden_identity", "user")
        if who not in creds:
            return None  # no token for this role; skip (recorded as not-run by absence)
        r = self._request(ctx, requests, method, url, creds[who].get("headers", {}))
        if r is not None and r.status_code == 200:
            return Finding(
                title=f"Broken function-level authorization: '{who}' reached {spec.get('auth_required','privileged')} "
                      f"endpoint {method} {spec.get('name', url)}",
                severity=Severity.CRITICAL, module="Authorization & BOLA",
                description=f"Identity '{who}' received 200 on an endpoint requiring "
                            f"'{spec.get('auth_required','?')}'. Low-privilege roles must be denied (403).",
                location=url, cwe="CWE-285", owasp="API5:2023", source="api",
                confidence="High", test_id=spec.get("test_id"),
                remediation="Enforce role/function-level authorization server-side on this endpoint.",
            )
        return None

    def _bola(self, ctx, requests, method, url, spec, creds):
        attacker = spec.get("attacker_identity")
        if not attacker or attacker not in creds:
            return None
        if "{" in url:
            return None  # unfilled path-param template; skip until a victim id is provided
        r = self._request(ctx, requests, method, url, creds[attacker].get("headers", {}))
        if r is not None and r.status_code == 200:
            return Finding(
                title=f"Possible BOLA: '{attacker}' accessed another tenant's object at {spec.get('name', url)}",
                severity=Severity.CRITICAL, module="Authorization & BOLA",
                description=f"Identity '{attacker}' received 200 for an object it should not own. "
                            "Confirm the object belongs to a different user/dealer/tenant.",
                location=url, cwe="CWE-639", owasp="API1:2023", source="api",
                confidence="Medium", test_id=spec.get("test_id"),
                remediation="Enforce object-level ownership checks on every request, server-side.",
            )
        return None

    def _request(self, ctx, requests, method, url, headers):
        ctx.scope.assert_in_scope(url)
        if ctx.throttle:
            ctx.throttle.gate()
        try:
            return requests.request(method, url, headers=headers, timeout=15, allow_redirects=False)
        except requests.RequestException:
            return None
