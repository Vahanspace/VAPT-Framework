import sys
import types

import pytest

from vaptframework.scanners.api import ApiScanner
from vaptframework.scanners.base import ScanContext
from vaptframework.core.scope import Scope, ScopeGuard
from vaptframework.core.authorization import Authorization
from vaptframework.core.severity import Severity


class FakeResp:
    def __init__(self, status):
        self.status_code = status


def fake_requests(routing):
    """routing: dict keyed by (method, url, auth_header_or_None) -> status code."""
    mod = types.ModuleType("requests")

    class RequestException(Exception):
        pass

    def request(method, url, headers=None, timeout=None, allow_redirects=None):
        auth = (headers or {}).get("Authorization")
        return FakeResp(routing.get((method, url, auth), 404))

    mod.request = request
    mod.RequestException = RequestException
    return mod


def make_ctx(api_tests, creds=None):
    scope = ScopeGuard(Scope.from_dict({
        "name": "t", "environment": "staging", "allowed_hosts": ["staging.example"],
    }))
    authz = Authorization.from_dict({
        "authorized_by": "Owner", "allow_active_testing": True,
        "valid_from": "2000-01-01", "valid_until": "2999-01-01",
    })
    return ScanContext(scope=scope, authorization=authz, targets=["https://staging.example"],
                       options={"api_tests": api_tests}, credentials=creds or {})


def run(ctx, routing, monkeypatch):
    monkeypatch.setitem(sys.modules, "requests", fake_requests(routing))
    return ApiScanner().scan(ctx)


def test_unauth_flag_when_not_denied(monkeypatch):
    url = "https://staging.example/api/v1/admin/users"
    ctx = make_ctx([{"name": "x", "url": url, "method": "GET", "check": "unauth", "protected": True}])
    findings = run(ctx, {("GET", url, None): 200}, monkeypatch)
    assert any(f.owasp == "API2:2023" for f in findings)


def test_unauth_ok_when_denied(monkeypatch):
    url = "https://staging.example/api/v1/admin/users"
    ctx = make_ctx([{"name": "x", "url": url, "method": "GET", "check": "unauth"}])
    findings = run(ctx, {("GET", url, None): 401}, monkeypatch)
    assert findings == []


def test_bfla_user_reaches_admin(monkeypatch):
    url = "https://staging.example/api/v1/admin/users"
    ctx = make_ctx(
        [{"name": "x", "url": url, "method": "GET", "check": "bfla", "forbidden_identity": "user",
          "auth_required": "admin"}],
        creds={"user": {"headers": {"Authorization": "Bearer U"}}},
    )
    findings = run(ctx, {("GET", url, "Bearer U"): 200}, monkeypatch)
    assert any(f.severity is Severity.CRITICAL and f.owasp == "API5:2023" for f in findings)


def test_bfla_denied_is_clean(monkeypatch):
    url = "https://staging.example/api/v1/admin/users"
    ctx = make_ctx(
        [{"name": "x", "url": url, "method": "GET", "check": "bfla", "forbidden_identity": "user"}],
        creds={"user": {"headers": {"Authorization": "Bearer U"}}},
    )
    findings = run(ctx, {("GET", url, "Bearer U"): 403}, monkeypatch)
    assert findings == []


def test_bola_template_skipped_until_filled(monkeypatch):
    url = "https://staging.example/api/v1/vehicles/{vehicle_id}"
    ctx = make_ctx(
        [{"name": "x", "url": url, "method": "GET", "check": "bola", "attacker_identity": "userB"}],
        creds={"userB": {"headers": {"Authorization": "Bearer B"}}},
    )
    findings = run(ctx, {}, monkeypatch)
    assert findings == []  # unfilled {vehicle_id} template must be skipped


def test_bola_confirmed_when_200(monkeypatch):
    url = "https://staging.example/api/v1/vehicles/42"
    ctx = make_ctx(
        [{"name": "x", "url": url, "method": "GET", "check": "bola", "attacker_identity": "userB"}],
        creds={"userB": {"headers": {"Authorization": "Bearer B"}}},
    )
    findings = run(ctx, {("GET", url, "Bearer B"): 200}, monkeypatch)
    assert any(f.owasp == "API1:2023" for f in findings)
