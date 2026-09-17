import pytest

from vaptframework.core.scope import Scope, ScopeGuard, ScopeViolation


def guard(**over):
    base = dict(
        name="t",
        environment="staging",
        allowed_hosts=["staging.vahanspace.example", "*.staging.vahanspace.example"],
        allowed_ports=[443, 8443],
        excluded_hosts=["admin.staging.vahanspace.example"],
        excluded_paths=["/internal/", "/danger"],
        allow_production=False,
    )
    base.update(over)
    return ScopeGuard(Scope.from_dict(base))


def test_allowed_host_passes():
    guard().assert_in_scope("https://staging.vahanspace.example/api/health")


def test_wildcard_subdomain_allowed():
    assert guard().is_in_scope("https://api.staging.vahanspace.example:8443/v1")


def test_unlisted_host_denied():
    with pytest.raises(ScopeViolation):
        guard().assert_in_scope("https://evil.example.com/")


def test_excluded_host_wins_over_allowlist():
    with pytest.raises(ScopeViolation):
        guard().assert_in_scope("https://admin.staging.vahanspace.example/")


def test_port_not_allowed():
    with pytest.raises(ScopeViolation):
        guard().assert_in_scope("https://staging.vahanspace.example:9999/")


def test_excluded_path_denied():
    with pytest.raises(ScopeViolation):
        guard().assert_in_scope("https://staging.vahanspace.example/internal/secrets")


def test_production_environment_refused():
    g = guard(environment="production", allowed_hosts=["app.vahanspace.example"])
    with pytest.raises(ScopeViolation):
        g.assert_in_scope("https://app.vahanspace.example/")


def test_production_like_hostname_refused_even_in_staging_scope():
    g = guard(allowed_hosts=["www.vahanspace.example"])
    with pytest.raises(ScopeViolation):
        g.assert_in_scope("https://www.vahanspace.example/")


def test_production_allowed_only_with_explicit_flag():
    g = guard(environment="production", allowed_hosts=["app.vahanspace.example"], allow_production=True)
    g.assert_in_scope("https://app.vahanspace.example/")  # no raise


def test_wildcard_does_not_match_bare_apex():
    g = guard(allowed_hosts=["*.staging.vahanspace.example"])
    # apex "staging.vahanspace.example" must not be matched by the wildcard alone
    with pytest.raises(ScopeViolation):
        g.assert_in_scope("https://staging.vahanspace.example/")
