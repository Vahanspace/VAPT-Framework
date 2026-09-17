import textwrap

from vaptframework.core.config import load_run_config, build_scanners
from vaptframework.core.preflight import preflight


def _cfg(tmp_path, body):
    p = tmp_path / "run.yaml"
    p.write_text(textwrap.dedent(body))
    return str(p)


ACTIVE_READY = """
scope:
  name: s
  environment: staging
  allowed_hosts: [staging.example]
authorization:
  authorized_by: Owner
  allow_active_testing: true
  valid_from: "2000-01-01"
  valid_until: "2999-01-01"
targets: ["https://staging.example"]
credentials:
  user: { headers: { Authorization: "Bearer U" } }
  userB: { headers: { Authorization: "Bearer B" } }
options:
  api_tests:
    - { name: t, url: "https://staging.example/api/v1/admin", check: bfla, forbidden_identity: user }
suites: [api]
"""


def test_go_when_ready(tmp_path):
    rc = load_run_config(_cfg(tmp_path, ACTIVE_READY))
    rep = preflight(rc, build_scanners(rc.suites))
    assert rep.go is True
    assert rep.blockers == []


def test_nogo_without_authorization(tmp_path):
    body = ACTIVE_READY.replace("allow_active_testing: true", "allow_active_testing: false")
    rc = load_run_config(_cfg(tmp_path, body))
    rep = preflight(rc, build_scanners(rc.suites))
    assert rep.go is False
    assert any("Active testing authorized" in c.message for c in rep.blockers)


def test_nogo_without_targets(tmp_path):
    body = ACTIVE_READY.replace('targets: ["https://staging.example"]', "targets: []")
    rc = load_run_config(_cfg(tmp_path, body))
    rep = preflight(rc, build_scanners(rc.suites))
    assert rep.go is False


def test_out_of_scope_target_blocks(tmp_path):
    body = ACTIVE_READY.replace("allowed_hosts: [staging.example]", "allowed_hosts: [other.example]")
    rc = load_run_config(_cfg(tmp_path, body))
    rep = preflight(rc, build_scanners(rc.suites))
    assert rep.go is False
    assert any("Target in scope" in c.message for c in rep.blockers)


def test_missing_credentials_is_warn_not_blocker(tmp_path):
    body = ACTIVE_READY.replace(
        '  userB: { headers: { Authorization: "Bearer B" } }\n', "")
    # reference an identity with no creds
    body = body.replace("forbidden_identity: user", "forbidden_identity: dealer")
    rc = load_run_config(_cfg(tmp_path, body))
    rep = preflight(rc, build_scanners(rc.suites))
    assert rep.go is True  # missing creds is a warning, not a blocker
    assert any("MISSING" in c.message for c in rep.checks)


def test_static_only_needs_source_roots(tmp_path):
    body = textwrap.dedent("""
        scope: { name: s, environment: staging }
        authorization: { authorized_by: "" }
        source_roots: []
        suites: [sast]
    """)
    rc = load_run_config(_cfg(tmp_path, body))
    rep = preflight(rc, build_scanners(rc.suites))
    assert rep.go is False
    assert any("source root" in c.message for c in rep.blockers)
