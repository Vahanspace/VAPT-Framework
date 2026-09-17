import os
import textwrap

from vaptframework.core.config import load_run_config, build_scanners, DEFAULT_SUITES


def test_load_run_config(tmp_path):
    cfg = tmp_path / "run.yaml"
    cfg.write_text(textwrap.dedent("""
        meta:
          application: VahanSpace
          engagement: VAPT-2026
        scope:
          name: vahanspace-staging
          environment: staging
          allowed_hosts: [staging.vahanspace.example]
          allowed_ports: [443]
        authorization:
          authorized_by: Owner
          allow_active_testing: false
        rate_limit:
          requests_per_second: 3
          burst: 5
        source_roots: ["%s"]
        suites: [secrets, sast]
    """ % str(tmp_path).replace("\\", "/")))
    rc = load_run_config(str(cfg))
    assert rc.context.scope.scope.environment == "staging"
    assert rc.context.authorization.authorized_by == "Owner"
    assert rc.suites == ["secrets", "sast"]
    assert rc.context.throttle.bucket.rate == 3
    assert os.path.isdir(rc.context.source_roots[0])


def test_build_scanners_default():
    scanners = build_scanners(DEFAULT_SUITES)
    names = {s.name for s in scanners}
    assert {"secrets", "sast", "sca", "config-audit", "dast", "api"} <= names


def test_build_scanners_ignores_unknown():
    scanners = build_scanners(["secrets", "bogus"])
    assert [s.name for s in scanners] == ["secrets"]


def test_api_tests_file_is_merged(tmp_path):
    import json
    (tmp_path / "tests.json").write_text(json.dumps(
        [{"name": "gen", "url": "https://staging.example/api/v1/admin", "check": "unauth"}]))
    cfg = tmp_path / "run.yaml"
    cfg.write_text(textwrap.dedent("""
        scope: { name: s, environment: staging, allowed_hosts: [staging.example] }
        authorization: { authorized_by: Owner, allow_active_testing: true }
        options:
          api_tests_file: tests.json
          api_tests:
            - { name: inline, url: "https://staging.example/api/v1/me", check: unauth }
        suites: [api]
    """))
    rc = load_run_config(str(cfg))
    names = {t["name"] for t in rc.context.options["api_tests"]}
    assert {"gen", "inline"} <= names
