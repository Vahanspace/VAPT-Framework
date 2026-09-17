"""Integration tests: the engine must enforce guardrails regardless of scanner behavior."""
import os

import pytest

from vaptframework.core.engine import Engine
from vaptframework.core.scope import Scope, ScopeGuard
from vaptframework.core.authorization import Authorization
from vaptframework.core.ratelimit import TokenBucket, KillSwitch, Throttle
from vaptframework.core.findings import Finding
from vaptframework.core.severity import Severity
from vaptframework.scanners.base import Scanner, Category, ScanContext


class SpyActive(Scanner):
    name = "spy-active"
    category = Category.ACTIVE
    destructive = False

    def __init__(self):
        self.ran = False

    def scan(self, ctx):
        self.ran = True
        return [Finding(title="active ran", severity=Severity.LOW, module="x", location="1")]


class SpyDestructive(SpyActive):
    name = "spy-destructive"
    destructive = True


class SpyPassive(Scanner):
    name = "spy-passive"
    category = Category.PASSIVE

    def __init__(self):
        self.ran = False

    def scan(self, ctx):
        self.ran = True
        return [Finding(title="passive ran", severity=Severity.LOW, module="x", location="p")]


def make_ctx(**over):
    scope = ScopeGuard(Scope.from_dict({
        "name": "t", "environment": "staging",
        "allowed_hosts": ["staging.example"], "allowed_ports": [443],
        "source_roots": [os.getcwd()],
    }))
    base = dict(
        scope=scope,
        authorization=Authorization.from_dict({"authorized_by": "", "allow_active_testing": False}),
        targets=[],
        source_roots=[os.getcwd()],
    )
    base.update(over)
    return ScanContext(**base)


def authz(**over):
    base = dict(authorized_by="Owner", allow_active_testing=True, allow_destructive=False,
                valid_from="2000-01-01", valid_until="2999-01-01")
    base.update(over)
    return Authorization.from_dict(base)


def test_passive_runs_without_authorization():
    spy = SpyPassive()
    report = Engine(make_ctx()).run([spy])
    assert spy.ran is True
    assert "spy-passive" in report.executed


def test_active_blocked_without_authorization():
    spy = SpyActive()
    ctx = make_ctx(targets=["https://staging.example"], authorization=authz(allow_active_testing=False))
    report = Engine(ctx).run([spy])
    assert spy.ran is False
    assert "spy-active" in report.skipped
    assert "not authorized" in report.skipped["spy-active"]


def test_active_blocked_without_target():
    spy = SpyActive()
    ctx = make_ctx(targets=[], authorization=authz())
    report = Engine(ctx).run([spy])
    assert spy.ran is False
    assert "no in-scope targets" in report.skipped["spy-active"]


def test_active_runs_when_authorized_and_targeted():
    spy = SpyActive()
    ctx = make_ctx(targets=["https://staging.example"], authorization=authz())
    report = Engine(ctx).run([spy])
    assert spy.ran is True
    assert len(report.register) == 1


def test_destructive_blocked_even_when_active_allowed():
    spy = SpyDestructive()
    ctx = make_ctx(targets=["https://staging.example"], authorization=authz(allow_destructive=False))
    report = Engine(ctx).run([spy])
    assert spy.ran is False
    assert "destructive testing not authorized" in report.skipped["spy-destructive"]


def test_kill_switch_blocks_active(tmp_path):
    stop = os.path.join(tmp_path, "STOP")
    ks = KillSwitch(stop_file=stop)
    ks.engage("stop")
    thr = Throttle(TokenBucket(10, 10), ks)
    spy = SpyActive()
    ctx = make_ctx(targets=["https://staging.example"], authorization=authz(), throttle=thr)
    report = Engine(ctx).run([spy])
    assert spy.ran is False
    assert "kill switch" in report.skipped["spy-active"]


def test_scanner_crash_does_not_abort_run():
    class Boom(Scanner):
        name = "boom"
        category = Category.PASSIVE

        def scan(self, ctx):
            raise RuntimeError("kaboom")

    spy = SpyPassive()
    report = Engine(make_ctx()).run([Boom(), spy])
    assert spy.ran is True  # subsequent scanner still ran
    boom_result = next(r for r in report.results if r.scanner == "boom")
    assert any("kaboom" in n for n in boom_result.notes)
