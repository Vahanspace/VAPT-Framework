import json

import pytest

from vaptframework.core.findings import Finding, FindingsRegister
from vaptframework.core.severity import Severity


def make(title="SQL injection in login", module="Authentication", location="POST /api/login", **kw):
    return Finding(title=title, severity=Severity.CRITICAL, module=module, location=location, **kw)


def test_finding_requires_title_and_module():
    with pytest.raises(ValueError):
        Finding(title="", severity=Severity.HIGH, module="X")
    with pytest.raises(ValueError):
        Finding(title="x", severity=Severity.HIGH, module="")


def test_severity_string_coerced():
    f = Finding(title="t", severity="high", module="m")
    assert f.severity is Severity.HIGH


def test_finding_id_is_stable_and_derived():
    a = make()
    b = make()
    assert a.finding_id == b.finding_id  # same content -> same id
    assert len(a.finding_id) == 12


def test_register_dedupes_by_fingerprint():
    reg = FindingsRegister()
    assert reg.add(make()) is True
    assert reg.add(make()) is False  # duplicate
    assert len(reg) == 1


def test_register_sorted_by_severity_desc():
    reg = FindingsRegister()
    reg.add(Finding(title="low one", severity=Severity.LOW, module="m", location="a"))
    reg.add(Finding(title="crit one", severity=Severity.CRITICAL, module="m", location="b"))
    reg.add(Finding(title="med one", severity=Severity.MEDIUM, module="m", location="c"))
    order = [f.severity for f in reg]
    assert order == [Severity.CRITICAL, Severity.MEDIUM, Severity.LOW]


def test_counts_by_severity():
    reg = FindingsRegister()
    reg.add(Finding(title="a", severity=Severity.CRITICAL, module="m", location="1"))
    reg.add(Finding(title="b", severity=Severity.CRITICAL, module="m", location="2"))
    reg.add(Finding(title="c", severity=Severity.LOW, module="m", location="3"))
    counts = reg.counts_by_severity()
    assert counts["Critical"] == 2
    assert counts["Low"] == 1
    assert counts["High"] == 0


def test_to_json_roundtrip_shape():
    reg = FindingsRegister()
    reg.add(make())
    data = json.loads(reg.to_json())
    assert data[0]["severity"] == "Critical"
    assert data[0]["module"] == "Authentication"
