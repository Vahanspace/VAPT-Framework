from vaptframework.core.severity import Severity, severity_from_cvss

import pytest


def test_ordering():
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.INFORMATIONAL
    assert max([Severity.LOW, Severity.CRITICAL, Severity.MEDIUM]) is Severity.CRITICAL


def test_from_string_aliases():
    assert Severity.from_string("critical") is Severity.CRITICAL
    assert Severity.from_string("  High ") is Severity.HIGH
    assert Severity.from_string("info") is Severity.INFORMATIONAL
    assert Severity.from_string("MED") is Severity.MEDIUM


def test_from_string_invalid():
    with pytest.raises(ValueError):
        Severity.from_string("catastrophic")


@pytest.mark.parametrize(
    "score,expected",
    [
        (0.0, Severity.INFORMATIONAL),
        (3.9, Severity.LOW),
        (4.0, Severity.MEDIUM),
        (6.9, Severity.MEDIUM),
        (7.0, Severity.HIGH),
        (8.9, Severity.HIGH),
        (9.0, Severity.CRITICAL),
        (10.0, Severity.CRITICAL),
    ],
)
def test_cvss_mapping(score, expected):
    assert severity_from_cvss(score) is expected


def test_cvss_out_of_range():
    with pytest.raises(ValueError):
        severity_from_cvss(11.0)
    with pytest.raises(ValueError):
        severity_from_cvss(-1.0)


def test_label():
    assert Severity.CRITICAL.label == "Critical"
