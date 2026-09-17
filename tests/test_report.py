from vaptframework.reporting.report import build_markdown, build_html, ReportMeta
from vaptframework.core.findings import Finding, FindingsRegister
from vaptframework.core.severity import Severity


def reg():
    r = FindingsRegister()
    r.add(Finding(title="SQLi in login", severity=Severity.CRITICAL, module="Auth",
                  location="db.py:10", cwe="CWE-89", remediation="Parameterize queries"))
    r.add(Finding(title="Missing HSTS", severity=Severity.LOW, module="Config", location="https://t/"))
    return r


def summary(skipped=None):
    return {"scanners_executed": ["sast", "secrets"], "scanners_skipped": skipped or {"dast": "no target"},
            "total_findings": 2, "by_severity": {}}


def test_markdown_has_sections_and_counts():
    md = build_markdown(ReportMeta(application="VahanSpace"), summary(), reg())
    assert "# VAPT Assessment Report — VahanSpace" in md
    assert "Executive Summary" in md
    assert "| Critical | 1 |" in md
    assert "SQLi in login" in md
    assert "Parameterize queries" in md


def test_markdown_lists_skipped_as_not_tested():
    md = build_markdown(ReportMeta(), summary(skipped={"dast": "active testing not authorized"}), reg())
    assert "Skipped suites (NOT tested)" in md
    assert "active testing not authorized" in md


def test_markdown_zero_findings_message():
    md = build_markdown(ReportMeta(), summary(), FindingsRegister())
    assert "No findings recorded" in md


def test_html_renders_findings():
    h = build_html(ReportMeta(application="VahanSpace"), summary(), reg())
    assert "<title>VAPT Report — VahanSpace</title>" in h
    assert "SQLi in login" in h
    assert "Missing HSTS" in h


def test_html_escapes_content():
    r = FindingsRegister()
    r.add(Finding(title="<script>alert(1)</script>", severity=Severity.HIGH, module="X", location="a"))
    h = build_html(ReportMeta(), summary(), r)
    assert "<script>alert(1)</script>" not in h
    assert "&lt;script&gt;" in h
