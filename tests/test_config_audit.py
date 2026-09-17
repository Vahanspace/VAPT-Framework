from vaptframework.scanners.config_audit import evaluate_headers
from vaptframework.core.severity import Severity


def test_flags_missing_hsts_and_csp():
    findings = evaluate_headers({"Content-Type": "text/html"}, "https://t/")
    titles = " ".join(f.title for f in findings)
    assert "strict-transport-security" in titles
    assert "content-security-policy" in titles


def test_all_headers_present_no_missing():
    headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
    }
    findings = evaluate_headers(headers, "https://t/")
    assert all("Missing security header" not in f.title for f in findings)


def test_verbose_server_header():
    findings = evaluate_headers({"Server": "nginx/1.19.0", **_full()}, "https://t/")
    assert any("discloses technology" in f.title for f in findings)


def test_cookie_flags():
    findings = evaluate_headers({"Set-Cookie": "sid=abc; Path=/", **_full()}, "https://t/")
    flags = " ".join(f.title for f in findings)
    assert "HttpOnly" in flags and "Secure" in flags and "SameSite" in flags


def test_secure_cookie_no_findings():
    findings = evaluate_headers(
        {"Set-Cookie": "sid=abc; HttpOnly; Secure; SameSite=Strict", **_full()}, "https://t/")
    assert all("cookie" not in f.title.lower() for f in findings)


def _full():
    return {
        "Strict-Transport-Security": "max-age=1",
        "Content-Security-Policy": "x",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
    }
