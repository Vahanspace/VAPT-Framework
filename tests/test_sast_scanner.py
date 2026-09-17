from vaptframework.scanners.sast import scan_text_native
from vaptframework.core.severity import Severity


def test_sql_fstring_critical():
    code = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'
    f = scan_text_native(code, "db.py")
    assert any(x.severity is Severity.CRITICAL and x.cwe == "CWE-89" for x in f)


def test_requests_verify_false():
    f = scan_text_native("requests.get(url, verify=False)", "client.py")
    assert any(x.cwe == "CWE-295" for x in f)


def test_shell_true():
    f = scan_text_native("subprocess.run(cmd, shell=True)", "runner.py")
    assert any(x.cwe == "CWE-78" for x in f)


def test_react_dangerous_html():
    f = scan_text_native("<div dangerouslySetInnerHTML={{__html: data}} />", "Comp.jsx")
    assert any(x.cwe == "CWE-79" for x in f)


def test_tls_off_node():
    f = scan_text_native("const agent = new https.Agent({ rejectUnauthorized: false })", "api.ts")
    assert any(x.cwe == "CWE-295" for x in f)


def test_comment_lines_ignored():
    f = scan_text_native("# subprocess.run(cmd, shell=True)", "runner.py")
    assert f == []


def test_ext_scoping():
    # python-only rule should not fire on a .js file
    f = scan_text_native("verify=False", "x.js")
    assert all(r.cwe != "CWE-295" or "requests" not in r.description for r in f)
