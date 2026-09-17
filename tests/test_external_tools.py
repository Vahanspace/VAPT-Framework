from vaptframework.scanners.external import (
    parse_nmap_xml, parse_nikto_json, parse_sqlmap_output, parse_zap_json,
    NmapScanner, NiktoScanner, SqlmapScanner, ZapScanner, _missing_note,
)
from vaptframework.scanners.base import ScanContext, Category
from vaptframework.core.severity import Severity


NMAP_XML = """<?xml version="1.0"?><nmaprun>
<host><address addr="10.0.0.5" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH"/></port>
<port protocol="tcp" portid="23"><state state="open"/><service name="telnet"/></port>
<port protocol="tcp" portid="80"><state state="closed"/><service name="http"/></port>
</ports></host></nmaprun>"""


def test_parse_nmap_open_ports_and_risky():
    f = parse_nmap_xml(NMAP_XML)
    titles = " ".join(x.title for x in f)
    assert "22/tcp" in titles and "ssh" in titles
    assert "telnet" in titles
    telnet = next(x for x in f if "telnet" in x.title)
    assert telnet.severity is Severity.MEDIUM
    assert all("80/tcp" not in x.title for x in f)  # closed port excluded


def test_parse_nmap_bad_xml():
    assert parse_nmap_xml("not xml") == []


def test_parse_nikto_json():
    data = {"vulnerabilities": [{"msg": "Server leaks inodes via ETags", "url": "https://t/"}]}
    f = parse_nikto_json(data)
    assert len(f) == 1 and f[0].source == "nikto"


def test_parse_sqlmap_positive():
    out = "sqlmap identified the following injection point\nParameter: id (GET) is vulnerable"
    f = parse_sqlmap_output(out, location="https://t/?id=1")
    assert any(x.severity is Severity.CRITICAL and x.cwe == "CWE-89" for x in f)


def test_parse_sqlmap_negative():
    assert parse_sqlmap_output("all tested parameters do not appear to be injectable") == []


def test_parse_zap_json_risk_mapping():
    data = {"site": [{"@name": "https://t", "alerts": [
        {"alert": "XSS", "riskcode": "3", "instances": [{"uri": "https://t/x"}], "cweid": "79"},
        {"alert": "Info", "riskcode": "0", "instances": []},
    ]}]}
    f = parse_zap_json(data)
    xss = next(x for x in f if "XSS" in x.title)
    assert xss.severity is Severity.HIGH and xss.cwe == "CWE-79"


def test_sqlmap_is_destructive_and_active():
    s = SqlmapScanner()
    assert s.destructive is True
    assert s.category is Category.ACTIVE


def test_missing_tool_returns_info_note_not_crash():
    # Scanners whose tool is absent must return a single informational note.
    ctx = ScanContext(scope=None, authorization=None, targets=["https://t"], options={})
    for cls in (NmapScanner, NiktoScanner, ZapScanner):
        s = cls()
        if not s.tool_available():
            notes = s.scan(ctx)
            assert len(notes) == 1 and notes[0].severity is Severity.INFORMATIONAL


def test_missing_note_shape():
    n = _missing_note("Nmap", "Infrastructure")
    assert n.severity is Severity.INFORMATIONAL and "not installed" in n.title
