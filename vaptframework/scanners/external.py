"""Optional wrappers for the external tools named in the engagement document.

Each wrapper:
  * declares the binary it needs (``required_tool``) and returns a single informational
    note (no crash) when that binary is absent, so a test-plan row stays visibly "manual"
    instead of silently passing;
  * is ACTIVE, so the engine only runs it with a valid authorization + in-scope target;
  * is scope-checked and rate-limited per target;
  * keeps its output-parsing logic in a pure function (``parse_*``) that is unit-tested
    without needing the tool installed.

Non-destructive by default. SQLMap is marked destructive (it sends injection payloads) so it
only runs under explicit destructive authorization, and even then in detection-only mode.

Burp Suite Pro/Enterprise and Nessus are intentionally not wrapped here — they are licensed
and GUI/REST-driven; the test plan keeps them as analyst-driven rows.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from typing import Optional

from ..core.findings import Finding
from ..core.severity import Severity
from .base import Category, ScanContext, Scanner


def _missing_note(tool: str, module: str) -> Finding:
    return Finding(
        title=f"{tool} not installed; check left to manual/GUI testing",
        severity=Severity.INFORMATIONAL, module=module,
        description=f"The optional tool '{tool}' is not on PATH, so this automated check did not run.",
        location="(tool missing)", source=tool.lower(), confidence="High",
        remediation=f"Install {tool} and re-run to automate this coverage.",
    )


# --------------------------------------------------------------------------- Nmap
_RISKY_SERVICES = {"telnet": Severity.MEDIUM, "ftp": Severity.MEDIUM, "rlogin": Severity.MEDIUM,
                   "vnc": Severity.MEDIUM, "microsoft-ds": Severity.LOW, "mysql": Severity.LOW,
                   "postgresql": Severity.LOW, "redis": Severity.MEDIUM, "mongodb": Severity.MEDIUM}


def parse_nmap_xml(xml_text: str, location: str = "") -> list[Finding]:
    findings: list[Finding] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return findings
    for host in root.findall("host"):
        addr_el = host.find("address")
        addr = addr_el.get("addr") if addr_el is not None else location
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            portid = port.get("portid")
            proto = port.get("protocol", "tcp")
            svc_el = port.find("service")
            svc = svc_el.get("name") if svc_el is not None else "unknown"
            product = (svc_el.get("product") if svc_el is not None else "") or ""
            sev = _RISKY_SERVICES.get(svc, Severity.INFORMATIONAL)
            findings.append(Finding(
                title=f"Open port {portid}/{proto} ({svc}{' ' + product if product else ''}) on {addr}",
                severity=sev, module="Infrastructure",
                description=f"nmap reports {portid}/{proto} open running {svc} {product}.".strip(),
                location=f"{addr}:{portid}", cwe="CWE-668" if sev != Severity.INFORMATIONAL else "",
                owasp="A05:2021", source="nmap", confidence="High",
                remediation="Confirm the service must be internet-exposed; restrict/firewall if not; patch to current.",
            ))
    return findings


class NmapScanner(Scanner):
    name = "nmap"
    category = Category.ACTIVE
    destructive = False
    required_tool = "nmap"

    def scan(self, ctx: ScanContext) -> list[Finding]:
        if not self.tool_available():
            return [_missing_note("Nmap", "Infrastructure")]
        findings: list[Finding] = []
        for target in ctx.targets:
            ctx.scope.assert_in_scope(target)
            host = _host_of(target)
            if ctx.throttle:
                ctx.throttle.gate()
            try:
                proc = subprocess.run(
                    ["nmap", "-sV", "-Pn", "--top-ports", "100", "-oX", "-", host],
                    capture_output=True, text=True, timeout=900)
                findings.extend(parse_nmap_xml(proc.stdout, location=host))
            except (FileNotFoundError, subprocess.TimeoutExpired):
                findings.append(_missing_note("Nmap", "Infrastructure"))
        return findings


# --------------------------------------------------------------------------- Nikto
def parse_nikto_json(data, location: str = "") -> list[Finding]:
    import json as _json
    if isinstance(data, str):
        try:
            data = _json.loads(data)
        except _json.JSONDecodeError:
            return []
    vulns = []
    if isinstance(data, dict):
        vulns = data.get("vulnerabilities", [])
    findings: list[Finding] = []
    for v in vulns:
        msg = v.get("msg") or v.get("message") or "Nikto finding"
        findings.append(Finding(
            title=f"Nikto: {msg[:120]}",
            severity=Severity.LOW, module="Web Security / Config",
            description=msg, location=v.get("url") or location, cwe="CWE-16", owasp="A05:2021",
            source="nikto", confidence="Medium",
            remediation="Review the web server configuration/finding and remediate.",
        ))
    return findings


class NiktoScanner(Scanner):
    name = "nikto"
    category = Category.ACTIVE
    destructive = False
    required_tool = "nikto"

    def scan(self, ctx: ScanContext) -> list[Finding]:
        if not self.tool_available():
            return [_missing_note("Nikto", "Web Security / Config")]
        findings: list[Finding] = []
        for target in ctx.targets:
            ctx.scope.assert_in_scope(target)
            if ctx.throttle:
                ctx.throttle.gate()
            out = os.path.join(tempfile.gettempdir(), "vapt_nikto.json")
            try:
                subprocess.run(["nikto", "-h", target, "-Format", "json", "-output", out],
                               capture_output=True, text=True, timeout=1200)
                if os.path.exists(out):
                    with open(out, "r", encoding="utf-8", errors="ignore") as fh:
                        findings.extend(parse_nikto_json(fh.read(), location=target))
                    os.remove(out)
            except (FileNotFoundError, subprocess.TimeoutExpired):
                findings.append(_missing_note("Nikto", "Web Security / Config"))
        return findings


# --------------------------------------------------------------------------- SQLMap
def parse_sqlmap_output(stdout: str, location: str = "") -> list[Finding]:
    findings: list[Finding] = []
    low = (stdout or "").lower()
    positive = ("is vulnerable" in low
                or "sqlmap identified the following injection point" in low
                or "the back-end dbms is" in low)
    negative = "do not appear to be injectable" in low or "not injectable" in low
    if positive and not negative:
        findings.append(Finding(
            title="SQL injection confirmed by SQLMap",
            severity=Severity.CRITICAL, module="Data Input Validation",
            description="SQLMap reported an injectable parameter (detection-only run).",
            location=location, cwe="CWE-89", owasp="A03:2021", source="sqlmap", confidence="High",
            remediation="Use parameterized queries / ORM bindings; never build SQL from input.",
        ))
    return findings


class SqlmapScanner(Scanner):
    name = "sqlmap"
    category = Category.ACTIVE
    destructive = True          # sends injection payloads -> needs explicit destructive authorization
    required_tool = "sqlmap"

    def scan(self, ctx: ScanContext) -> list[Finding]:
        if not self.tool_available():
            return [_missing_note("SQLMap", "Data Input Validation")]
        findings: list[Finding] = []
        # Only URLs explicitly listed for injection testing (avoid blanket fuzzing).
        for url in ctx.options.get("sqlmap_urls", []):
            ctx.scope.assert_in_scope(url)
            if ctx.throttle:
                ctx.throttle.gate()
            try:
                proc = subprocess.run(
                    ["sqlmap", "-u", url, "--batch", "--level", "1", "--risk", "1",
                     "--technique", "BEU", "--smart", "--flush-session"],
                    capture_output=True, text=True, timeout=1800)
                findings.extend(parse_sqlmap_output(proc.stdout, location=url))
            except (FileNotFoundError, subprocess.TimeoutExpired):
                findings.append(_missing_note("SQLMap", "Data Input Validation"))
        return findings


# --------------------------------------------------------------------------- OWASP ZAP
_ZAP_RISK = {0: Severity.INFORMATIONAL, 1: Severity.LOW, 2: Severity.MEDIUM, 3: Severity.HIGH}


def parse_zap_json(data, location: str = "") -> list[Finding]:
    import json as _json
    if isinstance(data, str):
        try:
            data = _json.loads(data)
        except _json.JSONDecodeError:
            return []
    findings: list[Finding] = []
    for site in (data.get("site") or []):
        for alert in site.get("alerts", []):
            try:
                risk = int(alert.get("riskcode", 0))
            except (TypeError, ValueError):
                risk = 0
            sev = _ZAP_RISK.get(risk, Severity.INFORMATIONAL)
            url = ""
            insts = alert.get("instances") or []
            if insts:
                url = insts[0].get("uri", "")
            findings.append(Finding(
                title=f"ZAP: {alert.get('alert') or alert.get('name') or 'alert'}",
                severity=sev, module="Web Security / Config",
                description=(alert.get("desc") or "")[:500],
                location=url or site.get("@name", location),
                cwe=f"CWE-{alert.get('cweid')}" if alert.get("cweid") not in (None, "", "-1") else "",
                owasp="A05:2021", source="zap", confidence="Medium",
                remediation=(alert.get("solution") or "Review the ZAP alert and remediate.")[:400],
            ))
    return findings


class ZapScanner(Scanner):
    name = "zap"
    category = Category.ACTIVE
    destructive = False
    required_tool = "zap-baseline.py"

    def scan(self, ctx: ScanContext) -> list[Finding]:
        if not self.tool_available():
            return [_missing_note("OWASP ZAP (zap-baseline.py)", "Web Security / Config")]
        findings: list[Finding] = []
        for target in ctx.targets:
            ctx.scope.assert_in_scope(target)
            if ctx.throttle:
                ctx.throttle.gate()
            out = os.path.join(tempfile.gettempdir(), "vapt_zap.json")
            try:
                subprocess.run(["zap-baseline.py", "-t", target, "-J", out],
                               capture_output=True, text=True, timeout=1800)
                if os.path.exists(out):
                    with open(out, "r", encoding="utf-8", errors="ignore") as fh:
                        findings.extend(parse_zap_json(fh.read(), location=target))
                    os.remove(out)
            except (FileNotFoundError, subprocess.TimeoutExpired):
                findings.append(_missing_note("OWASP ZAP (zap-baseline.py)", "Web Security / Config"))
        return findings


def _host_of(url: str) -> str:
    from urllib.parse import urlsplit
    parts = urlsplit(url if "//" in url else "//" + url)
    return parts.hostname or url
