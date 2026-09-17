"""Report generation.

Turns a RunReport (findings + what ran / what was skipped) plus engagement metadata into a
Markdown report and a self-contained HTML report. The report is explicit about coverage: it
always lists which scanner suites were skipped and why, so a reader never mistakes
"not tested" for "no issues".
"""
from __future__ import annotations

import html
from dataclasses import dataclass, field
from datetime import date

from ..core.findings import FindingsRegister
from ..core.severity import Severity

_SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFORMATIONAL]
_SEV_COLOR = {
    "Critical": "#b3122b", "High": "#d9480f", "Medium": "#e8a400",
    "Low": "#2f6feb", "Informational": "#6b7280",
}


@dataclass
class ReportMeta:
    application: str = "VahanSpace"
    engagement: str = ""
    environment: str = "static-analysis"
    tester: str = ""
    authorized_by: str = ""
    date: str = field(default_factory=lambda: date.today().isoformat())
    scope_note: str = ""
    testing_mode: str = "Static (SAST/SCA/Secrets/Config)"


def _exec_summary_counts(register: FindingsRegister) -> dict:
    return register.counts_by_severity()


def build_markdown(meta: ReportMeta, run_summary: dict, register: FindingsRegister,
                   coverage: list[dict] | None = None) -> str:
    counts = _exec_summary_counts(register)
    total = len(register)
    lines: list[str] = []
    a = lines.append
    a(f"# VAPT Assessment Report — {meta.application}")
    a("")
    a(f"- **Engagement:** {meta.engagement or 'N/A'}")
    a(f"- **Date:** {meta.date}")
    a(f"- **Environment:** {meta.environment}")
    a(f"- **Testing mode:** {meta.testing_mode}")
    a(f"- **Tester:** {meta.tester or 'N/A'}")
    a(f"- **Authorized by:** {meta.authorized_by or 'N/A'}")
    if meta.scope_note:
        a(f"- **Scope:** {meta.scope_note}")
    a("")
    a("> This report is produced by the guardrailed VAPT Framework. It states coverage "
      "explicitly: any suite listed as *skipped* was **not executed** and its controls are "
      "**unverified**, not confirmed safe.")
    a("")
    a("## 1. Executive Summary")
    a("")
    a(f"A total of **{total}** finding(s) were recorded in this run.")
    a("")
    a("| Severity | Count |")
    a("|---|---|")
    for sev in _SEV_ORDER:
        a(f"| {sev.label} | {counts.get(sev.label, 0)} |")
    a("")
    a("## 2. Coverage & What Ran")
    a("")
    a("**Executed scanner suites:** " + (", ".join(run_summary.get("scanners_executed", [])) or "none"))
    a("")
    skipped = run_summary.get("scanners_skipped", {})
    if skipped:
        a("**Skipped suites (NOT tested):**")
        a("")
        for name, reason in skipped.items():
            a(f"- `{name}` — {reason}")
        a("")
    if coverage:
        a("### Test-plan coverage by module")
        a("")
        a("| Module | Planned | Automatable |")
        a("|---|---|---|")
        for row in coverage:
            a(f"| {row['module']} | {row['planned']} | {row['automated']} |")
        a("")
    a("## 3. Findings")
    a("")
    if total == 0:
        a("_No findings recorded by the executed suites. Note the coverage section above — "
          "unexecuted suites are unverified._")
    else:
        n = 0
        for f in register:
            n += 1
            a(f"### {n}. [{f.severity.label}] {f.title}")
            a("")
            a(f"- **ID:** {f.finding_id}  |  **Module:** {f.module}  |  **Source:** {f.source}")
            meta_bits = [b for b in [f.cwe, f.owasp, (f'CVSS {f.cvss}' if f.cvss else '')] if b]
            if meta_bits:
                a(f"- **Refs:** {' · '.join(meta_bits)}  |  **Confidence:** {f.confidence}")
            if f.test_id:
                a(f"- **Test case:** {f.test_id}")
            a(f"- **Location:** `{f.location}`")
            a("")
            if f.description:
                a(f"{f.description}")
                a("")
            if f.remediation:
                a(f"**Remediation:** {f.remediation}")
                a("")
    a("## 4. Methodology")
    a("")
    a("Testing follows the engagement methodology (OWASP Top 10:2025, OWASP API Security Top 10, "
      "OWASP ASVS, OWASP MASVS for mobile) across reconnaissance, configuration, authentication, "
      "session, authorization, input validation, error handling, business logic, and client-side "
      "phases. See `docs/METHODOLOGY.md`.")
    a("")
    a("## 5. Guardrails Applied")
    a("")
    a("- Default-deny scope allowlist; production-like hosts refused without explicit approval.")
    a("- Active testing gated behind a signed, time-bound authorization record.")
    a("- Destructive tests disabled unless separately authorized.")
    a("- Rate-limited requests and a file-based kill switch. See `docs/GUARDRAILS.md`.")
    a("")
    return "\n".join(lines)


def build_html(meta: ReportMeta, run_summary: dict, register: FindingsRegister,
               coverage: list[dict] | None = None) -> str:
    counts = _exec_summary_counts(register)
    total = len(register)

    def esc(s):
        return html.escape(str(s))

    chips = "".join(
        f'<span class="chip" style="background:{_SEV_COLOR[s.label]}">{s.label}: {counts.get(s.label,0)}</span>'
        for s in _SEV_ORDER
    )
    rows = ""
    for i, f in enumerate(register, 1):
        rows += (
            f'<tr><td>{i}</td><td><span class="sev" style="background:{_SEV_COLOR[f.severity.label]}">'
            f'{f.severity.label}</span></td><td>{esc(f.title)}</td><td>{esc(f.module)}</td>'
            f'<td><code>{esc(f.location)}</code></td><td>{esc(f.cwe)} {esc(f.owasp)}</td>'
            f'<td>{esc(f.remediation)}</td></tr>'
        )
    skipped = run_summary.get("scanners_skipped", {})
    skipped_html = "".join(f"<li><code>{esc(k)}</code> — {esc(v)}</li>" for k, v in skipped.items()) or "<li>none</li>"
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>VAPT Report — {esc(meta.application)}</title>
<style>
 body{{font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;margin:0;color:#111;background:#fafafa}}
 header{{background:#0b1f3a;color:#fff;padding:28px 32px}}
 header h1{{margin:0 0 6px}} .muted{{color:#c9d4e5}}
 main{{max-width:1100px;margin:0 auto;padding:24px 32px}}
 .chip,.sev{{color:#fff;border-radius:12px;padding:3px 10px;font-size:12px;font-weight:600;display:inline-block;margin-right:6px}}
 table{{border-collapse:collapse;width:100%;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.08)}}
 th,td{{border-bottom:1px solid #eee;padding:9px 10px;text-align:left;font-size:13px;vertical-align:top}}
 th{{background:#f0f3f8}} code{{background:#f3f4f6;padding:1px 4px;border-radius:4px;font-size:12px}}
 .card{{background:#fff;border-radius:8px;padding:16px 20px;margin:16px 0;box-shadow:0 1px 3px rgba(0,0,0,.08)}}
</style></head><body>
<header><h1>VAPT Assessment Report — {esc(meta.application)}</h1>
<div class="muted">{esc(meta.engagement)} · {esc(meta.date)} · Mode: {esc(meta.testing_mode)} · Env: {esc(meta.environment)}</div></header>
<main>
 <div class="card"><h2>Executive Summary</h2><p><b>{total}</b> finding(s) recorded.</p><p>{chips}</p></div>
 <div class="card"><h2>Coverage</h2>
   <p><b>Executed:</b> {esc(', '.join(run_summary.get('scanners_executed', [])) or 'none')}</p>
   <p><b>Skipped (NOT tested):</b></p><ul>{skipped_html}</ul></div>
 <div class="card"><h2>Findings</h2>
 <table><thead><tr><th>#</th><th>Severity</th><th>Title</th><th>Module</th><th>Location</th><th>Refs</th><th>Remediation</th></tr></thead>
 <tbody>{rows or '<tr><td colspan=7>No findings from executed suites (see coverage).</td></tr>'}</tbody></table></div>
 <div class="card"><h2>Guardrails</h2><p>Default-deny scope, signed authorization for active tests, destructive tests off by default,
 rate limiting and a kill switch. See docs/GUARDRAILS.md.</p></div>
</main></body></html>"""
