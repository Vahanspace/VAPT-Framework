# VAPT Framework

A **guardrailed, test-driven** automation framework for Vulnerability Assessment and
Penetration Testing (VAPT) of web apps, REST APIs, and mobile backends. Built to be reusable
for **any application**, and pre-wired for the **VahanSpace** engagement.

It automates the ~30% of VAPT that tools do well (SAST, dependency/SCA, secret scanning,
security-config and non-destructive DAST/API checks) and structures the ~70% manual work via
a spreadsheet test plan — while making unsafe actions **impossible by default**.

> ⚠️ **Authorized testing only.** Only run this against systems you own or are explicitly
> authorized to test. See [`docs/RULES_OF_ENGAGEMENT.md`](docs/RULES_OF_ENGAGEMENT.md).

## Why this design
- **Safe-by-default:** default-deny scope allowlist, signed authorization required for any
  network probe, destructive tests off unless separately authorized, rate limiting, and a
  kill switch. Full list: [`docs/GUARDRAILS.md`](docs/GUARDRAILS.md).
- **TDD:** every guardrail and rule is covered by `pytest`. `tests/` is the spec.
- **Standards-aligned:** OWASP Top 10:2025, OWASP API Top 10, MASVS, ASVS, CVSS v3.1.
  See [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md).
- **Coverage honesty:** the report always states which suites were *skipped* (unverified),
  so "no findings" is never confused with "safe".

## Install
```bash
python -m pip install -r requirements.txt
```

## Quick start
```bash
# 1. Copy and edit a run config
cp config/example.yaml config/myapp.local.yaml

# 2. Static analysis only (safe, no target needed) — point source_roots at your code
python -m vaptframework.cli run --config config/myapp.local.yaml

# 3. Readiness go/no-go before any active testing
python -m vaptframework.cli preflight --config config/myapp.local.yaml

# 4. Check whether a URL is in scope
python -m vaptframework.cli scope-check --config config/myapp.local.yaml --url https://staging.example.com/

# 5. Emergency stop (engage kill switch)
python -m vaptframework.cli stop --config config/myapp.local.yaml
```

## Dynamic round (staging)
The active DAST + API round is turnkey. For VahanSpace, the API surface is already extracted
(`testplan/vahanspace_api_inventory.*` — 415 endpoints) and **224 read-only checks are
generated** (`testplan/vahanspace_api_tests.json`: unauth/API2, BFLA/API5, BOLA/API1 templates).
Provide a staging URL + per-role tokens + a signed RoE, run `preflight` until it prints **GO**,
then `run`. Full runbook: [`docs/STAGING_ROUND.md`](docs/STAGING_ROUND.md); RoE template:
[`docs/RULES_OF_ENGAGEMENT_VahanSpace.md`](docs/RULES_OF_ENGAGEMENT_VahanSpace.md).
Reports are written to `reports/` as `VAPT_Report.md`, `VAPT_Report.html`,
`findings.json`, and `run_summary.json`, and findings are written back into the test-plan
workbook.

## Scanner suites
| Suite | Type | Needs | What it does |
|---|---|---|---|
| `secrets` | passive | source | Hard-coded credentials/keys (redacted evidence) |
| `sast` | passive | source | Bandit (Python) + native rules (JS/TS/config): SQLi, eval, TLS-off, XSS sinks, weak crypto |
| `sca` | passive | source | `pip-audit` / `npm audit` for known-vulnerable dependencies |
| `config-audit` | active | target | Security headers, cookie flags, tech disclosure |
| `dast` | active | target+authz | HTTP methods, verbose errors, reflected-input surface (non-destructive) |
| `api` | active | target+authz+creds | Auth enforcement + BOLA/BFLA denial checks (OWASP API1/API2/API5) |
| `nmap` `nikto` `zap` | active (opt-in) | target+authz+tool | Wrappers for the engagement tools; degrade to a note if the binary is absent |
| `sqlmap` | active, **destructive-gated** | target+destructive authz | SQLi detection on explicitly listed URLs only |

**Passive** suites run offline on source. **Active** suites run only with a valid
authorization and an in-scope target (see guardrails).

## Enabling active testing
1. Put the authorized **staging** host in `scope.allowed_hosts` and `targets`.
2. Sign the `authorization` block (`authorized_by`, dates, `allow_active_testing: true`).
3. Provide staging test accounts under `credentials`.
Production is refused unless `allow_production: true` is set with separate written approval.

## Tests
```bash
python -m pytest -q
```

## Project layout
See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## For VahanSpace
`config/vahanspace.yaml` is pre-filled for static analysis of the VahanSpace codebase.
DAST/API stay disabled until an authorized staging target and credentials are supplied.
