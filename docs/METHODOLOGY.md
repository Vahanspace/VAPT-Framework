# Methodology

The framework operationalizes the engagement methodology described in the client KT
document, aligned to industry standards:

- **OWASP Top 10:2025** (web)
- **OWASP API Security Top 10:2023** (API)
- **OWASP MASVS / MASTG** (mobile)
- **OWASP ASVS** (verification requirements)
- **PTES** phases and **CVSS v3.1** scoring

Approximately **70% manual / 30% automated** is the intended split; this framework covers the
automatable 30% and structures the manual 70% via the test plan worksheet.

## Phases (mapped to scanners & test-plan modules)

| Phase | What it covers | Automated support | Manual (test plan) |
|---|---|---|---|
| Reconnaissance | Fingerprinting, entry points, info leakage | `config-audit` headers, `sca` tech/versions | Search-engine recon, enumeration |
| Configuration Mgmt | TLS, HTTP methods, headers, backup files | `config-audit`, `dast` (methods/errors) | File permissions, platform config |
| Authentication | Login, tokens, OTP, lockout, reset | `api` (unauth rejection), `sast` (JWT) | Bypass, cache, alt channels |
| Session Mgmt | Cookies, fixation, CSRF, timeout, logout | `config-audit` (cookie flags) | Fixation, CSRF, concurrency |
| Authorization / BOLA | Object & function-level access, IDOR | `api` (BOLA denial checks) | Privilege escalation, path traversal |
| Data Input Validation | XSS, SQLi, command/SSRF/LFI/RFI | `sast` (SQLi/eval/cmd), `dast` (reflection) | Manual injection & exploitation |
| Error Handling | Stack traces, error codes | `dast` (verbose error probe) | Crafted error analysis |
| Business Logic | Integrity, timing, forged requests, upload | — (design-specific) | Manual, creativity-driven |
| Client-side | JS exec, redirects, CORS, postMessage | `sast` (dangerous HTML, CORS, redirect) | DOM XSS, CSP bypass |
| Denial-of-Service | Availability (OPTIONAL) | Disabled by default (guardrail) | Only with explicit authorization |
| Reporting | Rank, prioritize, evidence, retest | `reporting` (MD/HTML/xlsx) | Executive summary, retest cycle |

## API stages (from the KT doc)
1. Scope & information gathering → `config/*.yaml`, endpoint/spec intake.
2. Reconnaissance → `sca`, `config-audit`.
3. Vulnerability analysis → `api` (BOLA/BFLA/auth), manual injection.
4. Reporting → `reporting`.

## Severity
Findings use the qualitative bands mapped from CVSS v3.1 base scores
(`vaptframework/core/severity.py`): Critical ≥ 9.0, High 7.0–8.9, Medium 4.0–6.9,
Low 0.1–3.9, Informational 0.0.

## Retest
Each retest cycle reassesses only previously identified, still-open findings — matching the
KT document's retesting model. Track this via the `Retest Status` column in the worksheet.
