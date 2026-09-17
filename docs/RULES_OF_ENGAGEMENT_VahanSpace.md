# Rules of Engagement — VahanSpace Dynamic Round (Round 2)

> Fill and sign before enabling active testing. Mirror the agreed values into
> `config/vahanspace.staging.local.yaml` `authorization:` block.

| Field | Value |
|---|---|
| Application | VahanSpace — Web (React), REST API (FastAPI `/api/v1`), Mobile (Android/iOS) |
| Engagement ID | VahanSpace VAPT 2026 — Round 2 (Dynamic) |
| Authorized by (name, title) | __________________________ |
| Client 24x7 contact | __________________________ |
| Testing window (from → to) | __________ → __________ |
| Environment in scope | **Staging only** (production explicitly OUT of scope) |
| In-scope host(s) | __________________________ (e.g. staging-api.vahanspace.example) |
| Out-of-scope paths | `/api/v1/admin/wipe`, `/api/v1/admin/*` destructive ops, `/internal/`, payment settlement |
| Test accounts | userA, userB, dealerA, dealerB, dealer_admin, dealer_employee, service_provider, loan_agent, admin (throwaway, staging) |
| Active testing permitted? | ☐ Yes  ☐ No |
| Destructive/mutating permitted? | ☐ No (default) — keep `allow_destructive: false` |
| DoS / load testing permitted? | ☐ No (default) |
| Max request rate | 2 req/s, burst 4 |
| Data handling | No real customer PII; seeded staging data only; evidence redacted |
| Emergency stop | Create `STOP_TESTING` (or `cli stop`); notify client contact |

## Scope of automated checks (this round)
- 136 unauthenticated-access checks (OWASP API2) across all protected endpoints.
- 80 broken-function-level-authorization checks (OWASP API5) — `user` token vs privileged endpoints.
- 8 BOLA templates (OWASP API1) — object-ownership, run once victim object ids are seeded.
- DAST: security headers, cookie flags, HTTP methods, verbose errors, reflected-input surface (non-destructive).
- SAST/SCA/secrets: re-run against source for regression.

## Standing rules
1. Staging only; production is never touched.
2. No real customer data is read, copied, or exfiltrated.
3. No destructive actions (no data mutation/deletion, no DoS) without a separate signed addendum.
4. Stop immediately on client request or on any sign of instability; engage the kill switch.
5. Findings and evidence are confidential to this engagement.

Signature: ____________________   Date: __________
