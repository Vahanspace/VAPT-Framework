# Rules of Engagement (RoE) — template

> Fill this in and have it signed **before** any active testing. The machine-readable
> `authorization:` block in your run config must mirror the values agreed here.

| Field | Value |
|---|---|
| Application | VahanSpace (Web / API / Mobile) |
| Engagement ID | |
| Authorized by (name, title) | |
| Client contact (24x7) | |
| Testing window (from → to) | |
| Environments in scope | Staging only (no production) |
| In-scope hosts / URLs | |
| Out-of-scope hosts / paths | |
| Test accounts provided | |
| Active testing permitted? | Yes / No |
| Destructive testing permitted? | No (default) |
| DoS / load testing permitted? | No (default) |
| Max request rate | 2 req/s (default) |
| Data handling | No real PII exfiltration; redact evidence |
| Emergency stop procedure | Create `STOP_TESTING`; notify client contact |

## Standing rules
1. **Staging only** unless production is separately authorized in writing.
2. **No real customer data** is to be read, copied, or exfiltrated. Use seeded test data.
3. **No destructive actions** (delete/modify other tenants' data, payments, DoS) without
   explicit `allow_destructive` authorization.
4. Stop immediately on the client's request or if instability is observed; engage the kill
   switch.
5. All findings and evidence are confidential to the engagement.

## Legal / ethical note
Only test systems you own or are explicitly authorized to test. Unauthorized testing may be
illegal. This framework enforces authorization and scope, but the operator remains
responsible for having valid permission.
