# Guardrails

This framework is **safe-by-default**. It is designed so that no destructive or
out-of-scope action can happen by accident. Every guardrail below is enforced in code and
covered by tests (`tests/test_scope.py`, `tests/test_authorization.py`,
`tests/test_ratelimit.py`, `tests/test_engine_guardrails.py`).

## 1. Default-deny scope allowlist
- Nothing is touched unless its host is on the `allowed_hosts` allowlist
  (`vaptframework/core/scope.py`).
- `excluded_hosts` and `excluded_paths` always win over the allowlist.
- An optional `allowed_ports` list restricts ports.
- Enforced at two layers: the engine checks scope, and each active scanner re-checks every
  URL immediately before the request (defence in depth).

## 2. Production is refused by default
- If `environment: production`, or a host looks production-like (`prod`, `www.`, `live.`),
  the target is **refused** unless `allow_production: true` is set explicitly.
- Use this only with separate, written authorization for production testing.

## 3. Authorization gate for active testing
- **Passive** work (reading your own source, evaluating captured responses) needs only a
  scope.
- **Active** work (any network probe) additionally requires a signed, in-date
  `authorization` record (`vaptframework/core/authorization.py`):
  - `authorized_by` must be a real name (placeholders like `TBD` are rejected),
  - the current date must be within `valid_from`..`valid_until`,
  - `allow_active_testing: true`.
- **Destructive** work (data mutation/deletion, DoS) additionally requires
  `allow_destructive: true`. It is off by default and never enabled implicitly.

## 4. Rate limiting
- A token-bucket limiter caps requests/second (`rate_limit` in the config) so the framework
  cannot behave like a DoS. Default: 2 req/s, burst 4.

## 5. Kill switch
- Creating the `kill_switch_file` (default `STOP_TESTING`) halts all active testing
  immediately. `python -m vaptframework.cli stop --config <cfg>` engages it.

## 6. No destructive exploitation by design
- The DAST scanner performs **non-destructive** checks only: header/method/error/reflection
  probes with a benign, non-executing marker. It does **not** run SQLi/RCE exploitation,
  brute force, or DoS. Those remain manual, explicitly-authorized activities.
- The API scanner confirms **denials** (which are safe) with idempotent verbs; non-idempotent
  probes require destructive authorization.

## 7. Fail-safe and transparent
- A scope violation or a scanner crash fails that suite safely and lets the run continue; it
  is recorded, never hidden.
- The report always lists **skipped suites as "NOT tested"** so absence of findings is never
  mistaken for proof of safety.

## 8. Evidence hygiene
- Secrets found in code are **redacted** in evidence.
- Never place secrets, tokens, or personal data in URLs or logs.

## Operator checklist before any active scan
1. Written authorization exists and is referenced in `authorization.notes`.
2. Target is **staging/non-production** and on the allowlist.
3. Test accounts are throwaway staging accounts.
4. `requests_per_second` is appropriate for the environment.
5. You know how to engage the kill switch.
