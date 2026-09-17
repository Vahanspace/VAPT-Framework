# Architecture

```
                    +---------------------+
   config/*.yaml -->|  core/config.py     |  builds Scope, Authorization,
                    |  (RunConfig)        |  Throttle, ScanContext
                    +----------+----------+
                               |
                               v
   testplan/*.xlsx --> +---------------------+   gates every scanner:
     (loader.py)       |  core/engine.py     |   PASSIVE always | ACTIVE needs authz+target
                       |  (Engine)           |   destructive needs allow_destructive
                       +----------+----------+   kill switch | scope | rate limit
                                  |
             +--------------------+---------------------+
             v                    v                     v
      scanners (PASSIVE)   scanners (ACTIVE)      core guardrails
      - secrets            - config-audit         - scope.py (allowlist)
      - sast (bandit+native)- dast                - authorization.py (RoE)
      - sca (pip/npm audit)- api (BOLA/auth)      - ratelimit.py (bucket+kill switch)
             |                    |                     |
             +---------+----------+---------------------+
                       v
             core/findings.py (Finding, FindingsRegister, dedup, severity roll-up)
                       |
                       v
             reporting/  ->  Markdown + HTML report  +  xlsx write-back
```

## Design principles
- **Guardrails are centralized.** The `Engine` is the only component that decides to run a
  scanner. Scanners declare their blast radius (`category`, `destructive`) and never bypass
  their own gates.
- **Default-deny everywhere.** Scope, authorization, and destructive flags all fail closed.
- **Deterministic, testable core.** Pure functions (severity mapping, header evaluation,
  secret/SAST rules, rate-limit math) are unit-tested with injected clocks and fixtures.
- **Graceful degradation.** Missing optional tools (nmap, npm, pip-audit) produce an explicit
  informational note instead of a false pass.
- **Extensible.** Add a scanner by subclassing `scanners/base.Scanner`, declaring its category,
  and registering it in `core/config.build_scanners`.

## Layout
```
vaptframework/
  core/        scope, authorization, ratelimit, severity, findings, engine, config
  scanners/    base, secrets, sast, sca, config_audit, dast, api
  reporting/   report (md/html), xlsx_writer
  testplan/    loader
  cli.py       run / scope-check / stop
config/        example.yaml, vahanspace.yaml
docs/          GUARDRAILS, RULES_OF_ENGAGEMENT, METHODOLOGY, ARCHITECTURE
testplan/      VahanSpace_VAPT_Automation_Test_Plan.xlsx
tests/         pytest suite (TDD)
reports/       generated output (gitignored)
evidence/      captured evidence (gitignored)
```
