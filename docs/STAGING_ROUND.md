# Dynamic Round Runbook (Staging)

Everything for the active DAST + API round is prepared. This is the operator checklist.

## What is already prepared
- **API inventory:** `testplan/vahanspace_api_inventory.json` / `.csv` — **415 endpoints** extracted
  from the FastAPI source (`/api/v1`), with method, auth level, and path params.
- **Generated checks:** `testplan/vahanspace_api_tests.json` — **224 read-only tests**:
  - **136 unauth** (API2) — each protected endpoint must reject anonymous access. *Needs only the target.*
  - **80 BFLA** (API5) — a plain `user` token must be denied admin/owner/staff/provider endpoints. *Needs only a user token.*
  - **8 BOLA templates** (API1) — endpoints addressing an object by id. *Fill a victim object id to run.*
- **Config template:** `config/vahanspace.staging.example.yaml`.
- **Framework support:** `preflight` go/no-go, `${TARGET}` substitution, kill switch, rate limiting.

## Endpoint auth breakdown (from source)
| Auth level | Count |
|---|---:|
| public | 79 |
| authenticated | 118 |
| admin | 146 |
| owner | 21 |
| staff | 19 |
| provider | 18 |
| optional | 12 |
| brand_owner | 2 |
| **total** | **415** |

## You provide (3 things)
1. **Staging base URL** (never production) → `scope.allowed_hosts` + `targets`.
2. **Throwaway staging test accounts + bearer tokens**, one per role (see `credentials` in the template).
   For BOLA, two of each tenant type (userA/userB, dealerA/dealerB) so one can try to reach the other's objects.
3. **Signed authorization** → fill `docs/RULES_OF_ENGAGEMENT_VahanSpace.md`, then set
   `authorization.authorized_by`, the dates, and `allow_active_testing: true`.

## Steps
```bash
# 1. Copy the template (the .local.yaml name is gitignored)
cp config/vahanspace.staging.example.yaml config/vahanspace.staging.local.yaml
#    ...edit: host, target, tokens, sign authorization...

# 2. Readiness gate — must print PREFLIGHT: GO
python -m vaptframework.cli preflight --config config/vahanspace.staging.local.yaml

# 3. Confirm the target is in scope
python -m vaptframework.cli scope-check --config config/vahanspace.staging.local.yaml --url https://STAGING-HOST/

# 4. Run (static + config-audit + dast + 224 api checks), write results into the workbook
python -m vaptframework.cli run --config config/vahanspace.staging.local.yaml \
    --plan testplan/VahanSpace_VAPT_Automation_Test_Plan.xlsx --write-plan

# Emergency stop at any time:
python -m vaptframework.cli stop --config config/vahanspace.staging.local.yaml   # creates STOP_TESTING
```

## Refreshing the inventory
If the API changes, regenerate the inventory/checks:
- **From a running staging app (most accurate):** fetch `https://STAGING-HOST/api/v1/openapi.json` and use
  `api_inventory.load_from_openapi`.
- **From source:** re-run the extractor (`api_inventory.extract_from_source`) against `backend/app/api/routes`.

## Safety notes
- Only **GET/HEAD** checks run by default (non-destructive). Mutating verbs stay off unless
  `allow_destructive: true` — keep it false.
- BOLA/BFLA confirm **denials**, which is safe. Investigate any 200 manually before reporting.
- The generated checks are the automatable core. The manual ~70% (business logic, payment
  flows, deep authorization matrices across the 9 roles, mobile MASTG) still needs an analyst.
```
