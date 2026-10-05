# XPRisk API reference

Phase 13. This is the hand-written companion to the auto-generated OpenAPI docs at
`/docs`; it records the reasoning that a schema cannot.

**Current surface: two endpoints.** `GET /health` and `POST /scan`. Five further
routers are planned and return `404`, which
`tests/test_backend_app.py::test_planned_but_unbuilt_routes_return_404` asserts
so the gap stays visible.

| Endpoint | Status | Purpose |
|---|---|---|
| `GET /health` | done | Liveness plus a database reachability probe |
| `POST /scan` | done | Run → normalize → score → explain → persist, returns `deployment_id` |
| `GET /findings`, `GET /findings/{id}` | planned | Query normalized findings |
| `GET /deployments`, `GET /deployments/{id}` | planned | Query stored assessments |
| `GET /risk/{id}`, `POST /risk/evaluate` | planned | Read a score; score without persisting |
| `GET /explanation/{id}` | planned | Read a stored explanation |
| `GET /trends` | planned | Historical risk over time |

---

## `POST /scan`

The only endpoint that runs the whole pipeline. It is the piece that was missing
from the project until Phase 12: before it, every package was individually
reachable but nothing joined them together, so the storage layer was correct and
unreachable.

### Request

```json
{
  "branch": "main",
  "commit_id": "a1b2c3d4",
  "context": {
    "environment": "production",
    "exposure": "internet-facing",
    "change_status": "new"
  },
  "gitleaks": true,
  "trivy": false,
  "checkov": false,
  "sonarqube": false,
  "gitleaks_target": ".",
  "trivy_image": "",
  "checkov_path": ".",
  "checkov_framework": "terraform",
  "fixtures": { "gitleaks": "fixtures/gitleaks/secrets_detected.json" }
}
```

Every scanner defaults to **off**. A request that selects nothing is valid and
produces a real, persisted, zero-finding deployment — a clean scan is a result,
not a no-op.

| Field | Type | Notes |
|---|---|---|
| `context.environment` | `development` \| `staging` \| `production` | Default `development` |
| `context.exposure` | `internal` \| `internet-facing` | Default `internal` |
| `context.change_status` | `new` \| `existing` | Default `new` |
| `branch` | string | Default `""` |
| `commit_id` | string \| null | Stored on the deployment row |
| `fixtures` | object | scanner name → recorded-output path. See below. |

### Why the body is required even though every field has a default

An omitted body is a `422`, not an empty scan. A CI webhook that fired with no
payload would otherwise create a genuine zero-finding deployment several times a
day, and nothing about the result would look wrong. Making the caller state what
it meant is the safer default.

### `fixtures` — and the rule that protects it

`fixtures` replays recorded scanner output instead of executing a tool. It exists
so the test suite and the demonstration are reproducible without Gitleaks,
Trivy or Checkov installed.

**A fixture supplied for a scanner that was not selected is rejected with a
`422`.** The alternative is worse than an error: a caller asks for a real
Trivy scan, XPRisk answers with a JSON file from six months ago, and the score
looks legitimate. `ScanRequest` uses `extra="forbid"` for the same reason — a
typo like `severity` instead of `change_status` is rejected rather than
silently ignored.

### Response — `201 Created`

```json
{
  "deployment_id": 1,
  "risk_score": 51.36,
  "decision": "WARNING",
  "base_score": 32.1,
  "total_raw": 22.1,
  "finding_count": 2,
  "context": { "environment": "production", "exposure": "internet-facing", "change_status": "new" },
  "statuses": { "gitleaks": "SUCCESS" },
  "errors": [],
  "severity_breakdown": { "HIGH": 1, "CRITICAL": 1 },
  "category_breakdown": { "SECRET": 2 },
  "explanation": { "...": "headline, summary, derivation, contributors, breakdowns" },
  "recommendation": { "...": "action, findings_to_fix, projected_score" }
}
```

`201` rather than `200` because the call has a durable effect: `deployment_id`
identifies a row in `deployments`, with its `findings` and `risk_factors`.

Measured, from the request above:

| Field | Value |
|---|---|
| `deployment_id` | 1 |
| `risk_score` / `decision` | 51.36 / WARNING |
| `base_score` | 32.1 (before context uplift) |
| `total_raw` | 22.1 (before normalization to 0-100) |
| `finding_count` | 2 |
| `statuses` | `{"gitleaks": "SUCCESS"}` |
| `explanation.headline` | `Risk score 51.4/100 -> WARNING` |

`base_score` 32.1 → 51.36 is the context model doing its work: the same two
findings score **36.915** in `development/internal`. The dashboard displays that as
`36.9`, because the headline rounds to one decimal while this field does not.
See [`risk-model.md`](risk-model.md) §4.

---

## `GET /health`

```json
{ "status": "healthy", "app": "XPRisk", "environment": "development", "database": "ok" }
```

`database` is `"ok"` or `"unavailable"`. It is a reachability probe
(`SELECT 1`), not a deep check.

**Health always returns `200`, even when the database is unreachable.** A
liveness probe that crashes when its dependency is down turns a partial outage
into a total one — the orchestrator restarts a process that was working fine.
The dependency's state is reported in the body, where a caller can act on it.

It lives in `main.py` rather than a router because it must answer even when a
service cannot be constructed. It depends on nothing but the settings object.

---

## Design rules this endpoint follows

**A scanner failure is not an HTTP error.** A missing binary, a non-zero exit or
a malformed report appears inside a `201`, per tool, in `statuses` and `errors`.
A gate that fails the whole pipeline because Gitleaks is not installed would be
unusable in practice, and a deployment row is always created regardless.

**Routers hold no business logic.** `backend/app/api/scan.py` validates,
delegates and returns a response model. The sequence lives in
`ScanService.assess`, so it stays reachable from a script without FastAPI
installed — which is what `run_integration_scenarios.py` and
`xprisk_comparative.py` rely on.

**Schemas are not the ORM.** `backend/app/schemas/scan.py` and
`backend/app/models/models.py` are separate on purpose: the database will change
(new columns, new indexes, a different engine), the API contract is a promise to
clients. A migration must never be able to break a client silently.

**An internal fault is sanitised.** A genuine bug in XPRisk produces a `500`
whose detail is `assessment failed: <ExceptionClass>` — never the message,
which may contain a filesystem path or a fragment of a scanned file. Asserted by
`test_an_internal_bug_becomes_a_sanitised_500`.

**Validation happens twice, on purpose.** The schema rejects a bad context value
with a `422` naming the field; the enums in `risk_engine/context.py` would also
reject it. That is belt-and-braces, not redundancy: the schema is the contract
with clients, the enum is the contract with the risk model.

---

## What is not here

Stated plainly, because a documented endpoint that does not exist is worse than
an undocumented one — an earlier README revision listed four of these as though
they worked, and every one of them returned `404`.

- **No read API.** `POST /scan` writes a full assessment, but there is no
  `GET /deployments/{id}` or `GET /risk/{id}`, so a stored result can currently
  only be read from the database or the dashboard's *Deployment history* view.
  The write side being done makes this the natural next slice.
- **No risk-only evaluation.** `POST /risk/evaluate` would score a supplied list
  of findings without persisting, which is what makes a sandbox usable. The same
  thing today is `ScanService.assess` in-process with a throwaway storage
  instance, or `risk_engine.engine.RiskEngine.assess` directly.
- **No authentication.** Nothing is exposed beyond localhost in this prototype.
  Real deployment needs auth, because `POST /scan` executes local tools against a
  caller-supplied path.
- **No CI/CD consumer.** Phase 15 is a fully commented-out stub. `POST /scan` is
  now a single call a gate could make, which it previously had nothing to call —
  but nothing makes it.

## Related

- [`risk-model.md`](risk-model.md) — the scoring this endpoint exposes
- [`architecture.md`](architecture.md) — layering and dependency rules
- README §17 — a runnable example request
- `tests/test_scan_endpoint.py` — the contract as executable assertions