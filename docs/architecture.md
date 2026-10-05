# XPRisk architecture

Phases 1-14. This document records the layering, the dependency rules that
enforce it, and — more usefully in a review — *why* each boundary exists. A
layer diagram on its own is decoration; a boundary nobody can state a reason for
is one that will be crossed by accident.

## Layers

```
                        ┌───────────────────────────────┐
                        │        dashboard/             │  Streamlit, engine-bound
                        │        (phase 14)            │
                        └───────────────┬───────────────┘
                                        │ direct calls
                                        │ (no HTTP)
┌───────────────────────────────────────┼─────────────────────���─────────────┐
│                          backend/app/                          │  12-13
│   ┌───────────┐   ┌────────────┐   ┌──────────────────────┐             │
│   │  api/     │──▶│ services/  │──▶│  database/ + models/ │             │
│   │ (routers) │   │ (use case) │   │  (persistence)       │             │
│   └───────────┘   └─────┬──────┘   └──────────────────────┘             │
│        ▲               │                                            │
│        │               ▼                                            │
│   ┌────┴───────┐  ┌─────────────────────────────────────┐           │
│   │ schemas/   │  │  scanners/  normalizer/  risk_engine/│           │
│   │ (Pydantic) │  │            explainability/           │           │
│   └────────────┘  │            (the domain core)         │           │
└───────────────────┴─────────────────────────────────────┘───────────┘
```

Dependencies point **downward only**. Nothing in the domain core imports from
`backend/`. Nothing in `risk_engine/` imports from `scanners/`. The practical
consequence: every risk-model test runs with no database, no subprocess and no
security tool installed, which is why the suite is fast and why
`docs/risk-model.md` can be verified by reading and by executing.

## The five boundaries, and what each one buys

### 1. Scanner execution vs finding normalization — `scanners/` vs `normalizer/`

**Rule.** `scanners/` may run subprocesses and knows about JSON files and CLI
flags. `normalizer/` may not run anything; it translates data structures only.

**Why.** Two reasons, and the second is the important one.

First, it makes parser logic testable without executing a security tool. The
whole test suite runs on a machine with nothing installed.

Second — and this is the one that only became clear from a real defect — it
means an integration bug cannot corrupt the risk model. When Checkov turned out
to emit a flat `check_name` rather than a nested `check` object, the bug lived
entirely in the parser. The scoring function did not change, was not re-tuned,
and every risk-model test kept passing. Had translation been tangled into
execution, that same bug would have had a plausible-looking path into the
aggregate.

### 2. Risk computation vs explanation — `risk_engine/` vs `explainability/`

**Rule.** The engine produces a number and a contribution breakdown. It produces
no prose. `explainability/` reads that breakdown and produces text. It computes
no risk.

**Why.** The score must be defensible on its own terms. If the same object both
decided the score and wrote the sentence justifying it, there would be no way to
check the sentence against the arithmetic — and the sentence is the part a human
actually reads and disputes.

It also keeps the research contribution separable. `risk_engine/` is the part
that could be validated against labelled incident data; `explainability/` is
presentation. Merging them would make the first impossible to extract.

### 3. Domain vs persistence — `normalizer/models.py` vs `backend/app/models/`

**Rule.** Two different types named `XPRiskFinding` exist. The normalizer's is a
dataclass; the ORM's is a SQLAlchemy model. They are never passed as one to the
other; `StorageService` translates at the boundary.

**Why.** A scanner finding is a fact about a file. A database row is a fact
about a fact, subject to schema migration, indexes and column types. Conflating
them means every column rename is a change to the risk model.

**Consequence, stated plainly.** This does duplicate a field list. That is the
intended trade: the duplication is caught by tests, whereas a shared type
couples the research core to a schema that will change.

### 4. API schemas vs ORM — `backend/app/schemas/` vs `backend/app/models/`

**Rule.** Same separation as above, one layer out. `schemas/scan.py` does not
import anything from `models/`.

**Why.** The API contract is a promise to the dashboard and to a future CI/CD
integration. The database is an implementation detail that will gain columns,
lose columns and eventually change engine. If both were one type, a migration
could break a client without any code change on the client side.

### 5. HTTP vs use case — `api/` vs `services/`

**Rule.** A router validates, delegates, returns. It contains no business logic
and performs no risk arithmetic.

**Why.** `ScanService.assess` is the whole pipeline as one plain method on a
plain dataclass. It can therefore be called from a script, from a test, or from
the dashboard, with no server running. That is not theoretical convenience —
`run_integration_scenarios.py` and `xprisk_comparative.py` both depend on it, and
so does `tests/test_scan_endpoint.py`, which drives the service directly for most
of its assertions.

`tests/test_scan_endpoint.py::test_the_service_does_not_import_http` asserts
`scan_service.py` contains no reference to `fastapi`, `pydantic` or `starlette`,
so the rule cannot rot into a suggestion.

## Where each responsibility actually lives

The design table in `backend/app/services/__init__.py` names six services. Two
exist. The honest reason the other four are absent is worth stating, because it
is not "missing logic":

| Named service | Status | Why |
|---|---|---|
| `scanner_service` | exists at `scanners/scanner_service.py` | Built in Phase 5 under a package-level name |
| `normalization_service` | exists at `normalizer/normalizer.py` | Built in Phase 6 the same way |
| `storage_service` | exists | Built in Phase 7 |
| `risk_service` | **absent** | Risk engine is a package; no wrapper |
| `explanation_service` | **absent** | Explainability is a package; no wrapper |
| `scan_service` | exists | Built in Phase 12 |

So the gap is a **naming and indirection** gap, not missing logic. Three of the
four "planned" services already do their jobs as packages, and `scan_service`
calls them directly. What is missing is a thin wrapper per concern so that a
router depends on one name rather than reaching into three packages. That is
worth ~40 lines and is the honest next slice — but it is not functionality.

## Two deviations from the layering, both deliberate

### The dashboard is engine-bound, not API-bound

`dashboard/service.py` imports `StorageService` and `risk_engine` directly. It
never makes an HTTP call, and `POST /scan` exists but the dashboard does not use
it.

**Why.** The demonstration must run with no server, no PostgreSQL and no Docker.
`demo.cmd` starts the dashboard as the last step and nothing else is running. If
the dashboard needed the API, the demo would need two processes and a health
check, and the failure mode would be a blank page rather than a clear error.

**What it costs.** Two callers of one scoring function. If they ever disagreed,
the number on screen would depend on which view was open. That is guarded:
`test_the_api_matches_the_dashboard_for_the_same_findings` asserts both produce
`51.36` / `WARNING` for the same findings.

`dashboard/api_client.py`, `components/` and `pages/` are placeholders. The
five-view plan (overview, findings, risk analysis, explanations, trends) is
Phase 14 and is not built; two views exist.

### The scanner service does not normalize

`ScannerService.collect` returns each adapter's own finding objects —
`TrivyFinding` stays Trivy-specific. Translation is a separate pass.

This is boundary 1 above, and it is worth restating at this level because it is
the one an implementer would most naturally get wrong. The collector's job is
fan-out and per-tool status, not translation.

## What the layering does *not* give you

- **No fault isolation between services.** There is no retry and no circuit
  breaker. Each adapter carries its own timeout and they differ widely — SonarQube
  30 s, Gitleaks 300 s, Trivy and Checkov 600 s — and nothing coordinates them.
- **Scanners run sequentially.** `ScannerService.collect` is a plain loop over the
  selected tools, so a four-tool scan takes the *sum* of the four times, not the
  maximum. Parallelising it is straightforward and was not done; it was
  unnecessary while the only caller replayed fixtures. It becomes a real cost
  once Trivy is scanning a large image.
- **No transactional boundary.** `ScanService.assess` performs three writes
  (`create_deployment`, `save_findings`, `save_risk_factors`) with no surrounding
  transaction. A failure on the third leaves a deployment row with findings but
  no contributions. Wrapping them is straightforward and is not done; the tests
  that exercise this path always succeed, so the gap is untested rather than
  known-broken.
- **No concurrency control.** Two scans of the same commit write two deployment
  rows. Nothing deduplicates, and nothing should — each is a real event.
- **No read API.** The write side is complete and tested; the read side is
  `list_deployments`, `get_deployment`, `get_findings_for_deployment` and
  `get_risk_factors` inside `StorageService`, with no router over them.

## Dependency rules, and how they are held

| Rule | Held by |
|---|---|
| The domain core imports nothing from `backend/` | structural; importable from a bare `sys.path` |
| `scan_service` imports no HTTP framework | `test_the_service_does_not_import_http` |
| `schemas/` imports nothing from `models/` | structural; no ORM type appears in the API surface |
| `normalizer/` runs no subprocess | structural; it receives data, it does not fetch it |
| Documented routers are mounted | `test_only_implemented_routes_are_registered` |
| Planned routers 404 | `test_planned_but_unbuilt_routes_return_404` |
| Persistence is reachable | `test_the_write_path_is_now_reachable` |
| The dev database is not used by tests | `test_temporary_database_is_not_the_development_database` |

The last three exist because of a specific failure this project had: persistence
was implemented, tested, and unreachable — `xprisk_dev.db` held zero rows and the
dashboard's *Deployment history* view was permanently empty, which looked like a
broken feature rather than a missing producer. Nothing flagged it. Each gap is now
asserted in the direction that fails if it regresses.

## Related

- [`risk-model.md`](risk-model.md) — the research core this architecture carries
- [`api.md`](api.md) — the HTTP surface
- README §4 — the same architecture, abbreviated
- README §18 — what is built, what is planned, and what was never verified