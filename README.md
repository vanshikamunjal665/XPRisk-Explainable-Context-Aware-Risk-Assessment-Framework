# XPRisk

### Explainable Context-Aware Risk Assessment Framework for Secure Cloud-Native CI/CD Pipelines

> Four DevSecOps scanners in. **One** auditable, explainable deployment decision out.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![Framework: FastAPI](https://img.shields.io/badge/backend-FastAPI-009688.svg)](https://fastapi.tiangolo.com/)
[![Dashboard: Streamlit](https://img.shields.io/badge/dashboard-Streamlit-FF4B4B.svg)](https://streamlit.io/)

---

## Table of contents

1. [Project overview](#1-project-overview)
2. [Problem statement](#2-problem-statement)
3. [Objectives](#3-objectives)
4. [Architecture](#4-architecture)
5. [Workflow](#5-workflow)
6. [Technology stack](#6-technology-stack)
7. [Repository structure](#7-repository-structure)
8. [Prerequisites](#8-prerequisites)
9. [Installation](#9-installation)
10. [Environment variables](#10-environment-variables)
11. [Database setup](#11-database-setup)
12. [Running the backend](#12-running-the-backend)
13. [Running the dashboard](#13-running-the-dashboard)
14. [Running the scanners](#14-running-the-scanners)
15. [Running the tests](#15-running-the-tests)
16. [Docker setup](#16-docker-setup)
17. [Example workflow](#17-example-workflow)
18. [Project status](#18-project-status)
19. [Security notes](#19-security-notes)
20. [Roadmap](#20-roadmap)

---

## 1. Project overview

Modern cloud-native pipelines already run several security scanners. Trivy finds
vulnerable packages in container images. Checkov finds insecure
infrastructure-as-code. Gitleaks finds committed secrets. SonarQube finds code
quality and security issues in source.

Each is useful alone. Together they produce four disconnected reports, in four
different formats, with four different severity vocabularies, and none of them
answers the only question a release manager actually has:

> **Should I ship this, and why?**

XPRisk is the missing layer. It collects findings from all four tools,
normalizes them into a single canonical schema, analyses the context the code
is being deployed into, computes **one** context-aware risk score between 0 and
100, maps that score onto **SAFE**, **WARNING** or **BLOCK**, and then explains
the decision by attributing the score to the specific findings and context
factors responsible for it.

```
Developer -> GitHub -> CI/CD Pipeline
                          |
        +-----------------+------------------+
        |                 |                  |
    SonarQube          Gitleaks            Trivy
        |                 |                  |
        |              Checkov               |
        +-----------------+------------------+
                          |
                 Finding Collector
                          |
                 Finding Normalizer        <- canonical XPRisk schema
                          |
             PostgreSQL  <-  history
                          |
                  Context Analyzer         <- environment, exposure,
                          |                    change status, category
                  Risk Engine               <- deterministic, 0-100
                          |
                  Explainability            <- derived from real contributions
                          |
              +-----------+-----------+
              |           |           |
            SAFE      WARNING      BLOCK
              |           |           |
              +-----------+-----------+
                          |
                  XPRisk Dashboard
```

## 2. Problem statement

1. **Fragmented visibility.** A pipeline may run four scanners and produce four
   reports. There is no single number, so no single release gate.
2. **Incompatible formats.** Trivy emits CVEs with package versions, Checkov
   emits check IDs with Terraform addresses, Gitleaks emits rule matches with
   file and line, SonarQube emits rule keys with components. None can be
   compared or aggregated directly.
3. **Severity vocabularies do not align.** `CRITICAL..UNKNOWN`, `null`,
   *no severity at all*, and `BLOCKER..INFO`.
4. **No deployment context.** A hardcoded password in a throwaway branch and
   the same password in an internet-facing production service are reported
   identically. Real risk is a function of *what* is wrong **and** *where* it is
   going.
5. **Unexplainable scores.** Existing risk scores are opaque. Once a number is
   published, nobody can reconstruct why it was produced, which makes it
   impossible to contest, audit or improve.

## 3. Objectives

| # | Objective | Where it is delivered |
|---|---|---|
| O1 | Collect findings from Trivy, Checkov, Gitleaks and SonarQube without coupling the framework to any single tool | `scanners/` |
| O2 | Define one **lossless** canonical finding schema for all four tools | `normalizer/` |
| O3 | Model deployment context (environment, exposure, change status, resource category) | `risk_engine/context.py` |
| O4 | Design a **deterministic, configurable, documented** context-aware risk-scoring algorithm | `risk_engine/scoring.py` |
| O5 | Map the score to a configurable SAFE / WARNING / BLOCK recommendation | `risk_engine/thresholds.py` |
| O6 | Generate an explanation **derived from actual contribution values**, never from hardcoded rules | `explainability/` |
| O7 | Persist deployments, findings and contributions so risk can be tracked over time | `backend/app/models/` |
| O8 | Expose everything through a documented REST API and an interactive dashboard | `backend/app/api/`, `dashboard/` |

## 4. Architecture

The dependency rule is strictly one-directional. This is the single most
important structural decision in the project:

```
backend/app  ->  explainability  ->  risk_engine  ->  normalizer
                                                        |
                                                        v
                                                     scanners
```

- Domain packages (`scanners/`, `normalizer/`, `risk_engine/`,
  `explainability/`) **never import FastAPI, SQLAlchemy or Streamlit.** This is
  enforced by a test, not by convention: `tests/test_config.py` walks the AST of
  every module in `risk_engine/` and `normalizer/` and fails the build if any of
  them reads `os.environ` or imports `pydantic_settings`.
- Consequences: the risk model is testable without a server or a database; the
  scanners can be replaced without touching the risk engine.
- The dashboard calls the risk engine and storage directly rather than over HTTP,
  so "deployable independently" is delivered for the API (`POST /scan` runs with
  no Streamlit involved) but not yet consumed by the dashboard. That is
  deliberate: engine-binding is what lets the demo run with no server, no
  database and no Docker.

Two further separations are deliberate, and both are specified explicitly:

| Separation | Why |
|---|---|
| Scanner execution vs finding normalization | Parser logic is unit testable without running any security tool. A scanner bug cannot corrupt the risk model. The split is the package boundary `scanners/` vs `normalizer/`. |
| `schemas/` (Pydantic) vs `models/` (SQLAlchemy) | The API contract cannot be changed silently by a database migration. Both are built; `schemas/scan.py` types `POST /scan` without importing anything from `models/`. |

## 5. Workflow

**Target pipeline.** Every step below now runs. The table still marks each step
with the package that implements it, because "done" is a weaker claim than
"reachable from a single call" and that distinction is the whole point of §5.1.

| # | Step | Status |
|---|---|---|
| 1 | A deployment is requested: a commit, a branch, an environment, an exposure flag. | **done** (`POST /scan`, or `ScanService.assess` directly) |
| 2 | The enabled scanners are triggered and a status is recorded per tool (`SUCCESS`, `FAILED`, `UNAVAILABLE`, `SKIPPED`) plus a duration. **One failing tool never fails the scan.** | **done** (`scanners/`) |
| 3 | Each tool's native JSON is converted into canonical `NormalizedFinding` objects, preserving tool-specific fields under `metadata`. | **done** (`normalizer/`) |
| 4 | `storage_service` persists the `Deployment` and its `Finding` rows. | **done** (called by `scan_service`) |
| 5 | `risk_engine` computes per-finding risk, aggregates it, normalizes to 0-100 through a piecewise-linear curve, applies a bounded context uplift, and maps the result through configurable thresholds. | **done** (`risk_engine/`) |
| 6 | Every individual contribution is persisted to `risk_factors`, which is what makes historical explanations reproducible. | **done** (called by `scan_service`) |
| 7 | `explainability` ranks the contributions into a human-readable rationale and actionable remediation. | **done** (`explainability/`) |
| 8 | FastAPI serves the result; Streamlit renders it. | `POST /scan` and `GET /health`; Streamlit reads the engine directly |

### 5.1 `scan_service`: the step that was missing

Until Phase 12, every package above was individually reachable and none of them
were joined together. `StorageService.create_deployment`, `.save_findings` and
`.save_risk_factors` existed and were correct, but the only caller was
`tests/test_storage.py`. The dashboard composed the pipeline in memory and threw
the result away, so `xprisk_dev.db` stayed at zero rows and the *Deployment
history* view was permanently empty — an empty screen that looked like a broken
feature rather than a missing producer.

`backend/app/services/scan_service.py` closes that gap with one method,
`ScanService.assess`, and `backend/app/api/scan.py` exposes it as `POST /scan`:

```python
outcome = ScanService().assess(ScanRequest(
    branch="main",
    environment="production", exposure="internet-facing",
    gitleaks=True,
    fixtures={"gitleaks": "fixtures/gitleaks/secrets_detected.json"},
))
outcome.risk_score, outcome.decision, outcome.deployment_id
# 51.36, 'WARNING', 1
```

The same two findings score **36.915** in `development/internal` and **51.36** in
`production/internet-facing`. The dashboard rounds to one decimal, so it shows
`36.9` and `51.4`; the API returns the exact value.

Three properties are deliberate and tested (`tests/test_scan_endpoint.py`):

- **One failing tool never fails the scan.** Each tool reports its own status. A
  missing binary, a non-zero exit or a malformed report is recorded against that
  tool and the others still contribute. A deployment row is always created, so a
  scan that found nothing is still a fact worth storing.
- **The breakdown is stored, not just the score.** Every contribution goes into
  `risk_factors` as a *raw risk value*, not a share of the total. A share is
  derivable by dividing by `total_raw`; raw risk is not recoverable from a share,
  so it is the one worth keeping — that is what makes a past explanation
  reproducible after the settings change.
- **The request cannot smuggle fixtures past a caller asking for a real scan.** A
  fixture path supplied for a scanner that was not selected is a 422, not a
  silently recorded result.

The dashboard still reads the engine directly rather than calling the API. That
is a deliberate shortcut: it keeps the demo working with no server, no database
and no Docker. It also means the dashboard and the API are two callers of one
scoring function, and `test_the_api_matches_the_dashboard_for_the_same_findings`
asserts they agree to the decimal — otherwise the number on screen would depend
on which view was open.

## 6. Technology stack

| Component | Technology |
|---|---|
| Programming | Python 3.11+ (developed on 3.12.7) |
| Backend | FastAPI, Pydantic v2, Uvicorn |
| Database | PostgreSQL (SQLAlchemy 2.0 ORM); SQLite fallback for tests |
| Dashboard | Streamlit, Plotly, pandas |
| Container scanning | Trivy |
| IaC scanning | Checkov |
| Secret detection | Gitleaks |
| Static analysis | SonarQube (Web API) |
| Containerization | Docker, Docker Compose |
| Source control | Git, GitHub |
| CI/CD | GitHub Actions |
| Testing | pytest, pytest-cov |
| Configuration | `.env` / environment variables via `pydantic-settings` |

No cloud provider account is required for the local version.

## 7. Repository structure

```
XPRisk-Explainable-Context-Aware-Risk-Assessment-Framework/
├── backend/
│   ├── app/
│   │   ├── main.py               FastAPI application factory
│   │   ├── config.py             Typed settings (pydantic-settings)
│   │   ├── api/                  HTTP routers
│   │   │   └── scan.py           POST /scan
│   │   ├── models/               SQLAlchemy ORM models
│   │   │   └── models.py         Deployment, Finding, RiskFactor
│   │   ├── schemas/              Pydantic request/response models
│   │   │   └── scan.py           ScanContext, ScanRequest, ScanResponse
│   │   ├── services/             Orchestration layer
│   │   │   ├── scan_service.py   The end-to-end use case
│   │   │   └── storage_service.py
│   │   └── database/
│   │       ├── database.py       Engine, session factory
│   │       └── init_db.py        Idempotent schema creation
├── scanners/                     Thin adapters, one per security tool
│   ├── base.py                   ScannerResult, ScannerStatus, safe runner
│   ├── scanner_service.py        Fan-out collector
│   ├── gitleaks_scanner.py
│   ├── trivy_scanner.py
│   ├── checkov_scanner.py
│   └── sonarqube_scanner.py
├── normalizer/
│   ├── models.py                 Canonical XPRiskFinding schema
│   └── normalizer.py             Per-tool parsers + severity mapping
├── risk_engine/                  Research core
│   ├── settings.py               All configurable defaults (no env access)
│   ├── severity.py               Severity + base weights
│   ├── context.py                Context model
│   ├── scoring.py                Scoring algorithm
│   ├── thresholds.py             SAFE / WARNING / BLOCK
│   └── engine.py                 Deterministic orchestration
├── explainability/
│   ├── contributors.py           Rank real contributions
│   ├── explanation.py            Structured explanation payload
│   └── recommendation.py         Actionable remediation
├── dashboard/
│   ├── app.py                    Streamlit entry point
│   ├── service.py                Facade over storage + engine
│   ├── transforms.py             Pure data reshaping
│   └── requirements.txt
├── tools/                        Regeneration scripts for real scanner output
│   ├── regenerate_fixtures.py    Checkov fixtures from a real run
│   └── regenerate_trivy_fixtures.py
├── run_integration_scenarios.py  Prints actual outcomes for the six scenarios
├── xprisk_comparative.py         Comparative study harness
├── demo.cmd                      Demo launcher: pre-flight, tests, scenarios, dashboard
├── demo-app/                     The application XPRisk scans
│   ├── app/                      Flask app (clean baseline)
│   │   ├── main.py               App factory + entry point
│   │   ├── config.py             Settings from the environment
│   │   ├── api/                  HTTP layer: health.py, routes.py
│   │   ├── services/             Pure business logic
│   │   └── requirements.txt
│   ├── Dockerfile
│   ├── docker-compose.yml
│   └── README.md
├── infrastructure/
│   └── terraform/
│       ├── main.tf               Intentionally insecure IaC for Checkov
│       └── main.tf.example-vars  Placeholder values only
├── fixtures/                     Labelled fixture data (see fixtures/README.md)
├── tests/                        pytest suite
├── reports/                      Generated scanner output (git-ignored)
├── docs/
│   └── risk-model.md             Risk-scoring methodology + rationale
├── docker/                       Docker assets for XPRisk itself
├── .github/workflows/xprisk.yml  CI/CD reference (inert, see Step 15)
├── conftest.py                   Puts repo root on sys.path for pytest
├── pyproject.toml                pytest / coverage configuration
├── requirements.txt              Everything
├── requirements-dev.txt          Backend + dashboard + test tooling
├── .env.example
├── .gitignore
├── LICENSE
└── README.md
```

## 8. Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.11 or newer | Developed and verified on 3.12.7 |
| Git | any recent | Already installed |
| PostgreSQL | 14 or newer | Optional for tests; required for the real target |
| Docker Desktop | any recent | Needed for the demo image, Trivy image scans, SonarQube |
| Trivy | any recent | Optional; Docker fallback provided |
| Checkov | any recent | Optional; Docker fallback provided |
| Gitleaks | any recent | Optional; Docker fallback provided |
| SonarQube | 9.x or newer | Optional; Docker fallback provided |

Check what is already available:

```powershell
python --version
docker --version
```

## 9. Installation

Windows, PowerShell. All commands are run from the repository root.

```powershell
# 1. Create and activate a virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# If PowerShell blocks the activation script, allow it for the current user:
#   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# 2. Install all dependencies
pip install --upgrade pip
pip install -r requirements.txt

# 3. Create your local environment file
Copy-Item .env.example .env
```

<details>
<summary>If <code>pip install</code> hangs or fails with <code>access violation</code></summary>

On some Windows machines `pip` stalls during TLS and reports:

```
WARNING: Retrying ... after connection broken by
'ProtocolError('Connection aborted.', OSError('exception: access violation writing 0x48'))': /simple/<package>/
```

and eventually exits with `0xC0000142` (`STATUS_DLL_INIT_FAILED`). Plain HTTPS
from the same interpreter still works, so this is specific to pip's own TLS
path, not a network outage.

Disabling certificate verification for PyPI resolves it:

```powershell
pip install --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt
```

This is a workaround for a broken local TLS stack, not a recommendation. If
pip works normally on your machine, use the plain command above.

</details>

Verify the install:

```powershell
python -c "import fastapi, sqlalchemy, streamlit, plotly, pytest; print('dependencies OK')"
```

On macOS or Linux the activation command is `source .venv/bin/activate`.

## 10. Environment variables

Configuration is read from the environment, with `.env` loaded automatically.
**`.env` is git-ignored. Never commit a real credential.**

`.env.example` documents every variable. The groups are:

| Group | Prefix | Purpose |
|---|---|---|
| Application | `APP_*`, `LOG_LEVEL`, `API_*`, `CORS_ORIGINS` | Runtime behaviour |
| Database | `DATABASE_URL`, `POSTGRES_*` | Connection |
| Orchestration | `SCANNERS_ENABLED`, `SCAN_TIMEOUT_SECONDS`, `ALLOW_FIXTURE_FALLBACK` | Scan behaviour |
| Per tool | `TRIVY_*`, `CHECKOV_*`, `GITLEAKS_*`, `SONARQUBE_*` | Tool configuration |
| Risk model | `XPRISK_*` | Weights, multipliers, anchors, thresholds |

The `XPRISK_*` variables mirror the defaults in `risk_engine/settings.py`.
They exist so the comparative study (severity-only vs severity+count vs
context-aware) can be run by changing configuration alone, with no code edits.

### About `ALLOW_FIXTURE_FALLBACK`

Default `false`. When a scanner executable is missing, XPRisk records that tool
as `UNAVAILABLE`, continues with the remaining tools, and tells you so. When set
to `true`, a missing tool falls back to labelled data from `fixtures/`.

Fixture-derived findings are tagged `"data_origin": "FIXTURE"` in their
metadata, and fixture files are never presented as real scanner output. See
[`fixtures/README.md`](fixtures/README.md).

## 11. Database setup

The project targets PostgreSQL. For development and for the automated tests,
SQLite is supported as a zero-setup fallback.

**Option A - SQLite (zero setup, default in `.env.example`)**

```powershell
# Leave DATABASE_URL=sqlite:///./xprisk_dev.db, then:
python -m backend.app.database.init_db
```

**Option B - PostgreSQL (recommended, matches the target architecture)**

```powershell
# 1. Start PostgreSQL (Docker is the quickest route)
docker run -d --name xprisk-postgres `
  -e POSTGRES_USER=xprisk `
  -e POSTGRES_PASSWORD=xprisk_dev_password `
  -e POSTGRES_DB=xprisk `
  -p 5432:5432 postgres:16-alpine

# 2. Point XPRisk at it in .env
#    DATABASE_URL=postgresql+psycopg2://xprisk:xprisk_dev_password@localhost:5432/xprisk

# 3. Create the schema
python -m backend.app.database.init_db
```

Schema creation is idempotent, so re-running it is safe.

## 12. Running the backend

```powershell
.\.venv\Scripts\Activate.ps1
python -m uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```

Use `python -m uvicorn` rather than bare `uvicorn`: the repository root must be
on `sys.path` so that `backend.app` can import the root-level domain packages
(`risk_engine`, `normalizer`, `scanners`, `explainability`).

Then open:

| URL | Description |
|---|---|
| <http://127.0.0.1:8000/health> | Backend health |
| <http://127.0.0.1:8000/docs> | Interactive Swagger UI |
| <http://127.0.0.1:8000/redoc> | ReDoc reference |

## 13. Running the dashboard

One command runs the whole demonstration — pre-flight, test suite, controlled
scenarios, then the dashboard:

```powershell
.\demo.cmd              # full demo
.\demo.cmd check        # everything except the dashboard
```

It needs no PostgreSQL, no Docker and no installed security tool. The dashboard
reads the risk engine and SQLite directly, so **the backend does not need to be
running** for the demo; start it separately only if you want to show `/health`.

Or run the dashboard on its own:

```powershell
.\.venv\Scripts\streamlit.exe run dashboard/app.py
```

Open <http://127.0.0.1:8501>.

### Suggested demo order

1. Sidebar → *Fixture scenario* = **Secrets only**. Development / internal →
   **Run assessment** → 36.9 WARNING.
2. Change only the context to production / internet-facing, re-run → **51.4
   WARNING**. Same two findings, different score. That single comparison is the
   contribution the project claims.
3. Scroll to **Explanation** — the five derivation steps, each contributor's
   share of the total, and the context cap binding at 1.6.
4. **Deployment context** and **Context factors** — show the cap explicitly.
5. Only then switch to a full-scan preset. Both of those saturate at 100.0 /
   BLOCK; the dashboard warns about it. Say so out loud rather than letting the
   panel discover it.

Steps 1-4 are the ones worth the time. Step 5 is there because the question will
be asked anyway, and the honest answer is stronger than a hidden number.

**Current state, stated plainly.** The dashboard has two sidebar views —
*Assessment* and *Deployment history*. It does not read the backend over HTTP; it
calls `StorageService` and the risk engine directly. There is no `api_client.py`,
and `components/` and `pages/` are placeholders. `POST /scan` now exists, so the
HTTP path is available to it, but using it would make the demo depend on a running
server — so the dashboard was deliberately left engine-bound. See §18, gap 4.

*Deployment history* was permanently empty until `scan_service` landed (§5.1).
Run `POST /scan` once (§17) and refresh the view: the deployment, its findings and
every contribution are there.

No dashboard value is hardcoded either way: every score, decision and
explanation is rendered from what the engine produced for the findings on screen.
The three selectable scenarios are replayed from `fixtures/`, which is real
scanner output for Gitleaks, Trivy and Checkov (see §18). Each scenario states
its own provenance on screen, and a saturated result is called out rather than
presented as a precise score.

## 14. Running the scanners

XPRisk drives the scanners itself. You do not need to run them by hand.

**Verify which tools XPRisk can actually see:**

```powershell
.\.venv\Scripts\python.exe -c "from scanners.base import _locate_executable as f; print({t: f(t) for t in ('checkov','trivy','gitleaks')})"
```

A path means the tool was found; `None` means it is not installed and that
scanner will report `UNAVAILABLE`. On the development machine this currently
prints only `checkov`, because Trivy and Gitleaks were installed as standalone
binaries rather than into the virtual environment.

**Activation is not required.** `.\.venv\Scripts\python.exe <script>` does not
put `.venv\Scripts` on `PATH`, so a tool installed into the virtual environment
would normally be invisible and its findings silently dropped. The adapters
search the running interpreter's own `Scripts` directory as well as `PATH`
(`scanners.base._locate_executable`), which is why the check above is the
reliable test. Verified: with `.venv\Scripts` removed from `PATH`, Checkov
still returns its 24 real findings.

**A tool that is not installed is not a crash.** It is reported as
`UNAVAILABLE` with a captured error, and the remaining tools still contribute
to the assessment. Every scanner adapter also supports Docker execution, which
is the fallback when a host install is not possible — see
[`docker/README.md`](docker/README.md).

SonarQube configuration (never hardcode a token):

```powershell
# .env
SONARQUBE_URL=http://localhost:9000
SONARQUBE_PROJECT_KEY=xprisk-demo-app
SONARQUBE_TOKEN=<generated from SonarQube: My Account -> Security -> Generate Token>
```

## 15. Running the tests

```powershell
.\.venv\Scripts\python.exe -m pytest -p no:cacheprovider -q
# 324 passed, 7 xfailed in ~10s

# a single module, verbose
.\.venv\Scripts\python.exe -m pytest tests/test_risk_engine.py -v

# with coverage
.\.venv\Scripts\python.exe -m pytest --cov
```

The suite runs against an isolated temporary database and uses labelled
fixture data, so it passes **without** PostgreSQL, Docker or any security tool
installed. It is fast because every scanner adapter is tested against a recorded
report with `subprocess` mocked; `tests/test_scanners.py` never invokes a real
tool.

**`pytest -m unit` and `pytest -m integration` do not work yet.** Five markers
(`unit`, `integration`, `contract`, `fixture`, `slow`) are declared in
`pyproject.toml` so that `--strict-markers` will accept them, but no test carries
one yet. Both commands currently report every test deselected and run nothing.
An earlier version of this section listed them as working. Applying the markers
is listed as a gap in §18.

The marker selection is guarded by a test, so it cannot quietly stay wrong:
`tests/test_pyproject_markers.py` fails if a documented `-m` expression selects
no tests.

## 16. Docker setup

### Dockerizing the demo application

```powershell
cd demo-app
docker build -t xprisk-demo-app:latest .
docker run --rm -p 5000:5000 xprisk-demo-app:latest
curl.exe http://127.0.0.1:5000/health

# or
docker compose up --build
```

The image is hardened: multi-stage build, non-root user, `HEALTHCHECK` that uses
the bundled interpreter, and a read-only filesystem with `no-new-privileges`
under Compose.

### Validating the demo infrastructure

```powershell
terraform -chdir=infrastructure/terraform init -backend=false
terraform -chdir=infrastructure/terraform validate
terraform -chdir=infrastructure/terraform fmt -check
```

Never run `terraform apply` against `infrastructure/`: it is intentionally
insecure and exists only as a Checkov test case.

### Running XPRisk under Docker Compose

Containerizing the XPRisk backend, dashboard and PostgreSQL is **Phase 21** of
the project plan and is not part of the current scope. See
[`docker/README.md`](docker/README.md) for what is planned and for the
per-scanner Docker invocations that already work.

## 17. Example workflow

**One endpoint exists: `POST /scan`.** `GET /risk/{id}`,
`GET /explanation/{id}` and `POST /risk/evaluate` do not; calling them returns
404. An earlier version of this section documented all four as though they
worked, which is worse than documenting none.

```powershell
.\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --port 8000
```

Then, from another terminal:

```powershell
# Replays recorded Gitleaks output, scores it, explains it and stores it.
# The response carries the persisted deployment_id.
$body = @{
  branch    = "main"
  commit_id = "a1b2c3d4"
  context   = @{ environment = "production"; exposure = "internet-facing"; change_status = "new" }
  gitleaks  = $true
  fixtures  = @{ gitleaks = "fixtures/gitleaks/secrets_detected.json" }
}
Invoke-RestMethod -Uri http://127.0.0.1:8000/scan -Method Post `
  -ContentType "application/json" -Body ($body | ConvertTo-Json -Depth 5)
```

Returns `201` with `risk_score`, `decision`, `severity_breakdown`, the full
`explanation` and `recommendation`, and the `deployment_id` that was written.
Interactive docs are at `http://127.0.0.1:8000/docs`. Run it with no body and you
get a real, persisted, zero-finding deployment — a clean scan is a recorded
result, not a no-op.

Drop `fixtures` and set `gitleaks = $true` to execute the real tool instead, if
it is installed (§8). Every adapter degrades to `UNAVAILABLE` when its tool is
missing, and a 201 still comes back with the failure reported per tool.

The scripts in the repository root remain the better thing to demonstrate,
because they print what the model actually does rather than a summary of what it
should do:

```powershell
# 1. The six controlled scenarios, with the real outcome of each
.\.venv\Scripts\python.exe run_integration_scenarios.py

# 2. The same finding sets scored under three policies, written to reports/
.\.venv\Scripts\python.exe xprisk_comparative.py
```

`run_integration_scenarios.py` is the substantive one. TEST 4 and TEST 5 show the
contribution of the context model directly: six identical findings score **36.4**
in `development/internal` and **58.2** in `production/internet-facing`. It also
prints the two rows where the result contradicts the scenario name, which is
worth showing rather than hiding (see §18, gap 1).

`demo.cmd` (§13) runs both scripts and then opens the dashboard, in that order.
The dashboard needs no server, no database and no Docker — it reads the risk
engine directly, so it is unaffected by the API work.

For a live scanner run, with the tool installed (§8):

```powershell
# Gitleaks 8.30.1 -> 2 findings
gitleaks dir demo-app/scenarios/insecure `
  --config fixtures/gitleaks/gitleaks.toml `
  --report-format json --report-path gl.json --redact

# Checkov 3.3.22 -> 24 failed checks; exits 1, which the adapter treats as SUCCESS
.\.venv\Scripts\checkov.cmd -d infrastructure/terraform `
  --framework terraform -o json
```

The dashboard presets in §13 replay recorded output from these tools, so nothing
needs to be installed to demo it.

## 18. Project status

Current delivery: **Phases 1-14 complete except the dashboard**, of the planned
1-14.

| Phase | Component | Status |
|---|---|---|
| 1 | Development environment, structure, configuration | Complete |
| 2 | Demo cloud-native application | Complete |
| 3 | Controlled security test cases | Complete |
| 4 | Trivy, Checkov, Gitleaks, SonarQube integration | Complete (3 of 4 verified live) |
| 5 | Finding collector | Complete |
| 6 | Finding normalization | Complete |
| 7 | PostgreSQL storage | Complete (SQLite verified; live PostgreSQL not yet run) |
| 8 | Context model | Complete |
| 9 | Risk-scoring algorithm | Complete |
| 10 | SAFE / WARNING / BLOCK thresholds | Complete |
| 11 | Explainability engine | Complete |
| 12 | Orchestration services | Complete (`scan_service` composes scan → normalize → score → explain → persist) |
| 13 | FastAPI routers | Partial (`GET /health` and `POST /scan`; 5 routers planned) |
| 14 | Streamlit dashboard | Partial (2 views, engine-bound) |
| 15 | GitHub Actions CI/CD | Reference stub, inert |
| 16-23 | Gate, historical analytics, performance, Docker, cloud, polish | Planned |

Phase 12 was the last structural gap. Before it, the storage layer was correct
but unreachable — nothing outside `tests/test_storage.py` called it, so
`xprisk_dev.db` held zero rows and the dashboard's *Deployment history* view was
permanently empty. `scan_service` is now the single caller, and
`tests/test_service_layer.py` asserts it stays that way.

### Promised in the source, not built

Three packages used to document architecture in the present tense that did not
exist. They now mark each item as done or planned, and the claims are guarded:

| Package | Before | Now |
|---|---|---|
| `backend/app/api/__init__.py` listed 6 routers, "all mounted by `main`" | Empty package; 0 routers | `scan` router done and mounted; the other 5 marked planned, each asserted to 404 |
| `backend/app/services/__init__.py` listed 6 services | Only `storage_service` existed | `scan_service` and `storage_service` done; the other 4 marked planned |
| `backend/app/schemas/__init__.py` described the API contract | Empty package | `scan.py` done; the `risk/evaluate` schemas marked planned |

The guards are inverted where the gap has closed.
`tests/test_service_layer.py::test_the_write_path_is_now_reachable` asserts
production code calls all three write methods, so if persistence ever becomes
unreachable again the suite fails — which is exactly the state this project was
in before Phase 12, and the state nobody noticed.

### Verified against real tools

| Tool | Version | Verification |
|---|---|---|
| Gitleaks | 8.30.1 | `gitleaks dir` — 2 findings on `demo-app/scenarios/insecure`, 0 on `demo-app/scenarios/clean` |
| Trivy | 0.75.0 | Image scan — `xprisk-vulnerable:demo` 651 findings, `xprisk-clean:demo` 283 |
| Checkov | 3.3.22 | `scenarios/insecure` 24 failed checks, `scenarios/clean` 8, `infrastructure/terraform` 53 |
| Docker | current | Both scenario images build; `python:3.6-slim` and `python:3.12-slim-bookworm` bases |

See [`demo-app/README.md`](demo-app/README.md),
[`infrastructure/terraform/README.md`](infrastructure/terraform/README.md),
[`demo-app/scenarios/README.md`](demo-app/scenarios/README.md) and
[`fixtures/README.md`](fixtures/README.md).

### Not yet verified

- **SonarQube.** The adapter has never been run against a live instance. It is an
  HTTP client, so the wrong-CLI-flag class of bug does not apply, but its
  severity handling is unconfirmed and probably needs its own policy the way
  Checkov's did.
- **PostgreSQL.** SQLite only. The schema and ORM are engine-agnostic and this is
  a `DATABASE_URL` change, but no live PostgreSQL run has been performed.
- **The HTTP API beyond one endpoint.** `POST /scan` exists and is tested, but
  `GET /risk/{id}`, `GET /explanation/{id}`, `GET /deployments` and
  `POST /risk/evaluate` do not, so a stored assessment cannot be read back over
  HTTP. The database is the only way to see one. The full pipeline is also
  exercised by the scripts in the root directory, which is what §17 demonstrates.

### Reproducing the risk model

```powershell
.\.venv\Scripts\python.exe -m pytest -p no:cacheprovider -q   # 384 tests, 7 xfailed
.\.venv\Scripts\python.exe run_integration_scenarios.py       # the six scenarios
.\.venv\Scripts\python.exe xprisk_comparative.py              # comparative study
```

`run_integration_scenarios.py` prints what the model **actually does** on each
scenario, including where the result contradicts the scenario name. Two rows
currently disagree with their expected decision; both trace to the additive
scoring limitation recorded in [`docs/risk-model.md`](docs/risk-model.md) §7.2,
where a single CRITICAL secret scores 29.3 and lands in SAFE.

### Known gaps

1. **A single CRITICAL finding scores SAFE** (score 29.3 in
   production/internet-facing). Purely additive scoring always values *n* medium
   findings above *one* critical. Documented, not patched — see
   [`docs/risk-model.md`](docs/risk-model.md) §7.2 for why steepening the curve
   cannot fix it and what the conventional repair would cost.
2. **Checkov reports no severity.** Every Terraform resource check has
   `severity: null`, so IaC severity is uninformative and count is the only
   discriminating signal. No severities were invented to paper over this — see
   §7.3.
3. **Saturation hides differences.** Large real scanner outputs (651 and 283
   findings) score 100.0 in every context, so the score carries no information
   for them — see §7.5.
4. **The dashboard reads the engine and database directly** rather than over
   HTTP, and runs assessments from `fixtures/`. `POST /scan` now exists, so an
   API client could replace this — but the dashboard was deliberately left
   engine-bound so the demo needs no server, no database and no Docker. Both
   paths call the same scoring function, and a test asserts they agree.
5. **A stored assessment cannot be read back over HTTP.** `POST /scan` writes a
   deployment, its findings and every contribution, but there is no
   `GET /deployments/{id}` or `GET /risk/{id}`. The database is currently the only
   reader, which means the read API is the natural next slice — the write side is
   done and tested.
6. **The `sonarqube/` fixtures are the only invented data left.** Every other
   fixture is genuine scanner output, regenerated by
   `tools/regenerate_fixtures.py` and `tools/regenerate_trivy_fixtures.py`.
   See [`fixtures/README.md`](fixtures/README.md) for the provenance table.
7. **~39 environment variables in `.env.example` are declared but not read.**
   Grouped and annotated in that file.
8. **Five pytest markers are declared but unapplied.** `pyproject.toml` registers
   `unit`, `integration`, `contract`, `fixture` and `slow`, and no test carries
   one, so `pytest -m unit` collects nothing. Reported as 7 `xfailed` rather than
   failures so the gap is visible without breaking the suite;
   `tests/test_pyproject_markers.py` holds the assertions that will flip to
   passing when the taxonomy is applied.

### Three defects found while verifying the run instructions

All three were found by executing the commands in this README rather than reading
them, and all three are now covered by tests.

- **Checkov silently dropped all 24 findings** when XPRisk was started without
  activating the virtual environment. Every command in this README uses
  `.\.venv\Scripts\python.exe`, which selects the interpreter but does *not*
  extend `PATH` — so the pip-installed `checkov` console script was
  unresolvable and the adapter reported `UNAVAILABLE`. The assessment still
  completed, just without a third of its findings and without an obvious error.
  `scanners.base._locate_executable` now also searches the running
  interpreter's own `Scripts` directory. Six tests cover it, including the
  inverse property: a native binary still inherits the environment untouched.
- **The documented backend command did not start.** §12 said to run
  `python -m uvicorn backend.app.main:app`, but `main.py` imported its settings
  with `from app.config import ...`, which resolves only when `backend/` is on
  `sys.path` — not what uvicorn sets up. It raised
  `ModuleNotFoundError: No module named 'app'` on the first line. The whole suite
  passed, because no test imported the module at all. Fixed, and
  `tests/test_backend_app.py` now imports it the way uvicorn does.
- **§17 documented four endpoints that do not exist.** `POST /scan`,
  `GET /risk/{id}`, `GET /explanation/{id}` and `POST /risk/evaluate` all returned
  404. A copy-paste of that section produced four errors. It now shows one
  working `POST /scan` request and states plainly that the other three do not
  exist.

### The fixtures are real scans

Most of what the dashboard displays is replayed from genuine scanner output:

| Fixture | Origin | Findings |
|---|---|---|
| `trivy/sample_image_scan.json` | Trivy 0.75.0 on `xprisk-vulnerable:demo` | 651 |
| `trivy/sample_image_scan_clean.json` | Trivy 0.75.0 on `xprisk-clean:demo` | 283 |
| `checkov/terraform_insecure.json` | Checkov 3.3.22, `scenarios/insecure` | 24 |
| `checkov/terraform_clean.json` | Checkov 3.3.22, `scenarios/clean` | 8 |
| `gitleaks/secrets_detected.json` | Gitleaks 8.30.1, redacted | 2 |
| `sonarqube/issues_sample.json` | hand-written; no live SonarQube run exists | 2 |

Two things that were wrong and are now corrected, because both would have been
caught by an examiner who ran the tools:

- The Trivy fixture used to contain invented CVE identifiers
  (`CVE-2023-12345`). It now holds a complete, untruncated real scan.
- The Checkov fixture used to declare `"severity": "HIGH"` on every check. Real
  Checkov emits `severity: null`, which is what §7.3 of the risk model documents.
  The fixture contradicted the documentation it was meant to illustrate.

The hardened scenarios are genuinely not clean, and the fixtures now say so: the
hardened image still carries 283 known advisories and the hardened Terraform
still fails 8 Checkov checks.

## 19. Security notes

This project is a security tool, so it holds itself to the constraints it
enforces on others:

- **No credentials in code.** Every secret is an environment variable. None are
  committed. `.env` is git-ignored.
- **No shell injection.** Tools run via `subprocess.run` with an explicit
  argument list and `shell=False`. No command string is ever built from user
  input.
  - **One documented exception.** On Windows, a pip-installed Python CLI is a
    `.cmd` batch shim, and `subprocess` with `shell=False` cannot execute one
    (`subprocess` does not consult `PATHEXT`; only `CreateProcess` appends
    `.exe`). Verified with checkov 3.3.22: `subprocess.run(["checkov", ...],
    shell=False)` raises `FileNotFoundError` even though the shim is on `PATH`.
    `scanners.base.resolve_executable()` therefore resolves such a shim and
    invokes it as `COMSPEC /d /c <shim> <args...>`. The lookup is `PATH` first,
    then the running interpreter's own `Scripts` directory, because a tool
    installed into the virtual environment is invisible unless it has been
    activated.
    - Real executables — `gitleaks.exe`, `trivy.exe` — are untouched and still
      run with `shell=False`.
    - Arguments are still passed as a list and are never concatenated into a
      command string. Only `cmd.exe` itself interprets them.
    - `/d` disables AutoRun script execution.
    - The shim's own directory is placed at the front of the child's `PATH`, and
      only for a resolved shim. A pip shim locates its interpreter by scanning
      `PATH`; without this it runs the system Python and fails with
      `ModuleNotFoundError`. The value comes from a resolved executable path, not
      from input, and a native binary inherits the environment unchanged
      (`scanners.base._shim_child_env`).
- **No `eval` or `exec`** anywhere in the project.
- **Untrusted scanner output.** Every scanner report is shape-validated before
  use, because a malformed report must not be able to crash the backend.
- **Parameterized database access only**, via the SQLAlchemy ORM.
- **No secret values stored or returned.** Secret *values* are redacted before
  a finding is persisted or returned; only a short masked preview is kept.
- **Logging excludes secrets.** Tokens, passwords and connection strings are
  never logged; the database URL is redacted before it appears in any log line.

## 20. Roadmap

### Completed ahead of plan

- [x] Comparative analysis: severity-only vs severity+count vs context-aware
      (`xprisk_comparative.py`, results in
      [`reports/comparative_study_results.json`](reports/comparative_study_results.json),
      analysis in [`docs/risk-model.md`](docs/risk-model.md) §9). Done early
      because Phase 9 made every constant injectable.

### Remaining

- [ ] Read-side API: `GET /deployments`, `GET /deployments/{id}`,
      `GET /risk/{id}`, `GET /explanation/{id}` (Phase 13). The write side is
      done — `POST /scan` persists a full assessment — so a stored result can
      only be read from the database today.
- [ ] Dashboard over HTTP with five views: overview, findings, risk analysis,
      explanations, trends (Phase 14). `POST /scan` now exists, so the write
      path is available; the dashboard is engine-bound on purpose (§18, gap 4).
- [ ] SonarQube against a live instance (closes the last unverified adapter)
- [ ] Live PostgreSQL run (currently SQLite only)
- [ ] GitHub Actions pipeline running the full scan chain (Phase 15). This is
      what would earn the "CI/CD" half of the title — `POST /scan` is now a
      single call a gate could make, which it previously had nothing to call.
- [ ] XPRisk as an enforced deployment gate: BLOCK stops the pipeline (Phase 16)
- [ ] Historical analytics: newly introduced vs resolved findings (Phase 17)
- [ ] Calibration study: fit the weights to labelled incident data rather than
      asserting them (Phase 19). This is what would turn the risk model from a
      documented heuristic into a validated metric — see
      [`docs/risk-model.md`](docs/risk-model.md) §8.
- [ ] A severity floor, so a single CRITICAL finding cannot score SAFE. Additive
      scoring structurally cannot fix this; the repair is a new component, not a
      new constant — see [`docs/risk-model.md`](docs/risk-model.md) §7.2.
- [ ] Performance measurement report (Phase 20)
- [ ] Containerize backend, dashboard and PostgreSQL (Phase 21)
- [ ] Cloud deployment (Phase 22)

---

**XPRisk** - Explainable Context-Aware Risk Assessment Framework for Secure
Cloud-Native CI/CD Pipelines. Licensed under the [MIT License](LICENSE).