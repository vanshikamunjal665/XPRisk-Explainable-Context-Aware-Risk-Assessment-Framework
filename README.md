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
  `explainability/`) **never import FastAPI, SQLAlchemy or Streamlit.**
- Consequences: the risk model is testable without a server or a database; the
  dashboard is a pure HTTP client and can be deployed independently; the
  scanners can be replaced without touching the risk engine.

Two further separations are deliberate, and both are specified explicitly:

| Separation | Why |
|---|---|
| `scanner_service` (execution) vs `normalization_service` (translation) | Parser logic is unit testable without running any security tool. A scanner bug cannot corrupt the risk model. |
| `schemas/` (Pydantic) vs `models/` (SQLAlchemy) | The API contract cannot be changed silently by a database migration. |

## 5. Workflow

1. A deployment is requested: a commit, a branch, an environment, an exposure
   flag.
2. `scanner_service` triggers the enabled scanners and records a status per
   tool (`SUCCESS`, `FAILED`, `UNAVAILABLE`, `SKIPPED`) plus a duration. **One
   failing tool never fails the scan.**
3. `normalization_service` converts each tool's native JSON into canonical
   `NormalizedFinding` objects, preserving tool-specific fields under
   `metadata`.
4. `storage_service` persists the `Deployment` and its `Finding` rows.
5. `risk_engine` computes per-finding risk, aggregates it, normalizes to 0-100
   through a piecewise-linear curve, applies a bounded context uplift, and maps
   the result through configurable thresholds.
6. Every individual contribution is persisted to `risk_factors`, which is what
   makes historical explanations reproducible.
7. `explainability` ranks the stored contributions into a human-readable
   rationale and actionable remediation.
8. FastAPI serves the result; Streamlit renders it.

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
│   │   ├── cli.py                Headless entry point (assess / gate)
│   │   ├── api/                  HTTP routers
│   │   │   ├── scans.py          POST /scan
│   │   │   ├── findings.py       GET /findings, /findings/{deployment_id}
│   │   │   ├── risk.py           GET /risk/{id}, POST /risk/evaluate
│   │   │   ├── deployments.py    GET /deployments, /deployments/{id}
│   │   │   ├── explanations.py   GET /explanation/{id}
│   │   │   └── trends.py         GET /trends
│   │   ├── models/               SQLAlchemy ORM models
│   │   │   ├── deployment.py
│   │   │   ├── finding.py
│   │   │   └── risk.py
│   │   ├── schemas/              Pydantic request/response models
│   │   ├── services/             Orchestration layer
│   │   │   ├── scanner_service.py
│   │   │   ├── normalization_service.py
│   │   │   ├── storage_service.py
│   │   │   ├── risk_service.py
│   │   │   ├── explanation_service.py
│   │   │   └── scan_service.py
│   │   └── database/
│   │       ├── database.py       Engine, session factory
│   │       └── init_db.py        Idempotent schema creation
│   └── requirements.txt
├── scanners/                     Thin adapters, one per security tool
│   ├── base.py                   ScannerResult, ScannerStatus, safe runner
│   ├── gitleaks_scanner.py
│   ├── trivy_scanner.py
│   ├── checkov_scanner.py
│   └── sonarqube_scanner.py
├── normalizer/
│   ├── models.py                 Canonical NormalizedFinding schema
│   └── normalizer.py             Per-tool parsers + severity mapping
├── risk_engine/                  Research core
│   ├── settings.py               All configurable defaults
│   ├── severity.py               Severity + base weights
│   ├── context.py                Context model
│   ├── scoring.py                Scoring algorithm
│   ├── thresholds.py             SAFE / WARNING / BLOCK
│   ├── strategies.py             Pluggable aggregation (comparative study)
│   └── engine.py                 Deterministic orchestration
├── explainability/
│   ├── contributors.py           Rank real contributions
│   ├── explanation.py            Structured explanation payload
│   └── recommendation.py         Actionable remediation
├── dashboard/
│   ├── app.py                    Entry point
│   ├── api_client.py             HTTP client for the backend only
│   ├── components/               Reusable render helpers
│   └── pages/
│       ├── overview.py
│       ├── findings.py
│       ├── risk_analysis.py
│       ├── explanations.py
│       └── trends.py
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

In a **second** terminal:

```powershell
.\.venv\Scripts\Activate.ps1
streamlit run dashboard/app.py
```

Open <http://127.0.0.1:8501>. The dashboard is a pure HTTP client: it reads
everything from the backend API and holds no data of its own, so no dashboard
value is ever hardcoded. Point it at a different backend with
`DASHBOARD_API_URL`.

## 14. Running the scanners

XPRisk drives the scanners itself. You do not need to run them by hand.

**Verify each tool is visible to XPRisk:**

```powershell
trivy --version
checkov --version
gitleaks version
```

**A tool that is not installed is not a crash.** It is reported as
`UNAVAILABLE` with a captured error, and the remaining tools still contribute
to the assessment. Every scanner adapter also supports Docker execution, which
is the fallback when a host install is not possible.

SonarQube configuration (never hardcode a token):

```powershell
# .env
SONARQUBE_URL=http://localhost:9000
SONARQUBE_PROJECT_KEY=xprisk-demo-app
SONARQUBE_TOKEN=<generated from SonarQube: My Account -> Security -> Generate Token>
```

## 15. Running the tests

```powershell
.\.venv\Scripts\Activate.ps1

pytest                      # everything
pytest -m unit              # fast, isolated tests only
pytest -m integration       # multi-component scenarios
pytest --cov                # with coverage
pytest tests/test_risk_engine.py -v
```

The suite runs against an isolated temporary database and uses labelled
fixture data, so it passes **without** PostgreSQL, Docker or any security tool
installed.

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

Once a release is ready to be assessed:

```powershell
# 1. Assess a commit for production, internet-facing
curl.exe -X POST http://127.0.0.1:8000/scan `
  -H "Content-Type: application/json" `
  -d '{
        "target_path": "./demo-app",
        "commit_id": "a1b2c3d4",
        "branch": "main",
        "environment": "production",
        "internet_exposed": true
      }'

# 2. Read the score and decision
curl.exe http://127.0.0.1:8000/risk/1

# 3. Read why
curl.exe http://127.0.0.1:8000/explanation/1

# 4. Score hypothetical findings without running any scanner
curl.exe -X POST http://127.0.0.1:8000/risk/evaluate `
  -H "Content-Type: application/json" `
  -d '{
        "context": {"environment": "development", "internet_exposed": false},
        "findings": [
          {"tool": "TRIVY", "category": "CONTAINER", "severity": "MEDIUM",
           "finding_id": "CVE-2024-0001", "resource": "openssl",
           "description": "Example finding"}
        ]
      }'
```

The same finding assessed in `development` and in `production` yields different
scores. That difference is the evidence for the context-aware design, and it is
covered by integration tests TEST 4 and TEST 5.

## 18. Project status

Current delivery: **Phases 1-8** of the planned 1-14.

| Phase | Component | Status |
|---|---|---|
| 1 | Development environment, structure, configuration | Complete |
| 2 | Demo cloud-native application | Complete |
| 3 | Controlled security test cases | Complete |
| 4 | Trivy, Checkov, Gitleaks, SonarQube integration | Complete |
| 5 | Finding collector | Complete |
| 6 | Finding normalization | Complete |
| 7 | PostgreSQL storage | Complete (SQLite verified; live PostgreSQL not yet run) |
| 8 | Context model | Complete |
| 9 | Risk-scoring algorithm | Next |
| 10 | Risk engine | Planned |
| 11 | SAFE / WARNING / BLOCK | Planned |
| 12 | Explainability engine | Planned |
| 13 | FastAPI backend | Planned (`/health` only) |
| 14 | Streamlit dashboard | Planned |
| 15 | GitHub Actions CI/CD | Reference stub, inert |
| 16-23 | Gate, historical analytics, comparative study, performance, Docker, cloud, polish | Planned |

Verified so far: the demo application starts and serves all seven endpoints
with `200`, every error path returns structured JSON (400 / 404 / 405 / 500),
`terraform validate` passes, and the Gitleaks path has been confirmed end to
end against a **real** `gitleaks dir` run (8.30.1) — 2 findings on the
insecure scenario, 0 on the clean one. See
[`demo-app/README.md`](demo-app/README.md),
[`infrastructure/terraform/README.md`](infrastructure/terraform/README.md),
[`demo-app/scenarios/README.md`](demo-app/scenarios/README.md) and
[`fixtures/README.md`](fixtures/README.md).

Known gaps carried into Phase 9: `backend/app/config.py` does not exist yet
(settings are read ad hoc via `os.environ`), and the Trivy adapter implements
`scan_image` only even though `.env.example` declares a filesystem target type.

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
    `scanners.base.resolve_executable()` therefore resolves such a shim with
    `shutil.which` and invokes it as `COMSPEC /d /c <shim> <args...>`.
    - Real executables — `gitleaks.exe`, `trivy.exe` — are untouched and still
      run with `shell=False`.
    - Arguments are still passed as a list and are never concatenated into a
      command string. Only `cmd.exe` itself interprets them.
    - `/d` disables AutoRun script execution.
- **No `eval` or `exec`** anywhere in the project.
- **Untrusted scanner output.** Every scanner report is shape-validated before
  use, because a malformed report must not be able to crash the backend.
- **Parameterized database access only**, via the SQLAlchemy ORM.
- **No secret values stored or returned.** Secret *values* are redacted before
  a finding is persisted or returned; only a short masked preview is kept.
- **Logging excludes secrets.** Tokens, passwords and connection strings are
  never logged; the database URL is redacted before it appears in any log line.

## 20. Roadmap

- [ ] GitHub Actions pipeline running the full scan chain (Phase 15)
- [ ] XPRisk as an enforced deployment gate: BLOCK stops the pipeline (Phase 16)
- [ ] Historical analytics: newly introduced vs resolved findings (Phase 17)
- [ ] Comparative study report: severity-only vs severity+count vs context-aware (Phase 19)
- [ ] Performance measurement report (Phase 20)
- [ ] Containerize backend, dashboard and PostgreSQL (Phase 21)
- [ ] Cloud deployment (Phase 22)

---

**XPRisk** - Explainable Context-Aware Risk Assessment Framework for Secure
Cloud-Native CI/CD Pipelines. Licensed under the [MIT License](LICENSE).