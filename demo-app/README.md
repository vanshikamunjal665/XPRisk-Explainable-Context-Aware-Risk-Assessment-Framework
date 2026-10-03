# XPRisk Demo Application

This is the **scan target**. XPRisk scans this application and its
infrastructure; it is not part of the framework itself.

A small Flask service with a health endpoint and a few API endpoints, plus a
matching Docker image and a matching Terraform configuration. It exists so
that XPRisk has something realistic to assess, and so that every finding the
framework reports can be traced back to a known cause.

---

## ⚠️ Security warning

This application is **intentionally insecure**. It is a laboratory artefact for
a university major project.

- The Terraform in `../infrastructure/terraform/` is deliberately vulnerable.
- Phase 3 adds deliberately flawed application code and clearly-labelled fake
  secrets as controlled test cases.
- **Never deploy any part of this to a real environment.**
- **No real credentials exist anywhere in this repository.** Every
  credential-shaped value is an obvious placeholder such as `CHANGEME`, or the
  canonical AWS documentation example key `AKIAIOSFODNN7EXAMPLE`, which is not
  a valid key.

---

## Layout

```
demo-app/
├── app/
│   ├── __init__.py
│   ├── main.py               Application factory + entry point
│   ├── config.py             Settings from the environment (no credentials)
│   ├── api/
│   │   ├── __init__.py
│   │   ├── health.py         /health, /health/live, /health/ready
│   │   └── routes.py         /, /api/info, /api/greet, /api/calculate
│   ├── services/
│   │   ├── __init__.py
│   │   └── greeting.py       Pure business logic
│   └── requirements.txt
├── Dockerfile                 Hardened baseline image
├── .dockerignore
├── docker-compose.yml
└── README.md
```

The split mirrors the XPRisk backend's own layering: `api/` handles HTTP,
`services/` holds pure logic. It keeps the target application clean enough that
SonarQube has real code to analyse, and it means the deliberately flawed code
added in Phase 3 can live in a clearly separate module without contaminating
the baseline.

## Endpoints

| Method | Path | Purpose | Success |
|---|---|---|---|
| GET | `/` | Service banner and route index | 200 |
| GET | `/health` | Overall health, version, scenario, runtime | 200 |
| GET | `/health/live` | Liveness probe (dependency free) | 200 |
| GET | `/health/ready` | Readiness probe | 200 |
| GET | `/api/info` | Service metadata and active scenario | 200 |
| GET | `/api/greet/<name>` | Greeting endpoint | 200 |
| GET | `/api/calculate` | `?left=&right=&operation=add\|subtract\|multiply` | 200 |

Error responses are always JSON, never Flask's default HTML page, so a pipeline
or a scanner parsing the output receives predictable content:

| Condition | Status | `error` |
|---|---|---|
| Non-numeric operand | 400 | `invalid_operand` |
| Unsupported operation | 400 | `unsupported_operation` |
| Unknown route | 404 | `not_found` |
| Wrong HTTP method | 405 | `method_not_allowed` |
| Unhandled fault | 500 | `internal_server_error` (no stack trace leaked) |

## Running locally

```powershell
cd demo-app
pip install -r app\requirements.txt
python -m app.main
```

Then:

```powershell
curl.exe http://127.0.0.1:5000/health
curl.exe "http://127.0.0.1:5000/api/calculate?left=6&right=7&operation=multiply"
```

`python -m app.main` must be run from the `demo-app` directory so that `app` is
importable as a package.

## Running in Docker

```powershell
cd demo-app
docker build -t xprisk-demo-app:latest .
docker run --rm -p 5000:5000 xprisk-demo-app:latest
curl.exe http://127.0.0.1:5000/health
```

Or with Compose:

```powershell
docker compose up --build
curl.exe http://127.0.0.1:5000/health
docker compose down
```

The image runs as a non-root user, declares a `HEALTHCHECK` that uses the
bundled interpreter (so no `curl` is installed just to support a probe), and
Compose adds `read_only`, `no-new-privileges` and log rotation.

## Configuration

All settings are environment variables with safe defaults, so the app starts
with no configuration at all.

| Variable | Default | Purpose |
|---|---|---|
| `DEMO_HOST` | `0.0.0.0` | Bind address |
| `DEMO_PORT` | `5000` | Listen port |
| `DEMO_ENVIRONMENT` | `development` | Environment name reported by `/health` |
| `DEMO_SCENARIO` | `clean` | Active code scenario |
| `DEMO_LOG_LEVEL` | `INFO` | Logging level |
| `DEMO_DEBUG` | `false` | Flask debug mode |
| `DEMO_REQUIRE_API_TOKEN` | `false` | Whether protected routes need a token |

An unrecognised `DEMO_SCENARIO` falls back to `clean` rather than crashing, so
a typo in a deployment manifest cannot take the service down.

## Relationship to XPRisk

| XPRisk phase | What this provides |
|---|---|
| 2 | A running, containerised application to scan |
| 3 | Controlled, attributable security issues (see Phase 3 docs) |
| 4 | A real image for Trivy, real code for SonarQube, real IaC for Checkov |

The scenario switch is what makes integration TEST 1 possible: the same
application, in `clean` mode, must produce zero findings and a SAFE decision,
and in `vulnerable` mode must produce findings that XPRisk can attribute.