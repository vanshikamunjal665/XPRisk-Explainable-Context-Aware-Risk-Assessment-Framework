# Docker assets for XPRisk

Dockerfiles and helper scripts for containerising the framework itself live
here. Phase 21 of the project plan ("Dockerize XPRisk") is **not** part of the
current 40–50% scope, so this directory is intentionally empty apart from this
placeholder.

| Planned file | Purpose |
|---|---|
| `Dockerfile.backend` | Production image for the FastAPI backend |
| `Dockerfile.dashboard` | Production image for the Streamlit dashboard |
| `Dockerfile.scanners` | Image bundling Trivy, Checkov and Gitleaks so a scan needs no host install |
| `scanner-entrypoint.sh` | Thin wrapper used when scanners run as containers |

## What is already containerised in the current scope

The **demo application** is containerised in this phase, because Milestone 1
("demo application runs") requires it. That lives in `demo-app/Dockerfile` and
`demo-app/docker-compose.yml`, not here.

## Running a scanner in Docker without a host install

Every scanner adapter also supports Docker execution, which is how the
framework remains usable on a machine where the tools are not installed. The
adapter runs an explicit argument list, never a shell string:

```powershell
docker run --rm `
  -v "${PWD}:/work" `
  zricethezav/gitleaks:latest `
  detect --no-git --source /work --report-format json --report-path /work/reports/gitleaks.json
```

The equivalent images are `aquasec/trivy` for Trivy and
`bridgecrew/checkov` for Checkov. Exact invocations are defined per adapter in
`scanners/`, not constructed from user input.