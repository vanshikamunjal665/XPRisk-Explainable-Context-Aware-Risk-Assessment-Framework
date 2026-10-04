# XPRisk Phase 3 — Controlled Scenario Fixtures

These fixtures are the **intentional security-test cases** created in Phase 3.
They exist so that Trivy, Checkov, Gitleaks and SonarQube each have a clear,
deterministic, isolated target in Phase 4.

> ⚠️ All values are fake. Every "secret" is obviously a test-only placeholder.
> No real credentials appear anywhere in this tree.
> The Terraform fixtures under `infrastructure/scenarios/` must **never** be
> applied. Nothing in this directory is imported by the demo application or
> the XPRisk backend.

## Layout

```
demo-app/scenarios/
├── README.md                       (this file)
├── insecure/
│   ├── secrets/fake_secrets.env    Gitleaks target: fake, marked credentials
│   ├── Dockerfile.vulnerable       Trivy target: EOL base image, many CVEs
│   └── code/insecure_code.py       SonarQube target: insecure code patterns
└── clean/
    ├── secrets/no_secrets.env      Gitleaks clean counterpart (no secrets)
    ├── Dockerfile.clean            Trivy clean counterpart (maintained base)
    └── code/secure_code.py         SonarQube clean counterpart

infrastructure/scenarios/
├── insecure/main.tf                Checkov target: insecure AWS IaC
└── clean/main.tf                   Checkov clean counterpart (hardened)
```

## Rules

1. Each vulnerable fixture has a structurally comparable `clean` counterpart
   so a later run can show `insecure → controlled findings` vs
   `clean → no intentional findings`.
2. Fixtures are static-analysis targets. Do not build the vulnerable image,
   do not run its code, do not `terraform apply` anything.
3. Scanner integration (Trivy/Checkov/Gitleaks/SonarQube) is Phase 4 and is
   intentionally absent from this phase.

## Verified Gitleaks results

Confirmed with a real `gitleaks dir` run (Gitleaks 8.30.1) using
`fixtures/gitleaks/gitleaks.toml`:

| Target | Findings |
|---|---|
| `insecure/secrets/fake_secrets.env` | `xprisk-test-secret` (L33 → HIGH), `private-key` (L40 → CRITICAL) |
| `clean/secrets/no_secrets.env` | none |

```powershell
gitleaks dir demo-app/scenarios/insecure --config fixtures/gitleaks/gitleaks.toml --report-format json --report-path gl.json --redact
gitleaks dir demo-app/scenarios/clean     --config fixtures/gitleaks/gitleaks.toml --report-format json --report-path gl.json --redact
```

Two things that surprise people reading the insecure fixture:

- The three shape-recognisable values at the top (`ghp_…`, `AKIA…`, `xoxb-…`)
  are **not** flagged. Upstream Gitleaks rules are tuned against real
  credentials and reject obvious placeholders. That is precisely why
  `fixtures/gitleaks/gitleaks.toml` adds the `xprisk-test-secret` rule.
- Three `XPRISK_TEST_*` assignments exist but yield **one** finding, because
  Gitleaks reports only the first match per rule per file.

See [`fixtures/README.md`](../../fixtures/README.md) for the full probe table
and the three Gitleaks behaviours that are easy to get wrong.

## Verified Trivy results

Both images build, and both were scanned with a real `trivy image` run
(Trivy 0.75.0, Docker Desktop 29.2.0):

| Image | Base | Findings | CRITICAL | HIGH |
|---|---|---|---|---|
| `xprisk-vulnerable:demo` | `python:3.6-slim` (Debian 11.2) | 651 | 31 | 174 |
| `xprisk-clean:demo` | `python:3.12-slim-bookworm` (Debian 12.15) | 283 | 5 | 58 |

That roughly 6x CRITICAL and 3x HIGH gap is the container half of the
controlled comparison in integration TEST 4.

```powershell
docker build -t xprisk-vulnerable:demo -f demo-app/scenarios/insecure/Dockerfile.vulnerable demo-app/scenarios/insecure
docker build -t xprisk-clean:demo      -f demo-app/scenarios/clean/Dockerfile.clean       demo-app/scenarios/clean

# On Windows, use scan_local_image(), not a bare `trivy image <tag>`:
#   docker save -o image.tar xprisk-vulnerable:demo
#   trivy image --input image.tar --format json --quiet
```

### Scan local images with `TrivyScanner.scan_local_image()`

`trivy image <local-tag>` **cannot work on Windows**. Trivy times out on the
`dockerDesktopLinuxEngine` named pipe, then falls back to the remote registry
and tries to pull your local tag from Docker Hub:

```
docker error: unable to inspect the image (...): context deadline exceeded
remote error: GET https://index.docker.io/v2/library/xprisk-vulnerable/manifests/demo:
  UNAUTHORIZED: authentication required
```

`scan_local_image()` exports the image with `docker save` and scans the
tarball via `trivy image --input`, which removes the socket dependency. It
also rewrites Trivy's reported target, because `--input` makes Trivy echo the
tarball path — a random temp path that would otherwise change every run and
make finding ids non-deterministic.

## Why committing this `secrets/` directory is safe

An earlier `.gitignore` rule of `secrets/` silently excluded
`demo-app/scenarios/*/secrets/`, so these files were never committed and the
Gitleaks integration was left with a documented scan target that did not exist.
The rule is now anchored (`/secrets/`, `/backend/secrets/`, …), so nothing under
`demo-app/scenarios/*/secrets/` is ignored. Every value in it is fake, and
Gitleaks runs with `--redact` so matched values are never written to reports.
