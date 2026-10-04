# Phase 3 — Controlled Security Test Cases

XPRisk Phase 3 adds a controlled, isolated, deterministic set of intentional
security findings. Each fixture maps to exactly one intended scanner. The
scanner integration that will consume them is Phase 4 and has **not** been
implemented.

> These are intentionally vulnerable fixtures for controlled security testing.
> All secrets are fake and labelled. No real credentials are used anywhere.
> Terraform/IaC fixtures must never be applied.

## Test matrix

| Test Case | Scanner | Fixture | Intentional Issue | Expected Purpose | Clean Counterpart |
|---|---|---|---|---|---|
| Fake secret | Gitleaks | `demo-app/scenarios/insecure/secrets/fake_secrets.env` | Obviously fake `ghp_TEST_ONLY_...` token, AWS documentation example key, fake DB password | Secret detection | `demo-app/scenarios/clean/secrets/no_secrets.env` (empty values) |
| Vulnerable container | Trivy | `demo-app/scenarios/insecure/Dockerfile.vulnerable` | End-of-life `python:3.6.15-slim-stretch` base → many CRITICAL/HIGH CVEs | Container vulnerability detection | `demo-app/scenarios/clean/Dockerfile.clean` (`python:3.12-slim-bookworm`) |
| Insecure IaC | Checkov | `infrastructure/scenarios/insecure/main.tf` | Public S3 ACL, no encryption/versioning, SSH + all-ports open to `0.0.0.0/0`, wildcard IAM | IaC security detection | `infrastructure/scenarios/clean/main.tf` (encryption, versioning, public-access block, scoped IAM, HTTPS-only ingress) |
| Insecure code | SonarQube | `demo-app/scenarios/insecure/code/insecure_code.py` | Hard-coded password, `eval`, `os.system`, `shell`-style command building, SQL string concatenation, weak PRNG, hard-coded IP, complexity | Static code security/quality analysis | `demo-app/scenarios/clean/code/secure_code.py` |

## Expected Checkov check IDs (insecure fixture)

- CKV_AWS_19 (S3 encryption), CKV_AWS_20 (public ACL), CKV_AWS_21
  (versioning), CKV_AWS_144 (public access block), CKV_AWS_18 (logging)
- CKV_AWS_24 (SSH from 0.0.0.0/0), CKV_AWS_23 (all ports from 0.0.0.0/0)
- CKV_AWS_286 (wildcard actions), CKV_AWS_355 (wildcard resource)

## Expected SonarQube rule families (insecure fixture)

- S2068 hard-coded credentials, S2076 command injection, S2083 path traversal,
  S1523 eval, S2245 weak PRNG, S1313 hard-coded IP, S3776 complexity,
  SQL-injection concatenation pattern.

## Expected Gitleaks detections (insecure fixture)

- `TEST_SECRET_ONLY=ghp_TEST_ONLY_NOT_A_REAL_TOKEN_1234567890` — shaped like
  a GitHub PAT; deterministic test-only value.
- `AKIAIOSFODNN7EXAMPLE` — AWS documentation example key (not a real key).

## Expected Trivy detections (insecure fixture)

Numerous OS/Python package CVEs for Debian stretch / Python 3.6-era layers.
The clean counterpart pins a maintained slim base to reduce findings.

## Scope boundaries

- No scanner is installed or configured in this phase.
- No vulnerability was added to the running demo application or the XPRisk
  backend; all fixtures are isolated under `demo-app/scenarios/` and
  `infrastructure/scenarios/`.
- The pre-existing intentionally insecure Terraform under
  `infrastructure/terraform/` is unchanged.
