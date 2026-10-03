# XPRisk Test Fixtures — READ THIS FIRST

This directory contains **fixture data**: hand-written or captured JSON files
that stand in for real security tool output so that the XPRisk test suite can
run on a machine where Trivy, Checkov, Gitleaks or SonarQube are not
installed.

## The one rule

> **Fixture output must never be presented as real scanner output.**

Every finding produced from a fixture is tagged in its metadata:

```json
"metadata": {
  "xprisk": {
    "data_origin": "FIXTURE",
    "fixture_path": "fixtures/trivy/sample_image_scan.json",
    "fixture_scenario": "critical-and-high-container-vulnerabilities"
  }
}
```

Real scanner output is tagged `"data_origin": "REAL"`. The distinction is
asserted in the test suite, surfaced through `GET /scan`, and recorded in the
database, so a fixture-derived assessment can always be identified after the
fact. A university evaluation must be able to trust that a reported score came
from a real scan.

## Directory layout

| Directory | Stands in for | Contents |
|---|---|---|
| `trivy/` | `trivy image --format json` | Image, filesystem and repository scan shapes |
| `checkov/` | `checkov -f json` | Terraform and Dockerfile scan shapes, including an empty-result report |
| `gitleaks/` | `gitleaks --report-format json` | Secret findings, plus `gitleaks.toml`, the extended rule set |
| `sonarqube/` | SonarQube Web API responses | `api/issues/search`, `api/components/show`, `api/ce/activity` |

## Fixtures are shaped from real schemas, not invented

Each fixture was modelled on the documented output schema of the tool it
stands in for, so that the parser exercised in tests is the same parser used
against live output. When a fixture disagrees with real tool output, **the
fixture is wrong** and must be corrected — not the parser. This is why
fixture-driven development is acceptable here: it tests the real code path, not
a mock of it.

## Naming convention

```
<scenario>[-<variant>].json
```

Examples: `sample_image_scan.json`, `sample_image_scan_clean.json`,
`terraform_insecure.json`, `terraform_clean.json`, `secrets_detected.json`,
`secrets_clean.json`.

The `_clean` suffix marks the no-findings scenario required by integration
TEST 1 (no findings -> low risk -> SAFE).

## `gitleaks/gitleaks.toml`

This is **not** a fixture. It is a real Gitleaks configuration that *extends*
the upstream rule set with one additional regex matching XPRisk's deliberately
fake, clearly labelled test secrets (see `demo-app/`).

It exists because Gitleaks is entropy and pattern driven: a readable string
such as `TEST_SECRET_ONLY` would **not** match any upstream rule, so the
controlled test case would silently produce zero findings. The added rule makes
detection deterministic while the matched value remains obviously not a real
credential.

`fixtures/gitleaks/secrets_detected.json` remains a fixture; the `.toml` is
real configuration used by real Gitleaks runs.