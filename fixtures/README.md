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
fake, clearly labelled test secrets (see `demo-app/scenarios/*/secrets/`).

It exists because Gitleaks is entropy and pattern driven, and upstream rules are
tuned to avoid false positives on real credentials. Probed against **Gitleaks
8.30.1**, the upstream default rule set does *not* flag obviously fake values:

| Value | Upstream verdict |
|---|---|
| `ghp_` + 36 chars (GitHub classic PAT) | not flagged |
| `AKIA` + 19 chars (AWS access key id) | not flagged |
| `xoxb-…` (Slack bot token) | not flagged |
| `AKIAIOSFODNN7EXAMPLE` (AWS doc example) | not flagged |
| `-----BEGIN RSA PRIVATE KEY-----` | **flagged** (`private-key`) |
| `glpat-…` (GitLab PAT) | **flagged** (`gitlab-pat`) |

So a readable placeholder such as `XPRISK_TEST_SECRET=demo-only-not-a-real-secret`
would produce **zero** findings. The scanner would look like it worked while
detecting nothing — the worst failure mode for an evaluation demo. The added
rule `xprisk-test-secret` makes detection deterministic while every matched
value stays obviously fake.

### Verified behaviour

Confirmed with a real `gitleaks dir` run (8.30.1):

| Target | Result |
|---|---|
| `demo-app/scenarios/insecure` | 2 findings — `xprisk-test-secret` (L33, HIGH), `private-key` (L40, CRITICAL) |
| `demo-app/scenarios/clean` | 0 findings |

Reproduce with:

```powershell
gitleaks dir demo-app/scenarios/insecure --config fixtures/gitleaks/gitleaks.toml --report-format json --report-path gl.json --redact
gitleaks dir demo-app/scenarios/clean     --config fixtures/gitleaks/gitleaks.toml --report-format json --report-path gl.json --redact
```

Three tool behaviours worth knowing before you interpret a scan, all confirmed
empirically rather than assumed:

1. **`[extend] useDefault = true` is required.** The bare top-level
   `useDefault = true` form is accepted by Gitleaks 8.19+ but does **not** merge
   the default rule set — it silently replaces it. The scan still exits 0 and
   still writes a report; only the finding count reveals the problem
   (2 findings vs 1).
2. **Only the first match per rule per file is reported.** The insecure fixture
   contains three `XPRISK_TEST_*` assignments and one PEM block, and yields
   exactly two findings.
3. **The separator class in the custom regex is `[ \t]`, not `\s`.** Gitleaks
   matches against multi-line content and `\s` also matches `\n`, so
   `\s*=\s*\S+` made the *empty* `XPRISK_TEST_SECRET=` in the clean fixture
   match the following line, producing a false positive.

`fixtures/gitleaks/secrets_detected.json` remains a fixture, but its structure
was regenerated from the verified run above (secrets redacted). The `.toml` is
real configuration used by real Gitleaks runs.