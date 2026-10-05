# XPRisk Test Fixtures — READ THIS FIRST

This directory holds JSON files that stand in for security tool output, so the
XPRisk test suite and dashboard can run on a machine where Trivy, Checkov,
Gitleaks or SonarQube are not installed.

## Provenance, file by file

Most of these files used to be hand-written, which made them a liability rather
than a convenience: they carried invented CVE identifiers and a
`"severity": "HIGH"` on Checkov checks that real Checkov never emits. Every file
below now states where it came from, and the `_xprisk_fixture` marker inside
each JSON records it in machine-readable form.

| File | Origin | Findings |
|---|---|---|
| `trivy/sample_image_scan.json` | **Real scan**, Trivy 0.75.0 on `xprisk-vulnerable:demo` | 651 |
| `trivy/sample_image_scan_clean.json` | **Real scan**, Trivy 0.75.0 on `xprisk-clean:demo` | 283 |
| `checkov/terraform_insecure.json` | **Real scan**, Checkov 3.3.22 on `infrastructure/scenarios/insecure` | 24 |
| `checkov/terraform_clean.json` | **Real scan**, Checkov 3.3.22 on `infrastructure/scenarios/clean` | 8 |
| `gitleaks/secrets_detected.json` | **Real run**, Gitleaks 8.30.1, secrets redacted | 2 |
| `gitleaks/secrets_clean.json` | **Real run**, Gitleaks 8.30.1 | 0 |
| `sonarqube/issues_sample.json` | **Hand-written.** No live SonarQube instance has ever been scanned. | 2 |
| `sonarqube/issues_clean.json` | **Hand-written**, same reason | 0 |
| `gitleaks/gitleaks.toml` | Not fixture data. Real configuration, used by real Gitleaks runs. | — |

Two consequences worth being explicit about:

- **The hardened scenarios are not zero-finding.** `xprisk-clean:demo` still has
  283 known advisories and the hardened Terraform still fails 8 Checkov checks.
  The old fixtures claimed zero for both, which flattered the demo. Scores built
  on the old data were wrong.
- **SonarQube is the remaining fiction.** Its fixtures model the documented
  `api/issues/search` response shape, but no live instance has been scanned, so
  they prove the parser works, not that the adapter does. `tests/` and
  `dashboard/service.py` both exclude SonarQube from any preset.

## Regenerating from a real run

Both scripts read genuine tool output and reduce it to the fields the adapter
actually reads. They never truncate a finding set: size is controlled by
dropping unread fields, not by sampling, because sampling is what made the
original files misleading.

```powershell
# Checkov
.\.venv\Scripts\checkov.cmd -d infrastructure/scenarios/insecure -o json --framework terraform --quiet > raw-ckv.json
.\.venv\Scripts\python.exe tools\regenerate_fixtures.py raw-ckv.json fixtures/checkov/terraform_insecure.json

# Trivy
docker save -o vuln.tar xprisk-vulnerable:demo
trivy image --input vuln.tar --format json -o raw-trivy.json
.\.venv\Scripts\python.exe tools\regenerate_trivy_fixtures.py raw-trivy.json fixtures/trivy/sample_image_scan.json
```

Fields dropped and why:

| Dropped | Reason |
|---|---|
| Trivy `References`, `CVSS`, `Layer`, dates | No adapter reads them. Cuts 3.0 MB to 623 kB with all 651 findings kept. |
| Checkov `evaluation_details` | No adapter reads it. Cuts the report by three quarters. |
| Checkov `file_abs_path` | An absolute path into the machine that ran the scan. Keeping it would commit a developer's home directory. |

PowerShell's `>` writes UTF-16, so both scripts detect the BOM and decode
accordingly.

## The one rule

> **Fixture replay must never be reported as a live scan.**

Every finding produced from a fixture is tagged in its metadata:

```json
"metadata": {
  "xprisk": {
    "data_origin": "FIXTURE",
    "fixture_path": "fixtures/trivy/sample_image_scan.json"
  }
}
```

Real scanner output is tagged `"data_origin": "REAL"`. The distinction is
asserted in the test suite, recorded in the database, and printed by the
dashboard alongside each scenario, so a fixture-derived assessment can always be
identified after the fact.

Note that the two are orthogonal and both matter: a file can hold genuine scanner
output (as nearly every file here now does) and still be replayed rather than
scanned live, in which case `data_origin` is `FIXTURE`. The file being real and
the run being real are different claims.

## Directory layout

| Directory | Stands in for | Contents |
|---|---|---|
| `trivy/` | `trivy image --format json` | Two real image scans, vulnerable and hardened |
| `checkov/` | `checkov -o json` | Two real Terraform scans, vulnerable and hardened |
| `gitleaks/` | `gitleaks --report-format json` | Real secret findings, plus `gitleaks.toml`, the extended rule set |
| `sonarqube/` | SonarQube Web API responses | `api/issues/search`, `api/components/show`, `api/ce/activity` |

## Naming convention

```
<scenario>[-<variant>].json
```

Examples: `sample_image_scan.json`, `sample_image_scan_clean.json`,
`terraform_insecure.json`, `terraform_clean.json`, `secrets_detected.json`,
`secrets_clean.json`.

The `_clean` suffix marks the *hardened* scenario, not a no-findings one. The
one genuinely empty result is `secrets_clean.json`, which integration TEST 1 uses
for its no-findings -> SAFE case.

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

`fixtures/gitleaks/secrets_detected.json` is real Gitleaks output with the
matched values redacted.

## Three tool behaviours the real fixtures made visible

Rewriting the fixtures from genuine runs surfaced facts that invented data had
hidden. All three are now asserted in `tests/test_scanners.py`:

1. **Checkov reports no severity.** Every Terraform resource check in the real
   output carries `"severity": null`, so XPRisk's documented MEDIUM fallback is
   what runs in production, not only in tests. See `docs/risk-model.md` §7.3.
2. **Checkov 3.3.22 has no nested `check` object.** The human-readable title
   arrives in a flat `check_name` field. Without that field every IaC finding
   would normalize with an empty description.
3. **Not every Trivy advisory is a CVE.** The vulnerable image contains 637 CVE
   identifiers plus Debian's own `DLA-nnnn-n` patches, one `DSA-nnnn-n`
   announcement, and six `TEMP-...` placeholders for advisories still awaiting an
   identifier. Only upstream advisories carry a `PrimaryURL`.