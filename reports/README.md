# Generated Reports

This directory holds **generated** output and is git-ignored (see `.gitignore`),
with the exception of this file and `.gitkeep`.

| File | Produced by | Notes |
|---|---|---|
| `gitleaks-report.json` | Gitleaks | Native Gitleaks JSON, unmodified |
| `trivy-report.json` | Trivy | Native Trivy JSON, unmodified |
| `checkov-report.json` | Checkov | Native Checkov JSON, unmodified |
| `sonar-report.json` | XPRisk SonarQube client | Raw API response, unmodified |
| `scan-<deployment_id>.json` | XPRisk | Full scan record: status, timings, normalized findings, contributions |
| `performance.json` | XPRisk | Phase 15+ scanner and stage timings |
| `comparative_study_results.json` | `xprisk_comparative.py` | Phase 9. **Committed** — see below |

## `comparative_study_results.json` is committed

This file is the exception to the rule below, and deliberately so.

It holds the Phase 9 comparative study: the same finding sets scored under
three policies (severity-only, severity + category, context-aware) across four
deployment contexts. It is small, fully deterministic, contains no paths or
digests, and it is **evidence for a claim made in `docs/risk-model.md` §9**.

That last point is why it is tracked. Methodology Step 4 requires a comparative
analysis, and an analysis whose numbers cannot be checked is an assertion rather
than a result. Anyone can re-run `xprisk_comparative.py` and diff the output
against the committed file to confirm the model behaves as documented.

Regenerate with:

```powershell
.\.venv\Scripts\python.exe xprisk_comparative.py
```

## Why the other files are not committed

1. **Size.** A Trivy JSON report is routinely tens of megabytes. Committing one
   per scan would make the repository unusable within a few runs.
2. **Environment specificity.** Reports record absolute paths, image digests and
   vulnerability-database versions that are specific to one machine.
3. **Secret fragments.** Even with redaction enabled, a Gitleaks report is
   derived from matched secret material. It does not belong in version control
   under any circumstances.

Raw scanner output is preserved rather than discarded because the
normalization layer is designed to be lossless: a report kept on disk can be
re-normalized later under an improved mapping without re-running any scan.

## Reproducing a scan

```powershell
curl.exe -X POST http://127.0.0.1:8000/scan `
  -H "Content-Type: application/json" `
  -d '{"target_path": "./demo-app", "environment": "production", "internet_exposed": true}' `
  -o reports\scan-latest.json
```