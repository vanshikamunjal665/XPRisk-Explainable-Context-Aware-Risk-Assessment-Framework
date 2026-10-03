# XPRisk Test Suite

Tests are organised by the component they exercise, mirroring the source
layout, so that a failing test points at exactly one module.

| File | Covers | Phase |
|---|---|---|
| `test_scanners.py` | Gitleaks, Trivy, Checkov and SonarQube parsers; missing-executable handling; failure handling | 4 |
| `test_normalizer.py` | Canonical schema; normalization from all four tools; metadata preservation | 6, 9 |
| `test_severity.py` | Severity mapping from every tool vocabulary | 6 |
| `test_context.py` | Context model construction and validation | 8 |
| `test_scoring.py` | Per-finding risk, aggregation, normalization curve, context uplift | 9 |
| `test_thresholds.py` | SAFE / WARNING / BLOCK and all boundary values | 11 |
| `test_risk_engine.py` | Engine determinism and the full scoring pipeline | 10 |
| `test_explainability.py` | Explanation derived from real contributions; remediation | 12 |
| `test_database.py` | Model constraints, storage service, historical queries | 7 |
| `test_api.py` | Every endpoint, validation and error handling | 13 |
| `test_integration.py` | TEST 1-6 end-to-end scenarios | 18 |

## Markers

Registered in `pyproject.toml`:

```powershell
pytest -m unit          # fast, isolated
pytest -m integration   # multi-component
pytest -m fixture       # uses labelled fixture data
pytest -m contract      # validates against a real tool's output schema
pytest -m slow          # executes a real security tool
```

## Principles

1. **No test may require an installed security tool.** Scanner behaviour is
   verified through parsers fed labelled fixtures and through a
   ``--docker``-style injection seam. Tests that genuinely need a real tool are
   marked ``slow`` and skipped when it is absent.
2. **No test may require PostgreSQL.** The suite runs against a temporary
   SQLite database, so it is green on a fresh clone with zero infrastructure.
3. **No hardcoded expectations about real scanner output.** Expected values are
   either asserted invariants (determinism, monotonicity, boundary behaviour) or
   values derived from the configured model, never from a scan that may change
   when a tool updates its rules.
4. **Determinism is tested explicitly.** The same findings and context must
   always yield the same score.

## Required integration scenarios

| Test | Scenario | Expected |
|---|---|---|
| TEST 1 | No findings | Low risk, `SAFE` |
| TEST 2 | Several medium findings | Moderate risk, `WARNING` |
| TEST 3 | Critical finding | High risk, `BLOCK` |
| TEST 4 | Same finding in `development` vs `production` | Different scores |
| TEST 5 | Internet-facing vs internal | Different scores |
| TEST 6 | Secret finding | Risk increases; decision can change |