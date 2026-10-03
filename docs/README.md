# XPRisk Documentation

| Document | Phase | Purpose |
|---|---|---|
| [`risk-model.md`](risk-model.md) | 9 | **The research core.** Severity weights, context multipliers, the normalization curve and the decision thresholds, each with its rationale, worked examples, sensitivity notes and an explicit statement of what is *not* claimed. |
| `architecture.md` | 1-14 | Layer diagram, dependency rules and the rationale for each separation. Written up during Phase 13. |
| `api.md` | 13 | Endpoint reference beyond the auto-generated OpenAPI docs. Written up during Phase 13. |

## Reporting artifacts

The project follows a seven-step methodology. These documents are the
evidence for the written phases:

| Methodology step | Evidence produced by the code |
|---|---|
| 2. Identification of requirements | Endpoint schemas, validated context model, risk-model configuration surface |
| 3. Identification of algorithm | `docs/risk-model.md` |
| 4. Comparative study | `risk_engine/strategies.py` (pluggable aggregation) and the Phase 19 report |
| 5. Design and development | This directory, plus module-level docstrings |
| 6. Implementation | The repository itself |
| 7. Results | Phase 19 and Phase 20 reports |

## A note on honesty in documentation

Two kinds of statement are kept strictly separate throughout this project:

**Measured.** Anything produced by running the code, such as a finding count, a
score or a duration. Always accompanied by how it was obtained.

**Asserted.** Design decisions such as the severity weights and context
multipliers. These are *prototype values chosen to be reasonable and
defensible*, not empirically proven constants. `docs/risk-model.md` states this
explicitly, because presenting an arbitrary weight as a scientific result is
the fastest way to lose credibility in an evaluation.

The same rule applies to fixture data. Findings produced from
`fixtures/` are labelled `"data_origin": "FIXTURE"` and are never described as
real scanner output.