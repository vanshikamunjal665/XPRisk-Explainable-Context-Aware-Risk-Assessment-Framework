# The XPRisk Risk Model

This document specifies the risk-scoring algorithm introduced in Phase 9 and the
explainability layer built on it in Phase 11. It covers what each constant means,
why it has the value it has, and — importantly — what the model cannot do.

> **Status of the constants.** Every number in this document is a **prototype
> design decision made by the authors, not an empirically proven value.** They
> are ordered, internally consistent and defensible as engineering judgement.
> They have **not** been calibrated against incident data, breach datasets, or a
> validated risk standard. No claim of scientific validity is made or implied
> anywhere in XPRisk. Section 7 states the limitations precisely, and Section 8
> describes how the Phase 19 evaluation would test these values properly.

---

## 1. What the model computes

Given a set of normalized findings and a deployment context, XPRisk produces a
score in the range 0–100 and maps it onto one of three deployment decisions.

```
for each finding:
    raw_risk = severity_weight[severity] x category_multiplier[category]

total_raw          = sum(raw_risk for all findings)
base_score         = normalize(total_raw, anchors)          # 0-100, saturating
context_multiplier = product of the three context factors, capped
risk_score         = clamp(base_score x context_multiplier, 0, 100)
decision           = thresholds.decide(risk_score)
```

Two structural properties matter more than the formula.

**Context is applied exactly once, to the normalized base score.** The three
context factors are multiplied together into one multiplier and applied *after*
normalization. They are deliberately not folded into per-finding raw risk. If
they were, context would scale with the *number* of findings, and a large
repository would be penalized for its size rather than for its risk. Applying
context once keeps scores comparable between a two-file project and a
two-thousand-file one.

**The score is a pure function of its inputs.** No randomness, no clock reads, no
dependence on dictionary ordering, and no dependence on the order findings
arrive in. Findings are summed from a sorted sequence because binary
floating-point addition is not associative, so unsorted accumulation would make
scores vary run to run. `tests/test_risk_engine.py` and
`tests/test_scoring.py` assert this directly.

---

## 2. Severity weights

| Severity | Weight | Reasoning |
|----------|-------:|-----------|
| CRITICAL  | 10.0 | RCE, credential compromise, data exposure. |
| HIGH      |  7.0 | Serious, exploitable with some precondition. |
| MEDIUM    |  4.0 | Real but requires conditions or is limited impact. |
| LOW       |  1.0 | Defence in depth, minor misconfiguration. |
| INFO      |  0.0 | Advisory only. Visible, never score-affecting. |

The progression is roughly geometric so that one CRITICAL finding dominates a
handful of LOW findings without erasing them.

`INFO` is weighted zero **deliberately**. An informational notice should be
visible in the findings list without inflating deployment risk; otherwise a
repository with many style advisories would score worse than one with a single
publicly readable storage bucket. INFO findings still appear in the severity
breakdown and finding count, so nothing is hidden.

An unrecognised severity falls back to the MEDIUM weight rather than LOW, so a
scanner reporting a vocabulary XPRisk does not know is treated as mid-risk
rather than silently ignored.

Configured by `XPRISK_WEIGHT_CRITICAL`, `_HIGH`, `_MEDIUM`, `_LOW`, `_INFO`.

---

## 3. Category multipliers

| Category | Multiplier | Reasoning |
|----------|-----------:|-----------|
| SECRET       | 1.30 | Directly exploitable by anyone who obtains the credential. |
| CONTAINER    | 1.20 | Ships with the artifact; reachable wherever it runs. |
| IAC          | 1.10 | Configuration and hygiene risk. |
| SOURCE_CODE  | 1.00 | Baseline. |

A leaked secret is weighted highest because it needs no vulnerability chain: the
credential *is* the finding. A vulnerable dependency requires a reachable
vulnerable code path to matter, which is slightly less direct. IaC and
source-code issues sit just above baseline.

An unknown category is neither amplified nor penalized (multiplier 1.0); it still
contributes its severity weight.

Configured by `XPRISK_CATEGORY_SECRET`, `_CONTAINER`, `_IAC`, `_SOURCE_CODE`.

---

## 4. Context model

Three factors, each with a neutral baseline of 1.0.

### 4.1 Environment

| Environment | Multiplier | Reasoning |
|-------------|-----------:|-----------|
| DEVELOPMENT | 1.00 | Baseline. |
| STAGING     | 1.15 | Partial production resemblance. |
| PRODUCTION  | 1.40 | Closest to real users and real data. |

Development is the baseline at 1.0 so a development scan reads as "the score of
these findings", not as a penalty for where you work.

### 4.2 Exposure

| Exposure | Multiplier | Reasoning |
|----------|-----------:|-----------|
| INTERNAL         | 1.00 | Requires a foothold inside the trust boundary. |
| INTERNET_FACING  | 1.25 | Reachable by unauthenticated attackers. |

This is the single strongest context signal in the model. Internet-facing
removes the need for a prior compromise.

### 4.3 Change status

| Change status | Multiplier | Reasoning |
|---------------|-----------:|-----------|
| EXISTING | 1.00 | Inherited; often not fixable in this change. |
| NEW      | 1.15 | Introduced by this run; still preventable before merge. |

A new finding is this pipeline run's responsibility. A pre-existing one is
inherited. The model does not punish a developer for debt they did not create.

### 4.4 The uplift cap

```
context_multiplier = min(environment x exposure x change_status, 1.6)
```

Production × internet-facing × new multiplies to `1.4 x 1.25 x 1.15 = 2.0125`.
Without a cap, any non-trivial finding set in that context saturates at 100,
which destroys the model's ability to rank two different production deployments
— and ranking is a large part of what a risk score is for. The cap of 1.6 keeps
context influential while leaving headroom above it.

When the cap binds, `was_capped` is set and the explanation reports both the
uncapped product and the applied value, so a reader's arithmetic still
reproduces the score. An explanation never implies an uplift it did not apply.

The cap binds for most production and staging combinations. Section 7.4 treats
this honestly rather than hiding it.

Configured by `XPRISK_ENV_*`, `XPRISK_EXPOSURE_*`, `XPRISK_CHANGE_*`,
`XPRISK_CONTEXT_UPLIFT_CAP`.

---

## 5. The normalization curve

`XPRISK_SCORE_ANCHORS` is a piecewise-linear curve from accumulated raw risk to
a 0–100 base score, written as `raw:score` pairs:

```
0:0, 8:10, 20:30, 45:55, 80:75, 140:90, 220:100
```

Values between anchors interpolate linearly. A raw value above the final anchor
**saturates at 100** rather than extrapolating: a score above 100 is meaningless,
and an extrapolated one would rank repositories by size.

The curve is **sub-linear by design**. The first 8 raw units buy 10 points; the
last 80 units buy only 10. This encodes diminishing returns explicitly and is
what stops a large repository from being permanently pinned at BLOCK.

Validation rejects any curve that does not start at `0:0` (so no finding can
score zero risk), does not end at score 100 (so the scale really is 0–100), or
whose raw/score values are not strictly increasing.

---

## 6. Decision bands

| Decision | Score range | Meaning |
|----------|-------------|---------|
| SAFE     | `0 <= s < 30`   | The pipeline may proceed. |
| WARNING  | `30 <= s < 70`  | Proceed, but a human should look. |
| BLOCK    | `70 <= s <= 100`| The pipeline must not proceed. |

Bands are half-open `[lower, upper)`, except BLOCK which is closed at the top, so
every score maps to **exactly one** decision — no overlap, no gap.

Three bands rather than two because a two-band model must answer "is this bad?"
with a yes/no, forcing the threshold to sit wherever the author felt about risk
appetite. WARNING expresses the genuinely common case: findings that are real and
worth fixing but do not justify stopping a deployment.

Configured by `XPRISK_THRESHOLD_SAFE` and `XPRISK_THRESHOLD_WARNING`.

---

## 7. Limitations

These are real constraints of the current design, stated plainly.

### 7.1 The constants are not empirically calibrated

Section 8 is the honest version of this. Nothing here has been validated against
incident data.

### 7.2 A single CRITICAL finding does not reach BLOCK

This is the model's most significant weakness and it is worth being explicit
about. Measured with the shipped defaults in `production/internet-facing`:

| Findings | Score | Decision |
|----------|------:|----------|
| 1 CRITICAL secret | 29.3 | SAFE |
| 2 CRITICAL secrets | 57.6 | WARNING |
| 3 CRITICAL secrets | 78.4 | BLOCK |

A **single leaked credential scored SAFE.** For a security tool that is
indefensible as a final answer, and it is not a tuning detail — it is a
structural property of additive scoring.

The cause is arithmetic. One CRITICAL secret contributes `10.0 x 1.3 = 13.0`
raw units. Five MEDIUM IaC findings contribute `5 x 4.0 x 1.1 = 22.0` raw units.
A purely additive model therefore always values *n* medium findings above *one*
critical finding, no matter how the curve is shaped.

Why it was not simply "fixed":

- **Steepening the curve does not work.** To make one CRITICAL reach BLOCK the
  base score at raw 13 must exceed 70, which requires an absurd first segment and
  destroys discrimination across the entire range.
- **A severity floor changes the model.** The conventional repair is a rule such
  as "if any CRITICAL is present the decision is at least WARNING". That is a
  defensible design, but it is an **additional model component**, not a
  recalibration, and it would need its own justification and testing.

This is flagged as an **open design decision** for Phase 19 evaluation, not
silently patched. `docs/risk-model.md` documents the measured numbers so the
trade-off is visible to an examiner rather than buried.

### 7.3 Checkov contributes no severity information

Verified empirically against Checkov 3.3.22: **every Terraform resource check
reports `severity: null`.** The normalizer's
`CHECKOV_MISSING_SEVERITY_POLICY` maps these to MEDIUM.

Consequence: for IaC findings, severity is uninformative and **count is the only
discriminating signal**. The verified runs give 24 findings for
`demo-app/scenarios/insecure` versus 8 for `demo-app/scenarios/clean`, and that
3:1 ratio is what separates the two scenarios — not the severity labels.

XPRisk deliberately does **not** invent severities for Checkov checks. Assigning
one would be XPRisk-authored editorial judgement that would need labelling as
such, and it would manufacture a precision the scanner does not provide.

### 7.4 The context cap binds often

The cap binds for production × internet-facing × new and most production
combinations. Beyond that point, context differences stop affecting the score.
The model handles this by reporting `was_capped`, but a deployment that saturates
the cap cannot be ranked against another that also saturates it.

### 7.5 Saturation hides differences

Both the curve and the final clamp saturate. Large real scanner outputs (the
verified Trivy runs produced 651 and 283 findings) score 100.0 in every context
and under every policy. For those inputs the score carries **no** discriminating
information, which is visible in `reports/comparative_study_results.json`.

### 7.6 One finding type, one severity

Findings are flattened to severity and category before scoring. Two findings with
identical severity and category contribute identically regardless of exploit
path, affected asset count, or data sensitivity. `risk_engine` does not
currently use scanner-supplied CVSS vectors or exploit-prediction scores.

### 7.7 Gitleaks severity is XPRisk-defined

Verified against Gitleaks 8.30.1: the tool reports no severity of its own. XPRisk
assigns it via `GITLEAKS_RULE_SEVERITY` in `normalizer/normalizer.py`, a
rule-based mapping from rule name to severity. These are **XPRisk-authored
severities**, and `fixtures/gitleaks/` documents the policy.

### 7.8 SonarQube is unverified

The SonarQube adapter has never been run against a live instance. Its severity
handling is unverified and may need its own policy, as Checkov did.

---

## 8. How Phase 19 would validate this properly

The constants are hypotheses. Testing them requires data XPRisk does not have:

1. **Collect labelled deployment outcomes.** For a sample of real changes,
   record whether a deployment incident followed, and within what window.
2. **Fit the weights rather than asserting them.** Regress observed incident
   frequency on severity and category to derive weights instead of choosing them.
3. **Tune thresholds to a stated risk appetite**, and report the resulting
   precision/recall and false-positive rate. A threshold is a business
   decision, and the numbers should be presented as such.
4. **Test the severity-floor question (7.2) empirically.** Measure how often a
   lone CRITICAL precedes an incident. If it is frequent, that is evidence for a
   floor; if rare, the additive model stands.
5. **Report confidence intervals.** No number in this document has one yet.

Until then the model should be described as a **transparent, configurable
heuristic that is auditable by construction**, which is a genuine and defensible
engineering contribution, and not as a validated risk metric.

---

## 9. Comparative study (methodology Step 4)

Because every constant is injectable, the same findings can be scored under
different policies without editing code. `xprisk_comparative.py` does this and
writes `reports/comparative_study_results.json`.

Three policies are compared:

| Label | Meaning |
|-------|---------|
| **S** | Severity only. No category multiplier, no context. |
| **C** | Severity × category. Count-driven, context-neutral. |
| **X** | C plus context. The full XPRisk model. |

### What the comparison actually shows

For the IaC finding sets, where severity is uniform (all MEDIUM, because of 7.3),
**S and C give identical rankings**, since all findings share one severity and
one category. Context (X) then separates identical findings by deployment target,
which is the contribution S and C structurally cannot make.

Discrimination between insecure and clean (`reports/comparative_study_results.json`):

| Policy | Context | Insecure | Clean | Ratio |
|--------|---------|---------:|------:|------:|
| S | development/internal | 79.0 | 42.0 | 1.88x |
| C | development/internal | 81.4 | 45.2 | 1.80x |
| X | development/internal | 81.4 | 45.2 | 1.80x |
| S | production/exposed | 100.0 | 67.2 | 1.49x |
| C | production/exposed | 100.0 | 72.3 | 1.38x |
| X | production/exposed | 100.0 | 72.3 | 1.38x |

**Honest reading of this table.** It does **not** show the full model
outperforming the baselines, and this report will not claim that it does:

- The ratios are close, and the full model's ratio is marginally *lower* in
  production because the uplift cap compresses the top of the range.
- For the container finding sets derived from the real Trivy runs, **all three
  policies produce 100.0 in every context**. Per 7.5, saturation means no
  discrimination at all.
- The distinguishing evidence for context-awareness is not the aggregate ratio.
  It is that **X scores identical findings differently across deployment
  contexts while S and C cannot**, demonstrated directly in integration TEST 4
  and TEST 5 where the same six findings score 36.4 in development and 58.2 in
  production under X, and 36.4 in both under C.

A fair conclusion: severity aggregation is the dominant signal for small,
uniform finding sets; context-awareness adds a dimension the baselines lack; and
for large finding sets all three saturate and none is informative. Phase 19 must
test whether that trade-off holds on real data.

---

## 10. Explainability (Phase 11)

Every number XPRisk publishes is reconstructible by hand from the explanation
payload. For 24 MEDIUM IaC findings plus 1 CRITICAL secret in production:

```
per_finding_risk   sum over findings of (severity_weight x category_multiplier)  = 118.6000
normalise          interpolate(118.6000, anchors) -> base score                    =  84.6500
context_uplift     1.4 x 1.25 x 1.15 = 2.0125, capped to 1.6000                  =   1.6000
final_score        clamp(84.6500 x 1.6000 = 135.4400, 0, 100)                     = 100.0000
decision           score 100.0000 against thresholds safe=30 warning=70           =   BLOCK
```

`tests/test_explainability.py::test_explanation_score_is_reproducible_from_the_payload_alone`
re-derives the score using **only** fields published in the explanation and
asserts equality against the engine's result. This makes "verifiable by hand" an
enforced property rather than a claim in a docstring.

Three further rules:

- **A finding that contributed nothing cannot be named as a reason.** Zero-risk
  findings remain in the severity breakdown but are excluded from contributors.
- **A context factor that was not applicable cannot be blamed.** All three
  factors are always reported, including non-amplifying ones, so a reader can
  distinguish "did not raise this" from "was never considered".
- **Remediation is a simulation, not a heuristic.** Resolving findings
  re-runs the engine's own normalization over the reduced set, so projected
  scores are what the system would actually produce. They are labelled
  predictions, never guarantees.

`context_alternatives()` reports what the score would be under every other
context. This is informational only: XPRisk does **not** recommend reducing
exposure or targeting a less critical environment to pass a gate. Finding-based
remediation is listed first for that reason.

---

## 11. Configuration and layering

`risk_engine` reads **nothing** from the environment. Phases 6 and 8 established
that domain packages stay free of ambient configuration; Phase 9 preserves it.

- `risk_engine/settings.py` holds the defaults. Override by constructing
  `RiskSettings` with different values.
- `backend/app/config.py` reads the `XPRISK_*` variables via pydantic-settings,
  validates them at startup, and constructs the `RiskSettings` injected into
  `RiskEngine`.

`.env.example` is the contract. `tests/test_config.py` asserts that every
`XPRISK_*` risk variable declared there is a real field, that the shipped
defaults match the documented values, and — via AST inspection rather than
substring matching — that no module in `risk_engine` or `normalizer` reads
`os.environ` or imports `pydantic_settings`.

Malformed configuration fails at startup rather than producing a quietly wrong
score. These all raise immediately:

```
XPRISK_SCORE_ANCHORS=0:0,8:10,4:20    raw values must increase
XPRISK_SCORE_ANCHORS=0:0,8:10,220:90   must end at score 100
XPRISK_SCORE_ANCHORS=0:0               needs at least two points
XPRISK_THRESHOLD_SAFE=90               thresholds must satisfy 0 <= safe < warning
XPRISK_CONTEXT_UPLIFT_CAP=0.5          cap must be >= 1.0
```

---

## 12. Reproducing the numbers

```powershell
# full test suite
.\.venv\Scripts\python.exe -m pytest -p no:cacheprovider -q

# the six integration scenarios, with actual outcomes
.\.venv\Scripts\python.exe run_integration_scenarios.py

# the comparative study, writes reports/comparative_study_results.json
.\.venv\Scripts\python.exe xprisk_comparative.py
```

`run_integration_scenarios.py` reports what the model **does**, including where
the result contradicts the scenario name, rather than asserting what it should
do. The 7.2 finding above comes from that script.