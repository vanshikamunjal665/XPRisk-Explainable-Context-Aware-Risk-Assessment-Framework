"""XPRisk risk engine - the research core of the framework.

This package turns canonical XPRisk findings plus a deployment context into a
single deterministic risk score in the range 0-100, and maps that score onto a
SAFE / WARNING / BLOCK deployment recommendation.

Modules
-------
``severity.py``
    Severity enumeration and the base severity weights.

``context.py``
    The context model: what XPRisk knows about *where* and *how* a finding is
    being deployed. Produces structured context data only; it contains no
    scoring logic, so the context model can evolve independently of the
    scoring formula.

``scoring.py``
    The scoring algorithm: per-finding risk, aggregation, the piecewise
    linear normalisation curve, and the bounded context uplift.

``thresholds.py``
    Configurable decision thresholds and the score-to-decision mapping.

``engine.py``
    Orchestration: findings + context in, score + decision + a full
    contribution breakdown out.

The scoring pipeline
--------------------
::

    for each finding:
        raw_risk = severity_weight[finding.severity]
                   x category_multiplier[finding.category]

    total_raw          = sum(raw_risk for all findings)
    base_score         = normalise(total_raw, anchors)      # 0-100, saturating
    context_multiplier = product of applicable context factors, capped
    risk_score         = clamp(base_score x context_multiplier, 0, 100)
    decision           = thresholds.decide(risk_score)

Determinism guarantee
---------------------
The engine is a pure function of its inputs. No randomness, no clock reads, no
dictionary-order dependence, no floating point accumulation order dependence.
The same findings and the same context always produce the same score, which
is asserted directly in the test suite. This is a hard requirement: an
unauditable score cannot be explained, and an unexplainable risk engine is
not a defensible research contribution.

Configuration
-------------
Every number above is a default held in :mod:`risk_engine.settings` and can be
overridden by environment variables (see ``.env.example``). This is what makes
the comparative study (severity-only vs severity+count vs context-aware)
possible without editing code. See ``docs/risk-model.md`` for the rationale
behind each default, including the explicit statement that these values are
prototype design decisions rather than empirically proven constants.
"""

__all__: list[str] = []