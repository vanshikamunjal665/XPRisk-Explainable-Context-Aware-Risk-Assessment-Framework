"""XPRisk explainability engine.

Answers the question *"why did XPRisk make this decision?"* using the real
numbers produced by the risk engine, never a canned narrative.

The distinction that matters
---------------------------
A system that prints "risk score is high, therefore there are critical
vulnerabilities" is not explainable; it is narrating. XPRisk's explanation is
*derived*: the risk engine emits a contribution for every individual finding
and every context factor, and this package ranks, groups and renders exactly
those contributions. If a finding contributed nothing, it cannot appear as a
reason. If a context factor was not applicable, it cannot be blamed.

Modules
-------
``contributors.py``
    Selects and ranks the significant contributors from the engine's
    contribution data, and computes how much of the final score each one is
    responsible for.

``explanation.py``
    Builds the structured explanation payload: decision, score, summary,
    top contributors with their contribution values, and the context factors
    that were applied.

``recommendation.py``
    Converts an explanation into actionable remediation guidance: what has to
    change to reach a different decision band, and which specific findings
    must be resolved first.

Why this is a contribution rather than a feature
------------------------------------------------
DevSecOps tooling is routinely criticised for producing alerts without
prioritisation. XPRisk's position is that a risk score is only useful if the
recipient can reconstruct it. Because every number in the explanation is the
same number the engine used, the explanation is verifiable by hand, which is
what makes the SAFE / WARNING / BLOCK recommendation auditable rather than
opaque.

``docs/risk-model.md`` records the full derivation.
"""

__all__: list[str] = []