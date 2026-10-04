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
    change to reach a **lower-risk** decision band, and which specific findings
    must be resolved first. The direction matters: remediation always reduces
    risk, so WARNING targets SAFE (below the SAFE edge) and BLOCK targets
    WARNING (below the WARNING edge). Also reports what the score would be under
    every other deployment context, for information only — XPRisk does not
    recommend reducing exposure to pass a gate.

Why this is a contribution rather than a feature
------------------------------------------------
DevSecOps tooling is routinely criticised for producing alerts without
prioritisation. XPRisk's position is that a risk score is only useful if the
recipient can reconstruct it. Because every number in the explanation is the
same number the engine used, the explanation is verifiable by hand, which is
what makes the SAFE / WARNING / BLOCK recommendation auditable rather than
opaque.

Two rules that constrain what an explanation may say
----------------------------------------------------
**A finding that contributed nothing cannot be named as a reason.** INFO-severity
findings are real and stay in the severity breakdown and finding count, but they
did not move the score, so they are excluded from the contributor list. A reason
that did not influence the outcome is not a reason.

**A context factor that was not applicable cannot be blamed.** All three context
factors are always reported, including the ones sitting at their neutral
baseline, so a reader can distinguish "internal exposure did not raise this
score" from "exposure was never considered". Where the uplift cap binds, both
the uncapped product and the applied value are reported, so the reader's
arithmetic still reproduces the score.

Remediation is a simulation rather than a heuristic. Resolving findings re-runs
the engine's own normalisation over the reduced set, so projected scores are what
the system would actually produce. They are labelled predictions, never
guarantees, and stopping at the first sufficient step keeps the plan minimal
rather than a full clean-up list.

``docs/risk-model.md`` records the full derivation.
"""

__all__: list[str] = []