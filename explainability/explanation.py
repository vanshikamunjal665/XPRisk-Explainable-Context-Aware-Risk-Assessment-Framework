"""Structured explanation payloads (Phase 11).

Builds the "why did XPRisk decide that?" payload entirely from numbers the risk
engine actually used.

The derivability guarantee
---------------------------
:class:`Explanation` carries a ``derivation`` list: an ordered sequence of
``(label, expression, value)`` triples that reconstruct the score by hand. For a
24-finding assessment it reads roughly::

    severity x category weights   sum(finding.raw_risk)        = 105.6
    normalisation                 interpolate(105.6, anchors)  = 81.4
    context uplift                1.4 x 1.25 x 1.15 = 2.0125   capped to 1.6
    final score                   81.4 x 1.6 = 130.24         clamped to 100.0

Every value in that list is the same number the engine computed, not a
re-derivation. ``tests/test_explainability.py`` re-computes the score from the
payload and asserts equality, which is what stops an explanation from ever
drifting away from the decision it is explaining.

No canned narrative
-------------------
Sentences are composed from the assessment's own fields. There is no
lookup table of "interesting" messages and no per-scenario special-casing, so
an explanation for a finding set nobody anticipated is as valid as one for the
integration scenarios.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from risk_engine.engine import RiskAssessment
from risk_engine.thresholds import Decision
from explainability.contributors import (
    ContextContributor,
    FindingContributor,
    category_raw_risk,
    dominant_category,
    select_context_contributors,
    select_finding_contributors,
    severity_counts,
)

__all__ = [
    "DerivationStep",
    "Explanation",
    "build_explanation",
    "DEFAULT_TOP_CONTRIBUTORS",
]

#: How many findings an explanation names by default. Enough to show what drove
#: a decision without burying it; the dashboard reads the full breakdown.
DEFAULT_TOP_CONTRIBUTORS = 5


@dataclass(frozen=True)
class DerivationStep:
    """One arithmetic step, in the order the engine applied it."""

    step: str
    expression: str
    value: float

    def to_dict(self) -> dict:
        return {"step": self.step, "expression": self.expression, "value": self.value}


@dataclass(frozen=True)
class Explanation:
    """The full, structured answer to "why this decision"."""

    decision: Decision
    risk_score: float
    base_score: float
    total_raw: float
    finding_count: int
    context: dict[str, Any]
    headline: str
    summary: str
    derivation: tuple[DerivationStep, ...]
    finding_contributors: tuple[FindingContributor, ...]
    context_contributors: tuple[ContextContributor, ...]
    severity_breakdown: dict[str, int]
    category_breakdown: dict[str, int]
    category_raw_risk: dict[str, float]
    dominant_category: str | None
    distance_to_edges: dict[str, float]
    context_capped: bool
    uncapped_multiplier: float
    capped_multiplier: float
    settings_snapshot: dict = field(default_factory=dict)

    # -- convenience --------------------------------------------------------

    @property
    def allows_deployment(self) -> bool:
        return self.decision.allows_deployment

    @property
    def top_share(self) -> float:
        """Combined share of raw risk held by the named contributors."""

        return sum(c.share_of_total for c in self.finding_contributors)

    def to_dict(self) -> dict:
        return {
            "decision": self.decision.value,
            "risk_score": self.risk_score,
            "base_score": self.base_score,
            "total_raw": self.total_raw,
            "finding_count": self.finding_count,
            "context": self.context,
            "headline": self.headline,
            "summary": self.summary,
            "derivation": [d.to_dict() for d in self.derivation],
            "finding_contributors": [c.to_dict() for c in self.finding_contributors],
            "context_contributors": [c.to_dict() for c in self.context_contributors],
            "severity_breakdown": dict(self.severity_breakdown),
            "category_breakdown": dict(self.category_breakdown),
            "category_raw_risk": dict(self.category_raw_risk),
            "dominant_category": self.dominant_category,
            "distance_to_edges": dict(self.distance_to_edges),
            "context_capped": self.context_capped,
            "uncapped_multiplier": self.uncapped_multiplier,
            "capped_multiplier": self.capped_multiplier,
            "settings_snapshot": dict(self.settings_snapshot),
        }


def _headline(assessment: RiskAssessment) -> str:
    return (
        f"Risk score {assessment.risk_score:.1f}/100 -> {assessment.decision.value}"
    )


def _summary(assessment: RiskAssessment, top: tuple[FindingContributor, ...], dominant: str | None) -> str:
    """Compose the summary sentence from the assessment's own numbers."""

    count = assessment.finding_count
    if count == 0:
        return (
            "No findings were reported, so the base score is 0 and no context "
            "uplift applies. This deployment is assessed as SAFE."
        )

    sevs = severity_counts(assessment)
    parts = [f"{count} finding{'s' if count != 1 else ''}"]
    for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        if sevs.get(name):
            parts.append(f"{sevs[name]} {name}")
    breakdown = ", ".join(parts[1:]) if len(parts) > 1 else ""

    category_phrase = ""
    if dominant:
        category_phrase = f" Most raw risk ({dominant}) came from "

    lead = f"{count} finding{'s' if count != 1 else ''} were reported"
    if breakdown:
        lead += f": {breakdown}."
    text = f"{lead} They accumulate to {assessment.total_raw:.1f} raw risk units"
    if dominant:
        text += f", which normalises to a base score of {assessment.base_score:.1f}."
    else:
        text += f", giving a base score of {assessment.base_score:.1f}."

    if top:
        top_label = top[0].label
        text += (
            f" The largest single contributor is {top_label} "
            f"({top[0].raw_risk:.1f} raw units, {top[0].share_of_total * 100:.0f}% of the total)."
        )

    uplift = assessment.uplift
    if uplift.was_capped:
        cap = assessment.settings_snapshot.get("context_uplift_cap", uplift.capped)
        text += (
            f" Context uplift would have been {uplift.uncapped:.4f} but is capped at "
            f"{cap:g}, so the uplift applied was {uplift.capped:.4f}."
        )
    elif uplift.capped != 1.0:
        text += f" Context uplift multiplies the base score by {uplift.capped:.2f}."

    return text


def _derivation(assessment: RiskAssessment) -> tuple[DerivationStep, ...]:
    """The ordered arithmetic that produced the score."""

    steps: list[DerivationStep] = []

    steps.append(
        DerivationStep(
            step="per_finding_risk",
            expression="sum over findings of (severity_weight x category_multiplier)",
            value=assessment.total_raw,
        )
    )
    steps.append(
        DerivationStep(
            step="normalise",
            expression=f"interpolate({assessment.total_raw:.4f}, anchors) -> base score",
            value=assessment.base_score,
        )
    )

    uplift = assessment.uplift
    steps.append(
        DerivationStep(
            step="context_uplift",
            expression=(
                f"{uplift.environment_multiplier} x {uplift.exposure_multiplier} x "
                f"{uplift.change_multiplier} = {uplift.uncapped:.4f}"
                + (f", capped to {uplift.capped:.4f}" if uplift.was_capped else "")
            ),
            value=uplift.capped,
        )
    )

    product = assessment.base_score * uplift.capped
    clamped = assessment.risk_score_unrounded
    if product > 100.0:
        steps.append(
            DerivationStep(
                step="final_score",
                expression=(
                    f"clamp({assessment.base_score:.4f} x {uplift.capped:.4f} = "
                    f"{product:.4f}, 0, 100)"
                ),
                value=clamped,
            )
        )
    else:
        steps.append(
            DerivationStep(
                step="final_score",
                expression=f"{assessment.base_score:.4f} x {uplift.capped:.4f}",
                value=clamped,
            )
        )

    steps.append(
        DerivationStep(
            step="decision",
            expression=(
                f"score {assessment.risk_score:.4f} against thresholds "
                f"safe={assessment.thresholds.safe:g} warning={assessment.thresholds.warning:g}"
            ),
            value=float(
                {"SAFE": 0, "WARNING": 1, "BLOCK": 2}[assessment.decision.value]
            ),
        )
    )

    return tuple(steps)


def build_explanation(
    assessment: RiskAssessment,
    *,
    top_n: int = DEFAULT_TOP_CONTRIBUTORS,
) -> Explanation:
    """Build the structured explanation for a completed assessment."""

    finding_contributors = select_finding_contributors(assessment, limit=top_n)
    context_contributors = select_context_contributors(assessment)
    dominant = dominant_category(assessment)

    return Explanation(
        decision=assessment.decision,
        risk_score=assessment.risk_score,
        base_score=assessment.base_score,
        total_raw=assessment.total_raw,
        finding_count=assessment.finding_count,
        context=assessment.context.to_dict(),
        headline=_headline(assessment),
        summary=_summary(assessment, finding_contributors, dominant),
        derivation=_derivation(assessment),
        finding_contributors=finding_contributors,
        context_contributors=context_contributors,
        severity_breakdown=severity_counts(assessment),
        category_breakdown=dict(assessment.category_breakdown),
        category_raw_risk=category_raw_risk(assessment),
        dominant_category=dominant,
        distance_to_edges=assessment.distance_to_edges(),
        context_capped=assessment.uplift.was_capped,
        uncapped_multiplier=assessment.uplift.uncapped,
        capped_multiplier=assessment.uplift.capped,
        settings_snapshot=dict(assessment.settings_snapshot),
    )