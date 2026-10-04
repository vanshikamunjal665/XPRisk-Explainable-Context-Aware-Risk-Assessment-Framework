"""Remediation guidance (Phase 11).

Converts an explanation into an answer to "what has to change?".

This is where most alerting tooling stops, and where XPRisk has something
specific to contribute. It does not print "fix your vulnerabilities". It
computes, from the engine's own arithmetic:

* how many points the score must fall to reach a different decision band;
* which findings, resolved in order of influence, would achieve that;
* what the score would become if exactly those findings were fixed.

That computation is a real simulation rather than a heuristic: it re-runs the
engine's own normalisation over the reduced finding set, so the predicted score
is the score the system would actually produce. It is labelled a prediction,
never a guarantee, because fixing a finding can also change context.

Limitation worth stating plainly
--------------------------------
Removing findings is the only lever modelled. The score also depends on
deployment context, so a team can legitimately reach a lower band by deploying
internally instead of by fixing code. :func:`context_alternatives` reports that
option where it is available, but XPRisk does not recommend weakening exposure
to pass a gate; the finding-based route is listed first for that reason.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from risk_engine.context import ChangeStatus, Environment, Exposure
from risk_engine.engine import RiskAssessment
from risk_engine.scoring import interpolate_score
from risk_engine.thresholds import Decision

__all__ = [
    "Recommendation",
    "FindingToFix",
    "build_recommendation",
    "context_alternatives",
]


@dataclass(frozen=True)
class FindingToFix:
    """One finding whose resolution would lower the score."""

    label: str
    location: str | None
    severity: str
    category: str
    tool: str
    raw_risk: float
    #: Score before this finding is resolved, and after.
    score_before: float
    score_after: float
    #: score_before - score_after, so a zero means this finding changes nothing.
    points_removed: float
    #: False when resolving this single finding is not enough on its own.
    reaches_target: bool

    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "location": self.location,
            "severity": self.severity,
            "category": self.category,
            "tool": self.tool,
            "raw_risk": self.raw_risk,
            "score_before": self.score_before,
            "score_after": self.score_after,
            "points_removed": self.points_removed,
            "reaches_target": self.reaches_target,
        }


@dataclass(frozen=True)
class Recommendation:
    """What to do about this assessment."""

    decision: Decision
    action: str
    rationale: str
    #: The band the recommendation is trying to reach, or None when already SAFE.
    target_decision: Decision | None
    #: Score below which ``target_decision`` applies.
    target_threshold: float | None
    current_score: float
    #: Points that must come off the score, or None if already at target.
    points_to_target: float | None
    findings_to_fix: tuple[FindingToFix, ...]
    #: Score predicted if every listed finding were resolved. None when the
    #: target cannot be reached by fixing findings alone.
    projected_score: float | None
    #: True when even fixing every contributing finding would not reach target.
    unreachable_by_fixing: bool
    context_note: str | None = None

    def to_dict(self) -> dict:
        return {
            "decision": self.decision.value,
            "action": self.action,
            "rationale": self.rationale,
            "target_decision": self.target_decision.value if self.target_decision else None,
            "target_threshold": self.target_threshold,
            "current_score": self.current_score,
            "points_to_target": self.points_to_target,
            "findings_to_fix": [f.to_dict() for f in self.findings_to_fix],
            "projected_score": self.projected_score,
            "unreachable_by_fixing": self.unreachable_by_fixing,
            "context_note": self.context_note,
        }


def _next_better_band(assessment: RiskAssessment) -> tuple[Decision, float] | None:
    """The next band *down* in risk from the current decision, and its threshold.

    Remediation always reduces risk, so the target is always a less restrictive
    band than the current one. Because the bands are half-open, the score has to
    fall strictly below the target band's upper edge:

    ==============  ====================  ======================
    Current         Target                Score must fall below
    ==============  ====================  ======================
    WARNING         SAFE                  ``threshold_safe``
    BLOCK           WARNING               ``threshold_warning``
    SAFE            (none)                already the best band
    ==============  ====================  ======================

    Note the direction. Moving from WARNING to SAFE means dropping below the
    *SAFE* edge, not the WARNING edge the score has already cleared.
    """

    if assessment.decision is Decision.SAFE:
        return None
    if assessment.decision is Decision.WARNING:
        return Decision.SAFE, assessment.thresholds.safe
    return Decision.WARNING, assessment.thresholds.warning


def _threshold_for(decision: Decision, assessment: RiskAssessment) -> float:
    """Upper edge (exclusive) of ``decision``, as a score to stay below."""

    if decision is Decision.SAFE:
        return assessment.thresholds.safe
    if decision is Decision.WARNING:
        return assessment.thresholds.warning
    return 100.0


def build_recommendation(
    assessment: RiskAssessment,
    *,
    max_steps: int = 10,
) -> Recommendation:
    """Compute the remediation path from ``assessment``.

    Findings are resolved greedily in order of raw risk, because that is the
    order in which each one removes the most accumulated risk. After each
    hypothetical resolution the engine's normalisation is re-run over the
    remaining raw risk, so the projected scores are the real function of the
    score curve rather than a linear approximation.
    """

    better = _next_better_band(assessment)

    if better is None:
        return Recommendation(
            decision=assessment.decision,
            action="No further remediation required by the risk model.",
            rationale=(
                f"The score of {assessment.risk_score:.1f} is below the SAFE threshold "
                f"({assessment.thresholds.safe:g}), which is the least restrictive band XPRisk "
                "can assign. There is no lower-risk band to move to."
            ),
            target_decision=None,
            target_threshold=None,
            current_score=assessment.risk_score,
            points_to_target=None,
            findings_to_fix=(),
            projected_score=None,
            unreachable_by_fixing=False,
        )

    target_decision, target_threshold = better
    points_needed = assessment.risk_score - target_threshold

    # Accumulated raw risk currently held by each contributing finding, in
    # influence order, so we can subtract and re-normalise.
    contributors = assessment.contributing_findings
    steps: list[FindingToFix] = []
    remaining_raw = assessment.total_raw
    current_score = assessment.risk_score
    unreachable = False

    for contribution in contributors[: max_steps]:
        if current_score < target_threshold:
            break
        before = current_score
        remaining_raw = max(0.0, remaining_raw - contribution.raw_risk)
        base = interpolate_score(remaining_raw, _anchors(assessment))
        after = min(100.0, base * assessment.uplift.capped)
        current_score = round(after, 4)
        steps.append(
            FindingToFix(
                label=contribution.label,
                location=contribution.location,
                severity=contribution.severity.value,
                category=contribution.category.value,
                tool=contribution.tool,
                raw_risk=contribution.raw_risk,
                score_before=before,
                score_after=current_score,
                points_removed=round(before - current_score, 4),
                reaches_target=current_score < target_threshold,
            )
        )

    reached = current_score < target_threshold
    if not reached:
        unreachable = True
        projected: float | None = current_score
    else:
        projected = current_score

    if reached and steps:
        action = (
            f"Resolve the {len(steps)} finding{'s' if len(steps) != 1 else ''} listed to move from "
            f"{assessment.decision.value} to {target_decision.value}."
        )
        rationale = (
            f"The score is {assessment.risk_score:.1f} and must fall below "
            f"{target_threshold:g} to reach {target_decision.value}, so at least "
            f"{max(0.0, points_needed):.1f} points have to come off. Resolving the listed "
            f"finding{'s' if len(steps) != 1 else ''} projects a score of {projected:.1f}."
        )
    elif unreachable and steps:
        action = (
            f"Resolving the {len(steps)} most influential finding{'s' if len(steps) != 1 else ''} "
            f"is still expected to leave the deployment at {current_score:.1f}."
        )
        rationale = (
            f"Even with those resolved the score projects to {projected:.1f}, which is not below "
            f"the {target_threshold:g} needed for {target_decision.value}. More findings must be "
            "addressed, or the deployment context must change."
        )
    elif unreachable and not steps:
        action = f"No remediation step was available to reach {target_decision.value}."
        rationale = (
            f"The score is {assessment.risk_score:.1f}, which is not below the "
            f"{target_threshold:g} needed for {target_decision.value}, yet no contributing "
            "finding was available to resolve. Either every finding was already weighted "
            "zero, or the step budget was exhausted before any could be considered."
        )
    else:
        action = "Already in the target band."
        rationale = (
            f"The score of {assessment.risk_score:.1f} is already below {target_threshold:g}."
        )

    return Recommendation(
        decision=assessment.decision,
        action=action,
        rationale=rationale,
        target_decision=target_decision,
        target_threshold=target_threshold,
        current_score=assessment.risk_score,
        points_to_target=max(0.0, points_needed),
        findings_to_fix=tuple(steps),
        projected_score=projected,
        unreachable_by_fixing=unreachable,
        context_note=_context_note(assessment),
    )


def _anchors(assessment: RiskAssessment) -> Sequence[tuple[float, float]]:
    raw = assessment.settings_snapshot.get("score_anchors") or []
    return tuple((float(pair[0]), float(pair[1])) for pair in raw)


def _context_note(assessment: RiskAssessment) -> str | None:
    """Name the context factors that are currently amplifying the score."""

    factors = []
    uplift = assessment.uplift
    if uplift.environment_multiplier > 1.0:
        factors.append(f"environment ({assessment.context.environment.value}, x{uplift.environment_multiplier:g})")
    if uplift.exposure_multiplier > 1.0:
        factors.append(f"exposure ({assessment.context.exposure.value}, x{uplift.exposure_multiplier:g})")
    if uplift.change_multiplier > 1.0:
        factors.append(f"change status ({assessment.context.change_status.value}, x{uplift.change_multiplier:g})")

    if not factors:
        return "No context factor is amplifying this score; all three are at their neutral baseline."
    note = (
        "Context is amplifying this score via "
        + ", ".join(factors)
        + f", for a combined uplift of x{uplift.capped:g}."
    )
    if uplift.was_capped:
        note += f" The uncapped product would have been x{uplift.uncapped:.4f}, limited by the configured cap."
    return note


def context_alternatives(assessment: RiskAssessment) -> tuple[dict, ...]:
    """What the score would be under other deployment contexts.

    Reported for completeness so a team can see how much of the score is
    context-driven. Not a remediation route: XPRisk does not suggest reducing
    exposure or promoting to production to move a deployment through a gate.
    """

    cap = float(assessment.settings_snapshot.get("context_uplift_cap", 1.0))
    results = []
    for environment in Environment:
        for exposure in Exposure:
            for change in ChangeStatus:
                product = (
                    _multiplier(assessment, "environment_multipliers", environment.value)
                    * _multiplier(assessment, "exposure_multipliers", exposure.value)
                    * _multiplier(assessment, "change_multipliers", change.value)
                )
                capped = min(product, cap)
                score = min(100.0, assessment.base_score * capped)
                results.append(
                    {
                        "environment": environment.value,
                        "exposure": exposure.value,
                        "change_status": change.value,
                        "multiplier": round(capped, 4),
                        "score": round(score, 4),
                    }
                )
    return tuple(results)


def _multiplier(assessment: RiskAssessment, table: str, key: str) -> float:
    values = assessment.settings_snapshot.get(table) or {}
    return float(values.get(key, 1.0))