"""Contributor selection and ranking (Phase 11).

Turns the engine's contribution breakdown into the ordered list of reasons that
actually moved the score.

The rule this module enforces
-----------------------------
A finding that contributed nothing cannot appear as a reason, and a context
factor that was not applicable cannot be blamed. Explanations are assembled
*only* from :class:`risk_engine.engine.RiskAssessment` fields, so the ranking
cannot invent, round away or embellish an influence the engine did not apply.

Two kinds of contributor exist and they are not comparable in the same units:

* ``FINDING`` contributors, measured in raw risk units. These are the findings
  that accumulated into the base score.
* ``CONTEXT`` contributors, measured as multipliers. These amplified an
  already-computed base score and did so exactly once.

They are kept separate rather than merged into one ranked list, because a
finding worth 13.0 raw units and a context multiplier of 1.4 are not the same
kind of statement. Presenting them in a single "top 5" list would imply a
comparability that does not exist.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Sequence

from risk_engine.context import Environment, Exposure, ChangeStatus
from risk_engine.engine import FindingContribution, RiskAssessment

__all__ = [
    "ContributorKind",
    "FindingContributor",
    "ContextContributor",
    "select_finding_contributors",
    "select_context_contributors",
    "dominant_category",
    "severity_counts",
]


class ContributorKind(str, Enum):
    FINDING = "FINDING"
    CONTEXT = "CONTEXT"


@dataclass(frozen=True)
class FindingContributor:
    """A finding ranked by how much raw risk it contributed."""

    kind: ContributorKind
    label: str
    location: str | None
    tool: str
    category: str
    severity: str
    raw_risk: float
    share_of_total: float
    severity_weight: float
    category_multiplier: float
    #: Rank by influence, 1 being the most influential finding.
    rank: int

    def to_dict(self) -> dict:
        return {
            "kind": self.kind.value,
            "rank": self.rank,
            "label": self.label,
            "location": self.location,
            "tool": self.tool,
            "category": self.category,
            "severity": self.severity,
            "raw_risk": self.raw_risk,
            "share_of_total": self.share_of_total,
            "severity_weight": self.severity_weight,
            "category_multiplier": self.category_multiplier,
        }


@dataclass(frozen=True)
class ContextContributor:
    """A context factor that amplified the base score."""

    kind: ContributorKind
    #: ``environment``, ``exposure`` or ``change_status``.
    factor: str
    value: str
    multiplier: float
    #: Multiplier this factor would have had at the neutral baseline of 1.0.
    baseline: float
    #: multiplier / baseline, i.e. 1.25 for an internet-facing 1.25.
    uplift_ratio: float
    applied: bool

    @property
    def amplified(self) -> bool:
        """True when this factor raised the score rather than leaving it alone."""

        return self.multiplier > self.baseline

    def to_dict(self) -> dict:
        return {
            "kind": self.kind.value,
            "factor": self.factor,
            "value": self.value,
            "multiplier": self.multiplier,
            "baseline": self.baseline,
            "uplift_ratio": self.uplift_ratio,
            "amplified": self.amplified,
            "applied": self.applied,
        }


def select_finding_contributors(
    assessment: RiskAssessment,
    limit: int = 5,
) -> tuple[FindingContributor, ...]:
    """The findings that contributed most, most influential first.

    Only findings with a positive contribution are returned. Findings worth
    zero raw risk (``INFO`` severity, for example) are real and remain visible
    in the findings list, but they did not move the score and must not be
    presented as having done so.

    ``limit`` is applied after filtering, so asking for 5 contributors can
    return fewer when fewer findings actually contributed.
    """

    contributing = assessment.contributing_findings
    selected = contributing[: max(0, limit)]

    return tuple(
        FindingContributor(
            kind=ContributorKind.FINDING,
            label=contribution.label,
            location=contribution.location,
            tool=contribution.tool,
            category=contribution.category.value,
            severity=contribution.severity.value,
            raw_risk=contribution.raw_risk,
            share_of_total=contribution.share_of_total,
            severity_weight=contribution.severity_weight,
            category_multiplier=contribution.category_multiplier,
            rank=index,
        )
        for index, contribution in enumerate(selected, start=1)
    )


def select_context_contributors(assessment: RiskAssessment) -> tuple[ContextContributor, ...]:
    """The three context factors, each with the multiplier it applied.

    All three are always returned, including ones that did not amplify. The
    explanation states what was applied and what was not, which is what lets a
    reader tell the difference between "internal exposure did not raise this"
    and "internal exposure was never considered".

    When the uplift cap bound, every factor is reported with its true
    multiplier and the explanation notes the cap separately, so the arithmetic
    a reader performs still reproduces the score.
    """

    uplift = assessment.uplift
    context = assessment.context
    baseline = 1.0

    specs = (
        ("environment", context.environment.value, uplift.environment_multiplier),
        ("exposure", context.exposure.value, uplift.exposure_multiplier),
        ("change_status", context.change_status.value, uplift.change_multiplier),
    )

    return tuple(
        ContextContributor(
            kind=ContributorKind.CONTEXT,
            factor=factor,
            value=value,
            multiplier=multiplier,
            baseline=baseline,
            uplift_ratio=multiplier / baseline,
            applied=True,
        )
        for factor, value, multiplier in specs
    )


def dominant_category(assessment: RiskAssessment) -> str | None:
    """The category contributing the most raw risk, or ``None`` if there is none."""

    totals: dict[str, float] = {}
    for contribution in assessment.contributions:
        totals[contribution.category.value] = totals.get(contribution.category.value, 0.0) + contribution.raw_risk

    if not totals or max(totals.values()) <= 0.0:
        return None

    best_value = max(totals.values())
    for category in sorted(totals):
        if totals[category] == best_value:
            return category
    return None


def category_raw_risk(assessment: RiskAssessment) -> dict[str, float]:
    """Raw risk attributable to each category, for the explanation's breakdown."""

    totals: dict[str, float] = {}
    for contribution in assessment.contributions:
        totals[contribution.category.value] = totals.get(contribution.category.value, 0.0) + contribution.raw_risk
    return dict(sorted(totals.items(), key=lambda kv: (-kv[1], kv[0])))


def severity_counts(assessment: RiskAssessment) -> dict[str, int]:
    """Finding counts per severity, highest severity first."""

    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    counts = assessment.severity_breakdown
    ordered = {name: counts[name] for name in order if counts.get(name)}
    for name in sorted(counts):
        if name not in ordered:
            ordered[name] = counts[name]
    return ordered