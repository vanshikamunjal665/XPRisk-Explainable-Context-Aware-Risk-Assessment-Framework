"""Risk engine orchestration (Phase 9).

Findings plus context in; a score, a decision, and a full contribution
breakdown out.

Why the breakdown is the point
------------------------------
The breakdown is not a debugging aid that happens to be useful. It is the
contract that :mod:`explainability` consumes. Every number in a published
explanation has to be a number this module actually used, which means the
engine has to emit per-finding and per-factor contributions rather than only a
final score.

Concretely, a :class:`RiskAssessment` carries enough information to reconstruct
the score by hand::

    sum(finding.raw_risk)            == total_raw
    interpolate(total_raw, anchors)  == base_score
    base_score * uplift.capped       == risk_score (before clamping)
    thresholds.decide(risk_score)    == decision

:mod:`explainability` renders exactly those fields, and
``tests/test_explainability.py`` re-derives the score from them. If the engine
and an explanation ever disagree, a test fails rather than a user being
misinformed.

Determinism
-----------
No clock reads and no randomness. ``risk_score`` is rounded to four decimal
places at the end purely so that JSON round-trips and hand-arithmetic agree;
the underlying computation is untouched by this and the pre-rounding value is
retained in :attr:`RiskAssessment.risk_score_unrounded`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Sequence

from normalizer.models import Category, Severity, XPRiskFinding
from risk_engine.context import ContextModel, DEFAULT_CONTEXT_MODEL, DeploymentContext
from risk_engine.scoring import (
    ContextUplift,
    clamp,
    compute_context_uplift,
    finding_raw_risk,
    interpolate_score,
)
from risk_engine.settings import DEFAULT_RISK_SETTINGS, RiskSettings
from risk_engine.thresholds import Decision, Thresholds

__all__ = [
    "FindingContribution",
    "RiskAssessment",
    "RiskEngine",
    "assess_risk",
]

#: Decimal places the published score is rounded to.
SCORE_PRECISION = 4


@dataclass(frozen=True)
class FindingContribution:
    """One finding's exact contribution to the score."""

    finding_id: str
    tool: str
    category: Category
    severity: Severity
    severity_weight: float
    category_multiplier: float
    raw_risk: float
    #: Share of total raw risk, in [0, 1]. Zero total raw yields 0 for all.
    share_of_total: float
    #: Short human-readable handle for the explanation, e.g. "CVE-2021-1234".
    label: str
    location: str | None

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "tool": self.tool,
            "category": self.category.value,
            "severity": self.severity.value,
            "severity_weight": self.severity_weight,
            "category_multiplier": self.category_multiplier,
            "raw_risk": self.raw_risk,
            "share_of_total": self.share_of_total,
            "label": self.label,
            "location": self.location,
        }


@dataclass(frozen=True)
class RiskAssessment:
    """The complete, auditable result of one assessment."""

    risk_score: float
    risk_score_unrounded: float
    base_score: float
    total_raw: float
    decision: Decision
    context: DeploymentContext
    uplift: ContextUplift
    contributions: tuple[FindingContribution, ...]
    thresholds: Thresholds
    severity_breakdown: dict[str, int] = field(default_factory=dict)
    category_breakdown: dict[str, int] = field(default_factory=dict)
    finding_count: int = 0
    settings_snapshot: dict = field(default_factory=dict)

    # -- derived views used by the explanation layer -----------------------

    @property
    def ranked_contributions(self) -> tuple[FindingContribution, ...]:
        """Contributions ordered by influence, highest first.

        Ties break on ``finding_id`` so the order is stable across runs and
        across equal-scoring findings. A finding with zero raw risk sorts last
        but is retained: it is still shown in the explanation as "no
        contribution" rather than silently disappearing.
        """

        return tuple(
            sorted(
                self.contributions,
                key=lambda c: (-c.raw_risk, c.finding_id),
            )
        )

    @property
    def contributing_findings(self) -> tuple[FindingContribution, ...]:
        """Only findings that actually moved the score."""

        return tuple(c for c in self.ranked_contributions if c.raw_risk > 0.0)

    def distance_to_edges(self) -> dict[str, float]:
        return self.thresholds.distance_to_edge(self.risk_score)

    def top_categories(self, limit: int = 3) -> list[tuple[str, int]]:
        ordered = sorted(self.category_breakdown.items(), key=lambda kv: (-kv[1], kv[0]))
        return ordered[:limit]

    def to_dict(self) -> dict:
        return {
            "risk_score": self.risk_score,
            "base_score": self.base_score,
            "total_raw": self.total_raw,
            "decision": self.decision.value,
            "context": self.context.to_dict(),
            "uplift": self.uplift.to_dict(),
            "contributions": [c.to_dict() for c in self.ranked_contributions],
            "thresholds": self.thresholds.to_dict(),
            "severity_breakdown": dict(self.severity_breakdown),
            "category_breakdown": dict(self.category_breakdown),
            "finding_count": self.finding_count,
            "distance_to_edges": self.distance_to_edges(),
        }


def _label_for(finding: XPRiskFinding) -> str:
    """A short, stable handle for the explanation to name the finding by."""

    return (
        finding.finding_id
        or finding.resource
        or finding.description
        or finding.id
    )


def _location_for(finding: XPRiskFinding) -> str | None:
    if finding.file and finding.line:
        return f"{finding.file}:{finding.line}"
    if finding.file:
        return finding.file
    if finding.resource:
        return finding.resource
    return None


class RiskEngine:
    """Scores a set of findings under a deployment context.

    Stateless apart from its immutable settings, so one instance can be reused
    across requests without risk of cross-contamination.
    """

    def __init__(
        self,
        settings: RiskSettings | None = None,
        *,
        context_model: ContextModel | None = None,
    ) -> None:
        self.settings = settings or DEFAULT_RISK_SETTINGS
        self.thresholds = Thresholds.from_settings(self.settings)
        self.context_model = context_model or DEFAULT_CONTEXT_MODEL

    def assess(
        self,
        findings: Iterable[XPRiskFinding],
        context: DeploymentContext,
    ) -> RiskAssessment:
        """Score ``findings`` under ``context`` and explain the arithmetic."""

        ordered = sorted(findings, key=lambda f: f.id)
        total_raw = 0.0
        raw_values: list[float] = []
        for finding in ordered:
            value = finding_raw_risk(finding, self.settings)
            raw_values.append(value)
            total_raw += value

        base_score = interpolate_score(total_raw, self.settings.score_anchors)
        uplift = compute_context_uplift(context, self.settings)
        raw_score = base_score * uplift.capped
        risk_score = clamp(raw_score)

        contributions = tuple(
            FindingContribution(
                finding_id=finding.id,
                tool=finding.tool,
                category=finding.category,
                severity=finding.severity,
                severity_weight=self.settings.severity_weight_for(finding.severity),
                category_multiplier=self.settings.category_multiplier_for(finding.category),
                raw_risk=value,
                share_of_total=(value / total_raw) if total_raw > 0.0 else 0.0,
                label=_label_for(finding),
                location=_location_for(finding),
            )
            for finding, value in zip(ordered, raw_values)
        )

        severity_breakdown: dict[str, int] = {}
        category_breakdown: dict[str, int] = {}
        for finding in ordered:
            severity_breakdown[finding.severity.value] = severity_breakdown.get(finding.severity.value, 0) + 1
            category_breakdown[finding.category.value] = category_breakdown.get(finding.category.value, 0) + 1

        return RiskAssessment(
            risk_score=round(risk_score, SCORE_PRECISION),
            risk_score_unrounded=risk_score,
            base_score=base_score,
            total_raw=total_raw,
            decision=self.thresholds.decide(risk_score),
            context=context,
            uplift=uplift,
            contributions=contributions,
            thresholds=self.thresholds,
            severity_breakdown=severity_breakdown,
            category_breakdown=category_breakdown,
            finding_count=len(ordered),
            settings_snapshot=self.settings.to_dict(),
        )

    def assess_from_strings(
        self,
        findings: Iterable[XPRiskFinding],
        *,
        environment: str,
        exposure: str,
        change_status: str,
    ) -> RiskAssessment:
        """Convenience wrapper that resolves the context vocabulary.

        Useful at the API boundary, where environment, exposure and change
        status arrive as request fields or environment variables rather than as
        already-validated enums.
        """

        context = self.context_model.build(
            environment=environment,
            exposure=exposure,
            change_status=change_status,
        )
        return self.assess(findings, context)


def assess_risk(
    findings: Iterable[XPRiskFinding],
    context: DeploymentContext,
    settings: RiskSettings | None = None,
) -> RiskAssessment:
    """One-shot convenience wrapper around :class:`RiskEngine`."""

    return RiskEngine(settings).assess(findings, context)