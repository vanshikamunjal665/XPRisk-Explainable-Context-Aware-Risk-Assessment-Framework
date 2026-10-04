"""The XPRisk risk-scoring algorithm (Phase 9).

This is the research core: it turns canonical findings plus deployment context
into one deterministic 0-100 score.

The pipeline
------------
::

    for each finding:
        raw_risk = severity_weight[severity] x category_multiplier[category]

    total_raw          = sum(raw_risk)
    base_score         = interpolate(total_raw, anchors)        # 0-100, saturating
    context_multiplier = product of the three context factors, capped
    risk_score         = clamp(base_score x context_multiplier, 0, 100)
    decision           = thresholds.decide(risk_score)

Two properties matter more than the formula itself.

**Context is applied exactly once.** The three context factors are multiplied
together into a single multiplier and applied to the already-normalised base
score. They are deliberately not folded into the per-finding raw risk: doing so
would multiply context by the *number* of findings, so a large repository would
be punished for its size rather than for its risk. Applying context once, after
normalisation, keeps a score comparable between a two-file project and a
two-thousand-file one.

**The score is a pure function of its inputs.** No randomness, no clock reads,
no reliance on dictionary ordering, no dependence on the order findings arrive
in. ``total_raw`` is summed from a sorted sequence so that floating-point
addition is reproducible. The same findings and context always produce the same
score, which the test suite asserts directly: an unauditable score cannot be
explained, and this is the property the whole explainability layer rests on.

Anchor interpolation
--------------------
``score_anchors`` is a piecewise-linear curve from raw risk to score, read as
``(raw, score)`` pairs::

    0->0, 8->10, 20->30, 45->55, 80->75, 140->90, 220->100

Values between two anchors interpolate linearly. A raw value above the final
anchor saturates at 100 rather than extrapolating, because a score above 100
would be meaningless and an extrapolated one would rank repositories by size.

The curve is sub-linear by design. The first 8 raw units buy 10 points; the
last 80 units buy only 10. That encodes diminishing returns explicitly, and it
is what stops a large repository from being permanently pinned at BLOCK.

These constants are prototype design decisions, not empirically derived
values. ``docs/risk-model.md`` records that limitation explicitly.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence

from normalizer.models import Category, Severity, XPRiskFinding
from risk_engine.context import DeploymentContext
from risk_engine.settings import DEFAULT_RISK_SETTINGS, RiskSettings

__all__ = [
    "interpolate_score",
    "finding_raw_risk",
    "total_raw_risk",
    "ContextUplift",
    "compute_context_uplift",
    "clamp",
]


def clamp(value: float, low: float = 0.0, high: float = 100.0) -> float:
    """Constrain ``value`` to ``[low, high]``."""

    if value < low:
        return low
    if value > high:
        return high
    return value


def interpolate_score(raw: float, anchors: Sequence[tuple[float, float]]) -> float:
    """Map raw accumulated risk onto 0-100 using a piecewise-linear curve.

    Behaviour at the boundaries, which the tests pin exactly:

    * ``raw`` at or below the first anchor's raw value interpolates inside the
      first segment, so a small positive raw value scores slightly above zero.
    * ``raw`` exactly on an anchor returns that anchor's score, with no float
      drift from the surrounding arithmetic.
    * ``raw`` at or above the final anchor's raw value saturates at that
      anchor's score, which is validated to be 100.
    """

    if not anchors:
        raise ValueError("anchors must not be empty")
    if raw <= anchors[0][0]:
        lower_raw, lower_score = anchors[0]
        if lower_raw == raw:
            return lower_score
        upper_raw, upper_score = anchors[1]
        return lower_score + (raw - lower_raw) * (upper_score - lower_score) / (upper_raw - lower_raw)

    for (lower_raw, lower_score), (upper_raw, upper_score) in zip(anchors, anchors[1:]):
        if raw <= upper_raw:
            if raw == upper_raw:
                return upper_score
            return lower_score + (raw - lower_raw) * (upper_score - lower_score) / (upper_raw - lower_raw)

    return anchors[-1][1]


def finding_raw_risk(finding: XPRiskFinding, settings: RiskSettings | None = None) -> float:
    """Raw risk contributed by one finding, before normalisation or context."""

    settings = settings or DEFAULT_RISK_SETTINGS
    weight = settings.severity_weight_for(finding.severity)
    multiplier = settings.category_multiplier_for(finding.category)
    return weight * multiplier


def total_raw_risk(findings: Iterable[XPRiskFinding], settings: RiskSettings | None = None) -> float:
    """Sum raw risk over all findings, deterministically.

    The contributions are computed and then summed in a fixed order rather than
    in iteration order. With binary floating point, ``a + b + c`` can differ
    from ``c + b + a``, so sorting by finding id removes any dependence on the
    order the caller happened to supply.
    """

    settings = settings or DEFAULT_RISK_SETTINGS
    contributions = sorted(finding_raw_risk(f, settings) for f in findings)
    total = 0.0
    for value in contributions:
        total += value
    return total


@dataclass(frozen=True)
class ContextUplift:
    """The combined context multiplier and the factors behind it.

    Every field is kept, including the factors that were *not* applied and
    whether the cap bound, so the explanation can state the full picture rather
    than only the final multiplier.
    """

    environment_multiplier: float
    exposure_multiplier: float
    change_multiplier: float
    uncapped: float
    capped: float
    was_capped: bool

    def to_dict(self) -> dict:
        return {
            "environment_multiplier": self.environment_multiplier,
            "exposure_multiplier": self.exposure_multiplier,
            "change_multiplier": self.change_multiplier,
            "uncapped_multiplier": self.uncapped,
            "capped_multiplier": self.capped,
            "was_capped": self.was_capped,
        }


def compute_context_uplift(context: DeploymentContext, settings: RiskSettings | None = None) -> ContextUplift:
    """Multiply the three context factors and apply the uplift cap.

    The cap matters: production + internet-facing + new multiplies to 2.0125,
    which would saturate any non-trivial finding set to 100 and make two
    different production deployments impossible to rank. Capping at 1.6 keeps
    context influential while preserving headroom, and ``was_capped`` reports
    when it bound so an explanation never implies an uplift it did not apply.
    """

    settings = settings or DEFAULT_RISK_SETTINGS
    env = settings.environment_multiplier_for(context.environment)
    exposure = settings.exposure_multiplier_for(context.exposure)
    change = settings.change_multiplier_for(context.change_status)

    uncapped = env * exposure * change
    capped = min(uncapped, settings.context_uplift_cap)
    return ContextUplift(
        environment_multiplier=env,
        exposure_multiplier=exposure,
        change_multiplier=change,
        uncapped=uncapped,
        capped=capped,
        was_capped=uncapped > settings.context_uplift_cap,
    )