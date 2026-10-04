"""Configurable defaults for the risk model (Phase 9).

Every number the risk engine uses lives here as a plain default. This module
deliberately reads **nothing** from the environment.

Why no environment access
-------------------------
``risk_engine`` is a domain package. Phases 6 and 8 both established that
domain packages stay free of ambient configuration: the normalizer keeps its
Gitleaks severity policy as a module constant, and ``ContextModel`` accepts
vocabulary through its constructor. Reading ``os.environ`` here would be the
first place the dependency pointed the wrong way, and it would make the engine
untestable without mutating process state.

The contract is therefore:

* :mod:`risk_engine.settings` holds defaults. Override them by constructing a
  :class:`RiskSettings` with different values.
* :mod:`backend.app.config` reads the ``XPRISK_*`` environment variables and
  constructs a :class:`RiskSettings`, injecting it into the engine.

That keeps one source of truth (``.env.example``) without leaking process state
into the domain layer, and it is what makes the comparative study in
``docs/risk-model.md`` possible: the same engine and the same findings can be
scored under different policies without editing code.

These values are prototype design decisions, not empirically derived
constants. See ``docs/risk-model.md`` for the full rationale and limitations.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from types import MappingProxyType
from typing import Mapping

from normalizer.models import Category, Severity
from risk_engine.context import ChangeStatus, Environment, Exposure
from risk_engine.severity import DEFAULT_SEVERITY_WEIGHTS, SeverityWeights

__all__ = [
    "RiskSettings",
    "DEFAULT_RISK_SETTINGS",
    "DEFAULT_CATEGORY_MULTIPLIERS",
    "DEFAULT_ENVIRONMENT_MULTIPLIERS",
    "DEFAULT_EXPOSURE_MULTIPLIERS",
    "DEFAULT_CHANGE_MULTIPLIERS",
    "DEFAULT_SCORE_ANCHORS",
]


def _freeze(mapping: Mapping) -> Mapping:
    return MappingProxyType(dict(mapping))


#: How much each finding category amplifies its severity weight.
#:
#: Rationale: a leaked secret is directly exploitable by anyone who obtains it,
#: so it is weighted above the others. A vulnerable dependency needs a reachable
#: vulnerable code path to matter, which is slightly less direct than a
#: credential in a repository. IaC and source-code issues are configuration and
#: hygiene risks, weighted just above baseline.
DEFAULT_CATEGORY_MULTIPLIERS: Mapping[Category, float] = _freeze(
    {
        Category.SECRET: 1.3,
        Category.CONTAINER: 1.2,
        Category.IAC: 1.1,
        Category.SOURCE_CODE: 1.0,
    }
)

#: How much the deployment environment amplifies the base score.
#:
#: Rationale: the same finding matters more the closer it gets to real users
#: and real data. Development is the baseline at 1.0 so that a development scan
#: reads as "the score of these findings", not "a penalty for where you work".
DEFAULT_ENVIRONMENT_MULTIPLIERS: Mapping[Environment, float] = _freeze(
    {
        Environment.DEVELOPMENT: 1.0,
        Environment.STAGING: 1.15,
        Environment.PRODUCTION: 1.4,
    }
)

#: Whether the deployed resource is reachable from the public internet.
#:
#: Rationale: internet-facing resources are reachable by unauthenticated
#: attackers, which removes the need for a prior foothold. This is the single
#: strongest context signal in the model.
DEFAULT_EXPOSURE_MULTIPLIERS: Mapping[Exposure, float] = _freeze(
    {
        Exposure.INTERNAL: 1.0,
        Exposure.INTERNET_FACING: 1.25,
    }
)

#: Whether the finding is newly introduced by this change.
#:
#: Rationale: a new finding is this pipeline run's responsibility and can still
#: be prevented before merge. A pre-existing one is inherited and often cannot
#: be fixed in the same change, so it is not amplified.
DEFAULT_CHANGE_MULTIPLIERS: Mapping[ChangeStatus, float] = _freeze(
    {
        ChangeStatus.EXISTING: 1.0,
        ChangeStatus.NEW: 1.15,
    }
)

#: Piecewise-linear mapping from raw accumulated risk to a 0-100 base score.
#:
#: Read as ``raw:score`` pairs. Values between two anchors are interpolated
#: linearly; anything above the final anchor saturates at 100.
#:
#: The shape is deliberately sub-linear: the gap from 0 to 8 raw is worth 10
#: points, while the gap from 140 to 220 raw is worth only 10 points. This is
#: what prevents a large repository from pinning itself permanently at BLOCK
#: and makes the score comparable across differently sized codebases. It also
#: means diminishing severity returns are encoded rather than assumed.
DEFAULT_SCORE_ANCHORS: tuple[tuple[float, float], ...] = (
    (0.0, 0.0),
    (8.0, 10.0),
    (20.0, 30.0),
    (45.0, 55.0),
    (80.0, 75.0),
    (140.0, 90.0),
    (220.0, 100.0),
)

#: Upper bound on the combined context multiplier.
#:
#: Without a cap, production + internet-facing + new multiplies to 2.01 and the
#: score saturates at 100 for any non-trivial finding set, which destroys the
#: model's ability to rank two different production deployments. Capping at
#: 1.6 keeps context influential while leaving headroom to distinguish
#: contexts above it. The cap binding is itself reported, so an explanation can
#: say the uplift was limited.
DEFAULT_CONTEXT_UPLIFT_CAP: float = 1.6

#: Upper edge of the SAFE band.
DEFAULT_THRESHOLD_SAFE: float = 30.0
#: Upper edge of the WARNING band. At or above this the decision is BLOCK.
DEFAULT_THRESHOLD_WARNING: float = 70.0


@dataclass(frozen=True)
class RiskSettings:
    """Complete, validated configuration for one risk assessment.

    Frozen and validated at construction so that an invalid policy fails when
    the engine is built rather than producing a nonsense score later.
    """

    severity_weights: SeverityWeights = field(default_factory=SeverityWeights)
    category_multipliers: Mapping[Category, float] = field(
        default_factory=lambda: DEFAULT_CATEGORY_MULTIPLIERS
    )
    environment_multipliers: Mapping[Environment, float] = field(
        default_factory=lambda: DEFAULT_ENVIRONMENT_MULTIPLIERS
    )
    exposure_multipliers: Mapping[Exposure, float] = field(
        default_factory=lambda: DEFAULT_EXPOSURE_MULTIPLIERS
    )
    change_multipliers: Mapping[ChangeStatus, float] = field(
        default_factory=lambda: DEFAULT_CHANGE_MULTIPLIERS
    )
    score_anchors: tuple[tuple[float, float], ...] = DEFAULT_SCORE_ANCHORS
    context_uplift_cap: float = DEFAULT_CONTEXT_UPLIFT_CAP
    threshold_safe: float = DEFAULT_THRESHOLD_SAFE
    threshold_warning: float = DEFAULT_THRESHOLD_WARNING

    def __post_init__(self) -> None:
        for name in (
            "category_multipliers",
            "environment_multipliers",
            "exposure_multipliers",
            "change_multipliers",
        ):
            mapping = getattr(self, name)
            object.__setattr__(self, name, _freeze(mapping))
            for key, value in mapping.items():
                if value < 0:
                    raise ValueError(f"negative multiplier for {key}: {value}")

        anchors = tuple((float(raw), float(score)) for raw, score in self.score_anchors)
        if len(anchors) < 2:
            raise ValueError("score_anchors needs at least two points")
        for (raw_a, score_a), (raw_b, score_b) in zip(anchors, anchors[1:]):
            if raw_b <= raw_a:
                raise ValueError(f"score_anchors raw values must increase: {raw_a} -> {raw_b}")
            if score_b <= score_a:
                raise ValueError(f"score_anchors scores must increase: {score_a} -> {score_b}")
        object.__setattr__(self, "score_anchors", anchors)

        if self.score_anchors[0][0] != 0.0 or self.score_anchors[0][1] != 0.0:
            raise ValueError("score_anchors must start at 0:0 so no finding scores 0 risk")
        if self.score_anchors[-1][1] != 100.0:
            raise ValueError("score_anchors must end at score 100 so the scale is 0-100")

        if self.context_uplift_cap < 1.0:
            raise ValueError(f"context_uplift_cap must be >= 1.0, got {self.context_uplift_cap}")
        if not 0.0 <= self.threshold_safe < self.threshold_warning <= 100.0:
            raise ValueError(
                "thresholds must satisfy 0 <= safe < warning <= 100, got "
                f"safe={self.threshold_safe} warning={self.threshold_warning}"
            )

        missing_env = {e for e in Environment} - set(self.environment_multipliers)
        if missing_env:
            raise ValueError(f"environment_multipliers missing: {sorted(m.value for m in missing_env)}")
        missing_exp = {e for e in Exposure} - set(self.exposure_multipliers)
        if missing_exp:
            raise ValueError(f"exposure_multipliers missing: {sorted(m.value for m in missing_exp)}")
        missing_chg = {c for c in ChangeStatus} - set(self.change_multipliers)
        if missing_chg:
            raise ValueError(f"change_multipliers missing: {sorted(m.value for m in missing_chg)}")
        missing_cat = {c for c in Category} - set(self.category_multipliers)
        if missing_cat:
            raise ValueError(f"category_multipliers missing: {sorted(m.value for m in missing_cat)}")

    # -- lookups ------------------------------------------------------------

    def category_multiplier_for(self, category: Category | str) -> float:
        """Category multiplier, defaulting to 1.0 for an unknown category.

        A finding whose category is not in the table is neither amplified nor
        penalised; it still contributes its severity weight.
        """

        key = _coerce_enum(Category, category)
        return 1.0 if key is None else float(self.category_multipliers.get(key, 1.0))

    def severity_weight_for(self, severity: Severity | str | None) -> float:
        return self.severity_weights.weight_for(severity)

    def environment_multiplier_for(self, environment: Environment | str) -> float:
        key = _coerce_enum(Environment, environment)
        if key is None:
            raise ValueError(f"unknown environment: {environment!r}")
        return float(self.environment_multipliers[key])

    def exposure_multiplier_for(self, exposure: Exposure | str) -> float:
        key = _coerce_enum(Exposure, exposure)
        if key is None:
            raise ValueError(f"unknown exposure: {exposure!r}")
        return float(self.exposure_multipliers[key])

    def change_multiplier_for(self, change_status: ChangeStatus | str) -> float:
        key = _coerce_enum(ChangeStatus, change_status)
        if key is None:
            raise ValueError(f"unknown change_status: {change_status!r}")
        return float(self.change_multipliers[key])

    # -- derived views ------------------------------------------------------

    def with_severity_weights(self, weights: Mapping[Severity, float]) -> "RiskSettings":
        return replace(self, severity_weights=SeverityWeights(weights=weights))

    def anchors_as_pairs(self) -> list[tuple[float, float]]:
        return [(raw, score) for raw, score in self.score_anchors]

    def to_dict(self) -> dict:
        """A JSON-serialisable snapshot of the active policy.

        Included in the explanation payload so a stored score can be traced
        back to the exact constants that produced it.
        """

        return {
            "severity_weights": self.severity_weights.to_dict(),
            "category_multipliers": {k.value: v for k, v in self.category_multipliers.items()},
            "environment_multipliers": {k.value: v for k, v in self.environment_multipliers.items()},
            "exposure_multipliers": {k.value: v for k, v in self.exposure_multipliers.items()},
            "change_multipliers": {k.value: v for k, v in self.change_multipliers.items()},
            "score_anchors": [list(pair) for pair in self.anchors_as_pairs()],
            "context_uplift_cap": self.context_uplift_cap,
            "threshold_safe": self.threshold_safe,
            "threshold_warning": self.threshold_warning,
        }


def _coerce_enum(enum_cls, value):
    """Best-effort conversion of a value to ``enum_cls``, or ``None``."""

    if isinstance(value, enum_cls):
        return value
    text = str(value).strip()
    for member in enum_cls:
        if member.value == text or member.value.lower() == text.lower() or member.name == text.upper():
            return member
    return None


#: The default policy. Construct :class:`RiskSettings` directly to override it.
DEFAULT_RISK_SETTINGS = RiskSettings()