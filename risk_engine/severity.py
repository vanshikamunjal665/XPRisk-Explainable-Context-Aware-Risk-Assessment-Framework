"""Severity enumeration and base severity weights (Phase 9).

The canonical :class:`Severity` enumeration lives in :mod:`normalizer.models`
because normalization is what produces severities. This module does not
redefine it; it re-exports it for convenience and adds the *weighting* that
turns a severity label into a number.

What the weights mean
---------------------
A severity weight answers: "how much raw risk does one finding of this
severity contribute, before any context is considered?" They are not
probabilities and they are not calibrated against incident data. They are an
ordered, roughly geometric progression chosen so that one CRITICAL finding
dominates a handful of LOW findings without erasing them.

========================  =====
Severity                  Weight
========================  =====
CRITICAL                  10.0
HIGH                       7.0
MEDIUM                     4.0
LOW                        1.0
INFO                       0.0
========================  =====

``INFO`` is weighted zero deliberately. An informational notice should be
visible in the findings list without inflating the deployment risk score; if it
did, a repository with many style advisories would score worse than one with a
single public bucket. It still contributes to the *count* shown in the
explanation, so nothing is hidden.

Nothing here reads the environment. See :mod:`risk_engine.settings` for the
full configurable surface and ``docs/risk-model.md`` for the rationale.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping

from normalizer.models import Severity

__all__ = [
    "DEFAULT_SEVERITY_WEIGHTS",
    "SeverityWeights",
    "Severity",
]


def _freeze(mapping: Mapping[Severity, float]) -> Mapping[Severity, float]:
    return MappingProxyType(dict(mapping))


#: Default base severity weights, overridable per deployment.
DEFAULT_SEVERITY_WEIGHTS: Mapping[Severity, float] = _freeze(
    {
        Severity.CRITICAL: 10.0,
        Severity.HIGH: 7.0,
        Severity.MEDIUM: 4.0,
        Severity.LOW: 1.0,
        Severity.INFO: 0.0,
    }
)


@dataclass(frozen=True)
class SeverityWeights:
    """A lookup from severity to raw risk weight.

    Frozen so that a settings object cannot be mutated after the engine has
    started producing scores. Determinism of the published score depends on the
    weights not changing mid-run.
    """

    weights: Mapping[Severity, float] = field(default=DEFAULT_SEVERITY_WEIGHTS)
    #: Weight used when a severity is absent from the table. Matches MEDIUM
    #: rather than LOW so that an unrecognised severity is never silently
    #: treated as harmless.
    fallback: float = 4.0

    def __post_init__(self) -> None:
        object.__setattr__(self, "weights", _freeze(self.weights))
        for severity, weight in self.weights.items():
            if weight < 0:
                raise ValueError(f"negative severity weight for {severity}: {weight}")

    def weight_for(self, severity: Severity | str | None) -> float:
        """Return the weight for ``severity``.

        Accepts the enum or its string form so callers holding raw scanner
        output do not have to convert first.
        """

        if severity is None:
            return self.fallback
        if isinstance(severity, Severity):
            key = severity
        else:
            try:
                key = Severity(str(severity).strip().upper())
            except ValueError:
                return self.fallback
        return self.weights.get(key, self.fallback)

    def to_dict(self) -> dict[str, float]:
        return {severity.value: weight for severity, weight in self.weights.items()}