"""Decision thresholds and the score-to-decision mapping (Phase 10).

Turns a 0-100 risk score into one of three deployment recommendations.

    SAFE     the pipeline may proceed
    WARNING  the pipeline may proceed, but a human should look
    BLOCK    the pipeline must not proceed

Band edges
----------
Bands are half-open, ``[lower, upper)``, except BLOCK which is closed at the
top, so every score maps to exactly one decision with no overlap and no gap::

    SAFE      0 <= score <  threshold_safe      (default 30)
    WARNING   threshold_safe <= score < threshold_warning  (default 70)
    BLOCK     threshold_warning <= score <= 100

The band a score falls in is reported alongside the score, and the explanation
states how far the score sits from the nearest edge. A decision that cannot be
traced back to a threshold is not auditable, so :func:`distance_to_edge` exists
specifically to make "why not the other band" answerable.

Why three bands and not two
---------------------------
A two-band model has to answer "is this bad?" with a yes/no, which forces the
threshold to sit wherever the author felt about the risk appetite. Splitting the
middle lets XPRisk express the genuinely common case: findings that are real
and worth fixing, but do not justify stopping a deployment. That is what makes
WARNING useful rather than decorative, and it is what the integration
scenarios in ``tests/README.md`` exercise.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

__all__ = [
    "Decision",
    "Thresholds",
    "DEFAULT_THRESHOLDS",
    "band_for_score",
]


class Decision(str, Enum):
    """The deployment recommendation produced from a risk score."""

    SAFE = "SAFE"
    WARNING = "WARNING"
    BLOCK = "BLOCK"

    @property
    def allows_deployment(self) -> bool:
        """Whether a pipeline gate should permit the deployment to continue."""

        return self in (Decision.SAFE, Decision.WARNING)

    @property
    def requires_human_review(self) -> bool:
        return self is Decision.WARNING

    @property
    def blocks_deployment(self) -> bool:
        return self is Decision.BLOCK

    @property
    def severity_rank(self) -> int:
        """Ordering helper: higher means a more restrictive decision."""

        return {Decision.SAFE: 0, Decision.WARNING: 1, Decision.BLOCK: 2}[self]


def band_for_score(score: float, *, safe: float, warning: float) -> Decision:
    """Map a score onto a decision band using explicit edges.

    Kept as a module-level function so the mapping can be tested and reasoned
    about without constructing a :class:`Thresholds` object.
    """

    if score < safe:
        return Decision.SAFE
    if score < warning:
        return Decision.WARNING
    return Decision.BLOCK


@dataclass(frozen=True)
class Thresholds:
    """The two band edges, plus the mapping and its supporting explanations."""

    safe: float = 30.0
    warning: float = 70.0

    def __post_init__(self) -> None:
        if not 0.0 <= self.safe < self.warning <= 100.0:
            raise ValueError(
                f"thresholds must satisfy 0 <= safe < warning <= 100, got safe={self.safe} warning={self.warning}"
            )

    def decide(self, score: float) -> Decision:
        """Return the decision for ``score``."""

        return band_for_score(score, safe=self.safe, warning=self.warning)

    def distance_to_edge(self, score: float) -> dict[str, float]:
        """How far ``score`` sits from each band edge.

        Positive means inside the band by that margin; negative means the score
        would have to move that far to cross the edge. Used by the explanation
        to say "this BLOCK is 6.2 points above the WARNING edge", which is the
        difference between an actionable recommendation and a bare label.
        """

        return {
            "from_safe_edge": float(score) - self.safe,
            "from_warning_edge": float(score) - self.warning,
        }

    def to_dict(self) -> dict[str, float]:
        return {"safe": self.safe, "warning": self.warning}

    @classmethod
    def from_settings(cls, settings) -> "Thresholds":
        """Build thresholds from a :class:`risk_engine.settings.RiskSettings`."""

        return cls(safe=settings.threshold_safe, warning=settings.threshold_warning)


#: The default bands. Construct :class:`Thresholds` directly to override.
DEFAULT_THRESHOLDS = Thresholds()