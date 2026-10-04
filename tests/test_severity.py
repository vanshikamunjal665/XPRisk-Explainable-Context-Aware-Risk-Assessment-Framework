"""Tests for severity weighting (Phase 9).

The weights are the first place the risk model turns a label into a number, so
the tests here pin the properties the rest of the model relies on: the ordering
is monotone, INFO contributes nothing, and an unrecognised severity is never
treated as harmless.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, ".")

from normalizer.models import Severity  # noqa: E402
from risk_engine.severity import (  # noqa: E402
    DEFAULT_SEVERITY_WEIGHTS,
    SeverityWeights,
)

SEVERITY_ORDER = [
    Severity.INFO,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
]


def test_default_weights_are_the_documented_values():
    assert DEFAULT_SEVERITY_WEIGHTS[Severity.CRITICAL] == 10.0
    assert DEFAULT_SEVERITY_WEIGHTS[Severity.HIGH] == 7.0
    assert DEFAULT_SEVERITY_WEIGHTS[Severity.MEDIUM] == 4.0
    assert DEFAULT_SEVERITY_WEIGHTS[Severity.LOW] == 1.0
    assert DEFAULT_SEVERITY_WEIGHTS[Severity.INFO] == 0.0


def test_weights_are_monotonically_ordered():
    """More severe must never score lower. The model depends on this."""

    values = [DEFAULT_SEVERITY_WEIGHTS[s] for s in SEVERITY_ORDER]
    assert values == sorted(values), f"weights are not monotone: {values}"


def test_info_contributes_nothing():
    """INFO must not inflate the score, but must still be countable."""

    assert DEFAULT_SEVERITY_WEIGHTS[Severity.INFO] == 0.0


def test_weight_for_accepts_enum_and_string():
    weights = SeverityWeights()
    assert weights.weight_for(Severity.HIGH) == 7.0
    assert weights.weight_for("HIGH") == 7.0
    assert weights.weight_for("high") == 7.0
    assert weights.weight_for("  High  ") == 7.0


@pytest.mark.parametrize("value", [None, "", "   ", "NOT_A_SEVERITY", "critical-ish"])
def test_unknown_severity_falls_back_to_medium(value):
    """An unrecognised severity must never be treated as harmless.

    Falling back to MEDIUM rather than LOW is deliberate: a scanner reporting a
    vocabulary XPRisk does not know should be treated as mid-risk, not ignored.
    """

    assert SeverityWeights().weight_for(value) == 4.0


def test_fallback_is_configurable():
    weights = SeverityWeights(weights={Severity.LOW: 1.0}, fallback=99.0)
    assert weights.weight_for(Severity.CRITICAL) == 99.0


def test_weights_are_immutable():
    """A settings object must not change mid-run and alter published scores."""

    weights = SeverityWeights()
    with pytest.raises(TypeError):
        weights.weights[Severity.HIGH] = 999.0  # type: ignore[index]


def test_negative_weight_is_rejected():
    with pytest.raises(ValueError, match="negative severity weight"):
        SeverityWeights(weights={Severity.HIGH: -1.0})


def test_to_dict_uses_severity_names():
    assert SeverityWeights().to_dict() == {
        "CRITICAL": 10.0,
        "HIGH": 7.0,
        "MEDIUM": 4.0,
        "LOW": 1.0,
        "INFO": 0.0,
    }