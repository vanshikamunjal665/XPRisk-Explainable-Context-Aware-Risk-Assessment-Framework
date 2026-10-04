"""Tests for the score-to-decision mapping (Phase 10).

The bands are half-open so that every score maps to exactly one decision. The
boundary cases are where an off-by-one would silently reclassify deployments, so
they are pinned exactly rather than tested with loose comparisons.
"""

from __future__ import annotations

import sys

import pytest

sys.path.insert(0, ".")

from risk_engine.thresholds import (  # noqa: E402
    DEFAULT_THRESHOLDS,
    Decision,
    Thresholds,
    band_for_score,
)


def test_default_edges_match_the_configured_contract():
    assert DEFAULT_THRESHOLDS.safe == 30.0
    assert DEFAULT_THRESHOLDS.warning == 70.0


@pytest.mark.parametrize(
    "score, expected",
    [
        (0.0, Decision.SAFE),
        (0.1, Decision.SAFE),
        (29.999, Decision.SAFE),
        (30.0, Decision.WARNING),   # lower edge is inclusive
        (30.001, Decision.WARNING),
        (50.0, Decision.WARNING),
        (69.999, Decision.WARNING),
        (70.0, Decision.BLOCK),     # lower edge is inclusive
        (70.001, Decision.BLOCK),
        (99.999, Decision.BLOCK),
        (100.0, Decision.BLOCK),
    ],
)
def test_band_boundaries(score, expected):
    assert Thresholds().decide(score) is expected


def test_bands_are_exhaustive_and_disjoint():
    """Every score in 0-100 maps to exactly one decision; no gap, no overlap."""

    seen = {Thresholds().decide(s / 10.0) for s in range(0, 1001)}
    assert seen == {Decision.SAFE, Decision.WARNING, Decision.BLOCK}

    for step in range(0, 1000):
        lower = Thresholds().decide(step / 10.0)
        upper = Thresholds().decide((step + 1) / 10.0)
        assert lower.severity_rank <= upper.severity_rank, "bands must be monotone in score"


def test_band_is_monotone_in_score():
    ranks = [Thresholds().decide(s).severity_rank for s in range(0, 101)]
    assert ranks == sorted(ranks)


def test_module_level_function_matches_the_class():
    for score in (0.0, 29.9, 30.0, 69.9, 70.0, 100.0):
        assert band_for_score(score, safe=30.0, warning=70.0) is Thresholds().decide(score)


def test_custom_edges_are_honoured():
    t = Thresholds(safe=10.0, warning=20.0)
    assert t.decide(9.9) is Decision.SAFE
    assert t.decide(10.0) is Decision.WARNING
    assert t.decide(19.9) is Decision.WARNING
    assert t.decide(20.0) is Decision.BLOCK


@pytest.mark.parametrize(
    "safe, warning",
    [(70.0, 30.0), (-1.0, 70.0), (30.0, 101.0), (50.0, 50.0)],
)
def test_invalid_edges_are_rejected(safe, warning):
    """Inverted, negative or overlapping edges must fail at construction."""

    with pytest.raises(ValueError):
        Thresholds(safe=safe, warning=warning)


def test_distance_to_edge_signs():
    d = Thresholds().distance_to_edge(50.0)
    assert d["from_safe_edge"] == pytest.approx(20.0)   # above the SAFE edge
    assert d["from_warning_edge"] == pytest.approx(-20.0)  # below the WARNING edge

    blocked = Thresholds().distance_to_edge(90.0)
    assert blocked["from_warning_edge"] == pytest.approx(20.0)


def test_decision_helpers():
    assert Decision.SAFE.allows_deployment
    assert Decision.WARNING.allows_deployment
    assert not Decision.BLOCK.allows_deployment

    assert Decision.WARNING.requires_human_review
    assert not Decision.SAFE.requires_human_review
    assert not Decision.BLOCK.requires_human_review

    assert Decision.BLOCK.blocks_deployment
    assert not Decision.WARNING.blocks_deployment


def test_from_settings_reads_the_configured_edges():
    class Stub:
        threshold_safe = 25.0
        threshold_warning = 75.0

    t = Thresholds.from_settings(Stub())
    assert (t.safe, t.warning) == (25.0, 75.0)
    assert t.decide(24.9) is Decision.SAFE
    assert t.decide(25.0) is Decision.WARNING
    assert t.decide(75.0) is Decision.BLOCK


def test_to_dict_round_trips():
    assert Thresholds(safe=1.0, warning=2.0).to_dict() == {"safe": 1.0, "warning": 2.0}