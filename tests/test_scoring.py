"""Tests for the scoring algorithm (Phase 9).

The anchor interpolation is the piece most likely to look correct and be subtly
wrong, so its boundary behaviour is pinned exactly: on an anchor, between
anchors, below the first anchor, and above the last one. The determinism and
context-applied-once properties are pinned too, because the whole explainability
layer depends on them.
"""

from __future__ import annotations

import sys

import pytest

sys.path.insert(0, ".")

from normalizer.models import Category, Severity, XPRiskFinding  # noqa: E402
from risk_engine.context import (  # noqa: E402
    ChangeStatus,
    ContextModel,
    Environment,
    Exposure,
)
from risk_engine.scoring import (  # noqa: E402
    clamp,
    compute_context_uplift,
    finding_raw_risk,
    interpolate_score,
    total_raw_risk,
)
from risk_engine.settings import DEFAULT_RISK_SETTINGS, DEFAULT_SCORE_ANCHORS  # noqa: E402

ANCHORS = DEFAULT_SCORE_ANCHORS
MODEL = ContextModel()


def make(idx: int, severity: Severity, category: Category = Category.IAC, **kw) -> XPRiskFinding:
    payload = {
        "id": f"xprisk-{idx:04d}",
        "tool": "checkov",
        "category": category,
        "severity": severity,
        "finding_id": f"CKV_{idx}",
        "resource": f"res_{idx}",
        "file": "main.tf",
        "line": idx,
    }
    payload.update(kw)
    return XPRiskFinding(**payload)


# -- anchors ----------------------------------------------------------------


@pytest.mark.parametrize("raw, score", ANCHORS)
def test_interpolation_returns_exact_anchor_scores(raw, score):
    """Landing exactly on an anchor must return that anchor's score, with no drift."""

    assert interpolate_score(raw, ANCHORS) == pytest.approx(score)


def test_interpolation_is_linear_between_anchors():
    for (raw_a, score_a), (raw_b, score_b) in zip(ANCHORS, ANCHORS[1:]):
        midpoint = (raw_a + raw_b) / 2.0
        expected = (score_a + score_b) / 2.0
        assert interpolate_score(midpoint, ANCHORS) == pytest.approx(expected)

        quarter = raw_a + (raw_b - raw_a) * 0.25
        expected_q = score_a + (score_b - score_a) * 0.25
        assert interpolate_score(quarter, ANCHORS) == pytest.approx(expected_q)


def test_interpolation_below_first_anchor_uses_first_segment():
    assert interpolate_score(0.0, ANCHORS) == pytest.approx(0.0)
    assert interpolate_score(4.0, ANCHORS) == pytest.approx(5.0)   # 4/8 of the way to 10
    assert interpolate_score(2.0, ANCHORS) == pytest.approx(2.5)


def test_interpolation_saturates_above_the_last_anchor():
    """Above the final anchor the score must cap at 100, not extrapolate."""

    assert interpolate_score(220.0, ANCHORS) == pytest.approx(100.0)
    assert interpolate_score(500.0, ANCHORS) == pytest.approx(100.0)
    assert interpolate_score(10000.0, ANCHORS) == pytest.approx(100.0)


def test_interpolation_is_monotone_and_bounded():
    previous = -1.0
    for step in range(0, 4001):
        value = interpolate_score(step / 10.0, ANCHORS)
        assert value >= previous - 1e-9, "interpolation must not decrease"
        assert 0.0 <= value <= 100.0
        previous = value


def test_curve_is_sublinear():
    """Early raw risk must be worth more score per unit than late raw risk."""

    early = (interpolate_score(8.0, ANCHORS) - interpolate_score(0.0, ANCHORS)) / 8.0
    late = (interpolate_score(220.0, ANCHORS) - interpolate_score(140.0, ANCHORS)) / 80.0
    assert early > late


def test_interpolation_rejects_empty_anchors():
    with pytest.raises(ValueError):
        interpolate_score(1.0, ())


# -- per-finding risk -------------------------------------------------------


def test_finding_raw_risk_is_weight_times_category_multiplier():
    assert finding_raw_risk(make(1, Severity.CRITICAL, Category.SECRET)) == pytest.approx(13.0)
    assert finding_raw_risk(make(2, Severity.CRITICAL, Category.SOURCE_CODE)) == pytest.approx(10.0)
    assert finding_raw_risk(make(3, Severity.MEDIUM, Category.CONTAINER)) == pytest.approx(4.8)
    assert finding_raw_risk(make(4, Severity.MEDIUM, Category.IAC)) == pytest.approx(4.4)
    assert finding_raw_risk(make(5, Severity.LOW, Category.IAC)) == pytest.approx(1.1)
    assert finding_raw_risk(make(6, Severity.INFO, Category.SECRET)) == pytest.approx(0.0)


def test_secret_is_the_most_amplified_category():
    weights = DEFAULT_RISK_SETTINGS.severity_weight_for(Severity.CRITICAL)
    multipliers = {
        c: DEFAULT_RISK_SETTINGS.category_multiplier_for(c) for c in Category
    }
    assert max(multipliers, key=lambda c: multipliers[c]) is Category.SECRET
    assert multipliers[Category.SECRET] > multipliers[Category.SOURCE_CODE]


# -- totals and determinism -------------------------------------------------


def test_total_raw_risk_sums_findings():
    findings = [make(1, Severity.MEDIUM), make(2, Severity.HIGH), make(3, Severity.INFO)]
    assert total_raw_risk(findings) == pytest.approx(4.4 + 7.7 + 0.0)


def test_total_raw_risk_is_zero_for_no_findings():
    assert total_raw_risk([]) == 0.0


def test_total_raw_risk_is_order_independent():
    """Findings must score identically regardless of arrival order.

    Binary floating-point addition is not associative, so this is not a
    formality: without sorting, a score could differ run to run.
    """

    findings = [
        make(i, Severity.MEDIUM if i % 3 else Severity.HIGH)
        for i in range(37)
    ]
    forward = total_raw_risk(findings)
    backward = total_raw_risk(list(reversed(findings)))
    shuffled = total_raw_risk(sorted(findings, key=lambda f: f.severity.value))
    assert forward == backward == shuffled


def test_total_raw_risk_is_exactly_repeatable():
    findings = [make(i, Severity.MEDIUM) for i in range(97)]
    values = {total_raw_risk(findings) for _ in range(50)}
    assert len(values) == 1, "repeated evaluation must be bit-identical"


# -- context uplift ---------------------------------------------------------


def test_neutral_context_applies_no_uplift():
    uplift = compute_context_uplift(
        MODEL.build(environment="development", exposure="internal", change_status="existing")
    )
    assert uplift.capped == pytest.approx(1.0)
    assert uplift.uncapped == pytest.approx(1.0)
    assert not uplift.was_capped


def test_context_factors_multiply():
    uplift = compute_context_uplift(
        MODEL.build(environment="staging", exposure="internal", change_status="existing")
    )
    assert uplift.uncapped == pytest.approx(1.15)
    assert uplift.capped == pytest.approx(1.15)


def test_full_context_product_is_computed_then_capped():
    """production x internet-facing x new = 2.0125, capped at 1.6."""

    uplift = compute_context_uplift(
        MODEL.build(environment="production", exposure="internet-facing", change_status="new")
    )
    assert uplift.uncapped == pytest.approx(1.4 * 1.25 * 1.15)
    assert uplift.capped == pytest.approx(1.6)
    assert uplift.was_capped


def test_cap_binds_and_is_reported():
    """Where the cap binds, `was_capped` must say so.

    An explanation that reported 2.0125 as applied would not reproduce the score.
    """

    for env, exposure, change in [
        ("production", "internet-facing", "new"),
        ("production", "internet-facing", "existing"),
        ("production", "internal", "new"),
        ("staging", "internet-facing", "new"),
    ]:
        uplift = compute_context_uplift(MODEL.build(environment=env, exposure=exposure, change_status=change))
        assert uplift.was_capped, f"{env}/{exposure}/{change} should hit the cap"
        assert uplift.capped == pytest.approx(1.6)


def test_context_below_the_cap_is_untouched():
    uplift = compute_context_uplift(
        MODEL.build(environment="development", exposure="internet-facing", change_status="new")
    )
    assert uplift.uncapped == pytest.approx(1.25 * 1.15)
    assert not uplift.was_capped
    assert uplift.capped == pytest.approx(uplift.uncapped)


def test_internet_facing_outranks_internal():
    """Exposure must raise the score for identical findings."""

    base = MODEL.build(environment="production", exposure="internal", change_status="existing")
    exposed = MODEL.build(environment="production", exposure="internet-facing", change_status="existing")
    assert (
        compute_context_uplift(exposed).capped > compute_context_uplift(base).capped
    )


def test_production_outranks_development():
    base = MODEL.build(environment="development", exposure="internal", change_status="existing")
    prod = MODEL.build(environment="production", exposure="internal", change_status="existing")
    assert compute_context_uplift(prod).capped > compute_context_uplift(base).capped


# -- clamping ---------------------------------------------------------------


@pytest.mark.parametrize(
    "value, expected",
    [(-5.0, 0.0), (0.0, 0.0), (50.0, 50.0), (100.0, 100.0), (150.0, 100.0)],
)
def test_clamp(value, expected):
    assert clamp(value) == expected