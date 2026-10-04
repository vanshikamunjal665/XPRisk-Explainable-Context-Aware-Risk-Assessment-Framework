"""Tests for risk engine orchestration (Phase 9).

The engine's job is to produce a score *and* a breakdown that reproduces that
score. These tests therefore assert the arithmetic twice: once from the
assessment's own fields, and once by re-deriving the score independently from
the contributions. If the two ever disagreed, the explanation layer would be
publishing numbers the engine never used.
"""

from __future__ import annotations

import sys

import pytest

sys.path.insert(0, ".")

from normalizer.models import Category, Severity, XPRiskFinding  # noqa: E402
from risk_engine.context import ContextModel  # noqa: E402
from risk_engine.engine import RiskEngine, assess_risk  # noqa: E402
from risk_engine.scoring import interpolate_score  # noqa: E402
from risk_engine.settings import RiskSettings  # noqa: E402
from risk_engine.thresholds import Decision  # noqa: E402

MODEL = ContextModel()
DEV = MODEL.build(environment="development", exposure="internal", change_status="existing")
PROD = MODEL.build(environment="production", exposure="internet-facing", change_status="new")


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


def findings(*specs) -> list[XPRiskFinding]:
    return [make(i, sev, cat) for i, (sev, cat) in enumerate(specs, start=1)]


# -- no findings ------------------------------------------------------------


def test_no_findings_scores_zero_and_is_safe():
    """Integration TEST 1: no findings -> SAFE."""

    a = RiskEngine().assess([], DEV)
    assert a.total_raw == 0.0
    assert a.base_score == 0.0
    assert a.risk_score == 0.0
    assert a.decision is Decision.SAFE
    assert a.finding_count == 0
    assert a.contributions == ()


def test_no_findings_is_safe_in_the_worst_context():
    """Context must not matter when there is nothing to amplify."""

    a = RiskEngine().assess([], PROD)
    assert a.risk_score == 0.0
    assert a.decision is Decision.SAFE
    assert a.uplift.was_capped  # the cap bound, but 0 x anything is still 0


# -- the score follows the documented arithmetic ----------------------------


def test_score_is_reproducible_from_the_assessment_fields():
    """sum(raw) -> interpolate -> x uplift -> clamp, exactly."""

    fs = findings(
        (Severity.CRITICAL, Category.SECRET),
        *[(Severity.MEDIUM, Category.IAC)] * 23,
    )
    a = RiskEngine().assess(fs, PROD)

    assert a.total_raw == pytest.approx(sum(c.raw_risk for c in a.contributions))
    expected_base = interpolate_score(a.total_raw, RiskSettings().score_anchors)
    assert a.base_score == pytest.approx(expected_base)
    assert a.risk_score_unrounded == pytest.approx(min(100.0, expected_base * a.uplift.capped))
    assert a.risk_score == pytest.approx(round(a.risk_score_unrounded, 4))


def test_score_saturates_at_100_and_stays_there():
    fs = findings(*[(Severity.MEDIUM, Category.IAC)] * 400)
    a = RiskEngine().assess(fs, PROD)
    assert a.risk_score == 100.0
    assert a.decision is Decision.BLOCK


def test_scores_stay_within_range():
    for count in range(0, 60):
        fs = findings(*[(Severity.MEDIUM, Category.IAC)] * count)
        a = RiskEngine().assess(fs, PROD)
        assert 0.0 <= a.base_score <= 100.0
        assert 0.0 <= a.risk_score <= 100.0


# -- context is applied once, and last --------------------------------------


def test_context_raises_the_score_for_identical_findings():
    """Integration TEST 4: development vs production."""

    fs = findings(*[(Severity.MEDIUM, Category.IAC)] * 6)
    dev = RiskEngine().assess(fs, DEV)
    prod = RiskEngine().assess(fs, PROD)
    assert prod.base_score == pytest.approx(dev.base_score), "context must not touch base_score"
    assert prod.risk_score > dev.risk_score


def test_exposure_raises_the_score():
    """Integration TEST 5: internet-facing vs internal."""

    fs = findings(*[(Severity.MEDIUM, Category.IAC)] * 6)
    internal = MODEL.build(environment="production", exposure="internal", change_status="existing")
    exposed = MODEL.build(environment="production", exposure="internet-facing", change_status="existing")
    assert RiskEngine().assess(fs, exposed).risk_score > RiskEngine().assess(fs, internal).risk_score


def test_context_is_applied_once_not_per_finding():
    """Context multiplies the normalised base, so it must not scale with count.

    If context were folded into per-finding risk, doubling the number of
    findings would also double the context contribution, and a large repository
    would be punished for its size.
    """

    small = findings(*[(Severity.MEDIUM, Category.IAC)] * 3)
    large = findings(*[(Severity.MEDIUM, Category.IAC)] * 30)

    engine = RiskEngine()
    a_small, a_large = engine.assess(small, PROD), engine.assess(large, PROD)

    for a in (a_small, a_large):
        # risk_score_unrounded carries the exact product; the published score is
        # that value rounded to 4dp so JSON and hand-arithmetic agree.
        assert a.risk_score_unrounded == pytest.approx(min(100.0, a.base_score * a.uplift.capped))
        assert a.risk_score == pytest.approx(round(a.risk_score_unrounded, 4))
        assert a.uplift.capped == pytest.approx(1.6)

    # The same multiplier applies regardless of finding count.
    assert a_small.uplift.capped == a_large.uplift.capped


def test_a_single_critical_secret_is_detected():
    """Integration TEST 6: secret detection must actually move the score."""

    none = RiskEngine().assess([], PROD)
    secret = RiskEngine().assess(findings((Severity.CRITICAL, Category.SECRET)), PROD)
    assert secret.total_raw > none.total_raw
    assert secret.risk_score > none.risk_score
    assert secret.severity_breakdown.get("CRITICAL") == 1


# -- contributions ----------------------------------------------------------


def test_contributions_cover_every_finding():
    fs = findings(
        (Severity.CRITICAL, Category.SECRET),
        (Severity.HIGH, Category.CONTAINER),
        (Severity.MEDIUM, Category.IAC),
    )
    a = RiskEngine().assess(fs, DEV)
    assert len(a.contributions) == 3
    assert {c.finding_id for c in a.contributions} == {f.id for f in fs}


def test_contribution_arithmetic_is_exposed_per_finding():
    fs = findings((Severity.CRITICAL, Category.SECRET), (Severity.MEDIUM, Category.IAC))
    a = RiskEngine().assess(fs, DEV)
    for c in a.contributions:
        assert c.raw_risk == pytest.approx(c.severity_weight * c.category_multiplier)


def test_shares_sum_to_one_when_there_is_raw_risk():
    fs = findings(
        (Severity.CRITICAL, Category.SECRET),
        (Severity.HIGH, Category.CONTAINER),
        *[(Severity.MEDIUM, Category.IAC)] * 5,
    )
    a = RiskEngine().assess(fs, DEV)
    assert sum(c.share_of_total for c in a.contributions) == pytest.approx(1.0)


def test_shares_are_zero_when_total_raw_is_zero():
    a = RiskEngine().assess(findings((Severity.INFO, Category.IAC)), DEV)
    assert a.total_raw == 0.0
    assert all(c.share_of_total == 0.0 for c in a.contributions)


def test_ranking_is_by_influence_and_stable():
    fs = [
        make(1, Severity.MEDIUM, Category.IAC),
        make(2, Severity.CRITICAL, Category.SECRET),
        make(3, Severity.INFO, Category.SOURCE_CODE),
    ]
    a = RiskEngine().assess(fs, DEV)
    ranked = a.ranked_contributions
    assert ranked[0].severity is Severity.CRITICAL
    assert ranked[-1].severity is Severity.INFO
    # INFO is still present, just last.
    assert len(ranked) == 3
    # Zero-contribution findings are excluded from the contributing view.
    assert len(a.contributing_findings) == 2


def test_ranking_is_stable_for_equal_contributions():
    fs = [make(i, Severity.MEDIUM, Category.IAC) for i in range(10)]
    first = [c.finding_id for c in RiskEngine().assess(fs, DEV).ranked_contributions]
    second = [c.finding_id for c in RiskEngine().assess(list(reversed(fs)), DEV).ranked_contributions]
    assert first == second, "ties must break deterministically, not by arrival order"


def test_breakdowns_are_populated():
    fs = findings(
        (Severity.CRITICAL, Category.SECRET),
        (Severity.MEDIUM, Category.IAC),
        (Severity.MEDIUM, Category.IAC),
    )
    a = RiskEngine().assess(fs, DEV)
    assert a.severity_breakdown == {"CRITICAL": 1, "MEDIUM": 2}
    assert a.category_breakdown == {"IAC": 2, "SECRET": 1}
    assert a.finding_count == 3


# -- determinism ------------------------------------------------------------


def test_assessment_is_deterministic_across_runs():
    fs = findings(
        (Severity.CRITICAL, Category.SECRET),
        *[(Severity.HIGH, Category.CONTAINER)] * 3,
        *[(Severity.MEDIUM, Category.IAC)] * 11,
    )
    engine = RiskEngine()
    scores = {engine.assess(fs, PROD).risk_score for _ in range(25)}
    assert len(scores) == 1


def test_assessment_is_independent_of_finding_order():
    fs = findings(
        (Severity.CRITICAL, Category.SECRET),
        *[(Severity.MEDIUM, Category.IAC)] * 7,
        (Severity.LOW, Category.SOURCE_CODE),
    )
    engine = RiskEngine()
    forward = engine.assess(fs, PROD)
    backward = engine.assess(list(reversed(fs)), PROD)
    assert forward.risk_score == backward.risk_score
    assert forward.total_raw == backward.total_raw
    assert forward.decision is backward.decision


def test_engine_instance_is_reusable_without_state_leak():
    fs = findings(*[(Severity.MEDIUM, Category.IAC)] * 5)
    engine = RiskEngine()
    first = engine.assess(fs, DEV).risk_score
    engine.assess([], PROD)
    engine.assess(findings((Severity.CRITICAL, Category.SECRET)), PROD)
    assert engine.assess(fs, DEV).risk_score == first


# -- custom settings --------------------------------------------------------


def test_custom_settings_change_the_score():
    """The comparative study depends on this: same findings, different policy."""

    fs = findings(*[(Severity.MEDIUM, Category.IAC)] * 6)
    default = RiskEngine().assess(fs, DEV)

    harsh = RiskSettings().with_severity_weights(
        {Severity.CRITICAL: 100.0, Severity.HIGH: 70.0, Severity.MEDIUM: 40.0, Severity.LOW: 10.0, Severity.INFO: 0.0}
    )
    weighted = RiskEngine(harsh).assess(fs, DEV)

    assert weighted.total_raw > default.total_raw
    assert weighted.risk_score > default.risk_score


def test_context_cap_is_configurable():
    fs = findings(*[(Severity.MEDIUM, Category.IAC)] * 6)
    from dataclasses import replace

    uncapped = replace(RiskSettings(), context_uplift_cap=99.0)
    a = RiskEngine(uncapped).assess(fs, PROD)
    assert not a.uplift.was_capped
    assert a.uplift.capped == pytest.approx(a.uplift.uncapped)


def test_assess_from_strings_resolves_context():
    fs = findings((Severity.CRITICAL, Category.SECRET))
    a = RiskEngine().assess_from_strings(
        fs, environment="production", exposure="internet-facing", change_status="new"
    )
    assert a.context.environment.value == "production"
    assert a.uplift.was_capped


def test_assess_from_strings_rejects_unknown_vocabulary():
    with pytest.raises(ValueError, match="unknown environment"):
        RiskEngine().assess_from_strings([], environment="qa", exposure="internal", change_status="new")


def test_module_level_helper_matches_the_class():
    fs = findings((Severity.HIGH, Category.CONTAINER))
    assert assess_risk(fs, DEV).risk_score == RiskEngine().assess(fs, DEV).risk_score


def test_settings_snapshot_is_published():
    """A stored score must be traceable to the constants that produced it."""

    a = RiskEngine().assess(findings((Severity.MEDIUM, Category.IAC)), DEV)
    assert a.settings_snapshot["severity_weights"]["MEDIUM"] == 4.0
    assert a.settings_snapshot["category_multipliers"]["IAC"] == 1.1
    assert a.settings_snapshot["context_uplift_cap"] == 1.6
    assert a.settings_snapshot["threshold_warning"] == 70.0


def test_to_dict_is_json_serialisable():
    import json

    a = RiskEngine().assess(findings((Severity.MEDIUM, Category.IAC)), PROD)
    payload = json.loads(json.dumps(a.to_dict()))
    assert payload["decision"] in {"SAFE", "WARNING", "BLOCK"}
    assert payload["contributions"]
    assert "distance_to_edges" in payload