"""Tests for the explainability layer (Phase 11).

The central guarantee under test is that an explanation cannot drift from the
decision it explains. That is checked by re-deriving the score independently
from the explanation payload and asserting equality against the engine's own
result, rather than by asserting on the prose.

Prose is deliberately not asserted word-for-word. Sentences are composed from
the assessment's fields, so testing exact strings would break on harmless
wording changes while proving nothing about correctness.
"""

from __future__ import annotations

import json
import sys

import pytest

sys.path.insert(0, ".")

from normalizer.models import Category, Severity, XPRiskFinding  # noqa: E402
from risk_engine.context import ContextModel  # noqa: E402
from risk_engine.engine import RiskEngine  # noqa: E402
from risk_engine.settings import RiskSettings  # noqa: E402
from risk_engine.thresholds import Decision, Thresholds  # noqa: E402
from explainability.contributors import (  # noqa: E402
    ContributorKind,
    category_raw_risk,
    dominant_category,
    select_context_contributors,
    select_finding_contributors,
    severity_counts,
)
from explainability.explanation import build_explanation  # noqa: E402
from explainability.recommendation import (  # noqa: E402
    build_recommendation,
    context_alternatives,
)

MODEL = ContextModel()
DEV = MODEL.build(environment="development", exposure="internal", change_status="existing")
PROD = MODEL.build(environment="production", exposure="internet-facing", change_status="new")
ENGINE = RiskEngine()


def make(idx: int, severity: Severity, category: Category, **kw) -> XPRiskFinding:
    payload = {
        "id": f"xprisk-{idx:04d}",
        "tool": "checkov",
        "category": category,
        "severity": severity,
        "finding_id": f"CKV_AWS_{idx}",
        "resource": f"res_{idx}",
        "file": "main.tf",
        "line": 30 + idx,
    }
    payload.update(kw)
    return XPRiskFinding(**payload)


def mixed(n_medium: int = 24) -> list[XPRiskFinding]:
    return [
        make(1, Severity.CRITICAL, Category.SECRET),
        make(2, Severity.HIGH, Category.CONTAINER),
        *[
            make(i, Severity.MEDIUM, Category.IAC)
            for i in range(3, 3 + n_medium)
        ],
    ]


# -- the derivability guarantee --------------------------------------------


def test_explanation_score_equals_the_engine_score():
    fs = mixed()
    assessment = ENGINE.assess(fs, PROD)
    explanation = build_explanation(assessment)
    assert explanation.risk_score == assessment.risk_score
    assert explanation.decision is assessment.decision


def test_explanation_score_is_reproducible_from_the_payload_alone():
    """Re-derive the score using only what the explanation publishes.

    This is the test that makes "verifiable by hand" an enforced property
    rather than a claim in a docstring.
    """

    fs = mixed()
    explanation = build_explanation(ENGINE.assess(fs, PROD))

    anchors = tuple(tuple(pair) for pair in explanation.settings_snapshot["score_anchors"])

    def interpolate(raw, anchors):
        if raw <= anchors[0][0]:
            lo, hi = anchors[0], anchors[1]
        else:
            segment = None
            for a, b in zip(anchors, anchors[1:]):
                if raw <= b[0]:
                    segment = (a, b)
                    break
            if segment is None:
                return anchors[-1][1]
            lo, hi = segment
        if raw == lo[0]:
            return lo[1]
        if raw == hi[0]:
            return hi[1]
        return lo[1] + (raw - lo[0]) * (hi[1] - lo[1]) / (hi[0] - lo[0])

    base = interpolate(explanation.total_raw, anchors)
    assert base == pytest.approx(explanation.base_score)

    uplift_steps = {d.step: d.value for d in explanation.derivation}
    assert uplift_steps["context_uplift"] == pytest.approx(explanation.capped_multiplier)

    expected = min(100.0, base * explanation.capped_multiplier)
    assert expected == pytest.approx(explanation.risk_score)


def test_derivation_steps_are_ordered_and_complete():
    explanation = build_explanation(ENGINE.assess(mixed(), PROD))
    steps = [d.step for d in explanation.derivation]
    assert steps == ["per_finding_risk", "normalise", "context_uplift", "final_score", "decision"]


def test_derivation_reports_the_cap_when_it_binds():
    explanation = build_explanation(ENGINE.assess(mixed(), PROD))
    assert explanation.context_capped
    step = next(d for d in explanation.derivation if d.step == "context_uplift")
    assert "capped" in step.expression
    assert step.value == pytest.approx(explanation.capped_multiplier)


def test_derivation_reports_clamping_when_score_exceeds_100():
    fs = [make(i, Severity.MEDIUM, Category.IAC) for i in range(200)]
    explanation = build_explanation(ENGINE.assess(fs, PROD))
    assert explanation.risk_score == 100.0
    step = next(d for d in explanation.derivation if d.step == "final_score")
    assert "clamp" in step.expression


def test_total_raw_matches_the_sum_of_all_contributions():
    """Not just the top-N: the published total must be the whole set."""

    fs = mixed(40)
    assessment = ENGINE.assess(fs, DEV)
    explanation = build_explanation(assessment, top_n=5)
    assert explanation.total_raw == pytest.approx(sum(c.raw_risk for c in assessment.contributions))


# -- contributors -----------------------------------------------------------


def test_only_contributing_findings_are_named_as_reasons():
    """A finding worth zero cannot be presented as having moved the score."""

    fs = [
        make(1, Severity.MEDIUM, Category.IAC),
        make(2, Severity.INFO, Category.SOURCE_CODE),
    ]
    explanation = build_explanation(ENGINE.assess(fs, DEV))
    labels = [c.label for c in explanation.finding_contributors]
    assert labels == ["CKV_AWS_1"]
    assert len(explanation.severity_breakdown) == 2, "INFO is still counted and visible"


def test_contributors_are_ranked_by_influence():
    explanation = build_explanation(ENGINE.assess(mixed(), DEV))
    ranks = [c.rank for c in explanation.finding_contributors]
    assert ranks == list(range(1, len(ranks) + 1))
    raw = [c.raw_risk for c in explanation.finding_contributors]
    assert raw == sorted(raw, reverse=True)
    assert explanation.finding_contributors[0].severity == "CRITICAL"


def test_top_n_limits_named_reasons():
    explanation = build_explanation(ENGINE.assess(mixed(30), DEV), top_n=3)
    assert len(explanation.finding_contributors) == 3


def test_zero_risk_assessment_names_no_contributors():
    explanation = build_explanation(ENGINE.assess([make(1, Severity.INFO, Category.IAC)], DEV))
    assert explanation.finding_contributors == ()
    assert explanation.dominant_category is None
    assert explanation.risk_score == 0.0


def test_all_three_context_factors_are_reported():
    explanation = build_explanation(ENGINE.assess(mixed(), PROD))
    factors = {c.factor for c in explanation.context_contributors}
    assert factors == {"environment", "exposure", "change_status"}
    assert all(c.applied for c in explanation.context_contributors)
    assert all(c.kind is ContributorKind.CONTEXT for c in explanation.context_contributors)


def test_neutral_context_reports_no_amplification():
    explanation = build_explanation(ENGINE.assess(mixed(), DEV))
    assert not any(c.amplified for c in explanation.context_contributors)
    assert explanation.capped_multiplier == pytest.approx(1.0)


def test_amplifying_context_is_flagged():
    explanation = build_explanation(ENGINE.assess(mixed(), PROD))
    amplified = [c.factor for c in explanation.context_contributors if c.amplified]
    assert amplified == ["environment", "exposure", "change_status"]


def test_severity_counts_are_ordered_by_severity():
    explanation = build_explanation(ENGINE.assess(mixed(), DEV))
    assert list(explanation.severity_breakdown) == ["CRITICAL", "HIGH", "MEDIUM"]


def test_dominant_category_is_the_largest_raw_contributor():
    explanation = build_explanation(ENGINE.assess(mixed(), DEV))
    raw = explanation.category_raw_risk
    assert explanation.dominant_category == max(raw, key=lambda k: (raw[k], k))
    # 24 MEDIUM IaC outweigh one CRITICAL secret.
    assert explanation.dominant_category == "IAC"


def test_severity_counts_helper_orders_high_first():
    fs = [make(1, Severity.LOW, Category.IAC), make(2, Severity.CRITICAL, Category.SECRET)]
    assert list(severity_counts(ENGINE.assess(fs, DEV))) == ["CRITICAL", "LOW"]


def test_category_raw_risk_totals_reconcile():
    explanation = build_explanation(ENGINE.assess(mixed(), DEV))
    assert sum(explanation.category_raw_risk.values()) == pytest.approx(explanation.total_raw)


# -- edge cases -------------------------------------------------------------


def test_no_findings_explanation_is_safe_and_says_so():
    explanation = build_explanation(ENGINE.assess([], PROD))
    assert explanation.decision is Decision.SAFE
    assert explanation.risk_score == 0.0
    assert "No findings" in explanation.summary
    assert explanation.finding_count == 0


def test_explanation_is_json_serialisable():
    payload = json.loads(json.dumps(build_explanation(ENGINE.assess(mixed(), PROD)).to_dict()))
    assert payload["decision"] == "BLOCK"
    assert payload["derivation"]
    assert payload["context"]["environment"] == "production"


def test_explanation_exposes_deployment_permission():
    assert build_explanation(ENGINE.assess(mixed(), PROD)).allows_deployment is False


def test_explanation_is_deterministic():
    fs = mixed()
    first = build_explanation(ENGINE.assess(fs, PROD)).to_dict()
    second = build_explanation(ENGINE.assess(list(reversed(fs)), PROD)).to_dict()
    assert first == second


# -- recommendations --------------------------------------------------------


def test_block_recommendation_targets_warning():
    """Remediation moves toward *less* risk, so BLOCK targets WARNING."""

    assessment = ENGINE.assess(mixed(), PROD)
    recommendation = build_recommendation(assessment)
    assert assessment.decision is Decision.BLOCK
    assert recommendation.target_decision is Decision.WARNING
    assert recommendation.target_threshold == pytest.approx(70.0)
    assert recommendation.points_to_target > 0


def test_warning_recommendation_targets_safe():
    """WARNING must target SAFE (below 30), not BLOCK, which it already cleared."""

    fs = [make(i, Severity.MEDIUM, Category.IAC) for i in range(6)]
    assessment = ENGINE.assess(fs, DEV)
    recommendation = build_recommendation(assessment)
    assert assessment.decision is Decision.WARNING
    assert recommendation.target_decision is Decision.SAFE
    assert recommendation.target_threshold == pytest.approx(30.0)
    assert recommendation.points_to_target > 0


def test_safe_recommendation_has_no_target():
    """SAFE is the least restrictive band; there is nowhere lower to go."""

    assessment = ENGINE.assess([make(1, Severity.MEDIUM, Category.IAC)], DEV)
    recommendation = build_recommendation(assessment)
    assert assessment.decision is Decision.SAFE
    assert recommendation.target_decision is None
    assert recommendation.points_to_target is None
    assert recommendation.findings_to_fix == ()
    assert "No further remediation" in recommendation.action


def test_remediation_steps_reach_the_target_band():
    """Resolving the listed findings must actually get the score under target."""

    fs = [make(i, Severity.MEDIUM, Category.IAC) for i in range(8)]
    assessment = ENGINE.assess(fs, DEV)
    recommendation = build_recommendation(assessment)
    assert not recommendation.unreachable_by_fixing
    assert recommendation.target_decision is Decision.SAFE
    assert recommendation.projected_score < recommendation.target_threshold
    assert recommendation.findings_to_fix[-1].reaches_target


def test_remediation_steps_are_ordered_and_monotone():
    fs = [make(i, Severity.MEDIUM, Category.IAC) for i in range(10)]
    recommendation = build_recommendation(ENGINE.assess(fs, DEV))
    steps = recommendation.findings_to_fix
    assert [s.raw_risk for s in steps] == sorted((s.raw_risk for s in steps), reverse=True)
    scores = [s.score_before for s in steps]
    assert scores == sorted(scores, reverse=True), "score must fall monotonically"
    for step in steps:
        assert step.points_removed >= 0.0


def test_remediation_prediction_uses_the_real_score_curve():
    """The projection must be the engine's normalisation, not a linear guess.

    A linear approximation would give a different answer than the piecewise
    curve, so this assertion distinguishes the two rather than just checking
    internal consistency.
    """

    from risk_engine.scoring import interpolate_score

    fs = [make(i, Severity.MEDIUM, Category.IAC) for i in range(8)]
    assessment = ENGINE.assess(fs, DEV)
    recommendation = build_recommendation(assessment)
    assert recommendation.findings_to_fix, "expected at least one remediation step"

    fixed = sum(c.raw_risk for c in assessment.contributions) - sum(
        s.raw_risk for s in recommendation.findings_to_fix
    )
    expected = min(100.0, interpolate_score(fixed, RiskSettings().score_anchors) * assessment.uplift.capped)
    assert recommendation.projected_score == pytest.approx(round(expected, 4))

    # The two genuinely differ here, so the test is not vacuous.
    linear = assessment.base_score * fixed / assessment.total_raw * assessment.uplift.capped
    assert abs(linear - expected) > 0.01


def test_remediation_stops_as_soon_as_the_target_is_reached():
    """The plan must not over-prescribe work.

    Once the projected score clears the target band, further steps stop being
    listed even though the budget would allow more. This is what makes the
    recommendation a minimal plan rather than a full clean-up list.
    """

    fs = [make(i, Severity.CRITICAL, Category.SECRET) for i in range(20)]
    assessment = ENGINE.assess(fs, PROD)
    assert assessment.decision is Decision.BLOCK

    recommendation = build_recommendation(assessment, max_steps=len(fs))
    assert not recommendation.unreachable_by_fixing
    assert recommendation.projected_score < recommendation.target_threshold
    assert recommendation.findings_to_fix[-1].reaches_target
    assert len(recommendation.findings_to_fix) < len(fs), "must stop early, not fix everything"
    assert recommendation.projected_score > 0.0, "stopped with score still above zero"


def test_unreachable_by_fixing_can_never_be_set_with_an_adequate_budget():
    """Fixing every contributing finding always clears any band.

    This bounds what ``unreachable_by_fixing`` can mean. Resolving all
    contributions drives total raw risk to 0, and zero findings always score 0,
    which is below every possible SAFE edge. So the flag can only ever describe
    a *step budget* limit, never a fundamental inability to remediate.
    """

    fs = [make(i, Severity.MEDIUM, Category.IAC) for i in range(50)]
    assessment = ENGINE.assess(fs, PROD)
    assert assessment.decision is Decision.BLOCK

    recommendation = build_recommendation(assessment, max_steps=len(fs))
    assert not recommendation.unreachable_by_fixing
    assert recommendation.findings_to_fix[-1].reaches_target


def test_unreachable_when_the_step_budget_is_exhausted():
    """Too few permitted steps is the one real cause of being unreachable."""

    fs = [make(i, Severity.MEDIUM, Category.IAC) for i in range(200)]
    assessment = ENGINE.assess(fs, PROD)
    assert assessment.decision is Decision.BLOCK

    recommendation = build_recommendation(assessment, max_steps=1)
    assert recommendation.unreachable_by_fixing
    assert recommendation.projected_score >= recommendation.target_threshold
    assert len(recommendation.findings_to_fix) == 1
    assert "More findings must be" in recommendation.rationale


def test_no_steps_available_is_reported_distinctly():
    """A zero step budget must not silently read as success."""

    fs = [make(i, Severity.MEDIUM, Category.IAC) for i in range(200)]
    recommendation = build_recommendation(ENGINE.assess(fs, PROD), max_steps=0)
    assert recommendation.unreachable_by_fixing
    assert recommendation.findings_to_fix == ()
    assert "No remediation step was available" in recommendation.action


def test_recommendation_reports_the_amplifying_context():
    recommendation = build_recommendation(ENGINE.assess(mixed(), PROD))
    assert recommendation.context_note
    assert "production" in recommendation.context_note
    assert "internet-facing" in recommendation.context_note


def test_recommendation_context_note_says_when_nothing_amplifies():
    recommendation = build_recommendation(ENGINE.assess(mixed(), DEV))
    assert "No context factor" in recommendation.context_note


def test_context_alternatives_cover_every_combination():
    alternatives = context_alternatives(ENGINE.assess(mixed(), DEV))
    assert len(alternatives) == 3 * 2 * 2
    for row in alternatives:
        assert 0.0 <= row["score"] <= 100.0
    # Current context must be reproduced exactly among the alternatives.
    current = next(
        row
        for row in alternatives
        if row["environment"] == "development"
        and row["exposure"] == "internal"
        and row["change_status"] == "existing"
    )
    assert current["score"] == pytest.approx(ENGINE.assess(mixed(), DEV).risk_score)


def test_recommendation_to_dict_is_serialisable():
    payload = json.loads(json.dumps(build_recommendation(ENGINE.assess(mixed(), DEV)).to_dict()))
    assert payload["decision"] in {"SAFE", "WARNING", "BLOCK"}
    assert "findings_to_fix" in payload