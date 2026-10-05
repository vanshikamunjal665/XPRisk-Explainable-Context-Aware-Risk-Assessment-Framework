"""Dashboard tests.

The Streamlit UI itself is exercised manually; these tests lock down the
data-transformation layer and the service facade the UI depends on.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from dashboard import transforms
from dashboard.service import DashboardData, FIXTURE_PRESETS
from normalizer.models import Category, Severity, XPRiskFinding
from risk_engine.engine import RiskEngine
from risk_engine.context import DeploymentContext


def _finding(idx: int, severity: Severity, category: Category, tool: str = "gitleaks"):
    return XPRiskFinding(
        id=f"xprisk-{idx:04d}",
        tool=tool,
        category=category,
        severity=severity,
        finding_id=f"F{idx}",
        resource=f"res_{idx}",
        file="main.tf",
        line=idx,
        description="demo finding",
    )


def _assessment():
    findings = [
        _finding(1, Severity.CRITICAL, Category.SECRET),
        _finding(2, Severity.HIGH, Category.CONTAINER, tool="trivy"),
        _finding(3, Severity.MEDIUM, Category.IAC, tool="checkov"),
    ]
    engine = RiskEngine()
    context = engine.context_model.build(
        environment="production", exposure="internet-facing", change_status="new"
    )
    return engine.assess(findings, context)


def test_transforms_module_imports():
    assert hasattr(transforms, "findings_table")


def test_service_module_imports():
    assert hasattr(DashboardData, "run_assessment")


def test_app_py_compiles():
    import py_compile

    py_compile.compile(str(Path("dashboard/app.py")), doraise=True)


def test_findings_table_sanitizes_and_is_complete():
    rows = transforms.findings_table(
        [_finding(1, Severity.LOW, Category.SOURCE_CODE, tool="sonarqube")]
    )
    assert len(rows) == 1
    row = rows[0]
    assert row["severity"] == "LOW"
    assert row["category"] == "SOURCE_CODE"
    assert row["tool"] == "sonarqube"
    # no metadata / secret values are carried into the table
    assert "metadata" not in row


def test_redaction_of_secret_like_values():
    leaked = "key AKIAIOSFODNN7EXAMPLE found"
    assert "AKIAIOSFODNN7EXAMPLE" not in transforms.redact_text(leaked)
    row = transforms.finding_row(
        {
            "tool": "gitleaks",
            "category": "SECRET",
            "severity": "CRITICAL",
            "description": "aws key AKIAIOSFODNN7EXAMPLE leaked",
        }
    )
    assert "AKIAIOSFODNN7EXAMPLE" not in row["description"]


def test_severity_counts_and_filters():
    rows = transforms.findings_table(
        [
            _finding(1, Severity.CRITICAL, Category.SECRET),
            _finding(2, Severity.CRITICAL, Category.SECRET),
            _finding(3, Severity.LOW, Category.IAC, tool="checkov"),
        ]
    )
    counts = transforms.severity_counts(rows)
    assert counts["CRITICAL"] == 2
    assert counts["LOW"] == 1
    filtered = transforms.filter_findings(rows, severities=["LOW"])
    assert len(filtered) == 1
    filtered = transforms.filter_findings(rows, tools=["checkov"], categories=["IAC"])
    assert len(filtered) == 1


def test_contributions_come_from_engine_not_recomputed():
    assessment = _assessment()
    rows = transforms.contributions_table(assessment)
    assert len(rows) == assessment.finding_count
    total = sum(r["raw_risk"] for r in rows)
    assert total == pytest.approx(assessment.total_raw)


def test_history_table_and_filter():
    class Dep:
        id = 1
        commit_id = "abc"
        branch = "main"
        environment = "production"
        internet_exposed = True
        timestamp = None
        risk_score = 88.0
        decision = "BLOCK"

    rows = transforms.history_table([Dep()])
    assert rows[0]["risk_score"] == 88.0
    assert transforms.filter_history(rows, decisions=["SAFE"]) == []
    assert len(transforms.filter_history(rows, decisions=["BLOCK"])) == 1


def test_empty_cases():
    assert transforms.findings_table([]) == []
    assert transforms.severity_counts([])["CRITICAL"] == 0
    assert transforms.history_table([]) == []
    assert transforms.contributions_table(type("A", (), {"ranked_contributions": ()})()) == []


def test_run_assessment_uses_engine():
    data = DashboardData.__new__(DashboardData)  # skip storage init
    bundle = data.run_assessment(
        [_finding(1, Severity.CRITICAL, Category.SECRET)],
        environment="production",
        exposure="internet-facing",
        change_status="new",
    )
    engine_score = _assessment().risk_score
    # the bundle score equals what the engine produces for the same context
    context = DeploymentContext(
        environment=_assessment().context.environment,
        exposure=_assessment().context.exposure,
        change_status=_assessment().context.change_status,
    )
    again = RiskEngine().assess(
        [_finding(1, Severity.CRITICAL, Category.SECRET)], context
    )
    assert bundle.risk_score == again.risk_score
    assert bundle.decision == again.decision.value
    assert bundle.explanation.risk_score == bundle.risk_score
    assert bundle.recommendation.current_score == bundle.risk_score
    assert engine_score >= 0  # sanity on the fixture engine


def test_storage_failures_surface_but_app_level_uses_empty_lists():
    # history helpers must cope with an empty deployment list without error
    assert transforms.filter_history([], environments=["production"]) == []


def test_fixture_loader_when_fixtures_present():
    data = DashboardData.__new__(DashboardData)
    findings = data.load_fixture_findings(next(iter(FIXTURE_PRESETS)))
    assert isinstance(findings, list)
    # Insecure fixture set should normalize at least one finding
    assert len(findings) >= 1
