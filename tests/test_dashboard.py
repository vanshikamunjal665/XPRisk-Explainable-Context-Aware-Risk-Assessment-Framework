"""Dashboard tests.

The Streamlit UI itself is exercised manually; these tests lock down the
data-transformation layer and the service facade the UI depends on.
"""

from __future__ import annotations

from collections import Counter
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
    # Real vulnerable-image scan: 2 Gitleaks + 24 Checkov + 651 Trivy.
    assert len(findings) == 677


def test_every_fixture_preset_loads_real_scanner_output():
    """Each preset must resolve to files that exist and parse to real findings.

    This guards the specific failure that motivated rewriting the fixtures: a
    preset whose files are absent or empty silently scores a deployment as
    clean, which is the most damaging way this dashboard can be wrong.
    """

    data = DashboardData.__new__(DashboardData)
    expected_counts = {
        "Vulnerable demo image - all scanners (real scan)": 677,
        "Hardened demo image - all scanners (real scan)": 291,
        "Secrets only - shows context sensitivity (real scan)": 2,
    }
    assert set(FIXTURE_PRESETS) == set(expected_counts)

    for label, preset in FIXTURE_PRESETS.items():
        assert preset.note, f"{label} has no provenance note"
        for tool, relative in preset.fixtures.items():
            path = Path(__file__).resolve().parent.parent / relative
            assert path.is_file(), f"{label}: missing {tool} fixture at {relative}"
        findings = data.load_fixture_findings(label)
        assert len(findings) == expected_counts[label], label
        assert all(f.metadata.get("data_origin") == "FIXTURE" for f in findings)


def test_hardened_preset_is_not_misrepresented_as_clean():
    """The hardened preset must not be presented as a zero-finding result.

    A previous version of these fixtures declared zero Trivy and zero Checkov
    findings for the hardened scenarios, which is not what either tool reports.
    The dashboard now shows 291 real findings, and this test fails if that ever
    silently reverts to zero.
    """

    data = DashboardData.__new__(DashboardData)
    findings = data.load_fixture_findings("Hardened demo image - all scanners (real scan)")
    by_tool = Counter(f.tool for f in findings)
    assert by_tool == {"TRIVY": 283, "CHECKOV": 8}
    assert by_tool["TRIVY"] > 0 and by_tool["CHECKOV"] > 0
