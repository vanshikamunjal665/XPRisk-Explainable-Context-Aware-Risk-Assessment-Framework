"""Tests for Phase 6 finding normalization.

No scanner execution: only in-memory findings and fixture files.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, ".")

from normalizer.models import Category, Severity  # noqa: E402
from normalizer.normalizer import (  # noqa: E402
    normalize_checkov,
    normalize_collection,
    normalize_gitleaks,
    normalize_result,
    normalize_sonarqube,
    normalize_trivy,
)
from scanners.base import DataOrigin, ScannerResult, ScannerStatus  # noqa: E402
from scanners.checkov_scanner import CheckovFinding  # noqa: E402
from scanners.gitleaks_scanner import GitleaksFinding  # noqa: E402
from scanners.scanner_service import ScannerService  # noqa: E402
from scanners.sonarqube_scanner import SonarQubeFinding  # noqa: E402
from scanners.trivy_scanner import TrivyFinding  # noqa: E402

FIX = Path("fixtures")
NOW = datetime(2026, 10, 4, tzinfo=timezone.utc)


# -- Gitleaks ----------------------------------------------------------------

def test_gitleaks_normalization_from_fixture():
    from scanners.gitleaks_scanner import parse_gitleaks_report

    findings = parse_gitleaks_report((FIX / "gitleaks/secrets_detected.json").read_text())
    nf = normalize_gitleaks(findings[0], data_origin="FIXTURE", now=NOW)
    assert nf.tool == "GITLEAKS"
    assert nf.category is Category.SECRET
    # xprisk-test-secret -> HIGH, per XPRISK_GITLEAKS_SEVERITY_RULES.
    assert nf.severity is Severity.HIGH
    assert nf.finding_id == "xprisk-test-secret"
    assert nf.file == "demo-app/scenarios/insecure/secrets/fake_secrets.env"
    assert nf.line == 33
    assert nf.description == "XPRisk labelled test-only secret (Phase 3 controlled fixture)"
    assert nf.metadata["gitleaks"]["severity_policy"].startswith("xprisk_policy")
    assert nf.metadata["gitleaks"]["severity_rule"] == "xprisk-test-secret"
    assert nf.metadata["gitleaks"]["tags"] == [
        "xprisk",
        "test-fixture",
        "false-positive-by-design",
    ]
    assert nf.metadata["data_origin"] == "FIXTURE"
    assert nf.id.startswith("xprisk-")


def test_gitleaks_private_key_is_critical():
    """A real `gitleaks dir` run also emits `private-key`; that must be CRITICAL.

    Both rule ids in the fixture come from a verified Gitleaks 8.30.1 run
    against demo-app/scenarios/insecure, so the two severity paths are
    exercised by real scanner output rather than by hand-written values.
    """
    from scanners.gitleaks_scanner import parse_gitleaks_report

    findings = parse_gitleaks_report((FIX / "gitleaks/secrets_detected.json").read_text())
    assert [f.rule_id for f in findings] == ["xprisk-test-secret", "private-key"]

    nf = normalize_gitleaks(findings[1], data_origin="FIXTURE", now=NOW)
    assert nf.severity is Severity.CRITICAL
    assert nf.line == 40
    assert nf.metadata["gitleaks"]["severity_rule"] == "private-key"


def test_gitleaks_unmapped_rule_falls_back_to_default():
    """An unknown rule id must not crash and must use the documented default."""
    nf = normalize_gitleaks(
        GitleaksFinding(rule_id="some-unmapped-rule", description="d"), now=NOW
    )
    assert nf.severity is Severity.HIGH  # GITLEAKS_DEFAULT_SEVERITY
    assert nf.metadata["gitleaks"]["severity_rule"] == "some-unmapped-rule"


def test_gitleaks_rule_matching_is_case_insensitive():
    nf = normalize_gitleaks(GitleaksFinding(rule_id="Private-Key"), now=NOW)
    assert nf.severity is Severity.CRITICAL


def test_gitleaks_missing_commit_and_date():
    nf = normalize_gitleaks(GitleaksFinding(rule_id="r", description="d"), now=NOW)
    assert nf.commit_id is None
    assert nf.timestamp == NOW.isoformat()
    assert nf.line is None


# -- Trivy -------------------------------------------------------------------

def test_trivy_normalization_from_fixture():
    """Normalization against a complete real Trivy scan.

    The previous version of this test pinned ``CVE-2023-12345`` against a
    hand-written fixture. That identifier was invented, so the test was proving
    only that the code round-trips its own fiction. It now runs over a real
    scan and asserts that the normalization contract holds for every record:
    tool and category are assigned, the CVE identifier is carried through as the
    finding id, Trivy's five severities all land on XPRisk severities, and the
    package, target and fix availability survive into metadata.
    """

    from scanners.trivy_scanner import parse_trivy_report

    raw = (FIX / "trivy/sample_image_scan.json").read_text(encoding="utf-8")
    findings = parse_trivy_report(raw)
    assert len(findings) == 651

    nf = normalize_trivy(findings[0], data_origin="FIXTURE", now=NOW)
    assert nf.tool == "TRIVY"
    assert nf.category is Category.CONTAINER
    assert nf.finding_id == findings[0].vulnerability_id
    assert nf.resource.startswith("xprisk-vulnerable:demo")
    assert nf.file is None  # Trivy reports no file for image packages
    assert nf.line is None
    assert nf.metadata["data_origin"] == "FIXTURE"

    # Every record normalizes without loss, and all five Trivy severities map
    # onto the XPRisk scale (UNKNOWN -> INFO).
    seen = set()
    for finding in findings:
        normalized = normalize_trivy(finding, data_origin="FIXTURE", now=NOW)
        assert normalized.tool == "TRIVY"
        assert normalized.category is Category.CONTAINER
        assert normalized.finding_id == finding.vulnerability_id
        assert normalized.metadata["trivy"]["package"] == finding.package
        assert normalized.metadata["trivy"]["installed_version"] == finding.installed_version
        assert normalized.metadata["trivy"]["fixed_version"] == finding.fixed_version
        assert normalized.metadata["trivy"]["primary_url"] == finding.primary_url
        seen.add(normalized.severity)
    assert seen == {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO}


def test_trivy_target_split_preserved_across_result_entries():
    """The real scan covers an OS package set and a Python package set.

    Trivy reports these as separate ``Results`` entries with different targets,
    and the adapter must not merge them into one indistinguishable blob.
    """

    from scanners.trivy_scanner import parse_trivy_report

    raw = (FIX / "trivy/sample_image_scan.json").read_text(encoding="utf-8")
    by_target = {}
    for finding in parse_trivy_report(raw):
        by_target.setdefault(finding.target, []).append(finding)

    assert len(by_target) == 2
    assert by_target["Python"][0].package_type == "python-pkg"
    os_findings = by_target["xprisk-vulnerable:demo (debian 11.2)"]
    assert len(os_findings) == 639
    assert {f.package_type for f in os_findings} == {"debian"}


def test_trivy_unknown_severity_maps_to_info():
    nf = normalize_trivy(TrivyFinding(vulnerability_id="CVE-X", severity="UNKNOWN"), now=NOW)
    assert nf.severity is Severity.INFO


def test_trivy_missing_fixed_version():
    nf = normalize_trivy(TrivyFinding(vulnerability_id="CVE-X", fixed_version=None), now=NOW)
    assert nf.metadata["trivy"]["fixed_version"] is None


# -- Checkov -----------------------------------------------------------------

def test_checkov_normalization_from_fixture():
    """Normalization against a complete real Checkov run.

    The hand-written fixture this used to read carried ``severity: "HIGH"`` and a
    POSIX file path, neither of which real Checkov produces on Windows. Every
    finding here comes from an actual run, so the asserted severity is the
    documented MEDIUM fallback rather than a severity Checkov supplied, and the
    asserted path is Checkov's real Windows-relative ``\\main.tf``.
    """

    from scanners.checkov_scanner import parse_checkov_report

    raw = (FIX / "checkov/terraform_insecure.json").read_text(encoding="utf-8")
    findings = parse_checkov_report(raw)
    assert len(findings) == 24

    nf = normalize_checkov(findings[0], data_origin="FIXTURE", now=NOW)
    assert nf.tool == "CHECKOV"
    assert nf.category is Category.IAC
    assert nf.finding_id == "CKV_AWS_23"
    assert nf.resource == "aws_security_group.insecure"
    assert nf.file == "\\main.tf"
    assert nf.line == 45
    # Checkov reported no severity, so the documented fallback applies and the
    # decision is recorded on the finding rather than hidden.
    assert findings[0].severity is None
    assert nf.severity is Severity.MEDIUM
    assert nf.metadata["checkov"]["severity_raw"] is None
    assert nf.metadata["checkov"]["severity_policy"].startswith("xprisk_policy")
    assert nf.description == "Ensure every security group and rule has a description"
    assert nf.metadata["checkov"]["check_type"] == "terraform"
    assert nf.metadata["data_origin"] == "FIXTURE"

    # Every real check normalizes to MEDIUM, because every real check is
    # severity-null. This is the behaviour docs/risk-model.md section 7.3
    # describes, now exercised against data that actually has the property.
    assert {normalize_checkov(f, data_origin="FIXTURE", now=NOW).severity for f in findings} == {
        Severity.MEDIUM
    }


def test_checkov_missing_severity_documented_default():
    nf = normalize_checkov(CheckovFinding(check_id="CKV_1", name="x"), now=NOW)
    assert nf.severity is Severity.MEDIUM
    assert nf.metadata["checkov"]["severity_policy"].startswith("xprisk_policy")


# -- SonarQube ---------------------------------------------------------------

def test_sonarqube_normalization_from_fixture():
    import json

    from scanners.sonarqube_scanner import parse_issues_payload

    findings = parse_issues_payload(json.loads((FIX / "sonarqube/issues_sample.json").read_text()))
    nf = normalize_sonarqube(findings[0], data_origin="FIXTURE", now=NOW)
    assert nf.tool == "SONARQUBE"
    assert nf.category is Category.SOURCE_CODE
    assert nf.finding_id == "python:S2068"
    assert nf.severity is Severity.CRITICAL
    assert nf.line == 34
    assert nf.metadata["sonarqube"]["severity_raw"] == "CRITICAL"
    assert nf.metadata["sonarqube"]["issue_type"] == "VULNERABILITY"
    assert nf.metadata["data_origin"] == "FIXTURE"


def test_sonarqube_issue_without_line():
    nf = normalize_sonarqube(
        SonarQubeFinding(rule="r", severity="MEDIUM", severity_raw="MINOR", component="c"),
        now=NOW,
    )
    assert nf.line is None
    assert nf.severity is Severity.MEDIUM


def test_sonarqube_severity_raw_mapping():
    nf = normalize_sonarqube(SonarQubeFinding(rule="r", severity_raw="BLOCKER"), now=NOW)
    assert nf.severity is Severity.CRITICAL
    nf = normalize_sonarqube(SonarQubeFinding(rule="r", severity_raw="INFO"), now=NOW)
    assert nf.severity is Severity.LOW


# -- normalize_result edge cases ---------------------------------------------

def _result(status, scanner="trivy", findings=None, origin=DataOrigin.REAL):
    return ScannerResult(scanner, status, origin, "t", findings=findings or [])


def test_no_findings_yields_empty():
    assert normalize_result(_result(ScannerStatus.NO_FINDINGS)) == []


def test_unavailable_failed_malformed_timeout_yield_empty():
    for status in (ScannerStatus.UNAVAILABLE, ScannerStatus.FAILED, ScannerStatus.MALFORMED, ScannerStatus.TIMEOUT):
        assert normalize_result(_result(status, findings=[TrivyFinding(vulnerability_id="CVE-1")])) == []


def test_multiple_findings_and_empty_list():
    res = _result(ScannerStatus.SUCCESS, findings=[TrivyFinding(vulnerability_id=f"CVE-{i}") for i in range(3)])
    assert len(normalize_result(res, now=NOW)) == 3
    assert normalize_result(_result(ScannerStatus.SUCCESS, findings=[])) == []


def test_real_origin_preserved():
    res = _result(ScannerStatus.SUCCESS, findings=[TrivyFinding(vulnerability_id="CVE-1")], origin=DataOrigin.REAL)
    out = normalize_result(res, now=NOW)
    assert out[0].metadata["data_origin"] == "REAL"


def test_missing_optional_fields_do_not_crash():
    res = _result(ScannerStatus.SUCCESS, scanner="gitleaks", findings=[GitleaksFinding()])
    out = normalize_result(res, now=NOW)
    assert len(out) == 1
    assert out[0].finding_id is None


def test_raw_result_not_mutated():
    findings = [TrivyFinding(vulnerability_id="CVE-1", severity="HIGH")]
    res = _result(ScannerStatus.SUCCESS, findings=findings)
    normalize_result(res, now=NOW)
    assert res.findings is findings
    assert res.findings[0].vulnerability_id == "CVE-1"


def test_deterministic_ids():
    a = normalize_trivy(TrivyFinding(vulnerability_id="CVE-1"), now=NOW)
    b = normalize_trivy(TrivyFinding(vulnerability_id="CVE-1"), now=NOW)
    assert a.id == b.id


# -- collection normalization -------------------------------------------------

def test_collection_normalization_fixture_mode():
    svc = ScannerService()
    collection = svc.collect(
        gitleaks=True, trivy=True, checkov=True, sonarqube=True,
        fixtures={
            "gitleaks": FIX / "gitleaks/secrets_detected.json",
            "trivy": FIX / "trivy/sample_image_scan.json",
            "checkov": FIX / "checkov/terraform_insecure.json",
            "sonarqube": FIX / "sonarqube/issues_sample.json",
        },
    )
    normalized = normalize_collection(collection, now=NOW)
    # Counts follow the real scans behind each fixture: Gitleaks 8.30.1 reports
    # 2 (xprisk-test-secret + private-key), Trivy reports 651, Checkov reports 24.
    # SonarQube is the one synthetic input, because no live instance has been run.
    assert len(normalized) == 2 + 651 + 24 + 2
    by_cat = {}
    for nf in normalized:
        by_cat.setdefault(nf.category, []).append(nf)
    assert len(by_cat[Category.SECRET]) == 2
    assert len(by_cat[Category.CONTAINER]) == 651
    assert len(by_cat[Category.IAC]) == 24
    assert len(by_cat[Category.SOURCE_CODE]) == 2
    # The two secret findings must land on two different severities, which is
    # the whole point of the rule-based Gitleaks severity policy.
    assert sorted(f.severity.value for f in by_cat[Category.SECRET]) == ["CRITICAL", "HIGH"]
    for nf in normalized:
        assert nf.metadata["data_origin"] == "FIXTURE"
        assert nf.severity in list(Severity)
