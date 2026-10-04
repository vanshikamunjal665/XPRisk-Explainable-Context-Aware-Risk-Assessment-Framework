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
    assert nf.severity is Severity.HIGH  # documented XPRisk policy
    assert nf.finding_id == "github-pat"
    assert nf.file == "demo-app/scenarios/insecure/secrets/fake_secrets.env"
    assert nf.line == 12
    assert nf.description == "GitHub Personal Access Token"
    assert nf.metadata["gitleaks"]["severity_policy"].startswith("xprisk_policy")
    assert nf.metadata["data_origin"] == "FIXTURE"
    assert nf.id.startswith("xprisk-")


def test_gitleaks_missing_commit_and_date():
    nf = normalize_gitleaks(GitleaksFinding(rule_id="r", description="d"), now=NOW)
    assert nf.commit_id is None
    assert nf.timestamp == NOW.isoformat()
    assert nf.line is None


# -- Trivy -------------------------------------------------------------------

def test_trivy_normalization_from_fixture():
    from scanners.trivy_scanner import parse_trivy_report

    findings = parse_trivy_report((FIX / "trivy/sample_image_scan.json").read_text())
    nf = normalize_trivy(findings[0], data_origin="FIXTURE", now=NOW)
    assert nf.tool == "TRIVY"
    assert nf.category is Category.CONTAINER
    assert nf.finding_id == "CVE-2023-12345"
    assert nf.severity is Severity.HIGH
    assert nf.resource == "python:3.6-slim (debian 10.13)"
    assert nf.file is None
    assert nf.line is None
    assert nf.metadata["trivy"]["fixed_version"] == "1.1.1n-0+deb10u5"
    assert nf.metadata["trivy"]["package"] == "libssl1.1"
    assert nf.metadata["data_origin"] == "FIXTURE"


def test_trivy_unknown_severity_maps_to_info():
    nf = normalize_trivy(TrivyFinding(vulnerability_id="CVE-X", severity="UNKNOWN"), now=NOW)
    assert nf.severity is Severity.INFO


def test_trivy_missing_fixed_version():
    nf = normalize_trivy(TrivyFinding(vulnerability_id="CVE-X", fixed_version=None), now=NOW)
    assert nf.metadata["trivy"]["fixed_version"] is None


# -- Checkov -----------------------------------------------------------------

def test_checkov_normalization_from_fixture():
    from scanners.checkov_scanner import parse_checkov_report

    findings = parse_checkov_report((FIX / "checkov/terraform_insecure.json").read_text())
    nf = normalize_checkov(findings[0], data_origin="FIXTURE", now=NOW)
    assert nf.tool == "CHECKOV"
    assert nf.category is Category.IAC
    assert nf.finding_id == "CKV_AWS_20"
    assert nf.resource == "aws_s3_bucket.insecure"
    assert nf.file == "/infrastructure/scenarios/insecure/main.tf"
    assert nf.line == 27
    assert nf.severity is Severity.HIGH
    assert "S3 Bucket" in (nf.description or "")
    assert nf.metadata["checkov"]["check_type"] == "terraform"
    assert nf.metadata["data_origin"] == "FIXTURE"


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
    assert len(normalized) == 7
    by_cat = {}
    for nf in normalized:
        by_cat.setdefault(nf.category, []).append(nf)
    assert len(by_cat[Category.SECRET]) == 1
    assert len(by_cat[Category.CONTAINER]) == 2
    assert len(by_cat[Category.IAC]) == 2
    assert len(by_cat[Category.SOURCE_CODE]) == 2
    for nf in normalized:
        assert nf.metadata["data_origin"] == "FIXTURE"
        assert nf.severity in list(Severity)
