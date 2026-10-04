"""Tests for the scanner adapters (Phase 4).

All tests mock subprocess/network I/O: no real Trivy, Checkov, Gitleaks or
SonarQube server is required. Fixture paths are labelled fixture-only.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, ".")  # repository root on sys.path (conftest also does this)

from scanners.base import DataOrigin, ScannerStatus, parse_json_object_or_list  # noqa: E402
from scanners.checkov_scanner import CheckovScanner, parse_checkov_report  # noqa: E402
from scanners.gitleaks_scanner import GitleaksScanner, parse_gitleaks_report  # noqa: E402
from scanners.sonarqube_scanner import (  # noqa: E402
    SEVERITY_MAP,
    SonarQubeScanner,
    parse_issues_payload,
)
from scanners.trivy_scanner import TrivyScanner, parse_trivy_report  # noqa: E402

FIX = Path("fixtures")


def _completed(rc: int, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=rc, stdout=stdout, stderr=stderr)


# --------------------------------------------------------------------------
# parse helpers
# --------------------------------------------------------------------------

def test_parse_json_rejects_empty_and_invalid():
    with pytest.raises(ValueError):
        parse_json_object_or_list("")
    with pytest.raises(ValueError):
        parse_json_object_or_list("not json")


# --------------------------------------------------------------------------
# Gitleaks
# --------------------------------------------------------------------------

def test_gitleaks_parse_findings():
    findings = parse_gitleaks_report((FIX / "gitleaks/secrets_detected.json").read_text())
    assert len(findings) == 1
    assert findings[0].rule_id == "github-pat"


def test_gitleaks_parse_clean():
    assert parse_gitleaks_report((FIX / "gitleaks/secrets_clean.json").read_text()) == []


def test_gitleaks_parse_malformed_and_non_list():
    with pytest.raises(ValueError):
        parse_gitleaks_report("{not a list}")
    with pytest.raises(ValueError):
        parse_gitleaks_report('{"a": 1}')


def test_gitleaks_missing_executable(monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(FileNotFoundError()))
    result = GitleaksScanner(executable="gitleaks-nope").scan(".")
    assert result.status is ScannerStatus.UNAVAILABLE
    assert result.data_origin is DataOrigin.REAL


def test_gitleaks_failure_and_timeout(monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _completed(2, stderr="boom"))
    assert GitleaksScanner().scan(".").status is ScannerStatus.FAILED
    def timeout(*a, **k):
        raise subprocess.TimeoutExpired(cmd="gitleaks", timeout=1)
    monkeypatch.setattr(subprocess, "run", timeout)
    assert GitleaksScanner(timeout=1).scan(".").status is ScannerStatus.TIMEOUT


def test_gitleaks_real_success_with_leaks(monkeypatch):
    report = (FIX / "gitleaks/secrets_detected.json").read_text()
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        report_path = Path(argv[argv.index("--report-path") + 1])
        report_path.write_text(report)
        return _completed(1)

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = GitleaksScanner().scan("demo-app/scenarios/insecure")
    assert result.status is ScannerStatus.SUCCESS
    assert len(result.findings) == 1
    assert captured["argv"][0] == "gitleaks"
    assert "--report-format" in captured["argv"]


def test_gitleaks_fixture_is_labelled():
    result = GitleaksScanner().scan_fixture(FIX / "gitleaks/secrets_detected.json")
    assert result.data_origin is DataOrigin.FIXTURE
    assert result.status is ScannerStatus.SUCCESS


# --------------------------------------------------------------------------
# Trivy
# --------------------------------------------------------------------------

def test_trivy_parse_multiple_vulns():
    findings = parse_trivy_report((FIX / "trivy/sample_image_scan.json").read_text())
    assert len(findings) == 2
    assert findings[0].vulnerability_id == "CVE-2023-12345"
    assert findings[1].fixed_version is None


def test_trivy_parse_clean_and_malformed():
    assert parse_trivy_report((FIX / "trivy/sample_image_scan_clean.json").read_text()) == []
    with pytest.raises(ValueError):
        parse_trivy_report("[1,2]")


def test_trivy_missing_executable(monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(FileNotFoundError()))
    assert TrivyScanner().scan_image("img:1").status is ScannerStatus.UNAVAILABLE


def test_trivy_failure_and_malformed_output(monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _completed(1, stderr="err"))
    assert TrivyScanner().scan_image("img:1").status is ScannerStatus.FAILED
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _completed(0, stdout="junk"))
    assert TrivyScanner().scan_image("img:1").status is ScannerStatus.MALFORMED


def test_trivy_real_success(monkeypatch):
    stdout = (FIX / "trivy/sample_image_scan.json").read_text()
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        return _completed(0, stdout=stdout)

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = TrivyScanner().scan_image("xprisk:vuln", severities="CRITICAL,HIGH")
    assert result.status is ScannerStatus.SUCCESS
    assert len(result.findings) == 2
    assert captured["argv"][:2] == ["trivy", "image"]


def test_trivy_fixture_labelled():
    assert TrivyScanner().scan_fixture(FIX / "trivy/sample_image_scan.json").data_origin is DataOrigin.FIXTURE


# --------------------------------------------------------------------------
# Checkov
# --------------------------------------------------------------------------

def test_checkov_parse_failed_checks():
    findings = parse_checkov_report((FIX / "checkov/terraform_insecure.json").read_text())
    assert len(findings) == 2
    assert findings[0].check_id == "CKV_AWS_20"
    assert findings[0].start_line == 27


def test_checkov_parse_clean_and_malformed():
    assert parse_checkov_report((FIX / "checkov/terraform_clean.json").read_text()) == []
    with pytest.raises(ValueError):
        parse_checkov_report('{"results": "nope"}')


def test_checkov_missing_executable(monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(FileNotFoundError()))
    assert CheckovScanner().scan(".").status is ScannerStatus.UNAVAILABLE


def test_checkov_failure_and_success_rc1(monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _completed(3, stderr="crash"))
    assert CheckovScanner().scan(".").status is ScannerStatus.FAILED

    stdout = (FIX / "checkov/terraform_insecure.json").read_text()
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _completed(1, stdout=stdout))
    result = CheckovScanner().scan("infrastructure/scenarios/insecure")
    assert result.status is ScannerStatus.SUCCESS
    assert len(result.findings) == 2


def test_checkov_fixture_labelled():
    assert CheckovScanner().scan_fixture(FIX / "checkov/terraform_insecure.json").data_origin is DataOrigin.FIXTURE


# --------------------------------------------------------------------------
# SonarQube
# --------------------------------------------------------------------------

def test_sonarqube_parse_and_severity_mapping():
    payload = json.loads((FIX / "sonarqube/issues_sample.json").read_text())
    findings = parse_issues_payload(payload)
    assert findings[0].severity == "CRITICAL"  # BLOCKER -> CRITICAL
    assert findings[0].severity_raw == "CRITICAL"
    assert findings[1].severity == "MEDIUM"  # MINOR -> MEDIUM
    assert findings[1].line is None


def test_sonarqube_severity_map_is_predictable():
    assert set(SEVERITY_MAP) == {"BLOCKER", "CRITICAL", "MAJOR", "MINOR", "INFO"}


def test_sonarqube_malformed_payload():
    with pytest.raises(ValueError):
        parse_issues_payload(["not", "a", "dict"])


class _FakeResponse:
    def __init__(self, status_code=200, json_value=None, text=""):
        self.status_code = status_code
        self._json = json_value
        self.text = text

    def raise_for_status(self):
        if self.status_code >= 400:
            import httpx

            raise httpx.HTTPStatusError("err", request=None, response=None)

    def json(self):
        if self._json is None:
            raise ValueError("no json")
        return self._json


class _FakeClient:
    def __init__(self, pages):
        self.pages = list(pages)
        self.calls = 0

    def get(self, url, params=None, auth=None, timeout=None):
        self.calls += 1
        page = self.pages[min(self.calls - 1, len(self.pages) - 1)]
        return page

    def close(self):
        pass


def test_sonarqube_fetch_success_and_pagination():
    page1 = _FakeResponse(200, {"total": 501, "issues": [{"rule": "r", "severity": "MAJOR"}]})
    page2 = _FakeResponse(200, {"total": 501, "issues": [{"rule": "r2", "severity": "INFO"}]})
    client = _FakeClient([page1, page2])
    scanner = SonarQubeScanner(url="http://sonar.test", project_key="p", token="t", client=client)
    result = scanner.fetch()
    assert result.status is ScannerStatus.SUCCESS
    assert len(result.findings) == 2
    assert client.calls == 2  # paginated


def test_sonarqube_auth_failure_and_unavailable():
    scanner = SonarQubeScanner(url="http://x", project_key="p", token="t", client=_FakeClient([_FakeResponse(401)]))
    assert scanner.fetch().status is ScannerStatus.FAILED

    import httpx

    class Down(_FakeClient):
        def get(self, *a, **k):
            raise httpx.ConnectError("refused")

    scanner = SonarQubeScanner(url="http://x", project_key="p", token="t", client=Down([]))
    assert scanner.fetch().status is ScannerStatus.UNAVAILABLE


def test_sonarqube_fixture_labelled_and_clean():
    result = SonarQubeScanner().scan_fixture(FIX / "sonarqube/issues_sample.json")
    assert result.data_origin is DataOrigin.FIXTURE
    assert result.status is ScannerStatus.SUCCESS
    clean = SonarQubeScanner().scan_fixture(FIX / "sonarqube/issues_clean.json")
    assert clean.status is ScannerStatus.NO_FINDINGS
    assert clean.data_origin is DataOrigin.FIXTURE
