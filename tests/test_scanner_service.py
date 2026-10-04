"""Tests for the Scanner Service (Phase 5).

All scanner adapters are mocked/faked: no real Gitleaks, Trivy, Checkov,
SonarQube, or Docker is required.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, ".")

from scanners.base import DataOrigin, ScannerResult, ScannerStatus  # noqa: E402
from scanners.gitleaks_scanner import GitleaksFinding  # noqa: E402
from scanners.trivy_scanner import TrivyFinding  # noqa: E402
from scanners.checkov_scanner import CheckovFinding  # noqa: E402
from scanners.sonarqube_scanner import SonarQubeFinding  # noqa: E402
from scanners.scanner_service import CollectionResult, ScannerService  # noqa: E402

FIX = Path("fixtures")


class FakeScanner:
    """Stands in for a Phase 4 adapter; returns preset results."""

    def __init__(self, name: str, result: ScannerResult | None = None, exc: Exception | None = None):
        self.name = name
        self.result = result or ScannerResult(name, ScannerStatus.NO_FINDINGS, DataOrigin.REAL, "<t>")
        self.exc = exc
        self.calls: list[dict] = []

    def _record(self, **kwargs):
        self.calls.append(kwargs)
        if self.exc:
            raise self.exc
        return self.result

    # adapter-shaped methods used by the service
    def scan(self, target, mode="dir", config=None, framework=None):
        return self._record(target=target, mode=mode, config=config, framework=framework)

    def scan_image(self, image, severities=None):
        return self._record(image=image, severities=severities)

    def fetch(self):
        return self._record()

    def scan_fixture(self, fixture_path, target="<fixture>"):
        return self._record(fixture_path=str(fixture_path), target=target)


def make_service(**fakes: FakeScanner) -> ScannerService:
    return ScannerService(
        gitleaks=fakes.get("gitleaks"),
        trivy=fakes.get("trivy"),
        checkov=fakes.get("checkov"),
        sonarqube=fakes.get("sonarqube"),
    )


def gitleaks_ok():
    return ScannerResult(
        "gitleaks",
        ScannerStatus.SUCCESS,
        DataOrigin.REAL,
        ".",
        findings=[GitleaksFinding(rule_id="r1"), GitleaksFinding(rule_id="r2")],
    )


def trivy_ok():
    return ScannerResult(
        "trivy", ScannerStatus.SUCCESS, DataOrigin.REAL, "img:1",
        findings=[TrivyFinding(vulnerability_id="CVE-1")],
    )


def checkov_ok():
    return ScannerResult(
        "checkov", ScannerStatus.SUCCESS, DataOrigin.REAL, ".",
        findings=[CheckovFinding(check_id="CKV_1") for _ in range(5)],
    )


# -- selection ---------------------------------------------------------------

def test_only_gitleaks():
    svc = make_service(gitleaks=FakeScanner("gitleaks", gitleaks_ok()))
    out = svc.collect(gitleaks=True, gitleaks_target=".")
    assert set(out.results) == {"gitleaks"}
    assert out.statuses["gitleaks"] is ScannerStatus.SUCCESS
    assert len(out.findings["gitleaks"]) == 2


def test_only_trivy():
    svc = make_service(trivy=FakeScanner("trivy", trivy_ok()))
    out = svc.collect(trivy=True, trivy_image="img:1")
    assert set(out.results) == {"trivy"}
    assert out.findings["trivy"][0].vulnerability_id == "CVE-1"


def test_only_checkov():
    svc = make_service(checkov=FakeScanner("checkov", checkov_ok()))
    out = svc.collect(checkov=True, checkov_path="iac")
    assert set(out.results) == {"checkov"}
    assert len(out.findings["checkov"]) == 5


def test_only_sonarqube():
    res = ScannerResult("sonarqube", ScannerStatus.SUCCESS, DataOrigin.REAL, "u/p",
                        findings=[SonarQubeFinding(rule="r")])
    svc = make_service(sonarqube=FakeScanner("sonarqube", res))
    out = svc.collect(sonarqube=True)
    assert set(out.results) == {"sonarqube"}
    assert out.findings["sonarqube"][0].rule == "r"


def test_multiple_subsets():
    svc = make_service(
        gitleaks=FakeScanner("gitleaks", gitleaks_ok()),
        trivy=FakeScanner("trivy", trivy_ok()),
        checkov=FakeScanner("checkov", checkov_ok()),
        sonarqube=FakeScanner("sonarqube"),
    )
    out = svc.collect(gitleaks=True, trivy=True)
    assert set(out.results) == {"gitleaks", "trivy"}
    out = svc.collect(checkov=True, sonarqube=True)
    assert set(out.results) == {"checkov", "sonarqube"}
    out = svc.collect(gitleaks=True, trivy=True, checkov=True, sonarqube=True,
                      gitleaks_target=".", trivy_image="i", checkov_path=".")
    assert set(out.results) == {"gitleaks", "trivy", "checkov", "sonarqube"}


def test_none_selected_returns_empty():
    svc = make_service()
    out = svc.collect()
    assert isinstance(out, CollectionResult)
    assert out.results == {} and out.findings == {} and out.errors == {}


# -- status preservation -----------------------------------------------------

def test_no_findings_is_not_error():
    svc = make_service(trivy=FakeScanner("trivy", ScannerResult("trivy", ScannerStatus.NO_FINDINGS, DataOrigin.REAL, "i")))
    out = svc.collect(trivy=True, trivy_image="i")
    assert out.statuses["trivy"] is ScannerStatus.NO_FINDINGS
    assert out.findings["trivy"] == []
    assert "trivy" not in out.errors


def test_unavailable_preserves_others():
    svc = make_service(
        gitleaks=FakeScanner("gitleaks", gitleaks_ok()),
        trivy=FakeScanner("trivy", ScannerResult("trivy", ScannerStatus.UNAVAILABLE, DataOrigin.REAL, "i", error="executable not found: trivy")),
    )
    out = svc.collect(gitleaks=True, trivy=True, gitleaks_target=".", trivy_image="i")
    assert out.statuses["trivy"] is ScannerStatus.UNAVAILABLE
    assert out.errors["trivy"].error == "executable not found: trivy"
    assert len(out.findings["gitleaks"]) == 2


def test_failed_preserves_successful_findings():
    svc = make_service(
        checkov=FakeScanner("checkov", checkov_ok()),
        sonarqube=FakeScanner("sonarqube", ScannerResult("sonarqube", ScannerStatus.FAILED, DataOrigin.REAL, "u", error="auth failed")),
    )
    out = svc.collect(checkov=True, sonarqube=True, checkov_path=".")
    assert out.statuses["sonarqube"] is ScannerStatus.FAILED
    assert out.errors["sonarqube"].findings_returned == 0
    assert len(out.findings["checkov"]) == 5


def test_malformed_not_silently_successful():
    svc = make_service(trivy=FakeScanner("trivy", ScannerResult("trivy", ScannerStatus.MALFORMED, DataOrigin.REAL, "i", error="invalid JSON")))
    out = svc.collect(trivy=True, trivy_image="i")
    assert out.statuses["trivy"] is ScannerStatus.MALFORMED
    assert out.findings["trivy"] == []
    assert out.errors["trivy"].status is ScannerStatus.MALFORMED


def test_timeout_preserved():
    svc = make_service(sonarqube=FakeScanner("sonarqube", ScannerResult("sonarqube", ScannerStatus.TIMEOUT, DataOrigin.REAL, "u", error="request timed out")))
    out = svc.collect(sonarqube=True)
    assert out.statuses["sonarqube"] is ScannerStatus.TIMEOUT
    assert "timed out" in out.errors["sonarqube"].error


def test_adapter_exception_is_captured_not_raised():
    svc = make_service(gitleaks=FakeScanner("gitleaks", exc=RuntimeError("boom")))
    out = svc.collect(gitleaks=True)
    assert out.statuses["gitleaks"] is ScannerStatus.FAILED
    assert "boom" in out.errors["gitleaks"].error


def test_fixture_origin_preserved():
    res = ScannerResult("gitleaks", ScannerStatus.SUCCESS, DataOrigin.FIXTURE, "<fixture>",
                        findings=[GitleaksFinding(rule_id="fx")])
    svc = make_service(gitleaks=FakeScanner("gitleaks", res))
    out = svc.collect(gitleaks=True, fixtures={"gitleaks": FIX / "gitleaks/secrets_detected.json"})
    assert out.results["gitleaks"].data_origin is DataOrigin.FIXTURE
    assert out.findings["gitleaks"][0].rule_id == "fx"


def test_real_origin_not_rewritten():
    svc = make_service(trivy=FakeScanner("trivy", trivy_ok()))
    out = svc.collect(trivy=True, trivy_image="i")
    assert out.results["trivy"].data_origin is DataOrigin.REAL


def test_scanner_specific_fields_not_flattened():
    svc = make_service(
        gitleaks=FakeScanner("gitleaks", gitleaks_ok()),
        trivy=FakeScanner("trivy", trivy_ok()),
        checkov=FakeScanner("checkov", checkov_ok()),
    )
    out = svc.collect(gitleaks=True, trivy=True, checkov=True,
                      gitleaks_target=".", trivy_image="i", checkov_path=".")
    assert out.findings["gitleaks"][0].rule_id == "r1"
    assert out.findings["trivy"][0].vulnerability_id == "CVE-1"
    assert out.findings["checkov"][0].check_id == "CKV_1"
    for lst in out.findings.values():
        first = lst[0]
        assert not hasattr(first, "normalized_severity")
        assert not hasattr(first, "normalized_type")


def test_fixture_mode_collection_with_real_adapters():
    """Manual-style fixture collection using the real adapter parsers."""
    svc = ScannerService()
    out = svc.collect(
        gitleaks=True, trivy=True, checkov=True, sonarqube=True,
        fixtures={
            "gitleaks": FIX / "gitleaks/secrets_detected.json",
            "trivy": FIX / "trivy/sample_image_scan.json",
            "checkov": FIX / "checkov/terraform_insecure.json",
            "sonarqube": FIX / "sonarqube/issues_sample.json",
        },
    )
    assert set(out.results) == {"gitleaks", "trivy", "checkov", "sonarqube"}
    for name, result in out.results.items():
        assert result.data_origin is DataOrigin.FIXTURE, name
        assert result.status is ScannerStatus.SUCCESS, name
    assert out.total_findings() > 0
