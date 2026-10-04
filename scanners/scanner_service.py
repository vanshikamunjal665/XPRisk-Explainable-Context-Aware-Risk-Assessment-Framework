"""Scanner Service — central collection/orchestration layer (Phase 5).

This module orchestrates the Phase 4 scanner adapters. It triggers the
selected scanners, collects their :class:`~scanners.base.ScannerResult`
objects, tracks statuses, records errors, and returns the raw,
scanner-specific findings untouched.

It is an orchestration layer only. It does NOT normalize findings,
calculate risk, derive severity scores, analyze context, make
SAFE/WARNING/BLOCK decisions, generate explanations, or persist anything.
Each adapter remains responsible for executing and parsing its own tool.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from scanners.base import DataOrigin, ScannerResult, ScannerStatus
from scanners.checkov_scanner import CheckovScanner
from scanners.gitleaks_scanner import GitleaksScanner
from scanners.sonarqube_scanner import SonarQubeScanner
from scanners.trivy_scanner import TrivyScanner

SCANNER_NAMES = ("gitleaks", "trivy", "checkov", "sonarqube")


@dataclass
class ScannerErrorRecord:
    """Per-scanner error information preserved from collection."""

    scanner: str
    status: ScannerStatus
    error: str | None
    findings_returned: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "scanner": self.scanner,
            "status": self.status.value,
            "error": self.error,
            "findings_returned": self.findings_returned,
        }


@dataclass
class CollectionResult:
    """Single result object returned by :meth:`ScannerService.collect`.

    ``results`` maps scanner name -> the adapter's own ``ScannerResult``.
    ``findings`` maps scanner name -> that adapter's raw finding list
    (e.g. ``TrivyFinding`` objects stay Trivy-specific; nothing is
    normalized here). ``statuses`` and ``errors`` preserve per-scanner
    status and error information.
    """

    results: dict[str, ScannerResult] = field(default_factory=dict)
    findings: dict[str, list[Any]] = field(default_factory=dict)
    statuses: dict[str, ScannerStatus] = field(default_factory=dict)
    errors: dict[str, ScannerErrorRecord] = field(default_factory=dict)

    def total_findings(self) -> int:
        return sum(len(f) for f in self.findings.values())

    def to_dict(self) -> dict[str, Any]:
        return {
            "scanners": sorted(self.results),
            "statuses": {k: v.value for k, v in self.statuses.items()},
            "finding_counts": {k: len(v) for k, v in self.findings.items()},
            "total_findings": self.total_findings(),
            "errors": {k: v.to_dict() for k, v in self.errors.items()},
            "results": {k: v.to_dict() for k, v in self.results.items()},
        }


class ScannerService:
    """Triggers selected scanner adapters and collects their results.

    Scanner instances are injectable so tests can substitute fakes; by
    default real adapter instances are created.
    """

    def __init__(
        self,
        gitleaks: GitleaksScanner | None = None,
        trivy: TrivyScanner | None = None,
        checkov: CheckovScanner | None = None,
        sonarqube: SonarQubeScanner | None = None,
    ) -> None:
        self.gitleaks = gitleaks or GitleaksScanner()
        self.trivy = trivy or TrivyScanner()
        self.checkov = checkov or CheckovScanner()
        self.sonarqube = sonarqube or SonarQubeScanner()

    # -- per-scanner runners -------------------------------------------------

    def _run_gitleaks(self, target: str, mode: str, config: str | None, fixture: str | Path | None) -> ScannerResult:
        if fixture is not None:
            return self.gitleaks.scan_fixture(fixture, target=str(target or "<fixture>"))
        return self.gitleaks.scan(str(target), mode=mode, config=config)

    def _run_trivy(self, image: str, severities: str | None, fixture: str | Path | None) -> ScannerResult:
        if fixture is not None:
            return self.trivy.scan_fixture(fixture, target=str(image or "<fixture>"))
        return self.trivy.scan_image(str(image), severities=severities)

    def _run_checkov(self, path: str, framework: str, fixture: str | Path | None) -> ScannerResult:
        if fixture is not None:
            return self.checkov.scan_fixture(fixture, target=str(path or "<fixture>"))
        return self.checkov.scan(str(path), framework=framework)

    def _run_sonarqube(self, fixture: str | Path | None) -> ScannerResult:
        if fixture is not None:
            return self.sonarqube.scan_fixture(fixture)
        return self.sonarqube.fetch()

    # -- orchestration --------------------------------------------------------

    def collect(
        self,
        *,
        gitleaks: bool = False,
        trivy: bool = False,
        checkov: bool = False,
        sonarqube: bool = False,
        gitleaks_target: str = ".",
        gitleaks_mode: str = "dir",
        gitleaks_config: str | None = None,
        trivy_image: str = "",
        trivy_severities: str | None = None,
        checkov_path: str = ".",
        checkov_framework: str = "terraform",
        fixtures: dict[str, str | Path] | None = None,
    ) -> CollectionResult:
        """Run the selected scanners sequentially and collect raw results.

        ``fixtures`` optionally maps scanner name -> fixture file path; when
        present for a scanner, that scanner replays its labelled fixture
        instead of executing the real tool. ``DataOrigin`` is preserved
        exactly as returned by each adapter.
        """

        fixtures = fixtures or {}
        runners: dict[str, Callable[[], ScannerResult]] = {}
        if gitleaks:
            runners["gitleaks"] = lambda: self._run_gitleaks(
                gitleaks_target, gitleaks_mode, gitleaks_config, fixtures.get("gitleaks")
            )
        if trivy:
            runners["trivy"] = lambda: self._run_trivy(trivy_image, trivy_severities, fixtures.get("trivy"))
        if checkov:
            runners["checkov"] = lambda: self._run_checkov(checkov_path, checkov_framework, fixtures.get("checkov"))
        if sonarqube:
            runners["sonarqube"] = lambda: self._run_sonarqube(fixtures.get("sonarqube"))

        collection = CollectionResult()
        for name, runner in runners.items():
            try:
                result = runner()
            except Exception as exc:  # adapter should never raise; fail soft
                result = ScannerResult(
                    name,
                    ScannerStatus.FAILED,
                    DataOrigin.REAL,
                    "",
                    error=f"unexpected scanner adapter error: {exc.__class__.__name__}: {exc}",
                )
            collection.results[name] = result
            collection.findings[name] = list(result.findings)
            collection.statuses[name] = result.status
            if result.error or result.status in (
                ScannerStatus.UNAVAILABLE,
                ScannerStatus.FAILED,
                ScannerStatus.MALFORMED,
                ScannerStatus.TIMEOUT,
            ):
                collection.errors[name] = ScannerErrorRecord(
                    scanner=name,
                    status=result.status,
                    error=result.error,
                    findings_returned=len(result.findings),
                )
        return collection
