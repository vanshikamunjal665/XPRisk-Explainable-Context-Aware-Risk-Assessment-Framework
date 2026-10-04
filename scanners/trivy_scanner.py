"""Trivy scanner adapter.

Executes the real `trivy` executable when available and parses its JSON
report into structured :class:`TrivyFinding` objects. Fixture replay is a
separate, explicitly labelled path.
"""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from scanners.base import (
    DataOrigin,
    ScannerResult,
    ScannerStatus,
    parse_json_object_or_list,
    run_command,
)


@dataclass
class TrivyFinding:
    vulnerability_id: str | None = None
    package: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
    severity: str | None = None
    title: str | None = None
    description: str | None = None
    target: str | None = None
    package_type: str | None = None
    primary_url: str | None = None
    source: str = "trivy"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_trivy_report(text: str) -> list[TrivyFinding]:
    data = parse_json_object_or_list(text)
    if not isinstance(data, dict) or not isinstance(data.get("Results"), list):
        raise ValueError("expected a Trivy JSON object with a Results array")
    findings: list[TrivyFinding] = []
    for result in data["Results"]:
        if not isinstance(result, dict):
            raise ValueError("result entry is not an object")
        target = result.get("Target")
        pkg_type = result.get("Type")
        for item in result.get("Vulnerabilities") or []:
            if not isinstance(item, dict):
                raise ValueError("vulnerability entry is not an object")
            findings.append(
                TrivyFinding(
                    vulnerability_id=item.get("VulnerabilityID"),
                    package=item.get("PkgName"),
                    installed_version=item.get("InstalledVersion"),
                    fixed_version=item.get("FixedVersion"),
                    severity=item.get("Severity"),
                    title=item.get("Title"),
                    description=item.get("Description"),
                    target=target,
                    package_type=pkg_type,
                    primary_url=item.get("PrimaryURL"),
                )
            )
    return findings


class TrivyScanner:
    def __init__(self, executable: str | None = None, timeout: float = 600.0) -> None:
        self.executable = executable or os.environ.get("TRIVY_EXECUTABLE", "trivy")
        self.timeout = timeout

    def scan_image(self, image: str, severities: str | None = None) -> ScannerResult:
        if not image or not str(image).strip():
            return ScannerResult("trivy", ScannerStatus.FAILED, DataOrigin.REAL, image, error="image target is required")
        argv = [self.executable, "image", "--format", "json", "--quiet"]
        if severities:
            argv += ["--severity", severities]
        argv.append(image)
        outcome = run_command(argv, self.timeout)
        if outcome.error and "not found" in outcome.error:
            return ScannerResult("trivy", ScannerStatus.UNAVAILABLE, DataOrigin.REAL, image, error=outcome.error)
        if outcome.error:
            return ScannerResult("trivy", ScannerStatus.TIMEOUT if "timed out" in outcome.error else ScannerStatus.FAILED, DataOrigin.REAL, image, error=outcome.error)
        if outcome.returncode != 0:
            return ScannerResult("trivy", ScannerStatus.FAILED, DataOrigin.REAL, image, error=(outcome.stderr or "trivy failed")[:500], returncode=outcome.returncode)
        try:
            findings = parse_trivy_report(outcome.stdout)
        except ValueError as exc:
            return ScannerResult("trivy", ScannerStatus.MALFORMED, DataOrigin.REAL, image, error=str(exc), returncode=outcome.returncode)
        status = ScannerStatus.SUCCESS if findings else ScannerStatus.NO_FINDINGS
        return ScannerResult("trivy", status, DataOrigin.REAL, image, findings=findings, returncode=outcome.returncode)

    def scan_fixture(self, fixture_path: str | Path, target: str = "<fixture>") -> ScannerResult:
        text = Path(fixture_path).read_text(encoding="utf-8")
        try:
            findings = parse_trivy_report(text)
        except ValueError as exc:
            return ScannerResult("trivy", ScannerStatus.MALFORMED, DataOrigin.FIXTURE, target, error=str(exc))
        status = ScannerStatus.SUCCESS if findings else ScannerStatus.NO_FINDINGS
        return ScannerResult("trivy", status, DataOrigin.FIXTURE, target, findings=findings)
