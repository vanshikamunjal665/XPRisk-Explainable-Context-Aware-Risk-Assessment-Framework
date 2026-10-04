"""Checkov scanner adapter.

Executes the real `checkov` executable when available and parses failed
checks into structured :class:`CheckovFinding` objects. Checkov exit code 1
means "checks failed" — i.e. a successful analysis that found issues — and is
treated as a normal result, not a tool failure.
"""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass
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
class CheckovFinding:
    check_id: str | None = None
    name: str | None = None
    severity: str | None = None
    resource: str | None = None
    file_path: str | None = None
    start_line: int | None = None
    end_line: int | None = None
    check_type: str | None = None
    evaluation_details: str | None = None
    source: str = "checkov"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_checkov_report(text: str) -> list[CheckovFinding]:
    data = parse_json_object_or_list(text)
    # Checkov -o json emits a list of per-framework report objects.
    reports = data if isinstance(data, list) else [data]
    findings: list[CheckovFinding] = []
    for report in reports:
        if not isinstance(report, dict):
            raise ValueError("report entry is not an object")
        check_type = report.get("check_type")
        results = report.get("results")
        if not isinstance(results, dict):
            raise ValueError("report is missing a results object")
        for item in results.get("failed_checks") or []:
            if not isinstance(item, dict):
                raise ValueError("failed check entry is not an object")
            line_range = item.get("file_line_range")
            start = line_range[0] if isinstance(line_range, list) and len(line_range) >= 1 else None
            end = line_range[1] if isinstance(line_range, list) and len(line_range) >= 2 else None
            check_meta = item.get("check") if isinstance(item.get("check"), dict) else {}
            findings.append(
                CheckovFinding(
                    check_id=item.get("check_id"),
                    name=check_meta.get("name") or item.get("check_name"),
                    severity=item.get("severity"),
                    resource=item.get("resource"),
                    file_path=item.get("file_path"),
                    start_line=start,
                    end_line=end,
                    check_type=check_type,
                    evaluation_details=item.get("evaluation_details") if isinstance(item.get("evaluation_details"), str) else None,
                )
            )
    return findings


class CheckovScanner:
    def __init__(self, executable: str | None = None, timeout: float = 600.0) -> None:
        self.executable = executable or os.environ.get("CHECKOV_EXECUTABLE", "checkov")
        self.timeout = timeout

    def scan(self, path: str, framework: str = "terraform") -> ScannerResult:
        if not path:
            return ScannerResult("checkov", ScannerStatus.FAILED, DataOrigin.REAL, path, error="scan path is required")
        argv = [self.executable, "-d", str(path), "-o", "json", "--framework", framework, "--quiet"]
        outcome = run_command(argv, self.timeout)
        if outcome.error and "not found" in outcome.error:
            return ScannerResult("checkov", ScannerStatus.UNAVAILABLE, DataOrigin.REAL, str(path), error=outcome.error)
        if outcome.error:
            return ScannerResult("checkov", ScannerStatus.TIMEOUT if "timed out" in outcome.error else ScannerStatus.FAILED, DataOrigin.REAL, str(path), error=outcome.error)
        # Checkov: 0 = no failed checks, 1 = failed checks found (successful run).
        if outcome.returncode not in (0, 1):
            return ScannerResult("checkov", ScannerStatus.FAILED, DataOrigin.REAL, str(path), error=(outcome.stderr or "checkov failed")[:500], returncode=outcome.returncode)
        try:
            findings = parse_checkov_report(outcome.stdout)
        except ValueError as exc:
            return ScannerResult("checkov", ScannerStatus.MALFORMED, DataOrigin.REAL, str(path), error=str(exc), returncode=outcome.returncode)
        status = ScannerStatus.SUCCESS if findings else ScannerStatus.NO_FINDINGS
        return ScannerResult("checkov", status, DataOrigin.REAL, str(path), findings=findings, returncode=outcome.returncode)

    def scan_fixture(self, fixture_path: str | Path, target: str = "<fixture>") -> ScannerResult:
        text = Path(fixture_path).read_text(encoding="utf-8")
        try:
            findings = parse_checkov_report(text)
        except ValueError as exc:
            return ScannerResult("checkov", ScannerStatus.MALFORMED, DataOrigin.FIXTURE, target, error=str(exc))
        status = ScannerStatus.SUCCESS if findings else ScannerStatus.NO_FINDINGS
        return ScannerResult("checkov", status, DataOrigin.FIXTURE, target, findings=findings)
