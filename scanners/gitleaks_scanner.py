"""Gitleaks scanner adapter.

Executes the real `gitleaks` executable when available and parses its JSON
report into structured :class:`GitleaksFinding` objects. Fixture replay is a
separate, explicitly labelled path — fixture findings are never presented as
a real Gitleaks execution.

Gitleaks exit codes:
  0 -> scan completed, no leaks
  1 -> scan completed, leaks found (still a successful run!)
  other / missing executable / timeout -> reported, not raised
"""

from __future__ import annotations

import json
import os
import tempfile
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
class GitleaksFinding:
    rule_id: str | None = None
    description: str | None = None
    file: str | None = None
    start_line: int | None = None
    end_line: int | None = None
    commit: str | None = None
    date: str | None = None
    author: str | None = None
    tags: list[str] = field(default_factory=list)
    source: str = "gitleaks"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _redact(match: Any) -> str | None:
    """Return a safely redacted match preview; never the secret itself."""

    if not isinstance(match, str) or not match:
        return None
    return f"{match[:4]}...[REDACTED]" if len(match) > 8 else "[REDACTED]"


def parse_gitleaks_report(text: str) -> list[GitleaksFinding]:
    """Parse Gitleaks JSON output into findings. Raises ValueError on bad data."""

    data = parse_json_object_or_list(text)
    if not isinstance(data, list):
        raise ValueError("expected a JSON array of leaks")
    findings: list[GitleaksFinding] = []
    for item in data:
        if not isinstance(item, dict):
            raise ValueError("leak entry is not an object")
        findings.append(
            GitleaksFinding(
                rule_id=item.get("RuleID"),
                description=item.get("Description"),
                file=item.get("File"),
                start_line=item.get("StartLine"),
                end_line=item.get("EndLine"),
                commit=item.get("Commit"),
                date=item.get("Date"),
                author=item.get("Author"),
                tags=item.get("Tags") if isinstance(item.get("Tags"), list) else [],
            )
        )
    return findings


class GitleaksScanner:
    def __init__(self, executable: str | None = None, timeout: float = 300.0) -> None:
        self.executable = executable or os.environ.get("GITLEAKS_EXECUTABLE", "gitleaks")
        self.timeout = timeout

    def scan(self, target: str, mode: str = "dir", config: str | None = None) -> ScannerResult:
        """Run a live Gitleaks scan. Never fabricates results on failure."""

        with tempfile.TemporaryDirectory() as tmp:
            report_path = Path(tmp) / "gitleaks.json"
            subcommand = "dir" if mode == "dir" else "detect"

            # The two Gitleaks generations disagree on how the target is
            # passed, so this cannot be one fixed argument list:
            #
            #   Gitleaks >= 8.19  `gitleaks dir <path>`      positional
            #   Gitleaks <  8.19  `gitleaks detect --source=<path>`
            #
            # Verified against 8.30.1: passing `--source` to `dir` fails with
            # `Error: unknown flag: --source` and exits 1, which this adapter
            # would have reported as ScannerStatus.FAILED on every real scan.
            if mode == "dir":
                path_args = [str(target)]
            else:
                path_args = ["--source", str(target)]

            argv = [
                self.executable,
                subcommand,
                *path_args,
                "--report-format",
                "json",
                "--report-path",
                str(report_path),
                "--redact",
            ]
            if config:
                argv += ["--config", str(config)]
            outcome = run_command(argv, self.timeout)

            if outcome.error and "not found" in outcome.error:
                return ScannerResult("gitleaks", ScannerStatus.UNAVAILABLE, DataOrigin.REAL, str(target), error=outcome.error)
            if outcome.error:
                return ScannerResult("gitleaks", ScannerStatus.TIMEOUT if "timed out" in outcome.error else ScannerStatus.FAILED, DataOrigin.REAL, str(target), error=outcome.error)
            if outcome.returncode not in (0, 1):
                return ScannerResult("gitleaks", ScannerStatus.FAILED, DataOrigin.REAL, str(target), error=(outcome.stderr or "gitleaks failed")[:500], returncode=outcome.returncode)
            try:
                text = report_path.read_text(encoding="utf-8") if report_path.exists() else "[]"
                findings = parse_gitleaks_report(text)
            except (ValueError, OSError) as exc:
                return ScannerResult("gitleaks", ScannerStatus.MALFORMED, DataOrigin.REAL, str(target), error=str(exc), returncode=outcome.returncode)
            status = ScannerStatus.SUCCESS if findings else ScannerStatus.NO_FINDINGS
            return ScannerResult("gitleaks", status, DataOrigin.REAL, str(target), findings=findings, returncode=outcome.returncode)

    def scan_fixture(self, fixture_path: str | Path, target: str = "<fixture>") -> ScannerResult:
        """Replay a labelled fixture file. Never claims a live scan occurred."""

        text = Path(fixture_path).read_text(encoding="utf-8")
        try:
            findings = parse_gitleaks_report(text)
        except ValueError as exc:
            return ScannerResult("gitleaks", ScannerStatus.MALFORMED, DataOrigin.FIXTURE, target, error=str(exc))
        status = ScannerStatus.SUCCESS if findings else ScannerStatus.NO_FINDINGS
        return ScannerResult("gitleaks", status, DataOrigin.FIXTURE, target, findings=findings)
