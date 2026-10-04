"""Shared scanner contracts and safe subprocess execution.

This module is the single place that knows how XPRisk runs an external
security tool. Adapters in this package build an argument list and delegate
execution here; they never call ``subprocess`` themselves and never build
shell strings.

Error classification
--------------------
Every run is reported with exactly one :class:`ScannerStatus`:

==================  =====================================================
``SUCCESS``         Tool ran; at least one finding was produced.
``NO_FINDINGS``     Tool ran cleanly; zero findings. Not a failure.
``UNAVAILABLE``     The executable was not found on this machine.
``FAILED``          The tool exited non-zero (with a real error).
``MALFORMED``       The tool ran but its output was not valid JSON.
``TIMEOUT``         The tool did not finish within the configured limit.
==================  =====================================================
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ScannerStatus(str, Enum):
    SUCCESS = "SUCCESS"
    NO_FINDINGS = "NO_FINDINGS"
    UNAVAILABLE = "UNAVAILABLE"
    FAILED = "FAILED"
    MALFORMED = "MALFORMED"
    TIMEOUT = "TIMEOUT"


class DataOrigin(str, Enum):
    REAL = "REAL"
    FIXTURE = "FIXTURE"


@dataclass
class CommandOutcome:
    """Result of one subprocess invocation."""

    returncode: int | None
    stdout: str
    stderr: str
    error: str | None = None  # set for missing executable / timeout / OSError

    @property
    def ok(self) -> bool:
        return self.error is None


def run_command(argv: list[str], timeout: float) -> CommandOutcome:
    """Run ``argv`` without a shell and capture output separately.

    Never raises for missing executables, timeouts or OS-level errors; those
    are reported on the returned :class:`CommandOutcome`.
    """

    try:
        completed = subprocess.run(  # noqa: S603 - argv list, shell=False
            argv,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return CommandOutcome(None, "", "", f"executable not found: {argv[0]}")
    except subprocess.TimeoutExpired:
        return CommandOutcome(None, "", "", f"timed out after {timeout}s")
    except OSError as exc:  # permission denied, etc.
        return CommandOutcome(None, "", "", f"os error: {exc}")
    return CommandOutcome(completed.returncode, completed.stdout, completed.stderr)


def parse_json_object_or_list(text: str) -> Any:
    """Parse scanner JSON, raising ``ValueError`` on anything unexpected.

    Scanner output is untrusted input: this is the validation boundary.
    """

    if not text or not text.strip():
        raise ValueError("empty output")
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON: {exc}") from exc


@dataclass
class ScannerResult:
    """Common envelope returned by every scanner adapter."""

    scanner: str
    status: ScannerStatus
    data_origin: DataOrigin = DataOrigin.REAL
    target: str = ""
    findings: list[Any] = field(default_factory=list)
    error: str | None = None
    returncode: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "scanner": self.scanner,
            "status": self.status.value,
            "data_origin": self.data_origin.value,
            "target": self.target,
            "finding_count": len(self.findings),
            "error": self.error,
            "returncode": self.returncode,
        }
