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
import os
import shutil
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


# Suffixes that Windows can only execute via the command interpreter.
# Python console-script shims (``pip install``d tools such as checkov) are
# generated as ``.cmd`` batch files, not as ``.exe``.
_SHELL_SHIM_SUFFIXES = (".cmd", ".bat")


def resolve_executable(argv: list[str]) -> list[str]:
    """Make a bare executable name resolvable on Windows.

    Why this exists
    ---------------
    ``subprocess.run(..., shell=False)`` does **not** consult ``PATHEXT``.
    On Windows it hands the name straight to ``CreateProcess``, which only
    ever appends ``.exe``. A pip-installed Python CLI is shipped as a ``.cmd``
    batch shim, so it is invisible to it even though the shim is on ``PATH``.

    Verified on Windows 11 with checkov 3.3.22:

    * ``shutil.which("checkov")`` -> ``.venv\\Scripts\\checkov.cmd``
    * ``subprocess.run(["checkov", "--version"], shell=False)`` ->
      ``FileNotFoundError: [WinError 2]``, surfaced by the adapter as
      ``ScannerStatus.UNAVAILABLE``

    Native binaries are unaffected: ``gitleaks.exe`` and ``trivy.exe`` resolve
    normally, which is why this was not caught before checkov was installed.

    What this does to the security guarantee
    ----------------------------------------
    Real executables still run with ``shell=False`` and an explicit argv list,
    exactly as before. Only a resolved ``.cmd``/``.bat`` shim is routed through
    ``COMSPEC``, which is unavoidable: ``cmd.exe`` is the only thing Windows
    can use to execute a batch file. ``/d`` disables AutoRun script
    execution. The project does not build command *strings* from scanner
    output or user input; arguments are still passed as a list, never
    concatenated. This is documented in README section 19 rather than left
    implicit.
    """

    if os.name != "nt" or not argv:
        return argv

    executable = argv[0]
    resolved = shutil.which(executable)
    if resolved is None:
        # Preserve the existing behaviour so the caller reports UNAVAILABLE
        # with the original name.
        return argv
    if os.path.splitext(resolved)[1].lower() not in _SHELL_SHIM_SUFFIXES:
        # A real executable: leave the argv untouched.
        return argv

    comspec = os.environ.get("COMSPEC") or os.environ.get("ComSpec") or "cmd.exe"
    return [comspec, "/d", "/c", resolved, *argv[1:]]


def run_command(argv: list[str], timeout: float) -> CommandOutcome:
    """Run ``argv`` without a shell and capture output separately.

    Never raises for missing executables, timeouts or OS-level errors; those
    are reported on the returned :class:`CommandOutcome`.
    """

    argv = resolve_executable(argv)

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
