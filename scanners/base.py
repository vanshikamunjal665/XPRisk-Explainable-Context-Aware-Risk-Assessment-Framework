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
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
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

#: Extensions probed next to the running interpreter, in preference order. The
#: bare name is included because a venv can hold a real extensionless binary.
_SIBLING_SUFFIXES = (".exe", ".cmd", ".bat", "")


def _locate_executable(name: str) -> str | None:
    """Find ``name`` on ``PATH``, then beside the running interpreter.

    The second lookup exists because of how a pip console script works on
    Windows. ``pip install checkov`` writes two files into the environment's
    ``Scripts`` directory: ``checkov.exe``, which *is* executable, and
    ``checkov.cmd``. XPRisk finds neither unless ``PATH`` contains that
    directory, which is only true once the virtual environment has been
    *activated*.

    Running a documented command such as ``.\\.venv\\Scripts\\python.exe -m
    pytest`` does **not** activate anything: it uses one interpreter out of the
    venv while leaving ``PATH`` untouched. In that state the Checkov adapter
    reported ``UNAVAILABLE`` and the assessment silently lost a whole scanner.

    Looking beside ``sys.executable`` restores the tool without activating the
    environment, and it cannot pick up a tool from a *different* environment,
    because only this interpreter's own directory is searched.
    """

    found = shutil.which(name)
    if found:
        return found

    if os.name != "nt":
        return None

    scripts_dir = Path(sys.executable).parent
    for suffix in _SIBLING_SUFFIXES:
        candidate = Path(f"{scripts_dir / name}{suffix}")
        if candidate.is_file():
            return str(candidate)
    return None


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

    Resolution order is ``PATH`` first, then the running interpreter's own
    ``Scripts`` directory. The second step exists because every command in the
    README uses ``.\\.venv\\Scripts\\python.exe <script>``, which selects the
    environment's interpreter without extending ``PATH``. Without that fallback,
    a tool installed into the virtual environment reported ``UNAVAILABLE`` and
    its findings were dropped from the assessment without any visible error.

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
    resolved = _locate_executable(executable)
    if resolved is None:
        # Preserve the existing behaviour so the caller reports UNAVAILABLE
        # with the original name.
        return argv
    if os.path.splitext(resolved)[1].lower() not in _SHELL_SHIM_SUFFIXES:
        # A real executable: leave the argv untouched.
        return argv

    comspec = os.environ.get("COMSPEC") or os.environ.get("ComSpec") or "cmd.exe"
    return [comspec, "/d", "/c", resolved, *argv[1:]]


def _shim_child_env(argv: list[str]) -> dict[str, str] | None:
    """Environment for a child process, or ``None`` to inherit unchanged.

    A pip ``.cmd`` shim locates its own interpreter by scanning ``PATH`` for
    ``python.exe``. When XPRisk is started with
    ``.\\.venv\\Scripts\\python.exe`` rather than an activated environment,
    ``PATH`` still points at the *system* interpreter, so the shim runs the
    wrong Python and dies with ``ModuleNotFoundError: No module named
    'checkov'``. That failure is indistinguishable from a missing tool once it
    surfaces as zero findings.

    Putting the shim's own directory at the front of the child's ``PATH``
    reproduces exactly what activation would have done, using a directory that
    was derived from a resolved executable path rather than from any input. It
    is only applied when a shim was actually resolved, so a native binary such
    as ``gitleaks.exe`` inherits the environment untouched.
    """

    if os.name != "nt" or len(argv) < 4 or argv[2] != "/c":
        return None

    shim_dir = str(Path(argv[3]).parent)
    env = dict(os.environ)
    env["PATH"] = os.pathsep.join(filter(None, [shim_dir, env.get("PATH", "")]))
    return env


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
            env=_shim_child_env(argv),
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
