"""Tests for the pytest configuration itself.

Why this file exists
--------------------
``pyproject.toml`` declares five markers and ``README.md`` §15 documented
``pytest -m unit`` and ``pytest -m integration`` as ways to run a subset. No test
carried any of those markers, so both commands reported ``322 deselected`` and
executed nothing. A documented command that silently runs zero tests is worse
than an undocumented one, because it looks like a passing result.

What is pinned here
-------------------
* Every marker the README tells a reader to select is actually applied to at
  least one test, so ``-m <name>`` cannot become a no-op again.
* Every declared marker is registered, since ``--strict-markers`` is on and an
  unregistered marker would fail the build rather than the reader.
* ``pythonpath`` and ``testpaths`` still point where the imports assume.

When the markers are applied to the suite for real, the first test flips from
failing to passing and nothing else needs to change. That is the intent: this
file is a to-do list expressed as a test.
"""

from __future__ import annotations

import re
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = REPO_ROOT / "pyproject.toml"
README = REPO_ROOT / "README.md"

MARKER_PATTERN = re.compile(r"pytest\.mark\.(\w+)")


def _config() -> dict:
    return tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))


def _declared_markers() -> list[str]:
    raw = _config()["tool"]["pytest"]["ini_options"]["markers"]
    return [line.split(":", 1)[0].strip() for line in raw]


def _markers_in_use() -> set[str]:
    """Declared markers actually applied to tests.

    Two filters matter. Only the five declared names count, so pytest's own
    builtins (``parametrize``, ``skipif``) do not make the suite look marked.
    And this file is excluded from its own scan, because it necessarily mentions
    ``pytest.mark.<name>`` in its parametrize list and documentation.
    """

    declared = set(_declared_markers())
    used: set[str] = set()
    for path in sorted((REPO_ROOT / "tests").glob("test_*.py")):
        if path.name == Path(__file__).name:
            continue
        found = MARKER_PATTERN.findall(path.read_text(encoding="utf-8"))
        used.update(name for name in found if name in declared)
    return used


def _marker_names_documented_in_readme() -> list[str]:
    body = README.read_text(encoding="utf-8")
    return sorted(set(re.findall(r"pytest -m (\w+)", body)))


def _select_count(marker: str) -> int:
    """How many tests ``-m <marker>`` would collect.

    pytest exits 5 ("no tests collected") when the selection is empty, so that
    return code is the interesting case, not a crash.
    """

    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "-q",
         "--collect-only", "-m", marker],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        timeout=300,
    )
    output = result.stdout + result.stderr
    assert result.returncode in (0, 5), output
    match = re.search(r"(\d+) tests? collected", output)
    return int(match.group(1)) if match else 0


#: True while no test in the suite carries a marker. These checks are a tracked
#: gap rather than a failure: they turn into real passes the moment the marker
#: taxonomy is applied, at which point the xfail marks should be removed.
PENDING = pytest.mark.xfail(
    condition=not _markers_in_use(),
    reason=(
        "no test carries a pytest marker yet, so every `-m <name>` selection is "
        "empty. Tracked as a gap in README section 18; these become real passes "
        "as soon as the markers are applied."
    ),
)


# -- configuration -----------------------------------------------------------


def test_pythonpath_and_testpaths_are_what_the_imports_assume():
    options = _config()["tool"]["pytest"]["ini_options"]
    assert options["pythonpath"] == ["."], (
        "the repository root must be the import root: the domain packages live "
        "at the root while the FastAPI app lives under backend/"
    )
    assert options["testpaths"] == ["tests"]
    assert "--strict-markers" in options["addopts"]


def test_every_declared_marker_is_registered():
    """Guards against a marker used in a test but missing from the config."""

    declared = set(_declared_markers())
    assert declared == {"unit", "integration", "contract", "fixture", "slow"}


@PENDING
@pytest.mark.parametrize("marker", sorted({"unit", "integration", "contract", "fixture", "slow"}))
def test_marker_is_applied_to_at_least_one_test(marker):
    """Every declared marker must select at least one real test."""

    assert marker in _markers_in_use(), (
        f"no test carries @pytest.mark.{marker}, so `pytest -m {marker}` runs "
        "nothing. Apply the marker to the relevant tests, or drop it from "
        "pyproject.toml and README section 15."
    )
    assert _select_count(marker) > 0


@PENDING
@pytest.mark.parametrize("marker", sorted(set(_marker_names_documented_in_readme()) or {"unit"}))
def test_readme_documented_marker_selection_runs_something(marker):
    """A ``-m <name>`` command in the README must not deselect the whole suite."""

    assert _select_count(marker) > 0, (
        f"README documents `pytest -m {marker}` but that expression collects "
        "zero tests."
    )