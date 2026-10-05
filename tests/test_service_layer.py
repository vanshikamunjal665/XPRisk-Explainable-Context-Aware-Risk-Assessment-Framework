"""Tests for the service and schema layers (Phases 12-13).

Why this file exists
--------------------
Three packages under ``backend/app/`` documented their intended contents in the
present tense, as though they had been built: ``api/__init__.py`` listed six
routers "all mounted by main", ``services/__init__.py`` listed six services as
though all six existed, and ``schemas/__init__.py`` described a validation
policy over schemas that were never defined. Nothing caught it, because a
package docstring is not executable.

These tests now do two jobs: they assert which modules exist, so a planned
module cannot be described as built, and they assert the write path is *used*,
because that gap was invisible until it was stated.

Status
------
Phase 12-13 has since landed the minimum viable API. ``scan_service`` composes
the pipeline, ``api/scan.py`` exposes ``POST /scan`` and ``schemas/scan.py``
validates it. The expected sets below were updated and the "no runnable path
writes to the database" assertions were removed, because they are no longer true
and keeping them would have been the same overclaiming in reverse.

What is still planned: the other five services and the other five routers.
"""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
BACKEND_APP = REPO_ROOT / "backend" / "app"

#: Services that exist. The documented-but-unbuilt five are listed in
#: ``backend/app/services/__init__.py`` as "planned".
EXPECTED_SERVICES = {"scan_service", "storage_service"}

#: Routers that exist. Phase 13 owns the rest of the table.
EXPECTED_ROUTERS = {"scan"}

#: Schema modules that exist.
EXPECTED_SCHEMAS = {"scan"}


# -- what exists -------------------------------------------------------------


def _modules(package: str) -> set[str]:
    """Module names directly inside ``backend/app/<package>``, minus dunders."""

    directory = BACKEND_APP / package
    if not directory.is_dir():
        return set()
    return {
        path.stem
        for path in directory.glob("*.py")
        if not path.stem.startswith("__")
    }


def test_only_the_implemented_services_exist():
    """An unbuilt module must not be described as if it exists."""

    assert _modules("services") == EXPECTED_SERVICES


def test_only_the_implemented_routers_exist():
    assert _modules("api") == EXPECTED_ROUTERS


def test_only_the_implemented_schema_modules_exist():
    assert _modules("schemas") == EXPECTED_SCHEMAS


def test_the_services_are_real_not_stubs():
    """Whatever exists must be a working implementation."""

    from backend.app.services.scan_service import ScanService
    from backend.app.services.storage_service import StorageService

    for method in ("create_deployment", "save_findings", "save_risk_factors"):
        assert callable(getattr(StorageService, method)), method

    assert callable(ScanService.assess)


# -- the docstrings must not overclaim ---------------------------------------


def _docstring(package: str) -> str:
    """Module docstring, whitespace-normalised and lowercased.

    Normalising matters: the sentences these tests look for are line-wrapped in
    the source, so a raw substring search would fail on formatting rather than on
    meaning.
    """

    path = BACKEND_APP / package / "__init__.py"
    if not path.exists():
        return ""
    text = ast.get_docstring(ast.parse(path.read_text(encoding="utf-8"))) or ""
    return " ".join(text.split()).lower()


@pytest.mark.parametrize(
    ("package", "planned_word"),
    [
        ("api", "planned"),
        ("services", "planned"),
        ("schemas", "planned"),
    ],
)
def test_unbuilt_packages_say_so(package, planned_word):
    """An unbuilt package must not describe itself as if it were built."""

    assert planned_word in _docstring(package), (
        f"backend/app/{package}/__init__.py describes unbuilt architecture in the "
        f"present tense. Say '{planned_word}' so a reader is not misled."
    )


def test_api_docstring_does_not_claim_unbuilt_routers_are_mounted():
    """The "all mounted by" phrasing is what made the original docstring a lie."""

    text = _docstring("api")
    assert "all mounted by" not in text
    assert "planned" in text


def test_service_docstring_no_longer_claims_an_absent_write_path():
    """The stale warning must be removed once persistence is live.

    An assertion in this file used to require the sentence "no runnable path
    writes to the database". That sentence was accurate when nothing called the
    write methods and became false the moment ``scan_service`` landed. Leaving it
    in would have been the same overclaiming the file exists to prevent, just
    pointing the other way.
    """

    assert "no runnable path writes to the database" not in _docstring("services")


def test_the_write_path_is_now_reachable():
    """Inverted from the assertion that used to require the gap.

    Persistence is live, so production code must call the write methods. If this
    ever stops being true the dashboard's history view silently goes empty again
    — which is exactly the failure this file was written to prevent.
    """

    write_methods = ("create_deployment", "save_findings", "save_risk_factors")
    callers = {
        method: [p for p in _production_sources() if _calls_method(p, method)]
        for method in write_methods
    }
    uncalled = sorted(m for m, paths in callers.items() if not paths)

    assert not uncalled, (
        f"nothing calls {uncalled} any more. Persistence is unreachable again, so "
        "the dashboard's Deployment history view will be permanently empty."
    )


# -- helpers for the write-path assertions -----------------------------------


def _production_sources() -> list[Path]:
    skipped = ("tests", "demo-app", ".venv", "dashboard", "__pycache__")
    out: list[Path] = []
    for path in REPO_ROOT.rglob("*.py"):
        parts = set(path.relative_to(REPO_ROOT).parts)
        if parts & set(skipped) or path.name == Path(__file__).name:
            continue
        out.append(path)
    return out


def _calls_method(path: Path, method: str) -> bool:
    """True if ``method`` is *called* somewhere in ``path``.

    The AST is used rather than a text search because a regex cannot tell a
    ``def create_deployment(`` definition from a call, and the definition itself
    lives in a production file. Counting that would report persistence as live
    when nothing calls it.
    """

    tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            name = (
                func.attr
                if isinstance(func, ast.Attribute)
                else getattr(func, "id", "")
            )
            if name == method:
                return True
    return False


def test_the_dashboard_history_view_has_a_producer():
    """The history view reads deployments, so something must write them.

    This is the inverse of the original gap assertion. Before ``scan_service``
    existed, the only writers were in the test suite and the view was
    permanently empty — an empty screen that looked like a broken feature rather
    than a missing producer.
    """

    import dashboard.app as app_module

    source = Path(app_module.__file__).read_text(encoding="utf-8")
    assert "Deployment history" in source, (
        "the history view was removed; if that was deliberate, update README "
        "section 13 and section 18 together"
    )
    assert _calls_method(Path(REPO_ROOT / "backend" / "app" / "services" / "scan_service.py"),
                         "create_deployment")


# -- the layering rule still holds -------------------------------------------


def test_domain_packages_do_not_import_the_service_layer():
    """`scanners`, `normalizer`, `risk_engine` and `explainability` stay free of
    the application layer, which is what keeps the risk model testable alone."""

    offenders: list[str] = []
    for package in ("scanners", "normalizer", "risk_engine", "explainability"):
        for path in sorted((REPO_ROOT / package).rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and (node.module or "").startswith(
                    ("backend", "dashboard")
                ):
                    offenders.append(f"{path.name}: {node.module}")
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name.startswith(("backend", "dashboard")):
                            offenders.append(f"{path.name}: {alias.name}")

    assert not offenders, (
        "domain packages must not import the application layer: " + "; ".join(offenders)
    )


def test_services_package_does_not_import_fastapi():
    """A service composes domain packages and the database, nothing above them."""

    path = BACKEND_APP / "services" / "__init__.py"
    assert "fastapi" not in path.read_text(encoding="utf-8").lower()


def test_importing_the_backend_needs_only_the_repository_root():
    """``python -m uvicorn backend.app.main:app`` sets up only the repo root.

    Regression guard for the ``from app.config import ...`` bug that made the
    documented run command fail; see ``tests/test_backend_app.py``.
    """

    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import backend.app.main, backend.app.services.storage_service;"
            "print('OK')",
        ],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        timeout=120,
    )
    assert result.returncode == 0, result.stderr
    assert "OK" in result.stdout