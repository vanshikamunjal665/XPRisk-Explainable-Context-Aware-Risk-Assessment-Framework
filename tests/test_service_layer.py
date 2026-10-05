"""Tests for the service and schema layers (Phase 12/13 groundwork).

Why this file exists
--------------------
Three packages under ``backend/app/`` documented their intended contents in the
present tense, as though they had been built:

* ``api/__init__.py`` listed six routers and said they were "all mounted by
  ``backend.app.main``". The package is empty.
* ``services/__init__.py`` listed six services as if all six existed. Only
  ``storage_service`` does.
* ``schemas/__init__.py`` described a detailed validation policy over schemas
  that were never defined. The package is empty.

Nothing caught this, because a package docstring is not executable and no test
asserted anything about it. The docstrings now say "planned", and these tests
keep them honest.

Why this matters more than a docstring nit
------------------------------------------
The write half of the persistence layer is unreachable. ``create_deployment``,
``save_findings`` and ``save_risk_factors`` are called only from the test suite,
because the service that would compose them (``scan_service``) does not exist.
So ``xprisk_dev.db`` has zero rows and the dashboard's *Deployment history*
view is permanently empty. That is a real product gap, and it is invisible
unless something states it.

When Phase 12 lands, the assertions below flip: the expected sets are named
``EXPECTED_SERVICES`` and ``EXPECTED_ROUTERS`` so there is one place to edit.
"""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
BACKEND_APP = REPO_ROOT / "backend" / "app"

#: Services that exist today. Adding one here is the Phase 12 signal.
EXPECTED_SERVICES = {"storage_service"}

#: Routers that exist today. Empty by design: Phase 13 owns this set.
EXPECTED_ROUTERS: set[str] = set()

#: Pydantic schemas that exist today. Empty: nothing is exposed over HTTP yet.
EXPECTED_SCHEMAS: set[str] = set()

#: The write methods that no production code calls.
UNUSED_WRITE_METHODS = ("create_deployment", "save_findings", "save_risk_factors")


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


def test_only_the_implemented_service_exists():
    assert _modules("services") == EXPECTED_SERVICES


def test_no_routers_exist_yet():
    assert _modules("api") == EXPECTED_ROUTERS


def test_no_schemas_exist_yet():
    assert _modules("schemas") == EXPECTED_SCHEMAS


def test_storage_service_is_importable_and_complete():
    """The one service that exists must be a real one, not a stub."""

    from backend.app.services.storage_service import StorageService

    for method in UNUSED_WRITE_METHODS:
        assert callable(getattr(StorageService, method)), method


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


def test_api_docstring_does_not_claim_routers_are_mounted():
    text = _docstring("api")
    # "all mounted by" is the phrasing that made this a lie.
    assert "all mounted by" not in text.lower()
    assert "none implemented" in text.lower()


def test_service_docstring_records_the_absent_write_path():
    """The most important sentence in the codebase, so it is asserted."""

    text = _docstring("services")
    assert "no runnable path writes to the database" in text
    assert "only from" in text  # attributes the callers to the test suite


# -- the write path is unreachable, and that is documented -------------------


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
            name = func.attr if isinstance(func, ast.Attribute) else getattr(
                func, "id", ""
            )
            if name == method:
                return True
    return False


@pytest.mark.parametrize("method", UNUSED_WRITE_METHODS)
def test_write_methods_have_no_production_caller_yet(method):
    """Documents the gap instead of hiding it.

    This passes while the method is uncalled and the reason is documented. It
    starts failing the moment production code calls it, which is the signal to
    delete the assertion and remove gap 5 from README section 18.
    """

    callers = [p for p in _production_sources() if _calls_method(p, method)]

    if not callers:
        assert "no runnable path writes to the database" in _docstring("services")
        return

    pytest.fail(
        f"{method} now has a production caller: "
        f"{[str(p.relative_to(REPO_ROOT)) for p in callers]}. Persistence is live. "
        "Drop this assertion and update README section 5 and section 18 gap 5."
    )


def test_readme_records_the_persistence_gap():
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert "No runnable path writes to the database" in readme
    assert "implemented, never called" in readme


def test_development_database_is_empty_as_documented():
    """The dev SQLite file must be empty, or the documentation is stale."""

    import sqlite3

    db = REPO_ROOT / "xprisk_dev.db"
    if not db.exists():
        pytest.skip("xprisk_dev.db has not been created on this machine")

    connection = sqlite3.connect(db)
    try:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        if not {"deployments", "findings", "risk_factors"} <= tables:
            pytest.skip("schema not initialised in the development database")

        counts = {
            table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("deployments", "findings", "risk_factors")
        }
    finally:
        connection.close()

    assert all(count == 0 for count in counts.values()), (
        f"the development database now holds rows: {counts}. Persistence is live, so "
        "README section 5 and section 18 gap 5 are out of date."
    )


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