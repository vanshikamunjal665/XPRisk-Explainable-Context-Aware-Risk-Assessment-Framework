"""Tests for the ASGI application itself (Phase 13 groundwork).

Why this file exists
--------------------
``backend/app/main.py`` previously imported its settings with
``from app.config import ...``, which only resolves when ``backend/`` is on
``sys.path``. Nothing in the suite exercised this module, so the mismatch
survived: the whole suite passed while the command the README tells a reader to
run failed on the first line::

    python -m uvicorn backend.app.main:app
    ModuleNotFoundError: No module named 'app'

Two things are pinned here so it cannot recur.

**The import path.** :func:`test_main_module_imports_without_backend_on_sys_path`
re-imports the module in a subprocess with only the repository root on
``sys.path``, which is exactly the environment uvicorn creates.

**The surface.** The application must register the routes it claims and only
those. That matters because README sections 12 and 17 document these endpoints,
and a documented endpoint that does not exist is worse than an undocumented one.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parent.parent

#: Paths README sections 12 and 17 tell a reader to open.
DOCUMENTED_ROUTES = frozenset({"/health"})

#: FastAPI mounts these on every application whether or not they are wanted.
FRAMEWORK_ROUTES = frozenset({"/docs", "/docs/oauth2-redirect", "/redoc", "/openapi.json"})


def _client(settings=None) -> TestClient:
    from backend.app.main import create_app

    return TestClient(create_app(settings))


# -- import path -------------------------------------------------------------


def test_main_module_imports_without_backend_on_sys_path(tmp_path):
    """Import exactly as uvicorn does: repo root on sys.path, nothing else.

    ``backend/`` is deliberately absent. A subprocess is used because the test
    process has already imported the module, and because ``sys.path`` cannot be
    meaningfully narrowed in-process without breaking pytest itself.
    """

    probe = tmp_path / "probe.py"
    probe.write_text(
        textwrap.dedent(
            """
            import sys
            from pathlib import Path

            root = Path(sys.argv[1])
            sys.path = [str(root)] + [p for p in sys.path if "backend" not in p]
            assert not any(p.endswith("backend") for p in sys.path), sys.path

            from backend.app.main import app  # noqa: F401

            paths = sorted(r.path for r in app.routes if getattr(r, "path", ""))
            print("PATHS", ",".join(paths))
            """
        ).strip(),
        encoding="utf-8",
    )

    result = subprocess.run(
        [sys.executable, str(probe), str(REPO_ROOT)],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        timeout=120,
    )
    assert result.returncode == 0, result.stderr
    assert "PATHS" in result.stdout, result.stdout
    assert "/health" in result.stdout


def test_the_broken_import_style_would_still_fail():
    """Pin *why* the subprocess test above is necessary.

    ``from app.config import ...`` resolves when ``backend/`` is on ``sys.path``
    and fails when it is not. If someone reintroduces that style, this test
    shows the failure is real rather than a stylistic preference.
    """

    script = "from app.config import AppSettings  # noqa: F401\n"
    with_backend = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        env={**_clean_env(), "PYTHONPATH": str(REPO_ROOT / "backend")},
        timeout=120,
    )
    without_backend = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        timeout=120,
    )

    assert with_backend.returncode == 0
    assert without_backend.returncode != 0
    assert "No module named 'app'" in without_backend.stderr


def _clean_env() -> dict[str, str]:
    """A copy of the environment with PYTHONPATH removed."""

    import os

    return {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}


def test_readme_run_command_is_the_one_that_works():
    """The documented ASGI target string must be the importable one.

    If this string changes in the README, this test fails rather than letting
    the documentation and the code drift apart silently.
    """

    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert "backend.app.main:app" in readme

    module_name, _, attribute = "backend.app.main:app".partition(":")
    import importlib

    module = importlib.import_module(module_name)
    assert hasattr(module, attribute)


# -- routes ------------------------------------------------------------------


def test_only_health_is_registered():
    """The application exposes /health and nothing that is not implemented.

    Phase 13 routers do not exist yet. This test is the guard that stops a
    half-written router from being mounted, and the reason README section 17
    lists no working API call. The documentation routes FastAPI adds itself are
    excluded, since they are not XPRisk code.
    """

    from backend.app.main import app

    paths = {r.path for r in app.routes if getattr(r, "path", "")}
    assert paths - FRAMEWORK_ROUTES == DOCUMENTED_ROUTES


def test_health_reports_status_and_database():
    response = _client().get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "healthy"
    assert body["database"] in {"ok", "unavailable"}
    assert set(body) == {"status", "app", "environment", "database"}


def test_health_survives_an_unreachable_database():
    """Health must report an unreachable database, never raise on it.

    A liveness probe that crashes when its dependency is down is worse than no
    probe, because it turns a partial outage into a total one.
    """

    from backend.app.config import AppSettings

    settings = AppSettings(
        app_name="XPRisk",
        app_env="development",
        database_url="postgresql+psycopg2://nobody:nothing@127.0.0.1:1/nothing",
    )
    response = _client(settings).get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"
    assert response.json()["database"] == "unavailable"


def test_settings_are_injectable_not_read_from_the_environment(monkeypatch):
    """``create_app`` takes its settings; it does not re-read the environment.

    This is the property that lets tests build isolated applications without
    mutating process state.
    """

    from backend.app.config import AppSettings

    monkeypatch.setenv("APP_NAME", "should-be-ignored")
    settings = AppSettings(app_name="Injected", app_env="staging", database_url="sqlite:///")
    body = _client(settings).get("/health").json()
    assert body["app"] == "Injected"
    assert body["environment"] == "staging"


# -- schema ------------------------------------------------------------------


def test_openapi_schema_is_served():
    response = _client().get("/openapi.json")
    assert response.status_code == 200
    assert "/health" in response.json()["paths"]


@pytest.mark.parametrize("path", ["/docs", "/redoc"])
def test_interactive_docs_are_served(path):
    assert _client().get(path).status_code == 200


@pytest.mark.parametrize(
    "path",
    ["/scan", "/findings", "/risk", "/risk/evaluate", "/explanation", "/trends", "/deployments"],
)
def test_documented_but_unimplemented_routes_return_404(path):
    """README section 17 previously documented these; they do not exist.

    They are Phase 12-13 work. Asserting the 404 keeps the gap explicit and
    makes it impossible for a half-implemented endpoint to pass as done.
    """

    assert _client().get(path).status_code == 404