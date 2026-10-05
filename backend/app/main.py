"""XPRisk FastAPI application factory.

This module intentionally provides the smallest runnable surface consistent
with the architecture documented in ``backend/app/__init__.py``:

* ``create_app()`` - application factory, so tests can build isolated apps.
* ``app``           - the module-level ASGI application uvicorn serves.
* ``GET /health``   - liveness/readiness summary. It answers even when the
                      database is unreachable; it only *reports* database
                      status, it never crashes on it.

Routers under ``backend/app/api/`` will be mounted here as the later phases
implement them. Nothing in this file performs scanning, normalization,
risk scoring or explanation.

Configuration
-------------
Settings come from :mod:`backend.app.config`, which is the single module in
XPRisk that reads the process environment. This module previously read
``APP_NAME``, ``APP_ENV`` and ``DATABASE_URL`` directly from ``os.environ``; it
now uses the validated ``AppSettings`` object instead, so a malformed value fails
at startup rather than at the first request that happens to need it.

The config import is absolute (``backend.app.config``) rather than relative for a
practical reason: this module must be importable by the ASGI server string
``backend.app.main:app`` with only the repository root on ``sys.path``. An earlier
version used ``from app.config import ...``, which resolves only when ``backend/``
itself is on ``sys.path``. That import passed the test suite, because the test
that imports this module also inserts ``backend`` into ``sys.path``, but it failed
immediately under the documented run command::

    python -m uvicorn backend.app.main:app
    ModuleNotFoundError: No module named 'app'

``tests/test_backend_app.py`` now imports this module the way uvicorn does, so
that class of mismatch cannot come back.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any

from fastapi import FastAPI

from backend.app.config import AppSettings, get_app_settings


@lru_cache(maxsize=1)
def _sqlalchemy_engine(database_url: str):
    """One SQLAlchemy engine per database URL, reused across health checks.

    Creating an engine per request opens a fresh connection pool every time,
    which leaks connections under repeated polling. Caching the engine keeps
    the pool alive and is the standard FastAPI pattern.

    Failures are not cached: if the database is unavailable at startup, a later
    request should still be able to establish a connection.
    """

    from sqlalchemy import create_engine

    return create_engine(database_url, pool_pre_ping=True)


def _database_status(settings: AppSettings) -> str:
    """Return "ok" when the configured database answers ``SELECT 1``."""

    try:
        from sqlalchemy import text

        engine = _sqlalchemy_engine(settings.database_url)
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return "ok"
    except Exception:  # noqa: BLE001 - health must report, never raise
        return "unavailable"


def create_app(settings: AppSettings | None = None) -> FastAPI:
    """Build the ASGI application.

    ``settings`` is injectable so tests can supply an isolated configuration
    instead of mutating the process environment.
    """

    resolved = settings or get_app_settings()
    application = FastAPI(title=resolved.app_name, version="0.1.0")

    @application.get("/health")
    def health() -> dict[str, Any]:
        return {
            "status": "healthy",
            "app": resolved.app_name,
            "environment": resolved.app_env,
            "database": _database_status(resolved),
        }

    return application


app = create_app()