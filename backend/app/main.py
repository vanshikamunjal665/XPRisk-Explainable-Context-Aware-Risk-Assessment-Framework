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
"""

from __future__ import annotations

import os
from typing import Any

from fastapi import FastAPI

APP_NAME = os.environ.get("APP_NAME", "XPRisk")
APP_ENV = os.environ.get("APP_ENV", "development")
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./xprisk_dev.db")


def _database_status() -> str:
    """Return "ok" when the configured database answers ``SELECT 1``."""

    try:
        from sqlalchemy import create_engine, text

        engine = create_engine(DATABASE_URL, pool_pre_ping=True)
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return "ok"
    except Exception:  # noqa: BLE001 - health must report, never raise
        return "unavailable"


def create_app() -> FastAPI:
    application = FastAPI(title=APP_NAME, version="0.1.0")

    @application.get("/health")
    def health() -> dict[str, Any]:
        return {
            "status": "healthy",
            "app": APP_NAME,
            "environment": APP_ENV,
            "database": _database_status(),
        }

    return application


app = create_app()
