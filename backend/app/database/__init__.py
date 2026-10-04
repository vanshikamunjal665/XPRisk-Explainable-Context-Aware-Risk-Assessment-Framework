"""Database engine, session management and schema initialisation.

Responsibilities
----------------
``database.py``
    Declarative base, engine creation, session factory and the FastAPI
    dependency that yields a scoped session.

``init_db.py``
    Idempotent schema creation plus a small connectivity check used by
    ``GET /health``.

Engine selection
----------------
The engine is chosen purely from ``DATABASE_URL``, so the same code runs
against PostgreSQL (the target) and SQLite (a zero-setup fallback for local
development and the automated test suite). PostgreSQL specific tuning
(pool sizing, ``pool_pre_ping``) is applied only when the dialect is
PostgreSQL.

Credentials
-----------
Connection strings come from the environment only. They are never hardcoded,
never logged, and the URL is redacted before it appears in any log line or
health payload.
"""

from backend.app.database.database import (  # noqa: E402
    Base,
    get_database_url,
    make_engine,
    make_session_factory,
    session_scope,
)

__all__ = [
    "Base",
    "get_database_url",
    "make_engine",
    "make_session_factory",
    "session_scope",
]