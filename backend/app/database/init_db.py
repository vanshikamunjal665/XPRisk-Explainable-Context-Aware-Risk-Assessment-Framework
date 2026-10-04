"""Idempotent schema creation: ``python -m backend.app.database.init_db``.

Creates tables only. No seed data, no scanner execution.
"""

from __future__ import annotations

import sys

from sqlalchemy import text

from backend.app.database.database import get_database_url, make_engine
from backend.app.models import models  # noqa: F401 - register tables on Base
from backend.app.database.database import Base


def init_db(url: str | None = None) -> int:
    url = url or get_database_url()
    try:
        engine = make_engine(url)
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        Base.metadata.create_all(engine)
    except Exception as exc:  # noqa: BLE001 - report and fail clearly
        print(f"ERROR: database initialization failed: {exc.__class__.__name__}: {exc}", file=sys.stderr)
        return 1
    print(f"OK: schema created/verified ({len(Base.metadata.tables)} tables).")
    return 0


if __name__ == "__main__":
    raise SystemExit(init_db())
