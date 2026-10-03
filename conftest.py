"""XPRisk test suite root configuration.

pytest is configured in ``pyproject.toml`` (``pythonpath = ["."]``), which puts
the repository root on ``sys.path``. That single mechanism is what allows the
tests to import both the FastAPI application (``backend.app``) and the root
level domain packages (``risk_engine``, ``normalizer``, ``scanners``,
``explainability``) without installing the project.

This module exists for two reasons:

1. It guarantees the repository root is importable even when pytest is invoked
   from a different working directory.
2. It is the single place where session-scoped fixtures that the whole suite
   depends on will live, so they are not scattered across test modules.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))