"""XPRisk Phase 3 - CLEAN code counterpart to insecure_code.py.

This module provides structurally comparable, safe implementations of the
same functions. SonarQube is expected to report none of the intentional
findings that insecure_code.py is designed to produce.
"""

from __future__ import annotations

import os
import secrets
import sqlite3
import subprocess

# Credentials come from the environment; no hard-coded value.
DEFAULT_PASSWORD_ENV_VAR = "XPRISK_PASSWORD"


def run_command(argv: list[str]) -> int:
    # Argument list form, never a shell string, no user-controlled shell.
    return subprocess.run(argv, check=False).returncode


def read_file(base_dir: str, filename: str) -> str:
    # Confine reads to a known directory.
    safe = os.path.normpath(os.path.join(base_dir, filename))
    if not safe.startswith(os.path.abspath(base_dir)):
        raise ValueError("path escapes base directory")
    with open(safe, "r", encoding="utf-8") as handle:
        return handle.read()


def login(username: str, password: str) -> bool:
    # Parameterised query; constant-time-free simple comparison is fine for a
    # fixture, the point is that no SQL concatenation occurs.
    connection = sqlite3.connect(":memory:")
    cursor = connection.execute(
        "SELECT 1 FROM users WHERE name = ?", (username,)
    )
    return cursor.fetchone() is not None and bool(password)


def generate_token() -> str:
    # Cryptographically secure randomness for security-sensitive values.
    return secrets.token_hex(16)
