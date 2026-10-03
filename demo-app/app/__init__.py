"""XPRisk demo cloud-native application.

A small, deliberately well-structured Flask service that exists to be
*scanned* by XPRisk.

Why Flask rather than FastAPI
-----------------------------
XPRisk's own backend is FastAPI. Using FastAPI here as well would mean the
thing under test shares a framework with the thing doing the testing, which
weakens the demonstration. Flask keeps the target application small and
independent, and keeps the dependency surface of the scan target minimal.

This package is the **clean baseline**. Every module here is written to avoid
the patterns that static analysis flags: no hardcoded credentials, no bare
``except``, no unused imports, no functions doing too much, explicit types and
docstrings throughout.

Phase 3 adds the deliberately flawed modules alongside this code, selected by an
explicit scenario switch, so that XPRisk can be exercised against both a clean
target (integration TEST 1: no findings -> SAFE) and a flawed one, without
either copy contaminating the other.

Layout
------
``config.py``  Settings resolved from the environment. Contains no credentials.
``api/``       HTTP layer: request handling and response shaping only.
``services/``  Business logic. Pure functions, no Flask imports.
``main.py``    Application factory and process entry point.
"""

__version__ = "0.1.0"