@echo off
REM ===========================================================================
REM XPRisk demonstration launcher
REM ===========================================================================
REM
REM Usage, from the repository root:
REM
REM     .\demo.cmd              full demo: pre-flight, scenarios, dashboard
REM     .\demo.cmd check        pre-flight and scenarios only, no dashboard
REM
REM What it deliberately does NOT do
REM -----------------------------
REM * It does not start the backend. The dashboard reads the risk engine and the
REM   SQLite database directly, so the backend is not part of the demo path. It
REM   is started separately, only if you want to show /health:
REM
REM       .\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --port 8000
REM
REM * It does not require PostgreSQL, Docker or any security tool to be
REM   installed. Every scanner adapter degrades to UNAVAILABLE when its tool is
REM   missing, and the dashboard replays recorded scanner output either way.
REM
REM * It does not modify risk_engine constants, and it does not invent data. The
REM   scenarios print what the model actually does, including the rows that
REM   contradict their expected decision.
REM
REM See README section 13 for the dashboard and section 18 for what is and is
REM not verified.
REM ===========================================================================

setlocal
set PYTHONIOENCODING=utf-8

set "PY=.\.venv\Scripts\python.exe"
set "STREAMLIT=.\.venv\Scripts\streamlit.exe"

if not exist "%PY%" (
    echo [FAIL] Virtual environment not found.
    echo        Expected: %PY%
    echo        Run: python -m venv .venv
    exit /b 1
)

echo.
echo ==========================================================
echo  XPRisk - Phase 1-14 demonstration
echo ==========================================================
echo.

REM --- 1. Which scanners can XPRisk actually see right now? ------------------
echo [1/4] Scanner availability (real tools, not fixtures)
echo --------------------------------------------------------------
"%PY%" -c "from scanners.base import _locate_executable as f; [print(f'      {t:<9} {f(t) or \"not installed - will report UNAVAILABLE\"}') for t in ('checkov','trivy','gitleaks')]"
echo.

REM --- 2. The test suite ----------------------------------------------------
echo [2/4] Test suite
echo --------------------------------------------------------------
"%PY%" -m pytest -p no:cacheprovider -p no:warnings -q --no-header -rN
if errorlevel 1 (
    echo.
    echo [FAIL] Tests did not pass. Stop and fix this before the panel.
    exit /b 1
)
echo.

REM --- 3. The six controlled scenarios --------------------------------------
echo [3/4] Controlled scenarios - what the model actually does
echo --------------------------------------------------------------
"%PY%" run_integration_scenarios.py
echo.
echo Note the MISMATCH rows in TEST 2 and TEST 3. They are a documented
echo limitation of additive scoring, not a bug: see docs\risk-model.md 7.2.
echo Show them rather than hiding them.
echo.

if /i "%~1"=="check" goto :done

REM --- 4. The dashboard -----------------------------------------------------
if not exist "%STREAMLIT%" (
    echo [FAIL] Streamlit not found in the virtual environment.
    echo        Run: .\.venv\Scripts\python.exe -m pip install -r requirements.txt
    exit /b 1
)

echo [4/4] Dashboard
echo --------------------------------------------------------------
echo   Starting Streamlit on http://localhost:8501
echo.
echo   Demo order:
echo     1. Sidebar: Fixture scenario = "Secrets only"
echo        Environment = development, Exposure = internal      score 36.9  WARNING
echo        Run assessment
echo        Switch to production + internet-facing, re-run      score 51.4  WARNING
echo        Identical findings, different score. That is the contribution.
echo     2. Scroll to Explanation - the derivation steps and contributors.
echo     3. Deployment context / Context factors - show the 1.6 cap binding.
echo     4. Only then, the full-scan preset. Both large presets saturate at
echo        100.0 / BLOCK; the dashboard warns about this. Say so out loud.
echo.
echo   Close the browser or press Ctrl+C here when finished.
echo --------------------------------------------------------------
echo.

"%STREAMLIT%" run dashboard/app.py --server.headless false

:done
echo.
echo Done.
endlocal