"""XPRisk security scanner adapters.

Each module in this package wraps exactly one external security tool:

===========================  ==========================================
Module                       Responsibility
===========================  ==========================================
``base.py``                  Shared contracts: :class:`ScannerResult`,
                             :class:`ScannerStatus`, the safe subprocess
                             runner, and error classification.
``gitleaks_scanner.py``      Secret detection over a git repo or directory.
``trivy_scanner.py``         Vulnerability scanning of an image, filesystem
                             path or remote repository.
``checkov_scanner.py``       Infrastructure-as-code policy scanning.
``sonarqube_scanner.py``     Static analysis via the SonarQube Web API.
===========================  ==========================================

Design rules enforced across this package
-----------------------------------------
1. **One tool per module.** A scanner adapter never parses another tool's
   output.
2. **No normalization here.** Adapters return *native* tool JSON plus status
   metadata. Translation into the XPRisk schema happens in ``normalizer/``,
   so that parser logic can be unit tested without executing any tool.
3. **No HTTP, no database, no risk logic.** Scanners are leaves of the
   dependency graph.
4. **Never trust scanner output.** Every adapter validates the shape of the
   JSON it receives before returning it, because a malformed or hostile
   report must not be able to crash the backend.
5. **Fail soft, report honestly.** A missing or failing tool yields a
   :class:`ScannerStatus` of ``UNAVAILABLE`` or ``FAILED`` with a captured
   error. It never raises through to the API layer.
6. **No shell.** Tools are executed with :func:`subprocess.run` using an
   explicit argument list and ``shell=False``. No command string is ever
   built from user input.
7. **No credentials in code or output.** SonarQube credentials come from the
   environment, and secret values are redacted before a finding is stored.

Real execution vs fixtures
--------------------------
Two clearly separated modes exist:

*Real execution* runs the genuine tool and returns genuinely produced JSON.
*Fixture mode* replays a JSON file from ``fixtures/<tool>/`` that is
labelled as fixture data.

Fixture mode exists so the test suite can run on a machine where the tools are
not installed. It is disabled by default (see ``ALLOW_FIXTURE_FALLBACK`` in
``.env.example``), is always marked as fixture-derived on the result, and is
never presented as real scanner output.
"""

__all__ = [
    "base",
    "checkov_scanner",
    "gitleaks_scanner",
    "sonarqube_scanner",
    "trivy_scanner",
]