"""Pydantic request and response schemas for the HTTP API.

One module exists: :mod:`backend.app.schemas.scan`, which validates the body of
``POST /scan`` and types its response. The remaining schemas named below belong
to endpoints that do not exist yet, so they are the design rather than code, and
are deliberately not written speculatively.

================================  ========  ======================================
Schema                            Status    For
================================  ========  ======================================
``ScanContext``                   **done**  ``POST /scan`` - deployment context
``ScanRequest``                   **done**  ``POST /scan`` - body
``ScanResponse``                  **done**  ``POST /scan`` - response
``DeploymentContextRequest``      planned   ``POST /risk/evaluate``
``FindingInput``                  planned   ``POST /risk/evaluate``
================================  ========  ======================================

Separation from the ORM
-----------------------
These schemas are intentionally *not* the SQLAlchemy models. The database is an
implementation detail that will change (new columns, new indexes, a
different engine); the API contract is a promise to the dashboard and to any
future CI/CD integration. Keeping them separate means a migration can never
silently break a client, and a response can be shaped for readability without
touching storage.

Validation policy
-----------------
Every request body and path parameter is validated before a service is called:

* ``ScanContext`` restricts ``environment``, ``exposure`` and ``change_status``
  to the values the context model accepts, so an invalid context can never reach
  the risk engine. It returns ``422`` with the offending field, where letting the
  enum raise would give ``500``.
* Both request models set ``extra="forbid"``, so a typo such as ``severity``
  instead of ``change_status`` is rejected rather than silently ignored. A
  silently ignored flag is worse than a rejected request: the caller believes it
  configured something it did not.
* ``ScanRequest`` also refuses a fixture path supplied for a scanner that was not
  selected, because the alternative is answering a request for a real scan with
  recorded output.
* Secret *values* are never part of any schema. A finding may carry a redacted
  preview of a matched secret, never the secret itself.

The context enums in :mod:`risk_engine.context` would also reject a bad value;
validating at the boundary is strictly better because it names the field. That
is a deliberate belt-and-braces arrangement, not redundancy: the schema is the
contract with clients, the enum is the contract with the model.

``tests/test_service_layer.py::test_only_the_implemented_schema_modules_exist``
asserts the module set, so a planned schema cannot be described as built.
"""

from backend.app.schemas.scan import (  # noqa: F401
    ScanContext,
    ScanRequest,
    ScanResponse,
    ScannerStatusReport,
)

__all__ = [
    "ScanContext",
    "ScanRequest",
    "ScanResponse",
    "ScannerStatusReport",
]