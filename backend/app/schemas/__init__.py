"""Pydantic request and response schemas - **planned, none defined**.

This package is empty. There is no schema class here, because there is no
endpoint to validate: the application registers only ``GET /health``, which
takes no input. Schemas are Phase 13 work.

``DeploymentContext``, ``EvaluateRiskRequest`` and the policy described below are
the design, not existing code.

Separation from the ORM
-----------------------
These schemas are intentionally *not* the SQLAlchemy models. The database is an
implementation detail that will change (new columns, new indexes, a
different engine); the API contract is a promise to the dashboard and to any
future CI/CD integration. Keeping them separate means a migration can never
silently break a client, and a response can be shaped for readability without
touching storage.

Validation policy (planned)
---------------------------
Every request body and path parameter is validated before a service is called.
In particular:

* ``DeploymentContext`` rejects unknown environments, unknown exposure values
  and unknown change statuses, so an invalid context can never reach the risk
  engine.
* ``EvaluateRiskRequest`` validates a supplied list of findings without
  persisting anything, which is what makes ``POST /risk/evaluate`` usable as a
  sandbox and in tests.
* Secret *values* are never part of any schema. A finding may carry a redacted
  preview of a matched secret, never the secret itself.

Until those schemas exist, context values are validated one layer down by the
enums in ``risk_engine.context`` and ``normalizer.models``: an unrecognised
environment raises rather than defaulting quietly. That is a weaker guarantee
than request-level validation, and it is the reason this package is on the
Phase 13 list rather than treated as optional.

``tests/test_service_layer.py::test_no_schemas_exist_yet`` asserts that this
package stays empty until that stops being true.
"""

__all__: list[str] = []