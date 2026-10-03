"""Pydantic request and response schemas (the public API contract).

Separation from the ORM
-----------------------
These schemas are intentionally *not* the SQLAlchemy models. The database is
an implementation detail that will change (new columns, new indexes, a
different engine); the API contract is a promise to the dashboard and to any
future CI/CD integration. Keeping them separate means a migration can never
silently break a client, and a response can be shaped for readability without
touching storage.

Validation policy
-----------------
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
"""

__all__: list[str] = []