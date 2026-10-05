"""XPRisk HTTP routers.

One router exists and is mounted by :mod:`backend.app.main`: ``scan``, providing
``POST /scan``. The rest of the table below is the Phase 13 design, **not**
current state — those endpoints return ``404``, and
``tests/test_backend_app.py`` asserts that so the gap cannot quietly close.

======================  ==========  ==========================================
Router                  Status      Endpoints
======================  ==========  ==========================================
``scan``                **done**    ``POST /scan``
``findings``            planned     ``GET /findings``, ``GET /findings/{deployment_id}``
``deployments``         planned     ``GET /deployments``, ``GET /deployments/{id}``
``risk``                planned     ``GET /risk/{deployment_id}``, ``POST /risk/evaluate``
``explanations``        planned     ``GET /explanation/{deployment_id}``
``trends``              planned     ``GET /trends``
======================  ==========  ==========================================

``GET /health`` lives directly in ``main.py`` because it must answer even when
the database or a scanner is unavailable, so it deliberately avoids depending
on any service.

Routers hold no business logic, which is the constraint the built one follows:
``scan.py`` validates with a Pydantic schema from ``backend.app.schemas``,
delegates to :class:`~backend.app.services.scan_service.ScanService`, and returns
a Pydantic response model. The pipeline sequence lives in the service, not here,
so it stays reachable from a script. That keeps the risk model testable without a
server.
"""

__all__: list[str] = []