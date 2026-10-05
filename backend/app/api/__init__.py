"""XPRisk HTTP routers - **planned, none implemented**.

This package is empty and contains no routers. The table below is the Phase 13
design, not a description of the current state. Verified: this package has no
submodules, and ``backend.app.main`` mounts nothing but ``GET /health``.

======================  ==================================================
Router                  Endpoints
======================  ==================================================
``scans``               ``POST /scan``
``findings``            ``GET /findings``, ``GET /findings/{deployment_id}``
``deployments``         ``GET /deployments``, ``GET /deployments/{id}``
``risk``                ``GET /risk/{deployment_id}``, ``POST /risk/evaluate``
``explanations``        ``GET /explanation/{deployment_id}``
``trends``              ``GET /trends``
======================  ==================================================

Until Phase 13 lands, every endpoint above returns ``404``. ``tests/
test_backend_app.py::test_documented_but_unimplemented_routes_return_404``
asserts that, so the gap cannot quietly close.

``GET /health`` lives directly in ``main.py`` because it must answer even when
the database or a scanner is unavailable, so it deliberately avoids depending
on any service. It is the only route the application registers.

The intended shape, when it is built: routers hold no business logic. Each one
validates its input with a Pydantic schema from ``backend.app.schemas``,
delegates to a service from ``backend.app.services``, and returns a Pydantic
response model. That keeps the risk model reachable without going through HTTP,
which is what allows the domain packages to be unit tested in isolation.
"""

__all__: list[str] = []