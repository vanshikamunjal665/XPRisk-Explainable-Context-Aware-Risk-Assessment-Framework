"""XPRisk HTTP routers.

One router per resource, all mounted by :mod:`backend.app.main`:

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

``GET /health`` lives directly in ``main.py`` because it must answer even when
the database or a scanner is unavailable, so it deliberately avoids depending
on any service.

Routers hold no business logic. Each one validates its input with a Pydantic
schema from ``backend.app.schemas``, delegates to a service from
``backend.app.services``, and returns a Pydantic response model. That keeps the
risk model reachable without going through HTTP, which is what allows the
domain packages to be unit tested in isolation.
"""

__all__: list[str] = []