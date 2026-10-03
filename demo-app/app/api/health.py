"""Health endpoints.

These exist because the demo application is the target of a cloud-native
pipeline, and a pipeline needs a probe. Keeping them in their own blueprint
means ``GET /health`` can be smoke tested independently of the business routes.

Endpoint contract
-----------------
``GET /health``
    Overall health. Returns ``200`` when the service is up.
``GET /health/live``
    Liveness probe. Answers "is the process running?". Never touches
    dependencies, so a slow dependency cannot cause a restart loop.
``GET /health/ready``
    Readiness probe. Answers "should this instance receive traffic?".
"""

from __future__ import annotations

import platform
import sys
from datetime import datetime, timezone
from typing import Any, Final

from flask import Blueprint, current_app, jsonify, request

health_bp = Blueprint("health", __name__, url_prefix="/health")

SERVICE_STATUS_OK: Final[str] = "healthy"
SERVICE_STATUS_DEGRADED: Final[str] = "degraded"


def _timestamp() -> str:
    """Return the current UTC time as an ISO 8601 string.

    Returns:
        An ISO 8601 timestamp with a ``Z`` suffix.
    """
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@health_bp.get("")
def health() -> Any:
    """Report overall service health.

    Returns:
        A JSON response carrying the service status, name, version, active
        scenario, runtime details and the caller's IP.
    """
    settings = current_app.config["SETTINGS"]
    payload: dict[str, Any] = {
        "status": SERVICE_STATUS_OK,
        "service": settings.app_name,
        "version": settings.version,
        "scenario": settings.scenario,
        "environment": settings.environment,
        "timestamp": _timestamp(),
        "runtime": {
            "python": sys.version.split()[0],
            "platform": platform.system(),
        },
    }
    request_info: dict[str, Any] = {"remote_addr": request.remote_addr}
    payload["request"] = request_info
    return jsonify(payload), 200


@health_bp.get("/live")
def liveness() -> Any:
    """Liveness probe.

    Intentionally dependency free: it reports only that the process is
    running and able to serve a request.

    Returns:
        A JSON response with ``status`` set to ``alive``.
    """
    return jsonify({"status": "alive", "timestamp": _timestamp()}), 200


@health_bp.get("/ready")
def readiness() -> Any:
    """Readiness probe.

    Reports whether the instance should receive traffic. The demo application
    has no external dependency to check, so readiness is equivalent to
    liveness; the endpoint exists so the pipeline contract is complete and so
    Phase 3 can demonstrate a genuinely failing readiness check.

    Returns:
        A JSON response with ``status`` set to ``ready``.
    """
    settings = current_app.config["SETTINGS"]
    return (
        jsonify(
            {
                "status": "ready",
                "service": settings.app_name,
                "checks": {"configuration": "ok", "dependencies": "none"},
                "timestamp": _timestamp(),
            }
        ),
        200,
    )