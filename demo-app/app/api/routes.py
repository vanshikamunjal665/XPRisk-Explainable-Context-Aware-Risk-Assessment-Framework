"""Application routes.

Three small endpoints that give the demo service a realistic surface to scan
and to exercise:

``GET /``
    Service banner and a route index.
``GET /api/info``
    Service metadata, including the active scenario.
``GET /api/greet/<name>``
    Basic greeting endpoint.
``GET /api/calculate``
    Basic business-logic endpoint with query parameters.

Input handling
--------------
All caller supplied values are parsed defensively and errors are returned as
structured JSON with an appropriate status code. Nothing here evaluates caller
input, and no caller input is ever passed to a shell or used to build a file
path.
"""

from __future__ import annotations

from typing import Any, Final

from flask import Blueprint, current_app, jsonify, request

from ..services.greeting import (
    SUPPORTED_OPERATIONS,
    calculate,
    describe_operation,
    greeting_for,
)

root_bp = Blueprint("root", __name__)
api_bp = Blueprint("api", __name__, url_prefix="/api")

DEFAULT_OPERAND: Final[float] = 0.0


@root_bp.get("/")
def index() -> Any:
    """Serve the service banner.

    Returns:
        A JSON response naming the service and listing the available routes.
    """
    settings = current_app.config["SETTINGS"]
    return (
        jsonify(
            {
                "service": settings.app_name,
                "message": "XPRisk Demo Application",
                "description": (
                    "Target application scanned by XPRisk, the Explainable "
                    "Context-Aware Risk Assessment Framework."
                ),
                "scenario": settings.scenario,
                "routes": {
                    "health": "/health",
                    "liveness": "/health/live",
                    "readiness": "/health/ready",
                    "info": "/api/info",
                    "greet": "/api/greet/<name>",
                    "calculate": "/api/calculate?left=1&right=2&operation=add",
                },
            }
        ),
        200,
    )


@api_bp.get("/info")
def info() -> Any:
    """Return service metadata.

    Returns:
        A JSON response describing the running service.
    """
    settings = current_app.config["SETTINGS"]
    return (
        jsonify(
            {
                "name": settings.app_name,
                "version": settings.version,
                "environment": settings.environment,
                "scenario": settings.scenario,
                "supported_operations": list(SUPPORTED_OPERATIONS),
            }
        ),
        200,
    )


@api_bp.get("/greet/<path:name>")
def greet(name: str) -> Any:
    """Greet a caller by name.

    Args:
        name: Caller supplied name, taken from the URL path.

    Returns:
        A JSON response containing the greeting.
    """
    return jsonify({"greeting": greeting_for(name)}), 200


def _parse_operand(raw: str | None) -> tuple[float, bool]:
    """Parse an optional numeric query parameter.

    Args:
        raw: Raw query parameter value, possibly ``None``.

    Returns:
        A tuple of the parsed value and a flag indicating whether parsing
        succeeded.
    """
    if raw is None or raw == "":
        return DEFAULT_OPERAND, True
    try:
        return float(raw), True
    except ValueError:
        return DEFAULT_OPERAND, False


@api_bp.get("/calculate")
def calculate_endpoint() -> Any:
    """Apply an arithmetic operation to two query parameters.

    Query Parameters:
        left: Left operand. Defaults to ``0``.
        right: Right operand. Defaults to ``0``.
        operation: One of ``add``, ``subtract``, ``multiply``. Defaults to
            ``add``.

    Returns:
        ``200`` with the result, or ``400`` when an operand is not numeric or
        the operation is unsupported.
    """
    left, left_ok = _parse_operand(request.args.get("left"))
    right, right_ok = _parse_operand(request.args.get("right"))

    if not left_ok or not right_ok:
        return (
            jsonify(
                {
                    "error": "invalid_operand",
                    "detail": "Query parameters 'left' and 'right' must be numeric.",
                }
            ),
            400,
        )

    operation = request.args.get("operation", "add")

    try:
        result = calculate(left, right, operation)
    except ValueError as error:
        return jsonify({"error": "unsupported_operation", "detail": str(error)}), 400

    return (
        jsonify(
            {
                "operation": operation.strip().lower(),
                "description": describe_operation(operation),
                "left": left,
                "right": right,
                "result": result,
            }
        ),
        200,
    )