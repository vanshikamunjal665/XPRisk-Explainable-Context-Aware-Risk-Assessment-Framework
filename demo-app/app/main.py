"""Application factory and process entry point for the XPRisk demo app.

Run locally::

    cd demo-app
    python -m app.main

Run in a container::

    docker build -t xprisk-demo-app:latest .
    docker run --rm -p 5000:5000 xprisk-demo-app:latest

The factory pattern is used so that the WSGI application object is created by a
callable rather than at import time. That allows the test suite to build an
isolated instance per test with overridden settings, which is the same approach
XPRisk's own backend uses.
"""

from __future__ import annotations

import logging
import sys
from typing import Any, Final

from flask import Flask, jsonify, request
from werkzeug.exceptions import HTTPException

from .api.health import health_bp
from .api.routes import api_bp, root_bp
from .config import Settings

LOG_FORMAT: Final[str] = "%(asctime)s %(levelname)-8s [%(name)s] %(message)s"


def configure_logging(level_name: str) -> logging.Logger:
    """Configure root logging for the process.

    Args:
        level_name: Logging level name such as ``INFO`` or ``DEBUG``.

    Returns:
        The configured root logger.
    """
    level = getattr(logging, level_name.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format=LOG_FORMAT,
        stream=sys.stdout,
        force=True,
    )
    return logging.getLogger("xprisk-demo-app")


def create_app(settings: Settings | None = None) -> Flask:
    """Build and configure the Flask application.

    Args:
        settings: Optional settings override. When omitted, settings are read
            from the environment via :meth:`Settings.from_env`.

    Returns:
        A fully configured :class:`~flask.Flask` application.
    """
    resolved = settings or Settings.from_env()

    app = Flask(__name__)
    app.config["SETTINGS"] = resolved
    app.config["JSON_SORT_KEYS"] = False
    app.url_map.strict_slashes = False

    app.register_blueprint(root_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(health_bp)

    _register_error_handlers(app)
    _register_request_logging(app)

    return app


def _register_error_handlers(app: Flask) -> None:
    """Attach JSON error handlers.

    A JSON API must not return Flask's default HTML error page, because a
    pipeline or a scanner parsing the response would receive unexpected markup.

    Args:
        app: The application to configure.
    """

    @app.errorhandler(404)
    def handle_not_found(error: HTTPException) -> Any:
        """Return a JSON body for an unknown route.

        Args:
            error: The raised HTTP exception. The live request is read from
                the request context rather than from the exception, because a
                werkzeug ``HTTPException`` is not guaranteed to carry a request.

        Returns:
            A JSON response with status 404.
        """
        return (
            jsonify(
                {
                    "error": "not_found",
                    "detail": f"No route matches {request.path!r}.",
                }
            ),
            404,
        )

    @app.errorhandler(405)
    def handle_method_not_allowed(error: HTTPException) -> Any:
        """Return a JSON body for an unsupported HTTP method.

        Args:
            error: The raised HTTP exception.

        Returns:
            A JSON response with status 405.
        """
        return (
            jsonify(
                {
                    "error": "method_not_allowed",
                    "detail": f"Method {request.method!r} is not allowed for {request.path!r}.",
                }
            ),
            405,
        )

    @app.errorhandler(Exception)
    def handle_unexpected(error: Exception) -> Any:
        """Return a JSON body for any unhandled error.

        The exception is logged but never echoed to the client, so an internal
        failure cannot leak a stack trace or a configuration value.

        Args:
            error: The raised exception.

        Returns:
            A JSON response with status 500.
        """
        app.logger.exception("Unhandled error while serving request: %s", error)
        return (
            jsonify(
                {
                    "error": "internal_server_error",
                    "detail": "The service encountered an unexpected condition.",
                }
            ),
            500,
        )


def _register_request_logging(app: Flask) -> None:
    """Log every request and its outcome.

    Args:
        app: The application to configure.
    """

    @app.after_request
    def log_request(response: Any) -> Any:
        """Log the completed request.

        The request context is still active inside ``after_request``, so
        ``flask.request`` is read from the context. ``response.request`` does
        not exist: a werkzeug ``Response`` carries no reference to its request.

        Args:
            response: The outgoing response object.

        Returns:
            The same response, unchanged.
        """
        app.logger.info(
            "%s %s -> %s",
            response.status_code,
            request.method,
            request.path,
        )
        return response


def main() -> None:
    """Run the development server.

    Reads host and port from the environment via
    :meth:`Settings.from_env`, and defaults to ``0.0.0.0:5000`` so the same
    command works locally and inside a container.
    """
    settings = Settings.from_env()
    logger = configure_logging(settings.log_level)
    app = create_app(settings)

    logger.info(
        "Starting %s v%s (scenario=%s, environment=%s)",
        settings.app_name,
        settings.version,
        settings.scenario,
        settings.environment,
    )
    logger.info("Health endpoint available at http://%s:%s/health", settings.host, settings.port)

    app.run(host=settings.host, port=settings.port, debug=settings.debug)


if __name__ == "__main__":
    main()