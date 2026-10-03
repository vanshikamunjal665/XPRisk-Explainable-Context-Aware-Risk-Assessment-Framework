"""HTTP layer for the XPRisk demo application.

Blueprints only. This package handles request parsing and response shaping;
all business logic lives in :mod:`app.services`.
"""

from .health import health_bp
from .routes import api_bp, root_bp

__all__ = ["api_bp", "health_bp", "root_bp"]