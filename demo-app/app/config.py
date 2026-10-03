"""Configuration for the XPRisk demo application.

Every value is resolved from the environment with a safe default, so the
application starts with no configuration at all and never requires a secret to
be supplied in order to boot.

Security note
-------------
This module contains **no credentials and no default passwords**. The only
authentication-related setting is ``REQUIRE_API_TOKEN``, which defaults to
``False`` so the demo runs unauthenticated out of the box. Phase 3 introduces a
clearly labelled, non-functional fake token for the secret-scanning test case;
it is read from the environment, never hardcoded, and is documented as fake
wherever it appears.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Final

DEFAULT_HOST: Final[str] = "0.0.0.0"
DEFAULT_PORT: Final[int] = 5000
DEFAULT_ENVIRONMENT: Final[str] = "development"

#: Scenarios this application can be started in. ``clean`` is the Phase 2
#: baseline; ``vulnerable`` is added in Phase 3 for the controlled test cases.
VALID_SCENARIOS: Final[frozenset[str]] = frozenset({"clean"})


def _read_bool(name: str, default: bool = False) -> bool:
    """Read a boolean from the environment.

    Accepts the spellings that appear in real configuration files, so that
    ``true``, ``True``, ``yes`` and ``1`` all behave as expected.

    Args:
        name: Environment variable name.
        default: Value used when the variable is unset or unparseable.

    Returns:
        The parsed boolean.
    """
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _read_int(name: str, default: int) -> int:
    """Read an integer from the environment, falling back on bad input.

    Args:
        name: Environment variable name.
        default: Value used when the variable is unset or not an integer.

    Returns:
        The parsed integer.
    """
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    """Immutable application settings.

    Attributes:
        app_name: Human readable service name.
        version: Service version, surfaced by ``/api/info``.
        environment: Deployment environment name.
        host: Interface the server binds to.
        port: TCP port the server listens on.
        debug: Flask debug mode. Defaults to off; never enable in production.
        require_api_token: Whether protected routes demand a token.
        scenario: Which code scenario is active.
        log_level: Logging level name.
    """

    app_name: str = "xprisk-demo-app"
    version: str = "0.1.0"
    environment: str = DEFAULT_ENVIRONMENT
    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    debug: bool = False
    require_api_token: bool = False
    scenario: str = "clean"
    log_level: str = "INFO"
    available_scenarios: frozenset[str] = field(default_factory=lambda: VALID_SCENARIOS)

    @classmethod
    def from_env(cls) -> "Settings":
        """Build settings from the process environment.

        An unrecognised ``DEMO_SCENARIO`` value falls back to ``clean`` rather
        than raising, so a typo in a deployment manifest cannot take the
        service down.

        Returns:
            A populated :class:`Settings` instance.
        """
        scenario = os.getenv("DEMO_SCENARIO", "clean").strip().lower()
        if scenario not in VALID_SCENARIOS:
            scenario = "clean"

        return cls(
            app_name=os.getenv("DEMO_APP_NAME", "xprisk-demo-app"),
            version=os.getenv("DEMO_APP_VERSION", "0.1.0"),
            environment=os.getenv("DEMO_ENVIRONMENT", DEFAULT_ENVIRONMENT),
            host=os.getenv("DEMO_HOST", DEFAULT_HOST),
            port=_read_int("DEMO_PORT", DEFAULT_PORT),
            debug=_read_bool("DEMO_DEBUG", False),
            require_api_token=_read_bool("DEMO_REQUIRE_API_TOKEN", False),
            scenario=scenario,
            log_level=os.getenv("DEMO_LOG_LEVEL", "INFO").upper(),
        )