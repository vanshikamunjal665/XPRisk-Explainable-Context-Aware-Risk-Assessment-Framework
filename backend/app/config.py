"""Application configuration (Phase 9).

The single place in XPRisk that reads the process environment.

Why this module exists
----------------------
Phases 6 and 8 kept the domain packages free of ambient configuration: the
normalizer holds its Gitleaks severity policy as a module constant, and
``ContextModel`` takes vocabulary through its constructor. ``risk_engine``
follows the same rule, so its numbers live in :mod:`risk_engine.settings` as
plain defaults.

This module is the other half of that contract. It reads the ``XPRISK_*``
variables declared in ``.env.example`` and *constructs* a
:class:`risk_engine.settings.RiskSettings`, which is then injected into the
engine. Nothing flows the other way: the domain packages never import this
module, so they stay testable without touching process state.

Fail fast
---------
Settings are validated by pydantic at construction. A malformed value such as
``XPRISK_SCORE_ANCHORS=8:10,0:0`` (anchors not increasing) or
``XPRISK_THRESHOLD_SAFE=90`` (safe above warning) raises immediately at
startup, instead of silently producing wrong scores that surface much later as
an unexplained risk number.

Import-time singleton
---------------------
:func:`get_settings` is cached, so the environment is read once. Tests that need
to vary configuration should construct their own
:class:`RiskModelSettings` rather than mutating the cached instance, or call
:func:`reset_settings_cache`.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from normalizer.models import Severity
from risk_engine.settings import RiskSettings
from risk_engine.severity import SeverityWeights

__all__ = [
    "AppSettings",
    "RiskModelSettings",
    "get_settings",
    "get_app_settings",
    "get_risk_settings",
    "reset_settings_cache",
]


def _parse_anchors(raw: str) -> tuple[tuple[float, float], ...]:
    """Parse ``XPRISK_SCORE_ANCHORS`` into ``((raw, score), ...)``.

    Accepts ``0:0,8:10`` and tolerates whitespace. Raises ``ValueError`` on a
    malformed entry so the failure surfaces at startup rather than at scoring
    time.
    """

    points: list[tuple[float, float]] = []
    for chunk in str(raw).split(","):
        text = chunk.strip()
        if not text:
            continue
        if ":" not in text:
            raise ValueError(f"score anchor {text!r} must be in 'raw:score' form")
        raw_part, _, score_part = text.partition(":")
        try:
            points.append((float(raw_part), float(score_part)))
        except ValueError as exc:
            raise ValueError(f"score anchor {text!r} has a non-numeric component") from exc

    if len(points) < 2:
        raise ValueError(f"XPRISK_SCORE_ANCHORS needs at least two points, got {len(points)}")
    return tuple(points)


class AppSettings(BaseSettings):
    """Application-level settings unrelated to the risk model."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    app_name: str = Field(default="XPRisk", alias="APP_NAME")
    app_env: str = Field(default="development", alias="APP_ENV")
    database_url: str = Field(default="sqlite:///./xprisk_dev.db", alias="DATABASE_URL")
    api_prefix: str = Field(default="/api", alias="API_PREFIX")
    cors_origins: str = Field(default="http://localhost:8501", alias="CORS_ORIGINS")

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


class RiskModelSettings(BaseSettings):
    """The ``XPRISK_*`` risk-model surface, validated.

    Field names map to environment variables by upper-casing and prefixing, so
    ``weight_critical`` reads ``XPRISK_WEIGHT_CRITICAL``. This mirrors
    ``.env.example`` exactly; that file is the contract.
    """

    model_config = SettingsConfigDict(
        env_prefix="XPRISK_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # Severity weights
    weight_critical: float = 10.0
    weight_high: float = 7.0
    weight_medium: float = 4.0
    weight_low: float = 1.0
    weight_info: float = 0.0

    # Category multipliers
    category_source_code: float = 1.0
    category_secret: float = 1.3
    category_container: float = 1.2
    category_iac: float = 1.1

    # Context multipliers
    env_development: float = 1.0
    env_staging: float = 1.15
    env_production: float = 1.4
    exposure_internal: float = 1.0
    exposure_internet_facing: float = 1.25
    change_existing: float = 1.0
    change_new: float = 1.15

    # Curve, cap and bands
    score_anchors: str = "0:0,8:10,20:30,45:55,80:75,140:90,220:100"
    context_uplift_cap: float = 1.6
    threshold_safe: float = 30.0
    threshold_warning: float = 70.0

    @field_validator("score_anchors")
    @classmethod
    def _validate_anchors(cls, value: str) -> str:
        _parse_anchors(value)
        return value

    @field_validator("context_uplift_cap")
    @classmethod
    def _validate_cap(cls, value: float) -> float:
        if value < 1.0:
            raise ValueError(f"XPRISK_CONTEXT_UPLIFT_CAP must be >= 1.0, got {value}")
        return value

    @field_validator("threshold_safe", "threshold_warning")
    @classmethod
    def _validate_threshold(cls, value: float) -> float:
        if not 0.0 <= value <= 100.0:
            raise ValueError(f"thresholds must lie in 0-100, got {value}")
        return value

    # -- conversion ---------------------------------------------------------

    def anchors(self) -> tuple[tuple[float, float], ...]:
        return _parse_anchors(self.score_anchors)

    def severity_weights(self) -> SeverityWeights:
        return SeverityWeights(
            weights={
                Severity.CRITICAL: self.weight_critical,
                Severity.HIGH: self.weight_high,
                Severity.MEDIUM: self.weight_medium,
                Severity.LOW: self.weight_low,
                Severity.INFO: self.weight_info,
            }
        )

    def to_risk_settings(self) -> RiskSettings:
        """Build the domain settings object this configuration describes.

        The enum-keyed multiplier tables are rebuilt here rather than being
        stored as strings, so ``risk_engine`` keeps working in terms of
        ``Environment`` / ``Exposure`` / ``ChangeStatus`` / ``Category`` and
        never has to know that configuration arrived as text.
        """

        from risk_engine.context import ChangeStatus, Environment, Exposure
        from normalizer.models import Category

        return RiskSettings(
            severity_weights=self.severity_weights(),
            category_multipliers={
                Category.SOURCE_CODE: self.category_source_code,
                Category.SECRET: self.category_secret,
                Category.CONTAINER: self.category_container,
                Category.IAC: self.category_iac,
            },
            environment_multipliers={
                Environment.DEVELOPMENT: self.env_development,
                Environment.STAGING: self.env_staging,
                Environment.PRODUCTION: self.env_production,
            },
            exposure_multipliers={
                Exposure.INTERNAL: self.exposure_internal,
                Exposure.INTERNET_FACING: self.exposure_internet_facing,
            },
            change_multipliers={
                ChangeStatus.EXISTING: self.change_existing,
                ChangeStatus.NEW: self.change_new,
            },
            score_anchors=self.anchors(),
            context_uplift_cap=self.context_uplift_cap,
            threshold_safe=self.threshold_safe,
            threshold_warning=self.threshold_warning,
        )


@lru_cache(maxsize=1)
def get_settings() -> RiskModelSettings:
    """Read and validate the risk-model configuration once."""

    return RiskModelSettings()


@lru_cache(maxsize=1)
def get_app_settings() -> AppSettings:
    return AppSettings()


def get_risk_settings() -> RiskSettings:
    """The domain settings object for the current process configuration."""

    return get_settings().to_risk_settings()


def reset_settings_cache() -> None:
    """Clear cached settings. For tests that manipulate the environment."""

    get_settings.cache_clear()
    get_app_settings.cache_clear()