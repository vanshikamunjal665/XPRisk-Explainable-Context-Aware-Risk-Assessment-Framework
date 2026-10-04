"""Context model for XPRisk (Phase 8).

Describes *where* and *how* findings are being deployed, and produces
structured, deterministic context information that the (future) scoring
engine can consume.

This module deliberately contains NO scoring logic: no weights, no
multipliers-as-scores, no thresholds, no decisions. It only validates
and structures deployment/resource context.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping

from normalizer.models import Category


class Environment(str, Enum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class Exposure(str, Enum):
    INTERNAL = "internal"
    INTERNET_FACING = "internet-facing"


class ChangeStatus(str, Enum):
    NEW = "new"
    EXISTING = "existing"


class ResourceCategory(str, Enum):
    SOURCE_CODE = "source code"
    SECRET = "secret"
    CONTAINER = "container"
    IAC = "IaC"


# Deterministic mapping from the Phase 6 normalized Category enum.
CATEGORY_TO_RESOURCE_CATEGORY: Mapping[Category, ResourceCategory] = {
    Category.SECRET: ResourceCategory.SECRET,
    Category.CONTAINER: ResourceCategory.CONTAINER,
    Category.IAC: ResourceCategory.IAC,
    Category.SOURCE_CODE: ResourceCategory.SOURCE_CODE,
}


def resource_category_for(category: Category | str) -> ResourceCategory:
    """Map a normalized finding category to its resource category."""
    if isinstance(category, str):
        category = Category(category) if category in {c.value for c in Category} else Category[category.upper()]
    try:
        return CATEGORY_TO_RESOURCE_CATEGORY[category]
    except KeyError:
        raise ValueError(f"unsupported category: {category!r}") from None


@dataclass(frozen=True)
class DeploymentContext:
    """Validated, immutable context for one deployment assessment."""

    environment: Environment
    exposure: Exposure
    change_status: ChangeStatus

    @property
    def internet_exposed(self) -> bool:
        return self.exposure is Exposure.INTERNET_FACING

    def to_dict(self) -> dict[str, Any]:
        return {
            "environment": self.environment.value,
            "exposure": self.exposure.value,
            "change_status": self.change_status.value,
        }

    def factors(self) -> dict[str, Any]:
        """Structured context consumed by the scoring engine."""
        return {
            **self.to_dict(),
            "internet_exposed": self.internet_exposed,
        }


class ContextModel:
    """Configurable factory/validator for context values.

    Default vocabularies are the standard XPRisk values; they can be
    overridden, so the model is configurable without editing this module.
    """

    def __init__(
        self,
        environments: Mapping[str, Environment] | None = None,
        exposures: Mapping[str, Exposure] | None = None,
        change_statuses: Mapping[str, ChangeStatus] | None = None,
        resource_categories: Mapping[str, ResourceCategory] | None = None,
    ) -> None:
        self._environments = dict(environments) if environments else {e.value: e for e in Environment}
        self._exposures = dict(exposures) if exposures else {e.value: e for e in Exposure}
        self._change_statuses = dict(change_statuses) if change_statuses else {c.value: c for c in ChangeStatus}
        self._resource_categories = (
            dict(resource_categories) if resource_categories else {c.value: c for c in ResourceCategory}
        )

    def _resolve(self, value: Any, table: Mapping, name: str):
        if isinstance(value, Enum):
            return value
        key = str(value).strip()
        if key in table:
            return table[key]
        lowered = key.lower()
        for k, v in table.items():
            if k.lower() == lowered:
                return v
        raise ValueError(f"unknown {name}: {value!r} (allowed: {sorted(table)})")

    def build(
        self,
        *,
        environment: str | Environment,
        exposure: str | Exposure,
        change_status: str | ChangeStatus,
    ) -> DeploymentContext:
        return DeploymentContext(
            environment=self._resolve(environment, self._environments, "environment"),
            exposure=self._resolve(exposure, self._exposures, "exposure"),
            change_status=self._resolve(change_status, self._change_statuses, "change_status"),
        )

    def resource_category(self, value: str | ResourceCategory) -> ResourceCategory:
        return self._resolve(value, self._resource_categories, "resource_category")


DEFAULT_CONTEXT_MODEL = ContextModel()
