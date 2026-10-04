"""Phase 8 context model tests."""

from __future__ import annotations

import pytest

from normalizer.models import Category
from risk_engine.context import (
    ChangeStatus,
    ContextModel,
    DeploymentContext,
    Environment,
    Exposure,
    ResourceCategory,
    resource_category_for,
)


@pytest.mark.parametrize("env", ["development", "staging", "production"])
def test_all_environments_accepted(env):
    ctx = ContextModel().build(environment=env, exposure="internal", change_status="existing")
    assert ctx.environment.value == env


@pytest.mark.parametrize("exp", ["internal", "internet-facing"])
def test_all_exposures_accepted(exp):
    ctx = ContextModel().build(environment="staging", exposure=exp, change_status="new")
    assert ctx.exposure.value == exp


@pytest.mark.parametrize("change", ["new", "existing"])
def test_all_change_statuses_accepted(change):
    ctx = ContextModel().build(environment="staging", exposure="internal", change_status=change)
    assert ctx.change_status.value == change


@pytest.mark.parametrize(
    "value,expected",
    [("source code", ResourceCategory.SOURCE_CODE), ("secret", ResourceCategory.SECRET),
     ("container", ResourceCategory.CONTAINER), ("IaC", ResourceCategory.IAC)],
)
def test_all_resource_categories_accepted(value, expected):
    assert ContextModel().resource_category(value) is expected


def test_invalid_environment_rejected():
    with pytest.raises(ValueError):
        ContextModel().build(environment="qa", exposure="internal", change_status="new")


def test_invalid_exposure_rejected():
    with pytest.raises(ValueError):
        ContextModel().build(environment="staging", exposure="public", change_status="new")


def test_invalid_change_status_rejected():
    with pytest.raises(ValueError):
        ContextModel().build(environment="staging", exposure="internal", change_status="rolling")


def test_invalid_resource_category_rejected():
    with pytest.raises(ValueError):
        ContextModel().resource_category("mainframe")


def test_development_internal_existing():
    ctx = ContextModel().build(environment="development", exposure="internal", change_status="existing")
    assert ctx.environment is Environment.DEVELOPMENT
    assert ctx.exposure is Exposure.INTERNAL
    assert ctx.change_status is ChangeStatus.EXISTING
    assert ctx.internet_exposed is False


def test_staging_internal_new():
    ctx = ContextModel().build(environment="staging", exposure="internal", change_status="new")
    assert ctx.environment is Environment.STAGING
    assert ctx.change_status is ChangeStatus.NEW


def test_production_internet_facing_new():
    ctx = ContextModel().build(environment="production", exposure="internet-facing", change_status="new")
    assert ctx.environment is Environment.PRODUCTION
    assert ctx.exposure is Exposure.INTERNET_FACING
    assert ctx.internet_exposed is True


def test_deterministic_serialization():
    ctx = DeploymentContext(Environment.PRODUCTION, Exposure.INTERNET_FACING, ChangeStatus.NEW)
    assert ctx.to_dict() == {
        "environment": "production",
        "exposure": "internet-facing",
        "change_status": "new",
    }
    assert ContextModel().resource_category("IaC").value == "IaC"


def test_category_mapping():
    assert resource_category_for(Category.SECRET) is ResourceCategory.SECRET
    assert resource_category_for(Category.CONTAINER) is ResourceCategory.CONTAINER
    assert resource_category_for(Category.IAC) is ResourceCategory.IAC
    assert resource_category_for(Category.SOURCE_CODE) is ResourceCategory.SOURCE_CODE
    assert resource_category_for("SECRET") is ResourceCategory.SECRET


def test_configurable_vocabularies():
    model = ContextModel(environments={"qa": Environment.STAGING})
    ctx = model.build(environment="qa", exposure="internal", change_status="new")
    assert ctx.environment is Environment.STAGING
