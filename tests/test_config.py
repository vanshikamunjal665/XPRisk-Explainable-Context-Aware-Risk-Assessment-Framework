"""Tests for the configuration boundary (Phase 9).

Two properties are worth protecting here.

**The domain packages stay configuration-free.** ``risk_engine`` must never read
the environment directly. If it did, the engine could not be tested without
mutating process state, and the layering rule would break.

**Bad configuration fails at startup.** A malformed anchor curve or an inverted
threshold must raise when settings are constructed, not produce a quietly wrong
score that surfaces much later as an unexplained risk number.
"""

from __future__ import annotations

import os
import sys
from contextlib import contextmanager
from pathlib import Path

import pytest

sys.path.insert(0, ".")
sys.path.insert(0, "backend")

from normalizer.models import Category, Severity  # noqa: E402
from risk_engine.context import ChangeStatus, Environment, Exposure  # noqa: E402
from risk_engine.settings import DEFAULT_RISK_SETTINGS, RiskSettings  # noqa: E402
from app.config import (  # noqa: E402
    AppSettings,
    RiskModelSettings,
    _parse_anchors,
    get_risk_settings,
    reset_settings_cache,
)

#: The values declared in ``.env.example``. These are the contract; the test
#: asserts the shipped defaults still match it.
ENV_EXAMPLE_CONTRACT = {
    "weight_critical": 10.0,
    "weight_high": 7.0,
    "weight_medium": 4.0,
    "weight_low": 1.0,
    "weight_info": 0.0,
    "category_source_code": 1.0,
    "category_secret": 1.3,
    "category_container": 1.2,
    "category_iac": 1.1,
    "env_development": 1.0,
    "env_staging": 1.15,
    "env_production": 1.4,
    "exposure_internal": 1.0,
    "exposure_internet_facing": 1.25,
    "change_existing": 1.0,
    "change_new": 1.15,
    "context_uplift_cap": 1.6,
    "threshold_safe": 30.0,
    "threshold_warning": 70.0,
}

EXPECTED_ANCHORS = (
    (0.0, 0.0),
    (8.0, 10.0),
    (20.0, 30.0),
    (45.0, 55.0),
    (80.0, 75.0),
    (140.0, 90.0),
    (220.0, 100.0),
)

#: Every variable ``.env.example`` declares for the risk model.
RISK_VARS = tuple(f"XPRISK_{name.upper()}" for name in ENV_EXAMPLE_CONTRACT) + (
    "XPRISK_SCORE_ANCHORS",
)


@contextmanager
def env(**overrides: str):
    """Apply environment overrides for the duration of the block."""

    saved = {k: os.environ.get(k) for k in overrides}
    for key, value in overrides.items():
        os.environ[key] = value
    reset_settings_cache()
    try:
        yield
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        reset_settings_cache()


# -- the layering rule ------------------------------------------------------


def _ambient_config_calls(source: str) -> list[str]:
    """Find real environment reads in ``source``, ignoring prose.

    A substring search is not good enough: ``risk_engine/settings.py``
    documents *why* it does not read ``os.environ``, so the token legitimately
    appears in a docstring. This walks the AST and reports only executable
    references, so the rule is checked against behaviour rather than wording.
    """

    import ast

    found: list[str] = []
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in {"environ", "getenv"}:
            found.append(ast.unparse(node))
        elif isinstance(node, ast.Name) and node.id == "getenv":
            found.append("getenv")
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            names = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module or ""]
            if any("dotenv" in n for n in names):
                found.append(ast.unparse(node))
    return found


def test_domain_packages_do_not_read_the_environment():
    """`risk_engine` must stay free of ambient configuration.

    Phases 6 and 8 established this rule for `normalizer` and `risk_engine`.
    Phase 9 preserves it: `backend/app/config.py` reads the environment and
    injects the result.
    """

    for package in ("risk_engine", "normalizer"):
        for module in sorted(Path(package).glob("*.py")):
            offenders = _ambient_config_calls(module.read_text(encoding="utf-8"))
            assert not offenders, f"{module} reads ambient config: {offenders}"


def test_the_domain_layer_never_imports_pydantic_settings():
    """Pydantic's settings machinery belongs to the backend layer only.

    Checked against the AST rather than the source text, because
    ``risk_engine/__init__.py`` documents this rule in its own docstring and
    therefore legitimately mentions the module name.
    """

    import ast

    forbidden_modules = {"pydantic_settings", "dotenv", "python_dotenv"}
    forbidden_names = {"BaseSettings", "SettingsConfigDict", "load_dotenv"}

    for package in ("risk_engine", "normalizer"):
        for module in sorted(Path(package).glob("*.py")):
            tree = ast.parse(module.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        assert alias.name.split(".")[0] not in forbidden_modules, (
                            f"{module} imports {alias.name}"
                        )
                elif isinstance(node, ast.ImportFrom):
                    root = (node.module or "").split(".")[0]
                    assert root not in forbidden_modules, f"{module} imports from {node.module}"
                    for alias in node.names:
                        assert alias.name not in forbidden_names, (
                            f"{module} imports {alias.name} from {node.module}"
                        )


def test_backend_config_does_not_leak_into_the_domain():
    assert "backend" not in Path("risk_engine/engine.py").read_text(encoding="utf-8")


# -- defaults match the declared contract ----------------------------------


@pytest.mark.parametrize("field, expected", sorted(ENV_EXAMPLE_CONTRACT.items()))
def test_default_field_matches_env_example(field, expected):
    assert getattr(RiskModelSettings(_env_file=None), field) == pytest.approx(expected)


def test_default_anchors_match_env_example():
    assert RiskModelSettings(_env_file=None).anchors() == EXPECTED_ANCHORS


def test_every_risk_variable_in_env_example_is_implemented():
    """No declared-but-unwired variable may remain in the risk model.

    Phases 6 and 8 shipped roughly twenty declared-but-unread scanner variables.
    This guards the risk model against repeating that.
    """

    for name in RISK_VARS:
        field = name.removeprefix("XPRISK_").lower()
        assert field in RiskModelSettings.model_fields, f"{name} is declared but not a field"


def test_configured_settings_equal_the_domain_defaults():
    """The shipped config must not silently differ from the domain defaults."""

    settings = RiskModelSettings(_env_file=None).to_risk_settings()
    defaults = DEFAULT_RISK_SETTINGS

    assert settings.anchors_as_pairs() == defaults.anchors_as_pairs()
    assert settings.context_uplift_cap == defaults.context_uplift_cap
    assert settings.threshold_safe == defaults.threshold_safe
    assert settings.threshold_warning == defaults.threshold_warning
    assert dict(settings.category_multipliers) == dict(defaults.category_multipliers)
    assert dict(settings.environment_multipliers) == dict(defaults.environment_multipliers)
    assert dict(settings.exposure_multipliers) == dict(defaults.exposure_multipliers)
    assert dict(settings.change_multipliers) == dict(defaults.change_multipliers)
    assert settings.severity_weights.to_dict() == defaults.severity_weights.to_dict()


def test_conversion_produces_enum_keyed_tables():
    settings = RiskModelSettings(_env_file=None).to_risk_settings()
    assert set(settings.environment_multipliers) == set(Environment)
    assert set(settings.exposure_multipliers) == set(Exposure)
    assert set(settings.change_multipliers) == set(ChangeStatus)
    assert set(settings.category_multipliers) == set(Category)


# -- environment overrides take effect --------------------------------------


def test_threshold_override_applies():
    with env(XPRISK_THRESHOLD_SAFE="10", XPRISK_THRESHOLD_WARNING="50"):
        settings = get_risk_settings()
        assert settings.threshold_safe == pytest.approx(10.0)
        assert settings.threshold_warning == pytest.approx(50.0)


def test_severity_weight_override_applies():
    with env(XPRISK_WEIGHT_CRITICAL="25"):
        assert get_risk_settings().severity_weight_for(Severity.CRITICAL) == pytest.approx(25.0)


def test_anchor_override_applies():
    with env(XPRISK_SCORE_ANCHORS="0:0,10:40,50:70,200:100"):
        settings = get_risk_settings()
        assert settings.anchors_as_pairs() == [(0.0, 0.0), (10.0, 40.0), (50.0, 70.0), (200.0, 100.0)]


def test_cap_override_applies():
    with env(XPRISK_CONTEXT_UPLIFT_CAP="2.5"):
        assert get_risk_settings().context_uplift_cap == pytest.approx(2.5)


def test_overrides_are_case_insensitive_on_the_variable_name():
    with env(xprisk_threshold_safe="12"):
        assert get_risk_settings().threshold_safe == pytest.approx(12.0)


def test_settings_cache_is_reset_between_blocks():
    with env(XPRISK_THRESHOLD_SAFE="10"):
        assert get_risk_settings().threshold_safe == pytest.approx(10.0)
    with env(XPRISK_THRESHOLD_SAFE="20"):
        assert get_risk_settings().threshold_safe == pytest.approx(20.0)


# -- fail fast --------------------------------------------------------------


@pytest.mark.parametrize(
    "anchors, reason",
    [
        ("0:0,8:10,4:20", "raw values must increase"),
        ("0:0,8:10,8:20", "duplicate raw value"),
        ("0:0,8:5", "scores must increase"),
        ("0:0", "needs at least two points"),
        ("garbage", "not in raw:score form"),
        ("0:0,abc:10", "non-numeric component"),
        ("5:10,8:20", "must start at 0:0"),
        ("0:0,8:10,220:90", "must end at score 100"),
    ],
)
def test_bad_anchor_curves_are_rejected_at_construction(anchors, reason):
    with env(XPRISK_SCORE_ANCHORS=anchors):
        with pytest.raises(Exception):
            get_risk_settings(), reason


def test_inverted_thresholds_are_rejected():
    with env(XPRISK_THRESHOLD_SAFE="90", XPRISK_THRESHOLD_WARNING="30"):
        with pytest.raises(Exception):
            get_risk_settings()


def test_out_of_range_thresholds_are_rejected():
    with env(XPRISK_THRESHOLD_WARNING="150"):
        with pytest.raises(Exception):
            get_risk_settings()


def test_cap_below_one_is_rejected():
    """A cap under 1.0 would apply a penalty for having any context at all."""

    with env(XPRISK_CONTEXT_UPLIFT_CAP="0.5"):
        with pytest.raises(Exception):
            get_risk_settings()


# -- anchor parsing ---------------------------------------------------------


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("0:0,8:10", ((0.0, 0.0), (8.0, 10.0))),
        (" 0 : 0 , 8 : 10 ", ((0.0, 0.0), (8.0, 10.0))),
        ("0:0,8:10,", ((0.0, 0.0), (8.0, 10.0))),
    ],
)
def test_anchor_parsing(raw, expected):
    assert _parse_anchors(raw) == expected


def test_anchor_parsing_requires_two_points():
    """A single-point curve cannot describe a mapping."""

    with pytest.raises(ValueError, match="at least two points"):
        _parse_anchors("0:0")


# -- app settings -----------------------------------------------------------


def test_app_settings_defaults():
    app = AppSettings(_env_file=None)
    assert app.app_name == "XPRisk"
    assert app.api_prefix == "/api"


def test_cors_origins_are_split():
    app = AppSettings(_env_file=None, cors_origins="http://a:8501, http://b:8501 ,")
    assert app.cors_origin_list == ["http://a:8501", "http://b:8501"]


def test_database_url_default_is_sqlite():
    """SQLite by default; PostgreSQL is opt-in via DATABASE_URL."""

    assert AppSettings(_env_file=None).database_url.startswith("sqlite")


# -- injected settings actually change the score ---------------------------


def test_injected_settings_change_the_engine_score():
    """The end-to-end reason the injection point exists."""

    from normalizer.models import XPRiskFinding
    from risk_engine.context import ContextModel
    from risk_engine.engine import RiskEngine

    findings = [
        XPRiskFinding(
            id=f"xprisk-{i:04d}",
            tool="checkov",
            category=Category.IAC,
            severity=Severity.MEDIUM,
            finding_id=f"CKV_{i}",
            resource=f"res_{i}",
            file="main.tf",
            line=i,
        )
        for i in range(6)
    ]
    context = ContextModel().build(
        environment="development", exposure="internal", change_status="existing"
    )

    default = RiskEngine(RiskSettings()).assess(findings, context)
    with env(XPRISK_SCORE_ANCHORS="0:0,1:50,10:90,100:100"):
        injected = RiskEngine(get_risk_settings()).assess(findings, context)

    assert default.base_score != injected.base_score
    assert default.decision is not injected.decision