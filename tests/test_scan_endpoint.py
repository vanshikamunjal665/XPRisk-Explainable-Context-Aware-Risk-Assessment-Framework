"""Tests for ``POST /scan`` and the service behind it (Phases 12-13).

What is being protected
-----------------------
This is the first code path in the project that *writes* to the database. Before
it existed, ``StorageService.create_deployment``, ``save_findings`` and
``save_risk_factors`` were called only from ``tests/test_storage.py``, the
development database held zero rows, and the dashboard's *Deployment history*
view was permanently empty.

Four properties are worth locking down, in rough order of how much damage their
failure would cause.

**The write path is actually reached.** ``test_assessment_is_persisted`` is the
one that would have failed before this feature existed.

**A scanner failure is not a 500.** A gate that fails the whole pipeline because
Gitleaks is not installed is useless. Missing tools, malformed reports and a tool
that raises outright must all produce a 201 with the failure reported per tool.

**A deployment is recorded even when nothing was found.** A clean scan is a fact
worth storing, not a no-op.

**The request cannot smuggle recorded output past a caller asking for a real
scan.** A fixture supplied for a scanner that was not selected is rejected,
because the alternative is silently answering a real-scan request with fixtures.

Every test runs against a temporary SQLite file and recorded scanner output. No
security tool is executed, no network call is made, and the shared development
database is never touched.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.app.config import AppSettings
from backend.app.database.database import Base, make_engine, make_session_factory
from backend.app.main import create_app
from backend.app.models import Deployment, Finding, RiskFactor  # noqa: F401
from backend.app.services.scan_service import ScanRequest, ScanService
from backend.app.services.storage_service import StorageService

REPO_ROOT = Path(__file__).resolve().parent.parent
GITLEAKS_FIXTURE = "fixtures/gitleaks/secrets_detected.json"
CHECKOV_FIXTURE = "fixtures/checkov/terraform_insecure.json"


@pytest.fixture()
def storage(tmp_path) -> StorageService:
    engine = make_engine(f"sqlite:///{(tmp_path / 'test.db').as_posix()}")
    Base.metadata.create_all(engine)
    return StorageService(make_session_factory(engine))


@pytest.fixture()
def service(storage: StorageService) -> ScanService:
    return ScanService(storage=storage)


@pytest.fixture()
def client(storage: StorageService) -> TestClient:
    app = create_app(
        AppSettings(app_name="XPRisk", app_env="test", database_url="sqlite:///"),
        scan_service=ScanService(storage=storage),
    )
    return TestClient(app)


def _post(client: TestClient, **overrides) -> dict:
    body = {
        "branch": "main",
        "commit_id": "deadbeef",
        "context": {
            "environment": "production",
            "exposure": "internet-facing",
            "change_status": "new",
        },
        "gitleaks": True,
        "fixtures": {"gitleaks": GITLEAKS_FIXTURE},
    }
    body.update(overrides)
    response = client.post("/scan", json=body)
    assert response.status_code == 201, response.text
    return response.json()


# -- the write path ----------------------------------------------------------


def test_assessment_is_persisted(storage, client):
    """The regression this whole feature exists for."""

    assert storage.list_deployments() == []

    body = _post(client)

    deployments = storage.list_deployments()
    assert len(deployments) == 1
    deployment = deployments[0]
    assert deployment.id == body["deployment_id"]
    assert deployment.branch == "main"
    assert deployment.commit_id == "deadbeef"
    assert deployment.environment == "production"
    assert deployment.internet_exposed is True
    assert deployment.risk_score == pytest.approx(body["risk_score"])
    assert deployment.decision == body["decision"]

    findings = storage.get_findings_for_deployment(deployment.id)
    assert len(findings) == body["finding_count"] == 2
    assert {f.tool for f in findings} == {"GITLEAKS"}

    factors = storage.get_risk_factors(deployment.id)
    assert len(factors) == 2
    assert sum(f.contribution for f in factors) == pytest.approx(body["total_raw"])


def test_risk_factors_store_raw_risk_not_share(storage, client):
    """The stored contribution must be reconstructible.

    A share of the total is derivable by dividing by ``total_raw``; raw risk is
    not recoverable from a share. Storing the share would quietly lose the
    information that makes a historical explanation reproducible.
    """

    body = _post(client)
    factors = storage.get_risk_factors(body["deployment_id"])

    assert all(f.contribution > 0 for f in factors)
    assert sum(f.contribution for f in factors) == pytest.approx(body["total_raw"])
    assert all(isinstance(f.factor_value, dict) for f in factors)
    # A share could never exceed 1.0; raw risk routinely does.
    assert max(f.contribution for f in factors) > 1.0


def test_a_clean_scan_still_records_a_deployment(storage, client):
    """Zero findings is a result, not a no-op."""

    body = _post(client, gitleaks=False, fixtures={})

    assert body["finding_count"] == 0
    assert body["risk_score"] == 0.0
    assert body["decision"] == "SAFE"

    deployments = storage.list_deployments()
    assert len(deployments) == 1
    assert deployments[0].decision == "SAFE"
    assert storage.get_findings_for_deployment(deployments[0].id) == []


# -- failing soft ------------------------------------------------------------


def test_an_uninstalled_scanner_is_reported_not_raised(client):
    """Trivy is not installed in CI. The scan must still succeed."""

    body = _post(client, trivy=True, trivy_image="does-not-exist:latest")

    assert body["statuses"]["trivy"] in {"UNAVAILABLE", "FAILED", "TIMEOUT"}
    assert body["statuses"]["gitleaks"] == "SUCCESS"
    assert body["finding_count"] == 2
    assert body["errors"], "the failing tool must be described, not just counted"


def test_an_internal_bug_becomes_a_sanitised_500(client, storage):
    """A fault in our own code must not leak a traceback to the caller.

    This is the one failure that genuinely is a 500: if the *collector* raises,
    that is a bug in XPRisk, not a scanner being unavailable. ``ScannerService
    .collect`` already converts per-tool failures into status records, so an
    exception escaping it means something is genuinely broken and the caller
    should be told so.

    The response must still not carry the exception message, because it may
    contain a filesystem path or a fragment of a scanned file.
    """

    class Exploding:
        def collect(self, **kwargs):
            raise RuntimeError("adapter exploded at C:/secret/path/config.tf")

    client.app.state.scan_service = ScanService(storage=storage, scanner_service=Exploding())

    response = client.post(
        "/scan",
        json={
            "gitleaks": True,
            "fixtures": {"gitleaks": GITLEAKS_FIXTURE},
        },
    )

    assert response.status_code == 500
    detail = response.json()["detail"]
    assert "RuntimeError" in detail
    assert "secret/path" not in detail, "the internal message leaked to the client"
    # And nothing was half-written.
    assert storage.list_deployments() == []


def test_statuses_cover_every_selected_scanner(client):
    body = _post(client, trivy=True, checkov=True, checkov_path="infrastructure/scenarios/insecure",
                 fixtures={"gitleaks": GITLEAKS_FIXTURE, "checkov": CHECKOV_FIXTURE})

    assert set(body["statuses"]) == {"gitleaks", "trivy", "checkov"}
    assert all(isinstance(v, str) for v in body["statuses"].values())


# -- request validation ------------------------------------------------------


@pytest.mark.parametrize(
    "context",
    [
        {"environment": "prod", "exposure": "internet-facing", "change_status": "new"},
        {"environment": "production", "exposure": "public", "change_status": "new"},
        {"environment": "production", "exposure": "internal", "change_status": "modified"},
        {"environment": "Production", "exposure": "internet-facing", "change_status": "new"},
    ],
)
def test_an_invalid_context_is_rejected_with_422(client, context):
    """A bad context must never reach the risk engine."""

    response = client.post(
        "/scan",
        json={"gitleaks": False, "context": context},
    )
    assert response.status_code == 422


def test_an_omitted_context_falls_back_to_the_documented_default(client):
    """Absent is not the same as invalid: defaults must be accepted.

    An earlier iteration of this file listed ``{"environment": "production"}`` as
    an invalid context, and the endpoint correctly answered 201. Both fields it
    omitted have defaults, so the request was well formed. A schema that rejects
    something the dashboard would happily accept is a worse bug than a permissive
    default, so the case was fixed rather than the schema.
    """

    body = _post(client, context={}, gitleaks=False, fixtures={})
    assert body["context"] == {
        "environment": "development",
        "exposure": "internal",
        "change_status": "new",
    }


def test_an_unknown_field_is_rejected(client):
    """`extra="forbid"` stops a typo becoming a silently ignored flag."""

    response = client.post("/scan", json={"gitleaks": False, "severity": "HIGH"})
    assert response.status_code == 422


def test_a_fixture_for_an_unselected_scanner_is_rejected(client):
    """The important one: fixtures must not be smuggled into a real scan."""

    response = client.post(
        "/scan",
        json={
            "trivy": True,
            "fixtures": {"gitleaks": GITLEAKS_FIXTURE},
        },
    )
    assert response.status_code == 422
    assert "not selected" in response.text


def test_scanners_default_to_off(client):
    """A bare request must not start executing four tools."""

    body = _post(client, gitleaks=False, fixtures={})
    assert body["statuses"] == {}
    assert body["finding_count"] == 0


# -- context is applied ------------------------------------------------------


def test_context_changes_the_persisted_row(client):
    """Same findings, different context, different stored result."""

    low = _post(client)
    high = _post(
        client,
        context={"environment": "development", "exposure": "internal", "change_status": "new"},
    )

    assert high["risk_score"] < low["risk_score"]

    rows = {d.environment: d for d in client.app.state.scan_service._storage.list_deployments()}
    assert rows["production"].internet_exposed is True
    assert rows["development"].internet_exposed is False


def test_the_api_matches_the_dashboard_for_the_same_findings(client):
    """One source of truth for scoring.

    The dashboard computes in memory and the API persists. If the two ever
    disagreed, the number on screen would depend on which view was open, which
    is the kind of inconsistency an examiner notices immediately.
    """

    from dashboard.service import FIXTURE_PRESETS, DashboardData

    body = _post(client)
    preset = [k for k in FIXTURE_PRESETS if k.startswith("Secrets")][0]
    bundle = DashboardData().run_assessment(
        DashboardData().load_fixture_findings(preset),
        environment="production",
        exposure="internet-facing",
        change_status="new",
    )

    assert body["risk_score"] == pytest.approx(bundle.risk_score)
    assert body["decision"] == bundle.decision
    assert body["base_score"] == pytest.approx(bundle.base_score)


# -- the service, without HTTP -----------------------------------------------


def test_service_returns_a_full_outcome(service):
    outcome = service.assess(
        ScanRequest(
            gitleaks=True,
            fixtures={"gitleaks": GITLEAKS_FIXTURE},
            environment="production",
            exposure="internet-facing",
        )
    )

    assert outcome.deployment_id >= 1
    assert outcome.risk_score > 0
    assert outcome.decision == "WARNING"
    assert outcome.statuses == {"gitleaks": "SUCCESS"}
    assert outcome.errors == []
    assert outcome.explanation.headline.startswith("Risk score")
    assert outcome.recommendation.action


def test_scan_request_defaults_to_scanning_nothing(storage):
    """Defaults are safe: nothing runs unless asked."""

    outcome = ScanService(storage=storage).assess(ScanRequest())
    assert outcome.statuses == {}
    assert outcome.finding_count == 0
    assert outcome.decision == "SAFE"


def test_the_service_does_not_import_http(storage):
    """A service must stay usable from a script.

    ``ScanRequest`` is a plain dataclass and ``assess`` is a plain method, so
    ``run_integration_scenarios.py`` can drive the pipeline without FastAPI.
    """

    import backend.app.services.scan_service as module

    source = Path(module.__file__).read_text(encoding="utf-8")
    for banned in ("fastapi", "pydantic", "starlette"):
        assert banned not in source.lower(), (
            f"scan_service imports {banned}; the service layer must not depend "
            "on the HTTP layer"
        )


# -- documentation guards ----------------------------------------------------


def test_openapi_documents_the_endpoint(client):
    paths = client.get("/openapi.json").json()["paths"]
    assert "/scan" in paths
    assert "post" in paths["/scan"]
    assert paths["/scan"]["post"]["responses"]["201"]


def test_health_still_answers_alongside_the_router(client):
    assert client.get("/health").status_code == 200


def test_the_development_database_is_no_longer_expected_to_be_empty():
    """The gap is closed, so the old assertion must not linger.

    ``tests/test_service_layer.py`` used to assert the dev database held zero
    rows. That assertion was correct when persistence was unreachable and would
    now be a lie, so it is inverted here rather than left to fail confusingly.
    """

    source = (REPO_ROOT / "tests" / "test_service_layer.py").read_text(encoding="utf-8")
    assert "test_development_database_is_empty_as_documented" not in source, (
        "persistence is live; delete the 'database is empty' assertion from "
        "tests/test_service_layer.py and update README section 5"
    )


def test_scan_service_is_exported():
    from backend.app.services import ScanService as Exported

    assert Exported is ScanService


def test_the_service_module_is_not_empty_on_disk():
    """Guards the docstring claims against an accidental truncation."""

    from backend.app.services import scan_service

    source = Path(scan_service.__file__).read_text(encoding="utf-8")
    assert "class ScanService" in source
    assert "def assess" in source


def test_temporary_database_is_not_the_development_database(storage, client):
    """A test must never write to ``xprisk_dev.db``."""

    _post(client)
    db = REPO_ROOT / "xprisk_dev.db"
    if not db.exists():
        pytest.skip("development database not present on this machine")

    connection = sqlite3.connect(db)
    try:
        row = connection.execute(
            "SELECT COUNT(*) FROM deployments WHERE commit_id = ?", ("deadbeef",)
        ).fetchone()
    finally:
        connection.close()
    assert row[0] == 0, "a test wrote to the shared development database"