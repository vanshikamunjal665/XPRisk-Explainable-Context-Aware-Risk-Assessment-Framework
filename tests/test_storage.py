"""Phase 7 database/storage tests.

Uses an in-memory SQLite database — no live PostgreSQL required.
PostgreSQL compatibility is provided by the JSON/JSONB variant types;
live PostgreSQL integration was NOT performed in this run.
"""

from __future__ import annotations

import sys

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

sys.path.insert(0, ".")

from backend.app.database.database import Base  # noqa: E402
from backend.app.models import Deployment, Finding, RiskFactor  # noqa: E402
from backend.app.services.storage_service import StorageService  # noqa: E402
from normalizer import normalize_collection  # noqa: E402
from scanners.scanner_service import ScannerService  # noqa: E402

from pathlib import Path  # noqa: E402

FIX = Path("fixtures")


@pytest.fixture()
def storage():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    sf = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    yield StorageService(sf)
    engine.dispose()


def _dep(storage, branch="main", env="staging"):
    return storage.create_deployment(commit_id="abc123", branch=branch, environment=env, internet_exposed=True)


def test_deployment_finding_riskfactor_creation_and_relationships(storage):
    dep = _dep(storage)
    storage.save_findings(dep.id, [{"tool": "TRIVY", "category": "CONTAINER", "severity": "HIGH", "finding_id": "CVE-1", "metadata": {}}])
    storage.save_risk_factors(dep.id, [{"factor_name": "internet_exposure", "factor_value": True, "contribution": 0.25}])
    dep2 = storage.get_deployment(dep.id)
    assert len(dep2.findings) == 1
    assert len(dep2.risk_factors) == 1
    assert dep2.findings[0].deployment_id == dep.id
    assert dep2.risk_factors[0].deployment_id == dep.id


def test_multiple_deployments_remain_separate(storage):
    a = storage.create_deployment(branch="a", environment="dev")
    b = storage.create_deployment(branch="b", environment="prod")
    assert a.id != b.id
    all_deps = storage.list_deployments()
    assert {d.branch for d in all_deps} == {"a", "b"}


def test_findings_scoped_to_deployment(storage):
    a = _dep(storage)
    b = _dep(storage)
    storage.save_findings(a.id, [{"tool": "GITLEAKS", "category": "SECRET", "severity": "HIGH"}])
    storage.save_findings(b.id, [{"tool": "CHECKOV", "category": "IAC", "severity": "LOW"}])
    assert len(storage.get_findings_for_deployment(a.id)) == 1
    assert len(storage.get_findings_for_deployment(b.id)) == 1


def test_historical_query_across_deployments(storage):
    a = _dep(storage)
    b = _dep(storage)
    storage.save_findings(a.id, [{"tool": "TRIVY", "category": "CONTAINER", "severity": "HIGH"}])
    storage.save_findings(b.id, [{"tool": "TRIVY", "category": "CONTAINER", "severity": "LOW"}] * 2)
    all_f = storage.query_findings()
    assert len(all_f) == 3
    assert {f.deployment_id for f in all_f} == {a.id, b.id}


def test_filtering(storage):
    a = _dep(storage)
    storage.save_findings(a.id, [
        {"tool": "TRIVY", "category": "CONTAINER", "severity": "HIGH"},
        {"tool": "GITLEAKS", "category": "SECRET", "severity": "HIGH"},
        {"tool": "CHECKOV", "category": "IAC", "severity": "LOW"},
    ])
    assert len(storage.query_findings(tool="TRIVY")) == 1
    assert len(storage.query_findings(severity="HIGH")) == 2
    assert len(storage.query_findings(category="SECRET")) == 1
    assert len(storage.query_findings(deployment_id=a.id)) == 3


def test_metadata_roundtrip(storage):
    a = _dep(storage)
    meta = {"trivy": {"fixed_version": "1.2.3", "tags": ["x"]}, "data_origin": "FIXTURE"}
    storage.save_findings(a.id, [{"tool": "TRIVY", "category": "CONTAINER", "severity": "HIGH", "metadata": meta}])
    f = storage.get_findings_for_deployment(a.id)[0]
    assert f.metadata_["trivy"]["fixed_version"] == "1.2.3"
    assert f.metadata_["data_origin"] == "FIXTURE"


def test_nullable_optional_fields(storage):
    dep = storage.create_deployment(branch="x", environment="dev")
    assert dep.commit_id is None
    assert dep.risk_score is None
    assert dep.decision is None
    f = storage.save_findings(dep.id, [{"tool": "TRIVY", "category": "CONTAINER", "severity": "HIGH"}])[0]
    assert f.resource is None and f.file is None and f.line is None


def test_risk_factors_multiple(storage):
    dep = _dep(storage)
    storage.save_risk_factors(dep.id, [
        {"factor_name": "env", "factor_value": "prod", "contribution": 1.4},
        {"factor_name": "exposure", "factor_value": True, "contribution": 1.25},
    ])
    factors = storage.get_risk_factors(dep.id)
    assert len(factors) == 2
    assert {f.factor_name for f in factors} == {"env", "exposure"}


def test_save_findings_unknown_deployment_errors(storage):
    with pytest.raises(ValueError):
        storage.save_findings(999, [])


def test_phase6_normalized_findings_persist(storage):
    collection = ScannerService().collect(
        gitleaks=True, trivy=True, checkov=True, sonarqube=True,
        fixtures={
            "gitleaks": FIX / "gitleaks/secrets_detected.json",
            "trivy": FIX / "trivy/sample_image_scan.json",
            "checkov": FIX / "checkov/terraform_insecure.json",
            "sonarqube": FIX / "sonarqube/issues_sample.json",
        },
    )
    normalized = normalize_collection(collection)
    # 2 Gitleaks (xprisk-test-secret + private-key) + 2 Trivy + 2 Checkov
    # + 2 SonarQube, matching the verified Gitleaks 8.30.1 run.
    assert len(normalized) == 8
    dep = _dep(storage)
    rows = storage.save_findings(dep.id, normalized)
    assert len(rows) == 8
    tools = {r.tool for r in rows}
    assert tools == {"GITLEAKS", "TRIVY", "CHECKOV", "SONARQUBE"}
    secrets = storage.query_findings(deployment_id=dep.id, category="SECRET")
    assert sorted(s.severity for s in secrets) == ["CRITICAL", "HIGH"]
    assert secrets[0].metadata_["data_origin"] == "FIXTURE"
