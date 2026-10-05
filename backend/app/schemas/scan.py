"""Request and response schemas for ``POST /scan`` (Phase 13).

Separation from the ORM
-----------------------
These are intentionally *not* the SQLAlchemy models. The database is an
implementation detail that will change (new columns, new indexes, a different
engine); the API contract is a promise to the dashboard and to any future CI/CD
integration. Keeping them separate means a migration can never silently break a
client, and a response can be shaped for readability without touching storage.

Validation policy
-----------------
Every field is validated before a service is called, so an invalid request can
never reach the risk engine or the database:

* :class:`ScanContext` restricts ``environment``, ``exposure`` and
  ``change_status`` to the exact values the context model accepts. This is a
  second line of defence: the enums in :mod:`risk_engine.context` would also
  reject them, but rejecting at the boundary produces a 422 with a field name
  instead of a 500.
* :class:`ScanRequest` rejects fixture paths for scanners it did not select,
  because silently ignoring them would mean a caller asking for a real scan and
  receiving recorded output.
* Secret *values* are never part of any schema. A finding may carry a redacted
  preview of a matched secret, never the secret itself.

Only the fields the API actually needs are modelled. The remaining planned
schemas (``DeploymentContext``, ``EvaluateRiskRequest``) belong to endpoints
that do not exist yet and are not written speculatively.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Environment = Literal["development", "staging", "production"]
Exposure = Literal["internal", "internet-facing"]
ChangeStatus = Literal["new", "existing"]

#: Every scanner the API can select. Kept as a literal so a typo is a 422 rather
#: than a silently ignored flag.
ScannerName = Literal["gitleaks", "trivy", "checkov", "sonarqube"]


class ScanContext(BaseModel):
    """The deployment context the findings are scored against."""

    model_config = ConfigDict(extra="forbid")

    environment: Environment = "development"
    exposure: Exposure = "internal"
    change_status: ChangeStatus = "new"

    @property
    def internet_exposed(self) -> bool:
        """The single boolean the ``deployments`` table stores."""

        return self.exposure == "internet-facing"


class ScanRequest(BaseModel):
    """Body of ``POST /scan``.

    Every scanner defaults to off. A request that selects nothing is valid and
    produces a real, persisted, zero-finding deployment — that is a fact worth
    recording, not an error.
    """

    model_config = ConfigDict(extra="forbid")

    context: ScanContext = Field(default_factory=ScanContext)
    branch: str = ""
    commit_id: str | None = None

    gitleaks: bool = False
    trivy: bool = False
    checkov: bool = False
    sonarqube: bool = False

    gitleaks_target: str = "."
    gitleaks_config: str | None = None
    trivy_image: str = ""
    checkov_path: str = "."
    checkov_framework: str = "terraform"

    #: Replay recorded scanner output instead of executing a tool. Keyed by
    #: scanner name. This exists so the demonstration and the test suite are
    #: reproducible; a production caller should leave it empty.
    fixtures: dict[ScannerName, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _fixtures_match_selected_scanners(self) -> ScanRequest:
        selected = {
            name
            for name in ("gitleaks", "trivy", "checkov", "sonarqube")
            if getattr(self, name)
        }
        orphaned = set(self.fixtures) - selected
        if orphaned:
            raise ValueError(
                f"fixtures supplied for scanners that were not selected: "
                f"{sorted(orphaned)}. Either enable the scanner or drop the "
                f"fixture, so a request for a real scan cannot silently return "
                f"recorded output."
            )
        return self

    def to_scan_request(self) -> Any:
        """Convert to the service-layer dataclass.

        The HTTP layer adapts to the service, never the other way round: the
        service must stay usable from a script or a test without importing
        FastAPI or Pydantic.
        """

        from backend.app.services.scan_service import ScanRequest as ServiceRequest

        return ServiceRequest(
            commit_id=self.commit_id,
            branch=self.branch,
            environment=self.context.environment,
            exposure=self.context.exposure,
            change_status=self.context.change_status,
            gitleaks=self.gitleaks,
            trivy=self.trivy,
            checkov=self.checkov,
            sonarqube=self.sonarqube,
            gitleaks_target=self.gitleaks_target,
            gitleaks_config=self.gitleaks_config,
            trivy_image=self.trivy_image,
            checkov_path=self.checkov_path,
            checkov_framework=self.checkov_framework,
            fixtures=dict(self.fixtures),
        )


class ScannerStatusReport(BaseModel):
    """Per-tool outcome. Present for every selected scanner, including failures."""

    status: str
    error: str | None = None
    finding_count: int = 0


class ScanResponse(BaseModel):
    """Result of ``POST /scan``.

    Includes the persisted ``deployment_id``, so the caller can read the stored
    result back and know the assessment is durable rather than transient.
    """

    model_config = ConfigDict(extra="forbid")

    deployment_id: int
    risk_score: float
    decision: str
    base_score: float
    total_raw: float
    finding_count: int
    context: dict[str, Any]
    statuses: dict[str, str]
    errors: list[dict[str, Any]] = Field(default_factory=list)
    severity_breakdown: dict[str, int] = Field(default_factory=dict)
    category_breakdown: dict[str, int] = Field(default_factory=dict)
    explanation: dict[str, Any] = Field(default_factory=dict)
    recommendation: dict[str, Any] = Field(default_factory=dict)