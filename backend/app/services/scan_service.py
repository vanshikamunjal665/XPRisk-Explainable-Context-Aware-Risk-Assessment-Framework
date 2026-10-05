"""End-to-end assessment use case (Phase 12).

This is the piece that was missing. Until now the repository could run
scanners, normalize their output, score the result and explain it, but no single
callable joined those steps into one durable assessment — the dashboard composed
them in memory and discarded the result, so nothing was ever written.

``ScanService.assess`` performs the whole sequence and persists it:

1. run the selected scanners (:mod:`scanners.scanner_service`), failing soft
2. normalize the native output (:mod:`normalizer.normalizer`)
3. score the findings against the deployment context (:mod:`risk_engine`)
4. explain the result (:mod:`explainability`)
5. write the deployment, its findings and every contribution

Two properties are deliberate and tested:

**One failing tool never fails the scan.** Each scanner reports its own
``ScannerStatus``. A missing binary, a non-zero exit or a malformed report is
recorded against that tool and the remaining tools still contribute. The
deployment is always created, so a scan that found nothing is still a fact worth
storing.

**A finding-level breakdown is stored, not just a score.** Every contribution is
persisted to ``risk_factors``. Storing only ``risk_score`` would make a past
explanation impossible to reproduce once the settings change; storing the
contributions means the historical explanation can be rebuilt. That is the whole
reason ``risk_factors`` exists as a table.

This module knows about the domain packages and the database, and nothing else.
It performs no risk arithmetic of its own and builds no command strings.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from backend.app.services.storage_service import StorageService

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ScanRequest:
    """What to scan, and the context to score it in.

    Mirrors the arguments of :meth:`scanners.scanner_service.ScannerService.collect`
    plus the deployment metadata. Context values are plain strings here; they are
    validated by the request schema at the HTTP boundary and, defensively, by the
    context model itself.
    """

    # Deployment identity
    commit_id: str | None = None
    branch: str = ""
    environment: str = "development"
    exposure: str = "internal"
    change_status: str = "new"

    # Scanner selection
    gitleaks: bool = False
    trivy: bool = False
    checkov: bool = False
    sonarqube: bool = False

    # Scanner targets
    gitleaks_target: str = "."
    gitleaks_mode: str = "dir"
    gitleaks_config: str | None = None
    trivy_image: str = ""
    trivy_severities: str | None = None
    checkov_path: str = "."
    checkov_framework: str = "terraform"

    #: scanner name -> fixture path. Replays recorded output instead of executing
    #: the tool. Keyed by tool so the caller can never substitute a fixture for a
    #: scanner it did not select.
    fixtures: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class ScanOutcome:
    """Everything one assessment produced, plus where it was stored."""

    deployment_id: int
    risk_score: float
    decision: str
    base_score: float
    total_raw: float
    finding_count: int
    context: dict[str, Any]
    statuses: dict[str, str]
    errors: list[dict[str, Any]]
    severity_breakdown: dict[str, int]
    category_breakdown: dict[str, int]
    explanation: Any
    recommendation: Any
    assessment: Any = None  # retained for in-process callers, not serialized


def _risk_factor_rows(assessment: Any) -> list[dict[str, Any]]:
    """Flatten an assessment's contributions into ``risk_factors`` rows.

    ``contribution`` is the finding's raw risk contribution, not its share of the
    total. The share is derivable by dividing by ``total_raw``; the raw value is
    not recoverable from a share, so it is the one worth keeping.
    """

    rows: list[dict[str, Any]] = []
    for item in getattr(assessment, "contributions", ()) or ():
        label = getattr(item, "label", None) or getattr(item, "finding_id", None)
        rows.append(
            {
                "factor_name": str(label or "unknown"),
                "factor_value": {
                    "tool": str(getattr(item, "tool", "") or ""),
                    "category": str(getattr(item, "category", "") or ""),
                    "severity": str(getattr(item, "severity", "") or ""),
                    "severity_weight": getattr(item, "severity_weight", None),
                    "category_multiplier": getattr(item, "category_multiplier", None),
                    "share_of_total": getattr(item, "share_of_total", None),
                    "location": getattr(item, "location", None),
                },
                "contribution": float(getattr(item, "raw_risk", 0.0) or 0.0),
            }
        )
    return rows


class ScanService:
    """Compose the scanners, the normalizer, the risk engine and storage."""

    def __init__(
        self,
        storage: StorageService | None = None,
        scanner_service: Any | None = None,
        engine: Any | None = None,
    ) -> None:
        """Every collaborator is injectable.

        Tests build a service against a temporary database and fixture files; no
        security tool is executed and no real database is touched.
        """

        self._storage = storage or StorageService()
        self._scanners = scanner_service
        self._engine = engine

    def _scanner_service(self) -> Any:
        if self._scanners is not None:
            return self._scanners
        from scanners.scanner_service import ScannerService

        return ScannerService()

    def _risk_engine(self) -> Any:
        if self._engine is not None:
            return self._engine
        from risk_engine.engine import RiskEngine

        return RiskEngine()

    # -- the use case --------------------------------------------------------

    def assess(self, request: ScanRequest) -> ScanOutcome:
        """Run, normalize, score, explain and persist one deployment.

        Never raises for a tool failure. A scanner that is missing, crashes or
        returns garbage is recorded in ``ScanOutcome.statuses`` and
        ``ScanOutcome.errors``; the assessment proceeds with whatever the other
        tools produced.
        """

        from explainability.explanation import build_explanation
        from explainability.recommendation import build_recommendation
        from normalizer.normalizer import normalize_collection

        engine = self._risk_engine()

        # 1. Run the scanners. `collect` already fails soft per tool.
        collection = self._scanner_service().collect(
            gitleaks=request.gitleaks,
            trivy=request.trivy,
            checkov=request.checkov,
            sonarqube=request.sonarqube,
            gitleaks_target=request.gitleaks_target,
            gitleaks_mode=request.gitleaks_mode,
            gitleaks_config=request.gitleaks_config,
            trivy_image=request.trivy_image,
            trivy_severities=request.trivy_severities,
            checkov_path=request.checkov_path,
            checkov_framework=request.checkov_framework,
            fixtures=dict(request.fixtures),
        )

        # 2. Translate to the canonical finding shape.
        findings = normalize_collection(collection)

        # 3. Score. An unrecognised context value raises here rather than
        #    silently defaulting, which is why the schema validates it first.
        context = engine.context_model.build(
            environment=request.environment,
            exposure=request.exposure,
            change_status=request.change_status,
        )
        assessment = engine.assess(findings, context)

        # 4. Explain, before persisting, so a failure cannot leave a scored row
        #    with no way to describe it.
        explanation = build_explanation(assessment)
        recommendation = build_recommendation(assessment)

        # 5. Persist. The deployment row carries the score so that history is
        #    queryable without recomputing it from findings.
        deployment = self._storage.create_deployment(
            commit_id=request.commit_id,
            branch=request.branch,
            environment=context.environment.value,
            internet_exposed=context.exposure.value == "internet-facing",
            risk_score=assessment.risk_score,
            decision=assessment.decision.value,
        )
        self._storage.save_findings(deployment.id, findings)
        self._storage.save_risk_factors(deployment.id, _risk_factor_rows(assessment))

        return ScanOutcome(
            deployment_id=deployment.id,
            risk_score=assessment.risk_score,
            decision=assessment.decision.value,
            base_score=assessment.base_score,
            total_raw=assessment.total_raw,
            finding_count=assessment.finding_count,
            context=context.to_dict(),
            # ScannerStatus is a str Enum, but `.value` is taken explicitly so the
            # value is a plain string and survives JSON encoding unchanged.
            statuses={
                name: (status.value if hasattr(status, "value") else str(status))
                for name, status in collection.statuses.items()
            },
            errors=[
                {**record.to_dict(), "scanner": name}
                for name, record in collection.errors.items()
            ],
            severity_breakdown=dict(assessment.severity_breakdown),
            category_breakdown=dict(assessment.category_breakdown),
            explanation=explanation,
            recommendation=recommendation,
            assessment=assessment,
        )