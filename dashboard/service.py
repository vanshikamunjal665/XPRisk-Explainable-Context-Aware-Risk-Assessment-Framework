"""Dashboard data-access layer.

Kept deliberately thin: every query goes through the existing
``StorageService`` and every score/explanation/recommendation comes from the
existing risk engine and explainability package. No scoring logic lives here.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parent.parent

FIXTURE_PRESETS: dict[str, dict[str, str]] = {
    "Insecure deployment (gitleaks + checkov + trivy)": {
        "gitleaks": "fixtures/gitleaks/secrets_detected.json",
        "checkov": "fixtures/checkov/terraform_insecure.json",
        "trivy": "fixtures/trivy/sample_image_scan.json",
    },
    "Clean deployment (fixtures)": {
        "gitleaks": "fixtures/gitleaks/secrets_clean.json",
        "checkov": "fixtures/checkov/terraform_clean.json",
        "trivy": "fixtures/trivy/sample_image_scan_clean.json",
    },
}


@dataclass
class AssessmentBundle:
    """Everything the dashboard renders for one assessment."""

    context: dict[str, Any]
    risk_score: float
    decision: str
    base_score: float
    total_raw: float
    finding_count: int
    findings: list[Any]
    assessment: Any  # risk_engine.engine.RiskAssessment
    explanation: Any  # explainability.explanation.Explanation
    recommendation: Any  # explainability.recommendation.Recommendation


class DashboardData:
    """Facade over existing storage + engine + explainability services."""

    def __init__(self, storage: Any | None = None) -> None:
        if storage is not None:
            self._storage = storage
        else:
            from backend.app.services.storage_service import StorageService

            self._storage = StorageService()

    # -- storage queries ----------------------------------------------------

    def list_deployments(self, limit: int | None = 200) -> list[Any]:
        try:
            return self._storage.list_deployments(limit=limit)
        except Exception as exc:  # noqa: BLE001 - dashboard must not crash
            logger.warning("deployment query failed: %s", exc)
            raise

    def deployment_details(self, deployment_id: int) -> dict[str, Any] | None:
        try:
            deployment = self._storage.get_deployment(deployment_id)
            if deployment is None:
                return None
            return {
                "deployment": deployment,
                "findings": self._storage.get_findings_for_deployment(deployment_id),
                "risk_factors": self._storage.get_risk_factors(deployment_id),
            }
        except Exception as exc:  # noqa: BLE001
            logger.warning("deployment details failed: %s", exc)
            raise

    # -- fixture-driven demo findings ---------------------------------------

    def load_fixture_findings(self, preset: str) -> list[Any]:
        mapping = FIXTURE_PRESETS.get(preset)
        if mapping is None:
            raise ValueError(f"unknown preset: {preset}")

        from normalizer.normalizer import normalize_collection
        from scanners.scanner_service import ScannerService

        fixtures = {name: str(REPO_ROOT / path) for name, path in mapping.items()}
        collection = ScannerService().collect(
            gitleaks="gitleaks" in mapping,
            checkov="checkov" in mapping,
            trivy="trivy" in mapping,
            fixtures=fixtures,
        )
        return normalize_collection(collection)

    # -- assessment ----------------------------------------------------------

    def run_assessment(
        self,
        findings: list[Any],
        *,
        environment: str,
        exposure: str,
        change_status: str,
    ) -> AssessmentBundle:
        """Delegate scoring to the existing engine, explanation to explainability."""

        from explainability.explanation import build_explanation
        from explainability.recommendation import build_recommendation
        from risk_engine.engine import RiskEngine

        engine = RiskEngine()
        context = engine.context_model.build(
            environment=environment, exposure=exposure, change_status=change_status
        )
        assessment = engine.assess(findings, context)
        explanation = build_explanation(assessment)
        recommendation = build_recommendation(assessment)
        return AssessmentBundle(
            context=context.to_dict(),
            risk_score=assessment.risk_score,
            decision=assessment.decision.value,
            base_score=assessment.base_score,
            total_raw=assessment.total_raw,
            finding_count=assessment.finding_count,
            findings=list(findings),
            assessment=assessment,
            explanation=explanation,
            recommendation=recommendation,
        )
