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


@dataclass(frozen=True)
class FixturePreset:
    """One selectable scenario, with its provenance attached.

    ``note`` is rendered in the dashboard next to the result. That is
    deliberate: a reader should not have to open the repository to learn that
    these numbers come from real scanner runs, nor that the hardened image is
    not vulnerability-free.
    """

    label: str
    fixtures: dict[str, str]
    note: str


FIXTURE_PRESETS: dict[str, FixturePreset] = {
    preset.label: preset
    for preset in (
        FixturePreset(
            label="Vulnerable demo image - all scanners (real scan)",
            fixtures={
                "gitleaks": "fixtures/gitleaks/secrets_detected.json",
                "checkov": "fixtures/checkov/terraform_insecure.json",
                "trivy": "fixtures/trivy/sample_image_scan.json",
            },
            note=(
                "677 findings from a real run: 2 Gitleaks 8.30.1 secrets, "
                "24 Checkov 3.3.22 Terraform checks, 651 Trivy 0.75.0 "
                "advisories in xprisk-vulnerable:demo."
            ),
        ),
        FixturePreset(
            label="Hardened demo image - all scanners (real scan)",
            fixtures={
                "gitleaks": "fixtures/gitleaks/secrets_clean.json",
                "checkov": "fixtures/checkov/terraform_clean.json",
                "trivy": "fixtures/trivy/sample_image_scan_clean.json",
            },
            note=(
                "291 findings from a real run of the hardened scenarios. Note "
                "what this is not: a zero-finding result. The hardened image "
                "still carries 283 Trivy advisories and the hardened Terraform "
                "still fails 8 Checkov checks. An earlier version of this "
                "fixture set claimed zero and was wrong."
            ),
        ),
        FixturePreset(
            label="Secrets only - shows context sensitivity (real scan)",
            fixtures={"gitleaks": "fixtures/gitleaks/secrets_detected.json"},
            note=(
                "2 real Gitleaks findings, chosen because they are the only "
                "scenario whose score is not saturated, so switching context "
                "actually moves the number: 36.9 in development/internal, "
                "51.4 in production/internet-facing. Same findings, different "
                "risk - that is the contribution of the context model."
            ),
        ),
    )
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
        entry = FIXTURE_PRESETS.get(preset)
        if entry is None:
            raise ValueError(f"unknown preset: {preset}")

        from normalizer.normalizer import normalize_collection
        from scanners.scanner_service import ScannerService

        mapping = entry.fixtures
        fixtures = {name: str(REPO_ROOT / path) for name, path in mapping.items()}
        collection = ScannerService().collect(
            gitleaks="gitleaks" in mapping,
            checkov="checkov" in mapping,
            trivy="trivy" in mapping,
            sonarqube="sonarqube" in mapping,
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
