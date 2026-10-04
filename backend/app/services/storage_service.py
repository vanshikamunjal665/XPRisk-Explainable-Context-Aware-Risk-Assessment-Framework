"""Storage service: persistence and querying of deployments, findings,
and risk factors (Phase 7).

Storage only. Does not calculate risk, does not run scanners, does not
normalize. Accepts Phase 6 ``XPRiskFinding`` objects for convenience.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from backend.app.database.database import make_session_factory, session_scope
from backend.app.models import Deployment, Finding, RiskFactor


def _enum_value(value: Any) -> Any:
    return value.value if hasattr(value, "value") else value


class StorageService:
    def __init__(self, session_factory: sessionmaker[Session] | None = None) -> None:
        if session_factory is None:
            from backend.app.database.database import make_engine

            session_factory = make_session_factory(make_engine())
        self._sf = session_factory

    # -- deployments --------------------------------------------------------

    def create_deployment(
        self,
        *,
        commit_id: str | None = None,
        branch: str = "",
        environment: str = "development",
        internet_exposed: bool = False,
        timestamp: datetime | None = None,
        risk_score: float | None = None,
        decision: str | None = None,
    ) -> Deployment:
        with session_scope(self._sf) as s:
            dep = Deployment(
                commit_id=commit_id,
                branch=branch,
                environment=environment,
                internet_exposed=internet_exposed,
                risk_score=risk_score,
                decision=decision,
            )
            if timestamp is not None:
                dep.timestamp = timestamp
            s.add(dep)
            s.flush()
            s.refresh(dep)
            return dep

    def get_deployment(self, deployment_id: int) -> Deployment | None:
        with session_scope(self._sf) as s:
            return s.get(Deployment, deployment_id)

    def list_deployments(self, *, limit: int | None = None) -> list[Deployment]:
        with session_scope(self._sf) as s:
            stmt = select(Deployment).order_by(Deployment.timestamp.desc(), Deployment.id.desc())
            if limit is not None:
                stmt = stmt.limit(limit)
            return list(s.scalars(stmt))

    # -- findings -----------------------------------------------------------

    def save_findings(self, deployment_id: int, findings: Iterable[Any]) -> list[Finding]:
        """Persist findings for a deployment.

        Accepts Phase 6 ``XPRiskFinding`` objects or mappings with the
        canonical field names. Scanner-specific metadata is preserved in
        the JSON ``metadata`` column.
        """
        rows: list[Finding] = []
        with session_scope(self._sf) as s:
            dep = s.get(Deployment, deployment_id)
            if dep is None:
                raise ValueError(f"deployment {deployment_id} not found")
            for f in findings:
                if isinstance(f, dict):
                    get = f.get
                else:
                    get = lambda k, d=None: getattr(f, k, d)  # noqa: E731
                rows.append(
                    Finding(
                        deployment_id=deployment_id,
                        tool=str(_enum_value(get("tool"))),
                        category=str(_enum_value(get("category"))),
                        severity=str(_enum_value(get("severity"))),
                        finding_id=get("finding_id"),
                        resource=get("resource"),
                        file=get("file"),
                        line=get("line"),
                        description=get("description"),
                        metadata_=dict(get("metadata") or {}),
                    )
                )
            s.add_all(rows)
            s.flush()
            for r in rows:
                s.refresh(r)
            return rows

    def get_findings_for_deployment(self, deployment_id: int) -> list[Finding]:
        with session_scope(self._sf) as s:
            return list(s.scalars(select(Finding).where(Finding.deployment_id == deployment_id)))

    def query_findings(
        self,
        *,
        deployment_id: int | None = None,
        tool: str | None = None,
        severity: str | None = None,
        category: str | None = None,
    ) -> list[Finding]:
        with session_scope(self._sf) as s:
            stmt = select(Finding)
            if deployment_id is not None:
                stmt = stmt.where(Finding.deployment_id == deployment_id)
            if tool is not None:
                stmt = stmt.where(Finding.tool == tool)
            if severity is not None:
                stmt = stmt.where(Finding.severity == severity)
            if category is not None:
                stmt = stmt.where(Finding.category == category)
            return list(s.scalars(stmt.order_by(Finding.id)))

    # -- risk factors -------------------------------------------------------

    def save_risk_factors(self, deployment_id: int, factors: Iterable[dict[str, Any]]) -> list[RiskFactor]:
        rows: list[RiskFactor] = []
        with session_scope(self._sf) as s:
            dep = s.get(Deployment, deployment_id)
            if dep is None:
                raise ValueError(f"deployment {deployment_id} not found")
            for f in factors:
                rows.append(
                    RiskFactor(
                        deployment_id=deployment_id,
                        factor_name=str(f["factor_name"]),
                        factor_value=f.get("factor_value"),
                        contribution=float(f.get("contribution", 0.0)),
                    )
                )
            s.add_all(rows)
            s.flush()
            for r in rows:
                s.refresh(r)
            return rows

    def get_risk_factors(self, deployment_id: int) -> list[RiskFactor]:
        with session_scope(self._sf) as s:
            return list(s.scalars(select(RiskFactor).where(RiskFactor.deployment_id == deployment_id)))
