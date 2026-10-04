"""SQLAlchemy ORM models.

Three tables carry the whole domain:

``Deployment``
    One row per assessed deployment (a commit in a branch, destined for an
    environment). Holds the assessment outcome: ``risk_score``, ``decision``,
    the environment and exposure context, and the raw aggregated inputs needed
    to reproduce the score.

``Finding``
    One row per normalized finding, linked to a deployment. Findings are
    historical: they are never updated in place, so trends across deployments
    remain meaningful.

``RiskFactor``
    One row per individual contribution to a deployment's score, whether it
    came from a finding or from a context factor. This table is the reason
    XPRisk is explainable after the fact: the explanation engine can be
    re-derived from stored contributions rather than recomputed from memory.

Why store contributions at all
-------------------------------
Storing only the final score would make the dashboard and the explanation page
dependent on re-running the engine, and a change to the risk model would
silently rewrite history. Persisting the contribution breakdown keeps every
past assessment auditable, which is a stated objective of the project.
"""

__all__ = ["Deployment", "Finding", "RiskFactor"]

from backend.app.models.models import Deployment, Finding, RiskFactor  # noqa: E402,F401