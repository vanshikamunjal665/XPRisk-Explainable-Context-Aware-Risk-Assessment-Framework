"""XPRisk - Explainable Context-Aware Risk Assessment Framework.

XPRisk is a risk assessment and explainability framework for secure
cloud-native CI/CD pipelines. It consumes security findings produced by
existing DevSecOps scanners and converts them into a single, auditable,
context-aware deployment risk score and an explainable SAFE / WARNING / BLOCK
recommendation.

The scanners (Trivy, Checkov, Gitleaks, SonarQube) are *inputs* to XPRisk.
They are not the product. XPRisk's contribution is the layer that sits above
them:

    scanner output
        -> collection
        -> normalization        (one canonical finding schema)
        -> context analysis     (environment, exposure, change, category)
        -> risk scoring         (weighted, deterministic, 0-100)
        -> decision             (SAFE / WARNING / BLOCK)
        -> explainability       (derived from real contribution values)
        -> API + dashboard

Package layout
--------------
``scanners/``
    Thin, isolated adapters that execute one security tool and return that
    tool's native JSON. Knows nothing about HTTP, the database or the risk
    model.

``normalizer/``
    Converts heterogeneous native scanner JSON into the single canonical
    :class:`normalizer.models.NormalizedFinding` schema.

``risk_engine/``
    The research core: severity weights, context model, scoring, thresholds
    and the deterministic engine that produces a 0-100 score.

``explainability/``
    Turns the engine's real contribution data into a human-readable rationale.

``backend/app/``
    FastAPI delivery layer. Imports the domain packages; never the reverse.

The dependency rule is strictly one-directional::

    backend/app  ->  explainability  ->  risk_engine  ->  normalizer
                                                        |
                                                        v
                                                     scanners

No domain package may import FastAPI, SQLAlchemy or Streamlit. That rule is
what keeps the risk model testable without a server and a database, and it is
the reason the project can be explained as a set of clean layers in a viva.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]