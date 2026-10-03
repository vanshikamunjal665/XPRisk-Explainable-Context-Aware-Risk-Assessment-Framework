"""Application services - orchestration layer.

A service composes the domain packages and the database. It is the only layer
allowed to know about more than one of them, and the layer routers call.

============================  ==============================================
Service                       Responsibility
============================  ==============================================
``scanner_service``           Trigger the selected scanners, collect their
                              output, track per-tool status, record errors
                              and timings. Executes tools; performs **no**
                              normalization.
``normalization_service``     Translate native scanner JSON into canonical
                              :class:`~normalizer.models.NormalizedFinding`
                              objects. Knows nothing about execution.
``storage_service``           Persist and query deployments, findings and
                              risk factors.
``risk_service``              Run the risk engine and the decision thresholds
                              over findings plus context.
``explanation_service``       Turn a stored or computed contribution breakdown
                              into the explanation payload.
``scan_service``              The end-to-end use case: run scanners,
                              normalize, persist the deployment and its
                              findings, score, persist the contributions,
                              then explain.
============================  ==============================================

Separating ``scanner_service`` (execution) from ``normalization_service``
(translation) is a deliberate design constraint from the project specification.
It means parser logic is unit testable without executing any security tool, and
a scanner integration bug cannot corrupt the risk model.
"""

__all__: list[str] = []