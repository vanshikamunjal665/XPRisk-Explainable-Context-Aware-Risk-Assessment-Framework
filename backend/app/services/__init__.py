"""Application services - orchestration layer.

A service composes the domain packages and the database. It is the only layer
allowed to know about more than one of them, and the layer routers call.

**One of the six exists.** ``storage_service`` is implemented and tested. The
other five are Phase 12 and are absent from this package. The table below is the
design, not the current state.

============================  =========  ==============================================
Service                       Status     Responsibility
============================  =========  ==============================================
``scanner_service``           planned    Trigger the selected scanners, collect their
                                        output, track per-tool status, record errors
                                        and timings. Executes tools; performs **no**
                                        normalization.
``normalization_service``     planned    Translate native scanner JSON into canonical
                                        :class:`~normalizer.models.NormalizedFinding`
                                        objects. Knows nothing about execution.
``storage_service``           **done**   Persist and query deployments, findings and
                                        risk factors.
``risk_service``              planned    Run the risk engine and the decision thresholds
                                        over findings plus context.
``explanation_service``       planned    Turn a stored or computed contribution breakdown
                                        into the explanation payload.
``scan_service``              planned    The end-to-end use case: run scanners,
                                        normalize, persist the deployment and its
                                        findings, score, persist the contributions,
                                        then explain.
============================  =========  ==============================================

The consequence of ``scan_service`` being absent is worth stating plainly,
because it is not obvious from the code: **no runnable path writes to the
database.** ``StorageService.create_deployment``, ``.save_findings`` and
``.save_risk_factors`` are called only from ``tests/test_storage.py``. The
dashboard composes scanners, normalizer and risk engine in memory and discards
the result, so ``xprisk_dev.db`` stays at zero rows and the dashboard's
*Deployment history* view always reports no deployments.

Separating ``scanner_service`` (execution) from ``normalization_service``
(translation) is a deliberate design constraint from the project specification.
It means parser logic is unit testable without executing any security tool, and
a scanner integration bug cannot corrupt the risk model.
"""

__all__ = ["StorageService"]

from backend.app.services.storage_service import StorageService  # noqa: E402,F401