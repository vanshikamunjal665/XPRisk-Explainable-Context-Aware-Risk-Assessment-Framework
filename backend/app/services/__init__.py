"""Application services - orchestration layer.

A service composes the domain packages and the database. It is the only layer
allowed to know about more than one of them, and the layer routers call.

**Two of the six exist.** ``scan_service`` and ``storage_service`` are
implemented and tested. The other four are planned and absent; the table marks
which is which.

============================  =========  ==============================================
Service                       Status     Responsibility
============================  =========  ==============================================
``scanner_service``           planned    Trigger the selected scanners, collect their
                                        output, track per-tool status, record errors
                                        and timings. Executes tools; performs **no**
                                        normalization. (Already delivered, but at
                                        ``scanners/scanner_service.py``.)
``normalization_service``     planned    Translate native scanner JSON into canonical
                                        :class:`~normalizer.models.NormalizedFinding`
                                        objects. (Already delivered at
                                        ``normalizer/normalizer.py``.)
``storage_service``           **done**   Persist and query deployments, findings and
                                        risk factors.
``risk_service``              planned    Run the risk engine and the decision thresholds
                                        over findings plus context.
``explanation_service``       planned    Turn a stored or computed contribution breakdown
                                        into the explanation payload.
``scan_service``              **done**   The end-to-end use case: run scanners,
                                        normalize, persist the deployment and its
                                        findings, score, persist the contributions,
                                        then explain.
============================  =========  ==============================================

Note the shape of that table. Three of the four "planned" services already exist
as *packages* — ``scanners/scanner_service.py``, ``normalizer/normalizer.py`` and
the risk engine — and ``scan_service`` calls them directly. What is missing is the
thin service wrappers that would let a router depend on one name per concern. That
is a naming and indirection gap, not missing logic, and it is worth being precise
about that in a review.

``scan_service`` being present means the persistence layer is now live:
``create_deployment``, ``save_findings`` and ``save_risk_factors`` have production
callers, ``xprisk_dev.db`` receives rows, and the dashboard's *Deployment history*
view has a producer. ``tests/test_service_layer.py`` asserts that, so the
situation cannot silently regress to an empty history screen.

Separating scanner execution from finding translation is a deliberate design
constraint. It means parser logic is unit testable without executing any security
tool, and a scanner integration bug cannot corrupt the risk model.
"""

__all__ = ["ScanService", "StorageService"]

from backend.app.services.scan_service import (  # noqa: E402,F401
    ScanOutcome,
    ScanRequest,
    ScanService,
)
from backend.app.services.storage_service import StorageService  # noqa: E402,F401