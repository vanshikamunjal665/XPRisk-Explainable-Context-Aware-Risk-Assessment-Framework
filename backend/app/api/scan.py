"""``POST /scan`` — the end-to-end assessment endpoint (Phase 13).

The first endpoint that exercises the whole pipeline: it runs the selected
scanners, normalizes their output, scores the findings against the supplied
context, explains the result and persists all of it, returning the stored
``deployment_id``.

Two design constraints, both from the architecture:

**Routers hold no business logic.** Every line here is HTTP: validate with a
schema from :mod:`backend.app.schemas`, delegate to
:class:`~backend.app.services.scan_service.ScanService`, return a response model.
The sequence lives in the service so it stays reachable from a script.

**A scanner failure is not an HTTP error.** A missing binary or a crashing tool
is reported inside a 200 response, per tool, in ``statuses`` and ``errors``. A
gate that fails the whole build because Gitleaks is not installed would be
useless in practice, and the service already guarantees a deployment is always
recorded.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Request, status

from backend.app.schemas.scan import ScanRequest, ScanResponse

logger = logging.getLogger(__name__)

router = APIRouter(tags=["scan"])


def _serialize(outcome: object) -> dict:
    """Flatten a :class:`ScanOutcome` into JSON-safe primitives.

    The explanation and recommendation are frozen dataclasses holding enums and
    nested dataclasses, so they go through ``dataclasses.asdict`` rather than
    ``str``: a stringified dataclass in an API response is unreadable to a client.
    """

    import dataclasses

    def convert(value: object) -> object:
        if dataclasses.is_dataclass(value) and not isinstance(value, type):
            return dataclasses.asdict(value)
        if isinstance(value, dict):
            return {str(k): convert(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [convert(v) for v in value]
        return value.value if hasattr(value, "value") else value

    return {
        "deployment_id": outcome.deployment_id,
        "risk_score": outcome.risk_score,
        "decision": outcome.decision,
        "base_score": outcome.base_score,
        "total_raw": outcome.total_raw,
        "finding_count": outcome.finding_count,
        "context": convert(outcome.context),
        "statuses": convert(outcome.statuses),
        "errors": convert(outcome.errors),
        "severity_breakdown": convert(outcome.severity_breakdown),
        "category_breakdown": convert(outcome.category_breakdown),
        "explanation": convert(outcome.explanation),
        "recommendation": convert(outcome.recommendation),
    }


@router.post(
    "/scan",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Run, score, explain and persist one deployment",
)
def create_scan(payload: ScanRequest, request: Request) -> ScanResponse:
    """Assess a deployment.

    Returns 201 with the persisted ``deployment_id`` so the caller can read the
    stored result back. A 4xx means the request was malformed; a scanner that
    failed is *not* a 4xx and appears in ``statuses``.
    """

    from backend.app.main import get_scan_service

    service = get_scan_service(request)
    try:
        outcome = service.assess(payload.to_scan_request())
    except ValueError as exc:
        # An unrecognised context value reaching the engine. The schema should
        # have caught it; this branch exists so a future caller that bypasses the
        # schema gets a 422 rather than a 500.
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001 - never leak an internal traceback
        logger.exception("scan failed")
        raise HTTPException(
            status_code=500, detail=f"assessment failed: {exc.__class__.__name__}"
        ) from exc

    return ScanResponse(**_serialize(outcome))