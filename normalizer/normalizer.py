"""Finding normalization (Phase 6).

Converts scanner-specific findings collected by the Phase 5 Scanner
Service into the canonical :class:`XPRiskFinding` schema.

This module never executes scanners: no subprocess, no HTTP, no adapter
invocation. It only transforms already-produced ``ScannerResult`` /
``CollectionResult`` objects. Raw ``ScannerResult`` objects are not
mutated.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

from normalizer.models import Category, Severity, XPRiskFinding
from scanners.base import ScannerResult, ScannerStatus
from scanners.checkov_scanner import CheckovFinding
from scanners.gitleaks_scanner import GitleaksFinding
from scanners.scanner_service import CollectionResult
from scanners.sonarqube_scanner import SonarQubeFinding
from scanners.trivy_scanner import TrivyFinding

# Severity mapping tables -------------------------------------------------

_TRIVY_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.INFO,
}

_CHECKOV_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
    "UNKNOWN": Severity.INFO,
}

_SONARQUBE_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MAJOR": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "MINOR": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.LOW,
    "BLOCKER": Severity.CRITICAL,
}

# Documented XPRisk normalization policies (not scanner-provided).
GITLEAKS_SEVERITY_POLICY = "xprisk_policy: secret finding -> HIGH"
CHECKOV_MISSING_SEVERITY_POLICY = "xprisk_policy: missing severity -> MEDIUM"


def _now_iso(now: datetime | None) -> str:
    if now is None:
        now = datetime.now(timezone.utc)
    elif now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    return now.astimezone(timezone.utc).isoformat()


def _make_id(tool: str, finding_id: str | None, file: str | None, line: int | None) -> str:
    """Deterministic finding id from stable attributes."""
    key = f"{tool}|{finding_id or ''}|{file or ''}|{line if line is not None else ''}"
    return "xprisk-" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def _sev(mapping: dict[str, Severity], raw: Any, default: Severity) -> Severity:
    if isinstance(raw, str) and raw.strip():
        return mapping.get(raw.strip().upper(), default)
    return default


# Gitleaks -------------------------------------------------------------------

def normalize_gitleaks(
    finding: GitleaksFinding,
    *,
    data_origin: str | None = None,
    now: datetime | None = None,
) -> XPRiskFinding:
    return XPRiskFinding(
        id=_make_id("GITLEAKS", finding.rule_id, finding.file, finding.start_line),
        tool="GITLEAKS",
        category=Category.SECRET,
        severity=Severity.HIGH,  # XPRisk policy; Gitleaks has no native severity
        finding_id=finding.rule_id,
        resource=finding.file,
        file=finding.file,
        line=finding.start_line,
        description=finding.description,
        commit_id=finding.commit or None,
        timestamp=finding.date or _now_iso(now),
        metadata={
            "gitleaks": {
                "tags": list(finding.tags),
                "author": finding.author,
                "date": finding.date,
                "commit": finding.commit,
                "start_line": finding.start_line,
                "end_line": finding.end_line,
                "severity_policy": GITLEAKS_SEVERITY_POLICY,
            },
            **({"data_origin": data_origin} if data_origin else {}),
        },
    )


# Trivy ----------------------------------------------------------------------

def normalize_trivy(
    finding: TrivyFinding,
    *,
    data_origin: str | None = None,
    now: datetime | None = None,
) -> XPRiskFinding:
    return XPRiskFinding(
        id=_make_id("TRIVY", finding.vulnerability_id, finding.target, None),
        tool="TRIVY",
        category=Category.CONTAINER,
        severity=_sev(_TRIVY_SEVERITY, finding.severity, Severity.INFO),
        finding_id=finding.vulnerability_id,
        resource=finding.target,
        file=None,  # Trivy image scans have no source file
        line=None,  # Trivy does not provide a meaningful source line
        description=finding.description or finding.title,
        commit_id=None,
        timestamp=_now_iso(now),
        metadata={
            "trivy": {
                "installed_version": finding.installed_version,
                "fixed_version": finding.fixed_version,
                "title": finding.title,
                "target": finding.target,
                "package_type": finding.package_type,
                "primary_url": finding.primary_url,
                "package": finding.package,
                "severity_raw": finding.severity,
            },
            **({"data_origin": data_origin} if data_origin else {}),
        },
    )


# Checkov --------------------------------------------------------------------

def normalize_checkov(
    finding: CheckovFinding,
    *,
    data_origin: str | None = None,
    now: datetime | None = None,
) -> XPRiskFinding:
    missing = not (isinstance(finding.severity, str) and finding.severity.strip())
    severity = _sev(_CHECKOV_SEVERITY, finding.severity, Severity.MEDIUM)
    return XPRiskFinding(
        id=_make_id("CHECKOV", finding.check_id, finding.file_path, finding.start_line),
        tool="CHECKOV",
        category=Category.IAC,
        severity=severity,
        finding_id=finding.check_id,
        resource=finding.resource,
        file=finding.file_path,
        line=finding.start_line,
        description=finding.name,
        commit_id=None,
        timestamp=_now_iso(now),
        metadata={
            "checkov": {
                "name": finding.name,
                "check_type": finding.check_type,
                "evaluation_details": finding.evaluation_details,
                "start_line": finding.start_line,
                "end_line": finding.end_line,
                "severity_raw": finding.severity,
                **({"severity_policy": CHECKOV_MISSING_SEVERITY_POLICY} if missing else {}),
            },
            **({"data_origin": data_origin} if data_origin else {}),
        },
    )


# SonarQube ------------------------------------------------------------------

def normalize_sonarqube(
    finding: SonarQubeFinding,
    *,
    data_origin: str | None = None,
    now: datetime | None = None,
) -> XPRiskFinding:
    # SonarQubeFinding.severity was already mapped by the Phase 4 adapter;
    # fall back to mapping the raw SonarQube vocabulary, then LOW.
    severity = _sev(_SONARQUBE_SEVERITY, finding.severity_raw, Severity.LOW)
    if isinstance(finding.severity, str) and finding.severity.strip():
        severity = _sev({s.value: s for s in Severity}, finding.severity, severity)
    return XPRiskFinding(
        id=_make_id("SONARQUBE", finding.rule, finding.component, finding.line),
        tool="SONARQUBE",
        category=Category.SOURCE_CODE,
        severity=severity,
        finding_id=finding.rule,
        resource=finding.component,
        file=finding.component,
        line=finding.line,
        description=finding.message,
        commit_id=None,
        timestamp=_now_iso(now),
        metadata={
            "sonarqube": {
                "severity_raw": finding.severity_raw,
                "issue_type": finding.issue_type,
                "status": finding.status,
                "component": finding.component,
            },
            **({"data_origin": data_origin} if data_origin else {}),
        },
    )


# ScannerResult / CollectionResult -------------------------------------------

_NORMALIZERS = {
    "gitleaks": normalize_gitleaks,
    "trivy": normalize_trivy,
    "checkov": normalize_checkov,
    "sonarqube": normalize_sonarqube,
}

# Statuses that produced real findings worth normalizing.
_FINDING_STATUSES = {ScannerStatus.SUCCESS}


def normalize_result(result: ScannerResult, *, now: datetime | None = None) -> list[XPRiskFinding]:
    """Normalize one scanner result. Never raises on missing optional fields.

    Only findings that actually exist are normalized. NO_FINDINGS,
    UNAVAILABLE, FAILED, MALFORMED and TIMEOUT results yield ``[]``;
    scanner errors never become security findings. The input result is
    not mutated.
    """
    if result.status not in _FINDING_STATUSES or not result.findings:
        return []
    fn = _NORMALIZERS.get(result.scanner.lower())
    if fn is None:
        return []
    origin = result.data_origin.value if result.data_origin else None
    out: list[XPRiskFinding] = []
    for finding in result.findings:
        try:
            out.append(fn(finding, data_origin=origin, now=now))
        except (AttributeError, TypeError, ValueError):
            # Skip un-normalizable entries rather than crashing the batch.
            continue
    return out


def normalize_collection(
    collection: CollectionResult, *, now: datetime | None = None
) -> list[XPRiskFinding]:
    """Normalize every scanner result in a Phase 5 CollectionResult."""
    normalized: list[XPRiskFinding] = []
    for scanner_name in ("gitleaks", "trivy", "checkov", "sonarqube"):
        result = collection.results.get(scanner_name)
        if result is not None:
            normalized.extend(normalize_result(result, now=now))
    return normalized
