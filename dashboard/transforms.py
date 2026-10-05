"""Pure dashboard data-transformation helpers.

These functions contain no Streamlit and no database access. They turn
existing XPRisk objects (findings, assessments, explanation payloads, stored
deployment rows) into plain rows/counts the dashboard renders, so they can be
unit tested without a browser or a running server.
"""

from __future__ import annotations

import re
from typing import Any, Iterable

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

# Columns the dashboard is allowed to show for a finding. Anything outside
# this list (scanner metadata, matched values, credentials) is never rendered.
FINDING_COLUMNS = ["tool", "category", "severity", "finding_id", "resource", "file", "line", "description"]

_SECRET_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?i)(aws_secret_access_key|secret|password|passwd|token|api[_-]?key)\s*[:=]\s*\S+"),
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]+"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
]


def redact_text(text: Any) -> Any:
    """Mask anything that looks like a credential before it reaches the UI."""

    if text is None or not isinstance(text, str):
        return text
    redacted = text
    for pattern in _SECRET_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)
    return redacted


def finding_row(finding: Any) -> dict[str, Any]:
    """One finding as a sanitized table row."""

    def get(name: str) -> Any:
        if isinstance(finding, dict):
            return finding.get(name)
        return getattr(finding, name, None)

    category = get("category")
    severity = get("severity")
    return {
        "tool": get("tool"),
        "category": category.value if hasattr(category, "value") else category,
        "severity": severity.value if hasattr(severity, "value") else severity,
        "finding_id": get("finding_id"),
        "resource": redact_text(get("resource")),
        "file": redact_text(get("file")),
        "line": get("line"),
        "description": redact_text(get("description")),
    }


def findings_table(findings: Iterable[Any]) -> list[dict[str, Any]]:
    return [finding_row(f) for f in findings]


def severity_counts(rows: Iterable[dict]) -> dict[str, int]:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for row in rows:
        sev = row.get("severity")
        if sev in counts:
            counts[sev] += 1
        else:
            counts[sev] = counts.get(sev, 0) + 1
    return counts


def group_counts(rows: Iterable[dict], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        value = row.get(key)
        counts[value] = counts.get(value, 0) + 1
    return counts


def filter_findings(
    rows: Iterable[dict],
    *,
    severities: Iterable[str] | None = None,
    tools: Iterable[str] | None = None,
    categories: Iterable[str] | None = None,
) -> list[dict]:
    sev = set(severities) if severities else None
    tl = set(tools) if tools else None
    cat = set(categories) if categories else None
    out = []
    for row in rows:
        if sev and row.get("severity") not in sev:
            continue
        if tl and row.get("tool") not in tl:
            continue
        if cat and row.get("category") not in cat:
            continue
        out.append(row)
    return out


def contributions_table(assessment: Any) -> list[dict[str, Any]]:
    """Engine-produced contributions, ranked. Never recomputed here."""

    rows = []
    for c in getattr(assessment, "ranked_contributions", ()):
        rows.append(
            {
                "finding": c.label,
                "tool": c.tool,
                "category": c.category.value if hasattr(c.category, "value") else c.category,
                "severity": c.severity.value if hasattr(c.severity, "value") else c.severity,
                "raw_risk": c.raw_risk,
                "share_of_total": c.share_of_total,
                "location": c.location,
            }
        )
    return rows


def context_contributors_table(explanation: Any) -> list[dict[str, Any]]:
    rows = []
    for c in getattr(explanation, "context_contributors", ()):
        rows.append(
            {
                "factor": c.factor,
                "value": c.value,
                "multiplier": c.multiplier,
                "amplified": c.amplified,
            }
        )
    return rows


def deployment_row(deployment: Any) -> dict[str, Any]:
    return {
        "id": getattr(deployment, "id", None),
        "commit_id": getattr(deployment, "commit_id", None),
        "branch": getattr(deployment, "branch", ""),
        "environment": getattr(deployment, "environment", ""),
        "internet_exposed": getattr(deployment, "internet_exposed", False),
        "timestamp": getattr(deployment, "timestamp", None),
        "risk_score": getattr(deployment, "risk_score", None),
        "decision": getattr(deployment, "decision", None),
    }


def history_table(deployments: Iterable[Any]) -> list[dict[str, Any]]:
    return [deployment_row(d) for d in deployments]


def filter_history(
    rows: Iterable[dict],
    *,
    environments: Iterable[str] | None = None,
    decisions: Iterable[str] | None = None,
    branches: Iterable[str] | None = None,
) -> list[dict]:
    env = set(environments) if environments else None
    dec = set(decisions) if decisions else None
    br = set(branches) if branches else None
    out = []
    for row in rows:
        if env and row.get("environment") not in env:
            continue
        if dec and row.get("decision") not in dec:
            continue
        if br and row.get("branch") not in br:
            continue
        out.append(row)
    return out


def risk_factors_table(factors: Iterable[Any]) -> list[dict[str, Any]]:
    rows = []
    for f in factors:
        rows.append(
            {
                "factor": getattr(f, "factor_name", None),
                "value": getattr(f, "factor_value", None),
                "contribution": getattr(f, "contribution", None),
            }
        )
    return rows
