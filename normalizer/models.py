"""Canonical XPRisk finding schema (Phase 6).

Every finding from every scanner is translated into one common
:class:`NormalizedFinding` structure. Tool-specific details are preserved
under ``metadata`` (namespaced by tool) so normalization is lossless.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Category(str, Enum):
    SOURCE_CODE = "SOURCE_CODE"
    SECRET = "SECRET"
    CONTAINER = "CONTAINER"
    IAC = "IAC"


@dataclass
class XPRiskFinding:
    id: str
    tool: str
    category: Category
    severity: Severity
    finding_id: str | None = None
    resource: str | None = None
    file: str | None = None
    line: int | None = None
    description: str | None = None
    commit_id: str | None = None
    timestamp: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["category"] = self.category.value
        d["severity"] = self.severity.value
        return d


# Backwards-compatible alias.
NormalizedFinding = XPRiskFinding
