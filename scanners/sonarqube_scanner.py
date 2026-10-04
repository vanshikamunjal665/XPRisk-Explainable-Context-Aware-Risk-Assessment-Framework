"""SonarQube scanner adapter.

Talks to the SonarQube Web API (``GET /api/issues/search``) using httpx.
Credentials come exclusively from the environment (``SONARQUBE_URL``,
``SONARQUBE_PROJECT_KEY``, ``SONARQUBE_TOKEN``); nothing is hardcoded and the
token is never logged or included in errors.

Severity is mapped into a predictable representation while the SonarQube
original is preserved as ``severity_raw``.
"""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import httpx

from scanners.base import DataOrigin, ScannerResult, ScannerStatus

#: Predictable severity mapping applied to SonarQube severities.
SEVERITY_MAP = {
    "BLOCKER": "CRITICAL",
    "CRITICAL": "CRITICAL",
    "MAJOR": "HIGH",
    "MINOR": "MEDIUM",
    "INFO": "LOW",
}


@dataclass
class SonarQubeFinding:
    rule: str | None = None
    component: str | None = None
    line: int | None = None
    message: str | None = None
    issue_type: str | None = None
    severity: str | None = None  # predictable representation
    severity_raw: str | None = None  # SonarQube's own vocabulary
    status: str | None = None
    source: str = "sonarqube"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_issues_payload(payload: Any) -> list[SonarQubeFinding]:
    if not isinstance(payload, dict) or not isinstance(payload.get("issues"), list):
        raise ValueError("expected an object with an 'issues' array")
    findings: list[SonarQubeFinding] = []
    for issue in payload["issues"]:
        if not isinstance(issue, dict):
            raise ValueError("issue entry is not an object")
        raw = issue.get("severity")
        findings.append(
            SonarQubeFinding(
                rule=issue.get("rule"),
                component=issue.get("component"),
                line=issue.get("line"),
                message=issue.get("message"),
                issue_type=issue.get("type"),
                severity=SEVERITY_MAP.get(str(raw).upper(), "INFO") if raw else None,
                severity_raw=raw,
                status=issue.get("status"),
            )
        )
    return findings


class SonarQubeScanner:
    def __init__(
        self,
        url: str | None = None,
        project_key: str | None = None,
        token: str | None = None,
        timeout: float = 30.0,
        client: httpx.Client | None = None,
    ) -> None:
        self.url = (url or os.environ.get("SONARQUBE_URL", "")).rstrip("/")
        self.project_key = project_key or os.environ.get("SONARQUBE_PROJECT_KEY", "")
        self.token = token if token is not None else os.environ.get("SONARQUBE_TOKEN", "")
        self.timeout = timeout
        self._client = client

    def _pages(self, client: httpx.Client):
        page = 1
        while True:
            response = client.get(
                f"{self.url}/api/issues/search",
                params={
                    "componentKeys": self.project_key,
                    "ps": 500,
                    "p": page,
                    "issueStatuses": "OPEN,CONFIRMED,REOPENED",
                },
                auth=(self.token, ""),
                timeout=self.timeout,
            )
            if response.status_code in (401, 403):
                raise PermissionError(f"authentication failed (HTTP {response.status_code})")
            response.raise_for_status()
            payload = response.json()
            yield payload
            total = payload.get("total") if isinstance(payload, dict) else None
            issues = payload.get("issues") if isinstance(payload, dict) else None
            if not isinstance(total, int) or not isinstance(issues, list) or page * 500 >= total:
                return
            page += 1

    def fetch(self) -> ScannerResult:
        target = f"{self.url}/{self.project_key}" if self.url else self.project_key
        if not self.url or not self.project_key:
            return ScannerResult("sonarqube", ScannerStatus.FAILED, DataOrigin.REAL, target, error="SONARQUBE_URL and SONARQUBE_PROJECT_KEY must be set")
        client = self._client or httpx.Client()
        try:
            findings: list[SonarQubeFinding] = []
            for payload in self._pages(client):
                findings.extend(parse_issues_payload(payload))
        except PermissionError as exc:
            return ScannerResult("sonarqube", ScannerStatus.FAILED, DataOrigin.REAL, target, error=str(exc))
        except httpx.ConnectError:
            return ScannerResult("sonarqube", ScannerStatus.UNAVAILABLE, DataOrigin.REAL, target, error="SonarQube server unreachable")
        except httpx.TimeoutException:
            return ScannerResult("sonarqube", ScannerStatus.TIMEOUT, DataOrigin.REAL, target, error="request timed out")
        except httpx.HTTPError as exc:
            return ScannerResult("sonarqube", ScannerStatus.FAILED, DataOrigin.REAL, target, error=f"HTTP error: {exc.__class__.__name__}")
        except (ValueError, KeyError) as exc:
            return ScannerResult("sonarqube", ScannerStatus.MALFORMED, DataOrigin.REAL, target, error=f"malformed response: {exc}")
        finally:
            if self._client is None:
                client.close()
        status = ScannerStatus.SUCCESS if findings else ScannerStatus.NO_FINDINGS
        return ScannerResult("sonarqube", status, DataOrigin.REAL, target, findings=findings)

    def scan_fixture(self, fixture_path: str | Path, target: str = "<fixture>") -> ScannerResult:
        try:
            payload = httpx.Response(200, text=Path(fixture_path).read_text(encoding="utf-8")).json()
            findings = parse_issues_payload(payload)
        except (ValueError, OSError) as exc:
            return ScannerResult("sonarqube", ScannerStatus.MALFORMED, DataOrigin.FIXTURE, target, error=str(exc))
        status = ScannerStatus.SUCCESS if findings else ScannerStatus.NO_FINDINGS
        return ScannerResult("sonarqube", status, DataOrigin.FIXTURE, target, findings=findings)
