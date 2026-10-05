"""Trivy scanner adapter.

Executes the real `trivy` executable when available and parses its JSON
report into structured :class:`TrivyFinding` objects. Fixture replay is a
separate, explicitly labelled path.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from scanners.base import (
    DataOrigin,
    ScannerResult,
    ScannerStatus,
    parse_json_object_or_list,
    run_command,
)


@dataclass
class TrivyFinding:
    vulnerability_id: str | None = None
    package: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
    severity: str | None = None
    title: str | None = None
    description: str | None = None
    target: str | None = None
    package_type: str | None = None
    primary_url: str | None = None
    source: str = "trivy"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _optional_version(value: Any) -> str | None:
    """Return a version string, or ``None`` when no fix has been published.

    Trivy represents "no fixed version available" two different ways: the key is
    sometimes absent, sometimes present and set to an empty string. Passing the
    empty string through would put a blank value in finding metadata and, worse,
    would render in the dashboard as though a fix existed. Both forms mean the
    same thing here, so they are collapsed.
    """

    if value is None:
        return None
    text = str(value).strip()
    return text or None


def parse_trivy_report(text: str) -> list[TrivyFinding]:
    data = parse_json_object_or_list(text)
    if not isinstance(data, dict) or not isinstance(data.get("Results"), list):
        raise ValueError("expected a Trivy JSON object with a Results array")
    findings: list[TrivyFinding] = []
    for result in data["Results"]:
        if not isinstance(result, dict):
            raise ValueError("result entry is not an object")
        target = result.get("Target")
        pkg_type = result.get("Type")
        for item in result.get("Vulnerabilities") or []:
            if not isinstance(item, dict):
                raise ValueError("vulnerability entry is not an object")
            findings.append(
                TrivyFinding(
                    vulnerability_id=item.get("VulnerabilityID"),
                    package=item.get("PkgName"),
                    installed_version=item.get("InstalledVersion"),
                    fixed_version=_optional_version(item.get("FixedVersion")),
                    severity=item.get("Severity"),
                    title=item.get("Title"),
                    description=item.get("Description"),
                    target=target,
                    package_type=pkg_type,
                    primary_url=item.get("PrimaryURL"),
                )
            )
    return findings


class TrivyScanner:
    def __init__(
        self,
        executable: str | None = None,
        timeout: float = 600.0,
        docker_executable: str | None = None,
    ) -> None:
        self.executable = executable or os.environ.get("TRIVY_EXECUTABLE", "trivy")
        self.timeout = timeout
        self.docker = docker_executable or os.environ.get("DOCKER_EXECUTABLE", "docker")

    # -- shared internals ----------------------------------------------------

    def _finish(
        self,
        argv: list[str],
        target: str,
        image_label: str,
    ) -> ScannerResult:
        """Run one Trivy invocation and classify the outcome."""

        outcome = run_command(argv, self.timeout)
        if outcome.error and "not found" in outcome.error:
            return ScannerResult("trivy", ScannerStatus.UNAVAILABLE, DataOrigin.REAL, target, error=outcome.error)
        if outcome.error:
            status = ScannerStatus.TIMEOUT if "timed out" in outcome.error else ScannerStatus.FAILED
            return ScannerResult("trivy", status, DataOrigin.REAL, target, error=outcome.error)
        if outcome.returncode != 0:
            return ScannerResult(
                "trivy",
                ScannerStatus.FAILED,
                DataOrigin.REAL,
                target,
                error=(outcome.stderr or "trivy failed")[:500],
                returncode=outcome.returncode,
            )
        try:
            findings = parse_trivy_report(outcome.stdout)
        except ValueError as exc:
            return ScannerResult(
                "trivy",
                ScannerStatus.MALFORMED,
                DataOrigin.REAL,
                target,
                error=str(exc),
                returncode=outcome.returncode,
            )
        status = ScannerStatus.SUCCESS if findings else ScannerStatus.NO_FINDINGS
        return ScannerResult(
            "trivy",
            status,
            DataOrigin.REAL,
            target,
            findings=findings,
            returncode=outcome.returncode,
        )

    # -- public API ----------------------------------------------------------

    @staticmethod
    def _retarget_tarball(findings: list[TrivyFinding], tarball: Path, image: str) -> None:
        """Rewrite the ephemeral tarball path in Trivy's ``Target`` field.

        With ``--input``, Trivy reports the artifact it was handed as the
        target, e.g. ``C:\\\\Users\\\\...\\\\Temp\\\\xprisk-trivy-8f3a\\\\image.tar (debian 11.2)``.
        That path is inside a temporary directory that is deleted straight
        after, and its random component changes on every single run.

        Left alone it causes two real problems:

        * ``XPRiskFinding.id`` is derived from the target, so identical scans
          would produce different ids every run. That breaks the Phase 17
          historical "new vs resolved" comparison and any trend chart.
        * The dashboard would display a meaningless temporary path instead of
          which image was scanned.

        Replacing it with the image reference makes the finding stable and
        meaningful. The trailing target detail that Trivy adds, for example
        ``(debian 11.2)``, is preserved.
        """

        raw = str(tarball)
        # Trivy may echo the path back in Windows or POSIX form.
        posix = tarball.as_posix()
        variants = {raw, posix}
        if len(raw) > 2 and raw[1] == ":":
            variants.add("/" + raw[0].lower() + raw[2:].replace("\\", "/"))
        for finding in findings:
            if not finding.target:
                continue
            target = finding.target
            for variant in variants:
                if variant and variant in target:
                    target = target.replace(variant, image)
            finding.target = target

    def scan_image(self, image: str, severities: str | None = None) -> ScannerResult:
        """Scan a registry image reference by passing it to Trivy directly.

        This requires Trivy to reach a registry, or to reach the local Docker
        daemon through its socket. See :meth:`scan_local_image` for the
        Windows/Docker Desktop case, where that socket is not reachable.
        """

        if not image or not str(image).strip():
            return ScannerResult("trivy", ScannerStatus.FAILED, DataOrigin.REAL, image, error="image target is required")
        argv = [self.executable, "image", "--format", "json", "--quiet"]
        if severities:
            argv += ["--severity", severities]
        argv.append(image)
        return self._finish(argv, image, image)

    def scan_local_image(
        self,
        image: str,
        severities: str | None = None,
        keep_tarball: bool = False,
    ) -> ScannerResult:
        """Scan a locally built image by exporting it with `docker save` first.

        Why this exists
        ---------------
        Verified on Windows with Docker Desktop 29.2.0 and Trivy 0.75.0:
        ``trivy image <local-image>`` cannot reach the daemon. Trivy tries, in
        order, the Docker socket, containerd and Podman, and fails with::

            docker error: unable to inspect the image (...):
              Get "http://%2F%2F%2F.%2Fpipe%2FdockerDesktopLinuxEngine/v1.56/...":
              context deadline exceeded
            containerd error: containerd socket not found
            podman error: no podman socket found

        It then falls back to the remote registry and tries to *pull* the
        local tag from Docker Hub::

            remote error: GET https://index.docker.io/v2/library/xprisk-vulnerable/manifests/demo:
              UNAUTHORIZED: authentication required

        So on this platform the direct path can never work for a locally built
        image. Exporting to a tarball and using ``trivy image --input`` removes
        the socket dependency entirely and is also deterministic.

        The tarball is written to a temporary directory and removed afterwards
        unless ``keep_tarball`` is set.
        """

        if not image or not str(image).strip():
            return ScannerResult("trivy", ScannerStatus.FAILED, DataOrigin.REAL, image, error="image target is required")

        tmp_dir = tempfile.mkdtemp(prefix="xprisk-trivy-")
        tarball = Path(tmp_dir) / "image.tar"
        try:
            save = run_command(
                [self.docker, "save", "-o", str(tarball), str(image)],
                self.timeout,
            )
            if save.error and "not found" in save.error:
                return ScannerResult(
                    "trivy",
                    ScannerStatus.UNAVAILABLE,
                    DataOrigin.REAL,
                    image,
                    error=f"docker executable not available for local image export: {save.error}",
                )
            if save.error:
                status = ScannerStatus.TIMEOUT if "timed out" in save.error else ScannerStatus.FAILED
                return ScannerResult("trivy", status, DataOrigin.REAL, image, error=save.error)
            if save.returncode != 0:
                return ScannerResult(
                    "trivy",
                    ScannerStatus.FAILED,
                    DataOrigin.REAL,
                    image,
                    error=(save.stderr or "docker save failed")[:500],
                    returncode=save.returncode,
                )

            argv = [self.executable, "image", "--input", str(tarball), "--format", "json", "--quiet"]
            if severities:
                argv += ["--severity", severities]
            result = self._finish(argv, image, image)
            if result.status in (ScannerStatus.SUCCESS, ScannerStatus.NO_FINDINGS):
                self._retarget_tarball(result.findings, tarball, image)
            return result
        finally:
            if not keep_tarball:
                shutil.rmtree(tmp_dir, ignore_errors=True)

    def scan_fixture(self, fixture_path: str | Path, target: str = "<fixture>") -> ScannerResult:
        text = Path(fixture_path).read_text(encoding="utf-8")
        try:
            findings = parse_trivy_report(text)
        except ValueError as exc:
            return ScannerResult("trivy", ScannerStatus.MALFORMED, DataOrigin.FIXTURE, target, error=str(exc))
        status = ScannerStatus.SUCCESS if findings else ScannerStatus.NO_FINDINGS
        return ScannerResult("trivy", status, DataOrigin.FIXTURE, target, findings=findings)
