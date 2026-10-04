"""Tests for the scanner adapters (Phase 4).

All tests mock subprocess/network I/O: no real Trivy, Checkov, Gitleaks or
SonarQube server is required. Fixture paths are labelled fixture-only.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, ".")  # repository root on sys.path (conftest also does this)

from scanners.base import (  # noqa: E402
    DataOrigin,
    ScannerStatus,
    parse_json_object_or_list,
    resolve_executable,
    run_command,
)
from scanners.checkov_scanner import CheckovScanner, parse_checkov_report  # noqa: E402
from scanners.gitleaks_scanner import GitleaksScanner, parse_gitleaks_report  # noqa: E402
from scanners.sonarqube_scanner import (  # noqa: E402
    SEVERITY_MAP,
    SonarQubeScanner,
    parse_issues_payload,
)
from scanners.trivy_scanner import TrivyScanner, parse_trivy_report  # noqa: E402
# Imported only for the id-stability test below: the scanner rewrites Trivy's
# ephemeral tarball target, and the consequence for finding ids is a
# scanner/normalizer contract worth pinning.
from normalizer.normalizer import normalize_trivy  # noqa: E402

FIX = Path("fixtures")


def _completed(rc: int, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=rc, stdout=stdout, stderr=stderr)


# --------------------------------------------------------------------------
# parse helpers
# --------------------------------------------------------------------------

def test_parse_json_rejects_empty_and_invalid():
    with pytest.raises(ValueError):
        parse_json_object_or_list("")
    with pytest.raises(ValueError):
        parse_json_object_or_list("not json")


# --------------------------------------------------------------------------
# Gitleaks
# --------------------------------------------------------------------------

def test_gitleaks_parse_findings():
    findings = parse_gitleaks_report((FIX / "gitleaks/secrets_detected.json").read_text())
    # Both rule ids come from a verified `gitleaks dir` run (8.30.1) against
    # demo-app/scenarios/insecure with fixtures/gitleaks/gitleaks.toml.
    assert [f.rule_id for f in findings] == ["xprisk-test-secret", "private-key"]
    assert findings[0].start_line == 33
    assert findings[0].tags == ["xprisk", "test-fixture", "false-positive-by-design"]
    assert findings[1].start_line == 40
    assert all(f.file == "demo-app/scenarios/insecure/secrets/fake_secrets.env" for f in findings)


def test_gitleaks_dir_mode_passes_target_positionally(monkeypatch):
    """`gitleaks dir` takes a positional path, not `--source`.

    Verified against 8.30.1: `--source` is rejected by `dir` with
    `unknown flag: --source` and exit 1. The legacy `detect` subcommand still
    requires `--source`, so the adapter must use a different argument shape
    per mode.
    """
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        Path(argv[argv.index("--report-path") + 1]).write_text("[]")
        return _completed(0)

    monkeypatch.setattr(subprocess, "run", fake_run)

    GitleaksScanner().scan("demo-app/scenarios/insecure", mode="dir")
    assert "--source" not in captured["argv"]
    assert captured["argv"][1] == "dir"
    assert captured["argv"][2] == "demo-app/scenarios/insecure"

    GitleaksScanner().scan("demo-app/scenarios/insecure", mode="detect")
    assert captured["argv"][1] == "detect"
    assert "--source" in captured["argv"]
    assert captured["argv"][captured["argv"].index("--source") + 1] == (
        "demo-app/scenarios/insecure"
    )


def test_gitleaks_parse_clean():
    assert parse_gitleaks_report((FIX / "gitleaks/secrets_clean.json").read_text()) == []


def test_gitleaks_parse_malformed_and_non_list():
    with pytest.raises(ValueError):
        parse_gitleaks_report("{not a list}")
    with pytest.raises(ValueError):
        parse_gitleaks_report('{"a": 1}')


def test_gitleaks_missing_executable(monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(FileNotFoundError()))
    result = GitleaksScanner(executable="gitleaks-nope").scan(".")
    assert result.status is ScannerStatus.UNAVAILABLE
    assert result.data_origin is DataOrigin.REAL


def test_gitleaks_failure_and_timeout(monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _completed(2, stderr="boom"))
    assert GitleaksScanner().scan(".").status is ScannerStatus.FAILED
    def timeout(*a, **k):
        raise subprocess.TimeoutExpired(cmd="gitleaks", timeout=1)
    monkeypatch.setattr(subprocess, "run", timeout)
    assert GitleaksScanner(timeout=1).scan(".").status is ScannerStatus.TIMEOUT


def test_gitleaks_real_success_with_leaks(monkeypatch):
    report = (FIX / "gitleaks/secrets_detected.json").read_text()
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        report_path = Path(argv[argv.index("--report-path") + 1])
        report_path.write_text(report)
        return _completed(1)

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = GitleaksScanner().scan("demo-app/scenarios/insecure")
    assert result.status is ScannerStatus.SUCCESS
    assert len(result.findings) == 2
    assert result.data_origin is DataOrigin.REAL
    assert captured["argv"][0] == "gitleaks"
    assert "--report-format" in captured["argv"]


def test_gitleaks_fixture_is_labelled():
    result = GitleaksScanner().scan_fixture(FIX / "gitleaks/secrets_detected.json")
    assert result.data_origin is DataOrigin.FIXTURE
    assert result.status is ScannerStatus.SUCCESS


# --------------------------------------------------------------------------
# Trivy
# --------------------------------------------------------------------------

def test_trivy_parse_multiple_vulns():
    findings = parse_trivy_report((FIX / "trivy/sample_image_scan.json").read_text())
    assert len(findings) == 2
    assert findings[0].vulnerability_id == "CVE-2023-12345"
    assert findings[1].fixed_version is None


def test_trivy_parse_clean_and_malformed():
    assert parse_trivy_report((FIX / "trivy/sample_image_scan_clean.json").read_text()) == []
    with pytest.raises(ValueError):
        parse_trivy_report("[1,2]")


def test_trivy_missing_executable(monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(FileNotFoundError()))
    assert TrivyScanner().scan_image("img:1").status is ScannerStatus.UNAVAILABLE


def test_trivy_failure_and_malformed_output(monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _completed(1, stderr="err"))
    assert TrivyScanner().scan_image("img:1").status is ScannerStatus.FAILED
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _completed(0, stdout="junk"))
    assert TrivyScanner().scan_image("img:1").status is ScannerStatus.MALFORMED


def test_trivy_real_success(monkeypatch):
    stdout = (FIX / "trivy/sample_image_scan.json").read_text()
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        return _completed(0, stdout=stdout)

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = TrivyScanner().scan_image("xprisk:vuln", severities="CRITICAL,HIGH")
    assert result.status is ScannerStatus.SUCCESS
    assert len(result.findings) == 2
    assert captured["argv"][:2] == ["trivy", "image"]


def test_trivy_scan_image_passes_image_as_positional(monkeypatch):
    """`trivy image <name>` takes the image as a positional final argument."""
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        return _completed(0, stdout="[]")

    monkeypatch.setattr(subprocess, "run", fake_run)
    TrivyScanner().scan_image("xprisk:vuln")
    assert captured["argv"][-1] == "xprisk:vuln"
    assert "--input" not in captured["argv"]


def test_trivy_local_image_uses_docker_save_then_input(monkeypatch):
    """Local images go via `docker save` + `trivy image --input`.

    On Windows with Docker Desktop, `trivy image <local-tag>` cannot reach the
    daemon (it times out on the `dockerDesktopLinuxEngine` named pipe) and then
    tries to pull the tag from Docker Hub, which fails with UNAUTHORIZED. The
    tarball path removes the socket dependency entirely.
    """
    report = (FIX / "trivy/sample_image_scan.json").read_text()
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(list(argv))
        if argv[1] == "save":
            # Emulate docker save creating the tarball it was asked for.
            Path(argv[argv.index("-o") + 1]).write_bytes(b"tar")
            return _completed(0)
        return _completed(0, stdout=report)

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = TrivyScanner().scan_local_image("xprisk-vulnerable:demo")

    assert result.status is ScannerStatus.SUCCESS
    assert result.data_origin is DataOrigin.REAL
    assert len(result.findings) == 2
    assert len(calls) == 2

    save_argv, trivy_argv = calls
    assert save_argv[:2] == ["docker", "save"]
    assert save_argv[-1] == "xprisk-vulnerable:demo"
    assert trivy_argv[:2] == ["trivy", "image"]
    assert "--input" in trivy_argv
    tarball = trivy_argv[trivy_argv.index("--input") + 1]
    assert tarball.endswith(".tar")
    # The image name is NOT passed to trivy: it is not a registry reference.
    assert "xprisk-vulnerable:demo" not in trivy_argv


def test_trivy_local_image_cleans_up_tarball(monkeypatch, tmp_path):
    seen = {}

    def fake_run(argv, **kwargs):
        if argv[1] == "save":
            tar = Path(argv[argv.index("-o") + 1])
            tar.write_bytes(b"tar")
            seen["tarball"] = tar
            seen["tmpdir"] = tar.parent
            return _completed(0)
        return _completed(0, stdout="[]")

    monkeypatch.setattr(subprocess, "run", fake_run)
    TrivyScanner().scan_local_image("xprisk-vulnerable:demo")
    assert not seen["tmpdir"].exists(), "temp tarball dir must be removed"

    seen.clear()

    def fake_run_keep(argv, **kwargs):
        if argv[1] == "save":
            tar = Path(argv[argv.index("-o") + 1])
            tar.write_bytes(b"tar")
            seen["tmpdir"] = tar.parent
            return _completed(0)
        return _completed(0, stdout="[]")

    monkeypatch.setattr(subprocess, "run", fake_run_keep)
    TrivyScanner().scan_local_image("xprisk-vulnerable:demo", keep_tarball=True)
    assert seen["tmpdir"].exists(), "keep_tarball=True must retain the tarball"
    import shutil

    shutil.rmtree(seen["tmpdir"], ignore_errors=True)


def test_trivy_local_image_docker_save_failures(monkeypatch):
    # docker binary absent -> UNAVAILABLE, not FAILED
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(FileNotFoundError())
    )
    r = TrivyScanner().scan_local_image("xprisk:vuln")
    assert r.status is ScannerStatus.UNAVAILABLE
    assert "docker" in (r.error or "")

    # docker save exits non-zero -> FAILED, and trivy is never invoked
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _completed(1, stderr="no such image"))
    r = TrivyScanner().scan_local_image("xprisk:vuln")
    assert r.status is ScannerStatus.FAILED
    assert "no such image" in r.error

    # docker save times out -> TIMEOUT
    def timeout(*a, **k):
        raise subprocess.TimeoutExpired(cmd="docker", timeout=1)

    monkeypatch.setattr(subprocess, "run", timeout)
    assert TrivyScanner(timeout=1).scan_local_image("xprisk:vuln").status is ScannerStatus.TIMEOUT


def test_trivy_local_image_rejects_empty_target():
    r = TrivyScanner().scan_local_image("   ")
    assert r.status is ScannerStatus.FAILED
    assert "image target is required" in r.error


def test_trivy_local_image_target_is_not_the_ephemeral_tarball(monkeypatch):
    """`--input` makes Trivy report the tarball as the target.

    The tarball lives in a random temp dir that is deleted immediately, so if
    that path were kept it would make finding ids non-deterministic across
    runs and show up as a meaningless path in the dashboard.
    """
    seen_targets = []

    def fake_run(argv, **kwargs):
        if argv[1] == "save":
            Path(argv[argv.index("-o") + 1]).write_bytes(b"tar")
            return _completed(0)
        # Mimic Trivy echoing the artifact it was handed.
        tar = argv[argv.index("--input") + 1]
        payload = json.dumps(
            {
                "Results": [
                    {
                        "Target": "%s (debian 11.2)" % tar,
                        "Type": "debian",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-2011-3374",
                                "PkgName": "apt",
                                "InstalledVersion": "1.8.2",
                                "Severity": "LOW",
                            }
                        ],
                    }
                ]
            }
        )
        return _completed(0, stdout=payload)

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = TrivyScanner().scan_local_image("xprisk-vulnerable:demo")

    assert result.status is ScannerStatus.SUCCESS
    assert len(result.findings) == 1
    target = result.findings[0].target
    seen_targets.append(target)

    assert "xprisk-vulnerable:demo" in target
    assert ".tar" not in target
    assert "Temp" not in target and "xprisk-trivy-" not in target
    # Trivy's own target detail must survive.
    assert target.endswith("(debian 11.2)")


def test_trivy_local_image_ids_are_stable_across_runs(monkeypatch):
    """Two scans of the same image must produce identical finding ids."""

    def fake_run(argv, **kwargs):
        if argv[1] == "save":
            Path(argv[argv.index("-o") + 1]).write_bytes(b"tar")
            return _completed(0)
        tar = argv[argv.index("--input") + 1]
        payload = json.dumps(
            {
                "Results": [
                    {
                        "Target": "%s (debian 11.2)" % tar,
                        "Type": "debian",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-2011-3374",
                                "PkgName": "apt",
                                "InstalledVersion": "1.8.2",
                                "Severity": "LOW",
                            }
                        ],
                    }
                ]
            }
        )
        return _completed(0, stdout=payload)

    monkeypatch.setattr(subprocess, "run", fake_run)
    ids = []
    for _ in range(2):
        r = TrivyScanner().scan_local_image("xprisk-vulnerable:demo")
        ids.append(normalize_trivy(r.findings[0], data_origin="REAL").id)
    assert ids[0] == ids[1]


def test_trivy_fixture_labelled():
    assert TrivyScanner().scan_fixture(FIX / "trivy/sample_image_scan.json").data_origin is DataOrigin.FIXTURE


# --------------------------------------------------------------------------
# Checkov
# --------------------------------------------------------------------------

def test_checkov_parse_failed_checks():
    findings = parse_checkov_report((FIX / "checkov/terraform_insecure.json").read_text())
    assert len(findings) == 2
    assert findings[0].check_id == "CKV_AWS_20"
    assert findings[0].start_line == 27


def test_checkov_parse_clean_and_malformed():
    assert parse_checkov_report((FIX / "checkov/terraform_clean.json").read_text()) == []
    with pytest.raises(ValueError):
        parse_checkov_report('{"results": "nope"}')


def test_checkov_missing_executable(monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(FileNotFoundError()))
    assert CheckovScanner().scan(".").status is ScannerStatus.UNAVAILABLE


def test_checkov_failure_and_success_rc1(monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _completed(3, stderr="crash"))
    assert CheckovScanner().scan(".").status is ScannerStatus.FAILED

    stdout = (FIX / "checkov/terraform_insecure.json").read_text()
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _completed(1, stdout=stdout))
    result = CheckovScanner().scan("infrastructure/scenarios/insecure")
    assert result.status is ScannerStatus.SUCCESS
    assert len(result.findings) == 2


def test_checkov_fixture_labelled():
    assert CheckovScanner().scan_fixture(FIX / "checkov/terraform_insecure.json").data_origin is DataOrigin.FIXTURE


def test_checkov_argv_shape(monkeypatch):
    """Pin the Checkov argument vector.

    There was no assertion on Checkov's argv at all, which is how the
    subprocess-handling bugs went unnoticed for this adapter specifically.
    Gitleaks and Trivy both have one.

    Verified against checkov 3.3.22: `-d <path> -o json --framework <fw>
    --quiet` produces valid JSON on stdout and exits 0 (or 1 when checks
    fail, which is still a successful scan).

    `shutil.which` is stubbed to None so that Windows .cmd-shim resolution is
    bypassed. Without this the assertions would depend on whether checkov
    happens to be installed on the machine running the suite: on Windows with
    checkov on PATH the argv is rewritten to `cmd.exe /d /c .../checkov.CMD`,
    on a machine without checkov it is left alone. This test is about the argv
    the adapter *builds*, so resolution is disabled explicitly.
    """
    stdout = (FIX / "checkov/terraform_insecure.json").read_text()
    captured = {}
    monkeypatch.setattr(shutil, "which", lambda name: None)

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        return _completed(1, stdout=stdout)

    monkeypatch.setattr(subprocess, "run", fake_run)
    CheckovScanner().scan("infrastructure/scenarios/insecure", framework="terraform")

    argv = captured["argv"]
    assert argv[0] == "checkov"
    assert "-d" in argv
    assert argv[argv.index("-d") + 1] == "infrastructure/scenarios/insecure"
    # -o json, not --output json: both exist, but -o is what was verified.
    assert "-o" in argv and argv[argv.index("-o") + 1] == "json"
    assert "--framework" in argv
    assert argv[argv.index("--framework") + 1] == "terraform"
    assert "--quiet" in argv


# --------------------------------------------------------------------------
# Windows executable resolution (scanners.base.resolve_executable)
# --------------------------------------------------------------------------

def test_resolve_executable_leaves_real_binaries_alone(monkeypatch):
    """A genuine executable must reach subprocess.run exactly as given.

    This is what preserves the `shell=False` guarantee for gitleaks.exe and
    trivy.exe.
    """
    monkeypatch.setattr(shutil, "which", lambda name: r"C:\tools\gitleaks.exe")
    argv = ["gitleaks", "dir", "some/path"]
    assert resolve_executable(argv) is argv


def test_resolve_executable_leaves_missing_names_alone(monkeypatch):
    """An unresolvable name is passed through so the caller reports UNAVAILABLE.

    Rewriting it to cmd.exe here would turn a clear 'executable not found'
    into a confusing cmd.exe exit code.
    """
    monkeypatch.setattr(shutil, "which", lambda name: None)
    argv = ["definitely-not-installed-xyz", "dir"]
    assert resolve_executable(argv) is argv


@pytest.mark.skipif(os.name != "nt", reason="PATHEXT shim resolution is Windows-only")
def test_resolve_executable_routes_cmd_shim_through_comspec(monkeypatch):
    """A pip-installed Python CLI is a .cmd shim, which CreateProcess cannot run.

    Verified with checkov 3.3.22: `subprocess.run(['checkov', ...], shell=False)`
    raises FileNotFoundError even with the shim on PATH and PATHEXT containing
    .CMD, because subprocess does not consult PATHEXT.
    """
    shim = r"C:\proj\.venv\Scripts\checkov.CMD"
    monkeypatch.setattr(shutil, "which", lambda name: shim)
    monkeypatch.setenv("COMSPEC", r"C:\WINDOWS\system32\cmd.exe")
    out = resolve_executable(["checkov", "-d", "iac", "-o", "json"])

    assert out[0].lower().endswith("cmd.exe")
    assert out[1] == "/d"
    assert out[2] == "/c"
    assert out[3] == shim
    # Tool arguments are preserved verbatim, in order.
    assert out[4:] == ["-d", "iac", "-o", "json"]


@pytest.mark.skipif(os.name != "nt", reason="PATHEXT shim resolution is Windows-only")
def test_resolve_executable_is_a_noop_off_windows(monkeypatch):
    monkeypatch.setattr(os, "name", "posix")
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/checkov")
    argv = ["checkov", "-d", "iac"]
    assert resolve_executable(argv) is argv


def test_run_command_uses_resolved_argv(monkeypatch):
    """run_command must actually pass the rewritten argv to subprocess.run."""
    monkeypatch.setattr(shutil, "which", lambda name: r"C:\proj\.venv\Scripts\checkov.CMD")
    monkeypatch.setenv("COMSPEC", r"C:\WINDOWS\system32\cmd.exe")
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured["shell"] = kwargs.get("shell")
        return _completed(0, stdout="[]")

    monkeypatch.setattr(subprocess, "run", fake_run)
    run_command(["checkov", "--version"], timeout=5)

    # Still shell=False: the interpreter is invoked directly, never via shell=True.
    assert captured["shell"] is False
    assert captured["argv"][3].lower().endswith("checkov.cmd")
    assert captured["argv"][-1] == "--version"


# --------------------------------------------------------------------------
# SonarQube
# --------------------------------------------------------------------------

def test_sonarqube_parse_and_severity_mapping():
    payload = json.loads((FIX / "sonarqube/issues_sample.json").read_text())
    findings = parse_issues_payload(payload)
    assert findings[0].severity == "CRITICAL"  # BLOCKER -> CRITICAL
    assert findings[0].severity_raw == "CRITICAL"
    assert findings[1].severity == "MEDIUM"  # MINOR -> MEDIUM
    assert findings[1].line is None


def test_sonarqube_severity_map_is_predictable():
    assert set(SEVERITY_MAP) == {"BLOCKER", "CRITICAL", "MAJOR", "MINOR", "INFO"}


def test_sonarqube_malformed_payload():
    with pytest.raises(ValueError):
        parse_issues_payload(["not", "a", "dict"])


class _FakeResponse:
    def __init__(self, status_code=200, json_value=None, text=""):
        self.status_code = status_code
        self._json = json_value
        self.text = text

    def raise_for_status(self):
        if self.status_code >= 400:
            import httpx

            raise httpx.HTTPStatusError("err", request=None, response=None)

    def json(self):
        if self._json is None:
            raise ValueError("no json")
        return self._json


class _FakeClient:
    def __init__(self, pages):
        self.pages = list(pages)
        self.calls = 0

    def get(self, url, params=None, auth=None, timeout=None):
        self.calls += 1
        page = self.pages[min(self.calls - 1, len(self.pages) - 1)]
        return page

    def close(self):
        pass


def test_sonarqube_fetch_success_and_pagination():
    page1 = _FakeResponse(200, {"total": 501, "issues": [{"rule": "r", "severity": "MAJOR"}]})
    page2 = _FakeResponse(200, {"total": 501, "issues": [{"rule": "r2", "severity": "INFO"}]})
    client = _FakeClient([page1, page2])
    scanner = SonarQubeScanner(url="http://sonar.test", project_key="p", token="t", client=client)
    result = scanner.fetch()
    assert result.status is ScannerStatus.SUCCESS
    assert len(result.findings) == 2
    assert client.calls == 2  # paginated


def test_sonarqube_auth_failure_and_unavailable():
    scanner = SonarQubeScanner(url="http://x", project_key="p", token="t", client=_FakeClient([_FakeResponse(401)]))
    assert scanner.fetch().status is ScannerStatus.FAILED

    import httpx

    class Down(_FakeClient):
        def get(self, *a, **k):
            raise httpx.ConnectError("refused")

    scanner = SonarQubeScanner(url="http://x", project_key="p", token="t", client=Down([]))
    assert scanner.fetch().status is ScannerStatus.UNAVAILABLE


def test_sonarqube_fixture_labelled_and_clean():
    result = SonarQubeScanner().scan_fixture(FIX / "sonarqube/issues_sample.json")
    assert result.data_origin is DataOrigin.FIXTURE
    assert result.status is ScannerStatus.SUCCESS
    clean = SonarQubeScanner().scan_fixture(FIX / "sonarqube/issues_clean.json")
    assert clean.status is ScannerStatus.NO_FINDINGS
    assert clean.data_origin is DataOrigin.FIXTURE
