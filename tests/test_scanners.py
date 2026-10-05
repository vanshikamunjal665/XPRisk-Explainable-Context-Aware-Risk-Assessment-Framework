"""Tests for the scanner adapters (Phase 4).

All tests mock subprocess/network I/O: no real Trivy, Checkov, Gitleaks or
SonarQube server is required. Fixture paths are labelled fixture-only.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, ".")  # repository root on sys.path (conftest also does this)

import scanners.base as scanners_base  # noqa: E402

from scanners.base import (  # noqa: E402
    DataOrigin,
    ScannerStatus,
    _locate_executable,
    _shim_child_env,
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

def test_trivy_parse_real_fixture():
    """The committed Trivy fixture is a complete, untruncated real scan.

    Assertions are invariants of genuine scanner output rather than specific
    CVE identifiers: the vulnerability database is refreshed periodically, so
    pinning ``CVE-2011-3374`` would make this test a tripwire that fails for a
    reason unrelated to the code. What must hold is that every record is
    well formed, that the OS and language targets are both present, and that
    the fixture still carries the provenance marker.
    """

    raw = (FIX / "trivy/sample_image_scan.json").read_text(encoding="utf-8")
    document = json.loads(raw)

    assert document["_xprisk_fixture"]["data_origin"] == "REAL_TRIVY_OUTPUT"
    assert document["_xprisk_fixture"]["true_total_vulnerabilities"] == sum(
        len(r["Vulnerabilities"]) for r in document["Results"]
    )

    findings = parse_trivy_report(raw)
    assert len(findings) == 651
    assert {f.package_type for f in findings} == {"debian", "python-pkg"}
    for f in findings:
        # Not every advisory carries a CVE. Real output on this image contains
        # 637 CVE identifiers plus Debian's own advisories: DLA-nnnn-n for
        # patches published before or instead of an upstream CVE, DSA-nnnn-n
        # for security announcements, and TEMP-... while an identifier is still
        # being assigned.
        assert re.fullmatch(
            r"(CVE-\d{4}-\d+|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}"
            r"|TEMP-[0-9A-F-]+|DLA-\d+-\d+|DSA-\d+-\d+)",
            f.vulnerability_id,
        ), f.vulnerability_id
        assert f.severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}
        assert f.package and f.installed_version
        assert f.target and f.package_type

    # Only upstream advisories carry a PrimaryURL; distribution advisories are
    # resolved against the distro tracker instead, which Trivy does not link.
    assert {f.vulnerability_id.split("-")[0] for f in findings if not f.primary_url} == {
        "DLA",
        "DSA",
    }


def test_trivy_fixture_absent_fix_version_becomes_none():
    """A real scan contains advisories with no fix published yet.

    ``FixedVersion`` is emitted as an empty string in that case, and the adapter
    must turn it into ``None`` rather than propagate an empty string as though
    it were a version.
    """

    unfixed = json.dumps(
        {
            "Results": [
                {
                    "Target": "demo:latest",
                    "Type": "debian",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-0000-0000",
                            "PkgName": "p",
                            "InstalledVersion": "1.0",
                            "FixedVersion": "",
                            "Severity": "LOW",
                        }
                    ],
                }
            ]
        }
    )
    assert parse_trivy_report(unfixed)[0].fixed_version is None


def test_trivy_clean_fixture_is_real_not_empty():
    """The 'clean' image is newer but not vulnerability-free.

    An earlier version of this fixture declared an empty ``Vulnerabilities``
    array, which claimed zero known vulnerabilities where a real scan finds
    hundreds. That flattered the demo, so the fixture now holds the real scan
    and this test pins the count.
    """

    raw = (FIX / "trivy/sample_image_scan_clean.json").read_text(encoding="utf-8")
    document = json.loads(raw)
    assert document["_xprisk_fixture"]["data_origin"] == "REAL_TRIVY_OUTPUT"
    assert "xprisk-clean:demo" in document["_xprisk_fixture"]["scanned_targets"][0]

    findings = parse_trivy_report(raw)
    assert len(findings) == 283
    assert all(f.target.startswith("xprisk-clean:demo") or f.target == "Python" for f in findings)


def test_trivy_parse_empty_and_malformed():
    empty = json.dumps({"Results": [{"Target": "x", "Type": "debian", "Vulnerabilities": []}]})
    assert parse_trivy_report(empty) == []
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
    assert len(result.findings) == 651
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
    assert len(result.findings) == 651
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

def test_checkov_parse_real_fixture():
    """The committed Checkov fixture is a complete real run.

    Two properties of genuine Checkov 3.3.22 output are pinned here, because
    both were previously contradicted by a hand-written fixture:

    * ``severity`` is ``null`` on every Terraform resource check, so the
      adapter must pass that ``None`` through rather than substitute a guess;
    * there is no nested ``check`` object, so the human-readable title arrives
      in the flat ``check_name`` field.
    """

    raw = (FIX / "checkov/terraform_insecure.json").read_text(encoding="utf-8")
    document = json.loads(raw)
    assert document[0]["_xprisk_fixture"]["data_origin"] == "REAL_CHECKOV_OUTPUT"

    findings = parse_checkov_report(raw)
    assert len(findings) == 24
    assert all(f.severity is None for f in findings)
    assert all(f.name for f in findings), "every real check carries check_name"
    assert all(f.check_id.startswith(("CKV_", "CKV2_")) for f in findings)
    assert all(f.start_line and f.end_line >= f.start_line for f in findings)
    assert {f.check_type for f in findings} == {"terraform"}

    by_id = {f.check_id: f for f in findings}
    security_group = by_id["CKV_AWS_24"]
    assert security_group.name == "Ensure no security groups allow ingress from 0.0.0.0:0 to port 22"
    assert security_group.resource == "aws_security_group.insecure"
    assert security_group.file_path == "\\main.tf"


def test_checkov_secure_fixture_is_real_not_empty():
    """The hardened scenario still fails some checks.

    An earlier version of this fixture declared zero failed checks. The real
    hardened Terraform fails 8, because Checkov's policy set includes rules the
    hardened file does not attempt to satisfy. That gap is real and is left
    visible rather than edited out of the fixture.
    """

    raw = (FIX / "checkov/terraform_clean.json").read_text(encoding="utf-8")
    findings = parse_checkov_report(raw)
    assert len(findings) == 8
    assert {f.resource for f in findings} == {
        "aws_security_group.secure",
        "aws_s3_bucket.secure",
    }
    assert {f.check_id for f in findings} == {
        "CKV_AWS_23",
        "CKV_AWS_382",
        "CKV_AWS_18",
        "CKV_AWS_144",
        "CKV_AWS_145",
        "CKV2_AWS_5",
        "CKV2_AWS_61",
        "CKV2_AWS_62",
    }
    assert all(f.severity is None for f in findings)


def test_checkov_parse_empty_and_malformed():
    empty = json.dumps([{"check_type": "terraform", "results": {"failed_checks": []}}])
    assert parse_checkov_report(empty) == []
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
    assert len(result.findings) == 24


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

    Executable resolution is stubbed out so that Windows `.cmd`-shim rewriting is
    bypassed. Without this the assertions would depend on whether checkov is
    installed next to the running interpreter: where it is, the argv is rewritten
    to `cmd.exe /d /c .../checkov.CMD`; where it is not, it is left alone. This
    test is about the argv the adapter *builds*, so resolution is disabled
    explicitly.
    """
    stdout = (FIX / "checkov/terraform_insecure.json").read_text()
    captured = {}
    # _locate_executable, not just shutil.which: the fallback also searches the
    # running interpreter's Scripts directory, and this repository's own venv has
    # checkov installed. Stubbing shutil.which alone would still resolve.
    monkeypatch.setattr(scanners_base, "_locate_executable", lambda name: None)

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
# Locating a tool installed in the environment XPRisk itself runs from
# --------------------------------------------------------------------------
#
# A pip console script is invisible unless PATH contains the environment's
# Scripts directory, which is only true after activation. Running a documented
# command such as `.\.venv\Scripts\python.exe -m pytest` uses the venv
# interpreter without touching PATH, and the Checkov adapter then reported
# UNAVAILABLE: 24 real findings became zero, with no error a presenter would
# notice. These tests pin the fallback.


@pytest.mark.skipif(os.name != "nt", reason="Windows script-directory layout")
def test_locate_executable_falls_back_to_the_running_interpreter(monkeypatch, tmp_path):
    monkeypatch.setattr(shutil, "which", lambda name: None)
    monkeypatch.setattr(sys, "executable", str(tmp_path / "python.exe"))
    (tmp_path / "checkov.cmd").write_text("@echo off\n", encoding="utf-8")

    assert _locate_executable("checkov") == str(tmp_path / "checkov.cmd")


@pytest.mark.skipif(os.name != "nt", reason="Windows script-directory layout")
def test_locate_executable_prefers_path_over_the_scripts_directory(monkeypatch, tmp_path):
    """A genuinely installed tool must win over the environment-local one."""

    monkeypatch.setattr(shutil, "which", lambda name: r"C:\tools\checkov.exe")
    monkeypatch.setattr(sys, "executable", str(tmp_path / "python.exe"))
    (tmp_path / "checkov.cmd").write_text("@echo off\n", encoding="utf-8")

    assert _locate_executable("checkov") == r"C:\tools\checkov.exe"


@pytest.mark.skipif(os.name != "nt", reason="Windows script-directory layout")
def test_locate_executable_still_reports_genuinely_absent_tools(monkeypatch, tmp_path):
    monkeypatch.setattr(shutil, "which", lambda name: None)
    monkeypatch.setattr(sys, "executable", str(tmp_path / "python.exe"))

    assert _locate_executable("definitely-not-installed-xyz") is None


@pytest.mark.skipif(os.name != "nt", reason="Windows script-directory layout")
def test_resolve_executable_routes_a_local_shim_through_comspec(monkeypatch, tmp_path):
    monkeypatch.setattr(shutil, "which", lambda name: None)
    monkeypatch.setattr(sys, "executable", str(tmp_path / "python.exe"))
    (tmp_path / "checkov.cmd").write_text("@echo off\n", encoding="utf-8")
    monkeypatch.setenv("COMSPEC", r"C:\WINDOWS\system32\cmd.exe")

    out = resolve_executable(["checkov", "-d", "iac", "-o", "json"])
    assert out[0].lower().endswith("cmd.exe")
    assert out[3] == str(tmp_path / "checkov.cmd")
    assert out[4:] == ["-d", "iac", "-o", "json"]


def test_shim_child_env_puts_the_shim_directory_first(monkeypatch):
    """The shim finds its own interpreter, not the system one.

    A pip `.cmd` shim locates python.exe by scanning PATH. Without this, a
    child inherits a PATH pointing at the system interpreter, the shim runs
    the wrong Python and exits with `ModuleNotFoundError: No module named
    'checkov'` -- which the adapter cannot distinguish from a missing tool.
    """

    monkeypatch.setattr(os, "name", "nt")
    monkeypatch.setenv("PATH", r"C:\Python312;C:\Windows\System32")
    argv = [r"C:\WINDOWS\system32\cmd.exe", "/d", "/c",
            r"C:\proj\.venv\Scripts\checkov.cmd", "--version"]

    env = _shim_child_env(argv)
    assert env is not None
    assert env["PATH"].split(os.pathsep)[0] == r"C:\proj\.venv\Scripts"
    assert r"C:\Python312" in env["PATH"]


def test_shim_child_env_is_not_applied_to_native_binaries():
    """gitleaks.exe and trivy.exe must inherit the environment untouched."""

    assert _shim_child_env(["gitleaks.exe", "dir", "."]) is None
    assert _shim_child_env(["C:\\tools\\trivy.exe", "image", "--input", "x.tar"]) is None


def test_run_command_passes_the_shim_environment(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: r"C:\proj\.venv\Scripts\checkov.CMD")
    monkeypatch.setenv("COMSPEC", r"C:\WINDOWS\system32\cmd.exe")
    captured = {}

    def fake_run(argv, **kwargs):
        captured["env"] = kwargs.get("env")
        return _completed(0, stdout="[]")

    monkeypatch.setattr(subprocess, "run", fake_run)
    run_command(["checkov", "--version"], timeout=5)

    assert captured["env"] is not None
    assert captured["env"]["PATH"].split(os.pathsep)[0] == r"C:\proj\.venv\Scripts"


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
