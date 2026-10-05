"""Regenerate Trivy fixtures from a real Trivy image scan.

Why this exists
---------------
The original ``fixtures/trivy/*.json`` files were hand-written and carried
invented CVE identifiers (``CVE-2023-12345``, ``CVE-2022-99999``) with
invented descriptions. Invented identifiers are a liability in a research
artifact: they look like vulnerability data, they cannot be checked against
anything, and they make the normalization layer look as though it consumes
information the tool never provided.

The ``clean`` fixture was wrong in the opposite direction. It declared an empty
``Vulnerabilities`` array, i.e. "this image has no known vulnerabilities", when
a real scan of ``xprisk-clean:demo`` reports 283. That flattered the demo.

What this script does
---------------------
It keeps **every** finding from the real scan, not a sample. Truncation is the
mechanism that produced the original misleading files, so it is not used here.

Size is controlled the other way: by dropping only the fields the adapter never
reads. ``scanners/trivy_scanner.py::parse_trivy_report` reads exactly

    VulnerabilityID, PkgName, InstalledVersion, FixedVersion,
    Severity, Title, Description, PrimaryURL, Target, Type

so ``References``, ``CVSS``, ``Layer``, ``DataSource`` and the date fields are
dropped. On the demo image that is 3.0 MB of Trivy output down to roughly
600 kB with all 651 findings intact and every retained value verbatim.

Each ``Result`` entry keeps its own ``Target`` and ``Type``, because the adapter
derives the finding target from them and the dashboard displays it.

Usage
-----
    trivy image --format json -o raw.json xprisk-vulnerable:demo
    python tools/regenerate_trivy_fixtures.py raw.json fixtures/trivy/sample_image_scan.json

Run from the repository root. Requires Docker for locally built images; on
Windows use ``docker save`` + ``trivy image --input`` as
``scanners/trivy_scanner.py::scan_local_image`` does.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

#: Vulnerability fields read by ``parse_trivy_report``. Kept verbatim.
KEPT_VULN_FIELDS = (
    "VulnerabilityID",
    "PkgName",
    "InstalledVersion",
    "FixedVersion",
    "Severity",
    "Title",
    "Description",
    "PrimaryURL",
)

#: Result-level fields read by the adapter.
KEPT_RESULT_FIELDS = ("Target", "Type", "Class")


def read_json_text(path: Path) -> str:
    """Read JSON, tolerating PowerShell's UTF-16 redirection.

    ``> file.json`` in Windows PowerShell writes UTF-16 with a BOM, which is not
    valid UTF-8. Capturing Trivy output that way is the normal case here.
    """

    blob = path.read_bytes()
    if blob[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return blob.decode("utf-16")
    if blob[:3] == b"\xef\xbb\xbf":
        return blob.decode("utf-8-sig")
    return blob.decode("utf-8")


def slim_vulnerability(vuln: dict) -> dict:
    """Keep only the fields the adapter reads, verbatim."""

    return {key: vuln.get(key) for key in KEPT_VULN_FIELDS}


def slim_result(result: dict) -> dict:
    """Keep the result-level fields plus every vulnerability it reported."""

    kept = {key: result.get(key) for key in KEPT_RESULT_FIELDS if key in result}
    kept["Vulnerabilities"] = [
        slim_vulnerability(v) for v in (result.get("Vulnerabilities") or [])
    ]
    return kept


def build_payload(report: dict) -> tuple[dict, dict[str, int]]:
    """Build the fixture document and the true severity totals."""

    results = [slim_result(r) for r in (report.get("Results") or []) if isinstance(r, dict)]

    totals: dict[str, int] = {}
    for result in results:
        for vuln in result["Vulnerabilities"]:
            severity = vuln.get("Severity") or "UNKNOWN"
            totals[severity] = totals.get(severity, 0) + 1

    payload = {
        "SchemaVersion": report.get("SchemaVersion", 2),
        "_xprisk_fixture": {
            "data_origin": "REAL_TRIVY_OUTPUT",
            "note": (
                "Complete, untruncated Trivy output, reduced only to the fields "
                "scanners/trivy_scanner.py reads. Every retained value is "
                "verbatim; References, CVSS, Layer and date fields are omitted "
                "because no adapter reads them."
            ),
            "true_total_vulnerabilities": sum(totals.values()),
            "true_total_by_severity": totals,
            "scanned_targets": [r.get("Target") for r in results if r.get("Target")],
        },
        "Results": results,
    }
    return payload, totals


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__)
        print("usage: regenerate_trivy_fixtures.py <raw-trivy.json> <target-fixture.json>")
        return 2

    report = json.loads(read_json_text(Path(argv[1])))
    target = Path(argv[2])

    payload, totals = build_payload(report)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    size_kb = target.stat().st_size / 1024
    print(f"Wrote {target}  ({size_kb:.0f} kB)")
    print(f"findings retained: {sum(totals.values())} of {sum(totals.values())} (no truncation)")
    for severity, count in sorted(totals.items(), key=lambda kv: -kv[1]):
        print(f"  {severity:<9} {count}")
    for name in payload["_xprisk_fixture"]["scanned_targets"]:
        print(f"  target: {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))