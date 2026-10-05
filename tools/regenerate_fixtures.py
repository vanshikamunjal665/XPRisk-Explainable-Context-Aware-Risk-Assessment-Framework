"""Regenerate Checkov fixtures from a real Checkov run.

Why this exists
---------------
The dashboard's original ``fixtures/checkov/*.json`` files were hand-written, and
they carried ``"severity": "HIGH"`` on every check. That is **not** what Checkov
produces. Verified against Checkov 3.3.22: every Terraform resource check
reports ``severity: null``. A fabricated severity in a fixture is worse than no
fixture, because it makes the normalization layer look like it consumes severity
information that the tool never provides.

This script takes genuine Checkov JSON and writes a fixture that:

* keeps every field the scanner adapter actually reads, verbatim;
* drops ``passed_checks`` and the verbose ``evaluation_details`` blocks, which
  the adapter never reads and which would triple the file size;
* records where the data came from, so a reader can never mistake it for
  hand-authored data.

Nothing is invented. Every ``check_id``, ``check_name``, ``resource``,
``file_path`` and ``file_line_range`` is exactly what Checkov emitted. The
``severity`` key is preserved exactly too, which means it stays ``null`` and the
normalizer's documented MEDIUM fallback applies as it does in production.

Two fields are dropped that a reader might expect to see:

``file_abs_path``
    An absolute path into the machine that ran the scan. Keeping it would make
    the fixture non-portable and would commit a developer's home directory. The
    adapter reads the relative ``file_path``.
``evaluation_details``
    A per-key diff that no adapter reads, and the bulk of the 204 kB report.

Usage
-----
    checkov -d infrastructure/scenarios/insecure -o json --framework terraform --quiet > raw.json
    python tools/regenerate_fixtures.py raw.json fixtures/checkov/terraform_insecure.json

Run from the repository root. PowerShell's ``>`` writes UTF-16, which this script
detects and decodes, so the command above works as written.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

#: Fields the Checkov adapter reads. Everything else is dropped.
KEPT_CHECK_FIELDS = (
    "check_id",
    "check_name",
    "bc_check_id",
    "check_result",
    "resource",
    "file_path",
    "file_line_range",
    "severity",  # preserved verbatim, including null
)

#: Fields of the inner ``check`` object the adapter reads.
KEPT_CHECK_META_FIELDS = ("id", "name", "category")


def slim_check(check: dict) -> dict:
    """Keep only the fields the adapter reads, dropping evaluation noise."""

    kept = {key: check[key] for key in KEPT_CHECK_FIELDS if key in check}

    meta = check.get("check")
    if isinstance(meta, dict):
        kept["check"] = {k: meta[k] for k in KEPT_CHECK_META_FIELDS if k in meta}

    return kept


def slim_report(raw: list[dict] | dict) -> list[dict]:
    """Slim a Checkov JSON report to the failed checks the adapter parses."""

    if isinstance(raw, dict):
        raw = [raw]

    reports = []
    for item in raw:
        results = item.get("results") or {}
        reports.append(
            {
                "check_type": item.get("check_type"),
                "results": {
                    "failed_checks": [
                        slim_check(c) for c in (results.get("failed_checks") or [])
                    ],
                },
            }
        )
    return reports


def annotate(reports: list[dict], source: str) -> list[dict]:
    """Add provenance so the fixture can never read as hand-authored data."""

    for report in reports:
        report["_xprisk_fixture"] = {
            "data_origin": "REAL_CHECKOV_OUTPUT",
            "tool_version": source,
            "note": (
                "Verbatim Checkov output, trimmed to the fields "
                "scanners/checkov_scanner.py reads. Severity is null because "
                "Checkov does not report severity for Terraform resource "
                "checks; see docs/risk-model.md section 7.3."
            ),
        }
    return reports


def read_json_text(path: Path) -> str:
    """Read a JSON file, tolerating PowerShell's UTF-16 redirection.

    ``> file.json`` in Windows PowerShell writes UTF-16 with a BOM, which is not
    valid UTF-8. Capturing Checkov output that way is the normal case here, so
    this is handled rather than left as a trap.
    """

    blob = path.read_bytes()
    if blob[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return blob.decode("utf-16")
    if blob[:3] == b"\xef\xbb\xbf":
        return blob.decode("utf-8-sig")
    return blob.decode("utf-8")


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__)
        print("usage: regenerate_fixtures.py <raw-checkov.json> <target-fixture.json>")
        return 2

    raw_path = Path(argv[1])
    target = Path(argv[2])

    raw = json.loads(read_json_text(raw_path))
    reports = annotate(slim_report(raw), "checkov 3.3.22")

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(reports, indent=2) + "\n", encoding="utf-8")

    count = sum(len(r["results"]["failed_checks"]) for r in reports)
    severities = {
        str(c.get("severity"))
        for r in reports
        for c in r["results"]["failed_checks"]
    }
    print(f"Wrote {target} with {count} failed checks")
    print(f"severity values present: {sorted(severities)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))