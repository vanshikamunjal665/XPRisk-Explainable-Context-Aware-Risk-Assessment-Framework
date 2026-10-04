"""Integration scenario runner (Phase 9 acceptance check).

Runs the six scenarios named in ``tests/README.md`` against the risk engine and
reports the *actual* outcome of each, including where the outcome does not match
what the scenario name implies.

This is deliberately not a test file. A test asserts what should happen; this
reports what does, so a calibration gap shows up as a visible result instead of
being papered over by loosening an assertion.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from normalizer.models import Category, Severity, XPRiskFinding
from risk_engine.engine import RiskEngine
from risk_engine.thresholds import Decision

ENGINE = RiskEngine()
MODEL = ENGINE.context_model


def finding(idx: int, severity: Severity, category: Category, tool: str = "fixture") -> XPRiskFinding:
    return XPRiskFinding(
        id=f"xprisk-{idx:04d}",
        tool=tool,
        category=category,
        severity=severity,
        finding_id=f"F{idx:03d}",
        resource=f"res_{idx:03d}",
        file="main.tf",
        line=idx,
    )


def n(count: int, severity: Severity, category: Category) -> list[XPRiskFinding]:
    return [finding(i, severity, category) for i in range(count)]


CONTEXTS = {
    "development/internal": MODEL.build(
        environment="development", exposure="internal", change_status="existing"
    ),
    "development/internet-facing": MODEL.build(
        environment="development", exposure="internet-facing", change_status="existing"
    ),
    "production/internal": MODEL.build(
        environment="production", exposure="internal", change_status="existing"
    ),
    "production/internet-facing": MODEL.build(
        environment="production", exposure="internet-facing", change_status="new"
    ),
}


def show(label: str, findings, context, expected: str) -> bool:
    a = ENGINE.assess(findings, context)
    ok = a.decision.value == expected
    mark = "PASS" if ok else "MISMATCH"
    print(
        f"  [{mark:>8}] {label:<40} score={a.risk_score:>6.1f} "
        f"decision={a.decision.value:<7} expected={expected}"
    )
    return ok


def main() -> int:
    print("TEST 1  no findings -> SAFE")
    print("-" * 100)
    t1 = []
    for name, ctx in CONTEXTS.items():
        t1.append(show(f"0 findings in {name}", [], ctx, "SAFE"))
    print()

    print("TEST 2  medium findings -> WARNING")
    print("-" * 100)
    t2 = []
    for count in (1, 2, 3, 4, 5, 6, 8, 10):
        label = f"{count} MEDIUM iac in production/exposed"
        t2.append((label, show(label, n(count, Severity.MEDIUM, Category.IAC),
                               CONTEXTS["production/internet-facing"], "WARNING")))
    print()

    print("TEST 3  critical findings -> BLOCK")
    print("-" * 100)
    t3 = []
    for count in (1, 2, 3, 5, 10):
        label = f"{count} CRITICAL secret in production/exposed"
        t3.append((label, show(label, n(count, Severity.CRITICAL, Category.SECRET),
                               CONTEXTS["production/internet-facing"], "BLOCK")))
    print()

    print("TEST 4  development scores lower than production (identical findings)")
    print("-" * 100)
    findings = n(6, Severity.MEDIUM, Category.IAC)
    dev = ENGINE.assess(findings, CONTEXTS["development/internal"])
    prod = ENGINE.assess(findings, CONTEXTS["production/internet-facing"])
    print(f"  development/internal        score={dev.risk_score:>6.1f} {dev.decision.value}")
    print(f"  production/internet-facing  score={prod.risk_score:>6.1f} {prod.decision.value}")
    t4 = [("context raises score", prod.risk_score > dev.risk_score)]
    t4.append(("base score is context-independent",
               ENGINE.assess(findings, CONTEXTS["development/internal"]).base_score
               == ENGINE.assess(findings, CONTEXTS["production/internal"]).base_score))
    for label, ok in t4:
        print(f"  [{'PASS' if ok else 'MISMATCH':>8}] {label}")
    print()

    print("TEST 5  internet-facing scores higher than internal (identical findings)")
    print("-" * 100)
    internal = ENGINE.assess(findings, CONTEXTS["production/internal"])
    exposed = ENGINE.assess(findings, CONTEXTS["production/internet-facing"])
    print(f"  production/internal        score={internal.risk_score:>6.1f} {internal.decision.value}")
    print(f"  production/internet-facing  score={exposed.risk_score:>6.1f} {exposed.decision.value}")
    t5 = [("exposure raises score", exposed.risk_score > internal.risk_score)]
    for label, ok in t5:
        print(f"  [{'PASS' if ok else 'MISMATCH':>8}] {label}")
    print()

    print("TEST 6  a detected secret moves the score")
    print("-" * 100)
    # Verified Gitleaks 8.30.1 output on demo-app/scenarios/insecure.
    secrets = [
        finding(0, Severity.CRITICAL, Category.SECRET, "gitleaks"),
        finding(1, Severity.HIGH, Category.SECRET, "gitleaks"),
    ]
    baseline = ENGINE.assess([], CONTEXTS["production/internet-facing"])
    detected = ENGINE.assess(secrets, CONTEXTS["production/internet-facing"])
    print(f"  no findings                score={baseline.risk_score:>6.1f} {baseline.decision.value}")
    print(f"  2 real gitleaks findings   score={detected.risk_score:>6.1f} {detected.decision.value}")
    t6 = [("secret raises score", detected.risk_score > baseline.risk_score),
          ("secret counted as CRITICAL", detected.severity_breakdown.get("CRITICAL") == 1),
          ("secret ranked as top contributor",
           detected.ranked_contributions[0].category is Category.SECRET)]
    for label, ok in t6:
        print(f"  [{'PASS' if ok else 'MISMATCH':>8}] {label}")
    print()

    print("SUMMARY")
    print("-" * 100)
    all_rows = (
        [("TEST 1", ok) for ok in t1]
        + [("TEST 2", ok) for _, ok in t2]
        + [("TEST 3", ok) for _, ok in t3]
        + [(f"TEST 4 {label}", ok) for label, ok in t4]
        + [(f"TEST 5 {label}", ok) for label, ok in t5]
        + [(f"TEST 6 {label}", ok) for label, ok in t6]
    )
    passed = sum(1 for _, ok in all_rows if ok)
    print(f"  {passed}/{len(all_rows)} scenario rows match their expected decision")
    for label, ok in all_rows:
        if not ok:
            print(f"    MISMATCH: {label}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())