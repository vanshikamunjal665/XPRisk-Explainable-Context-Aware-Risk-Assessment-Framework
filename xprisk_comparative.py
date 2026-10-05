"""Comparative study harness (methodology Step 4).

Scores the same finding sets under three policies, so the report can show what
each layer of the model actually contributes rather than asserting it.

    S  severity only            no category, no context
    C  severity + category      count-driven, context-neutral
    X  C + context              the full XPRisk model

Run from the repository root with ``python xprisk_comparative.py``.
"""

from __future__ import annotations

import json
import sys
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from normalizer.models import Category, Severity, XPRiskFinding
from risk_engine.engine import RiskEngine
from risk_engine.settings import DEFAULT_RISK_SETTINGS, RiskSettings

ENGINE_PROTOTYPE = RiskEngine()
MODEL = ENGINE_PROTOTYPE.context_model

DEV = MODEL.build(environment="development", exposure="internal", change_status="existing")
STAGING = MODEL.build(environment="staging", exposure="internal", change_status="existing")
PROD_INTERNAL = MODEL.build(environment="production", exposure="internal", change_status="existing")
PROD_EXPOSED = MODEL.build(environment="production", exposure="internet-facing", change_status="new")

#: Severity-only baseline: strip the category amplification.
SEVERITY_ONLY = replace(
    DEFAULT_RISK_SETTINGS,
    category_multipliers={category: 1.0 for category in Category},
)

POLICIES = {
    "S (severity only)": RiskEngine(SEVERITY_ONLY),
    "C (severity + category)": RiskEngine(DEFAULT_RISK_SETTINGS),
    "X (context-aware)": RiskEngine(DEFAULT_RISK_SETTINGS),
}


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


def finding_sets() -> dict[str, list[XPRiskFinding]]:
    """The finding sets the comparative report is built from.

    Counts and severities are taken from verified scanner runs so the comparison
    reflects real scanner output rather than invented numbers.

    The container sets reproduce the severity breakdown of the two real Trivy
    0.75.0 scans exactly, including Trivy's ``UNKNOWN`` band. ``UNKNOWN`` is
    carried as XPRisk ``INFO`` because that is what
    ``normalizer.normalize_trivy`` maps it to, so the sizes here match the sizes
    of the committed fixtures:

    ==============================  ======  =====  =====  =====  ====  =====
    Image                          CRITICAL  HIGH  MEDIUM  LOW  INFO  Total
    ==============================  ======  =====  =====  =====  ====  =====
    xprisk-vulnerable:demo              31    174     257   179    10    651
    xprisk-clean:demo                     5     58     118   101     1    283
    ==============================  ======  =====  =====  =====  ====  =====

    An earlier version of this function labelled these sets "651" and "283" while
    building 641 and 341 findings from them. Every container score saturates at
    100.0 either way, so the error was invisible in the output while the labels
    overstated what had been measured.
    """

    def n(count: int, severity: Severity, category: Category) -> list[XPRiskFinding]:
        return [finding(i, severity, category) for i in range(count)]

    return {
        # Gitleaks 8.30.1 on demo-app/scenarios/insecure -> 2 findings.
        "2 real secret findings": [
            finding(0, Severity.CRITICAL, Category.SECRET, "gitleaks"),
            finding(1, Severity.HIGH, Category.SECRET, "gitleaks"),
        ],
        # The threshold-relevant cases.
        "1 CRITICAL secret": n(1, Severity.CRITICAL, Category.SECRET),
        "5 MEDIUM iac": n(5, Severity.MEDIUM, Category.IAC),
        # Checkov 3.3.22 verified counts. Severity is MEDIUM for all of them
        # because Checkov reports none; see docs/risk-model.md section 7.3.
        "8 MEDIUM iac (clean)": n(8, Severity.MEDIUM, Category.IAC),
        "24 MEDIUM iac (insecure)": n(24, Severity.MEDIUM, Category.IAC),
        # xprisk-vulnerable:demo: 31 + 174 + 257 + 179 + 10 = 651.
        "651 CRIT/HIGH/MED/LOW container": (
            n(31, Severity.CRITICAL, Category.CONTAINER)
            + n(174, Severity.HIGH, Category.CONTAINER)
            + n(257, Severity.MEDIUM, Category.CONTAINER)
            + n(179, Severity.LOW, Category.CONTAINER)
            + n(10, Severity.INFO, Category.CONTAINER)
        ),
        # xprisk-clean:demo: 5 + 58 + 118 + 101 + 1 = 283.
        "283 CRIT/HIGH/MED/LOW container": (
            n(5, Severity.CRITICAL, Category.CONTAINER)
            + n(58, Severity.HIGH, Category.CONTAINER)
            + n(118, Severity.MEDIUM, Category.CONTAINER)
            + n(101, Severity.LOW, Category.CONTAINER)
            + n(1, Severity.INFO, Category.CONTAINER)
        ),
        # A critical finding alongside substantial background noise.
        "1 CRIT secret + 24 MEDIUM iac": (
            [finding(900, Severity.CRITICAL, Category.SECRET)]
            + n(24, Severity.MEDIUM, Category.IAC)
        ),
    }


def main() -> int:
    rows = []
    for name, findings in finding_sets().items():
        for policy_label, engine in POLICIES.items():
            for context_label, context in (
                ("development/internal", DEV),
                ("staging/internal", STAGING),
                ("production/internal", PROD_INTERNAL),
                ("production/internet-facing", PROD_EXPOSED),
            ):
                assessment = engine.assess(findings, context)
                rows.append(
                    {
                        "finding_set": name,
                        "policy": policy_label,
                        "context": context_label,
                        "risk_score": assessment.risk_score,
                        "decision": assessment.decision.value,
                    }
                )

    print(f"{'finding set':<32} {'policy':<26} {'context':<26} {'score':>7}  decision")
    print("-" * 104)
    for row in rows:
        print(
            f"{row['finding_set']:<32} {row['policy']:<26} {row['context']:<26} "
            f"{row['risk_score']:>7.1f}  {row['decision']}"
        )

    print()
    print("Discrimination check: does each policy separate insecure from clean?")
    print("-" * 104)
    for policy_label in POLICIES:
        for context_label, context in (
            ("development/internal", DEV),
            ("production/internet-facing", PROD_EXPOSED),
        ):
            insecure = next(
                r["risk_score"]
                for r in rows
                if r["finding_set"] == "24 MEDIUM iac (insecure)"
                and r["policy"] == policy_label
                and r["context"] == context_label
            )
            clean = next(
                r["risk_score"]
                for r in rows
                if r["finding_set"] == "8 MEDIUM iac (clean)"
                and r["policy"] == policy_label
                and r["context"] == context_label
            )
            ratio = insecure / clean if clean else float("inf")
            print(
                f"  {policy_label:<26} {context_label:<26} "
                f"insecure={insecure:>6.1f}  clean={clean:>6.1f}  ratio={ratio:>5.2f}x"
            )

    output = Path("reports/comparative_study_results.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
    print()
    print(f"Wrote {len(rows)} rows to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())