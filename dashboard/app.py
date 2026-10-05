"""XPRisk Streamlit dashboard.

Run with:

    python -m streamlit run dashboard/app.py

Architecture: the dashboard never scores, never thresholds and never
explains on its own. It renders what the existing risk engine, explainability
package and storage service produce.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pandas as pd  # noqa: E402
import plotly.express as px  # noqa: E402
import streamlit as st  # noqa: E402

from dashboard.service import FIXTURE_PRESETS, DashboardData  # noqa: E402
from dashboard.transforms import (  # noqa: E402
    SEVERITY_ORDER,
    contributions_table,
    context_contributors_table,
    filter_findings,
    filter_history,
    findings_table,
    group_counts,
    history_table,
    risk_factors_table,
    severity_counts,
)

DECISION_COLORS = {"SAFE": "green", "WARNING": "orange", "BLOCK": "red"}


def _severity_chart(rows: list[dict]):
    counts = severity_counts(rows)
    data = pd.DataFrame(
        {"severity": [s for s in SEVERITY_ORDER if counts.get(s, 0) > 0],
         "count": [counts[s] for s in SEVERITY_ORDER if counts.get(s, 0) > 0]}
    )
    if data.empty:
        st.info("No findings to chart.")
        return
    st.plotly_chart(px.bar(data, x="severity", y="count", title="Findings by severity"),
                    width='stretch')


def _tool_chart(rows: list[dict]):
    counts = group_counts(rows, "tool")
    if not counts:
        st.info("No findings to chart.")
        return
    data = pd.DataFrame({"tool": list(counts), "count": list(counts.values())})
    st.plotly_chart(px.pie(data, names="tool", values="count", title="Findings by scanner"),
                    width='stretch')


def _contribution_chart(rows: list[dict]):
    if not rows:
        st.info("No risk contributions recorded.")
        return
    data = pd.DataFrame(rows)
    st.plotly_chart(
        px.bar(data, x="finding", y="raw_risk", color="severity",
               title="Contribution to raw risk (engine values)"),
        width='stretch',
    )


def _render_findings(rows: list[dict], key_prefix: str):
    st.subheader("Findings")
    counts = severity_counts(rows)
    cols = st.columns(5)
    for col, sev in zip(cols, SEVERITY_ORDER):
        col.metric(sev, counts.get(sev, 0))

    tools = sorted({r.get("tool") for r in rows if r.get("tool")})
    categories = sorted({r.get("category") for r in rows if r.get("category")})
    severities = [s for s in SEVERITY_ORDER if any(r.get("severity") == s for r in rows)]

    f1, f2, f3 = st.columns(3)
    sel_sev = f1.multiselect("Severity", severities, default=severities, key=f"{key_prefix}_sev")
    sel_tool = f2.multiselect("Tool", tools, default=tools, key=f"{key_prefix}_tool")
    sel_cat = f3.multiselect("Category", categories, default=categories, key=f"{key_prefix}_cat")

    filtered = filter_findings(rows, severities=sel_sev, tools=sel_tool, categories=sel_cat)
    st.caption(f"{len(filtered)} of {len(rows)} findings shown")
    st.dataframe(pd.DataFrame(filtered), width='stretch', hide_index=True)

    c1, c2 = st.columns(2)
    with c1:
        _severity_chart(filtered)
    with c2:
        _tool_chart(filtered)


def _render_assessment(bundle) -> None:
    assessment = bundle.assessment
    explanation = bundle.explanation

    st.header("Risk summary")
    c1, c2, c3 = st.columns(3)
    c1.metric("Risk score", f"{bundle.risk_score:.1f} / 100")
    c2.metric("Decision", bundle.decision)
    c3.metric("Findings", bundle.finding_count)
    st.caption(explanation.headline)

    if bundle.total_raw > 100.0:
        st.warning(
            f"Score saturation: the raw contribution is {bundle.total_raw:.0f}, so the "
            f"base score is pinned at 100 before the context multiplier is applied. "
            f"Context cannot move a score that is already at the ceiling, so this "
            f"scenario reads {bundle.decision} in every context. This is a measured "
            f"limitation of the model, not a bug — see docs/risk-model.md section 7.5."
        )

    # Decision section
    st.subheader("Decision")
    color = DECISION_COLORS.get(bundle.decision, "gray")
    st.markdown(f":{color}[**{bundle.decision}**]")
    edges = assessment.distance_to_edges()
    st.caption(
        f"Thresholds: SAFE < {assessment.thresholds.safe:g}, "
        f"WARNING < {assessment.thresholds.warning:g}. "
        f"Distance to edges: {edges}"
    )

    # Deployment context
    st.subheader("Deployment context")
    ctx = bundle.context
    ctx_cols = st.columns(4 if len(ctx) >= 4 else len(ctx) or 1)
    labels = {"environment": "Environment", "exposure": "Exposure",
              "change_status": "Change status", "resource_category": "Resource category"}
    for col, key in zip(ctx_cols, ctx.keys()):
        col.metric(labels.get(key, key), str(ctx[key]))

    # Findings
    _render_findings(findings_table(bundle.findings), key_prefix="assessment")

    # Risk contributions
    st.subheader("Risk contributions")
    contribs = contributions_table(assessment)
    st.dataframe(pd.DataFrame(contribs), width='stretch', hide_index=True)
    _contribution_chart(contribs)

    st.subheader("Context factors")
    st.dataframe(pd.DataFrame(context_contributors_table(explanation)),
                 width='stretch', hide_index=True)

    # Explanation
    st.subheader("Explanation")
    st.write(explanation.summary)
    with st.expander("Derivation (how the score was produced)"):
        st.dataframe(pd.DataFrame([d.to_dict() for d in explanation.derivation]),
                     width='stretch', hide_index=True)

    # Recommendations
    st.subheader("Recommendations")
    rec = bundle.recommendation
    st.write(f"**Action:** {rec.action}")
    st.write(rec.rationale)
    if rec.context_note:
        st.caption(rec.context_note)
    if rec.findings_to_fix:
        st.dataframe(pd.DataFrame([f.to_dict() for f in rec.findings_to_fix]),
                     width='stretch', hide_index=True)
    elif rec.target_decision is None:
        st.success("No remediation required by the model.")


def _render_history(data: DashboardData) -> None:
    st.header("Deployment history")
    try:
        deployments = data.list_deployments()
    except Exception:
        st.error("Unable to load assessment data (database unavailable).")
        return

    rows = history_table(deployments)
    if not rows:
        st.info(
            "No stored deployments yet. This is not a failure to load — the "
            "history is genuinely empty."
        )
        st.caption(
            "This view reads the deployments table, and nothing has written to it "
            "yet. Assessments run in the *Assessment* view are computed and shown "
            "but not stored. To populate it, call `POST /scan` once "
            "(README section 17) or run `ScanService.assess` from a script — "
            "`backend/app/services/scan_service.py` is what writes the deployment, "
            "its findings and every contribution. It was previously unreachable, "
            "which is why this view used to be empty permanently; see README "
            "section 5.1."
        )
        return

    f1, f2, f3 = st.columns(3)
    envs = sorted({r["environment"] for r in rows})
    decs = sorted({r["decision"] for r in rows if r["decision"]})
    branches = sorted({r["branch"] for r in rows})
    sel_env = f1.multiselect("Environment", envs, default=envs, key="hist_env")
    sel_dec = f2.multiselect("Decision", decs, default=decs, key="hist_dec")
    sel_br = f3.multiselect("Branch", branches, default=branches, key="hist_br")

    filtered = filter_history(rows, environments=sel_env, decisions=sel_dec, branches=sel_br)
    st.dataframe(pd.DataFrame(filtered), width='stretch', hide_index=True)

    scored = [r for r in filtered if r["risk_score"] is not None]
    if scored:
        trend = pd.DataFrame(
            {"timestamp": [r["timestamp"] for r in scored],
             "risk_score": [r["risk_score"] for r in scored]}
        ).sort_values("timestamp")
        st.plotly_chart(px.line(trend, x="timestamp", y="risk_score",
                                title="Historical risk score trend", markers=True),
                        width='stretch')

    labels = {f"#{r['id']} {r['branch']} ({r['environment']})": r["id"] for r in filtered}
    choice = st.selectbox("Inspect deployment", ["— select —", *labels.keys()])
    if choice in labels:
        try:
            details = data.deployment_details(labels[choice])
        except Exception:
            st.error("Unable to load deployment details.")
            return
        if details is None:
            st.warning("Deployment not found.")
            return
        dep = details["deployment"]
        c1, c2, c3 = st.columns(3)
        c1.metric("Risk score", f"{dep.risk_score if dep.risk_score is not None else '—'}")
        c2.metric("Decision", dep.decision or "—")
        c3.metric("Environment", dep.environment)
        st.caption(
            f"Exposure: {'internet-facing' if dep.internet_exposed else 'internal'} · "
            f"Commit: {dep.commit_id or '—'} · Timestamp: {dep.timestamp}"
        )
        _render_findings(findings_table(details["findings"]), key_prefix="history")
        st.subheader("Stored risk factors")
        factors = risk_factors_table(details["risk_factors"])
        if factors:
            st.dataframe(pd.DataFrame(factors), width='stretch', hide_index=True)
        else:
            st.info("No stored risk factors for this deployment.")


def main() -> None:
    st.set_page_config(page_title="XPRisk Dashboard", layout="wide")
    st.title("XPRisk")
    st.caption("Explainable Context-Aware Risk Assessment Framework — dashboard")
    st.write(
        "This dashboard visualises XPRisk assessment results: findings, risk score, "
        "decision, deployment context, risk contributions, explanations and remediation "
        "recommendations produced by the existing XPRisk engine."
    )

    try:
        data = DashboardData()
    except Exception:
        st.error("Unable to load assessment data. Is the XPRisk database reachable?")
        return

    mode = st.sidebar.radio("View", ["Assessment", "Deployment history"])

    if mode == "Deployment history":
        _render_history(data)
        return

    st.sidebar.subheader("Assessment setup")
    preset = st.sidebar.selectbox("Fixture scenario", list(FIXTURE_PRESETS))
    environment = st.sidebar.selectbox("Environment", ["development", "staging", "production"],
                                       index=2)
    exposure = st.sidebar.selectbox("Exposure", ["internal", "internet-facing"], index=1)
    change_status = st.sidebar.selectbox("Change status", ["new", "existing"], index=0)

    if st.sidebar.button("Run assessment"):
        try:
            findings = data.load_fixture_findings(preset)
        except Exception as exc:  # noqa: BLE001
            st.error(f"Unable to load assessment data: {exc}")
            return
        st.info(FIXTURE_PRESETS[preset].note)
        if not findings:
            st.success("Assessment produced no findings — deployment looks clean.")
        try:
            bundle = data.run_assessment(
                findings,
                environment=environment,
                exposure=exposure,
                change_status=change_status,
            )
        except Exception as exc:  # noqa: BLE001
            st.error(f"Risk engine produced a malformed/empty result: {exc}")
            return
        _render_assessment(bundle)
    else:
        st.info("Choose a fixture scenario and context in the sidebar, then run the assessment.")


main()
