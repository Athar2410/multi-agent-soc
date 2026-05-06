import streamlit as st
from hitl.queue_manager import get_pending_alerts, get_all_alerts, update_decision
from hitl.auto_response import run_auto_response
from metrics import (
    compute_kpis, get_attack_type_distribution,
    get_severity_distribution, get_hourly_volume,
    get_analyst_leaderboard
)

st.set_page_config(page_title="SOC Dashboard", page_icon="🛡️", layout="wide")
st.title("🛡️ Multi-Agent SOC — Analyst Dashboard")

analyst = st.sidebar.text_input("👤 Analyst Name", value="analyst1")
page = st.sidebar.radio("View", [
    "🔴 Pending Approvals",
    "📋 All Alerts",
    "📊 Metrics"
])

# ── Pending Approvals ─────────────────────────────────────────────────────────
if page == "🔴 Pending Approvals":
    if st.button("🔄 Refresh"):
        st.rerun()
    pending = get_pending_alerts()
    st.header(f"🔴 Pending Approvals ({len(pending)})")

    if not pending:
        st.success("✅ No pending alerts — queue is clear.")
    else:
        for alert in pending:
            severity_color = "🔴" if alert["severity"] >= 8 else "🟡"
            with st.expander(
                f"{severity_color} [{alert['severity']}/10] {alert['attack_type'].upper()} | "
                f"IP: {alert['source_ip']} | {alert['created_at'][:19]}"
            ):
                col1, col2 = st.columns([3, 1])
                with col1:
                    st.markdown("**Alert:**")
                    st.info(alert["alert_text"])
                    st.markdown("**Incident Report:**")
                    st.markdown(alert["report"])
                with col2:
                    st.markdown("**Actions:**")
                    if st.button("✅ Approve & Block IP", key=f"approve_{alert['id']}"):
                        if not analyst:
                            st.error("Enter analyst name first!")
                        else:
                            response = run_auto_response(
                                alert["id"], alert["source_ip"],
                                alert["attack_type"], alert["severity"], analyst
                            )
                            update_decision(alert["id"], "approved", analyst)
                            st.success(response)
                            st.rerun()
                    if st.button("❌ Reject (False Positive)", key=f"reject_{alert['id']}"):
                        if not analyst:
                            st.error("Enter analyst name first!")
                        else:
                            update_decision(alert["id"], "rejected", analyst)
                            st.warning(f"Alert #{alert['id']} marked as false positive.")
                            st.rerun()
                    if st.button("🔼 Escalate", key=f"escalate_{alert['id']}"):
                        update_decision(alert["id"], "escalated", analyst)
                        st.info(f"Alert #{alert['id']} escalated.")
                        st.rerun()

# ── All Alerts History ────────────────────────────────────────────────────────
elif page == "📋 All Alerts":
    if st.button("🔄 Refresh"):
        st.rerun()
    all_alerts = get_all_alerts()
    st.header(f"📋 Alert History ({len(all_alerts)} total)")
    status_icons = {"pending": "🔴", "approved": "✅", "rejected": "❌", "escalated": "🔼"}
    for alert in all_alerts:
        icon = status_icons.get(alert["status"], "⚪")
        with st.expander(
            f"{icon} [{alert['status'].upper()}] [{alert['severity']}/10] "
            f"{alert['attack_type']} | {alert['source_ip']} | {alert['created_at'][:19]}"
        ):
            st.markdown(f"**Analyst:** {alert['analyst'] or 'Unassigned'}")
            st.markdown(f"**Decision Time:** {alert['decision_at'] or 'Pending'}")
            st.markdown(alert["report"])

# ── Metrics Tab ───────────────────────────────────────────────────────────────
elif page == "📊 Metrics":
    if st.button("🔄 Refresh"):
        st.rerun()
    st.header("📊 SOC Metrics")

    kpis = compute_kpis()

    # ── KPI Cards ─────────────────────────────────────────────────────────
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("📥 Total Alerts",   kpis["total"])
    c2.metric("🔴 Pending",        kpis["pending"])
    c3.metric("✅ Approved",        kpis["approved"])
    c4.metric("❌ Rejected (FP)",   kpis["rejected"])
    c5.metric("🔼 Escalated",       kpis["escalated"])

    st.divider()

    col1, col2 = st.columns(2)

    # ── Attack Type Distribution ──────────────────────────────────────────
    with col1:
        st.subheader("🎯 Attack Types")
        atk = get_attack_type_distribution()
        if atk:
            st.bar_chart(atk)
        else:
            st.info("No data yet.")

    # ── Severity Distribution ─────────────────────────────────────────────
    with col2:
        st.subheader("⚠️ Severity Buckets")
        sev = get_severity_distribution()
        st.bar_chart(sev)

    st.divider()

    # ── Alert Volume Over Time ────────────────────────────────────────────
    st.subheader("📈 Alert Volume Over Time")
    hourly = get_hourly_volume()
    if hourly:
        st.line_chart(hourly)
    else:
        st.info("No data yet.")

    st.divider()

    # ── Stats Row ─────────────────────────────────────────────────────────
    col3, col4, col5 = st.columns(3)
    with col3:
        st.metric("⏱️ Avg Response Time",
                  f"{kpis['mttr']} min" if kpis['mttr'] else "N/A")
    with col4:
        st.metric("🎯 Approval Rate", f"{kpis['apr_rate']}%")
    with col5:
        st.metric("🚫 False Positive Rate", f"{kpis['fp_rate']}%")

    # ── Analyst Leaderboard ───────────────────────────────────────────────
    st.divider()
    st.subheader("👤 Analyst Activity")
    leaderboard = get_analyst_leaderboard()
    if leaderboard:
        st.bar_chart(leaderboard)
    else:
        st.info("No analyst decisions recorded yet.")