import streamlit as st
from hitl.queue_manager import get_pending_alerts, get_all_alerts, update_decision
from hitl.auto_response import run_auto_response

st.set_page_config(page_title="SOC Dashboard", page_icon="🛡️", layout="wide")
# Auto-refresh every 10 seconds
from streamlit_autorefresh import st_autorefresh
count = st_autorefresh(interval=10000, key="dashboard_refresh")
st.title("🛡️ Multi-Agent SOC — Analyst Dashboard")

analyst = st.sidebar.text_input("👤 Analyst Name", value="analyst1")
page = st.sidebar.radio("View", ["🔴 Pending Approvals", "📋 All Alerts"])

if page == "🔴 Pending Approvals":
    if st.button("🔄 Refresh"):
        st.rerun()
    pending = get_pending_alerts()

# ── Pending Approvals ─────────────────────────────────────────────────────────
if page == "🔴 Pending Approvals":
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
                    if st.button(f"✅ Approve & Block IP", key=f"approve_{alert['id']}"):
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

                    if st.button(f"❌ Reject (False Positive)", key=f"reject_{alert['id']}"):
                        if not analyst:
                            st.error("Enter analyst name first!")
                        else:
                            update_decision(alert["id"], "rejected", analyst)
                            st.warning(f"Alert #{alert['id']} marked as false positive by {analyst}")
                            st.rerun()

                    if st.button(f"🔍 Escalate", key=f"escalate_{alert['id']}"):
                        update_decision(alert["id"], "escalated", analyst)
                        st.info(f"Alert #{alert['id']} escalated for senior review.")
                        st.rerun()

# ── All Alerts History ────────────────────────────────────────────────────────
elif page == "📋 All Alerts":
    all_alerts = get_all_alerts()
    st.header(f"📋 Alert History ({len(all_alerts)} total)")

    status_colors = {
        "pending":   "🔴",
        "approved":  "✅",
        "rejected":  "❌",
        "escalated": "🔼"
    }

    for alert in all_alerts:
        icon = status_colors.get(alert["status"], "⚪")
        with st.expander(
            f"{icon} [{alert['status'].upper()}] [{alert['severity']}/10] "
            f"{alert['attack_type']} | {alert['source_ip']} | {alert['created_at'][:19]}"
        ):
            st.markdown(f"**Analyst:** {alert['analyst'] or 'Unassigned'}")
            st.markdown(f"**Decision Time:** {alert['decision_at'] or 'Pending'}")
            st.markdown("**Report:**")
            st.markdown(alert["report"])