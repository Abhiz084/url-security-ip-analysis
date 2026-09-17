import streamlit as st
import pandas as pd
from database.connection import db_manager

def show(session_state):
    st.markdown('<p class="main-header">Alert Center</p>', unsafe_allow_html=True)

    c1, c2, c3 = st.columns(3)
    with c1: sev = st.selectbox("Severity", ["All", "critical", "high", "medium", "low"])
    with c2: status = st.selectbox("Status", ["All", "new", "acknowledged", "investigating", "resolved"])
    with c3:
        if st.button("🔄 Refresh", use_container_width=True): st.rerun()

    q = "SELECT * FROM alerts WHERE 1=1"
    p = []
    if sev != "All": q += " AND severity = %s"; p.append(sev)
    if status != "All": q += " AND status = %s"; p.append(status)
    q += " ORDER BY timestamp DESC LIMIT 50"

    alerts = db_manager.execute_query(q, tuple(p) if p else None)

    if alerts:
        crit = sum(1 for a in alerts if a['severity']=='critical')
        high = sum(1 for a in alerts if a['severity']=='high')
        new = sum(1 for a in alerts if a['status']=='new')

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total", len(alerts))
        c2.metric("🔴 Critical", crit)
        c3.metric("🟠 High", high)
        c4.metric("🆕 New", new)

        st.markdown('<div class="divider-glow"></div>', unsafe_allow_html=True)

        for a in alerts:
            sev = a['severity']
            icons = {'critical':'🔴','high':'🟠','medium':'🟡','low':'🔵'}
            icon = icons.get(sev,'⚪')
            with st.expander(f"{icon}  [{sev.upper()}]  {a.get('description','')[:80]}"):
                c1, c2 = st.columns(2)
                with c1:
                    st.write(f"**Type:** {a.get('alert_type')}")
                    st.write(f"**Source IP:** `{a.get('source_ip')}`")
                with c2:
                    st.write(f"**Status:** {a.get('status')}")
                    st.write(f"**Time:** {str(a.get('timestamp',''))[:19]}")
                st.write(f"**Description:** {a.get('description','')}")

                aid = a['alert_id']
                c1, c2, c3 = st.columns(3)
                with c1:
                    if st.button("✅ Acknowledge", key=f"a{aid}"):
                        session_state.alert_system.update_alert_status(aid, 'acknowledged'); st.rerun()
                with c2:
                    if st.button("🔍 Investigate", key=f"i{aid}"):
                        session_state.alert_system.update_alert_status(aid, 'investigating'); st.rerun()
                with c3:
                    if st.button("✔️ Resolve", key=f"r{aid}"):
                        session_state.alert_system.update_alert_status(aid, 'resolved',
                            resolved_by='analyst', notes='Resolved via dashboard'); st.rerun()
    else:
        st.success("✨ No alerts matched your filters")