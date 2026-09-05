"""
Alerts Management Page
"""

import streamlit as st
import pandas as pd
from database.connection import db_manager

def show(session_state):
    st.markdown('<p class="main-header">🚨 Alert Management</p>', unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns(3)
    with col1:
        severity_filter = st.selectbox("Severity", ["All", "critical", "high", "medium", "low"])
    with col2:
        status_filter = st.selectbox("Status", ["All", "new", "acknowledged", "investigating", "resolved"])
    with col3:
        st.button("🔄 Refresh", use_container_width=True, on_click=st.rerun)
    
    query = "SELECT * FROM alerts WHERE 1=1"
    params = []
    
    if severity_filter != "All":
        query += " AND severity = %s"
        params.append(severity_filter)
    if status_filter != "All":
        query += " AND status = %s"
        params.append(status_filter)
    
    query += " ORDER BY timestamp DESC LIMIT 50"
    
    try:
        alerts = db_manager.execute_query(query, tuple(params) if params else None)
        
        if alerts:
            total = len(alerts)
            critical = sum(1 for a in alerts if a['severity'] == 'critical')
            new = sum(1 for a in alerts if a['status'] == 'new')
            
            c1, c2, c3 = st.columns(3)
            c1.metric("Total", total)
            c2.metric("Critical", critical)
            c3.metric("New", new)
            
            st.markdown("---")
            
            for alert in alerts:
                sev = alert.get('severity', 'low')
                css_class = f"alert-{sev}"
                icons = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🔵'}
                icon = icons.get(sev, '⚪')
                
                with st.expander(f"{icon} [{sev.upper()}] {alert.get('description', 'Alert')[:80]}"):
                    c1, c2 = st.columns(2)
                    with c1:
                        st.write(f"Type: {alert.get('alert_type')}")
                        st.write(f"Source IP: {alert.get('source_ip')}")
                    with c2:
                        st.write(f"Status: {alert.get('status')}")
                        st.write(f"Time: {str(alert.get('timestamp', ''))[:19]}")
                    
                    st.write(f"Description: {alert.get('description')}")
                    
                    alert_id = alert['alert_id']
                    c1, c2, c3 = st.columns(3)
                    with c1:
                        if st.button("✅ Acknowledge", key=f"ack_{alert_id}"):
                            session_state.alert_system.update_alert_status(alert_id, 'acknowledged')
                            st.rerun()
                    with c2:
                        if st.button("🔍 Investigate", key=f"inv_{alert_id}"):
                            session_state.alert_system.update_alert_status(alert_id, 'investigating')
                            st.rerun()
                    with c3:
                        if st.button("✔️ Resolve", key=f"res_{alert_id}"):
                            session_state.alert_system.update_alert_status(alert_id, 'resolved', resolved_by='dashboard', notes='Resolved via dashboard')
                            st.rerun()
        else:
            st.success(" No alerts found!")
    except Exception as e:
        st.warning(f"Loading alerts: {e}")