"""
IP Intelligence Page
"""

import streamlit as st
import pandas as pd
from database.connection import db_manager

def show(session_state):
    st.markdown('<p class="main-header">🌐 IP Intelligence</p>', unsafe_allow_html=True)
    
    col1, col2 = st.columns([3, 1])
    with col1:
        ip_input = st.text_input("Enter IP Address", placeholder="8.8.8.8 or 185.220.101.34")
    with col2:
        lookup_btn = st.button("🔍 Lookup", type="primary", use_container_width=True)
    
    if lookup_btn and ip_input:
        with st.spinner("Checking IP reputation..."):
            result = db_manager.execute_query(
                "SELECT * FROM ip_addresses WHERE ip_address = %s", (ip_input,)
            )
            
            if result:
                ip_data = result[0]
                
                col1, col2, col3 = st.columns(3)
                with col1:
                    score = float(ip_data.get('threat_score', 0))
                    if score > 50:
                        st.error(f"🔴 Threat Score: {score}")
                    elif score > 20:
                        st.warning(f"🟡 Threat Score: {score}")
                    else:
                        st.success(f"🟢 Threat Score: {score}")
                
                with col2:
                    st.metric("Total Requests", ip_data.get('total_requests', 0))
                with col3:
                    st.metric("Country", ip_data.get('country', 'Unknown'))
                
                with st.expander("📋 IP Details"):
                    c1, c2 = st.columns(2)
                    with c1:
                        st.write(f"City: {ip_data.get('city', 'N/A')}")
                        st.write(f"Region: {ip_data.get('region', 'N/A')}")
                        st.write(f"Country: {ip_data.get('country', 'N/A')}")
                    with c2:
                        st.write(f"ISP: {ip_data.get('isp', 'N/A')}")
                        st.write(f"Org: {ip_data.get('organization', 'N/A')}")
                        st.write(f"ASN: {ip_data.get('asn', 'N/A')}")
                
                # Related alerts
                alerts = db_manager.execute_query(
                    "SELECT * FROM alerts WHERE source_ip = %s ORDER BY timestamp DESC LIMIT 5",
                    (ip_input,)
                )
                if alerts:
                    st.subheader("🚨 Related Alerts")
                    for a in alerts:
                        st.warning(f"[{a['severity'].upper()}] {a.get('description', 'N/A')[:100]}")
            else:
                st.info(f"No data for IP: {ip_input}")
    
    # High threat IPs table
    st.markdown("---")
    st.subheader("🔴 High Threat IPs")
    
    try:
        ips = db_manager.execute_query("""
            SELECT ip_address, country, city, threat_score, total_requests
            FROM ip_addresses WHERE threat_score > 20
            ORDER BY threat_score DESC LIMIT 20
        """)
        if ips:
            df = pd.DataFrame(ips)
            df.columns = ['IP', 'Country', 'City', 'Score', 'Requests']
            st.dataframe(df, use_container_width=True, hide_index=True)
        else:
            st.info("No high-threat IPs")
    except:
        pass