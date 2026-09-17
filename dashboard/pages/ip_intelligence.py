import streamlit as st
import pandas as pd
from database.connection import db_manager

def show(session_state):
    st.markdown('<p class="main-header">IP Intelligence</p>', unsafe_allow_html=True)

    col1, col2 = st.columns([4, 1])
    with col1:
        ip = st.text_input("IP Address", placeholder="8.8.8.8", label_visibility="collapsed")
    with col2:
        lookup = st.button("🔍 Lookup", type="primary", use_container_width=True)

    if lookup and ip:
        with st.spinner("Fetching reputation..."):
            result = db_manager.execute_query("SELECT * FROM ip_addresses WHERE ip_address = %s", (ip,))
            if result:
                d = result[0]
                score = float(d.get('threat_score', 0))
                if score > 50: color, chip, label = '#ef4444', 'chip-critical', 'CRITICAL'
                elif score > 30: color, chip, label = '#f97316', 'chip-high', 'HIGH'
                elif score > 15: color, chip, label = '#eab308', 'chip-medium', 'MEDIUM'
                else: color, chip, label = '#10b981', 'chip-safe', 'SAFE'

                st.markdown(f"""
                <div style="background: rgba(30,41,59,0.6); backdrop-filter: blur(20px);
                            border: 2px solid {color}; border-radius: 24px; padding: 40px; text-align:center;">
                    <div style="font-size: 4rem;">🌐</div>
                    <h1 style="color: {color}; margin: 15px 0; font-family:'JetBrains Mono';">{ip}</h1>
                    <span class="chip {chip}" style="font-size:1rem; padding: 8px 20px;">{label}</span>
                    <p style="color:#94a3b8; margin-top:20px;">Threat Score: <b style="color:{color};">{score}</b></p>
                </div>
                """, unsafe_allow_html=True)

                c1, c2, c3 = st.columns(3)
                c1.metric("Country", d.get('country', '—'))
                c2.metric("City", d.get('city', '—'))
                c3.metric("Requests", d.get('total_requests', 0))

                with st.expander("📋 Full Details"):
                    st.json(d)
            else:
                st.warning(f"No data for {ip}")

    st.markdown('<div class="divider-glow"></div>', unsafe_allow_html=True)
    st.markdown('<p class="sub-header">🔥 High Threat IPs</p>', unsafe_allow_html=True)

    ips = db_manager.execute_query("""
        SELECT ip_address, country, threat_score, total_requests
        FROM ip_addresses WHERE threat_score > 15
        ORDER BY threat_score DESC LIMIT 20
    """)
    if ips:
        df = pd.DataFrame(ips)
        df.columns = ['IP', 'Country', 'Score', 'Requests']
        st.dataframe(df, use_container_width=True, hide_index=True)