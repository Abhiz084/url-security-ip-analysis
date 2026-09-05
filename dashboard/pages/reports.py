"""
Reports Page
"""

import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
from database.connection import db_manager

def show(session_state):
    st.markdown('<p class="main-header">📋 Reports</p>', unsafe_allow_html=True)
    
    report_type = st.selectbox("Report Type", ["Security Summary", "Threat Analysis", "URL Scan Report", "IP Report"])
    
    col1, col2 = st.columns(2)
    with col1:
        start_date = st.date_input("Start", datetime.now() - timedelta(days=7))
    with col2:
        end_date = st.date_input("End", datetime.now())
    
    if st.button("📊 Generate Report", type="primary"):
        with st.spinner("Generating..."):
            if report_type == "Security Summary":
                alerts = db_manager.execute_query("""
                    SELECT severity, status, COUNT(*) as count
                    FROM alerts WHERE DATE(timestamp) BETWEEN %s AND %s
                    GROUP BY severity, status
                """, (start_date, end_date))
                
                urls = db_manager.execute_query("""
                    SELECT is_malicious, COUNT(*) as count
                    FROM urls WHERE DATE(submission_date) BETWEEN %s AND %s AND is_malicious IS NOT NULL
                    GROUP BY is_malicious
                """, (start_date, end_date))
                
                st.subheader("Alert Summary")
                if alerts:
                    st.dataframe(pd.DataFrame(alerts), use_container_width=True)
                
                st.subheader("URL Summary")
                if urls:
                    df = pd.DataFrame(urls)
                    df['Type'] = df['is_malicious'].map({True: '⚠️ Malicious', False: '✅ Benign'})
                    st.dataframe(df[['Type', 'count']], use_container_width=True, hide_index=True)
            
            elif report_type == "Threat Analysis":
                threats = db_manager.execute_query("""
                    SELECT threat_type, COUNT(*) as count, AVG(confidence_score) as avg_conf
                    FROM threat_intelligence WHERE DATE(first_reported) BETWEEN %s AND %s AND is_active = TRUE
                    GROUP BY threat_type ORDER BY count DESC
                """, (start_date, end_date))
                if threats:
                    df = pd.DataFrame(threats)
                    st.bar_chart(df.set_index('threat_type')['count'])
                    st.dataframe(df, use_container_width=True, hide_index=True)
                else:
                    st.info("No threats in period")
            
            elif report_type == "URL Scan Report":
                scans = db_manager.execute_query("""
                    SELECT u.full_url, u.domain, mp.predicted_class, mp.prediction_score, mp.prediction_timestamp
                    FROM urls u JOIN model_predictions mp ON u.url_id = mp.url_id
                    WHERE DATE(mp.prediction_timestamp) BETWEEN %s AND %s
                    ORDER BY mp.prediction_timestamp DESC LIMIT 50
                """, (start_date, end_date))
                if scans:
                    st.dataframe(pd.DataFrame(scans), use_container_width=True)
                else:
                    st.info("No scans in period")
            
            elif report_type == "IP Report":
                ips = db_manager.execute_query("""
                    SELECT ip_address, country, isp, threat_score, total_requests
                    FROM ip_addresses WHERE threat_score > 0
                    AND DATE(last_seen) BETWEEN %s AND %s
                    ORDER BY threat_score DESC LIMIT 30
                """, (start_date, end_date))
                if ips:
                    st.dataframe(pd.DataFrame(ips), use_container_width=True)
                else:
                    st.info("No IP data in period")
            
            st.download_button("📥 Download CSV", f"Report generated: {datetime.now()}", file_name=f"report_{datetime.now().strftime('%Y%m%d')}.csv")