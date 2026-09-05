"""
Analytics Page
"""

import streamlit as st
import pandas as pd
from database.queries import QueryBuilder
from database.connection import db_manager

def show(session_state):
    st.markdown('<p class="main-header">📈 Analytics</p>', unsafe_allow_html=True)
    
    qb = QueryBuilder()
    
    st.subheader("📊 Threat Trends")
    try:
        trends = qb.get_threat_trends(7)
        if trends:
            df = pd.DataFrame(trends)
            pivot = df.pivot_table(index='date', columns='severity', values='alert_count', aggfunc='sum', fill_value=0)
            st.line_chart(pivot, use_container_width=True)
    except:
        st.info("No trend data")
    
    st.markdown("---")
    
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("🤖 Model Performance")
        try:
            stats = qb.get_model_performance_stats()
            if stats:
                st.dataframe(pd.DataFrame(stats), use_container_width=True, hide_index=True)
        except:
            st.info("No model data")
    
    with col2:
        st.subheader("🌍 Geographic Distribution")
        try:
            geo = qb.get_geolocation_threat_distribution()
            if geo:
                df = pd.DataFrame(geo)
                st.bar_chart(df.set_index('country')['alert_count'], use_container_width=True)
        except:
            st.info("No geo data")