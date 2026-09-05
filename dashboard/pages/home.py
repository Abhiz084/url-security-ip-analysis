"""
Home Page - Professional Dashboard with Persistent Live Data
"""

import streamlit as st
import pandas as pd
import random
from datetime import datetime
from database.connection import db_manager
from database.crud_operations import CRUDOperations

def show(session_state):
    st.markdown('<p class="main-header">📊 Security Dashboard</p>', unsafe_allow_html=True)
    
    # Timestamp and manual refresh
    col1, col2 = st.columns([3, 1])
    with col1:
        st.caption(f"🕐 Last updated: {datetime.now().strftime('%B %d, %Y %H:%M:%S')}")
    with col2:
        if st.button("🔄 Refresh Now", use_container_width=True):
            st.rerun()

    # ============================================
    # REAL DATA FROM DATABASE
    # ============================================
    
    def safe_query(query, params=None):
        try:
            result = db_manager.execute_query(query, params)
            return result
        except Exception as e:
            st.warning(f"Database query failed: {str(e)[:80]}")
            return []

    # Total URLs
    total_urls = safe_query("SELECT COUNT(*) as cnt FROM urls")
    total_urls = total_urls[0]['cnt'] if total_urls else 0

    # Malicious URLs
    malicious_urls = safe_query("SELECT COUNT(*) as cnt FROM urls WHERE is_malicious = TRUE")
    malicious_urls = malicious_urls[0]['cnt'] if malicious_urls else 0

    # Live traffic URLs (from live_traffic or traffic_capture)
    live_urls = safe_query("SELECT COUNT(*) as cnt FROM urls WHERE source IN ('live_traffic', 'traffic_capture')")
    live_urls = live_urls[0]['cnt'] if live_urls else 0

    # Active alerts
    active_alerts = safe_query("SELECT COUNT(*) as cnt FROM alerts WHERE status IN ('new', 'acknowledged', 'investigating')")
    active_alerts = active_alerts[0]['cnt'] if active_alerts else 0

    # Today's alerts
    today_alerts = safe_query("SELECT COUNT(*) as cnt FROM alerts WHERE DATE(timestamp) = CURDATE()")
    today_alerts = today_alerts[0]['cnt'] if today_alerts else 0

    # Total IPs
    total_ips = safe_query("SELECT COUNT(*) as cnt FROM ip_addresses")
    total_ips = total_ips[0]['cnt'] if total_ips else 0

    # ============================================
    # METRICS ROW
    # ============================================
    st.markdown("### 📊 Overview")
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.markdown(f"""
        <div class="metric-card card-info">
            <span style="font-size: 2rem;">🔗</span>
            <div class="metric-value">{total_urls:,}</div>
            <div class="metric-label">Total URLs Scanned</div>
            <small style="color: #94a3b8;">🟢 Live Captured: {live_urls}</small>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        pct = f"{(malicious_urls/total_urls*100):.1f}%" if total_urls > 0 else "0%"
        st.markdown(f"""
        <div class="metric-card card-danger">
            <span style="font-size: 2rem;">⚠️</span>
            <div class="metric-value">{malicious_urls:,}</div>
            <div class="metric-label">Threats Detected</div>
            <small style="color: #f87171;">{pct} of total</small>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        st.markdown(f"""
        <div class="metric-card card-warning">
            <span style="font-size: 2rem;">🚨</span>
            <div class="metric-value">{active_alerts:,}</div>
            <div class="metric-label">Active Alerts</div>
            <small style="color: #fbbf24;">Today: {today_alerts}</small>
        </div>
        """, unsafe_allow_html=True)

    with col4:
        st.markdown(f"""
        <div class="metric-card card-safe">
            <span style="font-size: 2rem;">🌐</span>
            <div class="metric-value">{total_ips:,}</div>
            <div class="metric-label">IPs Tracked</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")

    # ============================================
    # LIVE SIMULATION BUTTON
    # ============================================
    col1, col2 = st.columns([3, 1])
    with col2:
        if st.button("🎲 Simulate Live Traffic", use_container_width=True):
            crud = CRUDOperations()
            domains = [
                ("https://www.google.com", "google.com"),
                ("http://phishing-test.xyz/login", "phishing-test.xyz"),
                ("https://github.com", "github.com"),
                ("http://malware-c2.tk/payload", "malware-c2.tk"),
                ("https://www.youtube.com", "youtube.com"),
                ("http://suspicious-bank.ga/verify", "suspicious-bank.ga"),
            ]
            url, domain = random.choice(domains)
            crud.insert_url(
                full_url=url,
                domain=domain,
                path="/",
                protocol="https" if url.startswith("https") else "http",
                tld=domain.split(".")[-1],
                url_length=len(url),
                source="manual_live_demo"
            )
            st.success(f"Inserted: {domain}")
            st.rerun()

    # ============================================
    # CHARTS & DATA FROM DATABASE
    # ============================================
    col1, col2 = st.columns(2)

    with col1:
        st.markdown('<p class="sub-header">🔥 Top Malicious Domains</p>', unsafe_allow_html=True)
        try:
            domains = safe_query("""
                SELECT domain, COUNT(*) as count 
                FROM urls WHERE is_malicious = TRUE 
                GROUP BY domain ORDER BY count DESC LIMIT 7
            """)
            if domains:
                df = pd.DataFrame(domains)
                df.columns = ['Domain', 'Count']
                st.bar_chart(df.set_index('Domain')['Count'], use_container_width=True)
                with st.expander("📋 View Table"):
                    st.dataframe(df, use_container_width=True, hide_index=True)
            else:
                st.info("No malicious domains yet – run live capture")
        except Exception as e:
            st.warning(f"Loading domain data... {str(e)[:50]}")

    with col2:
        st.markdown('<p class="sub-header">🌍 Top Threat IPs</p>', unsafe_allow_html=True)
        try:
            ips = safe_query("""
                SELECT ip_address, country, threat_score, total_requests
                FROM ip_addresses WHERE threat_score > 0
                ORDER BY threat_score DESC LIMIT 7
            """)
            if ips:
                df = pd.DataFrame(ips)
                df.columns = ['IP Address', 'Country', 'Threat Score', 'Requests']
                # Color code threat scores
                def color_score(val):
                    if val > 50: return 'color: #ef4444; font-weight: bold'
                    elif val > 20: return 'color: #f59e0b'
                    return 'color: #10b981'
                styled = df.style.applymap(color_score, subset=['Threat Score'])
                st.dataframe(styled, use_container_width=True, hide_index=True)
            else:
                st.info("No threat IPs yet – run live capture")
        except Exception as e:
            st.warning(f"Loading IP data... {str(e)[:50]}")

    # ============================================
    # RECENT ALERTS
    # ============================================
    st.markdown("---")
    st.markdown('<p class="sub-header">🚨 Recent Security Alerts</p>', unsafe_allow_html=True)

    try:
        alerts = safe_query("""
            SELECT alert_id, timestamp, alert_type, severity, source_ip, description, status
            FROM alerts ORDER BY timestamp DESC LIMIT 15
        """)
        if alerts:
            critical = sum(1 for a in alerts if a['severity'] == 'critical')
            high = sum(1 for a in alerts if a['severity'] == 'high')
            if critical > 0 or high > 0:
                c1, c2, c3 = st.columns(3)
                c1.metric("🔴 Critical", critical)
                c2.metric("🟠 High", high)
                c3.metric("📋 Total", len(alerts))

            for alert in alerts:
                sev = alert.get('severity', 'low')
                css_class = f"alert-{sev}"
                icons = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🔵'}
                icon = icons.get(sev, '⚪')
                status_icon = {'new': '🆕', 'acknowledged': '👁️', 'investigating': '🔍', 'resolved': '✅'}.get(alert.get('status', 'new'), '❓')
                st.markdown(f"""
                <div class="{css_class}">
                    <strong>{icon} [{sev.upper()}]</strong> {status_icon}
                    {alert.get('description', 'N/A')[:120]}<br>
                    <small>🖥️ IP: {alert.get('source_ip', 'N/A')} | 📅 {str(alert.get('timestamp', ''))[:19]}</small>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.success("🎉 No alerts - system is clean!")
    except Exception as e:
        st.info("Alert system ready")

    # ============================================
    # LIVE TRAFFIC STATUS
    # ============================================
    st.markdown("---")
    st.markdown('<p class="sub-header">📡 Live Traffic</p>', unsafe_allow_html=True)

    try:
        live_data = safe_query("""
            SELECT domain, protocol, submission_date 
            FROM urls WHERE source IN ('live_traffic', 'traffic_capture')
            ORDER BY submission_date DESC LIMIT 10
        """)
        if live_data:
            c1, c2 = st.columns(2)
            c1.metric("Live URLs", live_urls)
            c2.metric("Today's Alerts", today_alerts)
            for t in live_data:
                domain = t['domain'][:55]
                time_str = str(t['submission_date'])[:19] if t['submission_date'] else ''
                st.markdown(f"🌐 `{domain}` — *{time_str}*")
        else:
            st.info("📡 No live traffic yet. Run: `python scripts/live_monitor.py`")
    except Exception:
        pass

    # Footer
    st.markdown("---")
    st.markdown(f"""
    <div style="display: flex; justify-content: space-between; padding: 10px 0;">
        <span style="color: #475569;">🛡️ URL Security Dashboard</span>
        <span style="color: #60a5fa;">Auto-refresh: enabled</span>
        <span style="color: #475569;">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span>
    </div>
    """, unsafe_allow_html=True)