"""
Home Page - Ultra Modern Dashboard
"""

import streamlit as st
import pandas as pd
import random
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime
from database.connection import db_manager
from database.crud_operations import CRUDOperations

def create_donut(value, total, color, label):
    """Create an animated donut chart"""
    fig = go.Figure(data=[go.Pie(
        values=[value, total - value],
        hole=0.75,
        marker=dict(colors=[color, 'rgba(30, 41, 59, 0.5)']),
        textinfo='none',
        hoverinfo='skip',
        showlegend=False
    )])
    fig.update_layout(
        showlegend=False,
        margin=dict(t=0, b=0, l=0, r=0),
        height=150,
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
    )
    return fig

def safe_query(query, params=None):
    try:
        return db_manager.execute_query(query, params) or []
    except:
        return []

def show(session_state):
    st.markdown('<p class="main-header">Security Dashboard</p>', unsafe_allow_html=True)

    # Get data
    total_urls = safe_query("SELECT COUNT(*) as cnt FROM urls")
    total_urls = total_urls[0]['cnt'] if total_urls else 0

    malicious = safe_query("SELECT COUNT(*) as cnt FROM urls WHERE is_malicious = TRUE")
    malicious = malicious[0]['cnt'] if malicious else 0

    benign = total_urls - malicious

    live_urls = safe_query("SELECT COUNT(*) as cnt FROM urls WHERE source IN ('live_traffic', 'traffic_capture')")
    live_urls = live_urls[0]['cnt'] if live_urls else 0

    active_alerts = safe_query("SELECT COUNT(*) as cnt FROM alerts WHERE status IN ('new','acknowledged','investigating')")
    active_alerts = active_alerts[0]['cnt'] if active_alerts else 0

    today_alerts = safe_query("SELECT COUNT(*) as cnt FROM alerts WHERE DATE(timestamp) = CURDATE()")
    today_alerts = today_alerts[0]['cnt'] if today_alerts else 0

    total_ips = safe_query("SELECT COUNT(*) as cnt FROM ip_addresses")
    total_ips = total_ips[0]['cnt'] if total_ips else 0

    # Top row controls
    col1, col2 = st.columns([4, 1])
    with col1:
        st.markdown(f'<span style="color:#64748b; font-size:0.85rem;">🕐 {datetime.now().strftime("%A, %B %d, %Y • %H:%M:%S")}</span>', unsafe_allow_html=True)
    with col2:
        if st.button("🔄 Refresh", use_container_width=True):
            st.rerun()

    st.markdown('<div class="divider-glow"></div>', unsafe_allow_html=True)

    # ============================================
    # METRIC CARDS
    # ============================================
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.markdown(f"""
        <div class="metric-card card-info">
            <div style="font-size:2rem;">🔗</div>
            <div class="metric-value">{total_urls:,}</div>
            <div class="metric-label">Total URLs</div>
            <div style="margin-top:10px;"><span class="chip chip-safe">🟢 {live_urls} LIVE</span></div>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        pct = (malicious/total_urls*100) if total_urls > 0 else 0
        st.markdown(f"""
        <div class="metric-card card-danger">
            <div style="font-size:2rem;">⚠️</div>
            <div class="metric-value">{malicious:,}</div>
            <div class="metric-label">Threats Detected</div>
            <div style="margin-top:10px;"><span class="chip chip-critical">{pct:.1f}% RISK</span></div>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        st.markdown(f"""
        <div class="metric-card card-warning">
            <div style="font-size:2rem;">🚨</div>
            <div class="metric-value">{active_alerts:,}</div>
            <div class="metric-label">Active Alerts</div>
            <div style="margin-top:10px;"><span class="chip chip-medium">📅 {today_alerts} TODAY</span></div>
        </div>
        """, unsafe_allow_html=True)

    with col4:
        st.markdown(f"""
        <div class="metric-card card-safe">
            <div style="font-size:2rem;">🌐</div>
            <div class="metric-value">{total_ips:,}</div>
            <div class="metric-label">IPs Tracked</div>
            <div style="margin-top:10px;"><span class="chip chip-info">🔍 MONITORED</span></div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown('<div class="divider-glow"></div>', unsafe_allow_html=True)

    # ============================================
    # CHART ROW 1 - Detection Split
    # ============================================
    col_left, col_right = st.columns([1, 2])

    with col_left:
        st.markdown('<p class="sub-header">🎯 Detection Split</p>', unsafe_allow_html=True)
        if total_urls > 0:
            fig = go.Figure(data=[go.Pie(
                labels=['Malicious', 'Benign'],
                values=[malicious, benign],
                hole=0.7,
                marker=dict(
                    colors=['#ef4444', '#10b981'],
                    line=dict(color='#0f172a', width=3)
                ),
                textinfo='label+percent',
                textfont=dict(size=12, color='#e2e8f0', family='Inter'),
                hovertemplate='<b>%{label}</b><br>Count: %{value}<br>Percent: %{percent}<extra></extra>'
            )])
            fig.update_layout(
                showlegend=False,
                margin=dict(t=20, b=20, l=20, r=20),
                height=320,
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                annotations=[dict(
                    text=f'<b>{total_urls}</b><br><span style="font-size:10px;color:#94a3b8;">TOTAL</span>',
                    x=0.5, y=0.5, showarrow=False,
                    font=dict(size=22, color='#60a5fa', family='JetBrains Mono')
                )]
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No data yet")

    with col_right:
        st.markdown('<p class="sub-header">🔥 Top Malicious Domains</p>', unsafe_allow_html=True)
        domains = safe_query("""
            SELECT domain, COUNT(*) as count FROM urls 
            WHERE is_malicious = TRUE GROUP BY domain 
            ORDER BY count DESC LIMIT 8
        """)
        if domains:
            df = pd.DataFrame(domains)
            fig = go.Figure(data=[go.Bar(
                x=df['count'],
                y=df['domain'],
                orientation='h',
                marker=dict(
                    color=df['count'],
                    colorscale=[[0, '#3b82f6'], [0.5, '#a78bfa'], [1, '#f472b6']],
                    line=dict(color='rgba(96,165,250,0.3)', width=1)
                ),
                text=df['count'],
                textposition='outside',
                textfont=dict(color='#e2e8f0', size=11),
                hovertemplate='<b>%{y}</b><br>Occurrences: %{x}<extra></extra>'
            )])
            fig.update_layout(
                height=320,
                margin=dict(t=10, b=10, l=10, r=40),
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                xaxis=dict(showgrid=True, gridcolor='rgba(96,165,250,0.1)',
                          tickfont=dict(color='#94a3b8'), title=None),
                yaxis=dict(showgrid=False, tickfont=dict(color='#e2e8f0', size=11), title=None),
                showlegend=False
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No malicious domains detected")

    st.markdown('<div class="divider-glow"></div>', unsafe_allow_html=True)

    # ============================================
    # CHART ROW 2 - IP Threats & Traffic
    # ============================================
    col_left2, col_right2 = st.columns(2)

    with col_left2:
        st.markdown('<p class="sub-header">🌍 Top Threat IPs</p>', unsafe_allow_html=True)
        ips = safe_query("""
            SELECT ip_address, country, threat_score, total_requests
            FROM ip_addresses WHERE threat_score > 0
            ORDER BY threat_score DESC LIMIT 7
        """)
        if ips:
            df = pd.DataFrame(ips)
            for _, row in df.iterrows():
                score = float(row['threat_score'])
                if score > 50: chip, color = 'chip-critical', '#ef4444'
                elif score > 30: chip, color = 'chip-high', '#f97316'
                elif score > 15: chip, color = 'chip-medium', '#eab308'
                else: chip, color = 'chip-low', '#3b82f6'

                st.markdown(f"""
                <div style="background: rgba(30, 41, 59, 0.5); backdrop-filter: blur(10px); 
                            border-radius: 12px; padding: 14px 18px; margin: 8px 0;
                            border-left: 4px solid {color}; transition: all 0.3s;">
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <div>
                            <span style="font-family:'JetBrains Mono'; color:#e2e8f0; font-size:0.95rem; font-weight:600;">
                                {row['ip_address']}
                            </span>
                            <span style="color:#64748b; font-size:0.8rem; margin-left:10px;">
                                {row.get('country','—')[:25]}
                            </span>
                        </div>
                        <span class="chip {chip}">{score:.0f}</span>
                    </div>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("No threat IPs detected")

    with col_right2:
        st.markdown('<p class="sub-header">📊 Recent Activity (Last 7 Days)</p>', unsafe_allow_html=True)
        daily = safe_query("""
            SELECT DATE(timestamp) as date, severity, COUNT(*) as count
            FROM alerts WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)
            GROUP BY DATE(timestamp), severity ORDER BY date
        """)
        if daily:
            df = pd.DataFrame(daily)
            fig = go.Figure()
            colors = {'critical': '#ef4444', 'high': '#f97316', 'medium': '#eab308', 'low': '#3b82f6'}
            for sev in df['severity'].unique():
                subset = df[df['severity'] == sev]
                fig.add_trace(go.Scatter(
                    x=subset['date'], y=subset['count'],
                    name=sev.title(),
                    mode='lines+markers',
                    line=dict(color=colors.get(sev, '#60a5fa'), width=3, shape='spline'),
                    marker=dict(size=10, color=colors.get(sev, '#60a5fa'),
                               line=dict(color='#0f172a', width=2)),
                    fill='tozeroy',
                    fillcolor=f'rgba{tuple(list(int(colors.get(sev, "#60a5fa")[i:i+2], 16) for i in (1,3,5)) + [0.1])}'
                ))
            fig.update_layout(
                height=320,
                margin=dict(t=10, b=10, l=10, r=10),
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                xaxis=dict(showgrid=True, gridcolor='rgba(96,165,250,0.1)', tickfont=dict(color='#94a3b8'), title=None),
                yaxis=dict(showgrid=True, gridcolor='rgba(96,165,250,0.1)', tickfont=dict(color='#94a3b8'), title=None),
                legend=dict(bgcolor='rgba(30,41,59,0.5)', bordercolor='rgba(96,165,250,0.2)',
                           font=dict(color='#e2e8f0'), orientation='h', y=1.1)
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No recent activity")

    st.markdown('<div class="divider-glow"></div>', unsafe_allow_html=True)

    # ============================================
    # RECENT ALERTS
    # ============================================
    st.markdown('<p class="sub-header">🚨 Recent Security Alerts</p>', unsafe_allow_html=True)

    alerts_data = safe_query("""
        SELECT alert_id, timestamp, severity, source_ip, description, status
        FROM alerts ORDER BY timestamp DESC LIMIT 10
    """)

    if alerts_data:
        for alert in alerts_data:
            sev = alert.get('severity', 'low')
            icons = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🔵'}
            status_icon = {'new': '🆕', 'acknowledged': '👁️', 'investigating': '🔍', 'resolved': '✅'}.get(alert.get('status','new'), '❓')

            st.markdown(f"""
            <div class="alert-card alert-{sev}">
                <div style="display:flex; justify-content:space-between; align-items:start;">
                    <div style="flex:1;">
                        <div style="margin-bottom:6px;">
                            <span class="chip chip-{sev}">{sev.upper()}</span>
                            <span style="margin-left:8px; color:#94a3b8; font-size:0.8rem;">{status_icon} {alert.get('status','new')}</span>
                        </div>
                        <div style="color:#e2e8f0; font-size:0.9rem; margin-bottom:6px;">
                            {alert.get('description','N/A')[:140]}
                        </div>
                        <div style="color:#64748b; font-size:0.75rem; font-family:'JetBrains Mono';">
                            🖥 {alert.get('source_ip','—')} &nbsp;•&nbsp; 📅 {str(alert.get('timestamp',''))[:19]}
                        </div>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div style="text-align:center; padding:60px 20px; background:rgba(16,185,129,0.05);
                    border:1px solid rgba(16,185,129,0.2); border-radius:20px;">
            <div style="font-size:4rem;">✨</div>
            <h3 style="color:#10b981; margin:10px 0;">All Clear</h3>
            <p style="color:#94a3b8;">No active security alerts</p>
        </div>
        """, unsafe_allow_html=True)

    # Footer
    st.markdown(f"""
    <div class="footer">
        <p style="margin:0;">🛡️ <b>CyberGuard</b> — Enterprise Threat Intelligence Platform</p>
        <p style="margin:5px 0 0 0; color:#475569;">Session • {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    """, unsafe_allow_html=True)