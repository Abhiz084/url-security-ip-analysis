"""
Home Page - Security Dashboard

Uses dashboard.utils.safe_render for all tabular content
to avoid Streamlit's Arrow/LargeUtf8 serialization errors.
"""

import streamlit as st
import pandas as pd
import random
import plotly.graph_objects as go
from datetime import datetime

from database.connection import db_manager
from dashboard.utils.safe_render import render_table, esc


# ============================================
# HELPERS
# ============================================

def safe_query(query, params=None):
    """Run a query, swallow errors, always return a list"""
    try:
        return db_manager.execute_query(query, params) or []
    except Exception:
        return []


def _chip_class_for_score(score):
    if score > 50:
        return 'chip-critical', '#ef4444'
    elif score > 30:
        return 'chip-high', '#f97316'
    elif score > 15:
        return 'chip-medium', '#eab308'
    return 'chip-low', '#3b82f6'


def _hex_to_rgba(hex_color, alpha=0.1):
    """Convert #RRGGBB to rgba(...) string"""
    try:
        h = hex_color.lstrip('#')
        r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
        return f'rgba({r},{g},{b},{alpha})'
    except Exception:
        return f'rgba(96,165,250,{alpha})'


# ============================================
# PAGE ENTRY
# ============================================

def show(session_state):
    st.markdown('<p class="main-header">Security Dashboard</p>', unsafe_allow_html=True)

    # ============================================
    # FETCH METRICS
    # ============================================
    total_urls = safe_query("SELECT COUNT(*) as cnt FROM urls")
    total_urls = total_urls[0]['cnt'] if total_urls else 0

    malicious = safe_query("SELECT COUNT(*) as cnt FROM urls WHERE is_malicious = TRUE")
    malicious = malicious[0]['cnt'] if malicious else 0

    benign = total_urls - malicious

    live_urls = safe_query("""
        SELECT COUNT(*) as cnt FROM urls
        WHERE source IN ('live_traffic', 'traffic_capture')
    """)
    live_urls = live_urls[0]['cnt'] if live_urls else 0

    active_alerts = safe_query("""
        SELECT COUNT(*) as cnt FROM alerts
        WHERE status IN ('new','acknowledged','investigating')
    """)
    active_alerts = active_alerts[0]['cnt'] if active_alerts else 0

    today_alerts = safe_query("""
        SELECT COUNT(*) as cnt FROM alerts WHERE DATE(timestamp) = CURDATE()
    """)
    today_alerts = today_alerts[0]['cnt'] if today_alerts else 0

    total_ips = safe_query("SELECT COUNT(*) as cnt FROM ip_addresses")
    total_ips = total_ips[0]['cnt'] if total_ips else 0

    # ============================================
    # TOP CONTROLS
    # ============================================
    col1, col2 = st.columns([4, 1])
    with col1:
        st.markdown(
            f'<span style="color:#64748b; font-size:0.85rem;">'
            f'🕐 {datetime.now().strftime("%A, %B %d, %Y • %H:%M:%S")}</span>',
            unsafe_allow_html=True
        )
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
            <div style="margin-top:10px;">
                <span class="chip chip-safe">🟢 {live_urls} LIVE</span>
            </div>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        pct = (malicious / total_urls * 100) if total_urls > 0 else 0
        st.markdown(f"""
        <div class="metric-card card-danger">
            <div style="font-size:2rem;">⚠️</div>
            <div class="metric-value">{malicious:,}</div>
            <div class="metric-label">Threats Detected</div>
            <div style="margin-top:10px;">
                <span class="chip chip-critical">{pct:.1f}% RISK</span>
            </div>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        st.markdown(f"""
        <div class="metric-card card-warning">
            <div style="font-size:2rem;">🚨</div>
            <div class="metric-value">{active_alerts:,}</div>
            <div class="metric-label">Active Alerts</div>
            <div style="margin-top:10px;">
                <span class="chip chip-medium">📅 {today_alerts} TODAY</span>
            </div>
        </div>
        """, unsafe_allow_html=True)

    with col4:
        st.markdown(f"""
        <div class="metric-card card-safe">
            <div style="font-size:2rem;">🌐</div>
            <div class="metric-value">{total_ips:,}</div>
            <div class="metric-label">IPs Tracked</div>
            <div style="margin-top:10px;">
                <span class="chip chip-info">🔍 MONITORED</span>
            </div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown('<div class="divider-glow"></div>', unsafe_allow_html=True)

    # ============================================
    # CHART ROW 1 — Detection Split + Top Malicious Domains
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
                    line=dict(color='#0f172a', width=3),
                ),
                textinfo='label+percent',
                textfont=dict(size=12, color='#e2e8f0', family='Inter'),
                hovertemplate='<b>%{label}</b><br>Count: %{value}<br>Percent: %{percent}<extra></extra>',
            )])
            fig.update_layout(
                showlegend=False,
                margin=dict(t=20, b=20, l=20, r=20),
                height=320,
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                annotations=[dict(
                    text=f'<b>{total_urls}</b><br>'
                         f'<span style="font-size:10px;color:#94a3b8;">TOTAL</span>',
                    x=0.5, y=0.5, showarrow=False,
                    font=dict(size=22, color='#60a5fa', family='JetBrains Mono'),
                )],
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No data yet")

    with col_right:
        st.markdown('<p class="sub-header">🔥 Top Malicious Domains</p>', unsafe_allow_html=True)
        domains = safe_query("""
            SELECT domain, COUNT(*) as count FROM urls
            WHERE is_malicious = TRUE
            GROUP BY domain
            ORDER BY count DESC
            LIMIT 8
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
                    line=dict(color='rgba(96,165,250,0.3)', width=1),
                ),
                text=df['count'],
                textposition='outside',
                textfont=dict(color='#e2e8f0', size=11),
                hovertemplate='<b>%{y}</b><br>Occurrences: %{x}<extra></extra>',
            )])
            fig.update_layout(
                height=320,
                margin=dict(t=10, b=10, l=10, r=40),
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                xaxis=dict(showgrid=True, gridcolor='rgba(96,165,250,0.1)',
                           tickfont=dict(color='#94a3b8'), title=None),
                yaxis=dict(showgrid=False,
                           tickfont=dict(color='#e2e8f0', size=11), title=None),
                showlegend=False,
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No malicious domains detected")

    st.markdown('<div class="divider-glow"></div>', unsafe_allow_html=True)

    # ============================================
    # CHART ROW 2 — Top Threat IPs + Recent Activity
    # ============================================
    col_left2, col_right2 = st.columns(2)

    with col_left2:
        st.markdown('<p class="sub-header">🌍 Top Threat IPs</p>', unsafe_allow_html=True)
        ips = safe_query("""
            SELECT ip_address, country, threat_score, total_requests
            FROM ip_addresses
            WHERE threat_score > 0
            ORDER BY threat_score DESC
            LIMIT 10
        """)

        # ============================================
        # ✅ HTML rendering via shared utility (no Arrow error)
        # ============================================
        html = render_table(
            ips,
            columns=[
                {
                    'key': 'ip_address',
                    'label': 'IP Address',
                    'mono': True,
                    'color': '#60a5fa',
                    'max_len': 45,
                },
                {
                    'key': 'country',
                    'label': 'Country',
                    'max_len': 25,
                },
                {
                    'key': 'threat_score',
                    'label': 'Score',
                    'mono': True,
                    'render': lambda v: _render_score_badge(v),
                },
                {
                    'key': 'total_requests',
                    'label': 'Requests',
                    'mono': True,
                    'color': '#94a3b8',
                },
            ],
            max_rows=7,
            empty_message="No threat IPs detected yet",
        )
        st.markdown(html, unsafe_allow_html=True)

    with col_right2:
        st.markdown('<p class="sub-header">📊 Recent Activity (Last 7 Days)</p>', unsafe_allow_html=True)
        daily = safe_query("""
            SELECT DATE(timestamp) as date, severity, COUNT(*) as count
            FROM alerts
            WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)
            GROUP BY DATE(timestamp), severity
            ORDER BY date
        """)
        if daily:
            df = pd.DataFrame(daily)
            fig = go.Figure()
            colors = {
                'critical': '#ef4444',
                'high': '#f97316',
                'medium': '#eab308',
                'low': '#3b82f6',
            }
            for sev in df['severity'].unique():
                subset = df[df['severity'] == sev]
                color = colors.get(sev, '#60a5fa')
                fig.add_trace(go.Scatter(
                    x=subset['date'], y=subset['count'],
                    name=str(sev).title(),
                    mode='lines+markers',
                    line=dict(color=color, width=3, shape='spline'),
                    marker=dict(size=10, color=color,
                                line=dict(color='#0f172a', width=2)),
                    fill='tozeroy',
                    fillcolor=_hex_to_rgba(color, 0.1),
                ))
            fig.update_layout(
                height=320,
                margin=dict(t=10, b=10, l=10, r=10),
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                xaxis=dict(showgrid=True, gridcolor='rgba(96,165,250,0.1)',
                           tickfont=dict(color='#94a3b8'), title=None),
                yaxis=dict(showgrid=True, gridcolor='rgba(96,165,250,0.1)',
                           tickfont=dict(color='#94a3b8'), title=None),
                legend=dict(
                    bgcolor='rgba(30,41,59,0.5)',
                    bordercolor='rgba(96,165,250,0.2)',
                    font=dict(color='#e2e8f0'),
                    orientation='h', y=1.1,
                ),
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
        FROM alerts
        ORDER BY timestamp DESC
        LIMIT 10
    """)

    if alerts_data:
        for alert in alerts_data:
            _render_alert_card(alert)
    else:
        st.markdown("""
        <div style="text-align:center; padding:60px 20px;
                    background:rgba(16,185,129,0.05);
                    border:1px solid rgba(16,185,129,0.2);
                    border-radius:20px;">
            <div style="font-size:4rem;">✨</div>
            <h3 style="color:#10b981; margin:10px 0;">All Clear</h3>
            <p style="color:#94a3b8;">No active security alerts</p>
        </div>
        """, unsafe_allow_html=True)

    # ============================================
    # FOOTER
    # ============================================
    st.markdown(f"""
    <div class="footer">
        <p style="margin:0;">
            🛡️ <b>URL Security Using IP-Based Threat Analysis</b>
        </p>
        <p style="margin:5px 0 0 0; color:#475569;">
            Session • {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        </p>
    </div>
    """, unsafe_allow_html=True)


# ============================================
# SUB-RENDERERS
# ============================================

def _render_score_badge(score):
    """Render a threat score with color coding"""
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "—"

    if s > 50:
        color = '#ef4444'
    elif s > 30:
        color = '#f97316'
    elif s > 15:
        color = '#eab308'
    else:
        color = '#3b82f6'

    return f'<b style="color:{color}; font-size:0.95rem;">{s:.0f}</b>'


def _render_alert_card(alert):
    """Render a single recent alert as HTML"""
    sev = alert.get('severity', 'low') or 'low'
    status = alert.get('status', 'new') or 'new'

    icons = {
        'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🔵',
    }
    status_icon = {
        'new': '🆕', 'acknowledged': '👁️', 'investigating': '🔍',
        'resolved': '✅', 'false_positive': '🚫',
    }.get(status, '❓')

    desc = (alert.get('description') or 'N/A')[:140]
    ip = alert.get('source_ip') or '—'
    ts = str(alert.get('timestamp') or '')[:19]

    st.markdown(f"""
    <div class="alert-card alert-{esc(sev, max_len=20)}">
        <div style="display:flex; justify-content:space-between; align-items:start;">
            <div style="flex:1;">
                <div style="margin-bottom:6px;">
                    <span class="chip chip-{esc(sev, max_len=20)}">{esc(sev.upper(), max_len=20)}</span>
                    <span style="margin-left:8px; color:#94a3b8; font-size:0.8rem;">
                        {status_icon} {esc(status, max_len=20)}
                    </span>
                </div>
                <div style="color:#e2e8f0; font-size:0.9rem; margin-bottom:6px;">
                    {esc(desc, max_len=200)}
                </div>
                <div style="color:#64748b; font-size:0.75rem; font-family:'JetBrains Mono';">
                    🖥 {esc(ip, max_len=45)} &nbsp;•&nbsp; 📅 {esc(ts, max_len=19)}
                </div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)