"""
Analytics Page — HTML-based rendering (no Arrow/LargeUtf8 errors)
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go

from database.queries import QueryBuilder
from database.connection import db_manager
from dashboard.utils.safe_render import render_table, esc


def show(session_state):
    st.markdown('<p class="main-header">📈 Analytics</p>', unsafe_allow_html=True)

    qb = QueryBuilder()

    # ============================================
    # THREAT TRENDS
    # ============================================
    st.markdown('<p class="sub-header">📊 Threat Trends (Last 7 Days)</p>', unsafe_allow_html=True)
    _render_threat_trends(qb)

    st.markdown('<div class="divider-glow"></div>', unsafe_allow_html=True)

    # ============================================
    # MODEL PERFORMANCE + GEOGRAPHIC
    # ============================================
    col1, col2 = st.columns(2)

    with col1:
        st.markdown('<p class="sub-header">🤖 Model Performance</p>', unsafe_allow_html=True)
        _render_model_performance(qb)

    with col2:
        st.markdown('<p class="sub-header">🌍 Geographic Distribution</p>', unsafe_allow_html=True)
        _render_geographic(qb)

    # ============================================
    # URL STATISTICS
    # ============================================
    st.markdown('<div class="divider-glow"></div>', unsafe_allow_html=True)
    st.markdown('<p class="sub-header">📊 URL Statistics</p>', unsafe_allow_html=True)
    _render_url_stats()


# ============================================
# SECTION: THREAT TRENDS
# ============================================

def _render_threat_trends(qb):
    try:
        trends = qb.get_threat_trends(7) or []
    except Exception as e:
        st.warning(f"Could not load trends: {e}")
        return

    if not trends:
        st.info("No trend data available")
        return

    df = pd.DataFrame(trends)

    # Normalize column names
    df.columns = [c if isinstance(c, str) else str(c) for c in df.columns]

    # Ensure required columns exist
    required = {'date', 'severity', 'alert_count'}
    if not required.issubset(df.columns):
        st.warning(f"Missing columns in trend data: {required - set(df.columns)}")
        return

    pivot = df.pivot_table(
        index='date',
        columns='severity',
        values='alert_count',
        aggfunc='sum',
        fill_value=0,
    )

    fig = go.Figure()
    colors = {
        'critical': '#ef4444',
        'high': '#f97316',
        'medium': '#eab308',
        'low': '#3b82f6',
    }
    for sev in pivot.columns:
        fig.add_trace(go.Scatter(
            x=pivot.index,
            y=pivot[sev],
            name=str(sev).title(),
            mode='lines+markers',
            line=dict(color=colors.get(str(sev).lower(), '#60a5fa'), width=3, shape='spline'),
            marker=dict(size=10, line=dict(color='#0f172a', width=2)),
            fill='tozeroy',
            fillcolor=_hex_to_rgba(colors.get(str(sev).lower(), '#60a5fa'), 0.1),
        ))

    fig.update_layout(
        height=340,
        margin=dict(t=20, b=20, l=20, r=20),
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


# ============================================
# SECTION: MODEL PERFORMANCE (fixed)
# ============================================

def _render_model_performance(qb):
    try:
        stats = qb.get_model_performance_stats() or []
    except Exception as e:
        st.warning(f"Could not load model stats: {e}")
        return

    if not stats:
        st.info("No model performance data available yet")
        return

    # ⭐ HTML-based table — no Arrow errors
    render_table(
        stats,
        columns=[
            {'key': 'model_name', 'label': 'Model', 'mono': True,
             'color': '#60a5fa', 'max_len': 30},
            {'key': 'model_version', 'label': 'Version', 'mono': True,
             'color': '#94a3b8', 'max_len': 20},
            {'key': 'predicted_class', 'label': 'Class', 'mono': True,
             'render': lambda v: _class_badge(v)},
            {'key': 'prediction_count', 'label': 'Count', 'mono': True,
             'color': '#e2e8f0'},
            {'key': 'avg_confidence', 'label': 'Avg Conf',
             'mono': True,
             'render': lambda v: _confidence_badge(v)},
        ],
        max_rows=30,
        empty_message="No model predictions logged yet",
    )


# ============================================
# SECTION: GEOGRAPHIC DISTRIBUTION
# ============================================

def _render_geographic(qb):
    try:
        geo = qb.get_geolocation_threat_distribution() or []
    except Exception as e:
        st.warning(f"Could not load geo data: {e}")
        return

    if not geo:
        st.info("No geolocation data available yet")
        return

    df = pd.DataFrame(geo)
    df.columns = [c if isinstance(c, str) else str(c) for c in df.columns]

    if 'country' not in df.columns or 'alert_count' not in df.columns:
        st.warning("Missing required geo columns")
        return

    # Limit to top 10 countries
    df = df.head(10)

    fig = go.Figure(data=[go.Bar(
        x=df['alert_count'],
        y=df['country'],
        orientation='h',
        marker=dict(
            color=df['alert_count'],
            colorscale=[[0, '#3b82f6'], [0.5, '#a78bfa'], [1, '#f472b6']],
            line=dict(color='rgba(96,165,250,0.3)', width=1),
        ),
        text=df['alert_count'],
        textposition='outside',
        textfont=dict(color='#e2e8f0', size=11),
        hovertemplate='<b>%{y}</b><br>Alerts: %{x}<extra></extra>',
    )])
    fig.update_layout(
        height=340,
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


# ============================================
# SECTION: URL STATS
# ============================================

def _render_url_stats():
    try:
        url_stats = db_manager.execute_query("""
            SELECT
                is_malicious,
                COUNT(*) as count,
                AVG(url_length) as avg_length
            FROM urls
            WHERE is_malicious IS NOT NULL
            GROUP BY is_malicious
        """) or []
    except Exception as e:
        st.warning(f"Could not load URL stats: {e}")
        return

    if not url_stats:
        st.info("No URL statistics available")
        return

    # Render as metric cards (not a table)
    col1, col2 = st.columns(2)
    for stat in url_stats:
        try:
            is_mal = bool(stat.get('is_malicious'))
            count = int(stat.get('count') or 0)
            avg_len = float(stat.get('avg_length') or 0)
        except Exception:
            continue

        with (col1 if is_mal else col2):
            _metric_card(
                label=("⚠️ Malicious URLs" if is_mal else "✅ Benign URLs"),
                value=count,
                subtitle=f"Avg Length: {avg_len:.0f}",
                color="#ef4444" if is_mal else "#10b981",
            )


# ============================================
# HELPERS
# ============================================

def _hex_to_rgba(hex_color, alpha=0.1):
    try:
        h = hex_color.lstrip('#')
        r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
        return f'rgba({r},{g},{b},{alpha})'
    except Exception:
        return f'rgba(96,165,250,{alpha})'


def _class_badge(predicted_class):
    """Render predicted class as a colored chip"""
    if not predicted_class:
        return "—"
    s = str(predicted_class).lower()
    colors = {
        'malicious': '#ef4444',
        'suspicious': '#f59e0b',
        'benign': '#10b981',
    }
    color = colors.get(s, '#64748b')
    return (
        f'<span style="background:{color}22; color:{color}; '
        f'padding:2px 8px; border-radius:6px; font-size:0.7rem; '
        f'font-weight:700; text-transform:uppercase;">{esc(s)}</span>'
    )


def _confidence_badge(v):
    try:
        f = float(v or 0)
    except (TypeError, ValueError):
        return "—"
    if f > 0.8:
        color = '#ef4444'
    elif f > 0.5:
        color = '#f59e0b'
    else:
        color = '#10b981'
    return f'<b style="color:{color};">{f:.3f}</b>'


def _metric_card(label, value, subtitle="", color="#60a5fa"):
    st.markdown(f"""
    <div style="background:rgba(30,41,59,0.5); border-radius:12px;
                padding:20px; text-align:center;
                border:1px solid {color}44;">
        <div style="color:#94a3b8; font-size:0.7rem; letter-spacing:1.5px;
                    text-transform:uppercase; font-weight:600;">{label}</div>
        <div style="color:{color}; font-family:'JetBrains Mono';
                    font-size:2rem; font-weight:800; margin:8px 0;
                    line-height:1;">{value:,}</div>
        <div style="color:#64748b; font-size:0.75rem;">{subtitle}</div>
    </div>
    """, unsafe_allow_html=True)