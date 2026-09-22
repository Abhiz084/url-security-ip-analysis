"""
Reports Generation Page — HTML-based rendering (no Arrow/LargeUtf8 errors)
"""

import streamlit as st
import io
from datetime import datetime, timedelta

from database.connection import db_manager
from dashboard.utils.safe_render import render_table, esc


def show(session_state):
    st.markdown('<p class="main-header">📋 Reports</p>', unsafe_allow_html=True)
    st.markdown(
        '<p style="text-align:center; color:#94a3b8; margin-top:-15px;">'
        'Generate and export security reports for any date range'
        '</p>',
        unsafe_allow_html=True
    )

    # ============================================
    # CONTROLS
    # ============================================
    col1, col2, col3 = st.columns([2, 1, 1])

    with col1:
        report_type = st.selectbox(
            "Report Type",
            [
                "Security Summary",
                "Threat Analysis",
                "URL Scan Report",
                "IP Intelligence Report",
            ],
            key="report_type",
        )

    with col2:
        start_date = st.date_input(
            "Start Date",
            datetime.now() - timedelta(days=7),
            key="report_start",
        )

    with col3:
        end_date = st.date_input(
            "End Date",
            datetime.now(),
            key="report_end",
        )

    st.markdown('<div class="divider-glow"></div>', unsafe_allow_html=True)

    if st.button("📊 Generate Report", type="primary", use_container_width=False):
        with st.spinner("Generating report..."):
            if report_type == "Security Summary":
                _report_security_summary(start_date, end_date)
            elif report_type == "Threat Analysis":
                _report_threat_analysis(start_date, end_date)
            elif report_type == "URL Scan Report":
                _report_url_scans(start_date, end_date)
            elif report_type == "IP Intelligence Report":
                _report_ip_intelligence(start_date, end_date)


# ============================================
# REPORT 1: SECURITY SUMMARY
# ============================================

def _report_security_summary(start_date, end_date):
    st.markdown('<p class="sub-header">🛡️ Security Summary Report</p>', unsafe_allow_html=True)
    st.caption(f"Period: {start_date} → {end_date}")

    # ---------- Alerts ----------
    try:
        alerts = db_manager.execute_query("""
            SELECT severity, status, COUNT(*) as count
            FROM alerts
            WHERE DATE(timestamp) BETWEEN %s AND %s
            GROUP BY severity, status
            ORDER BY FIELD(severity, 'critical','high','medium','low'), status
        """, (start_date, end_date)) or []
    except Exception as e:
        st.error(f"Failed to load alerts: {e}")
        alerts = []

    st.markdown("**Alert Summary**")
    if alerts:
        render_table(
            alerts,
            columns=[
                {'key': 'severity', 'label': 'Severity',
                 'mono': True, 'render': lambda v: _severity_badge(v)},
                {'key': 'status', 'label': 'Status',
                 'mono': True, 'render': lambda v: _status_badge(v)},
                {'key': 'count', 'label': 'Count',
                 'mono': True, 'color': '#e2e8f0'},
            ],
            max_rows=50,
            empty_message="No alerts in this period",
        )
    else:
        st.info("No alerts in this period")

    # ---------- URLs ----------
    try:
        urls = db_manager.execute_query("""
            SELECT is_malicious, COUNT(*) as count
            FROM urls
            WHERE DATE(submission_date) BETWEEN %s AND %s
              AND is_malicious IS NOT NULL
            GROUP BY is_malicious
        """, (start_date, end_date)) or []
    except Exception as e:
        st.error(f"Failed to load URL stats: {e}")
        urls = []

    st.markdown("**URL Summary**")
    if urls:
        render_table(
            urls,
            columns=[
                {'key': 'is_malicious', 'label': 'Type',
                 'render': lambda v: _url_type_badge(v)},
                {'key': 'count', 'label': 'Count',
                 'mono': True, 'color': '#e2e8f0'},
            ],
            max_rows=10,
            empty_message="No URLs in this period",
        )
    else:
        st.info("No URLs in this period")

    _download_button("security_summary", alerts, urls)


# ============================================
# REPORT 2: THREAT ANALYSIS
# ============================================

def _report_threat_analysis(start_date, end_date):
    st.markdown('<p class="sub-header">🔍 Threat Analysis Report</p>', unsafe_allow_html=True)
    st.caption(f"Period: {start_date} → {end_date}")

    try:
        threats = db_manager.execute_query("""
            SELECT threat_type, COUNT(*) as count,
                   AVG(confidence_score) as avg_confidence
            FROM threat_intelligence
            WHERE DATE(first_reported) BETWEEN %s AND %s
              AND is_active = TRUE
            GROUP BY threat_type
            ORDER BY count DESC
        """, (start_date, end_date)) or []
    except Exception as e:
        st.error(f"Failed to load threats: {e}")
        return

    if not threats:
        st.info("No threats found for the selected period")
        return

    render_table(
        threats,
        columns=[
            {'key': 'threat_type', 'label': 'Threat Type',
             'mono': True, 'color': '#60a5fa'},
            {'key': 'count', 'label': 'Count',
             'mono': True, 'color': '#e2e8f0'},
            {'key': 'avg_confidence', 'label': 'Avg Confidence',
             'mono': True, 'render': lambda v: _confidence_badge(v)},
        ],
        max_rows=50,
        empty_message="No threats in this period",
    )

    _download_button("threat_analysis", threats)


# ============================================
# REPORT 3: URL SCAN REPORT
# ============================================

def _report_url_scans(start_date, end_date):
    st.markdown('<p class="sub-header">🔗 URL Scan Report</p>', unsafe_allow_html=True)
    st.caption(f"Period: {start_date} → {end_date}")

    try:
        scans = db_manager.execute_query("""
            SELECT u.full_url, u.domain, u.is_malicious,
                   mp.predicted_class, mp.prediction_score, mp.prediction_timestamp
            FROM urls u
            JOIN model_predictions mp ON u.url_id = mp.url_id
            WHERE DATE(mp.prediction_timestamp) BETWEEN %s AND %s
            ORDER BY mp.prediction_timestamp DESC
            LIMIT 100
        """, (start_date, end_date)) or []
    except Exception as e:
        st.error(f"Failed to load scans: {e}")
        return

    if not scans:
        st.info("No URL scans found for the selected period")
        return

    render_table(
        scans,
        columns=[
            {'key': 'full_url', 'label': 'URL', 'mono': True,
             'color': '#60a5fa', 'max_len': 70},
            {'key': 'domain', 'label': 'Domain', 'mono': True,
             'color': '#94a3b8', 'max_len': 30},
            {'key': 'predicted_class', 'label': 'Class',
             'render': lambda v: _class_badge(v)},
            {'key': 'prediction_score', 'label': 'Score',
             'mono': True, 'render': lambda v: _confidence_badge(v)},
            {'key': 'prediction_timestamp', 'label': 'Time',
             'mono': True, 'color': '#64748b', 'max_len': 19},
        ],
        max_rows=50,
        empty_message="No scans in this period",
    )

    _download_button("url_scans", scans)


# ============================================
# REPORT 4: IP INTELLIGENCE
# ============================================

def _report_ip_intelligence(start_date, end_date):
    st.markdown('<p class="sub-header">🌐 IP Intelligence Report</p>', unsafe_allow_html=True)
    st.caption(f"Period: {start_date} → {end_date}")

    try:
        ips = db_manager.execute_query("""
            SELECT ip_address, country, city, isp, threat_score, total_requests
            FROM ip_addresses
            WHERE threat_score > 0
              AND DATE(last_seen) BETWEEN %s AND %s
            ORDER BY threat_score DESC
            LIMIT 100
        """, (start_date, end_date)) or []
    except Exception as e:
        st.error(f"Failed to load IP data: {e}")
        return

    if not ips:
        st.info("No IP intelligence data for the selected period")
        return

    render_table(
        ips,
        columns=[
            {'key': 'ip_address', 'label': 'IP Address',
             'mono': True, 'color': '#60a5fa', 'max_len': 45},
            {'key': 'country', 'label': 'Country', 'max_len': 30},
            {'key': 'city', 'label': 'City', 'max_len': 25},
            {'key': 'isp', 'label': 'ISP', 'max_len': 40, 'color': '#94a3b8'},
            {'key': 'threat_score', 'label': 'Threat Score',
             'mono': True, 'render': lambda v: _score_badge(v)},
            {'key': 'total_requests', 'label': 'Requests',
             'mono': True, 'color': '#e2e8f0'},
        ],
        max_rows=50,
        empty_message="No IP data in this period",
    )

    _download_button("ip_intelligence", ips)


# ============================================
# DOWNLOAD BUTTON
# ============================================

def _download_button(name, *datasets):
    """Offer CSV export of the current report"""
    try:
        import pandas as pd
        frames = []
        for ds in datasets:
            if not ds:
                continue
            try:
                df = pd.DataFrame([dict(r) for r in ds])
                frames.append(df)
            except Exception:
                continue

        if not frames:
            return

        combined = pd.concat(frames, ignore_index=True)

        # Convert to CSV
        csv_buffer = io.StringIO()
        combined.to_csv(csv_buffer, index=False)
        csv_data = csv_buffer.getvalue()

        st.markdown('<div class="divider-glow"></div>', unsafe_allow_html=True)
        st.download_button(
            label="📥 Download Report (CSV)",
            data=csv_data,
            file_name=f"{name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            use_container_width=False,
        )
    except Exception as e:
        st.caption(f"Download unavailable: {str(e)[:60]}")


# ============================================
# BADGE HELPERS
# ============================================

def _severity_badge(severity):
    if not severity:
        return "—"
    s = str(severity).lower()
    colors = {
        'critical': '#ef4444',
        'high': '#f97316',
        'medium': '#f59e0b',
        'low': '#3b82f6',
    }
    color = colors.get(s, '#64748b')
    return (
        f'<span style="background:{color}22; color:{color}; '
        f'padding:2px 8px; border-radius:6px; font-size:0.7rem; '
        f'font-weight:700; text-transform:uppercase;">{esc(s)}</span>'
    )


def _status_badge(status):
    if not status:
        return "—"
    s = str(status).lower()
    colors = {
        'new': '#3b82f6',
        'acknowledged': '#8b5cf6',
        'investigating': '#f59e0b',
        'resolved': '#10b981',
        'false_positive': '#64748b',
    }
    color = colors.get(s, '#64748b')
    return (
        f'<span style="color:{color}; font-weight:600; '
        f'font-family:\'JetBrains Mono\';">{esc(s)}</span>'
    )


def _class_badge(predicted_class):
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


def _url_type_badge(is_malicious):
    try:
        val = bool(is_malicious) if is_malicious is not None else None
    except Exception:
        val = None

    if val is True:
        return '⚠️ <b style="color:#ef4444;">Malicious</b>'
    if val is False:
        return '✅ <b style="color:#10b981;">Benign</b>'
    return '—'


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
    return f'<b style="color:{color}; font-family:\'JetBrains Mono\';">{f:.3f}</b>'


def _score_badge(score):
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "—"
    if s > 50:
        color = '#ef4444'
    elif s > 30:
        color = '#f97316'
    elif s > 15:
        color = '#f59e0b'
    else:
        color = '#10b981'
    return f'<b style="color:{color};">{s:.1f}</b>'