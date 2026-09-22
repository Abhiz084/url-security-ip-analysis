"""
IP Intelligence Page — HTML-based rendering (no Arrow errors)

Uses iframe-based render_table from dashboard.utils.safe_render,
which bypasses Streamlit's Arrow serialization entirely.
"""

import streamlit as st
from database.connection import db_manager
from dashboard.utils.safe_render import render_table, esc


def show(session_state):
    st.markdown('<p class="main-header">🌐 IP Intelligence</p>', unsafe_allow_html=True)

    # ============================================
    # LOOKUP
    # ============================================
    col1, col2 = st.columns([4, 1])
    with col1:
        ip_input = st.text_input(
            "IP Address",
            placeholder="8.8.8.8 or 185.220.101.34",
            label_visibility="collapsed"
        )
    with col2:
        lookup_btn = st.button("🔍 Lookup", type="primary", use_container_width=True)

    if lookup_btn and ip_input:
        _render_lookup(ip_input)

    # ============================================
    # HIGH THREAT IPs
    # ============================================
    st.markdown('<div class="divider-glow"></div>', unsafe_allow_html=True)
    st.markdown('<p class="sub-header">🔥 High Threat IPs</p>', unsafe_allow_html=True)

    _render_high_threat_ips()


# ============================================
# LOOKUP VIEW
# ============================================

def _render_lookup(ip):
    with st.spinner(f"Fetching reputation for {ip}..."):
        try:
            rows = db_manager.execute_query(
                "SELECT * FROM ip_addresses WHERE ip_address = %s", (ip,)
            ) or []
        except Exception as e:
            st.error(f"Query failed: {e}")
            return

    if not rows:
        st.info(f"No data found for IP: {ip}")
        return

    d = dict(rows[0])
    score = float(d.get('threat_score') or 0)

    # Color by score
    if score > 50:
        color, chip = '#ef4444', 'CRITICAL'
    elif score > 30:
        color, chip = '#f97316', 'HIGH'
    elif score > 15:
        color, chip = '#f59e0b', 'MEDIUM'
    else:
        color, chip = '#10b981', 'SAFE'

    # ---------- Banner ----------
    st.markdown(f"""
    <div style="background:rgba(30,41,59,0.6); backdrop-filter:blur(20px);
                border:2px solid {color}; border-radius:20px; padding:30px;
                text-align:center; margin:20px 0;">
        <div style="font-size:3rem;">🌐</div>
        <h1 style="color:{color}; margin:12px 0;
                   font-family:'JetBrains Mono'; font-size:1.8rem;">
            {esc(ip, max_len=60)}
        </h1>
        <div style="display:inline-block; background:{color}22; color:{color};
                    padding:6px 18px; border-radius:20px;
                    font-size:0.85rem; font-weight:700; letter-spacing:2px;">
            {chip}
        </div>
        <div style="color:#94a3b8; margin-top:15px; font-size:1rem;">
            Threat Score: <b style="color:{color}; font-size:1.2rem;">{score:.1f}</b>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # ---------- Metrics ----------
    c1, c2, c3 = st.columns(3)
    with c1:
        _metric_card("Country", d.get('country') or '—')
    with c2:
        _metric_card("City", d.get('city') or '—')
    with c3:
        _metric_card("Requests", d.get('total_requests') or 0)

    # ---------- Details ----------
    with st.expander("📋 Full Details", expanded=False):
        detail_rows = [
            {'k': 'IP Address', 'v': d.get('ip_address')},
            {'k': 'IP Version', 'v': d.get('ip_version')},
            {'k': 'Country', 'v': d.get('country')},
            {'k': 'City', 'v': d.get('city')},
            {'k': 'Region', 'v': d.get('region')},
            {'k': 'ISP', 'v': d.get('isp')},
            {'k': 'Organization', 'v': d.get('organization')},
            {'k': 'ASN', 'v': d.get('asn')},
            {'k': 'Threat Score', 'v': d.get('threat_score')},
            {'k': 'First Seen', 'v': d.get('first_seen')},
            {'k': 'Last Seen', 'v': d.get('last_seen')},
        ]

        # render_table now renders itself (iframe) — no st.markdown wrapper
        render_table(
            detail_rows,
            columns=[
                {'key': 'k', 'label': 'Field', 'color': '#94a3b8'},
                {'key': 'v', 'label': 'Value', 'mono': True},
            ],
            max_rows=20,
            empty_message="No details available",
        )

    # ---------- Related alerts ----------
    try:
        alerts = db_manager.execute_query("""
            SELECT alert_id, alert_type, severity, description, timestamp, status
            FROM alerts
            WHERE source_ip = %s
            ORDER BY timestamp DESC
            LIMIT 10
        """, (ip,)) or []
    except Exception as e:
        st.warning(f"Could not load alerts: {e}")
        alerts = []

    if alerts:
        st.markdown("### 🚨 Related Alerts")
        render_table(
            alerts,
            columns=[
                {'key': 'alert_id', 'label': 'ID', 'mono': True, 'color': '#60a5fa'},
                {'key': 'severity', 'label': 'Severity', 'mono': True,
                 'render': lambda v: _severity_badge(v)},
                {'key': 'alert_type', 'label': 'Type', 'mono': True},
                {'key': 'description', 'label': 'Description', 'max_len': 80},
                {'key': 'status', 'label': 'Status', 'mono': True},
                {'key': 'timestamp', 'label': 'Time', 'color': '#94a3b8',
                 'max_len': 19},
            ],
            max_rows=10,
            empty_message="No related alerts",
        )


# ============================================
# HIGH THREAT IPs TABLE
# ============================================

def _render_high_threat_ips():
    try:
        rows = db_manager.execute_query("""
            SELECT ip_address, country, city, threat_score, total_requests
            FROM ip_addresses
            WHERE threat_score > 15
            ORDER BY threat_score DESC
            LIMIT 50
        """) or []
    except Exception as e:
        st.error(f"Query failed: {e}")
        return

    # render_table now renders itself (iframe) — no st.markdown wrapper
    render_table(
        rows,
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
                'max_len': 30,
            },
            {
                'key': 'city',
                'label': 'City',
                'max_len': 30,
            },
            {
                'key': 'threat_score',
                'label': 'Threat Score',
                'mono': True,
                'render': lambda v: _score_badge(v),
            },
            {
                'key': 'total_requests',
                'label': 'Requests',
                'mono': True,
                'color': '#94a3b8',
            },
        ],
        max_rows=50,
        empty_message="No high-threat IPs detected yet",
    )


# ============================================
# BADGE HELPERS
# ============================================

def _severity_badge(severity):
    """Render a colored severity chip"""
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


def _score_badge(score):
    """Render a colored numeric score"""
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


def _metric_card(label, value):
    """Render a small metric card"""
    st.markdown(f"""
    <div style="background:rgba(30,41,59,0.5); border-radius:12px;
                padding:16px; text-align:center;
                border:1px solid rgba(96,165,250,0.15);">
        <div style="color:#94a3b8; font-size:0.7rem; letter-spacing:1.5px;
                    text-transform:uppercase; font-weight:600;">{label}</div>
        <div style="color:#60a5fa; font-family:'JetBrains Mono';
                    font-size:1.2rem; font-weight:700; margin-top:6px;">
            {esc(value, max_len=40)}
        </div>
    </div>
    """, unsafe_allow_html=True)