"""
Alerts Management Page — Working Action Buttons

Features:
- Real DB persistence with verification
- Confirmation modal for Resolve (with notes)
- Status-aware buttons (only valid transitions shown)
- Toast notifications on every action
- Bulk actions
- Resolved alerts archive
- Auto-refresh after action
"""

import streamlit as st
import pandas as pd
from datetime import datetime
from database.connection import db_manager


# ============================================
# PAGE ENTRY
# ============================================

def show(session_state):
    st.markdown('<p class="main-header">🚨 Alert Management</p>', unsafe_allow_html=True)

    # Ensure alert_system is available
    if not session_state.get('alert_system'):
        st.error("⚠️ Alert system not initialized. Please click **Initialize System** first.")
        return

    alert_system = session_state.alert_system

    # Initialize session state for modal flows
    _init_session_state()

    # ============================================
    # MODAL: Resolve / False-Positive dialog
    # ============================================
    _render_resolve_modal(alert_system)

    # ============================================
    # TOP METRICS
    # ============================================
    _render_metrics(alert_system)

    st.markdown('<div class="divider-glow"></div>', unsafe_allow_html=True)

    # ============================================
    # FILTERS + REFRESH
    # ============================================
    _render_filters_and_controls()

    st.markdown('<div class="divider-glow"></div>', unsafe_allow_html=True)

    # ============================================
    # ACTIVE ALERTS LIST
    # ============================================
    _render_active_alerts(alert_system)

    # ============================================
    # BULK ACTIONS BAR
    # ============================================
    _render_bulk_actions(alert_system)

    # ============================================
    # RESOLVED ARCHIVE
    # ============================================
    st.markdown('<div class="divider-glow"></div>', unsafe_allow_html=True)
    _render_resolved_archive(alert_system)


# ============================================
# SESSION STATE
# ============================================

def _init_session_state():
    defaults = {
        'resolve_modal_alert_id': None,
        'resolve_modal_action': 'resolved',
        'bulk_selected': set(),
        'last_action_toast': None,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


# ============================================
# MODAL FOR RESOLVE
# ============================================

def _render_resolve_modal(alert_system):
    """
    Modal-style confirmation for Resolve / False-Positive.

    Rendered at the top of the page so it appears above the alert list.
    """
    alert_id = st.session_state.get('resolve_modal_alert_id')
    if not alert_id:
        return

    action = st.session_state.get('resolve_modal_action', 'resolved')
    action_label = "Resolve" if action == 'resolved' else "Mark as False Positive"

    st.markdown(f"""
    <div style="background:rgba(139,92,246,0.1); border:2px solid #8b5cf6;
                border-radius:16px; padding:20px 24px; margin-bottom:16px;">
        <h3 style="color:#a78bfa; margin:0 0 8px 0;">🎯 {action_label} Alert #{alert_id}</h3>
        <p style="color:#94a3b8; margin:0; font-size:0.9rem;">
            Add resolution notes (visible in the audit trail). Notes are recommended
            but optional — you can leave it blank for quick resolutions.
        </p>
    </div>
    """, unsafe_allow_html=True)

    with st.form("resolve_form", clear_on_submit=True):
        notes = st.text_area(
            "Resolution notes",
            placeholder="Example: Confirmed phishing site. Blocked at firewall. Reported to IT.",
            height=100,
            label_visibility="collapsed",
            key="resolve_notes_input"
        )
        analyst = st.text_input(
            "Analyst name",
            value="analyst",
            label_visibility="collapsed",
            key="resolve_analyst_input"
        )

        c1, c2 = st.columns([1, 1])
        with c1:
            submitted = st.form_submit_button(
                f"✅ Confirm {action_label}",
                type="primary",
                use_container_width=True
            )
        with c2:
            cancelled = st.form_submit_button(
                "✖ Cancel",
                use_container_width=True
            )

    if submitted:
        result = alert_system.update_alert_status(
            alert_id=alert_id,
            new_status=action,
            user=analyst or 'analyst',
            notes=notes or None,
        )
        st.session_state.resolve_modal_alert_id = None

        if result['success']:
            st.toast(f"✅ {result['message']}", icon="✅")
        else:
            st.toast(f"❌ {result['message']}", icon="❌")

        st.rerun()

    if cancelled:
        st.session_state.resolve_modal_alert_id = None
        st.rerun()


# ============================================
# METRICS
# ============================================

def _render_metrics(alert_system):
    summary = alert_system.get_today_summary()

    c1, c2, c3, c4 = st.columns(4)

    with c1:
        _metric_card("Total", summary.get('total_alerts', 0), "#3b82f6", "📋")
    with c2:
        _metric_card("🔴 Critical", summary.get('critical', 0), "#ef4444", "🔴")
    with c3:
        _metric_card("🟠 High", summary.get('high', 0), "#f97316", "🟠")
    with c4:
        _metric_card("🆕 New", summary.get('new_alerts', 0), "#f59e0b", "🆕")


def _metric_card(label, value, color, icon):
    st.markdown(f"""
    <div style="background:rgba(30,41,59,0.5); border-radius:12px; padding:16px;
                text-align:center; border:1px solid {color}44;">
        <div style="font-size:1.6rem;">{icon}</div>
        <div style="font-family:'JetBrains Mono', monospace; font-size:1.8rem;
                    font-weight:800; color:{color}; line-height:1; margin:6px 0;">
            {value}
        </div>
        <div style="color:#94a3b8; font-size:0.7rem; font-weight:700;
                    letter-spacing:1.5px; text-transform:uppercase;">{label}</div>
    </div>
    """, unsafe_allow_html=True)


# ============================================
# FILTERS
# ============================================

def _render_filters_and_controls():
    col1, col2, col3, col4 = st.columns([2, 1, 1, 1])

    with col1:
        search = st.text_input(
            "Search",
            placeholder="🔍 Search by IP, description, or type...",
            label_visibility="collapsed",
            key="alerts_search"
        )
        st.session_state['alerts_search_term'] = search

    with col2:
        severity = st.selectbox(
            "Severity",
            ["All", "critical", "high", "medium", "low"],
            label_visibility="collapsed",
            key="alerts_severity_filter"
        )

    with col3:
        status = st.selectbox(
            "Status",
            ["Active", "new", "acknowledged", "investigating", "All"],
            label_visibility="collapsed",
            key="alerts_status_filter"
        )

    with col4:
        if st.button("🔄 Refresh", use_container_width=True):
            st.rerun()


# ============================================
# ACTIVE ALERTS LIST
# ============================================

def _render_active_alerts(alert_system):
    st.markdown('<p class="sub-header">📋 Active Alerts</p>', unsafe_allow_html=True)

    # Build query
    query = "SELECT * FROM alerts WHERE 1=1"
    params = []

    severity_filter = st.session_state.get('alerts_severity_filter', 'All')
    status_filter = st.session_state.get('alerts_status_filter', 'Active')
    search_term = st.session_state.get('alerts_search_term', '')

    if severity_filter != 'All':
        query += " AND severity = %s"
        params.append(severity_filter)

    if status_filter == 'Active':
        query += " AND status IN ('new', 'acknowledged', 'investigating')"
    elif status_filter != 'All':
        query += " AND status = %s"
        params.append(status_filter)

    if search_term:
        query += " AND (source_ip LIKE %s OR description LIKE %s OR alert_type LIKE %s)"
        like = f"%{search_term}%"
        params.extend([like, like, like])

    query += """
        ORDER BY FIELD(severity, 'critical', 'high', 'medium', 'low'),
                 timestamp DESC
        LIMIT 100
    """

    try:
        alerts = db_manager.execute_query(query, tuple(params) if params else None)
    except Exception as e:
        st.error(f"Failed to load alerts: {e}")
        return

    if not alerts:
        st.markdown("""
        <div style="text-align:center; padding:40px 20px;
                    background:rgba(16,185,129,0.05); border:1px solid rgba(16,185,129,0.2);
                    border-radius:16px;">
            <div style="font-size:3rem;">✨</div>
            <h3 style="color:#10b981; margin:10px 0;">All Clear</h3>
            <p style="color:#94a3b8;">No alerts matching your filters.</p>
        </div>
        """, unsafe_allow_html=True)
        return

    st.caption(f"Showing {len(alerts)} alerts")

    for alert in alerts:
        _render_alert_card(alert, alert_system)


def _render_alert_card(alert, alert_system):
    """Render a single alert with working action buttons"""

    alert_id = alert['alert_id']
    severity = alert.get('severity', 'low')
    status = alert.get('status', 'new')

    # Icons and colors
    severity_icon = {
        'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🔵'
    }.get(severity, '⚪')

    status_icon = {
        'new': '🆕', 'acknowledged': '👁️',
        'investigating': '🔍', 'resolved': '✅', 'false_positive': '🚫'
    }.get(status, '❓')

    title = f"{severity_icon} [{severity.upper()}] {alert.get('description', 'Alert')[:80]}"

    with st.expander(f"{title}   ·   {status_icon} {status}", expanded=False):
        # -------- Details --------
        c1, c2 = st.columns(2)
        with c1:
            st.markdown(f"**Type:** `{alert.get('alert_type', 'N/A')}`")
            st.markdown(f"**Source IP:** `{alert.get('source_ip', 'N/A')}`")
            st.markdown(f"**Destination IP:** `{alert.get('destination_ip') or '—'}`")
        with c2:
            st.markdown(f"**Status:** `{status}`")
            st.markdown(f"**Severity:** `{severity}`")
            st.markdown(f"**Time:** `{str(alert.get('timestamp', ''))[:19]}`")

        st.markdown(f"**Description:** {alert.get('description', 'N/A')}")

        if alert.get('resolved_by'):
            st.markdown(f"**Resolved by:** `{alert['resolved_by']}`")
        if alert.get('resolution_notes'):
            st.markdown(f"**Notes:** {alert['resolution_notes']}")

        st.markdown("---")

        # -------- Actions --------
        _render_alert_actions(alert_id, status, alert_system)


def _render_alert_actions(alert_id, status, alert_system):
    """Action buttons — only valid transitions shown"""

    # Define all possible actions
    all_actions = [
        ('acknowledged', '✅ Acknowledge', 'secondary'),
        ('investigating', '🔍 Investigate', 'secondary'),
        ('resolved', '✔️ Resolve', 'primary'),
        ('false_positive', '🚫 False Positive', 'secondary'),
    ]

    # Show actions based on current status
    if status in ('resolved', 'false_positive'):
        # Only allow reopen
        c1, c2 = st.columns([1, 3])
        with c1:
            if st.button("🔄 Reopen", key=f"reopen_{alert_id}",
                         use_container_width=True):
                result = alert_system.update_alert_status(
                    alert_id=alert_id,
                    new_status='investigating',
                    user='analyst',
                    notes='Reopened for further review'
                )
                if result['success']:
                    st.toast(f"✅ {result['message']}", icon="✅")
                else:
                    st.toast(f"❌ {result['message']}", icon="❌")
                st.rerun()
        with c2:
            st.caption(f"This alert is **{status}**. Reopen to review again.")
        return

    # Active status — show valid transitions
    cols = st.columns(4)

    # Determine valid next states
    valid_states = alert_system.VALID_TRANSITIONS.get(status, set())

    # Acknowledge
    with cols[0]:
        if 'acknowledged' in valid_states:
            if st.button("✅ Acknowledge", key=f"ack_{alert_id}",
                         use_container_width=True):
                result = alert_system.update_alert_status(
                    alert_id=alert_id,
                    new_status='acknowledged',
                    user='analyst'
                )
                if result['success']:
                    st.toast(f"✅ {result['message']}", icon="✅")
                else:
                    st.toast(f"❌ {result['message']}", icon="❌")
                st.rerun()
        else:
            st.button("✅ Acknowledge", key=f"ack_disabled_{alert_id}",
                     disabled=True, use_container_width=True,
                     help="Already acknowledged or not applicable")

    # Investigate
    with cols[1]:
        if 'investigating' in valid_states:
            if st.button("🔍 Investigate", key=f"inv_{alert_id}",
                         use_container_width=True):
                result = alert_system.update_alert_status(
                    alert_id=alert_id,
                    new_status='investigating',
                    user='analyst'
                )
                if result['success']:
                    st.toast(f"✅ {result['message']}", icon="✅")
                else:
                    st.toast(f"❌ {result['message']}", icon="❌")
                st.rerun()
        else:
            st.button("🔍 Investigate", key=f"inv_disabled_{alert_id}",
                     disabled=True, use_container_width=True)

    # Resolve (opens modal)
    with cols[2]:
        if 'resolved' in valid_states:
            if st.button("✔️ Resolve", key=f"res_{alert_id}",
                         type="primary", use_container_width=True):
                st.session_state.resolve_modal_alert_id = alert_id
                st.session_state.resolve_modal_action = 'resolved'
                st.rerun()
        else:
            st.button("✔️ Resolve", key=f"res_disabled_{alert_id}",
                     disabled=True, use_container_width=True)

    # False Positive (opens modal)
    with cols[3]:
        if 'false_positive' in valid_states:
            if st.button("🚫 False Positive", key=f"fp_{alert_id}",
                         use_container_width=True):
                st.session_state.resolve_modal_alert_id = alert_id
                st.session_state.resolve_modal_action = 'false_positive'
                st.rerun()
        else:
            st.button("🚫 False Positive", key=f"fp_disabled_{alert_id}",
                     disabled=True, use_container_width=True)


# ============================================
# BULK ACTIONS
# ============================================

def _render_bulk_actions(alert_system):
    """Bulk action bar with quick resolve"""

    with st.expander("⚡ Bulk Actions"):
        st.caption(
            "Bulk update alerts by filters. Useful when many alerts share the "
            "same root cause (e.g., a known bad IP flooded you with alerts)."
        )

        c1, c2, c3, c4 = st.columns(4)
        with c1:
            bulk_severity = st.selectbox(
                "Severity to bulk-update",
                ["high", "critical", "medium", "low"],
                key="bulk_severity"
            )
        with c2:
            bulk_action = st.selectbox(
                "New status",
                ["acknowledged", "investigating", "resolved", "false_positive"],
                key="bulk_action"
            )
        with c3:
            bulk_notes = st.text_input(
                "Notes (optional)",
                key="bulk_notes",
                placeholder="Bulk resolution..."
            )
        with c4:
            st.markdown("<div style='height:28px;'></div>", unsafe_allow_html=True)
            run_bulk = st.button("⚡ Apply to All", type="primary",
                                use_container_width=True)

        if run_bulk:
            # Find all matching alerts in 'new' or 'acknowledged' state
            try:
                matches = db_manager.execute_query("""
                    SELECT alert_id FROM alerts
                    WHERE severity = %s
                      AND status IN ('new', 'acknowledged', 'investigating')
                """, (bulk_severity,))
            except Exception as e:
                st.error(f"Query failed: {e}")
                return

            if not matches:
                st.warning(f"No active {bulk_severity} alerts to update.")
                return

            ids = [m['alert_id'] for m in matches]
            result = alert_system.bulk_update(
                ids, bulk_action, user='analyst', notes=bulk_notes or 'Bulk update'
            )

            st.toast(
                f"✅ Updated {result['success']} alerts, {result['failed']} failed",
                icon="✅"
            )
            st.rerun()


# ============================================
# RESOLVED ARCHIVE
# ============================================

def _render_resolved_archive(alert_system):
    """Resolved and false-positive alerts — HTML rendering (no Arrow issues)"""

    with st.expander("📚 Resolved Alerts Archive"):
        try:
            resolved = alert_system.get_resolved_alerts(limit=50)
        except Exception as e:
            st.error(f"Failed to load archive: {e}")
            return

        if not resolved:
            st.info("No resolved alerts yet.")
            return

        st.caption(f"Showing {len(resolved)} most recent resolved alerts")

        # ---------- Build HTML table (bypasses Arrow completely) ----------
        def esc(v):
            """Escape and stringify any value safely"""
            if v is None:
                return "—"
            s = str(v)
            # HTML-escape basic chars
            s = (s.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;"))
            if len(s) > 120:
                s = s[:120] + "…"
            return s

        rows_html = ""
        for a in resolved:
            severity = (a.get('severity') or '').lower()
            sev_colors = {
                'critical': '#ef4444',
                'high': '#f97316',
                'medium': '#f59e0b',
                'low': '#3b82f6',
            }
            sev_color = sev_colors.get(severity, '#94a3b8')

            rows_html += f"""
            <tr style="border-bottom:1px solid rgba(96,165,250,0.08);">
                <td style="padding:10px 12px; color:#60a5fa;
                           font-family:'JetBrains Mono'; font-size:0.8rem;">
                    #{esc(a.get('alert_id'))}
                </td>
                <td style="padding:10px 12px;">
                    <span style="background:{sev_color}22; color:{sev_color};
                                 padding:2px 8px; border-radius:6px;
                                 font-size:0.7rem; font-weight:700;
                                 text-transform:uppercase;">
                        {esc(a.get('severity'))}
                    </span>
                </td>
                <td style="padding:10px 12px; color:#a78bfa;
                           font-family:'JetBrains Mono'; font-size:0.78rem;">
                    {esc(a.get('status'))}
                </td>
                <td style="padding:10px 12px; color:#e2e8f0;
                           font-family:'JetBrains Mono'; font-size:0.78rem;">
                    {esc(a.get('source_ip'))}
                </td>
                <td style="padding:10px 12px; color:#e2e8f0; font-size:0.8rem;">
                    {esc(a.get('description'))}
                </td>
                <td style="padding:10px 12px; color:#94a3b8; font-size:0.75rem;">
                    {esc(str(a.get('resolved_at'))[:19] if a.get('resolved_at') else None)}
                </td>
                <td style="padding:10px 12px; color:#94a3b8; font-size:0.75rem;">
                    {esc(a.get('resolved_by'))}
                </td>
            </tr>
            """

        html = f"""
        <div style="background:rgba(30,41,59,0.4); border-radius:12px;
                    border:1px solid rgba(96,165,250,0.15); overflow:hidden;">
            <table style="width:100%; border-collapse:collapse;">
                <thead>
                    <tr style="background:rgba(15,23,42,0.6);">
                        <th style="padding:12px; text-align:left; color:#60a5fa;
                                   font-size:0.7rem; letter-spacing:1.5px;
                                   text-transform:uppercase;">ID</th>
                        <th style="padding:12px; text-align:left; color:#60a5fa;
                                   font-size:0.7rem; letter-spacing:1.5px;
                                   text-transform:uppercase;">Severity</th>
                        <th style="padding:12px; text-align:left; color:#60a5fa;
                                   font-size:0.7rem; letter-spacing:1.5px;
                                   text-transform:uppercase;">Status</th>
                        <th style="padding:12px; text-align:left; color:#60a5fa;
                                   font-size:0.7rem; letter-spacing:1.5px;
                                   text-transform:uppercase;">Source IP</th>
                        <th style="padding:12px; text-align:left; color:#60a5fa;
                                   font-size:0.7rem; letter-spacing:1.5px;
                                   text-transform:uppercase;">Description</th>
                        <th style="padding:12px; text-align:left; color:#60a5fa;
                                   font-size:0.7rem; letter-spacing:1.5px;
                                   text-transform:uppercase;">Resolved At</th>
                        <th style="padding:12px; text-align:left; color:#60a5fa;
                                   font-size:0.7rem; letter-spacing:1.5px;
                                   text-transform:uppercase;">By</th>
                    </tr>
                </thead>
                <tbody>
                    {rows_html}
                </tbody>
            </table>
        </div>
        """

        st.markdown(html, unsafe_allow_html=True)