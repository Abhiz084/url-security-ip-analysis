"""
Live Monitor Page - Clickable Cards + Detail Panels

- Metric cards are clickable → show underlying data
- "Clear Stats" clears only in-memory counters (DB untouched)
"""

import streamlit as st
from datetime import datetime
from src.real_time_monitor.background_monitor import get_live_monitor


def show(session_state):
    st.markdown('<p class="main-header">📡 Live Traffic Monitor</p>', unsafe_allow_html=True)

    monitor = get_live_monitor()
    stats = monitor.get_stats()

    # Session state for selected card
    if 'live_detail_view' not in st.session_state:
        st.session_state.live_detail_view = None

    _render_status_banner(stats)
    _render_controls(monitor, stats)
    _render_metric_cards(stats)
    _render_detail_panel(stats)
    _render_help()


# ============================================
# STATUS BANNER
# ============================================

def _render_status_banner(stats):
    if stats['is_running']:
        mode = stats['mode'].upper()
        color = "#10b981" if mode == "LIVE" else "#f59e0b"
        bg = "rgba(16,185,129,0.1)" if mode == "LIVE" else "rgba(245,158,11,0.1)"
        label = "🔴 CAPTURING LIVE TRAFFIC" if mode == "LIVE" else "🎲 SIMULATION MODE"

        st.markdown(f"""
        <div style="background:{bg}; border:2px solid {color};
                    border-radius:20px; padding:24px; text-align:center;
                    backdrop-filter:blur(20px); margin-bottom:20px;">
            <div class="live-dot" style="background:{color};
                 box-shadow:0 0 20px {color}; display:inline-block;
                 width:14px; height:14px; border-radius:50%; margin-right:10px;"></div>
            <span style="color:{color}; font-size:1.3rem; font-weight:800;
                        letter-spacing:3px;">{label}</span>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div style="background:rgba(100,116,139,0.1); border:2px solid #64748b;
                    border-radius:20px; padding:24px; text-align:center; margin-bottom:20px;">
            <span style="color:#94a3b8; font-size:1.2rem; font-weight:700;
                        letter-spacing:3px;">⏸ MONITOR STOPPED</span>
        </div>
        """, unsafe_allow_html=True)


# ============================================
# CONTROLS
# ============================================

def _render_controls(monitor, stats):
    col1, col2, col3, col4 = st.columns([1, 1, 1, 1])

    with col1:
        if not stats['is_running']:
            if st.button("▶️ START LIVE MONITOR", type="primary", use_container_width=True):
                monitor.start(force_simulation=False)
                st.rerun()
        else:
            if st.button("⏹ STOP MONITOR", use_container_width=True):
                monitor.stop()
                st.rerun()

    with col2:
        if not stats['is_running']:
            if st.button("🎲 START (Simulation)", use_container_width=True):
                monitor.start(force_simulation=True)
                st.rerun()
        else:
            if st.button("🔄 Refresh", use_container_width=True):
                st.rerun()

    with col3:
        if st.button("🗑 Clear Stats", use_container_width=True,
                     help="Clears dashboard counters. Does NOT delete DB records."):
            monitor.reset_stats()
            st.session_state.live_detail_view = None
            st.rerun()

    with col4:
        if st.session_state.live_detail_view:
            if st.button("✖ Close Details", use_container_width=True):
                st.session_state.live_detail_view = None
                st.rerun()


# ============================================
# METRIC CARDS (CLICKABLE)
# ============================================

def _render_metric_cards(stats):
    st.markdown('<div style="height:12px;"></div>', unsafe_allow_html=True)

    cards = [
        {
            'key': 'packets',
            'icon': '📦',
            'value': stats['total_packets'],
            'label': 'Packets',
            'color': '#60a5fa',
            'bg': 'rgba(59,130,246,0.08)',
            'border': 'rgba(96,165,250,0.35)',
        },
        {
            'key': 'urls',
            'icon': '🔗',
            'value': stats['total_urls'],
            'label': 'URLs Captured',
            'color': '#10b981',
            'bg': 'rgba(16,185,129,0.08)',
            'border': 'rgba(16,185,129,0.35)',
        },
        {
            'key': 'threats',
            'icon': '🚨',
            'value': stats['total_alerts'],
            'label': 'Threats Detected',
            'color': '#f59e0b',
            'bg': 'rgba(245,158,11,0.08)',
            'border': 'rgba(245,158,11,0.35)',
        },
        {
            'key': 'domains',
            'icon': '🌐',
            'value': stats['unique_domains'],
            'label': 'Unique Domains',
            'color': '#8b5cf6',
            'bg': 'rgba(139,92,246,0.08)',
            'border': 'rgba(139,92,246,0.35)',
        },
    ]

    cols = st.columns(4)
    for col, card in zip(cols, cards):
        with col:
            is_active = st.session_state.live_detail_view == card['key']
            border = card['color'] if is_active else card['border']
            shadow = f"0 0 25px {card['color']}44" if is_active else "none"

            st.markdown(f"""
            <div style="background:{card['bg']}; border:2px solid {border};
                        border-radius:20px; padding:20px; text-align:center;
                        box-shadow:{shadow}; transition: all 0.3s ease;">
                <div style="font-size:2rem;">{card['icon']}</div>
                <div style="font-family:'JetBrains Mono', monospace; font-size:2.2rem;
                            font-weight:800; color:{card['color']}; margin:6px 0;
                            line-height:1;">
                    {card['value']:,}
                </div>
                <div style="color:#94a3b8; font-size:0.7rem; font-weight:700;
                            letter-spacing:2px; text-transform:uppercase;">
                    {card['label']}
                </div>
            </div>
            """, unsafe_allow_html=True)

            # Clickable button below each card
            btn_label = "✖ Hide" if is_active else "🔍 View"
            if st.button(btn_label, key=f"card_btn_{card['key']}",
                         use_container_width=True):
                if is_active:
                    st.session_state.live_detail_view = None
                else:
                    st.session_state.live_detail_view = card['key']
                st.rerun()


# ============================================
# DETAIL PANEL
# ============================================

def _render_detail_panel(stats):
    view = st.session_state.live_detail_view
    if not view:
        st.info("👆 Click **View** under any card above to see details. "
                "Click **Clear Stats** to reset counters without touching the database.")
        return

    st.markdown('<div class="divider-glow"></div>', unsafe_allow_html=True)

    if view == 'packets':
        _show_packets(stats)
    elif view == 'urls':
        _show_urls(stats)
    elif view == 'threats':
        _show_threats(stats)
    elif view == 'domains':
        _show_domains(stats)


# ---------- PACKETS ----------

def _show_packets(stats):
    st.markdown('<p class="sub-header">📦 Recent Packets</p>', unsafe_allow_html=True)

    packets = list(reversed(stats.get('recent_packets', [])))
    if not packets:
        st.info("No packets captured yet. Start the monitor and browse websites.")
        return

    st.caption(f"Showing latest {len(packets)} packets (buffer: {stats['total_packets']:,} total)")

    rows = ""
    for p in packets[:60]:
        rows += f"""
        <tr>
            <td style="padding:8px 12px; border-bottom:1px solid rgba(96,165,250,0.08);
                       color:#94a3b8; font-family:'JetBrains Mono'; font-size:0.78rem;">
                {p['time']}
            </td>
            <td style="padding:8px 12px; border-bottom:1px solid rgba(96,165,250,0.08);
                       color:#e2e8f0; font-family:'JetBrains Mono'; font-size:0.78rem;">
                {p['src_ip']}:{p['src_port']}
            </td>
            <td style="padding:8px 12px; border-bottom:1px solid rgba(96,165,250,0.08);
                       color:#e2e8f0; font-family:'JetBrains Mono'; font-size:0.78rem;">
                {p['dst_ip']}:{p['dst_port']}
            </td>
            <td style="padding:8px 12px; border-bottom:1px solid rgba(96,165,250,0.08);
                       text-align:center;">
                <span style="background:rgba(59,130,246,0.15); color:#60a5fa;
                             padding:2px 8px; border-radius:6px; font-size:0.7rem;
                             font-weight:700;">{p['protocol']}</span>
            </td>
            <td style="padding:8px 12px; border-bottom:1px solid rgba(96,165,250,0.08);
                       color:#94a3b8; font-family:'JetBrains Mono'; font-size:0.78rem;
                       text-align:right;">
                {p['size']} B
            </td>
        </tr>
        """

    st.markdown(f"""
    <div style="background:rgba(30,41,59,0.4); border-radius:12px;
                border:1px solid rgba(96,165,250,0.15); overflow:hidden;">
        <table style="width:100%; border-collapse:collapse;">
            <thead>
                <tr style="background:rgba(15,23,42,0.6);">
                    <th style="padding:10px 12px; text-align:left; color:#60a5fa;
                               font-size:0.7rem; letter-spacing:1.5px;
                               text-transform:uppercase;">Time</th>
                    <th style="padding:10px 12px; text-align:left; color:#60a5fa;
                               font-size:0.7rem; letter-spacing:1.5px;
                               text-transform:uppercase;">Source</th>
                    <th style="padding:10px 12px; text-align:left; color:#60a5fa;
                               font-size:0.7rem; letter-spacing:1.5px;
                               text-transform:uppercase;">Destination</th>
                    <th style="padding:10px 12px; text-align:center; color:#60a5fa;
                               font-size:0.7rem; letter-spacing:1.5px;
                               text-transform:uppercase;">Protocol</th>
                    <th style="padding:10px 12px; text-align:right; color:#60a5fa;
                               font-size:0.7rem; letter-spacing:1.5px;
                               text-transform:uppercase;">Size</th>
                </tr>
            </thead>
            <tbody>{rows}</tbody>
        </table>
    </div>
    """, unsafe_allow_html=True)


# ---------- URLS ----------

def _show_urls(stats):
    st.markdown('<p class="sub-header">🔗 Recently Captured URLs</p>', unsafe_allow_html=True)

    urls = list(reversed(stats.get('recent_domains', [])))
    if not urls:
        st.info("No URLs captured yet. Start the monitor and browse websites.")
        return

    st.caption(f"Showing latest {len(urls)} URLs (buffer: {stats['total_urls']:,} total)")

    for u in urls:
        domain = u['domain']
        is_suspicious = any(tld in domain for tld in
                            ['.tk', '.ml', '.ga', '.cf', '.xyz', '.work', '.icu'])
        color = '#ef4444' if is_suspicious else '#10b981'
        icon = '🚨' if is_suspicious else '✅'

        st.markdown(f"""
        <div style="background:rgba(30,41,59,0.5); border-left:4px solid {color};
                    border-radius:10px; padding:12px 16px; margin:6px 0;
                    display:flex; justify-content:space-between; align-items:center;
                    flex-wrap:wrap; gap:8px;">
            <div style="flex:1; min-width:200px;">
                <span style="font-size:1rem;">{icon}</span>
                <span style="color:#e2e8f0; font-family:'JetBrains Mono';
                            font-size:0.85rem; margin-left:8px; word-break:break-all;">
                    {u['url'][:100]}
                </span>
            </div>
            <div style="display:flex; gap:8px; align-items:center;">
                <span style="background:rgba(139,92,246,0.15); color:#a78bfa;
                            padding:2px 10px; border-radius:8px;
                            font-family:'JetBrains Mono'; font-size:0.7rem;">
                    {u['src_ip']}
                </span>
                <span style="color:#64748b; font-size:0.75rem;">{u['time']}</span>
            </div>
        </div>
        """, unsafe_allow_html=True)


# ---------- THREATS ----------

def _show_threats(stats):
    st.markdown('<p class="sub-header">🚨 Detected Threats</p>', unsafe_allow_html=True)

    threats = list(reversed(stats.get('recent_threats', [])))
    if not threats:
        st.markdown("""
        <div style="text-align:center; padding:40px 20px;
                    background:rgba(16,185,129,0.05);
                    border:1px solid rgba(16,185,129,0.2);
                    border-radius:16px;">
            <div style="font-size:3rem;">✨</div>
            <h3 style="color:#10b981; margin:10px 0;">All Clear</h3>
            <p style="color:#94a3b8;">No threats detected in this session.</p>
        </div>
        """, unsafe_allow_html=True)
        return

    st.caption(f"Showing latest {len(threats)} threats (buffer: {stats['total_alerts']:,} total)")

    for t in threats:
        st.markdown(f"""
        <div style="background:rgba(239,68,68,0.08); border:1px solid rgba(239,68,68,0.4);
                    border-left:4px solid #ef4444; border-radius:12px;
                    padding:14px 18px; margin:8px 0;">
            <div style="display:flex; justify-content:space-between;
                        align-items:center; flex-wrap:wrap; gap:8px; margin-bottom:6px;">
                <span style="color:#f87171; font-weight:700; font-size:0.9rem;">
                    🚨 {t['severity'].upper()}
                </span>
                <div style="display:flex; gap:8px;">
                    <span style="background:rgba(239,68,68,0.15); color:#f87171;
                                padding:2px 10px; border-radius:8px;
                                font-family:'JetBrains Mono'; font-size:0.7rem;">
                        {t['src_ip']}
                    </span>
                    <span style="color:#64748b; font-size:0.75rem;">{t['time']}</span>
                </div>
            </div>
            <div style="color:#e2e8f0; font-family:'JetBrains Mono';
                        font-size:0.85rem; word-break:break-all; margin-bottom:6px;">
                {t['url'][:120]}
            </div>
            <div style="color:#94a3b8; font-size:0.78rem;">
                <b>Reason:</b> {t['reason']}
            </div>
        </div>
        """, unsafe_allow_html=True)


# ---------- DOMAINS ----------

def _show_domains(stats):
    st.markdown('<p class="sub-header">🌐 All Unique Domains</p>', unsafe_allow_html=True)

    domains = stats.get('all_domains', [])
    if not domains:
        st.info("No domains captured yet.")
        return

    st.caption(f"Showing {len(domains)} unique domains seen in this session")

    # Split into columns
    cols = st.columns(3)
    per_col = (len(domains) + 2) // 3

    for i, col in enumerate(cols):
        chunk = domains[i * per_col:(i + 1) * per_col]
        with col:
            for d in chunk:
                is_suspicious = any(tld in d for tld in
                                    ['.tk', '.ml', '.ga', '.cf', '.xyz',
                                     '.work', '.icu', '.click'])
                color = '#ef4444' if is_suspicious else '#10b981'
                icon = '🚨' if is_suspicious else '✅'
                st.markdown(f"""
                <div style="background:rgba(30,41,59,0.4); border-radius:8px;
                            padding:8px 12px; margin:4px 0; border-left:3px solid {color};">
                    <span>{icon}</span>
                    <span style="color:#e2e8f0; font-family:'JetBrains Mono';
                                font-size:0.78rem; margin-left:6px;
                                word-break:break-all;">{d}</span>
                </div>
                """, unsafe_allow_html=True)


# ============================================
# HELP PANEL
# ============================================

def _render_help():
    st.markdown('<div class="divider-glow"></div>', unsafe_allow_html=True)

    with st.expander("ℹ️ How does Live Monitoring work?"):
        st.markdown("""
        **Two modes available:**

        1. **Live Capture** (default)  
           - Captures real network traffic from your machine
           - Requires administrator privileges
           - Extracts URLs from HTTP/HTTPS/DNS packets
           - If admin rights are missing, falls back to simulation

        2. **Simulation** (manual)  
           - Generates realistic fake traffic for demos
           - No admin privileges needed
           - Perfect for presentations

        **Clickable cards:**  
        Click **View** under any metric card to inspect its underlying data.
        Click **Close Details** or **✖ Hide** to collapse.

        **Clear Stats vs Database:**  
        🗑 **Clear Stats** resets the dashboard counters (in-memory only).  
        ✅ URLs and alerts already persisted to MySQL remain intact and are
        still visible on the **Alerts** and **Analytics** pages.
        """)