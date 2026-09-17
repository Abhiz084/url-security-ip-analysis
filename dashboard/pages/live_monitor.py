"""
Live Monitor Page - Start/Stop monitoring from the dashboard
"""

import streamlit as st
from datetime import datetime
from src.real_time_monitor.background_monitor import get_live_monitor


def show(session_state):
    st.markdown('<p class="main-header">📡 Live Traffic Monitor</p>', unsafe_allow_html=True)

    monitor = get_live_monitor()
    stats = monitor.get_stats()

    # ============================================
    # STATUS BANNER
    # ============================================
    if stats['is_running']:
        mode = stats['mode'].upper()
        banner_color = "#10b981" if mode == "LIVE" else "#f59e0b"
        banner_bg = "rgba(16,185,129,0.1)" if mode == "LIVE" else "rgba(245,158,11,0.1)"
        banner_text = "🔴 CAPTURING LIVE TRAFFIC" if mode == "LIVE" else "🎲 SIMULATION MODE"

        st.markdown(f"""
        <div style="background:{banner_bg}; border:2px solid {banner_color};
                    border-radius:20px; padding:30px; text-align:center;
                    backdrop-filter:blur(20px); margin-bottom:25px;">
            <div class="live-dot" style="background:{banner_color}; box-shadow:0 0 20px {banner_color};
                 display:inline-block; width:14px; height:14px; border-radius:50%; margin-right:10px;"></div>
            <span style="color:{banner_color}; font-size:1.5rem; font-weight:800; letter-spacing:3px;">
                {banner_text}
            </span>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div style="background:rgba(100,116,139,0.1); border:2px solid #64748b;
                    border-radius:20px; padding:30px; text-align:center; margin-bottom:25px;">
            <span style="color:#94a3b8; font-size:1.3rem; font-weight:700; letter-spacing:3px;">
                ⏸ MONITOR STOPPED
            </span>
        </div>
        """, unsafe_allow_html=True)

    # ============================================
    # CONTROL BUTTONS
    # ============================================
    col1, col2, col3 = st.columns([1, 1, 1])

    with col1:
        if not stats['is_running']:
            if st.button("▶️ START LIVE MONITOR", type="primary", use_container_width=True):
                monitor.start(force_simulation=False)
                st.success("Started! Browse websites to capture URLs.")
                st.rerun()
        else:
            if st.button("⏹ STOP MONITOR", use_container_width=True):
                monitor.stop()
                st.warning("Monitor stopped.")
                st.rerun()

    with col2:
        if not stats['is_running']:
            if st.button("🎲 START (Simulation)", use_container_width=True):
                monitor.start(force_simulation=True)
                st.success("Simulation started!")
                st.rerun()
        else:
            if st.button("🔄 Refresh Stats", use_container_width=True):
                st.rerun()

    with col3:
        if st.button("🗑 Clear Stats", use_container_width=True):
            monitor.stop()
            st.rerun()

    st.markdown('<div class="divider-glow"></div>', unsafe_allow_html=True)

    # ============================================
    # LIVE STATS
    # ============================================
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.markdown(f"""
        <div class="metric-card card-info">
            <div style="font-size:2rem;">📦</div>
            <div class="metric-value">{stats['total_packets']:,}</div>
            <div class="metric-label">Packets</div>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown(f"""
        <div class="metric-card card-safe">
            <div style="font-size:2rem;">🔗</div>
            <div class="metric-value">{stats['total_urls']:,}</div>
            <div class="metric-label">URLs Captured</div>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        st.markdown(f"""
        <div class="metric-card card-warning">
            <div style="font-size:2rem;">🚨</div>
            <div class="metric-value">{stats['total_alerts']:,}</div>
            <div class="metric-label">Threats Detected</div>
        </div>
        """, unsafe_allow_html=True)

    with col4:
        st.markdown(f"""
        <div class="metric-card">
            <div style="font-size:2rem;">🌐</div>
            <div class="metric-value">{stats['unique_domains']:,}</div>
            <div class="metric-label">Unique Domains</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown('<div class="divider-glow"></div>', unsafe_allow_html=True)

    # ============================================
    # RECENT CAPTURED DOMAINS
    # ============================================
    st.markdown('<p class="sub-header">🌐 Recent Captures</p>', unsafe_allow_html=True)

    if stats['recent_domains']:
        for entry in reversed(stats['recent_domains']):
            domain = entry['domain']
            is_suspicious = any(tld in domain for tld in ['.tk', '.ml', '.ga', '.cf', '.xyz', '.work'])
            color = '#ef4444' if is_suspicious else '#10b981'
            icon = '🚨' if is_suspicious else '✅'

            st.markdown(f"""
            <div style="background:rgba(30,41,59,0.5); border-left:4px solid {color};
                        border-radius:12px; padding:12px 18px; margin:6px 0;
                        display:flex; justify-content:space-between; align-items:center;">
                <div>
                    <span style="font-size:1.1rem;">{icon}</span>
                    <span style="color:#e2e8f0; font-family:'JetBrains Mono'; margin-left:8px;">
                        {domain[:60]}
                    </span>
                </div>
                <div>
                    <span class="chip chip-info" style="font-family:'JetBrains Mono'; font-size:0.7rem;">
                        {entry['src_ip']}
                    </span>
                    <span style="color:#64748b; font-size:0.75rem; margin-left:10px;">{entry['time']}</span>
                </div>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.info("👆 Click **START LIVE MONITOR** then browse websites to see captured URLs here.")

    # ============================================
    # INFO PANEL
    # ============================================
    st.markdown('<div class="divider-glow"></div>', unsafe_allow_html=True)

    with st.expander("ℹ️ How does Live Monitoring work?"):
        st.markdown("""
        **Two modes available:**

        1. **Live Capture Mode** (default)  
           - Captures real network traffic from your machine
           - Requires administrator privileges
           - Extracts URLs from HTTP/HTTPS/DNS packets
           - If admin rights are missing, falls back to simulation

        2. **Simulation Mode** (manual)  
           - Generates realistic fake traffic for demo purposes
           - No admin privileges needed
           - Perfect for presentations

        **What it captures:**
        - HTTP requests (full URL + host)
        - HTTPS domains via TLS SNI
        - DNS queries
        - Source IPs and timestamps

        **Threat detection:**
        - Each captured URL is scanned for suspicious TLDs and keywords
        - Alerts are auto-generated for threats
        - Everything is saved to MySQL
        """)