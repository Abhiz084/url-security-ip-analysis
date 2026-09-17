"""
URL Security Using IP-Based Threat Analysis
Main Streamlit Dashboard - Single Page Design (No Sidebar)
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import streamlit as st
import time
from datetime import datetime

st.set_page_config(
    page_title="🛡️ URL Security - IP-Based Threat Analysis",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ============================================
# ULTIMATE CSS - Hide Sidebar + Cyberpunk Theme
# ============================================
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600&display=swap');

    * { font-family: 'Inter', sans-serif; }

    /* COMPLETELY HIDE SIDEBAR */
    [data-testid="stSidebar"] { display: none !important; }
    [data-testid="collapsedControl"] { display: none !important; }
    section[data-testid="stSidebar"] { display: none !important; }

    /* Animated gradient background */
    .stApp {
        background: #0a0e1a;
        background-image:
            radial-gradient(at 20% 20%, rgba(59, 130, 246, 0.15) 0px, transparent 50%),
            radial-gradient(at 80% 30%, rgba(139, 92, 246, 0.15) 0px, transparent 50%),
            radial-gradient(at 50% 80%, rgba(236, 72, 153, 0.1) 0px, transparent 50%);
        background-attachment: fixed;
    }

    /* Matrix grid overlay */
    .stApp::before {
        content: "";
        position: fixed;
        top: 0; left: 0; width: 100%; height: 100%;
        background-image:
            linear-gradient(rgba(59,130,246,0.03) 1px, transparent 1px),
            linear-gradient(90deg, rgba(59,130,246,0.03) 1px, transparent 1px);
        background-size: 50px 50px;
        pointer-events: none;
        z-index: 0;
    }

    header[data-testid="stHeader"] { background: transparent !important; }

    .main .block-container {
        padding-top: 1rem;
        padding-bottom: 2rem;
        max-width: 1400px;
    }

    /* Main header */
    .main-header {
        font-size: 2.3rem;
        font-weight: 900;
        background: linear-gradient(135deg, #60a5fa 0%, #a78bfa 50%, #f472b6 100%);
        background-size: 200% 200%;
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        text-align: center;
        padding: 10px 0;
        letter-spacing: -1.5px;
        animation: gradient-shift 4s ease infinite;
    }

    @keyframes gradient-shift {
        0%, 100% { background-position: 0% 50%; }
        50% { background-position: 100% 50%; }
    }

    /* Top brand bar */
    .brand-bar {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 15px 25px;
        background: rgba(30, 41, 59, 0.5);
        backdrop-filter: blur(20px);
        border-radius: 20px;
        border: 1px solid rgba(96, 165, 250, 0.2);
        margin-bottom: 20px;
    }

    .brand-logo {
        display: flex;
        align-items: center;
        gap: 15px;
    }

    .brand-icon {
        width: 55px; height: 55px;
        border-radius: 50%;
        padding: 3px;
        background: linear-gradient(135deg, #60a5fa, #a78bfa);
        animation: float 3s ease-in-out infinite;
        flex-shrink: 0;
    }

    .brand-icon-inner {
        width: 100%; height: 100%;
        border-radius: 50%;
        background: #0f172a;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 1.6rem;
    }

    .brand-text h1 {
        color: #e2e8f0;
        margin: 0;
        font-size: 1.35rem;
        font-weight: 800;
        letter-spacing: -0.5px;
        line-height: 1.2;
    }

    .brand-text p {
        color: #60a5fa;
        margin: 3px 0 0 0;
        font-size: 0.7rem;
        letter-spacing: 2.5px;
        text-transform: uppercase;
        font-weight: 600;
    }

    /* Status badge */
    .status-badge {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        padding: 8px 18px;
        border-radius: 20px;
        font-size: 0.75rem;
        font-weight: 700;
        letter-spacing: 1.5px;
        white-space: nowrap;
    }

    .status-online {
        background: rgba(16, 185, 129, 0.15);
        color: #10b981;
        border: 1px solid rgba(16, 185, 129, 0.4);
    }

    .status-offline {
        background: rgba(245, 158, 11, 0.15);
        color: #f59e0b;
        border: 1px solid rgba(245, 158, 11, 0.4);
    }

    /* Sub-header */
    .sub-header {
        font-size: 1.3rem;
        font-weight: 700;
        color: #e2e8f0;
        margin: 20px 0 15px 0;
        padding-left: 15px;
        border-left: 4px solid;
        border-image: linear-gradient(180deg, #60a5fa, #a78bfa, #f472b6) 1;
    }

    /* Glassmorphism metric cards */
    .metric-card {
        background: rgba(30, 41, 59, 0.6);
        backdrop-filter: blur(20px);
        border-radius: 20px;
        padding: 24px;
        text-align: center;
        border: 1px solid rgba(96, 165, 250, 0.2);
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
        transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
        position: relative;
        overflow: hidden;
    }

    .metric-card::before {
        content: '';
        position: absolute;
        top: 0; left: -100%;
        width: 100%; height: 100%;
        background: linear-gradient(90deg, transparent, rgba(96,165,250,0.1), transparent);
        transition: left 0.6s;
    }

    .metric-card:hover::before { left: 100%; }

    .metric-card:hover {
        transform: translateY(-8px) scale(1.02);
        border-color: rgba(96, 165, 250, 0.6);
        box-shadow: 0 20px 60px rgba(96, 165, 250, 0.25);
    }

    .metric-value {
        font-family: 'JetBrains Mono', monospace;
        font-size: 2.5rem;
        font-weight: 700;
        background: linear-gradient(135deg, #60a5fa, #a78bfa);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        letter-spacing: -2px;
        line-height: 1;
        margin: 10px 0;
    }

    .metric-label {
        font-size: 0.75rem;
        color: #94a3b8;
        text-transform: uppercase;
        letter-spacing: 2px;
        font-weight: 600;
    }

    .card-safe { border-color: rgba(16, 185, 129, 0.4); }
    .card-safe .metric-value { background: linear-gradient(135deg, #10b981, #34d399); -webkit-background-clip: text; background-clip: text; }

    .card-danger { border-color: rgba(239, 68, 68, 0.4); }
    .card-danger .metric-value { background: linear-gradient(135deg, #ef4444, #f87171); -webkit-background-clip: text; background-clip: text; }

    .card-warning { border-color: rgba(245, 158, 11, 0.4); }
    .card-warning .metric-value { background: linear-gradient(135deg, #f59e0b, #fbbf24); -webkit-background-clip: text; background-clip: text; }

    .card-info { border-color: rgba(59, 130, 246, 0.4); }

    /* Buttons */
    .stButton > button {
        background: rgba(30, 41, 59, 0.6);
        color: #e2e8f0;
        border: 1px solid rgba(96, 165, 250, 0.2);
        border-radius: 12px;
        padding: 12px 20px;
        font-weight: 600;
        font-size: 0.9rem;
        letter-spacing: 0.5px;
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        width: 100%;
    }

    .stButton > button:hover {
        background: rgba(59, 130, 246, 0.2);
        border-color: #60a5fa;
        transform: translateY(-2px);
        box-shadow: 0 8px 25px rgba(59, 130, 246, 0.3);
        color: #ffffff;
    }

    .stButton > button[kind="primary"] {
        background: linear-gradient(135deg, #3b82f6 0%, #8b5cf6 100%);
        color: white;
        border: none;
        box-shadow: 0 4px 20px rgba(59, 130, 246, 0.4);
    }

    .stButton > button[kind="primary"]:hover {
        transform: translateY(-3px);
        box-shadow: 0 8px 30px rgba(59, 130, 246, 0.6);
    }

    /* Text inputs */
    .stTextInput > div > div > input {
        background: rgba(15, 23, 42, 0.6) !important;
        backdrop-filter: blur(10px);
        border: 2px solid rgba(96, 165, 250, 0.2) !important;
        border-radius: 12px !important;
        color: #e2e8f0 !important;
        padding: 14px 18px !important;
        font-size: 1rem !important;
        font-family: 'JetBrains Mono', monospace !important;
    }

    .stTextInput > div > div > input:focus {
        border-color: #60a5fa !important;
        box-shadow: 0 0 0 3px rgba(96, 165, 250, 0.2) !important;
    }

    /* Alert cards */
    .alert-card {
        background: rgba(30, 41, 59, 0.5);
        backdrop-filter: blur(10px);
        border-radius: 12px;
        padding: 16px 20px;
        margin: 10px 0;
        border-left: 4px solid;
        transition: all 0.3s;
    }

    .alert-card:hover {
        transform: translateX(5px);
        background: rgba(30, 41, 59, 0.7);
    }

    .alert-critical { border-left-color: #ef4444; }
    .alert-high { border-left-color: #f97316; }
    .alert-medium { border-left-color: #eab308; }
    .alert-low { border-left-color: #3b82f6; }

    /* Dataframes */
    [data-testid="stDataFrame"] {
        background: rgba(30, 41, 59, 0.4);
        backdrop-filter: blur(10px);
        border-radius: 16px;
        border: 1px solid rgba(96, 165, 250, 0.15);
    }

    /* Expanders */
    .streamlit-expanderHeader {
        background: rgba(30, 41, 59, 0.5) !important;
        backdrop-filter: blur(10px);
        border-radius: 12px !important;
        border: 1px solid rgba(96, 165, 250, 0.15) !important;
        font-weight: 600 !important;
    }

    /* Scrollbar */
    ::-webkit-scrollbar { width: 10px; height: 10px; }
    ::-webkit-scrollbar-track { background: #0a0e1a; }
    ::-webkit-scrollbar-thumb {
        background: linear-gradient(180deg, #3b82f6, #8b5cf6);
        border-radius: 5px;
    }

    /* Animations */
    @keyframes pulse {
        0%, 100% { opacity: 1; transform: scale(1); }
        50% { opacity: 0.5; transform: scale(1.1); }
    }

    @keyframes float {
        0%, 100% { transform: translateY(0px); }
        50% { transform: translateY(-8px); }
    }

    .live-dot {
        display: inline-block;
        width: 10px; height: 10px;
        background: #10b981;
        border-radius: 50%;
        animation: pulse 2s infinite;
        box-shadow: 0 0 15px #10b981;
    }

    /* Chips */
    .chip {
        display: inline-block;
        padding: 4px 12px;
        border-radius: 20px;
        font-size: 0.7rem;
        font-weight: 700;
        letter-spacing: 0.5px;
        text-transform: uppercase;
        margin: 2px;
    }

    .chip-critical { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }
    .chip-high { background: rgba(249, 115, 22, 0.2); color: #fb923c; border: 1px solid rgba(249, 115, 22, 0.4); }
    .chip-medium { background: rgba(234, 179, 8, 0.2); color: #facc15; border: 1px solid rgba(234, 179, 8, 0.4); }
    .chip-low { background: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.4); }
    .chip-safe { background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.4); }
    .chip-info { background: rgba(139, 92, 246, 0.2); color: #a78bfa; border: 1px solid rgba(139, 92, 246, 0.4); }

    /* Divider */
    .divider-glow {
        height: 1px;
        background: linear-gradient(90deg, transparent, rgba(96,165,250,0.5), transparent);
        margin: 25px 0;
        border: none;
    }

    /* Hero */
    .hero {
        text-align: center;
        padding: 50px 20px;
    }

    .hero-icon {
        font-size: 7rem;
        animation: float 4s ease-in-out infinite;
        filter: drop-shadow(0 0 40px rgba(96, 165, 250, 0.5));
    }

    /* Footer */
    .footer {
        text-align: center;
        padding: 25px 20px;
        margin-top: 40px;
        border-top: 1px solid rgba(96, 165, 250, 0.15);
        color: #64748b;
        font-size: 0.8rem;
    }

    /* Hide Streamlit branding */
    #MainMenu { visibility: hidden; }
    footer { visibility: hidden; }
</style>
""", unsafe_allow_html=True)

# ============================================
# SESSION STATE
# ============================================
for key in ['predictor', 'alert_system', 'initialized', 'auto_refresh', 'current_page']:
    if key not in st.session_state:
        if key in ['predictor', 'alert_system']:
            st.session_state[key] = None
        elif key == 'initialized':
            st.session_state[key] = False
        elif key == 'auto_refresh':
            st.session_state[key] = True
        elif key == 'current_page':
            st.session_state[key] = "🏠 Dashboard"

# Auto-refresh
if st.session_state.get('initialized') and st.session_state.get('auto_refresh'):
    st.markdown("<script>setTimeout(function(){window.location.reload();}, 30000);</script>", unsafe_allow_html=True)

# ============================================
# TOP BRAND BAR
# ============================================
status_html = """
<div class="status-badge status-online">
    <span class="live-dot"></span> SYSTEM ONLINE
</div>
""" if st.session_state.initialized else """
<div class="status-badge status-offline">
    ⏳ STANDBY
</div>
"""

st.markdown(f"""
<div class="brand-bar">
    <div class="brand-logo">
        <div class="brand-icon">
            <div class="brand-icon-inner">🛡️</div>
        </div>
        <div class="brand-text">
            <h1>URL Security</h1>
            <p>IP-Based Threat Analysis</p>
        </div>
    </div>
    <div>{status_html}</div>
</div>
""", unsafe_allow_html=True)

# ============================================
# WELCOME / INITIALIZE SCREEN
# ============================================
if not st.session_state.initialized:
    st.markdown("""
    <div class="hero">
        <div class="hero-icon">🛡️</div>
        <h1 style="color:#e2e8f0; margin: 20px 0 10px 0; font-weight:800; letter-spacing:-2px; font-size:2.2rem;">
            URL Security Using IP-Based Threat Analysis
        </h1>
        <p style="color:#94a3b8; font-size:1.05rem; line-height:1.7; max-width:750px; margin: 0 auto;">
            An AI-powered system that detects malicious URLs in real-time by combining
            rule-based heuristics with machine learning and IP-based threat intelligence.
        </p>
        <div style="margin-top: 25px;">
            <span class="chip chip-safe">✓ Real-Time Detection</span>
            <span class="chip chip-info">⚡ ML-Powered</span>
            <span class="chip chip-low">🌐 Live Capture</span>
            <span class="chip chip-medium">🔍 Hybrid Analysis</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Centered Initialize button
    col1, col2, col3 = st.columns([1, 1, 1])
    with col2:
        if st.button("⚡ INITIALIZE SYSTEM", type="primary", use_container_width=True):
            with st.spinner("Starting system..."):
                try:
                    from src.ml_pipeline.prediction import URLPredictor, find_latest_model
                    from src.real_time_monitor.alert_system import AlertSystem

                    model_path = find_latest_model('random_forest')
                    st.session_state.predictor = URLPredictor(model_path) if model_path else URLPredictor()
                    st.session_state.alert_system = AlertSystem()
                    st.session_state.initialized = True

                    # Auto-start live monitor
                    try:
                        from src.real_time_monitor.background_monitor import get_live_monitor
                        monitor = get_live_monitor()
                        monitor.start(force_simulation=False)
                    except Exception as e:
                        pass  # Silent — user can start manually from Live Monitor page

                    st.success("✅ System Ready!")
                    time.sleep(0.8)
                    st.rerun()
                except Exception as e:
                    st.error(f"❌ Failed: {str(e)[:80]}")

    st.markdown('<div class="divider-glow"></div>', unsafe_allow_html=True)

    # Feature cards
    col_a, col_b, col_c = st.columns(3)
    with col_a:
        st.markdown("""
        <div class="metric-card">
            <div style="font-size:2.5rem;">🔍</div>
            <h4 style="color:#e2e8f0; margin:10px 0 5px 0;">Hybrid Detection</h4>
            <p style="color:#94a3b8; font-size:0.85rem; margin:0;">Rule-based + ML models</p>
        </div>
        """, unsafe_allow_html=True)
    with col_b:
        st.markdown("""
        <div class="metric-card">
            <div style="font-size:2.5rem;">📡</div>
            <h4 style="color:#e2e8f0; margin:10px 0 5px 0;">Live Monitoring</h4>
            <p style="color:#94a3b8; font-size:0.85rem; margin:0;">Real-time traffic capture</p>
        </div>
        """, unsafe_allow_html=True)
    with col_c:
        st.markdown("""
        <div class="metric-card">
            <div style="font-size:2.5rem;">🚨</div>
            <h4 style="color:#e2e8f0; margin:10px 0 5px 0;">Instant Alerts</h4>
            <p style="color:#94a3b8; font-size:0.85rem; margin:0;">Auto threat detection</p>
        </div>
        """, unsafe_allow_html=True)

# ============================================
# MAIN DASHBOARD (After Initialize)
# ============================================
else:
    # Top navigation
    nav_cols = st.columns(7)
    pages = [
        ("🏠 Dashboard", "🏠 Dashboard"),
        ("🔍 URL Scanner", "🔍 URL Scanner"),
        ("🌐 IP Intel", "🌐 IP Intelligence"),
        ("📡 Live Monitor", "📡 Live Monitor"),
        ("🚨 Alerts", "🚨 Alerts"),
        ("📈 Analytics", "📈 Analytics"),
        ("📋 Reports", "📋 Reports"),
    ]

    for i, (label, page_value) in enumerate(pages):
        with nav_cols[i]:
            is_active = st.session_state.current_page == page_value
            btn_type = "primary" if is_active else "secondary"
            if st.button(label, key=f"nav_{i}", use_container_width=True, type=btn_type):
                st.session_state.current_page = page_value
                st.rerun()

    st.markdown('<div class="divider-glow"></div>', unsafe_allow_html=True)

    # Controls row
    ctrl_col1, ctrl_col2, ctrl_col3, ctrl_col4 = st.columns([3, 1, 1, 1])
    with ctrl_col1:
        st.markdown(
            f'<span style="color:#64748b; font-size:0.85rem;">🕐 {datetime.now().strftime("%A, %B %d, %Y • %H:%M:%S")}</span>',
            unsafe_allow_html=True
        )
    with ctrl_col2:
        if st.button("🔄 Sync", use_container_width=True):
            st.rerun()
    with ctrl_col3:
        st.session_state.auto_refresh = st.toggle("Auto", value=st.session_state.auto_refresh)
    with ctrl_col4:
        if st.button("🛑 Reset", use_container_width=True):
            st.session_state.initialized = False
            st.rerun()

    st.markdown('<div class="divider-glow"></div>', unsafe_allow_html=True)

    # Route to page
    page = st.session_state.current_page
    if page == "🏠 Dashboard":
        from dashboard.pages import home
        home.show(st.session_state)
    elif page == "🔍 URL Scanner":
        from dashboard.pages import url_scanner
        url_scanner.show(st.session_state)
    elif page == "🌐 IP Intelligence":
        from dashboard.pages import ip_intelligence
        ip_intelligence.show(st.session_state)
    elif page == "📡 Live Monitor":
        from dashboard.pages import live_monitor
        live_monitor.show(st.session_state)
    elif page == "🚨 Alerts":
        from dashboard.pages import alerts
        alerts.show(st.session_state)
    elif page == "📈 Analytics":
        from dashboard.pages import analytics
        analytics.show(st.session_state)
    elif page == "📋 Reports":
        from dashboard.pages import reports
        reports.show(st.session_state)

# ============================================
# FOOTER
# ============================================
st.markdown(f"""
<div class="footer">
    <p style="margin:0; color:#64748b;">
        🛡️ <b style="color:#e2e8f0;">URL Security Using IP-Based Threat Analysis</b>
    </p>
    <p style="margin:5px 0 0 0; font-size:0.75rem;">
        Final Year Project • {datetime.now().strftime('%Y')}
    </p>
</div>
""", unsafe_allow_html=True)