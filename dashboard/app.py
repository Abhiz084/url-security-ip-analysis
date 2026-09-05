"""
URL Security Dashboard - Professional Modern UI with Auto-Refresh
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import streamlit as st
import time
from datetime import datetime
from streamlit_autorefresh import st_autorefresh



# MUST be first Streamlit command
st.set_page_config(
    page_title="🛡️ URL Security - Threat Analysis",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================
# CUSTOM CSS - Modern Professional Theme
# ============================================
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');
    
    * {
        font-family: 'Inter', sans-serif;
    }
    
    .stApp {
        background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #0f172a 100%);
    }
    
    .main .block-container {
        padding-top: 2rem;
    }
    
    .main-header {
        font-size: 2.8rem;
        font-weight: 800;
        background: linear-gradient(135deg, #60a5fa, #a78bfa, #f472b6);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        text-align: center;
        padding: 20px;
        margin-bottom: 10px;
        letter-spacing: -1px;
    }
    
    .sub-header {
        font-size: 1.5rem;
        font-weight: 700;
        color: #e2e8f0;
        margin-bottom: 1rem;
        border-bottom: 2px solid #334155;
        padding-bottom: 10px;
    }
    
    .metric-card {
        background: linear-gradient(135deg, #1e293b, #334155);
        border-radius: 16px;
        padding: 24px;
        text-align: center;
        border: 1px solid #475569;
        box-shadow: 0 4px 6px rgba(0,0,0,0.3);
        transition: transform 0.3s ease, box-shadow 0.3s ease;
    }
    
    .metric-card:hover {
        transform: translateY(-5px);
        box-shadow: 0 10px 25px rgba(96, 165, 250, 0.2);
        border-color: #60a5fa;
    }
    
    .metric-value {
        font-size: 2.5rem;
        font-weight: 800;
        background: linear-gradient(135deg, #60a5fa, #a78bfa);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
    }
    
    .metric-label {
        font-size: 0.9rem;
        color: #94a3b8;
        text-transform: uppercase;
        letter-spacing: 1px;
        margin-top: 5px;
    }
    
    .card-safe {
        background: linear-gradient(135deg, #064e3b, #065f46);
        border: 1px solid #10b981;
    }
    
    .card-danger {
        background: linear-gradient(135deg, #7f1d1d, #991b1b);
        border: 1px solid #ef4444;
    }
    
    .card-warning {
        background: linear-gradient(135deg, #78350f, #92400e);
        border: 1px solid #f59e0b;
    }
    
    .card-info {
        background: linear-gradient(135deg, #1e3a5f, #1e40af);
        border: 1px solid #3b82f6;
    }
    
    .alert-critical {
        background: linear-gradient(90deg, #7f1d1d, #1e293b);
        border-left: 4px solid #ef4444;
        padding: 12px 16px;
        border-radius: 8px;
        margin: 8px 0;
    }
    
    .alert-high {
        background: linear-gradient(90deg, #78350f, #1e293b);
        border-left: 4px solid #f97316;
        padding: 12px 16px;
        border-radius: 8px;
        margin: 8px 0;
    }
    
    .alert-medium {
        background: linear-gradient(90deg, #713f12, #1e293b);
        border-left: 4px solid #eab308;
        padding: 12px 16px;
        border-radius: 8px;
        margin: 8px 0;
    }
    
    .alert-low {
        background: linear-gradient(90deg, #1e3a5f, #1e293b);
        border-left: 4px solid #3b82f6;
        padding: 12px 16px;
        border-radius: 8px;
        margin: 8px 0;
    }
    
    .stButton > button {
        background: linear-gradient(135deg, #3b82f6, #8b5cf6);
        color: white;
        border: none;
        border-radius: 10px;
        padding: 10px 24px;
        font-weight: 600;
        font-size: 0.95rem;
        transition: all 0.3s ease;
        box-shadow: 0 4px 15px rgba(59, 130, 246, 0.3);
    }
    
    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 25px rgba(59, 130, 246, 0.5);
    }
    
    .stTextInput > div > div > input {
        background: #1e293b;
        border: 2px solid #475569;
        border-radius: 10px;
        color: #e2e8f0;
        padding: 12px;
        font-size: 1rem;
    }
    
    .stTextInput > div > div > input:focus {
        border-color: #60a5fa;
        box-shadow: 0 0 15px rgba(96, 165, 250, 0.3);
    }
    
    .stSelectbox > div > div > select {
        background: #1e293b;
        border: 2px solid #475569;
        border-radius: 10px;
        color: #e2e8f0;
    }
    
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0f172a, #1e293b);
        border-right: 1px solid #334155;
    }
    
    [data-testid="stSidebar"] * {
        color: #e2e8f0;
    }
    
    [data-testid="stMetricValue"] {
        color: #e2e8f0;
        font-weight: 700;
    }
    
    [data-testid="stDataFrame"] {
        background: #1e293b;
        border-radius: 12px;
        border: 1px solid #334155;
    }
    
    .streamlit-expanderHeader {
        background: #1e293b;
        border-radius: 10px;
        border: 1px solid #334155;
    }
    
    ::-webkit-scrollbar {
        width: 8px;
    }
    
    ::-webkit-scrollbar-track {
        background: #0f172a;
    }
    
    ::-webkit-scrollbar-thumb {
        background: #475569;
        border-radius: 4px;
    }
    
    ::-webkit-scrollbar-thumb:hover {
        background: #60a5fa;
    }
    
    @keyframes pulse {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.5; }
    }
    
    .live-indicator {
        animation: pulse 2s infinite;
        color: #10b981;
        font-weight: 600;
    }
    
    .footer {
        text-align: center;
        padding: 20px;
        color: #475569;
        font-size: 0.8rem;
        border-top: 1px solid #334155;
        margin-top: 30px;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'predictor' not in st.session_state:
    st.session_state.predictor = None
if 'alert_system' not in st.session_state:
    st.session_state.alert_system = None
if 'initialized' not in st.session_state:
    st.session_state.initialized = False
if 'auto_refresh' not in st.session_state:
    st.session_state.auto_refresh = True

# ============================================
# AUTO-REFRESH SCRIPT
# ============================================
if st.session_state.get('initialized', False) and st.session_state.get('auto_refresh', True):
    st.markdown("""
    <script>
        // Auto-refresh every 30 seconds
        setTimeout(function() {
            window.location.reload();
        }, 30000);
    </script>
    """, unsafe_allow_html=True)

# ============================================
# SIDEBAR
# ============================================
with st.sidebar:
    st.markdown("""
    <div style="text-align: center; padding: 20px 0;">
        <span style="font-size: 3rem;">🛡️</span>
        <h2 style="color: #e2e8f0; font-weight: 700; margin: 10px 0;">URL Security</h2>
        <p style="color: #94a3b8; font-size: 0.85rem;">IP-Based Threat Analysis</p>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    st.markdown("### 📊 Navigation")
    page = st.radio(
        "",
        ["🏠 Dashboard", "🔍 URL Scanner", "🌐 IP Intelligence", 
         "🚨 Alerts", "📈 Analytics", "📋 Reports"],
        label_visibility="collapsed"
    )
    
    st.markdown("---")
    
    st.markdown("### ⚙️ System Control")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("🔌 Initialize", use_container_width=True):
            with st.spinner("Starting system..."):
                try:
                    from src.ml_pipeline.prediction import URLPredictor, find_latest_model
                    from src.real_time_monitor.alert_system import AlertSystem
                    
                    model_path = find_latest_model('random_forest')
                    st.session_state.predictor = URLPredictor(model_path) if model_path else URLPredictor()
                    st.session_state.alert_system = AlertSystem()
                    st.session_state.initialized = True
                    st.success("✅ System Ready!")
                    time.sleep(1)
                    st.rerun()
                except Exception as e:
                    st.error(f"Failed: {e}")
    
    with col2:
        if st.button("🔄 Refresh", use_container_width=True):
            st.rerun()
    
    # Auto-refresh toggle
    st.session_state.auto_refresh = st.toggle("🔄 Auto-Refresh (30s)", value=True)
    
    st.markdown("---")
    
    # Status
    if st.session_state.initialized:
        st.markdown("""
        <div style="background: linear-gradient(135deg, #064e3b, #065f46); 
                    border-radius: 10px; padding: 15px; text-align: center; border: 1px solid #10b981;">
            <span class="live-indicator">●</span> System Active
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div style="background: linear-gradient(135deg, #713f12, #78350f); 
                    border-radius: 10px; padding: 15px; text-align: center; border: 1px solid #f59e0b;">
            ⚠️ Click Initialize to start
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("---")
    st.markdown(f"""
    <div class="footer">
        <p>URL Security v1.0</p>
        <p>© 2024 | Threat Analysis</p>
    </div>
    """, unsafe_allow_html=True)

# ============================================
# MAIN CONTENT
# ============================================
if not st.session_state.initialized:
    st.markdown('<p class="main-header">🛡️ URL Security Using IP-Based Threat Analysis</p>', 
                unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown("""
        <div style="text-align: center; padding: 40px 0;">
            <span style="font-size: 6rem;">🛡️</span>
            <h2 style="color: #e2e8f0; margin-top: 20px;">Welcome to URL Security</h2>
            <p style="color: #94a3b8; font-size: 1.1rem; line-height: 1.8;">
                An AI-powered system for detecting malicious URLs using 
                IP-based threat analysis and machine learning.
            </p>
            <br>
            <p style="color: #60a5fa; font-size: 1rem;">
                👈 Click <b>Initialize System</b> in the sidebar to begin
            </p>
        </div>
        """, unsafe_allow_html=True)
        
        col_a, col_b, col_c = st.columns(3)
        with col_a:
            st.markdown("""
            <div class="metric-card" style="padding: 20px;">
                <span style="font-size: 2rem;">🔍</span>
                <h4 style="color: #e2e8f0;">Hybrid Detection</h4>
                <p style="color: #94a3b8; font-size: 0.8rem;">Rule-based + ML</p>
            </div>
            """, unsafe_allow_html=True)
        with col_b:
            st.markdown("""
            <div class="metric-card" style="padding: 20px;">
                <span style="font-size: 2rem;">📡</span>
                <h4 style="color: #e2e8f0;">Live Monitoring</h4>
                <p style="color: #94a3b8; font-size: 0.8rem;">Real-time capture</p>
            </div>
            """, unsafe_allow_html=True)
        with col_c:
            st.markdown("""
            <div class="metric-card" style="padding: 20px;">
                <span style="font-size: 2rem;">🚨</span>
                <h4 style="color: #e2e8f0;">Instant Alerts</h4>
                <p style="color: #94a3b8; font-size: 0.8rem;">Auto threat detection</p>
            </div>
            """, unsafe_allow_html=True)
else:
    # Route to selected page
    if page == "🏠 Dashboard":
        from dashboard.pages import home
        home.show(st.session_state)
    elif page == "🔍 URL Scanner":
        from dashboard.pages import url_scanner
        url_scanner.show(st.session_state)
    elif page == "🌐 IP Intelligence":
        from dashboard.pages import ip_intelligence
        ip_intelligence.show(st.session_state)
    elif page == "🚨 Alerts":
        from dashboard.pages import alerts
        alerts.show(st.session_state)
    elif page == "📈 Analytics":
        from dashboard.pages import analytics
        analytics.show(st.session_state)
    elif page == "📋 Reports":
        from dashboard.pages import reports
        reports.show(st.session_state)