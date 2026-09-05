#!/usr/bin/env python3
"""
Launch Streamlit Dashboard
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

if __name__ == "__main__":
    import streamlit.web.cli as stcli
    
    dashboard_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        'dashboard', 'app.py'
    )
    
    sys.argv = ["streamlit", "run", dashboard_path, "--server.port=8501"]
    stcli.main()