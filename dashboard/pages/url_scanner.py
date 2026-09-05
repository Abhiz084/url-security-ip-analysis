"""
URL Scanner Page
"""

import streamlit as st
import time
from datetime import datetime

def show(session_state):
    st.markdown('<p class="main-header">🔍 URL Scanner</p>', unsafe_allow_html=True)
    
    # Single URL Scan
    st.markdown("### Scan Single URL")
    col1, col2 = st.columns([4, 1])
    
    with col1:
        url_input = st.text_input(
            "Enter URL to scan",
            placeholder="https://example.com or http://suspicious-site.xyz/login",
            key="single_url",
            label_visibility="collapsed"
        )
    
    with col2:
        scan_btn = st.button("🔍 Scan", type="primary", use_container_width=True)
    
    if scan_btn and url_input:
        with st.spinner("🔍 Analyzing URL..."):
            time.sleep(0.3)
            result = session_state.predictor.predict_url(url_input, save_to_db=True)
            
            st.markdown("---")
            
            if result['prediction'] == 'malicious':
                st.error(f"## ⚠️ MALICIOUS - Threat Detected!")
                st.markdown(f"""
                <div class="alert-critical">
                    <h3>🚨 This URL appears to be dangerous!</h3>
                    <p><strong>Risk Level:</strong> {result.get('risk_level', 'HIGH')}</p>
                    <p><strong>Confidence:</strong> {result['confidence']:.1%}</p>
                </div>
                """, unsafe_allow_html=True)
            elif result['prediction'] == 'suspicious':
                st.warning(f"## 🔶 SUSPICIOUS - Exercise Caution")
            else:
                st.success(f"## ✅ BENIGN - URL appears safe")
            
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Confidence", f"{result['confidence']:.1%}")
            with col2:
                st.metric("Risk Level", result.get('risk_level', 'N/A'))
            with col3:
                st.metric("Method", result.get('method', 'N/A'))
            with col4:
                st.metric("Model", result.get('model', 'N/A'))
            
            with st.expander("📋 Detailed Analysis"):
                st.json(result)
    
    # Batch Scan
    st.markdown("---")
    st.markdown("### 📋 Batch URL Scan")
    
    batch_urls = st.text_area(
        "Enter URLs (one per line)",
        placeholder="https://www.google.com\nhttp://suspicious-site.xyz/login\nhttps://github.com",
        height=150
    )
    
    if st.button("🔍 Scan All URLs", type="secondary"):
        urls = [u.strip() for u in batch_urls.split('\n') if u.strip()]
        
        if urls:
            progress = st.progress(0)
            results = []
            
            for i, url in enumerate(urls):
                result = session_state.predictor.predict_url(url, save_to_db=True)
                results.append(result)
                progress.progress((i + 1) / len(urls))
            
            malicious = sum(1 for r in results if r['prediction'] == 'malicious')
            suspicious = sum(1 for r in results if r['prediction'] == 'suspicious')
            benign = sum(1 for r in results if r['prediction'] == 'benign')
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("⚠️ Malicious", malicious)
            with col2:
                st.metric("🔶 Suspicious", suspicious)
            with col3:
                st.metric("✅ Benign", benign)
            
            st.markdown("---")
            for r in results:
                if r['prediction'] == 'malicious':
                    st.error(f"⚠️ {r['url'][:80]} — **{r['prediction'].upper()}** ({r['confidence']:.1%})")
                elif r['prediction'] == 'suspicious':
                    st.warning(f"🔶 {r['url'][:80]} — **{r['prediction'].upper()}** ({r['confidence']:.1%})")
                else:
                    st.success(f"✅ {r['url'][:80]} — **{r['prediction'].upper()}** ({r['confidence']:.1%})")