"""
URL Investigation Dashboard

Evidence-based investigation interface with:
- Tabbed layout (Overview, URL Analysis, IP Intelligence, Threat Intelligence, ML Explanation)
- Plotly risk gauge
- Evidence checklist (✓ marks per finding)
- Typosquatting detection panel
- SHAP explainability
- SSRF / policy blocks
- Batch scanning with export

Preserves backward compatibility with older result schemas.
"""

import streamlit as st
import time
import json
import plotly.graph_objects as go
from datetime import datetime


# ============================================
# PAGE ENTRY
# ============================================

def show(session_state):
    st.markdown('<p class="main-header">URL Investigation</p>', unsafe_allow_html=True)
    st.markdown(
        '<p style="text-align:center; color:#94a3b8; margin-top:-15px;">'
        'Multi-signal investigation: rules · ML · IP · DNS · WHOIS · typosquatting · SSRF · SHAP'
        '</p>',
        unsafe_allow_html=True
    )

    _render_input_section(session_state)
    st.markdown('<div class="divider-glow"></div>', unsafe_allow_html=True)
    _render_batch_section(session_state)


# ============================================
# INPUT SECTION
# ============================================

def _render_input_section(session_state):
    st.markdown('<p class="sub-header">🔍 New Investigation</p>', unsafe_allow_html=True)

    col1, col2, col3 = st.columns([3, 1, 1])
    with col1:
        url_input = st.text_input(
            "Enter URL",
            placeholder="https://example.com  or  http://suspicious-login.xyz/verify.php",
            label_visibility="collapsed",
            key="inv_url"
        )
    with col2:
        deep_scan = st.checkbox(
            "Deep Scan",
            value=False,
            help="Includes DNS/WHOIS/IP intelligence lookups (slower)"
        )
    with col3:
        scan_btn = st.button("⚡ INVESTIGATE", type="primary", use_container_width=True)

    if scan_btn and url_input:
        with st.spinner("🔍 Running investigation..."):
            time.sleep(0.3)
            result = session_state.predictor.predict_url(
                url_input, save_to_db=True, with_intelligence=deep_scan
            )
            st.session_state['last_result'] = result

    # Display last result if available
    if st.session_state.get('last_result'):
        st.markdown('<div class="divider-glow"></div>', unsafe_allow_html=True)
        _render_investigation(st.session_state['last_result'])


# ============================================
# INVESTIGATION RENDERER
# ============================================

def _render_investigation(result):
    """Render the full investigation interface for one result"""
    _render_verdict_banner(result)

    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "📋 Overview",
        "🔗 URL Analysis",
        "🌐 IP Intelligence",
        "🚨 Threat Intelligence",
        "🧠 ML Explanation",
    ])

    with tab1:
        _tab_overview(result)
    with tab2:
        _tab_url_analysis(result)
    with tab3:
        _tab_ip_intelligence(result)
    with tab4:
        _tab_threat_intelligence(result)
    with tab5:
        _tab_ml_explanation(result)

    # Raw JSON
    with st.expander("🔧 View Raw Result JSON"):
        display = {k: v for k, v in result.items() if k != 'explanation'}
        st.json(display)


# ============================================
# VERDICT BANNER (always visible at top)
# ============================================

def _render_verdict_banner(result):
    """Big top banner with verdict, score, confidence, and evidence checklist"""

    pred = result.get('prediction', 'error')
    verdict = result.get('verdict', pred.upper())
    risk_score = float(result.get('risk_score', 0))
    confidence = float(result.get('confidence', 0))
    url = result.get('url', '')

    # Colors by verdict
    if verdict in ('MALICIOUS',) or pred == 'malicious':
        color = "#ef4444"
        bg = "rgba(239,68,68,0.1)"
        icon = "🚨"
    elif verdict in ('HIGH_RISK',):
        color = "#f97316"
        bg = "rgba(249,115,22,0.1)"
        icon = "⚠️"
    elif verdict in ('SUSPICIOUS',) or pred == 'suspicious':
        color = "#f59e0b"
        bg = "rgba(245,158,11,0.1)"
        icon = "⚠️"
    else:
        color = "#10b981"
        bg = "rgba(16,185,129,0.1)"
        icon = "✅"

    # Build evidence checklist
    evidence = _build_evidence_list(result)
    evidence_html = ""
    if evidence:
        evidence_items = "".join(
            f'<div style="padding:6px 0; color:#e2e8f0; font-size:0.9rem;">'
            f'<span style="color:{color}; font-weight:700;">✓</span> {e}</div>'
            for e in evidence[:8]
        )
        evidence_html = f"""
        <div style="background:rgba(15,23,42,0.5); border-radius:12px;
                    padding:16px 20px; margin-top:16px; text-align:left;">
            <div style="color:{color}; font-size:0.75rem; font-weight:700;
                        letter-spacing:2px; text-transform:uppercase;
                        margin-bottom:8px;">Evidence</div>
            {evidence_items}
        </div>
        """

    st.markdown(f"""
    <div style="background:{bg}; border:2px solid {color}; border-radius:24px;
                padding:32px; backdrop-filter:blur(20px);">
        <div style="text-align:center;">
            <div style="font-size:4rem;">{icon}</div>
            <h1 style="color:{color}; margin:10px 0 0 0; font-weight:800;
                       letter-spacing:3px; font-size:2rem;">{verdict}</h1>
            <div style="color:#e2e8f0; font-family:'JetBrains Mono';
                        font-size:1rem; margin-top:8px; word-break:break-all;">
                {url[:110]}{'...' if len(url) > 110 else ''}
            </div>
            <div style="margin-top:20px; display:flex; justify-content:center;
                        gap:12px; flex-wrap:wrap;">
                <span class="chip chip-info">Risk: {risk_score:.1f}/100</span>
                <span class="chip chip-low">Confidence: {confidence:.1%}</span>
                <span class="chip chip-medium">Method: {result.get('method','—')}</span>
            </div>
        </div>
        {evidence_html}
    </div>
    """, unsafe_allow_html=True)


# ============================================
# EVIDENCE BUILDER
# ============================================

def _build_evidence_list(result):
    """Extract human-readable evidence strings from result"""
    evidence = []
    signals = result.get('signals', {})

    # Rule score
    rs = signals.get('rule_score')
    if rs is not None and rs >= 30:
        evidence.append(f"Rule engine score: **{rs:.0f}/100**")

    # ML probability
    ml = signals.get('ml_probability')
    if ml is not None and ml >= 0.5:
        evidence.append(f"ML probability: **{ml:.1%}**")

    # Typosquatting
    tq = result.get('typosquat')
    if tq and tq.get('is_typosquat'):
        for m in tq.get('matches', [])[:2]:
            evidence.append(
                f"Typosquatting: mimics **{m.get('brand','?').upper()}** "
                f"(similarity {m.get('similarity', 0):.0%}, "
                f"{m.get('technique','?').replace('_', ' ')})"
            )

    # IP intel
    intel = result.get('intelligence') or {}
    ip_intel = intel.get('ip_intel') if intel else None
    if ip_intel:
        abuse = ip_intel.get('abuse_score')
        if abuse:
            evidence.append(f"IP abuse score: **{abuse}**")
        if ip_intel.get('is_tor'):
            evidence.append("Source IP is a **Tor exit node**")
        if ip_intel.get('is_vpn'):
            evidence.append("Source IP is a **VPN**")
        if ip_intel.get('is_hosting'):
            evidence.append("Source IP is a **hosting/datacenter**")
        country = ip_intel.get('country')
        if country:
            evidence.append(f"IP located in **{country}**")

    # WHOIS
    whois = intel.get('whois_intel') if intel else None
    if whois:
        age = whois.get('domain_age_days')
        if whois.get('is_new_domain'):
            evidence.append(f"**Newly registered domain** ({age} days old)")
        elif age and age < 90:
            evidence.append(f"Recently registered domain ({age} days old)")
        if whois.get('is_privacy_protected'):
            evidence.append("**Privacy-protected registration** (WHOIS hidden)")
        if whois.get('is_expiring_soon'):
            evidence.append(f"Domain expiring in {whois.get('days_until_expiry')} days")

    # DNS
    dns = intel.get('dns_intel') if intel else None
    if dns:
        if not dns.get('has_mx') and dns.get('lookup_success'):
            evidence.append("**No MX records** (can't receive email)")
        if not dns.get('has_spf') and dns.get('lookup_success'):
            evidence.append("**No SPF record** (email spoofing possible)")
        if not dns.get('has_dmarc') and dns.get('lookup_success'):
            evidence.append("**No DMARC record**")

    # Normalization flags
    norm = result.get('normalization') or {}
    if norm.get('is_punycode'):
        evidence.append("**Punycode/IDN** domain detected")
    if norm.get('has_unicode'):
        evidence.append("**Unicode characters** in hostname (homograph risk)")
    if norm.get('has_at_symbol'):
        evidence.append("**@ symbol** in URL (redirect trick)")
    if norm.get('has_double_encoding'):
        evidence.append("**Double URL encoding** detected")
    if norm.get('is_ip_host'):
        evidence.append("**IP address used as host**")
    if norm.get('percent_encoding_count', 0) > 5:
        evidence.append(f"**Heavy URL encoding**: {norm['percent_encoding_count']} encoded chars")

    # SSRF block
    if result.get('method') == 'ssrf_block':
        evidence.insert(0, "**🚨 SSRF protection triggered** — internal resource blocked")

    # Rule reasons fallback
    if not evidence:
        for r in result.get('reasons', [])[:5]:
            evidence.append(f"Rule triggered: `{r}`")

    return evidence


# ============================================
# TAB 1: OVERVIEW
# ============================================

def _tab_overview(result):
    risk_score = float(result.get('risk_score', 0))
    verdict = result.get('verdict', 'UNKNOWN')

    col_gauge, col_breakdown = st.columns([1, 1])

    with col_gauge:
        st.markdown('<p class="sub-header">🎯 Risk Score</p>', unsafe_allow_html=True)
        fig = _risk_gauge(risk_score, verdict)
        st.plotly_chart(fig, use_container_width=True)

    with col_breakdown:
        st.markdown('<p class="sub-header">📊 Signal Contributions</p>', unsafe_allow_html=True)
        _render_signal_contributions(result)

    # Summary metrics
    st.markdown('<div class="divider-glow"></div>', unsafe_allow_html=True)
    st.markdown('<p class="sub-header">📈 At a Glance</p>', unsafe_allow_html=True)

    c1, c2, c3, c4 = st.columns(4)
    signals = result.get('signals', {})

    with c1:
        _metric_card("Rule Score", signals.get('rule_score', '—'), "/100", "#3b82f6")
    with c2:
        ml = signals.get('ml_probability')
        _metric_card("ML Probability", f"{ml:.1%}" if isinstance(ml, float) else "—", "", "#8b5cf6")
    with c3:
        tq = signals.get('typosquat_score')
        _metric_card("Typosquat Score", tq if tq else "—", "/100", "#ef4444")
    with c4:
        ip = signals.get('ip_score')
        _metric_card("IP Score", ip if ip else "—", "/100", "#f59e0b")


def _risk_gauge(score, verdict):
    """Plotly risk gauge"""
    if score >= 80:
        bar_color = '#ef4444'
    elif score >= 60:
        bar_color = '#f97316'
    elif score >= 30:
        bar_color = '#f59e0b'
    else:
        bar_color = '#10b981'

    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        number={'font': {'size': 48, 'color': bar_color, 'family': 'JetBrains Mono'}},
        gauge={
            'axis': {'range': [0, 100], 'tickcolor': '#94a3b8',
                     'tickfont': {'color': '#94a3b8', 'size': 10}},
            'bar': {'color': bar_color, 'thickness': 0.35},
            'bgcolor': 'rgba(30,41,59,0.5)',
            'borderwidth': 2,
            'bordercolor': 'rgba(96,165,250,0.3)',
            'steps': [
                {'range': [0, 30], 'color': 'rgba(16,185,129,0.15)'},
                {'range': [30, 60], 'color': 'rgba(245,158,11,0.15)'},
                {'range': [60, 80], 'color': 'rgba(249,115,22,0.15)'},
                {'range': [80, 100], 'color': 'rgba(239,68,68,0.15)'},
            ],
        }
    ))
    fig.update_layout(
        height=300,
        margin=dict(t=30, b=10, l=20, r=20),
        paper_bgcolor='rgba(0,0,0,0)',
        font={'color': '#e2e8f0'},
    )
    return fig


def _render_signal_contributions(result):
    """Weighted contribution bars from Risk Engine"""
    rb = result.get('risk_breakdown') or {}
    contributions = rb.get('contributions') or {}
    weights = rb.get('weights_used') or {}
    missing = rb.get('missing_signals') or []

    if not contributions:
        st.info("No risk engine breakdown available")
        return

    labels = {
        'rule_score': 'Rule Engine',
        'ml_score': 'ML Model',
        'ip_score': 'IP Intel',
        'domain_score': 'Domain Intel',
        'threat_score': 'Threat Feed',
    }

    max_c = max(contributions.values()) if contributions else 1

    for signal, contrib in sorted(contributions.items(), key=lambda x: x[1], reverse=True):
        if contrib <= 0:
            continue
        label = labels.get(signal, signal)
        weight = weights.get(signal, 0)
        bar_pct = (contrib / max_c) * 100 if max_c > 0 else 0

        if contrib > 40:
            c = '#ef4444'
        elif contrib > 20:
            c = '#f97316'
        elif contrib > 10:
            c = '#f59e0b'
        else:
            c = '#3b82f6'

        st.markdown(f"""
        <div style="background:rgba(30,41,59,0.5); border-radius:10px;
                    padding:10px 14px; margin:5px 0; border-left:4px solid {c};">
            <div style="display:flex; justify-content:space-between; margin-bottom:6px;">
                <span style="color:#e2e8f0; font-weight:600; font-size:0.9rem;">{label}</span>
                <span style="color:#60a5fa; font-family:'JetBrains Mono'; font-size:0.85rem;">
                    {contrib:.1f} <span style="color:#64748b;">(w={weight:.2f})</span>
                </span>
            </div>
            <div style="background:rgba(15,23,42,0.5); border-radius:3px;
                        height:5px; overflow:hidden;">
                <div style="background:{c}; height:100%; width:{bar_pct}%;"></div>
            </div>
        </div>
        """, unsafe_allow_html=True)

    if missing:
        st.caption(f"⚠️ Missing signals (weights renormalized): {', '.join(missing)}")


def _metric_card(label, value, suffix, color):
    st.markdown(f"""
    <div style="background:rgba(30,41,59,0.5); border-radius:12px; padding:16px;
                text-align:center; border:1px solid rgba(96,165,250,0.15);">
        <div style="color:#94a3b8; font-size:0.7rem; letter-spacing:1.5px;
                    text-transform:uppercase; font-weight:600;">{label}</div>
        <div style="color:{color}; font-family:'JetBrains Mono'; font-size:1.6rem;
                    font-weight:700; margin-top:6px;">
            {value}<span style="font-size:0.9rem; color:#64748b;">{suffix}</span>
        </div>
    </div>
    """, unsafe_allow_html=True)


# ============================================
# TAB 2: URL ANALYSIS
# ============================================

def _tab_url_analysis(result):
    norm = result.get('normalization')
    tq = result.get('typosquat')

    # ============================================
    # Normalization
    # ============================================
    st.markdown('<p class="sub-header">🔗 URL Normalization</p>', unsafe_allow_html=True)

    if norm:
        warnings = norm.get('warnings', [])
        # Flag chips
        flags_html = ""
        flag_map = [
            ('is_ip_host', 'IP Host', 'chip-critical'),
            ('is_punycode', 'Punycode', 'chip-high'),
            ('has_unicode', 'Unicode', 'chip-medium'),
            ('has_double_encoding', 'Double Encoding', 'chip-high'),
            ('has_at_symbol', '@ Symbol', 'chip-critical'),
            ('has_userinfo', 'Userinfo', 'chip-medium'),
        ]
        for key, label, cls in flag_map:
            if norm.get(key):
                flags_html += f'<span class="chip {cls}">{label}</span>'
        if norm.get('port'):
            flags_html += f'<span class="chip chip-low">Port {norm["port"]}</span>'
        if norm.get('percent_encoding_count', 0) > 0:
            flags_html += f'<span class="chip chip-low">%{norm["percent_encoding_count"]} encoding</span>'

        if flags_html:
            st.markdown(f'<div style="margin-bottom:15px;">{flags_html}</div>', unsafe_allow_html=True)

        col1, col2 = st.columns(2)
        with col1:
            st.markdown(f"""
            <div style="background:rgba(30,41,59,0.5); border-radius:12px;
                        padding:16px; font-family:'JetBrains Mono'; font-size:0.8rem;">
                <div style="color:#60a5fa; font-weight:700; margin-bottom:6px;">Normalized URL</div>
                <div style="color:#e2e8f0; word-break:break-all; margin-bottom:12px;">
                    {norm.get('normalized_url','—')}
                </div>
                <div style="color:#60a5fa; font-weight:700; margin-bottom:6px;">Decoded URL</div>
                <div style="color:#e2e8f0; word-break:break-all;">
                    {norm.get('decoded_url','—')}
                </div>
            </div>
            """, unsafe_allow_html=True)

        with col2:
            rows = [
                ("Scheme", norm.get('scheme','—')),
                ("Hostname", norm.get('hostname','—')),
                ("Registered Domain", norm.get('registered_domain','—')),
                ("Subdomain", norm.get('subdomain') or '—'),
                ("TLD", norm.get('tld','—')),
                ("Path", norm.get('path','—')[:60]),
            ]
            rows_html = "".join(
                f'<div style="display:flex; justify-content:space-between; padding:5px 0; '
                f'border-bottom:1px solid rgba(96,165,250,0.08);">'
                f'<span style="color:#94a3b8;">{k}</span>'
                f'<span style="color:#e2e8f0; text-align:right; margin-left:10px; '
                f'word-break:break-all;">{v}</span></div>'
                for k, v in rows
            )
            st.markdown(f"""
            <div style="background:rgba(30,41,59,0.5); border-radius:12px;
                        padding:16px; font-family:'JetBrains Mono'; font-size:0.8rem;">
                {rows_html}
            </div>
            """, unsafe_allow_html=True)

        if warnings:
            st.markdown("**Warnings:**")
            st.markdown(
                " ".join(f'<span class="chip chip-medium">{w}</span>' for w in warnings),
                unsafe_allow_html=True
            )
    else:
        st.info("No normalization data available.")

    # ============================================
    # Typosquatting
    # ============================================
    st.markdown('<div class="divider-glow"></div>', unsafe_allow_html=True)
    st.markdown('<p class="sub-header">🎯 Typosquatting / Homograph Detection</p>', unsafe_allow_html=True)

    if tq and tq.get('is_typosquat'):
        st.markdown(f"""
        <div style="background:rgba(239,68,68,0.1); border:2px solid #ef4444;
                    border-radius:14px; padding:14px 20px; margin-bottom:15px;">
            <div style="color:#f87171; font-weight:700; font-size:1.05rem;">
                🎯 Brand Impersonation Detected
            </div>
        </div>
        """, unsafe_allow_html=True)

        tech_labels = {
            'character_substitution': '🔤 Character Substitution',
            'homoglyph': '👁️ Homoglyph',
            'punycode': '🔡 Punycode',
            'combosquatting': '🔗 Combosquatting',
            'insertion': '➕ Insertion',
            'deletion': '➖ Deletion',
            'transposition': '🔄 Transposition',
            'vowel_swap': '🔀 Vowel Swap',
            'edit_distance': '✏️ Edit Distance',
        }

        for m in tq.get('matches', []):
            brand = m.get('brand', '?')
            sim = m.get('similarity', 0)
            tech = tech_labels.get(m.get('technique'), m.get('technique'))
            risk = m.get('risk', 0)

            rcolor = '#ef4444' if risk >= 80 else '#f97316' if risk >= 60 else '#f59e0b'

            st.markdown(f"""
            <div style="background:rgba(30,41,59,0.5); border-radius:12px;
                        padding:14px 18px; margin:8px 0; border-left:4px solid {rcolor};">
                <div style="display:flex; justify-content:space-between;
                            flex-wrap:wrap; gap:8px; margin-bottom:8px;">
                    <span style="color:#e2e8f0; font-weight:700; font-size:1rem;">
                        Mimics: <span style="color:{rcolor};">{brand.upper()}</span>
                    </span>
                    <div style="display:flex; gap:8px;">
                        <span class="chip chip-medium">{tech}</span>
                        <span style="color:{rcolor}; font-family:'JetBrains Mono';
                                    font-weight:700; font-size:0.9rem;">
                            Risk {risk}/100
                        </span>
                    </div>
                </div>
                <div style="margin:8px 0;">
                    <div style="display:flex; justify-content:space-between; margin-bottom:4px;">
                        <span style="color:#94a3b8; font-size:0.75rem;">Similarity</span>
                        <span style="color:#e2e8f0; font-size:0.8rem;
                                    font-family:'JetBrains Mono';">{sim:.1%}</span>
                    </div>
                    <div style="background:rgba(15,23,42,0.5); border-radius:4px;
                                height:5px; overflow:hidden;">
                        <div style="background:{rcolor}; height:100%; width:{sim*100}%;"></div>
                    </div>
                </div>
                <div style="color:#94a3b8; font-size:0.8rem;">{m.get('details','')}</div>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.success("✅ No typosquatting or homograph patterns detected.")


# ============================================
# TAB 3: IP INTELLIGENCE
# ============================================

def _tab_ip_intelligence(result):
    intel = result.get('intelligence') or {}
    ip_intel = intel.get('ip_intel')
    whois = intel.get('whois_intel')

    if not ip_intel and not whois:
        st.info(
            "🔍 No IP/WHOIS intelligence available. "
            "Enable **Deep Scan** when investigating to enrich results."
        )
        return

    # ============================================
    # IP Summary
    # ============================================
    if ip_intel:
        st.markdown('<p class="sub-header">🌐 IP Reputation</p>', unsafe_allow_html=True)

        abuse = ip_intel.get('abuse_score', 0)
        combined = ip_intel.get('combined_risk', 0) * 100

        c1, c2, c3, c4 = st.columns(4)
        with c1:
            _metric_card("Abuse Score", abuse, "/100", "#ef4444" if abuse > 50 else "#10b981")
        with c2:
            _metric_card("Combined Risk", f"{combined:.0f}", "/100",
                         "#ef4444" if combined > 60 else "#f59e0b" if combined > 30 else "#10b981")
        with c3:
            _metric_card("Reports", ip_intel.get('total_reports', 0), "", "#3b82f6")
        with c4:
            _metric_card("Country", ip_intel.get('country') or '—', "", "#8b5cf6")

        # Infrastructure flags
        flags = []
        if ip_intel.get('is_tor'):
            flags.append(('🚨 Tor Exit Node', 'chip-critical'))
        if ip_intel.get('is_vpn'):
            flags.append(('🔒 VPN', 'chip-high'))
        if ip_intel.get('is_hosting'):
            flags.append(('🏢 Hosting / Datacenter', 'chip-medium'))
        if ip_intel.get('is_proxy'):
            flags.append(('🎭 Proxy', 'chip-high'))

        if flags:
            st.markdown("**Infrastructure Flags:**")
            st.markdown(
                " ".join(f'<span class="chip {c}">{l}</span>' for l, c in flags),
                unsafe_allow_html=True
            )

        # Details
        with st.expander("📋 Full IP Details"):
            st.json(ip_intel)

    # ============================================
    # WHOIS
    # ============================================
    if whois:
        st.markdown('<div class="divider-glow"></div>', unsafe_allow_html=True)
        st.markdown('<p class="sub-header">📅 Domain Registration (WHOIS)</p>', unsafe_allow_html=True)

        age = whois.get('domain_age_days', 0)
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            _metric_card("Domain Age", f"{age}", " days",
                         "#ef4444" if age < 30 else "#f59e0b" if age < 90 else "#10b981")
        with c2:
            expiry = whois.get('days_until_expiry', 0)
            _metric_card("Expires In", expiry, " days",
                         "#f59e0b" if 0 < expiry < 30 else "#10b981")
        with c3:
            _metric_card("Registrar", (whois.get('registrar') or '—')[:20], "", "#3b82f6")
        with c4:
            _metric_card("Nameservers", whois.get('nameserver_count', 0), "", "#8b5cf6")

        flags = []
        if whois.get('is_new_domain'):
            flags.append(('🆕 New Domain', 'chip-critical'))
        if whois.get('is_privacy_protected'):
            flags.append(('🕵️ Privacy Protected', 'chip-medium'))
        if whois.get('is_free_tld'):
            flags.append(('🆓 Free TLD', 'chip-high'))
        if whois.get('is_expiring_soon'):
            flags.append(('⏰ Expiring Soon', 'chip-medium'))

        if flags:
            st.markdown("**Registration Flags:**")
            st.markdown(
                " ".join(f'<span class="chip {c}">{l}</span>' for l, c in flags),
                unsafe_allow_html=True
            )

        with st.expander("📋 Full WHOIS Details"):
            st.json(whois)


# ============================================
# TAB 4: THREAT INTELLIGENCE
# ============================================

def _tab_threat_intelligence(result):
    st.markdown('<p class="sub-header">🚨 Rules Triggered</p>', unsafe_allow_html=True)

    reasons = result.get('reasons', [])
    if reasons:
        for r in reasons:
            # Categorize for color
            if r.startswith('typosquat') or r.startswith('ssrf'):
                cls = 'chip-critical'
            elif 'high_risk_tld' in r or 'brand_mimic' in r or 'executable' in r:
                cls = 'chip-high'
            else:
                cls = 'chip-medium'
            st.markdown(f'<span class="chip {cls}">{r}</span>', unsafe_allow_html=True)
    else:
        st.success("✅ No rules triggered.")

    # DNS Intel
    st.markdown('<div class="divider-glow"></div>', unsafe_allow_html=True)
    st.markdown('<p class="sub-header">🔍 DNS & Email Security</p>', unsafe_allow_html=True)

    intel = result.get('intelligence') or {}
    dns = intel.get('dns_intel')

    if dns:
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            _metric_card("A Records", dns.get('a_record_count', 0), "", "#3b82f6")
        with c2:
            _metric_card("MX Records", dns.get('mx_count', 0), "",
                         "#ef4444" if dns.get('mx_count', 0) == 0 else "#10b981")
        with c3:
            _metric_card("SPF", "Yes" if dns.get('has_spf') else "No", "",
                         "#10b981" if dns.get('has_spf') else "#ef4444")
        with c4:
            _metric_card("DMARC", "Yes" if dns.get('has_dmarc') else "No", "",
                         "#10b981" if dns.get('has_dmarc') else "#ef4444")

        # Provider info
        if dns.get('mail_provider'):
            st.caption(f"📧 Mail provider: **{dns['mail_provider']}**")
        if dns.get('dns_provider'):
            st.caption(f"🌐 DNS provider: **{dns['dns_provider']}**")

        with st.expander("📋 Full DNS Details"):
            st.json(dns)
    else:
        st.info("Enable Deep Scan to see DNS intelligence.")

    # Risk Engine Breakdown
    st.markdown('<div class="divider-glow"></div>', unsafe_allow_html=True)
    st.markdown('<p class="sub-header">⚙️ Risk Engine Weights</p>', unsafe_allow_html=True)

    rb = result.get('risk_breakdown') or {}
    weights = rb.get('weights_used') or {}
    if weights:
        labels = {
            'rule_score': 'Rule Engine',
            'ml_score': 'ML Model',
            'ip_score': 'IP Intel',
            'domain_score': 'Domain Intel',
            'threat_score': 'Threat Feed',
        }
        for k, w in sorted(weights.items(), key=lambda x: x[1], reverse=True):
            if w <= 0:
                continue
            label = labels.get(k, k)
            pct = w * 100
            st.markdown(f"""
            <div style="display:flex; justify-content:space-between; padding:8px 0;
                        border-bottom:1px solid rgba(96,165,250,0.08);">
                <span style="color:#e2e8f0;">{label}</span>
                <span style="color:#60a5fa; font-family:'JetBrains Mono';">{pct:.0f}%</span>
            </div>
            """, unsafe_allow_html=True)


# ============================================
# TAB 5: ML EXPLANATION
# ============================================

def _tab_ml_explanation(result):
    st.markdown('<p class="sub-header">🧠 SHAP Feature Contributions</p>', unsafe_allow_html=True)

    expl = result.get('explanation')
    narrative = result.get('explanation_narrative')

    if narrative:
        st.markdown(f"""
        <div style="background:rgba(30,41,59,0.5); border-left:4px solid #8b5cf6;
                    border-radius:12px; padding:18px; margin-bottom:15px;
                    font-size:0.95rem; line-height:1.7; color:#e2e8f0;">
            {narrative.replace(chr(10), '<br>')}
        </div>
        """, unsafe_allow_html=True)

    if expl and expl.get('top_features'):
        features = expl['top_features']
        max_impact = max(abs(f['impact']) for f in features) or 1

        for i, feat in enumerate(features, 1):
            impact = feat['impact']
            pct = abs(impact) * 100
            bar = (abs(impact) / max_impact) * 100

            if feat['direction'] == 'increases_risk':
                c = '#ef4444'
                arrow = '▲'
            else:
                c = '#10b981'
                arrow = '▼'

            st.markdown(f"""
            <div style="background:rgba(30,41,59,0.5); border-radius:12px;
                        padding:14px 18px; margin:6px 0; border-left:4px solid {c};">
                <div style="display:flex; justify-content:space-between;
                            align-items:center; flex-wrap:wrap; gap:8px; margin-bottom:8px;">
                    <div>
                        <span style="color:#e2e8f0; font-weight:600;">
                            {i}. {feat['description']}
                        </span>
                        <span style="color:#64748b; font-size:0.75rem; margin-left:8px;">
                            ({feat['feature']})
                        </span>
                    </div>
                    <span style="color:{c}; font-family:'JetBrains Mono'; font-weight:700;">
                        {arrow} {pct:.1f}%
                    </span>
                </div>
                <div style="background:rgba(15,23,42,0.5); border-radius:4px;
                            height:6px; overflow:hidden;">
                    <div style="background:{c}; height:100%; width:{bar}%;"></div>
                </div>
                <div style="color:#94a3b8; font-size:0.8rem; margin-top:6px;">
                    {feat['reason']}
                </div>
            </div>
            """, unsafe_allow_html=True)

        st.caption(f"🧪 Method: **{expl.get('method','unknown')}**")
    else:
        st.info("No SHAP explanation available. Enable model-based predictions to see feature contributions.")


# ============================================
# BATCH SCAN
# ============================================

def _render_batch_section(session_state):
    st.markdown('<p class="sub-header">📋 Batch Scan</p>', unsafe_allow_html=True)

    batch = st.text_area(
        "URLs (one per line)",
        placeholder="https://www.google.com\nhttps://github.com\nhttp://phishing-test.xyz/login\nhttps://paypa1.com/login",
        height=140,
        label_visibility="collapsed",
        key="batch_urls"
    )

    col1, col2 = st.columns([1, 3])
    with col1:
        batch_btn = st.button("🚀 Scan All", type="primary", use_container_width=True)
    with col2:
        st.caption("Batch scan skips SHAP/intel to keep it fast.")

    if batch_btn and batch.strip():
        _run_batch(session_state, batch)
    elif batch_btn:
        st.warning("Please enter at least one URL")


def _run_batch(session_state, batch_text):
    urls = [u.strip() for u in batch_text.split('\n') if u.strip()]
    if not urls:
        st.warning("No valid URLs found")
        return

    progress = st.progress(0)
    status = st.empty()
    results = []

    for i, url in enumerate(urls):
        status.text(f"Scanning {i+1}/{len(urls)}: {url[:60]}...")
        try:
            results.append(session_state.predictor.predict_url(url, save_to_db=True))
        except Exception as e:
            results.append({
                'url': url, 'prediction': 'error', 'verdict': 'ERROR',
                'risk_score': 0, 'confidence': 0, 'reasons': [str(e)[:80]],
            })
        progress.progress((i + 1) / len(urls))

    status.empty()
    progress.empty()

    # Summary
    st.markdown('<div class="divider-glow"></div>', unsafe_allow_html=True)
    st.markdown('<p class="sub-header">📊 Summary</p>', unsafe_allow_html=True)

    m = sum(1 for r in results if r['prediction'] == 'malicious')
    s = sum(1 for r in results if r['prediction'] == 'suspicious')
    b = sum(1 for r in results if r['prediction'] == 'benign')

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        _metric_card("Total", len(results), "", "#3b82f6")
    with c2:
        _metric_card("Malicious", m, "", "#ef4444")
    with c3:
        _metric_card("Suspicious", s, "", "#f59e0b")
    with c4:
        _metric_card("Benign", b, "", "#10b981")

    # Details
    st.markdown('<div class="divider-glow"></div>', unsafe_allow_html=True)
    st.markdown('<p class="sub-header">📄 Details</p>', unsafe_allow_html=True)

    for i, r in enumerate(results, 1):
        pred = r.get('prediction', 'error')
        verdict = r.get('verdict', pred.upper())
        score = r.get('risk_score', 0)

        if pred == 'malicious':
            c = '#ef4444'; icon = '🚨'; chip = 'chip-critical'
        elif pred == 'suspicious':
            c = '#f59e0b'; icon = '⚠️'; chip = 'chip-medium'
        elif pred == 'benign':
            c = '#10b981'; icon = '✅'; chip = 'chip-safe'
        else:
            c = '#64748b'; icon = '❌'; chip = 'chip-low'

        # Typosquat tag
        tq_tag = ""
        if r.get('typosquat') and r['typosquat'].get('is_typosquat'):
            m_first = r['typosquat']['matches'][0]
            tq_tag = f'<span class="chip chip-high">🎯 {m_first["brand"]}</span>'

        st.markdown(f"""
        <div style="background:rgba(30,41,59,0.5); border-radius:10px;
                    padding:12px 16px; margin:6px 0; border-left:4px solid {c};">
            <div style="display:flex; justify-content:space-between;
                        align-items:center; flex-wrap:wrap; gap:8px;">
                <div style="flex:1; min-width:200px;">
                    <span style="font-size:1.1rem;">{icon}</span>
                    <span style="color:#e2e8f0; font-family:'JetBrains Mono';
                                margin-left:8px; font-size:0.85rem; word-break:break-all;">
                        {i}. {r['url'][:80]}{'...' if len(r['url']) > 80 else ''}
                    </span>
                </div>
                <div style="display:flex; gap:6px; align-items:center;">
                    {tq_tag}
                    <span class="chip {chip}">{pred.upper()}</span>
                    <span style="color:#94a3b8; font-size:0.75rem;
                                font-family:'JetBrains Mono';">
                        {verdict} · {score:.0f}
                    </span>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

    # Export
    st.markdown('<div class="divider-glow"></div>', unsafe_allow_html=True)
    export = json.dumps(
        [{
            'url': r.get('url'),
            'prediction': r.get('prediction'),
            'verdict': r.get('verdict'),
            'risk_score': r.get('risk_score'),
            'confidence': r.get('confidence'),
            'reasons': r.get('reasons'),
        } for r in results],
        indent=2,
        default=str
    )
    st.download_button(
        "📥 Download Results (JSON)",
        data=export,
        file_name=f"batch_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
        mime="application/json"
    )