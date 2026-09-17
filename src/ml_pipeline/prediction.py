"""
Real-Time URL Prediction Module (Complete Integration)

Combines:
- URL Normalization (percent-decoding, IP/punycode detection, TLD splitting)
- Rule-Based Detection (55+ heuristics using normalized URL)
- ⭐ Typosquatting + Homograph Detection (145+ brands, 9 techniques)
- ML Model (Random Forest / XGBoost / etc.)
- IP Intelligence (abuse_score, ASN risk, Tor/VPN/hosting detection)
- DNS Intelligence (SPF/DMARC, nameserver analysis)
- WHOIS / Domain Intelligence (domain age, registrar)
- SHAP Explainability (WHY the URL was flagged)
- Hybrid Risk Engine (weighted 5-signal consensus)

Works on ANY URL — trained or unseen.
"""

import json
import pickle
import os
import glob
import re
import socket
import numpy as np
from datetime import datetime
from urllib.parse import urlparse, unquote
from loguru import logger

from database.crud_operations import CRUDOperations
from src.feature_engineering.url_features import URLFeatureExtractor
from src.normalization.url_normalizer import URLNormalizer
from src.detection.risk_engine import RiskEngine, RiskInput
from src.detection.typosquatting import TyposquattingDetector
from src.security.ssrf_protection import (
    validate_external_destination,
    SSRFProtectionError,
)


class URLPredictor:
    """
    Real-time URL threat prediction with full intelligence integration.
    Uses Hybrid Risk Engine + Typosquatting Detection for the final verdict.
    """

    def __init__(self, model_path=None):
        self.crud = CRUDOperations()
        self.model = None
        self.scaler = None
        self.model_name = "rule-based"
        self.selected_features = None
        self.explainer = None  # SHAP explainer

        # Extractors / normalizer
        self.url_extractor = URLFeatureExtractor()
        self.normalizer = URLNormalizer()

        # ⭐ Hybrid Risk Engine
        self.risk_engine = RiskEngine()

        # ⭐ Typosquatting + Homograph detector
        try:
            self.typosquat_detector = TyposquattingDetector()
        except Exception as e:
            logger.warning(f"Typosquatting detector unavailable: {e}")
            self.typosquat_detector = None

        # Optional intelligence clients (lazy-loaded)
        self._ip_intel = None
        self._dns_intel = None
        self._whois_intel = None

        # ============================================
        # KNOWN BENIGN DOMAINS (trust list)
        # ============================================
        self.known_benign_domains = [
            # Search
            'google.com', 'google.co.in', 'google.co.uk', 'bing.com',
            'yahoo.com', 'duckduckgo.com', 'baidu.com', 'yandex.com',
            # Social
            'youtube.com', 'youtu.be', 'facebook.com', 'fb.com',
            'instagram.com', 'twitter.com', 'x.com', 'linkedin.com',
            'reddit.com', 'pinterest.com', 'tumblr.com', 'snapchat.com',
            'tiktok.com', 'discord.com', 'telegram.org', 'whatsapp.com',
            # Streaming
            'netflix.com', 'spotify.com', 'twitch.tv', 'vimeo.com',
            'hulu.com', 'disneyplus.com', 'primevideo.com', 'hbomax.com',
            # Tech
            'github.com', 'gitlab.com', 'bitbucket.org', 'stackoverflow.com',
            'stackexchange.com', 'npmjs.com', 'pypi.org', 'docker.com',
            'kubernetes.io', 'terraform.io', 'ansible.com',
            # Cloud
            'aws.amazon.com', 'cloud.google.com', 'azure.microsoft.com',
            'digitalocean.com', 'heroku.com', 'vercel.com', 'netlify.com',
            'cloudflare.com', 'fastly.com', 'akamai.com',
            # E-commerce
            'amazon.com', 'amazon.in', 'amazon.co.uk', 'ebay.com',
            'etsy.com', 'shopify.com', 'walmart.com', 'target.com',
            'bestbuy.com', 'aliexpress.com', 'flipkart.com',
            # News
            'bbc.com', 'bbc.co.uk', 'cnn.com', 'nytimes.com', 'wsj.com',
            'theguardian.com', 'reuters.com', 'bloomberg.com', 'forbes.com',
            'techcrunch.com', 'theverge.com', 'wired.com', 'arstechnica.com',
            # Education / Reference
            'wikipedia.org', 'wikimedia.org', 'wiktionary.org',
            'coursera.org', 'udemy.com', 'edx.org', 'khanacademy.org',
            'udacity.com', 'pluralsight.com', 'skillshare.com',
            'docs.python.org', 'python.org', 'w3schools.com', 'mozilla.org',
            'developer.mozilla.org', 'geeksforgeeks.org', 'tutorialspoint.com',
            # Productivity
            'docs.google.com', 'sheets.google.com', 'slides.google.com',
            'drive.google.com', 'calendar.google.com', 'meet.google.com',
            'notion.so', 'trello.com', 'asana.com', 'slack.com',
            'zoom.us', 'teams.microsoft.com', 'webex.com', 'skype.com',
            # Tech giants
            'microsoft.com', 'office.com', 'live.com', 'outlook.com',
            'apple.com', 'icloud.com', 'mac.com',
            # Content
            'medium.com', 'dev.to', 'hashnode.com', 'substack.com',
            'wordpress.com', 'wordpress.org', 'blogger.com', 'wix.com',
            'godaddy.com', 'namecheap.com',
            'paypal.com', 'stripe.com', 'square.com', 'venmo.com',
            'dropbox.com', 'box.com', 'onedrive.com', 'wetransfer.com',
        ]

        # ============================================
        # HIGH-RISK TLDS
        # ============================================
        self.high_risk_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work',
            '.date', '.click', '.icu', '.cfd', '.gdn', '.bond', '.cyou',
            '.sbs', '.hair', '.monster', '.lol', '.pics', '.download',
            '.review', '.country', '.stream', '.loan', '.win', '.racing',
            '.accountant', '.science', '.party', '.webcam', '.bid',
            '.trade', '.cricket', '.men',
        ]

        # ============================================
        # BRAND NAMES (for legacy rule-based detection;
        # typosquatting module handles deeper checks)
        # ============================================
        self.brand_names = [
            'paypal', 'google', 'facebook', 'apple', 'amazon', 'microsoft',
            'netflix', 'instagram', 'whatsapp', 'twitter', 'linkedin',
            'dropbox', 'spotify', 'discord', 'steam', 'github', 'gitlab',
            'binance', 'coinbase', 'metamask', 'trustwallet', 'blockchain',
            'bank', 'credit', 'loan', 'mortgage', 'irs', 'tax',
            'dhl', 'fedex', 'ups', 'usps', 'westernunion', 'moneygram',
            'norton', 'mcafee', 'avg', 'avast', 'kaspersky', 'bitdefender',
            'zoom', 'skype', 'telegram', 'signal', 'viber',
            'wordpress', 'shopify', 'wix', 'squarespace', 'weebly',
            'roblox', 'fortnite', 'minecraft', 'epicgames', 'origin',
            'tinder', 'bumble', 'hinge', 'grindr',
            'uber', 'lyft', 'doordash', 'airbnb', 'booking',
            'crypto', 'nft', 'defi', 'web3', 'dao',
        ]

        # ============================================
        # SUSPICIOUS KEYWORDS
        # ============================================
        self.suspicious_keywords = [
            'login', 'signin', 'logon', 'authenticate', 'authorize',
            'verify', 'confirm', 'validate', 'activate',
            'password', 'passwd', 'pwd', 'credential', 'secret',
            'account', 'profile', 'dashboard', 'admin', 'administrator',
            'recover', 'reset', 'unlock', 'restore', 'change-password',
            'paypal', 'banking', 'payment', 'checkout', 'billing', 'invoice',
            'wallet', 'deposit', 'withdraw', 'transfer', 'transaction',
            'credit', 'debit', 'balance', 'statement', 'tax', 'refund', 'irs',
            'security', 'alert', 'warning', 'suspended', 'limited', 'blocked',
            'urgent', 'immediate', 'attention', 'important', 'critical',
            'unauthorized', 'suspicious', 'compromised', 'breach', 'hacked',
            'won', 'winner', 'prize', 'reward', 'bonus', 'free', 'gift',
            'claim', 'congratulations', 'selected', 'chosen', 'lucky',
            'exclusive', 'limited-time', 'expires', 'hurry', 'act-now',
            'cmd', 'config', 'backup', 'root', 'exec', 'script',
            'token', 'api', 'oauth', 'callback', 'redirect', 'webscr',
            'tracking', 'shipment', 'delivery', 'parcel', 'package', 'courier',
            'customs', 'duty', 'clearance', 'dispatch', 'arrival',
        ]

        # ============================================
        # DANGEROUS EXTENSIONS
        # ============================================
        self.dangerous_extensions = [
            '.exe', '.bat', '.cmd', '.msi', '.scr', '.ps1',
            '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh',
            '.jar', '.apk', '.dmg', '.pkg', '.deb', '.rpm',
            '.hta', '.cpl', '.msc', '.reg', '.lnk', '.url',
        ]

        # Load ML model if path provided
        if model_path:
            self.load_model(model_path)

    # ============================================
    # LAZY INTELLIGENCE LOADERS
    # ============================================

    def _get_ip_intel(self):
        if self._ip_intel is None:
            try:
                from src.intelligence.ip_intelligence import IPIntelligence
                self._ip_intel = IPIntelligence()
            except Exception as e:
                logger.debug(f"IPIntelligence unavailable: {e}")
                self._ip_intel = False
        return self._ip_intel if self._ip_intel is not False else None

    def _get_dns_intel(self):
        if self._dns_intel is None:
            try:
                from src.intelligence.dns_intelligence import DNSIntelligence
                self._dns_intel = DNSIntelligence()
            except Exception as e:
                logger.debug(f"DNSIntelligence unavailable: {e}")
                self._dns_intel = False
        return self._dns_intel if self._dns_intel is not False else None

    def _get_whois_intel(self):
        if self._whois_intel is None:
            try:
                from src.intelligence.whois_intelligence import WHOISIntelligence
                self._whois_intel = WHOISIntelligence()
            except Exception as e:
                logger.debug(f"WHOISIntelligence unavailable: {e}")
                self._whois_intel = False
        return self._whois_intel if self._whois_intel is not False else None

    # ============================================
    # MODEL LOADING
    # ============================================

    def load_model(self, model_path):
        """Load ML model, feature list, scaler, and initialize SHAP explainer"""
        try:
            model_dir = os.path.dirname(model_path)

            # Selected features
            features_file = os.path.join(model_dir, 'selected_features.json')
            if os.path.exists(features_file):
                with open(features_file, 'r') as f:
                    data = json.load(f)
                    self.selected_features = data.get('selected_features', [])
                    logger.info(f"Loaded {len(self.selected_features)} selected features")
            else:
                logger.warning("No selected_features.json found — using rule-based only")
                return False

            # Scaler (reference)
            scaler_file = os.path.join(model_dir, 'scaler.pkl')
            if os.path.exists(scaler_file):
                with open(scaler_file, 'rb') as f:
                    self.scaler = pickle.load(f)

            # Model
            if model_path.endswith('.pkl'):
                with open(model_path, 'rb') as f:
                    self.model = pickle.load(f)
                self.model_name = os.path.basename(model_path).replace('.pkl', '')
                logger.info(f"ML Model loaded: {self.model_name}")
            else:
                logger.error(f"Unsupported format: {model_path}")
                return False

            # SHAP explainer
            try:
                from src.ml_pipeline.explainability import URLExplainer
                if self.selected_features:
                    self.explainer = URLExplainer(self.model, self.selected_features)
                    logger.info("SHAP explainer initialized")
            except Exception as e:
                logger.warning(f"SHAP explainer unavailable: {e}")
                self.explainer = None

            return True

        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            import traceback
            logger.debug(traceback.format_exc())
            return False

    # ============================================
    # FEATURE EXTRACTION
    # ============================================

    def extract_url_features(self, url):
        """Extract full URL features using the enhanced extractor"""
        parsed = urlparse(url)
        domain = parsed.netloc or url
        path = parsed.path or '/'
        protocol = parsed.scheme or 'http'
        tld = domain.split('.')[-1] if '.' in domain else ''

        return self.url_extractor.extract_all_features(
            url=url, domain=domain, path=path,
            protocol=protocol, tld=tld
        )

    # ============================================
    # RULE-BASED DETECTION
    # ============================================

    def rule_based_check(self, url):
        """
        Enhanced rule-based detection using URLNormalizer +
        Typosquatting detector.

        Returns: (prediction, confidence, reasons)
        """
        # -------- Normalize --------
        try:
            norm = self.normalizer.normalize(url)
        except Exception as e:
            logger.debug(f"Normalizer error: {e}")
            norm = None

        # Use normalized fields if available
        if norm and norm.is_valid:
            hostname = norm.hostname
            registered_domain = norm.registered_domain or hostname
            decoded_url = norm.decoded_url or url
            url_lower = decoded_url.lower()
            scheme = norm.scheme
            path = norm.path
            is_https = norm.is_https
        else:
            parsed = urlparse(url)
            hostname = (parsed.netloc or '').lower()
            registered_domain = hostname
            decoded_url = unquote(url)
            url_lower = decoded_url.lower()
            scheme = parsed.scheme or 'http'
            path = parsed.path or '/'
            is_https = scheme == 'https'

        hostname_no_port = hostname.split(':')[0]
        domain_lower = registered_domain.lower()

        # ============================================
        # LEVEL 1: KNOWN BENIGN DOMAINS
        # ============================================
        for benign in self.known_benign_domains:
            if domain_lower == benign or domain_lower.endswith('.' + benign):
                return 'benign', 0.01, ['known_benign_domain']

        # Safe TLDs
        for safe_tld in ['.gov', '.edu', '.mil', '.ac.uk', '.gov.in', '.nic.in']:
            if domain_lower.endswith(safe_tld):
                return 'benign', 0.02, ['safe_tld']

        # ============================================
        # LEVEL 2: SCORE-BASED ANALYSIS
        # ============================================
        score = 0
        reasons = []

        # -------- Normalizer-driven red flags --------
        if norm and norm.is_valid:
            if norm.has_at_symbol:
                score += 25
                reasons.append("at_symbol_in_url")

            if norm.has_double_encoding:
                score += 20
                reasons.append("double_encoding")

            if norm.is_punycode:
                score += 15
                reasons.append("punycode_hostname")

            if norm.has_unicode and not norm.is_punycode:
                score += 10
                reasons.append("unicode_hostname")

            if norm.percent_encoding_count > 5:
                score += 12
                reasons.append(f"url_encoding:{norm.percent_encoding_count}")
            elif norm.percent_encoding_count > 2:
                score += 5

        # -------- ⭐ Typosquatting + Homograph detection --------
        typosquat_result = None
        if self.typosquat_detector is not None:
            try:
                typosquat_result = self.typosquat_detector.analyze(url)
                if typosquat_result.is_typosquat:
                    # Blend highest-risk match into the rule score (capped)
                    ts_score = min(typosquat_result.highest_risk, 100)
                    score += min(int(ts_score * 0.4), 40)
                    for m in typosquat_result.matches[:2]:
                        reasons.append(f"typosquat:{m.brand}({m.technique})")
            except Exception as e:
                logger.debug(f"Typosquat detection failed: {e}")

        # -------- High-risk TLDs --------
        for tld in self.high_risk_tlds:
            if domain_lower.endswith(tld):
                score += 35
                reasons.append(f"high_risk_tld:{tld}")
                break

        # -------- Brand mimicry (legacy simple check) --------
        for brand in self.brand_names:
            if brand in domain_lower:
                official_domains = [
                    f'{brand}.com', f'{brand}.org', f'{brand}.net',
                    f'{brand}.co', f'{brand}.io', f'{brand}.in',
                    f'www.{brand}.com', f'www.{brand}.org',
                ]
                is_official = any(
                    domain_lower == off or domain_lower.endswith('.' + off)
                    for off in official_domains
                )
                if not is_official:
                    score += 30
                    reasons.append(f"brand_mimic:{brand}")
                    break

        # -------- IP as host --------
        if norm and norm.is_ip_host:
            if norm.is_private_ip:
                score += 10
                reasons.append("private_ip_host")
            else:
                score += 30
                reasons.append("public_ip_as_host")

        # -------- Dangerous schemes --------
        for scheme_bad in ['data:', 'javascript:', 'vbscript:', 'file:']:
            if scheme_bad in url_lower:
                score += 40
                reasons.append(f"dangerous_scheme:{scheme_bad}")
                break

        # -------- Missing HTTPS on sensitive pages --------
        if not is_https:
            sensitive_indicators = [
                'login', 'signin', 'password', 'account', 'banking',
                'payment', 'checkout', 'verify', 'credit', 'billing',
                'auth', 'token', 'secret', 'credential',
            ]
            if any(ind in url_lower for ind in sensitive_indicators):
                score += 25
                reasons.append("no_https_sensitive")
            else:
                score += 8
                reasons.append("no_https")

        # -------- Suspicious keywords --------
        keyword_count = sum(1 for kw in self.suspicious_keywords if kw in url_lower)
        if keyword_count >= 5:
            score += 25
            reasons.append(f"many_keywords:{keyword_count}")
        elif keyword_count >= 3:
            score += 15
            reasons.append(f"multiple_keywords:{keyword_count}")
        elif keyword_count >= 1:
            score += 8
            reasons.append("suspicious_keyword")

        # -------- Dangerous extensions --------
        for ext in self.dangerous_extensions:
            if url_lower.endswith(ext) or f'{ext}?' in url_lower or f'{ext}&' in url_lower:
                score += 25
                reasons.append(f"executable:{ext}")
                break

        # -------- Admin panel paths --------
        admin_patterns = [
            '/wp-admin', '/wp-content', '/wp-includes', '/administrator',
            '/phpmyadmin', '/cpanel', '/webmail', '/.env', '/config.php',
        ]
        if any(pattern in url_lower for pattern in admin_patterns):
            score += 20
            reasons.append("admin_panel_exposed")

        # -------- Subdomain analysis --------
        if norm and norm.subdomain:
            subdomain_count = len([p for p in norm.subdomain.split('.') if p])
        else:
            subdomain_count = max(0, len(hostname_no_port.split('.')) - 2)

        if subdomain_count > 5:
            score += 15
            reasons.append(f"excessive_subdomains:{subdomain_count}")
        elif subdomain_count > 3:
            score += 8
            reasons.append(f"many_subdomains:{subdomain_count}")

        # -------- Hyphens in domain --------
        hyphen_count = domain_lower.count('-')
        if hyphen_count > 4:
            score += 12
            reasons.append(f"many_hyphens:{hyphen_count}")
        elif hyphen_count > 2:
            score += 5

        # -------- Digit-heavy domain --------
        digit_ratio = sum(c.isdigit() for c in domain_lower) / max(len(domain_lower), 1)
        if digit_ratio > 0.5 and len(domain_lower) > 20:
            score += 15
            reasons.append("digit_heavy_domain")

        # -------- Phishing URL patterns --------
        phishing_patterns = [
            '/login.php', '/signin.php', '/verify.php', '/account.php',
            '/update.php', '/confirm.php', '/secure/', '/auth/',
            '/api/v1/auth', '/oauth/callback', '/password-reset',
        ]
        if any(pattern in url_lower for pattern in phishing_patterns):
            score += 12
            reasons.append("phishing_pattern")

        # -------- Non-standard port --------
        if norm and norm.port:
            default_ports = {'http': 80, 'https': 443}
            if norm.port != default_ports.get(scheme):
                score += 5
                reasons.append(f"non_standard_port:{norm.port}")

        # -------- Redirect params --------
        redirect_params = ['redirect', 'url=', 'return=', 'next=', 'goto=', 'target=', 'redir=']
        if any(param in url_lower for param in redirect_params):
            score += 8
            reasons.append("redirect_param")

        # -------- Very long URL --------
        url_length = len(url)
        if url_length > 500:
            score += 15
            reasons.append("extremely_long_url")
        elif url_length > 200:
            score += 8
            reasons.append("very_long_url")

        # -------- Base64-like payload --------
        if re.search(r'[A-Za-z0-9+/=]{50,}', url):
            score += 20
            reasons.append("base64_encoded")

        # ============================================
        # LEVEL 3: DECISION
        # ============================================
        if reasons:
            logger.debug(f"URL: {url[:70]} | Score: {score} | {', '.join(reasons[:5])}")

        if score >= 60:
            confidence = min(0.90 + (score - 60) / 100, 0.99)
            return 'malicious', confidence, reasons
        elif score >= 40:
            confidence = 0.65 + (score - 40) / 100
            return 'malicious', confidence, reasons
        elif score >= 25:
            confidence = 0.40 + (score - 25) / 100
            return 'suspicious', confidence, reasons
        elif score >= 12:
            confidence = 0.20 + (score - 12) / 100
            return 'suspicious', confidence, reasons
        else:
            confidence = max(score / 100, 0.01)
            return 'benign', confidence, reasons

    # ============================================
    # ML PREDICTION
    # ============================================

    def ml_predict(self, url):
        """ML-based prediction — returns (result, probability)"""
        if self.model is None or self.selected_features is None:
            return None, None
        try:
            features = self.extract_url_features(url)
            feature_vector = np.array([
                float(features.get(f, 0.0)) for f in self.selected_features
            ]).reshape(1, -1)

            if hasattr(self.model, 'predict_proba'):
                proba = self.model.predict_proba(feature_vector)[0]
                malicious_prob = float(proba[1]) if len(proba) > 1 else 0.0
                if malicious_prob > 0.7:
                    return 'malicious', malicious_prob
                elif malicious_prob < 0.3:
                    return 'benign', 1 - malicious_prob
                else:
                    return 'suspicious', malicious_prob
            return None, None
        except Exception as e:
            logger.debug(f"ML prediction skipped: {e}")
            return None, None

    # ============================================
    # SHAP EXPLANATION
    # ============================================

    def explain_prediction(self, url, prediction, confidence):
        """Generate SHAP explanation for a prediction"""
        if self.explainer is None or self.selected_features is None:
            return None, None
        try:
            features = self.extract_url_features(url)
            feature_vector = np.array([
                float(features.get(f, 0.0)) for f in self.selected_features
            ])
            explanation = self.explainer.explain(feature_vector, top_k=5)

            from src.ml_pipeline.explainability import generate_narrative
            narrative = generate_narrative(
                prediction, confidence,
                explanation.get('top_features', []),
                url
            )
            return explanation, narrative
        except Exception as e:
            logger.debug(f"SHAP explanation failed: {e}")
            return None, None

    # ============================================
    # INTELLIGENCE ENRICHMENT
    # ============================================

    def enrich_with_intelligence(self, url, norm=None):
        """
        Enrich prediction with IP/DNS/WHOIS intelligence.
        Returns dict with ip_intel, dns_intel, whois_intel sub-dicts.
        """
        enrichment = {
            'ip_intel': None,
            'dns_intel': None,
            'whois_intel': None
        }

        try:
            if norm and norm.is_valid:
                domain = norm.registered_domain or norm.hostname
            else:
                parsed = urlparse(url)
                domain = (parsed.netloc or '').lower().split(':')[0]
        except Exception:
            return enrichment

        if not domain:
            return enrichment

        # DNS Intel
        try:
            dns = self._get_dns_intel()
            if dns:
                enrichment['dns_intel'] = dns.lookup(domain)
        except Exception as e:
            logger.debug(f"DNS enrichment failed: {e}")

        # WHOIS Intel
        try:
            whois = self._get_whois_intel()
            if whois:
                enrichment['whois_intel'] = whois.lookup(domain)
        except Exception as e:
            logger.debug(f"WHOIS enrichment failed: {e}")

        # IP Intel
        try:
            ip = socket.gethostbyname(domain)
            ipi = self._get_ip_intel()
            if ipi:
                enrichment['ip_intel'] = ipi.check(ip)
        except Exception as e:
            logger.debug(f"IP enrichment failed for {domain}: {e}")

        return enrichment

    # ============================================
    # SCORE HELPERS
    # ============================================

    @staticmethod
    def _rule_result_to_score(rule_result, rule_confidence):
        """
        Convert rule result + confidence to 0-100 risk score.
        - 'malicious'  → 60-100
        - 'suspicious' → 30-60
        - 'benign'     → 0-15
        """
        if rule_result == 'malicious':
            return min(60 + rule_confidence * 40, 100)
        elif rule_result == 'suspicious':
            return min(30 + rule_confidence * 30, 60)
        else:
            return min(rule_confidence * 15, 15)

    def _intel_to_scores(self, intelligence):
        """
        Extract risk scores from intelligence enrichment.
        Returns (ip_score, domain_score, threat_score) each 0-100 or None.
        """
        ip_score = None
        domain_score = None
        threat_score = None

        if not intelligence:
            return ip_score, domain_score, threat_score

        # -------- IP Score --------
        ip_intel = intelligence.get('ip_intel')
        if ip_intel:
            combined = ip_intel.get('combined_risk')
            if combined is not None:
                ip_score = float(combined) * 100

            abuse = ip_intel.get('abuse_score')
            if abuse is not None:
                threat_score = float(abuse)

        # -------- Domain Score --------
        whois_intel = intelligence.get('whois_intel')
        if whois_intel:
            score = 0
            if whois_intel.get('is_new_domain'):
                score += 40
            if whois_intel.get('is_privacy_protected'):
                score += 20
            if whois_intel.get('is_free_tld'):
                score += 30
            if whois_intel.get('is_expiring_soon'):
                score += 10
            domain_score = min(score, 100)

        return ip_score, domain_score, threat_score

    # ============================================
    # MAIN PREDICTION (uses Hybrid Risk Engine)
    # ============================================

    def predict_url(self, url, save_to_db=False, with_intelligence=False):
        """
        Main prediction method.

        Uses the Hybrid Risk Engine to combine:
        - Rule engine score (0-100) — now includes typosquatting
        - ML probability (0-1)
        - IP intelligence score (0-100)
        - Domain intelligence score (0-100) — now includes typosquatting
        - Threat intelligence score (0-100)
        """
        # ============================================
        # Validate
        # ============================================
        if not url or not isinstance(url, str):
            return {
                'url': str(url),
                'prediction': 'error',
                'confidence': 0,
                'risk_level': 'UNKNOWN',
                'error': 'Invalid URL'
            }

        if not url.startswith('http'):
            url = 'http://' + url

        # ============================================
        # STEP 1: Rule-based detection (includes typosquat)
        # ============================================
        rule_result, rule_confidence, reasons = self.rule_based_check(url)
        rule_score = self._rule_result_to_score(rule_result, rule_confidence)

        # ============================================
        # STEP 2: Typosquatting detection (dedicated run)
        # ============================================
        typosquat_result = None
        typosquat_score = 0.0
        if self.typosquat_detector is not None:
            try:
                tq = self.typosquat_detector.analyze(url)
                if tq.is_typosquat:
                    typosquat_score = float(tq.highest_risk)
                    typosquat_result = tq.to_dict()
            except Exception as e:
                logger.debug(f"Typosquat check failed: {e}")

        # ============================================
        # STEP 3: ML probability
        # ============================================
        ml_probability = None
        if self.model is not None and self.selected_features is not None:
            try:
                features = self.extract_url_features(url)
                feature_vector = np.array([
                    float(features.get(f, 0.0)) for f in self.selected_features
                ]).reshape(1, -1)
                if hasattr(self.model, 'predict_proba'):
                    proba = self.model.predict_proba(feature_vector)[0]
                    ml_probability = float(proba[1]) if len(proba) > 1 else 0.0
            except Exception as e:
                logger.debug(f"ML probability extraction failed: {e}")

        # ============================================
        # STEP 4: Normalization
        # ============================================
        norm = None
        try:
            norm = self.normalizer.normalize(url)
        except Exception:
            pass

        # ============================================
        # STEP 5: Intelligence enrichment (optional)
        # ============================================
        intelligence = None
        ip_score = None
        domain_score = None
        threat_score = None

        if with_intelligence:
            try:
                intelligence = self.enrich_with_intelligence(url, norm)
                ip_score, domain_score, threat_score = self._intel_to_scores(intelligence)
            except Exception as e:
                logger.debug(f"Intelligence enrichment failed: {e}")

        # ============================================
        # STEP 6: Blend typosquatting into domain_score
        # ============================================
        if typosquat_score > 0:
            if domain_score is None:
                domain_score = typosquat_score
            else:
                domain_score = max(domain_score, typosquat_score)

        # ============================================
        # STEP 7: Hybrid Risk Engine
        # ============================================
        risk_input = RiskInput(
            rule_score=rule_score,
            ml_probability=ml_probability,
            ip_score=ip_score,
            domain_score=domain_score,
            threat_score=threat_score,
        )
        risk_verdict = self.risk_engine.compute(risk_input)

        # ============================================
        # STEP 8: Map verdict → prediction field
        # ============================================
        verdict = risk_verdict.verdict
        verdict_map = {
            'BENIGN':     ('benign',     'SAFE'),
            'SUSPICIOUS': ('suspicious', 'MEDIUM'),
            'HIGH_RISK':  ('malicious',  'HIGH'),
            'MALICIOUS':  ('malicious',  'HIGH'),
            'UNKNOWN':    ('error',      'UNKNOWN'),
        }
        final_prediction, risk_level = verdict_map.get(verdict, ('suspicious', 'MEDIUM'))

        # ============================================
        # STEP 9: Normalization summary (for UI)
        # ============================================
        norm_summary = None
        if norm and norm.is_valid:
            norm_summary = {
                'normalized_url': norm.normalized_url,
                'decoded_url': norm.decoded_url,
                'scheme': norm.scheme,
                'hostname': norm.hostname,
                'registered_domain': norm.registered_domain,
                'subdomain': norm.subdomain,
                'tld': norm.tld,
                'port': norm.port,
                'path': norm.path,
                'is_ip_host': norm.is_ip_host,
                'is_punycode': norm.is_punycode,
                'has_unicode': norm.has_unicode,
                'percent_encoding_count': norm.percent_encoding_count,
                'has_double_encoding': norm.has_double_encoding,
                'has_at_symbol': norm.has_at_symbol,
                'has_userinfo': norm.has_userinfo,
                'warnings': norm.warnings,
            }

        # ============================================
        # STEP 10: SHAP Explanation
        # ============================================
        explanation = None
        explanation_narrative = None
        if self.explainer is not None:
            explanation, explanation_narrative = self.explain_prediction(
                url, final_prediction, risk_verdict.confidence
            )

        # ============================================
        # STEP 11: Build result
        # ============================================
        result = {
            'url': url,
            'prediction': final_prediction,
            'confidence': round(float(risk_verdict.confidence), 4),
            'risk_level': risk_level,

            # ⭐ Hybrid Risk Engine outputs
            'risk_score': round(risk_verdict.risk_score, 2),
            'verdict': verdict,
            'risk_breakdown': risk_verdict.to_dict(),

            # ⭐ Signal values (transparency)
            'signals': {
                'rule_score': round(rule_score, 2),
                'rule_result': rule_result,
                'ml_probability': round(ml_probability, 4) if ml_probability is not None else None,
                'ip_score': round(ip_score, 2) if ip_score is not None else None,
                'domain_score': round(domain_score, 2) if domain_score is not None else None,
                'threat_score': round(threat_score, 2) if threat_score is not None else None,
                'typosquat_score': round(typosquat_score, 2) if typosquat_score > 0 else None,
            },

            # ⭐ Typosquatting detection
            'typosquat': typosquat_result,

            # Legacy fields (backwards compatible)
            'method': 'hybrid_risk_engine',
            'rule_result': rule_result,
            'rule_confidence': round(float(rule_confidence), 4),
            'reasons': reasons[:8],
            'model': self.model_name,
            'timestamp': datetime.now().isoformat(),

            # Normalization + explainability
            'normalization': norm_summary,
            'explanation': explanation,
            'explanation_narrative': explanation_narrative,

            # Optional intelligence
            'intelligence': intelligence,
        }

        if save_to_db:
            self._save_to_db(url, result)

        return result

    # ============================================
    # DATABASE
    # ============================================

    def _save_to_db(self, url, result):
        """Save prediction to DB"""
        try:
            norm = result.get('normalization') or {}
            domain = norm.get('registered_domain') or norm.get('hostname')
            path = norm.get('path', '/')
            scheme = norm.get('scheme', 'http')
            tld = norm.get('tld', '')

            if not domain:
                parsed = urlparse(url)
                domain = parsed.netloc or url
                path = parsed.path or '/'
                scheme = parsed.scheme or 'http'
                tld = domain.split('.')[-1] if '.' in domain else ''

            url_id = self.crud.insert_url(
                full_url=url,
                domain=domain,
                path=path,
                protocol=scheme,
                tld=tld[:20],
                url_length=len(url),
                source='real_time_prediction'
            )

            if url_id:
                try:
                    self.crud.insert_prediction(
                        url_id=url_id,
                        prediction_score=result['confidence'],
                        predicted_class=result['prediction'],
                        model_name=self.model_name,
                        model_version='latest'
                    )
                except Exception as e:
                    logger.debug(f"Prediction DB save skipped: {e}")

        except Exception as e:
            logger.debug(f"DB save skipped: {e}")

    # ============================================
    # BATCH
    # ============================================

    def predict_batch(self, urls, save_to_db=False, with_intelligence=False):
        """Predict multiple URLs"""
        results = []
        for i, url in enumerate(urls):
            logger.info(f"Scanning {i+1}/{len(urls)}: {url[:60]}...")
            results.append(
                self.predict_url(
                    url,
                    save_to_db=save_to_db,
                    with_intelligence=with_intelligence
                )
            )
        malicious = sum(1 for r in results if r['prediction'] == 'malicious')
        suspicious = sum(1 for r in results if r['prediction'] == 'suspicious')
        benign = sum(1 for r in results if r['prediction'] == 'benign')
        logger.info(f"Batch: {malicious} malicious, {suspicious} suspicious, {benign} benign")
        return results


# ============================================
# UTILITY FUNCTIONS
# ============================================

def find_latest_model(model_type=None):
    """Find the latest trained model"""
    if model_type:
        files = glob.glob(f'models/model_versions/v_*/{model_type}.pkl')
    else:
        files = glob.glob('models/model_versions/v_*/*.pkl')

    if not files:
        return None

    rf_files = [f for f in files if 'random_forest' in f]
    if rf_files:
        return sorted(rf_files)[-1]

    return sorted(files)[-1]


# ============================================
# TEST SUITE
# ============================================

def test_predictor():
    """Comprehensive predictor test with typosquatting"""
    model_path = find_latest_model('random_forest')
    if not model_path:
        model_path = find_latest_model()

    predictor = URLPredictor(model_path) if model_path else URLPredictor()

    print(f"\n{'=' * 95}")
    print(f"🔍 URL PREDICTOR TEST (Full Integration + Typosquatting)")
    print(f"{'=' * 95}")
    print(f"Model:         {predictor.model_name}")
    print(f"SHAP:          {'✅' if predictor.explainer else '❌'}")
    print(f"Normalizer:    ✅")
    print(f"Risk Engine:   ✅")
    print(f"Typosquatting: {'✅' if predictor.typosquat_detector else '❌'}")
    print(f"{'=' * 95}\n")

    tests = [
        # Benign
        ('https://www.google.com', 'benign'),
        ('https://www.github.com', 'benign'),
        ('https://www.youtube.com', 'benign'),
        ('https://www.amazon.com', 'benign'),
        ('https://www.netflix.com', 'benign'),
        # Malicious
        ('http://suspicious-login.xyz/verify/account.php', 'malicious'),
        ('http://paypal-secure.verify-account.ml/login', 'malicious'),
        ('http://banking-update.ga/secure/login.php', 'malicious'),
        ('http://free-iphone-winner.xyz/claim', 'malicious'),
        # Typosquatting
        ('https://gooogle.com/login', 'malicious'),
        ('https://paypa1.com/login', 'malicious'),
        ('https://micros0ft.com/login', 'malicious'),
        ('https://arnazon.com/verify', 'malicious'),
        ('https://g00gle.com/signin', 'malicious'),
        # Homograph (Cyrillic а)
        ('https://аpple.com/login', 'malicious'),
        # Normalizer challenges
        ('HTTPS://PAYPAL.COM:443/login', 'malicious'),
        ('http://trusted.com@evil.com/phishing', 'malicious'),
        ('https://example.com/%6C%6F%67%69%6E', 'suspicious'),
        ('http://192.168.1.1/admin', 'suspicious'),
    ]

    correct = 0
    for url, expected in tests:
        result = predictor.predict_url(url)
        pred = result['prediction']
        verdict = result.get('verdict', 'N/A')
        score = result.get('risk_score', 0)

        # Show typosquat info if detected
        tq_note = ""
        if result.get('typosquat') and result['typosquat'].get('matches'):
            top_match = result['typosquat']['matches'][0]
            tq_note = f" 🎯{top_match['brand']}/{top_match['technique']}"

        ok = "✅" if pred == expected else "❌"
        if pred == expected:
            correct += 1
        print(
            f"{ok} {url[:48]:<48} -> {pred:<11} "
            f"[{verdict:<10}] score={score:>5.1f} conf={result['confidence']:.0%}{tq_note}"
        )

    print(f"\n{'=' * 95}")
    print(f"📊 Accuracy: {correct}/{len(tests)} ({correct/len(tests)*100:.0f}%)")
    print(f"{'=' * 95}\n")

    # Detailed example with typosquatting
    print(f"\n{'=' * 95}")
    print("🧠 SAMPLE FULL BREAKDOWN (Typosquatting case)")
    print(f"{'=' * 95}\n")

    url = "https://paypa1.com/login"
    result = predictor.predict_url(url)

    print(f"URL:         {url}")
    print(f"Prediction:  {result['prediction'].upper()}")
    print(f"Verdict:     {result.get('verdict')}")
    print(f"Risk Score:  {result.get('risk_score')}/100")
    print(f"Confidence:  {result['confidence']:.1%}")

    if result.get('typosquat'):
        tq = result['typosquat']
        print(f"\n🎯 Typosquatting Detection:")
        print(f"  Is typosquat:   {tq['is_typosquat']}")
        print(f"  Highest risk:   {tq['highest_risk']}/100")
        for m in tq.get('matches', []):
            print(
                f"    → Brand: {m['brand']:<12} "
                f"Sim: {m['similarity']:.2f}  "
                f"Technique: {m['technique']:<22}  "
                f"Risk: {m['risk']}"
            )

    signals = result.get('signals', {})
    print(f"\n📡 Signal Values:")
    print(f"  Rule Score:      {signals.get('rule_score', 'N/A')}/100")
    print(f"  Typosquat Score: {signals.get('typosquat_score', 'N/A')}/100")
    print(f"  ML Probability:  {signals.get('ml_probability', 'N/A')}")
    print(f"  Domain Score:    {signals.get('domain_score', 'N/A')}")

    rb = result.get('risk_breakdown', {})
    print(f"\n🎯 Risk Engine Contributions:")
    for signal, contrib in sorted(
        rb.get('contributions', {}).items(),
        key=lambda x: x[1], reverse=True
    ):
        if contrib > 0:
            weight = rb.get('weights_used', {}).get(signal, 0)
            print(f"  • {signal:<16} → {contrib:>6.2f} pts  (weight={weight:.2f})")

    if rb.get('missing_signals'):
        print(f"\n⚠️  Missing signals: {', '.join(rb['missing_signals'])}")

    print(f"\n{result.get('explanation_narrative', 'No narrative available')}")

    print(f"\n{'=' * 95}\n")


if __name__ == "__main__":
    test_predictor()