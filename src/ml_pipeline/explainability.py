"""
SHAP Explainability Module
Explains WHY the model classified a URL as malicious or benign.

Handles:
- XGBoost, LightGBM, Random Forest (TreeExplainer — fast & exact)
- Logistic Regression, SVM (LinearExplainer)
- Neural Networks (KernelExplainer — slower but works)
- Graceful fallback when SHAP unavailable

Translates SHAP values into human-readable explanations.
"""

import numpy as np
from loguru import logger

# Try importing SHAP
try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False
    logger.warning("SHAP not installed. Run: pip install shap")


# ============================================
# HUMAN-READABLE FEATURE DESCRIPTIONS
# ============================================
FEATURE_DESCRIPTIONS = {
    # URL Structure
    'url_length': ('URL length', 'Long URLs often hide malicious payloads'),
    'domain_length': ('Domain length', 'Unusually long domains can be suspicious'),
    'path_length': ('Path length', 'Deep paths may indicate hidden resources'),
    'subdomain_count': ('Subdomain count', 'Many subdomains often signal phishing'),
    'dot_count': ('Dot count', 'Excessive dots indicate obfuscation'),
    'hyphen_count': ('Hyphen count', 'Many hyphens are common in fake domains'),
    'underscore_count': ('Underscore count', 'Unusual in legitimate domains'),
    'slash_count': ('Slash count', 'Deep URL paths may hide resources'),
    'question_mark_count': ('Query markers', 'Multiple query strings can be suspicious'),
    'equal_count': ('Equals signs', 'Param-heavy URLs may be phishing'),
    'at_count': ('@ symbols', 'Strong indicator of URL redirection tricks'),
    'digit_count': ('Digit count', 'Auto-generated domains use many digits'),
    'letter_count': ('Letter count', 'Composition of the URL string'),
    'digit_ratio': ('Digit ratio', 'High digit ratio = auto-generated domains'),
    'special_char_count': ('Special characters', 'Obfuscation via symbols'),
    'entropy': ('URL entropy', 'Randomness indicates encoded payloads'),

    # Security
    'is_https': ('HTTPS enabled', 'Missing HTTPS is a strong phishing signal'),
    'suspicious_tld': ('Suspicious TLD', 'High-risk TLDs like .tk, .ml, .xyz'),
    'suspicious_keywords_count': ('Suspicious keywords', 'Keywords like "login", "verify", "paypal"'),
    'has_ip_address': ('IP as domain', 'Legitimate sites rarely use raw IPs'),
    'has_hex_chars': ('Hex encoding', 'URL-encoded characters hide intent'),
    'has_suspicious_file_extension': ('Dangerous extension', 'Executable downloads (.exe, .scr, .bat)'),

    # Domain analysis
    'url_depth': ('URL depth', 'Deep paths can hide resources'),
    'query_params_count': ('Query parameters', 'Excessive parameters are suspicious'),
    'domain_token_count': ('Domain tokens', 'Number of parts in the domain'),
    'longest_token_length': ('Longest token', 'Very long tokens indicate randomness'),

    # IP features
    'is_private': ('Private IP', 'Internal network address'),
    'is_ipv6': ('IPv6 address', 'IPv6 protocol in use'),
    'ip_numeric': ('Numeric IP value', 'Encoded IP representation'),
    'threat_score': ('IP threat score', 'Reputation from threat feeds'),
    'total_requests': ('Request count', 'Traffic volume from this IP'),
    'active_threats_count': ('Active threats', 'Known threats tied to this IP'),
    'is_known_malicious': ('Known malicious IP', 'Confirmed threat intelligence hit'),
    'days_since_first_seen': ('Days since first seen', 'Newer IPs are riskier'),
    'octet_1': ('IP octet 1', 'First octet of IPv4 address'),
    'octet_2': ('IP octet 2', 'Second octet of IPv4 address'),
    'octet_3': ('IP octet 3', 'Third octet of IPv4 address'),
    'octet_4': ('IP octet 4', 'Fourth octet of IPv4 address'),

    # DNS features
    'a_record_count': ('DNS A records', 'Number of IP addresses for domain'),
    'has_mx_record': ('MX record', 'Presence of mail exchange record'),
    'has_txt_record': ('TXT record', 'Presence of TXT/SPF record'),
    'has_ns_record': ('NS record', 'Presence of nameserver record'),
    'nameserver_count': ('Nameserver count', 'Number of DNS nameservers'),
    'mx_server_count': ('Mail server count', 'Number of MX servers'),
    'ttl_min': ('Minimum TTL', 'DNS TTL lower bound'),
    'ttl_max': ('Maximum TTL', 'DNS TTL upper bound'),
    'ttl_avg': ('Average TTL', 'Suspiciously low TTL = fast-changing DNS'),
    'dns_resolution_time': ('DNS resolution time', 'Slow DNS is a weak signal'),
    'subdomain_count_dns': ('DNS subdomains', 'Subdomains found in DNS responses'),
    'has_cname': ('CNAME record', 'Canonical name record present'),

    # Geo features
    'country_risk': ('Country risk', 'High-risk geolocation'),
    'has_geolocation': ('Geolocation available', 'Geo data resolved'),
    'latitude': ('Latitude', 'Server location latitude'),
    'longitude': ('Longitude', 'Server location longitude'),
    'isp_length': ('ISP name length', 'ISP identifier characteristic'),
    'org_exists': ('Organization data', 'Organization info present'),

    # Traffic features
    'request_frequency': ('Request frequency', 'Traffic from this IP per minute'),
    'unique_destinations': ('Unique destinations', 'Breadth of IP activity'),
    'protocol_diversity': ('Protocol diversity', 'Number of protocols used'),
    'https_ratio': ('HTTPS ratio', 'Share of HTTPS traffic'),
    'avg_payload_size': ('Average payload size', 'Typical packet size'),
    'port_scan_likelihood': ('Port scan likelihood', 'Signal of scanning behavior'),
    'traffic_burstiness': ('Traffic burstiness', 'Sudden spikes in activity'),
}


def _get_description(feature_name):
    """Get human-readable description for a feature"""
    if feature_name in FEATURE_DESCRIPTIONS:
        return FEATURE_DESCRIPTIONS[feature_name]

    # Fallback: prettify the feature name
    pretty = feature_name.replace('_', ' ').title()
    return (pretty, 'Contributes to the prediction')


# ============================================
# MAIN EXPLAINER
# ============================================

class URLExplainer:
    """
    Explain URL predictions using SHAP.
    Automatically selects the right SHAP explainer for the model type.
    """

    def __init__(self, model, feature_names):
        """
        Args:
            model: Trained sklearn/xgboost/lightgbm/keras model
            feature_names: List of feature names in the same order as training
        """
        self.model = model
        self.feature_names = list(feature_names)
        self.explainer = None
        self.explainer_type = None
        self._init_explainer()

    def _init_explainer(self):
        """Initialize the right SHAP explainer based on model type"""
        if not SHAP_AVAILABLE:
            logger.warning("SHAP unavailable — explainability will use fallback")
            return

        model_class = type(self.model).__name__

        try:
            # Tree-based models (fast, exact)
            if any(name in model_class for name in ['XGB', 'Forest', 'LGBM', 'Boost']):
                try:
                    self.explainer = shap.TreeExplainer(self.model)
                    self.explainer_type = 'tree'
                    logger.info(f"SHAP TreeExplainer initialized for {model_class}")
                    return
                except Exception as e:
                    logger.debug(f"TreeExplainer failed: {e}")

            # Linear models
            if any(name in model_class for name in ['Logistic', 'Linear', 'Ridge', 'SGD']):
                try:
                    # Create a small background dataset
                    background = np.zeros((1, len(self.feature_names)))
                    self.explainer = shap.LinearExplainer(self.model, background)
                    self.explainer_type = 'linear'
                    logger.info(f"SHAP LinearExplainer initialized for {model_class}")
                    return
                except Exception as e:
                    logger.debug(f"LinearExplainer failed: {e}")

            # Fallback to KernelExplainer (slower, works for anything)
            background = np.zeros((5, len(self.feature_names)))
            self.explainer = shap.KernelExplainer(
                lambda x: self.model.predict_proba(x)[:, 1],
                background
            )
            self.explainer_type = 'kernel'
            logger.info(f"SHAP KernelExplainer initialized for {model_class}")

        except Exception as e:
            logger.error(f"Failed to initialize SHAP: {e}")
            self.explainer = None

    # ============================================
    # EXPLAIN A SINGLE PREDICTION
    # ============================================

    def explain(self, feature_vector, top_k=5):
        """
        Explain a single prediction.

        Args:
            feature_vector: 1D array of feature values (same order as feature_names)
            top_k: Number of top contributing features to return

        Returns:
            dict with structured explanation
        """
        try:
            # Ensure proper shape
            features = np.array(feature_vector).reshape(1, -1)

            # Get SHAP values
            if self.explainer is None or self.explainer_type is None:
                return self._fallback_explanation(features, top_k)

            if self.explainer_type == 'tree':
                shap_values = self.explainer.shap_values(features)
                # For binary classification, tree explainers may return list
                if isinstance(shap_values, list):
                    shap_values = shap_values[1]  # Class 1 = malicious
                shap_values = shap_values[0]

            elif self.explainer_type == 'linear':
                shap_values = self.explainer.shap_values(features)
                if isinstance(shap_values, list):
                    shap_values = shap_values[1]
                shap_values = np.array(shap_values).flatten()

            elif self.explainer_type == 'kernel':
                shap_values = self.explainer.shap_values(features, nsamples=100)
                if isinstance(shap_values, list):
                    shap_values = shap_values[1]
                shap_values = np.array(shap_values).flatten()

            else:
                return self._fallback_explanation(features, top_k)

            # Pair features with their SHAP impacts
            contributions = list(zip(self.feature_names, shap_values))
            # Sort by absolute impact
            contributions.sort(key=lambda x: abs(x[1]), reverse=True)

            # Build human-readable top_k
            top_features = []
            for feat_name, impact in contributions[:top_k]:
                description, reason = _get_description(feat_name)
                top_features.append({
                    'feature': feat_name,
                    'description': description,
                    'impact': float(impact),
                    'direction': 'increases_risk' if impact > 0 else 'decreases_risk',
                    'reason': reason,
                    'feature_value': float(features[0][self.feature_names.index(feat_name)])
                })

            return {
                'method': f'SHAP ({self.explainer_type})',
                'top_features': top_features,
                'all_contributions': {f: float(v) for f, v in contributions}
            }

        except Exception as e:
            logger.error(f"Explanation failed: {e}")
            return self._fallback_explanation(feature_vector, top_k)

    # ============================================
    # FALLBACK (when SHAP unavailable)
    # ============================================

    def _fallback_explanation(self, features, top_k=5):
        """Fallback using heuristic importance when SHAP fails"""
        # Simple heuristic: features with non-zero values are "active"
        feature_vector = np.array(features).flatten()

        # Score features by absolute value (crude but useful)
        active = []
        for i, name in enumerate(self.feature_names):
            val = feature_vector[i] if i < len(feature_vector) else 0
            if val != 0:
                active.append((name, abs(val), val))

        active.sort(key=lambda x: x[1], reverse=True)

        top_features = []
        for name, _, val in active[:top_k]:
            description, reason = _get_description(name)
            top_features.append({
                'feature': name,
                'description': description,
                'impact': float(val),
                'direction': 'increases_risk' if val > 0 else 'decreases_risk',
                'reason': reason,
                'feature_value': float(val)
            })

        return {
            'method': 'heuristic_fallback',
            'top_features': top_features,
            'all_contributions': {}
        }

    # ============================================
    # GLOBAL IMPORTANCE (for dashboard)
    # ============================================

    def global_importance(self, X_sample, top_k=10):
        """
        Compute global feature importance across a sample of data.
        Useful for the dashboard "Top features" chart.
        """
        if self.explainer is None:
            return None

        try:
            X = np.array(X_sample)[:100]  # Limit for speed
            if self.explainer_type == 'tree':
                shap_values = self.explainer.shap_values(X)
                if isinstance(shap_values, list):
                    shap_values = shap_values[1]
            else:
                shap_values = self.explainer.shap_values(X, nsamples=50)
                if isinstance(shap_values, list):
                    shap_values = shap_values[1]

            # Mean absolute SHAP value per feature
            mean_abs = np.mean(np.abs(shap_values), axis=0)
            importance = sorted(
                zip(self.feature_names, mean_abs),
                key=lambda x: x[1],
                reverse=True
            )[:top_k]

            return [
                {'feature': f, 'importance': float(v), 'description': _get_description(f)[0]}
                for f, v in importance
            ]
        except Exception as e:
            logger.error(f"Global importance failed: {e}")
            return None


# ============================================
# HUMAN-READABLE NARRATIVE
# ============================================

def generate_narrative(prediction, confidence, top_features, url=''):
    """
    Generate a human-readable explanation string.
    Example:
        "This URL was flagged as MALICIOUS because:
         1. High entropy (randomness) in URL — +31%
         2. Missing HTTPS — +22%
         ..."
    """
    if not top_features:
        return f"Prediction: {prediction.upper()} with {confidence:.0%} confidence."

    # Filter only features that increase risk
    risk_features = [f for f in top_features if f['direction'] == 'increases_risk']

    if prediction.lower() == 'malicious':
        lines = [f"🚨 This URL was flagged as **MALICIOUS** ({confidence:.0%} confidence)."]
        lines.append("")
        lines.append("**Top contributing factors:**")
        for i, f in enumerate(risk_features[:4], 1):
            impact_pct = abs(f['impact']) * 100
            lines.append(f"{i}. **{f['description']}** — {f['reason']} (+{impact_pct:.1f}%)")
    else:
        lines = [f"✅ This URL appears **BENIGN** ({confidence:.0%} confidence)."]
        lines.append("")
        safe_features = [f for f in top_features if f['direction'] == 'decreases_risk']
        if safe_features:
            lines.append("**Reasons it looks safe:**")
            for i, f in enumerate(safe_features[:3], 1):
                impact_pct = abs(f['impact']) * 100
                lines.append(f"{i}. **{f['description']}** — {f['reason']} (-{impact_pct:.1f}%)")

    return "\n".join(lines)