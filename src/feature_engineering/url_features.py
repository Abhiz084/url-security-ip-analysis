"""
URL Structural Feature Extractor (Enhanced)

Uses URLNormalizer to safely parse URLs and extract ~40 features
ready for ML training.
"""

import math
import re
from collections import Counter
from urllib.parse import urlparse
from loguru import logger

from src.normalization.url_normalizer import URLNormalizer


class URLFeatureExtractor:
    """Extract URL structural features for ML"""

    def __init__(self):
        self.normalizer = URLNormalizer()

        # Suspicious TLDs
        self.suspicious_tlds = {
            'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work', 'date',
            'click', 'icu', 'cfd', 'gdn', 'bond', 'cyou', 'sbs', 'hair',
            'monster', 'lol', 'pics', 'download', 'review', 'country',
            'stream', 'loan', 'win', 'racing', 'accountant', 'science',
            'party', 'webcam', 'bid', 'trade', 'cricket', 'men',
        }

        # Suspicious keywords
        self.suspicious_keywords = [
            'login', 'signin', 'verify', 'secure', 'account', 'update',
            'confirm', 'banking', 'password', 'credential', 'paypal',
            'billing', 'support', 'alert', 'recovery', 'unlock', 'validate',
        ]

        # Suspicious file extensions
        self.suspicious_extensions = {
            '.exe', '.bat', '.cmd', '.msi', '.scr', '.js', '.vbs',
            '.ps1', '.jar', '.apk', '.dmg', '.deb', '.rpm', '.hta',
        }

        # Suspicious chars for regex
        self.special_chars = set('!@#$%^&*()_+-=[]{}|;:,.<>?/~`')

    # ============================================
    # MAIN ENTRY
    # ============================================
    def extract_all_features(self, url, domain=None, path=None, protocol=None, tld=None):
        """
        Extract all URL structural features.

        Args:
            url: Full URL string
            domain/path/protocol/tld: Optional overrides (legacy support)

        Returns:
            dict of features
        """
        # Normalize first
        try:
            norm = self.normalizer.normalize(url)
            if not norm.is_valid:
                logger.debug(f"URL normalization failed for: {url[:80]}")
        except Exception as e:
            logger.debug(f"Normalizer crashed for {url[:80]}: {e}")
            norm = None

        # Fallback parsing if normalizer failed
        if norm is None or not norm.hostname:
            parsed = urlparse(url)
            norm = type('obj', (object,), {
                'normalized_url': url,
                'decoded_url': url,
                'scheme': parsed.scheme or 'http',
                'hostname': domain or parsed.netloc or '',
                'registered_domain': domain or parsed.netloc or '',
                'subdomain': '',
                'tld': tld or (domain.split('.')[-1] if domain and '.' in domain else ''),
                'port': None,
                'path': path or parsed.path or '/',
                'query': parsed.query or '',
                'query_param_count': 0,
                'is_ip_host': False,
                'is_punycode': False,
                'has_unicode': False,
                'is_https': parsed.scheme == 'https',
                'percent_encoding_count': url.count('%'),
                'has_double_encoding': False,
                'has_at_symbol': '@' in url,
                'has_userinfo': False,
                'is_private_ip': False,
            })()

        # ============================================
        # BASIC LENGTH FEATURES
        # ============================================
        features = {
            'url_length': len(url),
            'normalized_length': len(norm.normalized_url),
            'decoded_length': len(norm.decoded_url),
            'hostname_length': len(norm.hostname),
            'domain_length': len(norm.registered_domain),
            'subdomain_length': len(norm.subdomain),
            'path_length': len(norm.path),
            'query_length': len(norm.query),
            'fragment_length': len(getattr(norm, 'fragment', '') or ''),

            # ============================================
            # COUNT FEATURES
            # ============================================
            'dot_count': url.count('.'),
            'hyphen_count': url.count('-'),
            'underscore_count': url.count('_'),
            'slash_count': url.count('/'),
            'question_mark_count': url.count('?'),
            'equal_count': url.count('='),
            'ampersand_count': url.count('&'),
            'at_count': url.count('@'),
            'colon_count': url.count(':'),
            'percent_encoding_count': norm.percent_encoding_count,
            'digit_count': sum(c.isdigit() for c in url),
            'letter_count': sum(c.isalpha() for c in url),
            'special_character_count': sum(1 for c in url if c in self.special_chars),

            # ============================================
            # RATIO FEATURES
            # ============================================
            'digit_ratio': round(sum(c.isdigit() for c in url) / max(len(url), 1), 4),
            'special_ratio': round(
                sum(1 for c in url if c in self.special_chars) / max(len(url), 1), 4
            ),

            # ============================================
            # ENTROPY
            # ============================================
            'entropy': round(self._entropy(url), 4),
            'hostname_entropy': round(self._entropy(norm.hostname), 4),
            'path_entropy': round(self._entropy(norm.path), 4),

            # ============================================
            # DOMAIN STRUCTURE
            # ============================================
            'subdomain_count': len([p for p in norm.subdomain.split('.') if p]) if norm.subdomain else 0,
            'domain_token_count': len([p for p in norm.registered_domain.split('.') if p]),
            'tld_length': len(norm.tld or ''),
            'longest_token_length': self._longest_token_length(norm.registered_domain),

            # ============================================
            # SECURITY FLAGS
            # ============================================
            'is_https': 1 if norm.is_https else 0,
            'has_port': 1 if norm.port else 0,
            'port': norm.port or 0,
            'non_standard_port': 1 if self._is_nonstandard_port(norm) else 0,

            'is_ip_host': 1 if norm.is_ip_host else 0,
            'is_private_ip': 1 if getattr(norm, 'is_private_ip', False) else 0,
            'is_punycode': 1 if norm.is_punycode else 0,
            'has_unicode': 1 if norm.has_unicode else 0,

            'suspicious_tld': 1 if (norm.tld or '').lower() in self.suspicious_tlds else 0,
            'suspicious_keywords_count': self._count_keywords(url),
            'suspicious_file_extension': 1 if self._has_suspicious_extension(norm.path) else 0,

            'has_hex_chars': 1 if self._has_hex(norm.normalized_url) else 0,
            'has_double_encoding': 1 if norm.has_double_encoding else 0,
            'has_at_symbol': 1 if norm.has_at_symbol else 0,
            'has_userinfo': 1 if norm.has_userinfo else 0,

            # ============================================
            # PATH / QUERY
            # ============================================
            'url_depth': self._path_depth(norm.path),
            'query_param_count': norm.query_param_count,
            'has_query': 1 if norm.query else 0,
            'has_fragment': 1 if getattr(norm, 'fragment', '') else 0,

            # ============================================
            # LEXICAL DIVERSITY
            # ============================================
            'unique_char_count': len(set(url)),
            'unique_char_ratio': round(len(set(url)) / max(len(url), 1), 4),
        }

        return features

    # ============================================
    # HELPERS
    # ============================================

    @staticmethod
    def _entropy(text):
        """Shannon entropy of a string"""
        if not text:
            return 0.0
        counts = Counter(text)
        length = len(text)
        return -sum(
            (count / length) * math.log2(count / length)
            for count in counts.values()
        )

    @staticmethod
    def _longest_token_length(domain):
        if not domain:
            return 0
        tokens = re.split(r'[.\-_]', domain)
        return max((len(t) for t in tokens if t), default=0)

    @staticmethod
    def _path_depth(path):
        if not path:
            return 0
        return len([p for p in path.split('/') if p])

    def _count_keywords(self, url):
        url_lower = url.lower()
        return sum(1 for kw in self.suspicious_keywords if kw in url_lower)

    def _has_suspicious_extension(self, path):
        if not path:
            return False
        path_lower = path.lower().split('?')[0]
        return any(path_lower.endswith(ext) for ext in self.suspicious_extensions)

    @staticmethod
    def _has_hex(url):
        """Detect hex-encoded sequences like %6C%6F%67"""
        return 1 if re.search(r'(%[0-9a-fA-F]{2}){3,}', url) else 0

    def _is_nonstandard_port(self, norm):
        """Return True if URL uses unusual port"""
        if not norm.port:
            return False
        default = {'http': 80, 'https': 443, 'ftp': 21, 'ws': 80, 'wss': 443}
        return norm.port != default.get(norm.scheme)


# ============================================
# QUICK TEST
# ============================================
if __name__ == "__main__":
    import json
    extractor = URLFeatureExtractor()

    tests = [
        "https://www.google.com",
        "http://suspicious-login.xyz/verify/account.php",
        "http://192.168.1.1/admin",
        "https://xn--paypal-9d0b.com/login",
        "http://trusted.com@evil.com/phishing",
        "HTTPS://PAYPAL.COM:443/login",
        "https://example.com/%6C%6F%67%69%6E",
    ]

    for url in tests:
        print(f"\n{'='*70}")
        print(f"URL: {url}")
        print('='*70)
        f = extractor.extract_all_features(url)
        # Print a subset
        keys_of_interest = [
            'url_length', 'hostname_length', 'path_length',
            'subdomain_count', 'dot_count', 'hyphen_count',
            'digit_count', 'special_character_count', 'percent_encoding_count',
            'entropy', 'is_https', 'is_ip_host', 'is_punycode', 'has_unicode',
            'suspicious_tld', 'suspicious_keywords_count', 'has_at_symbol',
            'has_double_encoding', 'port', 'url_depth',
        ]
        for k in keys_of_interest:
            if k in f:
                print(f"  {k:<32} = {f[k]}")