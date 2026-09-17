"""
URL Normalizer

Normalizes URLs before feature extraction and detection.

What it does:
1. Parses raw URL into structured components (scheme, host, path, query, ...)
2. Decodes percent-encoded characters (with safety checks)
3. Detects IP-based hosts
4. Detects Punycode (international domains)
5. Extracts registered domain + subdomain correctly
6. Normalizes ports, trailing slashes, and case

The output (NormalizedURL) is used by:
- Rule-based detection
- Feature extraction
- ML model inference
"""

import re
import ipaddress
import unicodedata
from urllib.parse import urlparse, unquote, parse_qs
from dataclasses import dataclass, field
from typing import Optional
from loguru import logger


# ============================================
# PUBLIC KNOWN MULTI-PART TLDS
# (used to correctly split subdomain / registered_domain)
# ============================================
KNOWN_MULTI_PART_TLDS = {
    # Country codes with two-part structure
    'co.uk', 'ac.uk', 'gov.uk', 'org.uk', 'me.uk', 'net.uk', 'sch.uk',
    'co.in', 'net.in', 'org.in', 'gov.in', 'ac.in', 'nic.in', 'firm.in', 'gen.in', 'ind.in',
    'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
    'com.br', 'net.br', 'org.br', 'gov.br', 'edu.br',
    'co.jp', 'or.jp', 'ne.jp', 'go.jp', 'ac.jp', 'ad.jp',
    'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn', 'ac.cn',
    'co.kr', 'or.kr', 'ne.kr', 'go.kr', 're.kr', 'ac.kr',
    'co.za', 'org.za', 'net.za', 'gov.za', 'ac.za',
    'com.mx', 'net.mx', 'org.mx', 'gob.mx', 'edu.mx',
    'com.tr', 'net.tr', 'org.tr', 'gov.tr', 'edu.tr',
    'com.sg', 'net.sg', 'org.sg', 'gov.sg', 'edu.sg',
    'com.hk', 'net.hk', 'org.hk', 'gov.hk', 'edu.hk',
    'com.tw', 'net.tw', 'org.tw', 'gov.tw', 'edu.tw',
    'com.ar', 'net.ar', 'org.ar', 'gob.ar', 'edu.ar',
    'com.my', 'net.my', 'org.my', 'gov.my', 'edu.my',
    'co.id', 'or.id', 'ne.id', 'go.id', 'ac.id', 'web.id',
    'com.ph', 'net.ph', 'org.ph', 'gov.ph', 'edu.ph',
    'com.vn', 'net.vn', 'org.vn', 'gov.vn', 'edu.vn',
    'com.pk', 'net.pk', 'org.pk', 'gov.pk', 'edu.pk',
    'com.bd', 'net.bd', 'org.bd', 'gov.bd', 'edu.bd',
    'com.sa', 'net.sa', 'org.sa', 'gov.sa', 'edu.sa',
    'com.eg', 'net.eg', 'org.eg', 'gov.eg', 'edu.eg',
    'com.ng', 'net.ng', 'org.ng', 'gov.ng', 'edu.ng',
    'com.ke', 'net.ke', 'org.ke', 'go.ke', 'ac.ke',
    'com.ua', 'net.ua', 'org.ua', 'gov.ua', 'edu.ua',
    'com.pl', 'net.pl', 'org.pl', 'gov.pl', 'edu.pl',
    'com.ru', 'net.ru', 'org.ru', 'msk.ru', 'spb.ru',
    'com.es', 'net.es', 'org.es', 'gob.es', 'edu.es',
    'com.it', 'net.it', 'org.it', 'gov.it', 'edu.it',
    'com.fr', 'net.fr', 'org.fr', 'gouv.fr',
    'com.de', 'net.de', 'org.de', 'gov.de', 'edu.de',
}

# Multi-part TLD patterns with three parts (rare but exist)
KNOWN_THREE_PART_TLDS = {
    'co.uk.com', 'com.br.com',
}


# ============================================
# DATACLASS FOR NORMALIZED RESULT
# ============================================
@dataclass
class NormalizedURL:
    """Structured result of URL normalization"""

    # Original
    raw_url: str = ""

    # Cleaned
    normalized_url: str = ""
    decoded_url: str = ""

    # Components
    scheme: str = ""
    hostname: str = ""
    registered_domain: str = ""
    subdomain: str = ""
    tld: str = ""
    port: Optional[int] = None
    path: str = "/"
    query: str = ""
    fragment: str = ""

    # Query params (parsed)
    query_params: dict = field(default_factory=dict)
    query_param_count: int = 0

    # Security signals
    is_ip_host: bool = False
    ip_version: Optional[str] = None        # 'IPv4' or 'IPv6'
    is_private_ip: bool = False
    is_punycode: bool = False
    has_unicode: bool = False
    is_https: bool = False

    # Encoding / obfuscation
    percent_encoding_count: int = 0
    has_double_encoding: bool = False       # e.g. %2520
    has_at_symbol: bool = False             # http://trusted@evil.com
    has_userinfo: bool = False              # username:password@host
    userinfo: str = ""

    # Normalization flags
    is_valid: bool = False
    is_normalized: bool = False
    warnings: list = field(default_factory=list)

    def to_dict(self):
        """Convert to dict (JSON-serializable)"""
        return {
            'raw_url': self.raw_url,
            'normalized_url': self.normalized_url,
            'decoded_url': self.decoded_url,
            'scheme': self.scheme,
            'hostname': self.hostname,
            'registered_domain': self.registered_domain,
            'subdomain': self.subdomain,
            'tld': self.tld,
            'port': self.port,
            'path': self.path,
            'query': self.query,
            'fragment': self.fragment,
            'query_params': self.query_params,
            'query_param_count': self.query_param_count,
            'is_ip_host': self.is_ip_host,
            'ip_version': self.ip_version,
            'is_private_ip': self.is_private_ip,
            'is_punycode': self.is_punycode,
            'has_unicode': self.has_unicode,
            'is_https': self.is_https,
            'percent_encoding_count': self.percent_encoding_count,
            'has_double_encoding': self.has_double_encoding,
            'has_at_symbol': self.has_at_symbol,
            'has_userinfo': self.has_userinfo,
            'userinfo': self.userinfo,
            'is_valid': self.is_valid,
            'is_normalized': self.is_normalized,
            'warnings': self.warnings,
        }


# ============================================
# NORMALIZER CLASS
# ============================================
class URLNormalizer:
    """URL normalizer with security-aware parsing"""

    def __init__(self):
        # Default port mapping
        self.default_ports = {
            'http': 80,
            'https': 443,
            'ftp': 21,
            'sftp': 22,
            'ws': 80,
            'wss': 443,
        }

        # Regex for IP hosts
        self.ipv4_regex = re.compile(
            r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
        )

    # ============================================
    # MAIN ENTRY POINT
    # ============================================
    def normalize(self, raw_url):
        """
        Normalize a URL into structured components.

        Args:
            raw_url: Raw URL string

        Returns:
            NormalizedURL dataclass instance
        """
        result = NormalizedURL(raw_url=raw_url or "")

        if not raw_url or not isinstance(raw_url, str):
            result.warnings.append('empty_or_invalid_input')
            return result

        # Trim and strip
        url = raw_url.strip()

        # Add scheme if missing
        if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', url):
            url = 'http://' + url
            result.warnings.append('scheme_added')

        # ============================================
        # PARSE
        # ============================================
        try:
            parsed = urlparse(url)
        except Exception as e:
            result.warnings.append(f'parse_error:{str(e)[:50]}')
            return result

        # Scheme
        scheme = (parsed.scheme or '').lower()
        result.scheme = scheme
        result.is_https = (scheme == 'https')

        # Hostname (lowercase, IDN-safe)
        hostname = (parsed.hostname or '').lower()
        result.hostname = hostname

        # Port
        try:
            result.port = parsed.port
        except ValueError:
            result.warnings.append('invalid_port')
            result.port = None

        # Path
        path = parsed.path or '/'
        result.path = path

        # Query
        result.query = parsed.query or ''

        # Fragment
        result.fragment = parsed.fragment or ''

        # Userinfo (username:password@host)
        if parsed.username or parsed.password:
            result.has_userinfo = True
            result.userinfo = f"{parsed.username or ''}:{parsed.password or ''}"
            result.warnings.append('userinfo_present')

        # ============================================
        # SECURITY CHECKS
        # ============================================

        # 1. Percent encoding count
        result.percent_encoding_count = url.count('%')

        # 2. Double encoding detection (%25 = encoded '%')
        if '%25' in url.lower() or re.search(r'%25[0-9a-fA-F]{2}', url):
            result.has_double_encoding = True
            result.warnings.append('double_encoding')

        # 3. @ symbol in URL (redirect trick)
        # Note: `@` inside userinfo is legitimate; `@` in path/query is not suspicious
        if '@' in url and not result.has_userinfo:
            result.has_at_symbol = True
            result.warnings.append('at_symbol_in_url')

        # 4. Safe decode
        try:
            decoded = unquote(url)
            result.decoded_url = decoded
            # Check if decoded introduces new @ or suspicious chars
            if decoded.count('@') > url.count('@'):
                result.warnings.append('decoded_at_symbol')
        except Exception:
            result.decoded_url = url

        # 5. Unicode / IDN detection
        try:
            ascii_host = hostname.encode('idna').decode('ascii')
            if ascii_host != hostname:
                result.has_unicode = True
                result.warnings.append('unicode_hostname')
        except Exception:
            pass

        # 6. Punycode detection
        if hostname.startswith('xn--') or '.xn--' in hostname:
            result.is_punycode = True
            result.warnings.append('punycode_hostname')

        # ============================================
        # IP HOST DETECTION
        # ============================================
        self._detect_ip_host(result)

        # ============================================
        # DOMAIN SPLITTING
        # ============================================
        if not result.is_ip_host and hostname:
            self._split_domain(result)

        # ============================================
        # QUERY PARAM PARSING
        # ============================================
        if result.query:
            try:
                params = parse_qs(result.query, keep_blank_values=True)
                # Flatten to single values for simplicity
                result.query_params = {
                    k: (v[0] if isinstance(v, list) and len(v) == 1 else v)
                    for k, v in params.items()
                }
                result.query_param_count = len(result.query_params)
            except Exception:
                result.query_param_count = result.query.count('&') + 1

        # ============================================
        # BUILD NORMALIZED URL
        # ============================================
        result.normalized_url = self._build_normalized_url(result)
        result.is_normalized = True
        result.is_valid = bool(result.hostname)

        return result

    # ============================================
    # HELPERS
    # ============================================

    def _detect_ip_host(self, result):
        """Detect IPv4 / IPv6 / private IP hosts"""
        host = result.hostname

        if not host:
            return

        # IPv4
        try:
            ip = ipaddress.ip_address(host)
            result.is_ip_host = True
            result.ip_version = f"IPv{ip.version}"

            if ip.is_private or ip.is_loopback:
                result.is_private_ip = True
                result.warnings.append('private_ip_host')

            return
        except ValueError:
            pass

        # IPv6 in brackets is stripped by urlparse
        if ':' in host:
            try:
                ip = ipaddress.ip_address(host)
                result.is_ip_host = True
                result.ip_version = f"IPv{ip.version}"
                return
            except ValueError:
                pass

        # Also detect obfuscated IPv4 (e.g. 0x7f.0.0.1 or 017700000001)
        if self._looks_like_obfuscated_ip(host):
            result.is_ip_host = True
            result.warnings.append('obfuscated_ip_host')

    def _looks_like_obfuscated_ip(self, host):
        """Detect octet obfuscation like 0x7f.0.0.1 or 0177.0.0.1"""
        parts = host.split('.')
        if len(parts) != 4:
            return False
        for p in parts:
            if not re.match(r'^(0x[0-9a-fA-F]+|0[0-7]+|\d+)$', p):
                return False
        return True

    def _split_domain(self, result):
        """Split hostname into subdomain, registered_domain, tld"""
        host = result.hostname

        # Remove trailing dot
        host = host.rstrip('.')

        parts = host.split('.')
        if len(parts) < 2:
            # e.g. "localhost"
            result.registered_domain = host
            result.tld = ""
            result.subdomain = ""
            return

        # Check for known multi-part TLDs
        last_two = '.'.join(parts[-2:])
        last_three = '.'.join(parts[-3:]) if len(parts) >= 3 else ""

        if last_three in KNOWN_THREE_PART_TLDS:
            result.tld = last_three
            registered_parts = parts[-4:] if len(parts) >= 4 else parts
            result.registered_domain = '.'.join(parts[-4:-1]) + '.' + parts[-1] if len(parts) >= 4 else host
            # Simplify: registered_domain = everything except subdomain
            subdomain_parts = parts[:-4] if len(parts) > 4 else []
        elif last_two in KNOWN_MULTI_PART_TLDS:
            result.tld = last_two
            result.registered_domain = '.'.join(parts[-3:]) if len(parts) >= 3 else host
            subdomain_parts = parts[:-3]
        else:
            # Simple: tld = last part, registered_domain = last two parts
            result.tld = parts[-1]
            result.registered_domain = '.'.join(parts[-2:]) if len(parts) >= 2 else host
            subdomain_parts = parts[:-2]

        result.subdomain = '.'.join(subdomain_parts) if subdomain_parts else ""

    def _build_normalized_url(self, result):
        """Reassemble URL in canonical form"""
        parts = []

        # Scheme
        parts.append(f"{result.scheme}://")

        # Userinfo (if present)
        if result.has_userinfo:
            parts.append(f"{result.userinfo}@")

        # Hostname (brackets for IPv6)
        if result.ip_version == 'IPv6':
            parts.append(f"[{result.hostname}]")
        else:
            parts.append(result.hostname)

        # Port (only if non-default)
        if result.port:
            default = self.default_ports.get(result.scheme)
            if result.port != default:
                parts.append(f":{result.port}")

        # Path (ensure leading slash)
        path = result.path or '/'
        if not path.startswith('/'):
            path = '/' + path
        parts.append(path)

        # Query
        if result.query:
            parts.append(f"?{result.query}")

        # Fragment
        if result.fragment:
            parts.append(f"#{result.fragment}")

        return ''.join(parts)


# ============================================
# QUICK TEST
# ============================================
if __name__ == "__main__":
    import json

    normalizer = URLNormalizer()

    tests = [
        "HTTPS://PAYPAL.COM:443/login",
        "http://sub.domain.example.co.uk:8080/path?x=1&y=2#frag",
        "http://192.168.1.1/admin",
        "https://xn--paypal-9d0b.com/login",
        "https://example.com/%6C%6F%67%69%6E",
        "http://trusted.com@evil.com/phishing",
        "https://example.com/path%2520double",
        "http://0x7f.0.0.1/loopback",
        "https://www.google.com",
    ]

    for url in tests:
        print(f"\n{'='*70}")
        print(f"INPUT: {url}")
        print('='*70)
        r = normalizer.normalize(url)
        print(f"  normalized_url:   {r.normalized_url}")
        print(f"  decoded_url:      {r.decoded_url}")
        print(f"  scheme:           {r.scheme}")
        print(f"  hostname:         {r.hostname}")
        print(f"  registered_domain:{r.registered_domain}")
        print(f"  subdomain:        {r.subdomain}")
        print(f"  tld:              {r.tld}")
        print(f"  port:             {r.port}")
        print(f"  path:             {r.path}")
        print(f"  is_ip_host:       {r.is_ip_host} ({r.ip_version})")
        print(f"  is_punycode:      {r.is_punycode}")
        print(f"  is_https:         {r.is_https}")
        print(f"  percent_encoding: {r.percent_encoding_count}")
        print(f"  has_at_symbol:    {r.has_at_symbol}")
        print(f"  has_userinfo:     {r.has_userinfo}")
        print(f"  warnings:         {r.warnings}")