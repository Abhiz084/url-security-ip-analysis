"""
IP Intelligence Orchestrator

Unified interface for querying IP reputation, geolocation, and risk signals.

Sources:
- AbuseIPDB (external reputation)
- Internal DB (previous detections)
- IP-API (geolocation + ASN — free tier, no API key)
- ASN heuristics (hosting / VPN / Tor detection)

Usage:
    from src.intelligence.ip_intelligence import IPIntelligence
    intel = IPIntelligence()
    result = intel.check("8.8.8.8")
"""

import time
import socket
import requests
from datetime import datetime
from loguru import logger

from src.intelligence.abuseipdb import AbuseIPDBProvider
from src.intelligence.internal_reputation import InternalReputationProvider


class IPIntelligence:
    """Unified IP intelligence orchestrator"""

    # ============================================
    # ASN HEURISTICS FOR INFRASTRUCTURE CLASSIFICATION
    # ============================================

    # Known hosting/datacenter ASNs (subset — extend as needed)
    HOSTING_ASNS = {
        'AS16509',  # Amazon AWS
        'AS14618',  # Amazon AWS
        'AS14061',  # DigitalOcean
        'AS63949',  # Linode
        'AS20473',  # Vultr / Choopa
        'AS16276',  # OVH
        'AS24940',  # Hetzner
        'AS12876',  # Scaleway
        'AS60781',  # LeaseWeb
        'AS9009',   # M247
        'AS4766',   # Korea Telecom (often abused)
        'AS45102',  # Alibaba Cloud
        'AS132203', # Tencent Cloud
        'AS8075',   # Microsoft Azure
        'AS15169',  # Google Cloud
        'AS396982', # Google Cloud
        'AS13335',  # Cloudflare
    }

    # Known VPN ASNs
    VPN_ASNS = {
        'AS9009',    # M247 (NordVPN, others)
        'AS212238',  # Datacamp (used by VPNs)
        'AS62240',   # Clouvider (used by VPNs)
        'AS49981',   # WorldStream (VPNs)
        'AS60068',   # Datacamp CDN77 (VPNs)
    }

    # Known Tor exit ranges (subset — for full accuracy, fetch from
    # https://check.torproject.org/torbulkexitlist periodically)
    TOR_EXIT_RANGES = [
        '185.220.',  # Common Tor exit prefix
        '51.15.',
        '51.75.',
        '51.77.',
        '51.89.',
        '176.10.',
        '176.126.',
        '199.249.',
        '204.13.',
        '171.25.',
        '46.165.',
    ]

    # Countries with elevated cybercrime origin statistics
    HIGH_RISK_COUNTRIES = {
        'KP',  # North Korea
        'IR',  # Iran
        'SY',  # Syria
        'SD',  # Sudan
        'CU',  # Cuba
        'VE',  # Venezuela
        'RU',  # Russia
        'BY',  # Belarus
        'MM',  # Myanmar
    }

    # Medium-risk countries
    MEDIUM_RISK_COUNTRIES = {'CN', 'NG', 'PK', 'BD', 'VN', 'ID', 'UA', 'TR'}

    # ============================================
    # INIT
    # ============================================

    def __init__(self):
        self.abuseipdb = AbuseIPDBProvider()
        self.internal = InternalReputationProvider()

        # Cache for geo/ASN lookups
        self._geo_cache = {}
        self._geo_cache_ttl = 24 * 60 * 60  # 24 hours

    # ============================================
    # PUBLIC API
    # ============================================

    def check(self, ip_address):
        """
        Main entry point. Returns unified intelligence dict.
        """
        if not self._is_valid_ip(ip_address):
            return self._empty_result(ip_address, error='invalid_ip')

        # Private IPs skip external lookups
        if self._is_private(ip_address):
            return self._empty_result(ip_address, note='private_ip')

        # 1. Internal reputation (fast, always works)
        internal_data = self.internal.check(ip_address)

        # 2. AbuseIPDB (external, might fail)
        abuse_data = self.abuseipdb.check(ip_address)

        # 3. Geo/ASN lookup (free tier)
        geo_data = self._lookup_geo_asn(ip_address)

        # 4. Merge everything
        return self._merge_results(ip_address, internal_data, abuse_data, geo_data)

    # ============================================
    # GEO / ASN LOOKUP
    # ============================================

    def _lookup_geo_asn(self, ip_address):
        """Lookup geolocation and ASN via ip-api.com (free, no key)"""
        # Cache
        if ip_address in self._geo_cache:
            cached = self._geo_cache[ip_address]
            if time.time() - cached['ts'] < self._geo_cache_ttl:
                return cached['data']

        try:
            # ip-api.com free tier: 45 requests/minute
            url = f"http://ip-api.com/json/{ip_address}"
            params = {'fields': 'status,country,countryCode,regionName,city,lat,lon,isp,org,as,asname,proxy,hosting,mobile'}

            response = requests.get(url, params=params, timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    result = {
                        'country': data.get('country'),
                        'country_code': data.get('countryCode'),
                        'region': data.get('regionName'),
                        'city': data.get('city'),
                        'latitude': data.get('lat'),
                        'longitude': data.get('lon'),
                        'isp': data.get('isp'),
                        'organization': data.get('org'),
                        'asn': data.get('as', '').split()[0] if data.get('as') else None,
                        'asn_name': data.get('asname'),
                        'is_proxy': bool(data.get('proxy', False)),
                        'is_hosting': bool(data.get('hosting', False)),
                        'is_mobile': bool(data.get('mobile', False)),
                        'source': 'ip-api'
                    }
                    self._geo_cache[ip_address] = {
                        'data': result,
                        'ts': time.time()
                    }
                    return result
        except Exception as e:
            logger.debug(f"Geo lookup failed for {ip_address}: {e}")

        return {}

    # ============================================
    # MERGE + CLASSIFY
    # ============================================

    def _merge_results(self, ip, internal, abuse, geo):
        """Merge all sources into unified result"""

        # -------- Base fields --------
        result = {
            'ip': ip,
            'country': None,
            'country_code': None,
            'city': None,
            'region': None,
            'latitude': None,
            'longitude': None,
            'asn': None,
            'asn_name': None,
            'organization': None,
            'isp': None,

            # Reputation scores
            'abuse_score': 0,
            'total_reports': 0,
            'last_reported': None,
            'internal_threat_score': 0.0,
            'internal_alerts': 0,
            'active_threats': 0,
            'threat_types': [],

            # Classification flags
            'is_hosting': False,
            'is_vpn': False,
            'is_tor': False,
            'is_proxy': False,

            # Risk metrics
            'asn_risk': 0.0,       # 0.0 – 1.0
            'country_risk': 0.0,   # 0.0 – 1.0
            'combined_risk': 0.0,  # 0.0 – 1.0

            # Meta
            'sources': [],
            'timestamp': datetime.now().isoformat()
        }

        # -------- 1. Internal data --------
        if internal:
            result['sources'].append('internal')
            for key in ['country', 'city', 'region', 'latitude', 'longitude',
                        'asn', 'organization', 'isp',
                        'internal_threat_score', 'internal_alerts',
                        'active_threats', 'threat_types', 'total_requests']:
                if internal.get(key) is not None:
                    result[key] = internal[key]

        # -------- 2. AbuseIPDB data --------
        if abuse:
            result['sources'].append('abuseipdb')
            result['abuse_score'] = abuse.get('abuse_score', 0)
            result['total_reports'] = abuse.get('total_reports', 0)
            result['last_reported'] = abuse.get('last_reported')

            # Fill missing fields
            if not result['country'] and abuse.get('country'):
                result['country'] = abuse['country']
                result['country_code'] = abuse.get('country')
            if not result['isp'] and abuse.get('isp'):
                result['isp'] = abuse['isp']

        # -------- 3. Geo/ASN data (highest priority for geo) --------
        if geo:
            result['sources'].append('ip-api')
            for key in ['country', 'country_code', 'region', 'city',
                        'latitude', 'longitude', 'isp', 'organization',
                        'asn', 'asn_name']:
                if geo.get(key):
                    result[key] = geo[key]

            if geo.get('is_proxy'):
                result['is_proxy'] = True
            if geo.get('is_hosting'):
                result['is_hosting'] = True

        # -------- 4. Heuristic classification --------
        result['is_tor'] = self._is_tor_exit(ip)
        result['is_hosting'] = result['is_hosting'] or self._is_hosting_asn(result['asn'])
        result['is_vpn'] = self._is_vpn_asn(result['asn'])
        result['is_proxy'] = result['is_proxy'] or result['is_vpn'] or result['is_tor']

        # -------- 5. Risk scores --------
        result['asn_risk'] = self._compute_asn_risk(result['asn'], result['is_hosting'])
        result['country_risk'] = self._compute_country_risk(result.get('country_code'))
        result['combined_risk'] = self._compute_combined_risk(result)

        return result

    # ============================================
    # RISK HEURISTICS
    # ============================================

    def _is_tor_exit(self, ip):
        for prefix in self.TOR_EXIT_RANGES:
            if ip.startswith(prefix):
                return True
        return False

    def _is_hosting_asn(self, asn):
        if not asn:
            return False
        return asn.upper() in self.HOSTING_ASNS

    def _is_vpn_asn(self, asn):
        if not asn:
            return False
        return asn.upper() in self.VPN_ASNS

    def _compute_asn_risk(self, asn, is_hosting):
        """ASN risk: hosting providers = higher risk (often abused for phishing)"""
        risk = 0.0
        if is_hosting:
            risk += 0.5
        if asn and asn.upper() in self.HOSTING_ASNS:
            risk += 0.2
        return min(risk, 1.0)

    def _compute_country_risk(self, country_code):
        if not country_code:
            return 0.0
        cc = country_code.upper()
        if cc in self.HIGH_RISK_COUNTRIES:
            return 0.9
        if cc in self.MEDIUM_RISK_COUNTRIES:
            return 0.4
        return 0.0

    def _compute_combined_risk(self, result):
        """
        Weighted combination of all risk signals → 0.0 – 1.0
        """
        weights = {
            'abuse_score': 0.35,           # 0-100 scale
            'internal_threat_score': 0.20, # 0-100 scale
            'asn_risk': 0.15,              # 0-1
            'country_risk': 0.10,          # 0-1
            'threat_bonus': 0.10,          # 0-1 (active threats)
            'alert_bonus': 0.10            # 0-1 (recent alerts)
        }

        abuse = result.get('abuse_score', 0) / 100.0
        internal = result.get('internal_threat_score', 0) / 100.0
        asn_risk = result.get('asn_risk', 0)
        country = result.get('country_risk', 0)
        threats = min(result.get('active_threats', 0) / 5.0, 1.0)
        alerts = min(result.get('internal_alerts', 0) / 10.0, 1.0)

        combined = (
            weights['abuse_score'] * abuse +
            weights['internal_threat_score'] * internal +
            weights['asn_risk'] * asn_risk +
            weights['country_risk'] * country +
            weights['threat_bonus'] * threats +
            weights['alert_bonus'] * alerts
        )

        # Boost for known-bad flags
        if result.get('is_tor'):
            combined = min(combined + 0.3, 1.0)
        if result.get('is_vpn'):
            combined = min(combined + 0.1, 1.0)

        return round(combined, 4)

    # ============================================
    # HELPERS
    # ============================================

    @staticmethod
    def _is_valid_ip(ip):
        try:
            socket.inet_aton(ip)
            return True
        except:
            return False

    @staticmethod
    def _is_private(ip):
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return True
            a, b = int(parts[0]), int(parts[1])
            return (
                a == 10 or
                a == 127 or
                (a == 172 and 16 <= b <= 31) or
                (a == 192 and b == 168) or
                (a == 169 and b == 254)
            )
        except:
            return True

    @staticmethod
    def _empty_result(ip, note=None, error=None):
        return {
            'ip': ip,
            'country': None, 'country_code': None, 'city': None, 'region': None,
            'latitude': None, 'longitude': None,
            'asn': None, 'asn_name': None, 'organization': None, 'isp': None,
            'abuse_score': 0, 'total_reports': 0, 'last_reported': None,
            'internal_threat_score': 0.0, 'internal_alerts': 0,
            'active_threats': 0, 'threat_types': [],
            'is_hosting': False, 'is_vpn': False, 'is_tor': False, 'is_proxy': False,
            'asn_risk': 0.0, 'country_risk': 0.0, 'combined_risk': 0.0,
            'sources': [],
            'note': note,
            'error': error,
            'timestamp': datetime.now().isoformat()
        }