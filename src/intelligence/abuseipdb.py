"""
AbuseIPDB Provider
Wraps the AbuseIPDB API with caching, rate-limiting, and graceful fallbacks.
"""

import time
import requests
from datetime import datetime, timedelta
from loguru import logger
from config.settings import settings


class AbuseIPDBProvider:
    """Query IP reputation from AbuseIPDB"""

    BASE_URL = "https://api.abuseipdb.com/api/v2/check"

    # In-memory cache: {ip: {'data': dict, 'timestamp': datetime}}
    _cache = {}
    CACHE_TTL_MINUTES = 60

    def __init__(self, api_key=None):
        self.api_key = api_key or settings.ABUSEIPDB_API_KEY
        self.session = requests.Session()
        self.session.headers.update({
            'Accept': 'application/json',
            'User-Agent': 'URL-Security-IPIntel/1.0'
        })
        if self.api_key:
            self.session.headers['Key'] = self.api_key

    # ============================================
    # PUBLIC
    # ============================================

    def is_available(self):
        """Check if API key is configured"""
        return bool(self.api_key) and self.api_key != 'your_abuseipdb_key'

    def check(self, ip_address, force_refresh=False):
        """
        Check an IP against AbuseIPDB.

        Returns:
            dict with normalized fields, or None if unavailable
        """
        # Cache check
        if not force_refresh and ip_address in self._cache:
            cached = self._cache[ip_address]
            age = datetime.now() - cached['timestamp']
            if age < timedelta(minutes=self.CACHE_TTL_MINUTES):
                result = cached['data'].copy()
                result['cached'] = True
                return result

        # API key check
        if not self.is_available():
            logger.debug(f"AbuseIPDB unavailable (no API key) for {ip_address}")
            return None

        # Private IP check — AbuseIPDB doesn't track these
        if self._is_private(ip_address):
            return {
                'ip': ip_address,
                'abuse_score': 0,
                'total_reports': 0,
                'last_reported': None,
                'country': None,
                'isp': None,
                'domain': None,
                'is_whitelisted': False,
                'source': 'abuseipdb',
                'cached': False,
                'note': 'private_ip'
            }

        # Call API
        try:
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': 90,
                'verbose': ''
            }
            response = self.session.get(
                self.BASE_URL,
                params=params,
                timeout=10
            )

            if response.status_code == 200:
                data = response.json().get('data', {})
                result = {
                    'ip': ip_address,
                    'abuse_score': int(data.get('abuseConfidenceScore', 0)),
                    'total_reports': int(data.get('totalReports', 0)),
                    'last_reported': data.get('lastReportedAt'),
                    'country': data.get('countryCode'),
                    'isp': data.get('isp'),
                    'domain': data.get('domain'),
                    'usage_type': data.get('usageType'),       # hosting / ISP / etc.
                    'is_whitelisted': bool(data.get('isWhitelisted', False)),
                    'is_public': bool(data.get('isPublic', True)),
                    'source': 'abuseipdb',
                    'cached': False
                }

                self._cache[ip_address] = {
                    'data': result,
                    'timestamp': datetime.now()
                }
                return result

            elif response.status_code == 429:
                logger.warning(f"AbuseIPDB rate limit hit for {ip_address}")
                return None

            else:
                logger.debug(f"AbuseIPDB returned {response.status_code} for {ip_address}")
                return None

        except requests.exceptions.Timeout:
            logger.debug(f"AbuseIPDB timeout for {ip_address}")
            return None
        except Exception as e:
            logger.debug(f"AbuseIPDB error for {ip_address}: {e}")
            return None

    # ============================================
    # HELPERS
    # ============================================

    @staticmethod
    def _is_private(ip):
        """Check if IP is private/reserved"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return True  # IPv6 or invalid
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
    def clear_cache():
        AbuseIPDBProvider._cache.clear()