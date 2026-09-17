"""
WHOIS Intelligence Provider

Extracts domain registration info:
- creation_date → domain_age_days
- expiration_date → days_until_expiry
- registrar, updated_date
- name servers

Detects:
- Newly registered domains (< 30 days)
- Domains expiring soon
- Free / privacy-protected registrations

Timeouts are critical — WHOIS servers can hang for 30+ seconds.
We cap each lookup at ~5 seconds.
"""

import socket
import time
from datetime import datetime, timezone
from loguru import logger


# Try to import whois library
try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False
    logger.warning("python-whois not installed. Run: pip install python-whois")


class WHOISIntelligence:
    """WHOIS lookup with strict timeouts and caching"""

    _cache = {}
    CACHE_TTL_SECONDS = 24 * 60 * 60  # 24 hours — WHOIS rarely changes

    # Socket timeout for WHOIS (critical!)
    SOCKET_TIMEOUT = 5

    # Known "privacy / free" registrars
    PRIVACY_REGISTRARS = {
        'namecheap', 'godaddy', 'namesilo', 'cloudflare',
        'tucows', 'enom', 'publicdomainregistry',
        'privacy', 'whoisguard', 'domainsbyproxy'
    }

    # Free TLD registrars (high-abuse)
    FREE_TLD_PATTERNS = ['.tk', '.ml', '.ga', '.cf', '.gq']

    def __init__(self):
        if not WHOIS_AVAILABLE:
            logger.debug("WHOIS library not available; WHOIS features disabled")

    # ============================================
    # PUBLIC
    # ============================================

    def lookup(self, domain, force_refresh=False):
        """
        WHOIS lookup for a domain.

        Returns dict with:
        - creation_date, expiration_date, updated_date
        - registrar, registrant org
        - name_servers
        - domain_age_days, days_until_expiry
        - is_new_domain, is_expiring_soon
        - is_privacy_protected
        - is_free_tld
        - whois_success
        """
        if not WHOIS_AVAILABLE:
            return self._empty_result(domain, error='whois_not_installed')

        if not domain or not isinstance(domain, str):
            return self._empty_result(domain, error='invalid_domain')

        # Normalize
        domain = domain.lower().strip().rstrip('.')
        # Strip subdomains → keep base domain only
        parts = domain.split('.')
        if len(parts) > 2:
            domain = '.'.join(parts[-2:])

        # Cache
        if not force_refresh and domain in self._cache:
            entry = self._cache[domain]
            if time.time() - entry['ts'] < self.CACHE_TTL_SECONDS:
                result = entry['data'].copy()
                result['cached'] = True
                return result

        # Perform lookup with socket timeout
        result = self._empty_result(domain)
        original_timeout = socket.getdefaulttimeout()

        try:
            # Set global socket timeout to prevent hanging
            socket.setdefaulttimeout(self.SOCKET_TIMEOUT)

            start = time.time()
            w = whois.whois(domain)
            elapsed = time.time() - start

            result['lookup_time_ms'] = round(elapsed * 1000, 2)
            result['whois_success'] = 1

            # -------- Dates --------
            creation = self._first_date(w.get('creation_date'))
            expiration = self._first_date(w.get('expiration_date'))
            updated = self._first_date(w.get('updated_date'))

            result['creation_date'] = creation.isoformat() if creation else None
            result['expiration_date'] = expiration.isoformat() if expiration else None
            result['updated_date'] = updated.isoformat() if updated else None

            # Domain age
            if creation:
                now = datetime.now(timezone.utc)
                # Make timezone aware if needed
                if creation.tzinfo is None:
                    creation = creation.replace(tzinfo=timezone.utc)
                result['domain_age_days'] = (now - creation).days
                result['is_new_domain'] = 1 if result['domain_age_days'] < 30 else 0

            # Expiry check
            if expiration:
                now = datetime.now(timezone.utc)
                if expiration.tzinfo is None:
                    expiration = expiration.replace(tzinfo=timezone.utc)
                days_left = (expiration - now).days
                result['days_until_expiry'] = days_left
                result['is_expiring_soon'] = 1 if 0 < days_left < 30 else 0

            # -------- Registrar --------
            registrar = w.get('registrar')
            if isinstance(registrar, list):
                registrar = registrar[0] if registrar else None
            result['registrar'] = str(registrar)[:200] if registrar else None

            # Privacy detection
            if registrar:
                reg_lower = str(registrar).lower()
                result['is_privacy_protected'] = 1 if any(
                    p in reg_lower for p in self.PRIVACY_REGISTRARS
                ) else 0

            # -------- Registrant org --------
            org = w.get('org')
            if isinstance(org, list):
                org = org[0] if org else None
            result['registrant_org'] = str(org)[:200] if org else None

            # -------- Name servers --------
            ns = w.get('name_servers')
            if ns:
                if isinstance(ns, str):
                    ns = [ns]
                result['name_servers'] = [
                    str(n).lower().rstrip('.') for n in ns
                ][:10]
                result['nameserver_count'] = len(result['name_servers'])

            # -------- Free TLD check --------
            for pattern in self.FREE_TLD_PATTERNS:
                if domain.endswith(pattern):
                    result['is_free_tld'] = 1
                    break

            # -------- New domain risk flag --------
            if result['is_new_domain']:
                result['new_domain_risk'] = 1
            elif result['domain_age_days'] and result['domain_age_days'] < 90:
                result['new_domain_risk'] = 0.5
            else:
                result['new_domain_risk'] = 0.0

        except Exception as e:
            logger.debug(f"WHOIS failed for {domain}: {e}")
            result['error'] = str(e)[:200]

        finally:
            # Restore original timeout
            socket.setdefaulttimeout(original_timeout)

        # Cache
        self._cache[domain] = {
            'data': result,
            'ts': time.time()
        }

        return result

    # ============================================
    # HELPERS
    # ============================================

    @staticmethod
    def _first_date(value):
        """WHOIS may return a list of dates; take the earliest"""
        if not value:
            return None
        if isinstance(value, list):
            value = [v for v in value if isinstance(v, datetime)]
            return min(value) if value else None
        if isinstance(value, datetime):
            return value
        return None

    @staticmethod
    def _empty_result(domain, error=None):
        return {
            'domain': domain,
            'creation_date': None,
            'expiration_date': None,
            'updated_date': None,
            'registrar': None,
            'registrant_org': None,
            'name_servers': [],
            'nameserver_count': 0,
            'domain_age_days': 0,
            'days_until_expiry': 0,
            'is_new_domain': 0,
            'is_expiring_soon': 0,
            'is_privacy_protected': 0,
            'is_free_tld': 0,
            'new_domain_risk': 0.0,
            'lookup_time_ms': 0,
            'whois_success': 0,
            'cached': False,
            'error': error
        }

    @staticmethod
    def clear_cache():
        WHOISIntelligence._cache.clear()