"""
DNS Intelligence Provider
Collects A, AAAA, MX, NS, TXT, CNAME records with caching and timeouts.

Detects:
- SPF (email spoofing protection)
- DMARC (email authentication)
- Nameserver count
- Missing MX (phishing sign)
- DNS resolution time

All lookups have strict timeouts so the pipeline never hangs.
"""

import time
import dns.resolver
import dns.exception
from datetime import datetime, timedelta
from loguru import logger


class DNSIntelligence:
    """DNS record collection with caching"""

    # Module-level cache: {domain: {'data': dict, 'ts': float}}
    _cache = {}
    CACHE_TTL_SECONDS = 6 * 60 * 60  # 6 hours

    # Timeouts
    QUERY_TIMEOUT = 3       # per-query timeout
    QUERY_LIFETIME = 5      # total lifetime

    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = self.QUERY_TIMEOUT
        self.resolver.lifetime = self.QUERY_LIFETIME

        # Common nameservers for fallback
        try:
            self.resolver.nameservers = ['8.8.8.8', '1.1.1.1']  # Google, Cloudflare
        except Exception as e:
            logger.debug(f"Could not set nameservers: {e}")

    # ============================================
    # PUBLIC
    # ============================================

    def lookup(self, domain, force_refresh=False):
        """
        Full DNS intelligence lookup.

        Returns:
            dict with all record types + derived flags
        """
        if not domain or not isinstance(domain, str):
            return self._empty_result()

        # Normalize domain
        domain = domain.lower().strip().rstrip('.')

        # Cache check
        if not force_refresh and domain in self._cache:
            entry = self._cache[domain]
            if time.time() - entry['ts'] < self.CACHE_TTL_SECONDS:
                result = entry['data'].copy()
                result['cached'] = True
                return result

        # Perform lookups
        result = self._empty_result()
        result['domain'] = domain
        result['cached'] = False

        start_time = time.time()

        # A records
        result['a_records'] = self._query(domain, 'A')

        # AAAA records (IPv6)
        result['aaaa_records'] = self._query(domain, 'AAAA')

        # MX records (mail servers)
        result['mx_records'] = self._query(domain, 'MX', extract='exchange')

        # NS records (nameservers)
        result['nameservers'] = self._query(domain, 'NS')

        # TXT records (SPF, DMARC, verification)
        txt_records = self._query(domain, 'TXT')
        result['txt_records'] = txt_records

        # CNAME records
        result['cname_records'] = self._query(domain, 'CNAME')

        # SOA (authoritative info)
        result['soa_record'] = self._query(domain, 'SOA', extract='first')

        # Resolution time
        result['resolution_time_ms'] = round((time.time() - start_time) * 1000, 2)

        # ============================================
        # DERIVED FLAGS
        # ============================================
        txt_lower = ' '.join(str(r).lower() for r in txt_records)

        result['has_a'] = 1 if result['a_records'] else 0
        result['has_aaaa'] = 1 if result['aaaa_records'] else 0
        result['has_mx'] = 1 if result['mx_records'] else 0
        result['has_ns'] = 1 if result['nameservers'] else 0
        result['has_txt'] = 1 if result['txt_records'] else 0
        result['has_cname'] = 1 if result['cname_records'] else 0

        result['has_spf'] = 1 if 'v=spf1' in txt_lower else 0
        result['has_dmarc'] = 1 if 'v=dmarc1' in txt_lower else 0
        result['has_dkim'] = 1 if 'v=dkim1' in txt_lower else 0

        result['a_record_count'] = len(result['a_records'])
        result['aaaa_record_count'] = len(result['aaaa_records'])
        result['mx_count'] = len(result['mx_records'])
        result['ns_count'] = len(result['nameservers'])
        result['txt_count'] = len(txt_records)

        result['mail_provider'] = self._detect_mail_provider(result['mx_records'])
        result['dns_provider'] = self._detect_dns_provider(result['nameservers'])

        result['lookup_success'] = 1 if (
            result['a_records'] or result['aaaa_records'] or
            result['mx_records'] or result['nameservers']
        ) else 0

        # Cache
        self._cache[domain] = {
            'data': result,
            'ts': time.time()
        }

        return result

    # ============================================
    # INTERNALS
    # ============================================

    def _query(self, domain, record_type, extract=None):
        """
        Query a specific record type. Never raises.
        extract: 'exchange' | 'first' | None
        """
        try:
            answers = self.resolver.resolve(domain, record_type)
            results = []
            for rdata in answers:
                if extract == 'exchange':
                    # MX records: extract mail server hostname
                    results.append(str(rdata.exchange).rstrip('.'))
                elif extract == 'first':
                    results.append(str(rdata))
                    break
                else:
                    results.append(str(rdata).strip('"'))
            return results
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.exception.Timeout,
                dns.resolver.LifetimeTimeout):
            return []
        except Exception as e:
            logger.debug(f"DNS query {record_type} failed for {domain}: {e}")
            return []

    @staticmethod
    def _empty_result():
        return {
            'domain': None,
            'a_records': [],
            'aaaa_records': [],
            'mx_records': [],
            'nameservers': [],
            'txt_records': [],
            'cname_records': [],
            'soa_record': [],
            'resolution_time_ms': 0,
            'has_a': 0, 'has_aaaa': 0, 'has_mx': 0, 'has_ns': 0,
            'has_txt': 0, 'has_cname': 0,
            'has_spf': 0, 'has_dmarc': 0, 'has_dkim': 0,
            'a_record_count': 0, 'aaaa_record_count': 0,
            'mx_count': 0, 'ns_count': 0, 'txt_count': 0,
            'mail_provider': None,
            'dns_provider': None,
            'lookup_success': 0,
            'cached': False
        }

    @staticmethod
    def _detect_mail_provider(mx_records):
        """Detect common mail providers from MX hostnames"""
        if not mx_records:
            return None
        joined = ' '.join(mx_records).lower()
        if 'google' in joined or 'googlemail' in joined:
            return 'Google'
        if 'outlook' in joined or 'microsoft' in joined:
            return 'Microsoft'
        if 'zoho' in joined:
            return 'Zoho'
        if 'yandex' in joined:
            return 'Yandex'
        if 'protonmail' in joined or 'proton' in joined:
            return 'ProtonMail'
        if 'cloudflare' in joined:
            return 'Cloudflare'
        return 'Other'

    @staticmethod
    def _detect_dns_provider(nameservers):
        """Detect common DNS providers from NS records"""
        if not nameservers:
            return None
        joined = ' '.join(nameservers).lower()
        if 'cloudflare' in joined:
            return 'Cloudflare'
        if 'awsdns' in joined:
            return 'AWS Route53'
        if 'googledomains' in joined or 'google.com' in joined:
            return 'Google Cloud DNS'
        if 'azure' in joined:
            return 'Azure DNS'
        if 'godaddy' in joined or 'domaincontrol' in joined:
            return 'GoDaddy'
        if 'namecheap' in joined:
            return 'Namecheap'
        if 'digitalocean' in joined:
            return 'DigitalOcean'
        return 'Other'

    @staticmethod
    def clear_cache():
        DNSIntelligence._cache.clear()