"""
DNS Feature Extractor — Enhanced via DNSIntelligence

Returns features ready for ML:
- Counts, flags, provider info
- Uses cached DNS intelligence to avoid redundant lookups
"""

from loguru import logger


class DNSFeatureExtractor:
    """Extract DNS-based features for ML"""

    def __init__(self):
        self._intel = None

    # Lazy loader
    def _get_intel(self):
        if self._intel is None:
            try:
                from src.intelligence.dns_intelligence import DNSIntelligence
                self._intel = DNSIntelligence()
            except Exception as e:
                logger.debug(f"DNSIntelligence unavailable: {e}")
                self._intel = False
        return self._intel if self._intel is not False else None

    # ============================================
    # MAIN
    # ============================================

    def extract_all_features(self, domain):
        """Extract all DNS-related features"""
        defaults = {
            'dns_a_count': 0,
            'dns_aaaa_count': 0,
            'dns_mx_count': 0,
            'dns_ns_count': 0,
            'dns_txt_count': 0,
            'dns_has_a': 0,
            'dns_has_aaaa': 0,
            'dns_has_mx': 0,
            'dns_has_ns': 0,
            'dns_has_txt': 0,
            'dns_has_cname': 0,
            'dns_has_spf': 0,
            'dns_has_dmarc': 0,
            'dns_has_dkim': 0,
            'dns_resolution_time_ms': 0,
            'dns_lookup_success': 0,
            'dns_mail_provider_google': 0,
            'dns_mail_provider_microsoft': 0,
            'dns_mail_provider_other': 0,
            'dns_provider_cloudflare': 0,
            'dns_provider_aws': 0,
        }

        intel = self._get_intel()
        if intel is None:
            return defaults

        try:
            r = intel.lookup(domain)
        except Exception as e:
            logger.debug(f"DNS lookup failed for {domain}: {e}")
            return defaults

        # Mail provider one-hot
        mail = (r.get('mail_provider') or '').lower()
        dns_provider = (r.get('dns_provider') or '').lower()

        return {
            'dns_a_count': r.get('a_record_count', 0),
            'dns_aaaa_count': r.get('aaaa_record_count', 0),
            'dns_mx_count': r.get('mx_count', 0),
            'dns_ns_count': r.get('ns_count', 0),
            'dns_txt_count': r.get('txt_count', 0),
            'dns_has_a': r.get('has_a', 0),
            'dns_has_aaaa': r.get('has_aaaa', 0),
            'dns_has_mx': r.get('has_mx', 0),
            'dns_has_ns': r.get('has_ns', 0),
            'dns_has_txt': r.get('has_txt', 0),
            'dns_has_cname': r.get('has_cname', 0),
            'dns_has_spf': r.get('has_spf', 0),
            'dns_has_dmarc': r.get('has_dmarc', 0),
            'dns_has_dkim': r.get('has_dkim', 0),
            'dns_resolution_time_ms': r.get('resolution_time_ms', 0),
            'dns_lookup_success': r.get('lookup_success', 0),
            'dns_mail_provider_google': 1 if 'google' in mail else 0,
            'dns_mail_provider_microsoft': 1 if 'microsoft' in mail else 0,
            'dns_mail_provider_other': 1 if mail and 'google' not in mail and 'microsoft' not in mail else 0,
            'dns_provider_cloudflare': 1 if 'cloudflare' in dns_provider else 0,
            'dns_provider_aws': 1 if 'aws' in dns_provider or 'route53' in dns_provider else 0,
        }