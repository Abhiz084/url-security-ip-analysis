"""
Domain Feature Extractor — WHOIS + Domain-level features

Extracts:
- domain_age_days
- days_until_expiry
- is_new_domain
- is_expiring_soon
- is_privacy_protected
- is_free_tld
- new_domain_risk
- whois_success
"""

from loguru import logger


class DomainFeatureExtractor:
    """Extract domain-level features via WHOIS"""

    def __init__(self):
        self._intel = None

    def _get_intel(self):
        if self._intel is None:
            try:
                from src.intelligence.whois_intelligence import WHOISIntelligence
                self._intel = WHOISIntelligence()
            except Exception as e:
                logger.debug(f"WHOISIntelligence unavailable: {e}")
                self._intel = False
        return self._intel if self._intel is not False else None

    def extract_all_features(self, domain):
        """Extract WHOIS-based domain features"""
        defaults = {
            'domain_age_days': 0,
            'days_until_expiry': 0,
            'is_new_domain': 0,
            'is_expiring_soon': 0,
            'is_privacy_protected': 0,
            'is_free_tld': 0,
            'new_domain_risk': 0.0,
            'whois_nameserver_count': 0,
            'whois_success': 0,
        }

        intel = self._get_intel()
        if intel is None:
            return defaults

        try:
            r = intel.lookup(domain)
        except Exception as e:
            logger.debug(f"WHOIS lookup failed for {domain}: {e}")
            return defaults

        return {
            'domain_age_days': min(r.get('domain_age_days', 0), 20000),  # cap at ~55 years
            'days_until_expiry': r.get('days_until_expiry', 0),
            'is_new_domain': r.get('is_new_domain', 0),
            'is_expiring_soon': r.get('is_expiring_soon', 0),
            'is_privacy_protected': r.get('is_privacy_protected', 0),
            'is_free_tld': r.get('is_free_tld', 0),
            'new_domain_risk': float(r.get('new_domain_risk', 0.0)),
            'whois_nameserver_count': r.get('nameserver_count', 0),
            'whois_success': r.get('whois_success', 0),
        }