"""
IP-Based Feature Extractor - Enhanced with IP Intelligence

Extracts:
- Original structural features (private, octets, etc.)
- NEW: abuse_score, total_reports, asn_risk, country_risk,
       is_hosting, is_vpn, is_tor, is_proxy, hosting_provider
"""

import ipaddress
import re
from loguru import logger
from database.crud_operations import CRUDOperations


class IPFeatureExtractor:
    """Extract features from IP addresses"""

    def __init__(self):
        self.crud = CRUDOperations()

        # Lazy-load IPIntelligence (avoid importing at module level)
        self._intel = None

        # Private ranges
        self.private_ranges = [
            ipaddress.ip_network('10.0.0.0/8'),
            ipaddress.ip_network('172.16.0.0/12'),
            ipaddress.ip_network('192.168.0.0/16'),
            ipaddress.ip_network('127.0.0.0/8'),
        ]

    # ============================================
    # LAZY INTELLIGENCE LOADER
    # ============================================

    def _get_intel(self):
        """Lazy-load IPIntelligence singleton"""
        if self._intel is None:
            try:
                from src.intelligence.ip_intelligence import IPIntelligence
                self._intel = IPIntelligence()
            except Exception as e:
                logger.debug(f"IPIntelligence unavailable: {e}")
                self._intel = False  # Mark as unavailable
        return self._intel if self._intel is not False else None

    # ============================================
    # STRUCTURAL FEATURES (existing)
    # ============================================

    def extract_is_private(self, ip_address):
        try:
            ip = ipaddress.ip_address(ip_address)
            return 1 if any(ip in network for network in self.private_ranges) else 0
        except:
            return 0

    def extract_is_ipv6(self, ip_address):
        return 1 if ':' in ip_address else 0

    def extract_ip_octets(self, ip_address):
        if ':' in ip_address:
            return {'octet_1': 0, 'octet_2': 0, 'octet_3': 0, 'octet_4': 0}
        try:
            parts = ip_address.split('.')
            return {
                'octet_1': int(parts[0]) if len(parts) > 0 else 0,
                'octet_2': int(parts[1]) if len(parts) > 1 else 0,
                'octet_3': int(parts[2]) if len(parts) > 2 else 0,
                'octet_4': int(parts[3]) if len(parts) > 3 else 0,
            }
        except:
            return {'octet_1': 0, 'octet_2': 0, 'octet_3': 0, 'octet_4': 0}

    def extract_ip_numeric(self, ip_address):
        try:
            return int(ipaddress.ip_address(ip_address))
        except:
            return 0

    def extract_threat_score(self, ip_address):
        try:
            info = self.crud.get_ip_info(ip_address)
            return float(info.get('threat_score', 0)) if info else 0.0
        except:
            return 0.0

    def extract_total_requests(self, ip_address):
        try:
            info = self.crud.get_ip_info(ip_address)
            return int(info.get('total_requests', 0)) if info else 0
        except:
            return 0

    def extract_active_threats_count(self, ip_address):
        try:
            threats = self.crud.get_threats_for_ip(ip_address)
            return len(threats) if threats else 0
        except:
            return 0

    def extract_is_known_malicious(self, ip_address):
        try:
            threats = self.crud.get_threats_for_ip(ip_address)
            return 1 if threats else 0
        except:
            return 0

    def extract_days_since_first_seen(self, ip_address):
        try:
            info = self.crud.get_ip_info(ip_address)
            if info and info.get('first_seen'):
                from datetime import datetime
                first_seen = info['first_seen']
                if isinstance(first_seen, str):
                    first_seen = datetime.strptime(first_seen, '%Y-%m-%d %H:%M:%S')
                return (datetime.now() - first_seen).days
        except:
            pass
        return 0

    # ============================================
    # NEW: INTELLIGENCE-DRIVEN FEATURES
    # ============================================

    def extract_intelligence_features(self, ip_address, use_cache=True):
        """
        Extract reputation + classification features via IPIntelligence.

        Returns a dict of features. If intelligence is unavailable,
        returns zeros (safe defaults) so ML still runs.
        """
        defaults = {
            'abuse_score': 0,
            'total_reports': 0,
            'asn_risk': 0.0,
            'country_risk': 0.0,
            'combined_risk': 0.0,
            'is_hosting': 0,
            'is_vpn': 0,
            'is_tor': 0,
            'is_proxy': 0,
            'hosting_provider': 0,   # 1 if ASN is a known hosting provider
            'intel_available': 0,    # 1 if we successfully got intelligence
        }

        # Private IPs → skip
        if self.extract_is_private(ip_address):
            return defaults

        # Get intelligence
        intel = self._get_intel()
        if intel is None:
            return defaults

        try:
            result = intel.check(ip_address)

            return {
                'abuse_score': int(result.get('abuse_score', 0)),
                'total_reports': int(result.get('total_reports', 0)),
                'asn_risk': float(result.get('asn_risk', 0.0)),
                'country_risk': float(result.get('country_risk', 0.0)),
                'combined_risk': float(result.get('combined_risk', 0.0)),
                'is_hosting': 1 if result.get('is_hosting') else 0,
                'is_vpn': 1 if result.get('is_vpn') else 0,
                'is_tor': 1 if result.get('is_tor') else 0,
                'is_proxy': 1 if result.get('is_proxy') else 0,
                'hosting_provider': 1 if result.get('asn') and result['asn'].upper() in intel.HOSTING_ASNS else 0,
                'intel_available': 1,
            }
        except Exception as e:
            logger.debug(f"Intelligence features failed for {ip_address}: {e}")
            return defaults

    # ============================================
    # MAIN ENTRY POINT
    # ============================================

    def extract_all_features(self, ip_address):
        """Extract ALL IP features (structural + intelligence)"""
        features = {
            # Structural
            'is_private': self.extract_is_private(ip_address),
            'is_ipv6': self.extract_is_ipv6(ip_address),
            'ip_numeric': self.extract_ip_numeric(ip_address),
            'threat_score': self.extract_threat_score(ip_address),
            'total_requests': self.extract_total_requests(ip_address),
            'active_threats_count': self.extract_active_threats_count(ip_address),
            'is_known_malicious': self.extract_is_known_malicious(ip_address),
            'days_since_first_seen': self.extract_days_since_first_seen(ip_address),
        }

        # Octets
        features.update(self.extract_ip_octets(ip_address))

        # NEW: Intelligence features
        features.update(self.extract_intelligence_features(ip_address))

        return features