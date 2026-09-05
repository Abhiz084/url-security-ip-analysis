"""
IP-Based Feature Extractor
Extracts features from IP addresses
"""

import ipaddress
import re
from loguru import logger
from database.crud_operations import CRUDOperations

class IPFeatureExtractor:
    """Extract features from IP addresses"""
    
    def __init__(self):
        self.crud = CRUDOperations()
        
        # Private IP ranges
        self.private_ranges = [
            ipaddress.ip_network('10.0.0.0/8'),
            ipaddress.ip_network('172.16.0.0/12'),
            ipaddress.ip_network('192.168.0.0/16'),
            ipaddress.ip_network('127.0.0.0/8'),
        ]
    
    def extract_is_private(self, ip_address):
        """Feature 1: Is private IP"""
        try:
            ip = ipaddress.ip_address(ip_address)
            return 1 if any(ip in network for network in self.private_ranges) else 0
        except:
            return 0
    
    def extract_is_ipv6(self, ip_address):
        """Feature 2: Is IPv6"""
        return 1 if ':' in ip_address else 0
    
    def extract_ip_octets(self, ip_address):
        """Feature 3-6: Individual octets of IPv4"""
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
        """Feature 7: IP as numeric value"""
        try:
            return int(ipaddress.ip_address(ip_address))
        except:
            return 0
    
    def extract_threat_score(self, ip_address):
        """Feature 8: Threat score from database"""
        try:
            ip_info = self.crud.get_ip_info(ip_address)
            return float(ip_info.get('threat_score', 0)) if ip_info else 0.0
        except:
            return 0.0
    
    def extract_total_requests(self, ip_address):
        """Feature 9: Total requests from this IP"""
        try:
            ip_info = self.crud.get_ip_info(ip_address)
            return int(ip_info.get('total_requests', 0)) if ip_info else 0
        except:
            return 0
    
    def extract_active_threats_count(self, ip_address):
        """Feature 10: Number of active threats for IP"""
        try:
            threats = self.crud.get_threats_for_ip(ip_address)
            return len(threats) if threats else 0
        except:
            return 0
    
    def extract_is_known_malicious(self, ip_address):
        """Feature 11: Known malicious from threat intel"""
        threats = self.crud.get_threats_for_ip(ip_address)
        return 1 if threats else 0
    
    def extract_days_since_first_seen(self, ip_address):
        """Feature 12: Days since first seen"""
        try:
            ip_info = self.crud.get_ip_info(ip_address)
            if ip_info and ip_info.get('first_seen'):
                from datetime import datetime
                first_seen = ip_info['first_seen']
                if isinstance(first_seen, str):
                    first_seen = datetime.strptime(first_seen, '%Y-%m-%d %H:%M:%S')
                delta = datetime.now() - first_seen
                return delta.days
        except:
            pass
        return 0
    
    def extract_all_features(self, ip_address):
        """Extract all IP features"""
        features = {
            'is_private': self.extract_is_private(ip_address),
            'is_ipv6': self.extract_is_ipv6(ip_address),
            'ip_numeric': self.extract_ip_numeric(ip_address),
            'threat_score': self.extract_threat_score(ip_address),
            'total_requests': self.extract_total_requests(ip_address),
            'active_threats_count': self.extract_active_threats_count(ip_address),
            'is_known_malicious': self.extract_is_known_malicious(ip_address),
            'days_since_first_seen': self.extract_days_since_first_seen(ip_address),
        }
        
        # Add octet features
        octet_features = self.extract_ip_octets(ip_address)
        features.update(octet_features)
        
        return features