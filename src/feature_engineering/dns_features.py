"""
DNS Feature Extractor
Extracts features from DNS records
"""

import dns.resolver
import time
from datetime import datetime
from loguru import logger
from database.crud_operations import CRUDOperations

class DNSFeatureExtractor:
    """Extract DNS-related features"""
    
    def __init__(self):
        self.crud = CRUDOperations()
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 5
    
    def extract_dns_record_count(self, domain, record_type='A'):
        """Feature 1: Number of DNS records of a type"""
        try:
            answers = self.resolver.resolve(domain, record_type)
            return len(answers)
        except:
            return 0
    
    def extract_has_mx_record(self, domain):
        """Feature 2: Has MX record"""
        return 1 if self.extract_dns_record_count(domain, 'MX') > 0 else 0
    
    def extract_has_txt_record(self, domain):
        """Feature 3: Has TXT record (SPF/DKIM)"""
        return 1 if self.extract_dns_record_count(domain, 'TXT') > 0 else 0
    
    def extract_has_ns_record(self, domain):
        """Feature 4: Has NS record"""
        return 1 if self.extract_dns_record_count(domain, 'NS') > 0 else 0
    
    def extract_nameserver_count(self, domain):
        """Feature 5: Number of nameservers"""
        return self.extract_dns_record_count(domain, 'NS')
    
    def extract_mx_server_count(self, domain):
        """Feature 6: Number of mail servers"""
        return self.extract_dns_record_count(domain, 'MX')
    
    def extract_ttl_min(self, domain):
        """Feature 7: Minimum TTL"""
        try:
            answers = self.resolver.resolve(domain, 'A')
            return min(rdata.ttl for rdata in answers.response.answer) if answers.response.answer else 0
        except:
            return 0
    
    def extract_ttl_max(self, domain):
        """Feature 8: Maximum TTL"""
        try:
            answers = self.resolver.resolve(domain, 'A')
            return max(rdata.ttl for rdata in answers.response.answer) if answers.response.answer else 0
        except:
            return 0
    
    def extract_ttl_avg(self, domain):
        """Feature 9: Average TTL"""
        try:
            answers = self.resolver.resolve(domain, 'A')
            ttls = [rdata.ttl for rdata in answers.response.answer]
            return sum(ttls) / len(ttls) if ttls else 0
        except:
            return 0
    
    def extract_dns_resolution_time(self, domain):
        """Feature 10: DNS resolution time in ms"""
        try:
            start = time.time()
            self.resolver.resolve(domain, 'A')
            return (time.time() - start) * 1000
        except:
            return 5000  # Timeout value
    
    def extract_subdomain_count_dns(self, domain):
        """Feature 11: Subdomain count from DNS"""
        try:
            answers = self.resolver.resolve(domain, 'A')
            subdomains = set()
            for rdata in answers:
                name = str(rdata.name).rstrip('.')
                if name != domain:
                    subdomains.add(name)
            return len(subdomains)
        except:
            return 0
    
    def extract_has_cname(self, domain):
        """Feature 12: Has CNAME record"""
        return self.extract_dns_record_count(domain, 'CNAME')
    
    def extract_all_features(self, domain):
        """Extract all DNS features"""
        features = {
            'a_record_count': self.extract_dns_record_count(domain, 'A'),
            'has_mx_record': self.extract_has_mx_record(domain),
            'has_txt_record': self.extract_has_txt_record(domain),
            'has_ns_record': self.extract_has_ns_record(domain),
            'nameserver_count': self.extract_nameserver_count(domain),
            'mx_server_count': self.extract_mx_server_count(domain),
            'ttl_min': self.extract_ttl_min(domain),
            'ttl_max': self.extract_ttl_max(domain),
            'ttl_avg': round(self.extract_ttl_avg(domain), 2),
            'dns_resolution_time': round(self.extract_dns_resolution_time(domain), 2),
            'subdomain_count_dns': self.extract_subdomain_count_dns(domain),
            'has_cname': self.extract_has_cname(domain),
        }
        
        # Save DNS records to database
        self._save_dns_records(domain)
        
        return features
    
    def _save_dns_records(self, domain):
        """Save DNS records to database"""
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
        
        for record_type in record_types:
            try:
                answers = self.resolver.resolve(domain, record_type)
                for rdata in answers:
                    ttl = rdata.ttl if hasattr(rdata, 'ttl') else 0
                    self.crud.insert_dns_record(
                        domain=domain,
                        record_type=record_type,
                        record_value=str(rdata),
                        ttl=ttl
                    )
            except:
                pass