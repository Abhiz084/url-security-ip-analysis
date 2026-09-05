"""
URL Structural Feature Extractor
Extracts lexical and structural features from URLs
"""

import re
import math
from collections import Counter
from urllib.parse import urlparse, parse_qs
from loguru import logger
from database.crud_operations import CRUDOperations

class URLFeatureExtractor:
    """Extract features from URL structure"""
    
    def __init__(self):
        self.crud = CRUDOperations()
        
        # Suspicious patterns
        self.suspicious_tlds = {'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work', 'date'}
        self.suspicious_keywords = [
            'login', 'signin', 'verify', 'secure', 'account', 'update', 'confirm',
            'banking', 'password', 'credential', 'paypal', 'billing', 'support'
        ]
        self.suspicious_chars = ['@', '-', '_', '=', '&', '%', '#']
        
    def extract_url_length(self, url):
        """Feature 1: URL length"""
        return len(url)
    
    def extract_domain_length(self, domain):
        """Feature 2: Domain length"""
        return len(domain)
    
    def extract_path_length(self, path):
        """Feature 3: Path length"""
        return len(path) if path else 0
    
    def extract_subdomain_count(self, domain):
        """Feature 4: Number of subdomains"""
        parts = domain.split('.')
        return max(0, len(parts) - 2)  # Subtract main domain and TLD
    
    def extract_dot_count(self, url):
        """Feature 5: Number of dots in URL"""
        return url.count('.')
    
    def extract_hyphen_count(self, url):
        """Feature 6: Number of hyphens"""
        return url.count('-')
    
    def extract_underscore_count(self, url):
        """Feature 7: Number of underscores"""
        return url.count('_')
    
    def extract_slash_count(self, url):
        """Feature 8: Number of slashes"""
        return url.count('/')
    
    def extract_question_mark_count(self, url):
        """Feature 9: Number of question marks"""
        return url.count('?')
    
    def extract_equal_count(self, url):
        """Feature 10: Number of equals signs"""
        return url.count('=')
    
    def extract_at_count(self, url):
        """Feature 11: Number of @ symbols"""
        return url.count('@')
    
    def extract_digit_count(self, url):
        """Feature 12: Number of digits"""
        return sum(c.isdigit() for c in url)
    
    def extract_letter_count(self, url):
        """Feature 13: Number of letters"""
        return sum(c.isalpha() for c in url)
    
    def extract_digit_ratio(self, url):
        """Feature 14: Ratio of digits to total characters"""
        total = len(url)
        if total == 0:
            return 0
        return self.extract_digit_count(url) / total
    
    def extract_special_char_count(self, url):
        """Feature 15: Count of special characters"""
        special_chars = set('!@#$%^&*()_+-=[]{}|;:,.<>?/~`')
        return sum(1 for c in url if c in special_chars)
    
    def extract_entropy(self, text):
        """Feature 16: Shannon entropy of URL"""
        if not text:
            return 0
        
        char_counts = Counter(text)
        length = len(text)
        
        entropy = 0
        for count in char_counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def extract_suspicious_tld(self, tld):
        """Feature 17: Suspicious TLD flag"""
        return 1 if tld.lower() in self.suspicious_tlds else 0
    
    def extract_suspicious_keywords_count(self, url):
        """Feature 18: Count of suspicious keywords"""
        url_lower = url.lower()
        return sum(1 for keyword in self.suspicious_keywords if keyword in url_lower)
    
    def extract_has_ip_address(self, domain):
        """Feature 19: Domain contains IP address"""
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        return 1 if re.match(ip_pattern, domain) else 0
    
    def extract_has_hex_chars(self, url):
        """Feature 20: Contains hexadecimal characters"""
        return 1 if '%' in url and any(c in '0123456789abcdefABCDEF' for c in url) else 0
    
    def extract_url_depth(self, path):
        """Feature 21: URL directory depth"""
        if not path:
            return 0
        return len([p for p in path.split('/') if p])
    
    def extract_query_params_count(self, url):
        """Feature 22: Number of query parameters"""
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query)
            return len(params)
        return 0
    
    def extract_is_https(self, protocol):
        """Feature 23: Uses HTTPS"""
        return 1 if protocol == 'https' else 0
    
    def extract_domain_token_count(self, domain):
        """Feature 24: Number of tokens in domain"""
        tokens = re.split(r'[.\-_]', domain)
        return len([t for t in tokens if t])
    
    def extract_longest_token_length(self, domain):
        """Feature 25: Length of longest token in domain"""
        tokens = re.split(r'[.\-_]', domain)
        if not tokens:
            return 0
        return max(len(t) for t in tokens if t)
    
    def extract_has_suspicious_file_extension(self, url):
        """Feature 26: Has suspicious file extension"""
        suspicious_extensions = {'.exe', '.bat', '.cmd', '.msi', '.scr', '.js', '.vbs'}
        url_lower = url.lower()
        return 1 if any(ext in url_lower for ext in suspicious_extensions) else 0
    
    def extract_all_features(self, url, domain=None, path=None, protocol=None, tld=None):
        """Extract all URL features"""
        if domain is None or path is None:
            parsed = urlparse(url)
            domain = domain or parsed.netloc
            path = path or parsed.path
            protocol = protocol or parsed.scheme
            tld = tld or (domain.split('.')[-1] if '.' in domain else '')
        
        features = {
            # Length features
            'url_length': self.extract_url_length(url),
            'domain_length': self.extract_domain_length(domain),
            'path_length': self.extract_path_length(path),
            
            # Count features
            'subdomain_count': self.extract_subdomain_count(domain),
            'dot_count': self.extract_dot_count(url),
            'hyphen_count': self.extract_hyphen_count(url),
            'underscore_count': self.extract_underscore_count(url),
            'slash_count': self.extract_slash_count(url),
            'question_mark_count': self.extract_question_mark_count(url),
            'equal_count': self.extract_equal_count(url),
            'at_count': self.extract_at_count(url),
            
            # Character composition
            'digit_count': self.extract_digit_count(url),
            'letter_count': self.extract_letter_count(url),
            'digit_ratio': self.extract_digit_ratio(url),
            'special_char_count': self.extract_special_char_count(url),
            
            # Advanced features
            'entropy': round(self.extract_entropy(url), 4),
            'suspicious_tld': self.extract_suspicious_tld(tld),
            'suspicious_keywords_count': self.extract_suspicious_keywords_count(url),
            'has_ip_address': self.extract_has_ip_address(domain),
            'has_hex_chars': self.extract_has_hex_chars(url),
            'url_depth': self.extract_url_depth(path),
            'query_params_count': self.extract_query_params_count(url),
            'is_https': self.extract_is_https(protocol),
            'domain_token_count': self.extract_domain_token_count(domain),
            'longest_token_length': self.extract_longest_token_length(domain),
            'has_suspicious_file_extension': self.extract_has_suspicious_file_extension(url),
        }
        
        return features
    
    def process_urls_batch(self, limit=100):
        """Process a batch of URLs from database"""
        urls = self.crud.get_all_urls(limit=limit)
        
        processed = 0
        for url_record in urls:
            try:
                features = self.extract_all_features(
                    url=url_record['full_url'],
                    domain=url_record['domain'],
                    path=url_record.get('path', ''),
                    protocol=url_record.get('protocol', ''),
                    tld=url_record.get('tld', '')
                )
                
                # Save to feature cache
                import json
                self.crud.insert_feature_cache(
                    url_id=url_record['url_id'],
                    feature_vector=json.dumps(features),
                    feature_count=len(features)
                )
                
                processed += 1
                
            except Exception as e:
                logger.error(f"Error processing URL {url_record.get('url_id')}: {e}")
        
        logger.info(f"Processed {processed} URLs for features")
        return processed