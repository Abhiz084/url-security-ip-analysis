"""
Complete Feature Engineering Pipeline
Orchestrates all feature extractors
"""

import json
import time
from loguru import logger
from database.crud_operations import CRUDOperations
from src.feature_engineering.url_features import URLFeatureExtractor
from src.feature_engineering.ip_features import IPFeatureExtractor
from src.feature_engineering.dns_features import DNSFeatureExtractor
from src.feature_engineering.geo_features import GeoFeatureExtractor
from src.feature_engineering.traffic_features import TrafficFeatureExtractor

class FeaturePipeline:
    """Complete feature extraction pipeline"""
    
    def __init__(self):
        self.crud = CRUDOperations()
        self.url_extractor = URLFeatureExtractor()
        self.ip_extractor = IPFeatureExtractor()
        self.dns_extractor = DNSFeatureExtractor()
        self.geo_extractor = GeoFeatureExtractor()
        self.traffic_extractor = TrafficFeatureExtractor()
        
        self.feature_stats = {
            'total_processed': 0,
            'url_features': 0,
            'ip_features': 0,
            'dns_features': 0,
            'geo_features': 0,
            'traffic_features': 0,
        }
    
    def extract_features_for_url(self, url_record):
        """Extract all features for a single URL"""
        url = url_record['full_url']
        domain = url_record['domain']
        url_id = url_record['url_id']
        
        all_features = {}
        
        # 1. URL Structural Features (26 features)
        url_features = self.url_extractor.extract_all_features(
            url=url,
            domain=domain,
            path=url_record.get('path', ''),
            protocol=url_record.get('protocol', ''),
            tld=url_record.get('tld', '')
        )
        all_features.update(url_features)
        self.feature_stats['url_features'] += len(url_features)
        
        # 2. IP Features - if we have associated IP data
        ip_features = self._extract_ip_features_from_domain(domain)
        if ip_features:
            all_features.update(ip_features)
            self.feature_stats['ip_features'] += len(ip_features)
        
        # 3. DNS Features (12 features)
        try:
            dns_features = self.dns_extractor.extract_all_features(domain)
            all_features.update(dns_features)
            self.feature_stats['dns_features'] += len(dns_features)
        except Exception as e:
            logger.debug(f"DNS extraction failed for {domain}: {e}")
        
        # 4. Save combined features to cache
        self.crud.insert_feature_cache(
            url_id=url_id,
            feature_vector=json.dumps(all_features),
            feature_count=len(all_features)
        )
        
        self.feature_stats['total_processed'] += 1
        
        return all_features
    
    def _extract_ip_features_from_domain(self, domain):
        """Try to resolve domain to IP and extract features"""
        import socket
        
        try:
            ip_address = socket.gethostbyname(domain)
            
            # IP structural features
            ip_features = self.ip_extractor.extract_all_features(ip_address)
            
            # Geolocation features
            geo_features = self.geo_extractor.extract_all_features(ip_address)
            ip_features.update(geo_features)
            
            # Traffic features
            traffic_features = self.traffic_extractor.extract_all_features(ip_address)
            ip_features.update(traffic_features)
            
            return ip_features
            
        except Exception as e:
            logger.debug(f"IP resolution failed for {domain}: {e}")
            return None
    
    def run_pipeline(self, limit=50):
        """Run complete feature extraction pipeline"""
        logger.info("=" * 50)
        logger.info("Starting Feature Extraction Pipeline")
        logger.info("=" * 50)
        
        start_time = time.time()
        
        # Get URLs from database
        urls = self.crud.get_all_urls(limit=limit)
        logger.info(f"Processing {len(urls)} URLs for feature extraction...")
        
        for i, url_record in enumerate(urls):
            try:
                features = self.extract_features_for_url(url_record)
                
                if (i + 1) % 10 == 0:
                    logger.info(f"Progress: {i + 1}/{len(urls)} URLs processed")
                
            except Exception as e:
                logger.error(f"Failed to extract features for URL {url_record.get('url_id')}: {e}")
        
        elapsed = time.time() - start_time
        
        logger.info(f"\nFeature Extraction Complete:")
        logger.info(f"  Total URLs processed: {self.feature_stats['total_processed']}")
        logger.info(f"  URL features extracted: {self.feature_stats['url_features']}")
        logger.info(f"  IP features extracted: {self.feature_stats['ip_features']}")
        logger.info(f"  DNS features extracted: {self.feature_stats['dns_features']}")
        logger.info(f"  Geo features extracted: {self.feature_stats['geo_features']}")
        logger.info(f"  Traffic features extracted: {self.feature_stats['traffic_features']}")
        logger.info(f"  Time elapsed: {elapsed:.2f}s")
        
        return self.feature_stats