"""
Complete Feature Engineering Pipeline

Integrates:
- URL structural features
- IP features + IP intelligence (AbuseIPDB, ASN, Tor/VPN/hosting)
- DNS intelligence (A, AAAA, MX, NS, TXT, SPF, DMARC)
- WHOIS / domain intelligence (domain age, registrar, expiry)
- Geolocation features
- Network traffic features

Performance:
- Parallel processing with ThreadPoolExecutor (default 10 workers)
- DNS/WHOIS results are cached for 6/24 hours respectively
- Graceful error handling — one failure never blocks the pipeline
"""

import json
import time
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from loguru import logger

from database.crud_operations import CRUDOperations
from src.feature_engineering.url_features import URLFeatureExtractor
from src.feature_engineering.ip_features import IPFeatureExtractor
from src.feature_engineering.dns_features import DNSFeatureExtractor
from src.feature_engineering.domain_features import DomainFeatureExtractor
from src.feature_engineering.geo_features import GeoFeatureExtractor
from src.feature_engineering.traffic_features import TrafficFeatureExtractor


class FeaturePipeline:
    """
    Complete feature extraction pipeline.

    Usage:
        pipeline = FeaturePipeline(max_workers=10)
        pipeline.run_pipeline(limit=500)
    """

    def __init__(self, max_workers=10):
        self.crud = CRUDOperations()

        # Extractors
        self.url_extractor = URLFeatureExtractor()
        self.ip_extractor = IPFeatureExtractor()
        self.dns_extractor = DNSFeatureExtractor()
        self.domain_extractor = DomainFeatureExtractor()
        self.geo_extractor = GeoFeatureExtractor()
        self.traffic_extractor = TrafficFeatureExtractor()

        # Parallel processing
        self.max_workers = max_workers

        # Stats
        self.feature_stats = {
            'total_processed': 0,
            'total_failed': 0,
            'url_features': 0,
            'ip_features': 0,
            'dns_features': 0,
            'domain_features': 0,
            'geo_features': 0,
            'traffic_features': 0,
            'ip_lookup_failures': 0,
            'dns_lookup_failures': 0,
            'whois_lookup_failures': 0,
        }

        # Thread-safe lock for stats updates
        import threading
        self._stats_lock = threading.Lock()

    # ============================================
    # MAIN ENTRY POINT
    # ============================================

    def run_pipeline(self, limit=500, batch_save_size=50):
        """
        Run complete feature extraction pipeline with parallel processing.

        Args:
            limit: Max number of URLs to process
            batch_save_size: Number of features to save per DB batch (not used yet, reserved)
        """
        logger.info("=" * 60)
        logger.info("Starting Feature Extraction Pipeline (Parallel)")
        logger.info("=" * 60)
        logger.info(f"Workers: {self.max_workers}")

        start_time = time.time()

        # Load URLs from database
        urls = self.crud.get_all_urls(limit=limit)
        logger.info(f"Processing {len(urls)} URLs with {self.max_workers} workers...")

        if not urls:
            logger.warning("No URLs found in database")
            return self.feature_stats

        # ============================================
        # PARALLEL EXTRACTION
        # ============================================
        completed = 0
        total = len(urls)
        progress_step = max(1, total // 20)  # log every 5%

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_url = {
                executor.submit(self._extract_and_save_safe, url_record): url_record
                for url_record in urls
            }

            # Collect results as they complete
            for future in as_completed(future_to_url):
                completed += 1
                url_record = future_to_url[future]

                try:
                    future.result()  # raises if _extract_and_save_safe raised
                except Exception as e:
                    logger.debug(f"Task failed for URL ID {url_record.get('url_id')}: {e}")
                    with self._stats_lock:
                        self.feature_stats['total_failed'] += 1

                # Progress logging
                if completed % progress_step == 0 or completed == total:
                    logger.info(f"Progress: {completed}/{total} URLs processed")

        # ============================================
        # SUMMARY
        # ============================================
        elapsed = time.time() - start_time
        logger.info("")
        logger.info("=" * 60)
        logger.info("Feature Extraction Complete")
        logger.info("=" * 60)
        logger.info(f"  Total URLs processed:    {self.feature_stats['total_processed']}")
        logger.info(f"  Total URLs failed:       {self.feature_stats['total_failed']}")
        logger.info(f"  URL features extracted:  {self.feature_stats['url_features']}")
        logger.info(f"  IP features extracted:   {self.feature_stats['ip_features']}")
        logger.info(f"  DNS features extracted:  {self.feature_stats['dns_features']}")
        logger.info(f"  Domain features:         {self.feature_stats['domain_features']}")
        logger.info(f"  Geo features extracted:  {self.feature_stats['geo_features']}")
        logger.info(f"  Traffic features:        {self.feature_stats['traffic_features']}")
        logger.info(f"  IP lookup failures:      {self.feature_stats['ip_lookup_failures']}")
        logger.info(f"  DNS lookup failures:     {self.feature_stats['dns_lookup_failures']}")
        logger.info(f"  WHOIS lookup failures:   {self.feature_stats['whois_lookup_failures']}")
        logger.info(f"  Time elapsed:            {elapsed:.2f}s")
        if self.feature_stats['total_processed'] > 0:
            logger.info(f"  Avg time per URL:        {elapsed / self.feature_stats['total_processed']:.2f}s")
        logger.info("=" * 60)

        return self.feature_stats

    # ============================================
    # WORKER (safe wrapper)
    # ============================================

    def _extract_and_save_safe(self, url_record):
        """Wrapper: extract features + save, catching all errors"""
        try:
            features = self.extract_features_for_url(url_record)

            if features and url_record.get('url_id'):
                try:
                    self.crud.insert_feature_cache(
                        url_id=url_record['url_id'],
                        feature_vector=json.dumps(features),
                        feature_count=len(features)
                    )
                except Exception as e:
                    logger.debug(f"Feature cache save failed for URL ID {url_record['url_id']}: {e}")

            with self._stats_lock:
                self.feature_stats['total_processed'] += 1

            return features

        except Exception as e:
            logger.debug(f"Extraction failed for URL ID {url_record.get('url_id')}: {e}")
            raise

    # ============================================
    # EXTRACTION LOGIC
    # ============================================

    def extract_features_for_url(self, url_record):
        """
        Extract all features for a single URL.

        Returns dict of features (no DB writes here — done by caller).
        """
        url = url_record.get('full_url', '')
        domain = url_record.get('domain', '')
        url_id = url_record.get('url_id')

        if not url or not domain:
            return {}

        all_features = {}

        # ============================================
        # 1. URL STRUCTURAL FEATURES
        # ============================================
        try:
            url_features = self.url_extractor.extract_all_features(
                url=url,
                domain=domain,
                path=url_record.get('path', '') or '/',
                protocol=url_record.get('protocol', '') or 'http',
                tld=url_record.get('tld', '') or ''
            )
            all_features.update(url_features)
            with self._stats_lock:
                self.feature_stats['url_features'] += len(url_features)
        except Exception as e:
            logger.debug(f"URL features failed for {domain}: {e}")

        # ============================================
        # 2. DNS INTELLIGENCE
        # ============================================
        try:
            dns_features = self.dns_extractor.extract_all_features(domain)
            all_features.update(dns_features)
            with self._stats_lock:
                self.feature_stats['dns_features'] += len(dns_features)

            # Track failures
            if dns_features.get('dns_lookup_success', 0) == 0:
                with self._stats_lock:
                    self.feature_stats['dns_lookup_failures'] += 1
        except Exception as e:
            logger.debug(f"DNS features failed for {domain}: {e}")

        # ============================================
        # 3. WHOIS / DOMAIN INTELLIGENCE
        # ============================================
        try:
            domain_features = self.domain_extractor.extract_all_features(domain)
            all_features.update(domain_features)
            with self._stats_lock:
                self.feature_stats['domain_features'] += len(domain_features)

            if domain_features.get('whois_success', 0) == 0:
                with self._stats_lock:
                    self.feature_stats['whois_lookup_failures'] += 1
        except Exception as e:
            logger.debug(f"Domain features failed for {domain}: {e}")

        # ============================================
        # 4. IP-BASED FEATURES (resolve domain → IP)
        # ============================================
        ip_address = self._resolve_domain(domain)
        if ip_address:
            # 4a. IP structural + intelligence
            try:
                ip_features = self.ip_extractor.extract_all_features(ip_address)
                all_features.update(ip_features)
                with self._stats_lock:
                    self.feature_stats['ip_features'] += len(ip_features)
            except Exception as e:
                logger.debug(f"IP features failed for {ip_address}: {e}")
                with self._stats_lock:
                    self.feature_stats['ip_lookup_failures'] += 1

            # 4b. Geolocation
            try:
                geo_features = self.geo_extractor.extract_all_features(ip_address)
                all_features.update(geo_features)
                with self._stats_lock:
                    self.feature_stats['geo_features'] += len(geo_features)
            except Exception as e:
                logger.debug(f"Geo features failed for {ip_address}: {e}")

            # 4c. Traffic
            try:
                traffic_features = self.traffic_extractor.extract_all_features(ip_address)
                all_features.update(traffic_features)
                with self._stats_lock:
                    self.feature_stats['traffic_features'] += len(traffic_features)
            except Exception as e:
                logger.debug(f"Traffic features failed for {ip_address}: {e}")
        else:
            # Add default IP features so ML still works
            all_features.update(self._default_ip_features())

        return all_features

    # ============================================
    # HELPERS
    # ============================================

    @staticmethod
    def _resolve_domain(domain):
        """Resolve domain to IP. Returns None on failure."""
        try:
            # Fast socket resolve with implicit timeout
            return socket.gethostbyname(domain)
        except Exception:
            return None

    @staticmethod
    def _default_ip_features():
        """Default IP features when domain doesn't resolve"""
        return {
            # Structural
            'is_private': 0,
            'is_ipv6': 0,
            'ip_numeric': 0,
            'threat_score': 0,
            'total_requests': 0,
            'active_threats_count': 0,
            'is_known_malicious': 0,
            'days_since_first_seen': 0,
            'octet_1': 0, 'octet_2': 0, 'octet_3': 0, 'octet_4': 0,

            # Intelligence
            'abuse_score': 0,
            'total_reports': 0,
            'asn_risk': 0.0,
            'country_risk': 0.0,
            'combined_risk': 0.0,
            'is_hosting': 0,
            'is_vpn': 0,
            'is_tor': 0,
            'is_proxy': 0,
            'hosting_provider': 0,
            'intel_available': 0,

            # Geo
            'has_geolocation': 0,
            'latitude': 0,
            'longitude': 0,
            'isp_length': 0,
            'org_exists': 0,

            # Traffic
            'request_frequency': 0,
            'unique_destinations': 0,
            'protocol_diversity': 0,
            'https_ratio': 0,
            'avg_payload_size': 0,
            'port_scan_likelihood': 0,
            'traffic_burstiness': 0,
        }

    # ============================================
    # STATS ACCESS
    # ============================================

    def get_stats(self):
        """Return current feature stats"""
        return self.feature_stats.copy()

    def reset_stats(self):
        """Reset stats (for a fresh run)"""
        with self._stats_lock:
            for key in self.feature_stats:
                self.feature_stats[key] = 0


# ============================================
# STANDALONE RUN
# ============================================

if __name__ == "__main__":
    import sys
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 500
    workers = int(sys.argv[2]) if len(sys.argv) > 2 else 10

    pipeline = FeaturePipeline(max_workers=workers)
    pipeline.run_pipeline(limit=limit)