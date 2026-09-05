"""
URL Collection Module
Collects URLs from various sources - PhishTank, OpenPhish, URLhaus, and web scraping
"""

import requests
import csv
import json
import time
from datetime import datetime
from urllib.parse import urlparse
from loguru import logger
from database.crud_operations import CRUDOperations

class URLScraper:
    """Collect URLs from threat intelligence sources and public datasets"""
    
    def __init__(self):
        self.crud = CRUDOperations()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'URL-Security-Research/1.0'
        })
        self.collected_urls = []
        
    def collect_from_phishtank(self, limit=100):
        """Collect phishing URLs from PhishTank"""
        logger.info("Collecting URLs from PhishTank...")
        urls = []
        
        try:
            # PhishTank API v2 - requires app registration but has free tier
            # Using the developer API endpoint
            phishtank_urls = [
                "https://data.phishtank.com/data/online-valid.json",
                "http://data.phishtank.com/data/online-valid.csv"
            ]
            
            for api_url in phishtank_urls:
                try:
                    response = self.session.get(api_url, timeout=30)
                    
                    if response.status_code == 200:
                        if api_url.endswith('.json'):
                            data = response.json()
                            
                            if isinstance(data, list):
                                for entry in data[:limit]:
                                    url = entry.get('url', '') or entry.get('phish_detail_url', '')
                                    if url and url.startswith('http'):
                                        parsed = urlparse(url)
                                        url_data = {
                                            'full_url': url,
                                            'domain': parsed.netloc or parsed.path.split('/')[0],
                                            'path': parsed.path or '/',
                                            'protocol': parsed.scheme,
                                            'tld': parsed.netloc.split('.')[-1] if '.' in parsed.netloc else '',
                                            'url_length': len(url),
                                            'source': 'PhishTank',
                                            'is_malicious': True
                                        }
                                        urls.append(url_data)
                        
                        elif api_url.endswith('.csv'):
                            lines = response.text.strip().split('\n')
                            # Skip header
                            for line in lines[1:limit+1]:
                                parts = line.split(',')
                                if len(parts) > 1:
                                    url = parts[1].strip() if len(parts) > 1 else parts[0].strip()
                                    if url and url.startswith('http'):
                                        parsed = urlparse(url)
                                        url_data = {
                                            'full_url': url,
                                            'domain': parsed.netloc,
                                            'path': parsed.path or '/',
                                            'protocol': parsed.scheme,
                                            'tld': parsed.netloc.split('.')[-1] if '.' in parsed.netloc else '',
                                            'url_length': len(url),
                                            'source': 'PhishTank',
                                            'is_malicious': True
                                        }
                                        urls.append(url_data)
                        
                        if urls:
                            logger.info(f"PhishTank returned {len(urls)} URLs from {api_url}")
                            break
                            
                except Exception as e:
                    logger.debug(f"PhishTank endpoint {api_url} failed: {e}")
                    continue
                    
        except Exception as e:
            logger.error(f"Error collecting from PhishTank: {e}")
        
        # Fallback: Use a static sample of known phishing URLs if API fails
        if not urls:
            logger.warning("PhishTank API failed, using fallback sample data")
            urls = self._get_fallback_phishing_urls(limit)
        
        return urls
    
    def _get_fallback_phishing_urls(self, limit=50):
        """Fallback phishing URLs if APIs fail"""
        fallback_urls = [
            "http://suspicious-login.xyz/verify/account.php",
            "http://paypal-secure.verify-account.ml/login",
            "http://banking-update.ga/secure/login.php",
            "http://amazon-order-confirm.cf/verify",
            "http://netflix-verify-account.tk/update",
            "http://apple-id-verify.work/check",
            "http://microsoft-security.xyz/alert",
            "http://dropbox-share-file.ml/download",
            "http://facebook-security-check.ga/verify",
            "http://instagram-verify-badge.cf/confirm",
            "http://whatsapp-web-login.tk/verify",
            "http://gmail-security-alert.work/check",
            "http://yahoo-verify-mail.ml/update",
            "http://outlook-security.xyz/login",
            "http://steam-community-market.ga/trade",
            "http://discord-nitro-free.cf/claim",
            "http://spotify-premium-free.tk/upgrade",
            "http://crypto-wallet-verify.work/check",
            "http://binance-trading-signal.ml/join",
            "http://coinbase-verify-account.xyz/login",
            "http://tax-refund-irs.ga/claim",
            "http://covid-vaccine-pass.cf/verify",
            "http://job-offer-linkedin.tk/apply",
            "http://lottery-winner-claim.work/prize",
            "http://inheritance-fund-transfer.ml/claim",
            "http://shipping-dhl-track.xyz/package",
            "http://fedex-delivery-confirm.ga/verify",
            "http://ups-parcel-redirect.cf/track",
            "http://western-union-transfer.tk/send",
            "http://moneygram-receive.work/claim",
        ]
        
        urls = []
        for url in fallback_urls[:limit]:
            parsed = urlparse(url)
            url_data = {
                'full_url': url,
                'domain': parsed.netloc,
                'path': parsed.path or '/',
                'protocol': parsed.scheme,
                'tld': parsed.netloc.split('.')[-1] if '.' in parsed.netloc else '',
                'url_length': len(url),
                'source': 'PhishTank_Fallback',
                'is_malicious': True
            }
            urls.append(url_data)
        
        logger.info(f"Using {len(urls)} fallback phishing URLs")
        return urls
    
    def collect_from_openphish(self, limit=100):
        """Collect phishing URLs from OpenPhish"""
        logger.info("Collecting URLs from OpenPhish...")
        urls = []
        
        try:
            # OpenPhish public feed
            openphish_urls = [
                "https://openphish.com/feed.txt",
            ]
            
            for feed_url in openphish_urls:
                try:
                    response = self.session.get(feed_url, timeout=30)
                    if response.status_code == 200:
                        feed_lines = response.text.strip().split('\n')
                        
                        for line in feed_lines[:limit]:
                            url = line.strip()
                            if url and url.startswith('http'):
                                parsed = urlparse(url)
                                url_data = {
                                    'full_url': url,
                                    'domain': parsed.netloc,
                                    'path': parsed.path or '/',
                                    'protocol': parsed.scheme,
                                    'tld': parsed.netloc.split('.')[-1] if '.' in parsed.netloc else '',
                                    'url_length': len(url),
                                    'source': 'OpenPhish',
                                    'is_malicious': True
                                }
                                urls.append(url_data)
                        
                        if urls:
                            logger.info(f"OpenPhish returned {len(urls)} URLs")
                            break
                except:
                    continue
                    
        except Exception as e:
            logger.error(f"Error collecting from OpenPhish: {e}")
        
        return urls
    
    def collect_from_urlhaus(self, limit=100):
        """Collect malware URLs from URLhaus"""
        logger.info("Collecting URLs from URLhaus...")
        urls = []
        
        try:
            # URLhaus API - more reliable
            urlhaus_urls = [
                "https://urlhaus-api.abuse.ch/v1/urls/recent/",
                "https://urlhaus.abuse.ch/downloads/csv_recent/"
            ]
            
            for api_url in urlhaus_urls:
                try:
                    response = self.session.get(api_url, timeout=30)
                    
                    if response.status_code == 200:
                        if 'json' in response.headers.get('Content-Type', ''):
                            data = response.json()
                            
                            for entry in data.get('urls', [])[:limit]:
                                url = entry.get('url', '')
                                if url:
                                    parsed = urlparse(url)
                                    url_data = {
                                        'full_url': url,
                                        'domain': parsed.netloc,
                                        'path': parsed.path or '/',
                                        'protocol': parsed.scheme,
                                        'tld': parsed.netloc.split('.')[-1] if '.' in parsed.netloc else '',
                                        'url_length': len(url),
                                        'source': 'URLhaus',
                                        'is_malicious': True
                                    }
                                    urls.append(url_data)
                        
                        elif 'csv' in response.headers.get('Content-Type', ''):
                            lines = response.text.strip().split('\n')
                            # Skip header comment lines
                            for line in lines:
                                if line.startswith('#'):
                                    continue
                                parts = line.split(',')
                                if len(parts) > 2:
                                    url = parts[2].strip().strip('"')
                                    if url and url.startswith('http'):
                                        parsed = urlparse(url)
                                        url_data = {
                                            'full_url': url,
                                            'domain': parsed.netloc,
                                            'path': parsed.path or '/',
                                            'protocol': parsed.scheme,
                                            'tld': parsed.netloc.split('.')[-1] if '.' in parsed.netloc else '',
                                            'url_length': len(url),
                                            'source': 'URLhaus',
                                            'is_malicious': True
                                        }
                                        urls.append(url_data)
                                        if len(urls) >= limit:
                                            break
                        
                        if urls:
                            logger.info(f"URLhaus returned {len(urls)} URLs")
                            break
                            
                except Exception as e:
                    logger.debug(f"URLhaus endpoint {api_url} failed: {e}")
                    continue
                    
        except Exception as e:
            logger.error(f"Error collecting from URLhaus: {e}")
        
        return urls
    
    def collect_from_phishing_army(self, limit=100):
        """Collect from Phishing Army blocklist"""
        logger.info("Collecting URLs from Phishing Army...")
        urls = []
        
        try:
            army_url = "https://phishing.army/download/phishing_army_blocklist.txt"
            response = self.session.get(army_url, timeout=30)
            
            if response.status_code == 200:
                lines = response.text.strip().split('\n')
                
                for line in lines[:limit]:
                    url = line.strip()
                    if url and url.startswith('http'):
                        parsed = urlparse(url)
                        url_data = {
                            'full_url': url,
                            'domain': parsed.netloc,
                            'path': parsed.path or '/',
                            'protocol': parsed.scheme,
                            'tld': parsed.netloc.split('.')[-1] if '.' in parsed.netloc else '',
                            'url_length': len(url),
                            'source': 'Phishing_Army',
                            'is_malicious': True
                        }
                        urls.append(url_data)
                        
                logger.info(f"Phishing Army returned {len(urls)} URLs")
                
        except Exception as e:
            logger.error(f"Error collecting from Phishing Army: {e}")
        
        return urls
    
    def collect_benign_urls(self, limit=100):
        """Collect benign URLs from top websites"""
        logger.info("Collecting benign URLs...")
        urls = []
        
        # Common benign websites for training
        benign_sources = [
            "https://www.google.com",
            "https://www.youtube.com",
            "https://www.facebook.com",
            "https://www.wikipedia.org",
            "https://www.amazon.com",
            "https://www.twitter.com",
            "https://www.linkedin.com",
            "https://www.github.com",
            "https://www.stackoverflow.com",
            "https://www.reddit.com",
            "https://www.microsoft.com",
            "https://www.apple.com",
            "https://www.cloudflare.com",
            "https://www.mozilla.org",
            "https://www.python.org",
            "https://www.nginx.com",
            "https://www.apache.org",
            "https://www.docker.com",
            "https://www.kubernetes.io",
            "https://www.ansible.com",
            "https://www.udemy.com",
            "https://www.coursera.org",
            "https://www.medium.com",
            "https://www.dev.to",
            "https://www.npmjs.com",
            "https://www.pypi.org",
            "https://www.typescriptlang.org",
            "https://www.reactjs.org",
            "https://www.vuejs.org",
            "https://www.angular.io",
            "https://www.djangoproject.com",
            "https://www.flask.palletsprojects.com",
            "https://www.fastapi.tiangolo.com",
            "https://www.postgresql.org",
            "https://www.mysql.com",
            "https://www.mongodb.com",
            "https://www.redis.io",
            "https://www.elastic.co",
            "https://www.heroku.com",
            "https://www.netlify.com",
            "https://www.vercel.com",
            "https://www.digitalocean.com",
            "https://www.linode.com",
            "https://www.namecheap.com",
            "https://www.godaddy.com",
            "https://www.cloudways.com",
            "https://www.shopify.com",
            "https://www.wordpress.org",
            "https://www.joomla.org",
            "https://www.drupal.org",
        ]
        
        for url in benign_sources[:limit]:
            parsed = urlparse(url)
            url_data = {
                'full_url': url,
                'domain': parsed.netloc,
                'path': parsed.path or '/',
                'protocol': parsed.scheme,
                'tld': parsed.netloc.split('.')[-1] if '.' in parsed.netloc else '',
                'url_length': len(url),
                'source': 'Benign_Top_Sites',
                'is_malicious': False
            }
            urls.append(url_data)
            
        logger.info(f"Collected {len(urls)} benign URLs")
        
        return urls
    
    def collect_all(self, malicious_limit=200, benign_limit=200):
        """Collect all URLs from all sources"""
        logger.info("Starting URL collection from all sources...")
        
        all_urls = []
        
        # Collect malicious URLs from multiple sources
        logger.info("Collecting malicious URLs...")
        all_urls.extend(self.collect_from_phishtank(malicious_limit))
        all_urls.extend(self.collect_from_openphish(malicious_limit))
        all_urls.extend(self.collect_from_urlhaus(malicious_limit))
        all_urls.extend(self.collect_from_phishing_army(malicious_limit))
        
        # Remove duplicate malicious URLs
        seen_urls = set()
        unique_malicious = []
        for url_data in all_urls:
            if url_data['full_url'] not in seen_urls:
                seen_urls.add(url_data['full_url'])
                unique_malicious.append(url_data)
        
        logger.info(f"Unique malicious URLs: {len(unique_malicious)}")
        
        # Collect benign URLs
        benign_urls = self.collect_benign_urls(benign_limit)
        
        # Combine
        final_urls = unique_malicious + benign_urls
        self.collected_urls = final_urls
        
        logger.info(f"Total URLs collected: {len(final_urls)} ({len(unique_malicious)} malicious, {len(benign_urls)} benign)")
        
        return final_urls
    
    def save_to_database(self, urls=None):
        """Save collected URLs to MySQL database"""
        if urls is None:
            urls = self.collected_urls
        
        saved_count = 0
        duplicate_count = 0
        error_count = 0
        
        for url_data in urls:
            try:
                result = self.crud.insert_url(
                    full_url=url_data['full_url'],
                    domain=url_data.get('domain', ''),
                    path=url_data.get('path', ''),
                    protocol=url_data.get('protocol', ''),
                    tld=url_data.get('tld', ''),
                    url_length=url_data.get('url_length', len(url_data['full_url'])),
                    source=url_data.get('source', 'unknown'),
                    is_malicious=url_data.get('is_malicious', None)
                )
                
                if result:
                    saved_count += 1
                else:
                    duplicate_count += 1
                    
            except Exception as e:
                error_count += 1
                if 'Duplicate' not in str(e):
                    logger.debug(f"Error saving URL: {str(e)[:100]}")
        
        logger.info(f"Saved {saved_count} new URLs, {duplicate_count} duplicates, {error_count} errors")
        return saved_count
    
    def run_collection_pipeline(self):
        """Run full collection pipeline"""
        logger.info("=" * 50)
        logger.info("Starting URL Collection Pipeline")
        logger.info("=" * 50)
        
        # Collect URLs
        urls = self.collect_all(malicious_limit=200, benign_limit=100)
        
        # Save to database
        saved = self.save_to_database(urls)
        
        logger.info(f"Collection pipeline complete. {saved} URLs saved to database.")
        return saved


# Quick test function
def test_collectors():
    """Test all collectors"""
    scraper = URLScraper()
    
    print("\n" + "="*50)
    print("Testing URL Collectors...")
    print("="*50)
    
    # Test PhishTank
    print("\n1. Testing PhishTank...")
    phish_urls = scraper.collect_from_phishtank(10)
    print(f"   Got {len(phish_urls)} URLs")
    
    # Test OpenPhish
    print("\n2. Testing OpenPhish...")
    openphish_urls = scraper.collect_from_openphish(10)
    print(f"   Got {len(openphish_urls)} URLs")
    
    # Test URLhaus
    print("\n3. Testing URLhaus...")
    urlhaus_urls = scraper.collect_from_urlhaus(10)
    print(f"   Got {len(urlhaus_urls)} URLs")
    
    # Test Phishing Army
    print("\n4. Testing Phishing Army...")
    army_urls = scraper.collect_from_phishing_army(10)
    print(f"   Got {len(army_urls)} URLs")
    
    print("\n" + "="*50)
    print("All tests complete!")
    print("="*50)

if __name__ == "__main__":
    test_collectors()