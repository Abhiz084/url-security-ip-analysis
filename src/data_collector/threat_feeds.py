"""
Threat Intelligence Feed Collector
Integrates with AbuseIPDB, VirusTotal, and AlienVault OTX
"""

import requests
import time
from datetime import datetime
from loguru import logger
from config.settings import settings
from database.crud_operations import CRUDOperations

class ThreatFeedCollector:
    """Collect threat intelligence from external feeds"""
    
    def __init__(self):
        self.crud = CRUDOperations()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'URL-Security-ThreatIntel/1.0'
        })
        
        # API Keys from settings
        self.abuseipdb_key = settings.ABUSEIPDB_API_KEY
        self.virustotal_key = settings.VIRUSTOTAL_API_KEY
        
        self.ip_cache = {}
        
    def check_abuseipdb(self, ip_address):
        """Check IP reputation on AbuseIPDB"""
        if ip_address in self.ip_cache:
            return self.ip_cache[ip_address]
        
        logger.debug(f"Checking AbuseIPDB for {ip_address}")
        
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {
                'Key': self.abuseipdb_key,
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': 90
            }
            
            response = self.session.get(url, headers=headers, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json().get('data', {})
                
                threat_info = {
                    'ip_address': ip_address,
                    'abuse_confidence_score': data.get('abuseConfidenceScore', 0),
                    'country': data.get('countryCode', ''),
                    'isp': data.get('isp', ''),
                    'domain': data.get('domain', ''),
                    'total_reports': data.get('totalReports', 0),
                    'last_reported': data.get('lastReportedAt', ''),
                    'is_public': data.get('isPublic', False)
                }
                
                self.ip_cache[ip_address] = threat_info
                return threat_info
            else:
                logger.debug(f"AbuseIPDB returned {response.status_code}")
                
        except Exception as e:
            logger.error(f"AbuseIPDB check failed for {ip_address}: {e}")
        
        return None
    
    def check_virustotal(self, ip_address):
        """Check IP reputation on VirusTotal"""
        logger.debug(f"Checking VirusTotal for {ip_address}")
        
        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
            headers = {
                'x-apikey': self.virustotal_key,
                'Accept': 'application/json'
            }
            
            response = self.session.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json().get('data', {})
                attributes = data.get('attributes', {})
                
                last_analysis = attributes.get('last_analysis_stats', {})
                total_engines = sum(last_analysis.values())
                malicious_count = last_analysis.get('malicious', 0)
                
                threat_score = (malicious_count / total_engines * 100) if total_engines > 0 else 0
                
                threat_info = {
                    'ip_address': ip_address,
                    'threat_score': round(threat_score, 2),
                    'malicious_votes': malicious_count,
                    'total_engines': total_engines,
                    'country': attributes.get('country', ''),
                    'asn': attributes.get('asn', ''),
                    'network': attributes.get('network', '')
                }
                
                return threat_info
            else:
                logger.debug(f"VirusTotal returned {response.status_code}")
                
        except Exception as e:
            logger.error(f"VirusTotal check failed for {ip_address}: {e}")
        
        return None
    
    def collect_suspicious_ips(self):
        """Collect list of known suspicious IPs from public feeds"""
        logger.info("Collecting suspicious IPs from public feeds...")
        suspicious_ips = []
        
        # Public IP blocklists
        blocklist_urls = [
            "https://lists.blocklist.de/lists/all.txt",
            "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
            "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
        ]
        
        for url in blocklist_urls:
            try:
                response = self.session.get(url, timeout=30)
                if response.status_code == 200:
                    lines = response.text.strip().split('\n')
                    
                    for line in lines[:50]:  # Limit per source
                        # Extract IP from line (handle comments)
                        line = line.strip()
                        if line and not line.startswith('#'):
                            # Get first word/IP
                            ip = line.split()[0] if ' ' in line else line
                            ip = ip.split('/')[0]  # Remove CIDR notation
                            
                            # Validate IP format
                            parts = ip.split('.')
                            if len(parts) == 4 and all(p.isdigit() for p in parts):
                                suspicious_ips.append(ip)
                                
            except Exception as e:
                logger.error(f"Error collecting from {url}: {e}")
        
        # Remove duplicates
        suspicious_ips = list(set(suspicious_ips))
        logger.info(f"Collected {len(suspicious_ips)} suspicious IPs")
        
        return suspicious_ips
    
    def enrich_ip_data(self, ip_address, ip_version='IPv4'):
        """Enrich IP with threat intelligence data"""
        logger.debug(f"Enriching data for IP: {ip_address}")
        
        threat_score = 0.0
        threat_type = None
        source_feed = None
        description = None
        
        # Check AbuseIPDB
        abuseipdb_data = self.check_abuseipdb(ip_address)
        if abuseipdb_data:
            abuse_score = abuseipdb_data.get('abuse_confidence_score', 0)
            if abuse_score > threat_score:
                threat_score = abuse_score
                source_feed = 'AbuseIPDB'
                description = f"AbuseIPDB Score: {abuse_score}%"
            
            # Save to database
            self.crud.insert_ip_address(
                ip_address=ip_address,
                ip_version=ip_version,
                country=abuseipdb_data.get('country', ''),
                isp=abuseipdb_data.get('isp', ''),
                threat_score=threat_score
            )
            
            if abuse_score > 50:
                self.crud.insert_threat_intel(
                    ip_address=ip_address,
                    threat_type='other',
                    confidence_score=abuse_score,
                    source_feed='AbuseIPDB',
                    description=description
                )
        
        # Check VirusTotal
        virustotal_data = self.check_virustotal(ip_address)
        if virustotal_data:
            vt_score = virustotal_data.get('threat_score', 0)
            if vt_score > threat_score:
                threat_score = vt_score
                source_feed = 'VirusTotal'
                description = f"VirusTotal: {virustotal_data.get('malicious_votes', 0)}/{virustotal_data.get('total_engines', 0)} engines"
            
            # Update threat score
            self.crud.update_threat_score(ip_address, threat_score)
            
            if vt_score > 30:
                self.crud.insert_threat_intel(
                    ip_address=ip_address,
                    threat_type='malware',
                    confidence_score=vt_score,
                    source_feed='VirusTotal',
                    description=description
                )
        
        return {
            'ip_address': ip_address,
            'threat_score': threat_score,
            'source_feed': source_feed,
            'description': description
        }
    
    def run_threat_intel_pipeline(self):
        """Run complete threat intelligence collection pipeline"""
        logger.info("=" * 50)
        logger.info("Starting Threat Intelligence Collection")
        logger.info("=" * 50)
        
        # Get suspicious IPs
        suspicious_ips = self.collect_suspicious_ips()
        
        # Enrich each IP
        enriched_count = 0
        for ip in suspicious_ips[:20]:  # Limit API calls
            try:
                self.enrich_ip_data(ip)
                enriched_count += 1
                time.sleep(1)  # Rate limiting
            except Exception as e:
                logger.error(f"Failed to enrich {ip}: {e}")
        
        logger.info(f"Enriched {enriched_count} IPs with threat intelligence")
        return enriched_count