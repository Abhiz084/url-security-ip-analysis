"""
IP Reputation Checker
Checks IP addresses against threat intelligence
"""

import requests
import time
from datetime import datetime, timedelta
from loguru import logger
from database.crud_operations import CRUDOperations
from database.connection import db_manager
from config.settings import settings

class IPReputationChecker:
    """Check IP reputation from multiple sources"""
    
    def __init__(self):
        self.crud = CRUDOperations()
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'URL-Security-Reputation/1.0'})
        
        # Cache to avoid repeated lookups
        self.cache = {}
        self.cache_ttl = 3600  # 1 hour
        
        # API keys
        self.abuseipdb_key = settings.ABUSEIPDB_API_KEY
        
        # High-risk countries (known cybercrime sources)
        self.high_risk_countries = {
            'KP', 'IR', 'SY', 'SD', 'CU', 'VE', 'RU', 'CN', 'BY', 'MM', 'NG'
        }
    
    def check_ip(self, ip_address, force=False):
        """Check IP reputation with caching"""
        # Check cache first
        if not force and ip_address in self.cache:
            cached = self.cache[ip_address]
            if (datetime.now() - cached['timestamp']).total_seconds() < self.cache_ttl:
                return cached['data']
        
        # Check database
        db_info = self._check_database(ip_address)
        if db_info and db_info.get('threat_score', 0) > 0:
            self._update_cache(ip_address, db_info)
            return db_info
        
        # Check external APIs
        reputation = self._check_abuseipdb(ip_address)
        
        if reputation:
            self._update_cache(ip_address, reputation)
            self._save_to_database(ip_address, reputation)
        
        return reputation or {'ip_address': ip_address, 'threat_score': 0, 'is_malicious': False}
    
    def _check_database(self, ip_address):
        """Check if IP exists in our database"""
        result = self.crud.get_ip_info(ip_address)
        if result:
            return {
                'ip_address': ip_address,
                'threat_score': float(result.get('threat_score', 0)),
                'country': result.get('country', ''),
                'city': result.get('city', ''),
                'isp': result.get('isp', ''),
                'is_malicious': float(result.get('threat_score', 0)) > 50,
                'source': 'database'
            }
        return None
    
    def _check_abuseipdb(self, ip_address):
        """Check IP against AbuseIPDB"""
        if not self.abuseipdb_key or self.abuseipdb_key == 'your_abuseipdb_key':
            return None
        
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {
                'Key': self.abuseipdb_key,
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': 90,
                'verbose': ''
            }
            
            response = self.session.get(url, headers=headers, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json().get('data', {})
                
                abuse_score = data.get('abuseConfidenceScore', 0)
                
                return {
                    'ip_address': ip_address,
                    'threat_score': float(abuse_score),
                    'country': data.get('countryCode', ''),
                    'isp': data.get('isp', ''),
                    'domain': data.get('domain', ''),
                    'total_reports': data.get('totalReports', 0),
                    'last_reported': data.get('lastReportedAt', ''),
                    'is_malicious': abuse_score > 30,
                    'source': 'abuseipdb'
                }
                
        except Exception as e:
            logger.debug(f"AbuseIPDB check failed for {ip_address}: {e}")
        
        return None
    
    def _update_cache(self, ip_address, data):
        """Update local cache"""
        self.cache[ip_address] = {
            'data': data,
            'timestamp': datetime.now()
        }
    
    def _save_to_database(self, ip_address, reputation):
        """Save reputation data to database"""
        try:
            self.crud.insert_ip_address(
                ip_address=ip_address,
                ip_version='IPv4',
                country=reputation.get('country', ''),
                isp=reputation.get('isp', ''),
                threat_score=reputation.get('threat_score', 0)
            )
            
            if reputation.get('is_malicious'):
                self.crud.insert_threat_intel(
                    ip_address=ip_address,
                    threat_type='other',
                    confidence_score=reputation.get('threat_score', 0),
                    source_feed=reputation.get('source', 'unknown'),
                    description=f"Automated reputation check"
                )
        except Exception as e:
            logger.debug(f"Failed to save reputation: {e}")
    
    def get_threat_summary(self, ip_address):
        """Get comprehensive threat summary for an IP"""
        reputation = self.check_ip(ip_address)
        
        # Get alerts for this IP
        alerts = db_manager.execute_query(
            "SELECT COUNT(*) as count FROM alerts WHERE source_ip = %s",
            (ip_address,)
        )
        alert_count = alerts[0]['count'] if alerts else 0
        
        # Get traffic stats
        traffic = db_manager.execute_query(
            "SELECT COUNT(*) as count FROM traffic_logs WHERE src_ip = %s",
            (ip_address,)
        )
        traffic_count = traffic[0]['count'] if traffic else 0
        
        return {
            **reputation,
            'alert_count': alert_count,
            'traffic_count': traffic_count,
            'risk_level': self._calculate_risk_level(reputation.get('threat_score', 0), alert_count)
        }
    
    def _calculate_risk_level(self, threat_score, alert_count):
        """Calculate overall risk level"""
        risk = threat_score + (alert_count * 10)
        
        if risk > 80:
            return 'CRITICAL'
        elif risk > 50:
            return 'HIGH'
        elif risk > 30:
            return 'MEDIUM'
        elif risk > 10:
            return 'LOW'
        else:
            return 'SAFE'
    
    def clear_cache(self):
        """Clear the reputation cache"""
        self.cache.clear()
        logger.info("Reputation cache cleared")