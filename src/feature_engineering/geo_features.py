"""
Geolocation Feature Extractor
Extracts geographic features from IP addresses
"""

import requests
from loguru import logger
from database.crud_operations import CRUDOperations

class GeoFeatureExtractor:
    """Extract geolocation features from IPs"""
    
    def __init__(self):
        self.crud = CRUDOperations()
        self.cache = {}
        
        # High-risk countries (example list)
        self.high_risk_countries = {
            'KP', 'IR', 'SY', 'SD', 'CU', 'VE', 'RU', 'CN', 'BY', 'MM'
        }
    
    def get_geolocation(self, ip_address):
        """Get geolocation data for IP"""
        if ip_address in self.cache:
            return self.cache[ip_address]
        
        # Skip private IPs
        if ip_address.startswith(('192.168.', '10.', '172.16.', '127.')):
            return None
        
        try:
            # Using ip-api.com (free, no API key required)
            response = requests.get(
                f'http://ip-api.com/json/{ip_address}',
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    geo_data = {
                        'country': data.get('country', ''),
                        'country_code': data.get('countryCode', ''),
                        'city': data.get('city', ''),
                        'region': data.get('regionName', ''),
                        'latitude': data.get('lat', 0),
                        'longitude': data.get('lon', 0),
                        'isp': data.get('isp', ''),
                        'org': data.get('org', ''),
                        'asn': data.get('as', ''),
                    }
                    self.cache[ip_address] = geo_data
                    return geo_data
                    
        except Exception as e:
            logger.debug(f"Geolocation failed for {ip_address}: {e}")
        
        return None
    
    def extract_country_risk(self, country_code):
        """Feature 1: High-risk country flag"""
        return 1 if country_code in self.high_risk_countries else 0
    
    def extract_has_geolocation(self, ip_address):
        """Feature 2: Has geolocation data"""
        geo = self.get_geolocation(ip_address)
        return 1 if geo else 0
    
    def extract_latitude(self, ip_address):
        """Feature 3: Latitude"""
        geo = self.get_geolocation(ip_address)
        return geo.get('latitude', 0) if geo else 0
    
    def extract_longitude(self, ip_address):
        """Feature 4: Longitude"""
        geo = self.get_geolocation(ip_address)
        return geo.get('longitude', 0) if geo else 0
    
    def extract_isp_length(self, ip_address):
        """Feature 5: ISP name length"""
        geo = self.get_geolocation(ip_address)
        return len(geo.get('isp', '')) if geo else 0
    
    def extract_org_exists(self, ip_address):
        """Feature 6: Organization data exists"""
        geo = self.get_geolocation(ip_address)
        return 1 if geo and geo.get('org') else 0
    
    def extract_all_features(self, ip_address):
        """Extract all geolocation features"""
        geo = self.get_geolocation(ip_address)
        
        features = {
            'country_risk': self.extract_country_risk(geo.get('country_code', '') if geo else ''),
            'has_geolocation': 1 if geo else 0,
            'latitude': geo.get('latitude', 0) if geo else 0,
            'longitude': geo.get('longitude', 0) if geo else 0,
            'isp_length': len(geo.get('isp', '')) if geo else 0,
            'org_exists': 1 if geo and geo.get('org') else 0,
        }
        
        # Update IP address info in database
        if geo:
            try:
                self.crud.insert_ip_address(
                    ip_address=ip_address,
                    ip_version='IPv4',
                    country=geo.get('country', ''),
                    city=geo.get('city', ''),
                    region=geo.get('region', ''),
                    latitude=geo.get('latitude'),
                    longitude=geo.get('longitude'),
                    isp=geo.get('isp', ''),
                    organization=geo.get('org', ''),
                    asn=geo.get('asn', '')
                )
            except Exception as e:
                logger.debug(f"Failed to save geo data: {e}")
        
        return features