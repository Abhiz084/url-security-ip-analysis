"""
Network Traffic Feature Extractor
Extracts behavioral features from traffic patterns
"""

from datetime import datetime, timedelta
from collections import defaultdict
from loguru import logger
from database.crud_operations import CRUDOperations
from database.queries import QueryBuilder

class TrafficFeatureExtractor:
    """Extract features from network traffic patterns"""
    
    def __init__(self):
        self.crud = CRUDOperations()
        self.query_builder = QueryBuilder()
    
    def extract_request_frequency(self, ip_address, window_minutes=60):
        """Feature 1: Request frequency (requests per minute)"""
        try:
            traffic = self.crud.get_traffic_by_ip(ip_address, limit=1000)
            
            if not traffic:
                return 0
            
            now = datetime.now()
            window_start = now - timedelta(minutes=window_minutes)
            
            recent_traffic = [
                t for t in traffic 
                if isinstance(t.get('timestamp'), datetime) and t['timestamp'] >= window_start
            ]
            
            return len(recent_traffic) / window_minutes
            
        except Exception as e:
            logger.debug(f"Frequency calculation error: {e}")
            return 0
    
    def extract_unique_destinations(self, ip_address):
        """Feature 2: Number of unique destination IPs"""
        try:
            traffic = self.crud.get_traffic_by_ip(ip_address, limit=1000)
            if not traffic:
                return 0
            
            destinations = set()
            for t in traffic:
                if t.get('dst_ip'):
                    destinations.add(t['dst_ip'])
            
            return len(destinations)
        except:
            return 0
    
    def extract_protocol_diversity(self, ip_address):
        """Feature 3: Number of different protocols used"""
        try:
            traffic = self.crud.get_traffic_by_ip(ip_address, limit=1000)
            if not traffic:
                return 0
            
            protocols = set()
            for t in traffic:
                if t.get('protocol'):
                    protocols.add(t['protocol'])
            
            return len(protocols)
        except:
            return 0
    
    def extract_https_ratio(self, ip_address):
        """Feature 4: Ratio of HTTPS traffic"""
        try:
            traffic = self.crud.get_traffic_by_ip(ip_address, limit=1000)
            if not traffic:
                return 0
            
            https_count = sum(1 for t in traffic if t.get('protocol') == 'HTTPS')
            total = len(traffic)
            
            return https_count / total if total > 0 else 0
        except:
            return 0
    
    def extract_avg_payload_size(self, ip_address):
        """Feature 5: Average payload size"""
        try:
            traffic = self.crud.get_traffic_by_ip(ip_address, limit=1000)
            if not traffic:
                return 0
            
            sizes = [t.get('payload_size', 0) for t in traffic if t.get('payload_size')]
            
            return sum(sizes) / len(sizes) if sizes else 0
        except:
            return 0
    
    def extract_port_scan_likelihood(self, ip_address):
        """Feature 6: Port scan likelihood (many unique ports)"""
        try:
            traffic = self.crud.get_traffic_by_ip(ip_address, limit=500)
            if not traffic:
                return 0
            
            dst_ports = set()
            for t in traffic:
                if t.get('dst_port'):
                    dst_ports.add(t['dst_port'])
            
            # If accessing many different ports, might be scanning
            return min(len(dst_ports) / 50, 1.0)  # Normalize
        except:
            return 0
    
    def extract_traffic_burstiness(self, ip_address):
        """Feature 7: Traffic burstiness score"""
        try:
            traffic = self.crud.get_traffic_by_ip(ip_address, limit=1000)
            if not traffic or len(traffic) < 2:
                return 0
            
            timestamps = [
                t['timestamp'] for t in traffic 
                if isinstance(t.get('timestamp'), datetime)
            ]
            timestamps.sort()
            
            # Calculate intervals between requests
            intervals = []
            for i in range(1, len(timestamps)):
                delta = (timestamps[i] - timestamps[i-1]).total_seconds()
                intervals.append(delta)
            
            if not intervals:
                return 0
            
            # Burstiness = std/mean of intervals
            mean_interval = sum(intervals) / len(intervals)
            if mean_interval == 0:
                return 1.0
            
            variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
            std_interval = variance ** 0.5
            
            return std_interval / mean_interval if mean_interval > 0 else 0
            
        except Exception as e:
            logger.debug(f"Burstiness calculation error: {e}")
            return 0
    
    def extract_all_features(self, ip_address):
        """Extract all traffic features"""
        features = {
            'request_frequency': round(self.extract_request_frequency(ip_address), 2),
            'unique_destinations': self.extract_unique_destinations(ip_address),
            'protocol_diversity': self.extract_protocol_diversity(ip_address),
            'https_ratio': round(self.extract_https_ratio(ip_address), 4),
            'avg_payload_size': round(self.extract_avg_payload_size(ip_address), 2),
            'port_scan_likelihood': round(self.extract_port_scan_likelihood(ip_address), 4),
            'traffic_burstiness': round(self.extract_traffic_burstiness(ip_address), 4),
        }
        
        return features