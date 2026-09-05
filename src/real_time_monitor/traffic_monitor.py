"""
Network Traffic Monitor - With Real URL Extraction
"""

import time
import threading
import re
from datetime import datetime, timedelta
from collections import defaultdict, deque
from loguru import logger
from database.crud_operations import CRUDOperations
from database.connection import db_manager

try:
    from scapy.all import sniff, IP, TCP, UDP, DNS, Raw, conf
    from scapy.layers.http import HTTPRequest, HTTPResponse
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

class TrafficMonitor:
    """Real-time network traffic monitor with URL extraction"""
    
    def __init__(self, interface=None):
        self.crud = CRUDOperations()
        self.interface = interface
        self.is_running = False
        self.alert_system = None
        
        # Traffic tracking
        self.packet_buffer = deque(maxlen=10000)
        self.ip_stats = defaultdict(lambda: {
            'request_count': 0,
            'first_seen': None,
            'last_seen': None,
            'destinations': set(),
            'protocols': set(),
            'urls_visited': set(),
            'total_bytes': 0
        })
        self.url_stats = defaultdict(int)
        self.stats_lock = threading.Lock()
        
        # Stats
        self.total_packets = 0
        self.total_urls_extracted = 0
        self.total_alerts = 0
        self.start_time = None
        
        # Thresholds
        self.thresholds = {
            'requests_per_minute': 100,
            'unique_urls': 50,
            'suspicious_ports': {22, 23, 445, 3389, 8080},
        }
    
    def set_alert_system(self, alert_system):
        """Link alert system"""
        self.alert_system = alert_system
    
    def extract_url_from_packet(self, packet):
        """
        Extract URL from HTTP/HTTPS packet
        
        For HTTP: Parse the Host header and Request URI
        For HTTPS: Extract SNI (Server Name Indication) from TLS handshake
        For DNS: Extract queried domains
        """
        urls = []
        
        try:
            # === HTTP Request ===
            if packet.haslayer(HTTPRequest):
                http_layer = packet[HTTPRequest]
                host = http_layer.Host.decode() if http_layer.Host else ''
                path = http_layer.Path.decode() if http_layer.Path else '/'
                method = http_layer.Method.decode() if http_layer.Method else 'GET'
                
                if host:
                    protocol = 'https' if packet.haslayer(TCP) and packet[TCP].dport == 443 else 'http'
                    full_url = f"{protocol}://{host}{path}"
                    urls.append(('HTTP', full_url, host, path, method))
            
            # === HTTPS SNI (TLS Handshake) ===
            if packet.haslayer(TCP) and packet.haslayer(Raw):
                raw_data = bytes(packet[Raw].load)
                
                # Check for TLS Client Hello
                if len(raw_data) > 5 and raw_data[0] == 0x16 and raw_data[1] == 0x03:
                    # Try to extract SNI
                    try:
                        # Look for server_name extension (type 0x00 0x00)
                        sni_pattern = rb'\x00\x00.{2}\x00.{2}([\w\.-]+)'
                        match = re.search(sni_pattern, raw_data[:200])
                        if match:
                            server_name = match.group(1).decode('utf-8', errors='ignore')
                            if server_name and '.' in server_name:
                                full_url = f"https://{server_name}/"
                                urls.append(('HTTPS_SNI', full_url, server_name, '/', 'CONNECT'))
                    except:
                        pass
            
            # === DNS Queries ===
            if packet.haslayer(DNS):
                dns_layer = packet[DNS]
                if dns_layer.qr == 0:  # Query
                    for query in dns_layer.qd:
                        domain = query.qname.decode('utf-8', errors='ignore').rstrip('.')
                        if domain and '.' in domain:
                            urls.append(('DNS', f"dns://{domain}", domain, '', 'QUERY'))
            
        except Exception as e:
            logger.debug(f"URL extraction error: {e}")
        
        return urls
    
    def packet_handler(self, packet):
        """Process captured packet and extract URLs"""
        try:
            if not IP in packet:
                return
            
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            timestamp = datetime.now()
            
            # Extract URLs from packet
            extracted_urls = self.extract_url_from_packet(packet)
            
            protocol = 'OTHER'
            src_port = 0
            dst_port = 0
            payload_size = len(packet)
            
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                protocol = 'HTTP' if dst_port in [80, 8080] else 'HTTPS' if dst_port == 443 else 'TCP'
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                protocol = 'DNS' if dst_port == 53 else 'UDP'
            
            # Update stats
            with self.stats_lock:
                self.total_packets += 1
                
                stats = self.ip_stats[src_ip]
                stats['request_count'] += 1
                stats['last_seen'] = timestamp
                if stats['first_seen'] is None:
                    stats['first_seen'] = timestamp
                stats['destinations'].add(dst_ip)
                stats['protocols'].add(protocol)
                stats['total_bytes'] += payload_size
                
                # Store extracted URLs
                for url_type, full_url, host, path, method in extracted_urls:
                    stats['urls_visited'].add(full_url)
                    self.url_stats[full_url] += 1
                    self.total_urls_extracted += 1
                    
                    # Log real URLs as they're captured
                    logger.info(f"🌐 [{url_type}] {src_ip} → {full_url[:100]}")
                    
                    # Save URL to database
                    try:
                        self.crud.insert_url(
                            full_url=full_url,
                            domain=host,
                            path=path,
                            protocol='https' if 'https' in full_url else 'http',
                            tld=host.split('.')[-1] if '.' in host else '',
                            url_length=len(full_url),
                            source='traffic_capture'
                        )
                    except:
                        pass
                    
                    # Check URL for threats
                    self._check_url_threat(full_url, src_ip)
            
            # Check for anomalies
            self._check_anomalies(src_ip, dst_ip, dst_port, timestamp)
            
        except Exception as e:
            logger.debug(f"Packet processing error: {e}")
    
    def _check_url_threat(self, url, source_ip):
        """Check if captured URL is malicious"""
        # Quick local check
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work']
        suspicious_keywords = ['login', 'verify', 'paypal', 'banking', 'password', 'account']
        
        domain = url.split('/')[2] if '//' in url else url
        url_lower = url.lower()
        
        is_suspicious = False
        reason = ""
        
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            is_suspicious = True
            reason = "suspicious_tld"
        elif any(kw in url_lower for kw in suspicious_keywords):
            is_suspicious = True
            reason = "suspicious_keywords"
        
        if is_suspicious:
            self._trigger_alert(
                alert_type='suspicious_url',
                severity='high',
                source_ip=source_ip,
                description=f"Suspicious URL detected: {url[:100]} ({reason})"
            )
    
    # ... rest of the methods stay the same ...
    # (_check_anomalies, _trigger_alert, _flush_to_database, etc.)
    