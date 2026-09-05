#!/usr/bin/env python3
"""
LIVE Network Traffic Monitor - Captures REAL URLs from your network
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time
from datetime import datetime
from loguru import logger
from database.crud_operations import CRUDOperations

logger.add("logs/live_monitor.log", rotation="10 MB", level="INFO")

# Try importing Scapy
try:
    from scapy.all import sniff, IP, TCP, UDP, DNS, Raw
    from scapy.layers.http import HTTPRequest
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Scapy not installed. Run: pip install scapy")
    exit()

class LiveTrafficMonitor:
    """Captures REAL URLs from your network traffic"""
    
    def __init__(self, interface=None):
        self.interface = interface
        self.crud = CRUDOperations()
        self.is_running = False
        self.total_packets = 0
        self.total_urls = 0
        self.total_alerts = 0
        self.domains_seen = set()
        
    def extract_http_url(self, packet):
        """Extract full URL from HTTP request"""
        try:
            if packet.haslayer(HTTPRequest):
                http_layer = packet[HTTPRequest]
                host = http_layer.Host.decode() if http_layer.Host else b''
                path = http_layer.Path.decode() if http_layer.Path else b'/'
                
                if host:
                    host = host.decode() if isinstance(host, bytes) else host
                    path = path.decode() if isinstance(path, bytes) else path
                    full_url = f"http://{host}{path}"
                    return full_url, host
        except:
            pass
        return None, None
    
    def extract_https_sni(self, packet):
        """Extract domain from HTTPS TLS SNI"""
        try:
            if packet.haslayer(TCP) and packet.haslayer(Raw):
                raw = bytes(packet[Raw].load)
                if len(raw) > 5 and raw[0] == 0x16 and raw[1] == 0x03:
                    for i in range(len(raw) - 50):
                        if raw[i:i+2] == b'\x00\x00':
                            try:
                                length = int.from_bytes(raw[i+2:i+4], 'big')
                                sni_data = raw[i+4:i+4+length]
                                if len(sni_data) > 3:
                                    name_len = sni_data[2]
                                    server_name = sni_data[3:3+name_len].decode('utf-8', errors='ignore')
                                    # Only accept valid domain names
                                    if '.' in server_name and len(server_name) > 3 and len(server_name) < 100:
                                        # Check for printable ASCII only
                                        if all(32 <= ord(c) < 127 for c in server_name):
                                            return f"https://{server_name}/", server_name
                            except:
                                pass
        except:
            pass
        return None, None
    
    def extract_dns_query(self, packet):
        """Extract domain from DNS query"""
        try:
            if packet.haslayer(DNS) and packet[DNS].qr == 0:
                for query in packet[DNS].qd:
                    domain = query.qname.decode('utf-8', errors='ignore').rstrip('.')
                    if '.' in domain and len(domain) > 3:
                        return f"dns://{domain}", domain
        except:
            pass
        return None, None
    
    def check_url_threat(self, url, domain):
        """Quick threat check on captured URL"""
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.click']
        suspicious_keywords = ['login', 'verify', 'paypal', 'banking', 'password', 'account', 'confirm']
        
        for tld in suspicious_tlds:
            if domain.endswith(tld):
                return True, f"suspicious_tld:{tld}"
        
        url_lower = url.lower()
        matches = [kw for kw in suspicious_keywords if kw in url_lower]
        if len(matches) >= 2:
            return True, f"suspicious_keywords:{','.join(matches)}"
        
        return False, ""
    
    def packet_handler(self, packet):
        """Process each captured packet"""
        try:
            if not IP in packet:
                return
            
            src_ip = packet[IP].src
            self.total_packets += 1
            
            # Try to extract URL from different protocols
            url = None
            domain = None
            protocol = 'OTHER'
            
            # HTTP
            url, domain = self.extract_http_url(packet)
            if url:
                protocol = 'HTTP'
            
            # HTTPS
            if not url:
                url, domain = self.extract_https_sni(packet)
                if url:
                    protocol = 'HTTPS'
            
            # DNS
            if not url:
                url, domain = self.extract_dns_query(packet)
                if url:
                    protocol = 'DNS'
            
            if url and domain and domain not in self.domains_seen:
                self.domains_seen.add(domain)
                self.total_urls += 1
                
                # Log the captured URL
                print(f"🌐 [{protocol}] {src_ip} → {domain}")
                
                # Save to database - truncate TLD if too long
                tld = domain.split('.')[-1] if '.' in domain else ''
                if len(tld) > 20:
                    tld = tld[:20]
                
                try:
                    self.crud.insert_url(
                        full_url=url,
                        domain=domain,
                        path='/',
                        protocol='https' if 'https' in url else 'http',
                        tld=tld,
                        url_length=len(url),
                        source='live_traffic'
                    )
                except:
                    pass
                
                # Check for threats
                is_threat, reason = self.check_url_threat(url, domain)
                if is_threat:
                    self.total_alerts += 1
                    print(f"  🚨 THREAT DETECTED: {domain} ({reason})")
                    
                    # Create alert in database
                    try:
                        from src.real_time_monitor.alert_system import AlertSystem
                        alert = AlertSystem()
                        alert.create_alert(
                            alert_type='suspicious_url',
                            severity='high',
                            source_ip=src_ip,
                            description=f'Live traffic: Suspicious URL - {domain} ({reason})'
                        )
                    except:
                        pass
        
        except Exception as e:
            pass
    
    def start(self, duration=120):
        """Start live capture"""
        print(f"""
╔══════════════════════════════════════════════════╗
║     🔴 LIVE NETWORK TRAFFIC MONITOR             ║
║                                                  ║
║  Capturing REAL URLs from your network           ║
║  Browse websites to see them appear below        ║
║  Press Ctrl+C to stop                            ║
╚══════════════════════════════════════════════════╝
        """)
        
        self.is_running = True
        start_time = datetime.now()
        
        try:
            sniff(
                iface=self.interface,
                prn=self.packet_handler,
                store=False,
                timeout=duration,
                filter="tcp port 80 or tcp port 443 or udp port 53"
            )
        except PermissionError:
            print("\n❌ ERROR: Need administrator privileges!")
            print("   Run PowerShell as Administrator and try again.")
            return
        except Exception as e:
            print(f"\n❌ Capture error: {e}")
            return
        finally:
            self.is_running = False
        
        elapsed = (datetime.now() - start_time).total_seconds()
        
        print(f"""
╔══════════════════════════════════════════════════╗
║     ✅ LIVE CAPTURE COMPLETE                     ║
║                                                  ║
║  Duration:    {elapsed:.0f} seconds              ║
║  Packets:     {self.total_packets}               ║
║  URLs Found:  {self.total_urls}                  ║
║  Alerts:      {self.total_alerts}                ║
║  Domains:     {len(self.domains_seen)}           ║
╚══════════════════════════════════════════════════╝
        """)
        
        if self.domains_seen:
            print("\n📋 Captured Domains:")
            for d in sorted(self.domains_seen)[:20]:
                print(f"   • {d}")
            if len(self.domains_seen) > 20:
                print(f"   ... and {len(self.domains_seen) - 20} more")


if __name__ == "__main__":
    monitor = LiveTrafficMonitor()
    
    print("\n⚠️  IMPORTANT:")
    print("   1. Run this as ADMINISTRATOR for live capture")
    print("   2. Browse websites while it's running")
    print("   3. URLs will appear in real-time below\n")
    
    try:
        duration = int(input("   Capture duration (seconds) [60]: ") or "60")
    except:
        duration = 60
    
    monitor.start(duration=duration)