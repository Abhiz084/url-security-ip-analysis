"""
Background Live Monitor
Runs packet capture in a thread so it can be started/stopped from the dashboard
"""

import threading
import time
import re
import socket
from datetime import datetime
from loguru import logger
from database.crud_operations import CRUDOperations

try:
    from scapy.all import sniff, IP, TCP, UDP, DNS, Raw
    from scapy.layers.http import HTTPRequest
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class BackgroundLiveMonitor:
    """Thread-based live traffic monitor that can be controlled from the dashboard"""

    def __init__(self):
        self.crud = CRUDOperations()
        self.thread = None
        self.stop_event = threading.Event()
        self.is_running = False
        self.use_simulation = False

        # Stats
        self.total_packets = 0
        self.total_urls = 0
        self.total_alerts = 0
        self.domains_seen = set()
        self.recent_domains = []  # last 50 domains for display

        # Thread lock for safe stat updates
        self.lock = threading.Lock()

        # Suspicious patterns
        self.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top',
                                '.work', '.click', '.icu', '.cfd']
        self.suspicious_keywords = ['login', 'verify', 'paypal', 'banking', 'password',
                                    'account', 'confirm', 'secure', 'signin']

    # ============================================
    # PACKET PARSING
    # ============================================

    def _extract_http_url(self, packet):
        try:
            if packet.haslayer(HTTPRequest):
                http_layer = packet[HTTPRequest]
                host = http_layer.Host.decode() if http_layer.Host else ''
                path = http_layer.Path.decode() if http_layer.Path else '/'
                if host:
                    return f"http://{host}{path}", host
        except:
            pass
        return None, None

    def _extract_https_sni(self, packet):
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
                                    name = sni_data[3:3+name_len].decode('utf-8', errors='ignore')
                                    if '.' in name and 3 < len(name) < 100:
                                        if all(32 <= ord(c) < 127 for c in name):
                                            return f"https://{name}/", name
                            except:
                                pass
        except:
            pass
        return None, None

    def _extract_dns(self, packet):
        try:
            if packet.haslayer(DNS) and packet[DNS].qr == 0:
                for query in packet[DNS].qd:
                    domain = query.qname.decode('utf-8', errors='ignore').rstrip('.')
                    if '.' in domain and len(domain) > 3:
                        return f"dns://{domain}", domain
        except:
            pass
        return None, None

    def _check_threat(self, url, domain):
        for tld in self.suspicious_tlds:
            if domain.endswith(tld):
                return True, f"suspicious_tld:{tld}"
        url_lower = url.lower()
        matches = [kw for kw in self.suspicious_keywords if kw in url_lower]
        if len(matches) >= 2:
            return True, f"suspicious_keywords:{','.join(matches)}"
        return False, ""

    def _save_url(self, url, domain, src_ip):
        """Save URL to database and check threats"""
        tld = domain.split('.')[-1] if '.' in domain else ''
        if len(tld) > 20:
            tld = tld[:20]

        try:
            self.crud.insert_url(
                full_url=url, domain=domain, path='/',
                protocol='https' if 'https' in url else 'http',
                tld=tld, url_length=len(url),
                source='live_traffic'
            )
        except Exception as e:
            logger.debug(f"DB insert skipped: {e}")

        # Threat check
        is_threat, reason = self._check_threat(url, domain)
        if is_threat:
            try:
                from src.real_time_monitor.alert_system import AlertSystem
                alert = AlertSystem()
                alert.create_alert(
                    alert_type='suspicious_url', severity='high',
                    source_ip=src_ip,
                    description=f'Live: {domain} ({reason})'
                )
                with self.lock:
                    self.total_alerts += 1
            except:
                pass

    # ============================================
    # PACKET HANDLER
    # ============================================

    def _packet_handler(self, packet):
        try:
            if not IP in packet:
                return
            src_ip = packet[IP].src

            with self.lock:
                self.total_packets += 1

            # Extract URL
            url, domain = self._extract_http_url(packet)
            if not url:
                url, domain = self._extract_https_sni(packet)
            if not url:
                url, domain = self._extract_dns(packet)

            if url and domain and domain not in self.domains_seen:
                self.domains_seen.add(domain)

                with self.lock:
                    self.total_urls += 1
                    self.recent_domains.append({
                        'domain': domain,
                        'url': url,
                        'src_ip': src_ip,
                        'time': datetime.now().strftime('%H:%M:%S')
                    })
                    # Keep last 50
                    self.recent_domains = self.recent_domains[-50:]

                # Save to DB
                self._save_url(url, domain, src_ip)

        except Exception as e:
            logger.debug(f"Packet error: {e}")

    # ============================================
    # SIMULATION MODE (Fallback)
    # ============================================

    def _run_simulation(self):
        """Simulated traffic when real capture is unavailable"""
        import random
        fake_ips = [
            '192.168.1.100', '10.0.0.50', '45.155.205.233',
            '185.220.101.34', '8.8.8.8', '1.1.1.1'
        ]
        fake_domains = [
            ('https://www.google.com/search', 'google.com'),
            ('https://github.com/trending', 'github.com'),
            ('https://www.youtube.com/watch', 'youtube.com'),
            ('https://stackoverflow.com/questions', 'stackoverflow.com'),
            ('https://www.wikipedia.org/wiki', 'wikipedia.org'),
            ('http://suspicious-login.xyz/verify', 'suspicious-login.xyz'),
            ('http://paypal-secure.ml/login', 'paypal-secure.ml'),
            ('http://free-crypto.work/claim', 'free-crypto.work'),
            ('https://www.netflix.com/browse', 'netflix.com'),
            ('https://www.linkedin.com/feed', 'linkedin.com'),
        ]

        logger.info("Running in SIMULATION mode")

        while not self.stop_event.is_set():
            url, domain = random.choice(fake_domains)
            src_ip = random.choice(fake_ips)

            with self.lock:
                self.total_packets += 1

            if domain not in self.domains_seen:
                self.domains_seen.add(domain)
                with self.lock:
                    self.total_urls += 1
                    self.recent_domains.append({
                        'domain': domain, 'url': url,
                        'src_ip': src_ip,
                        'time': datetime.now().strftime('%H:%M:%S')
                    })
                    self.recent_domains = self.recent_domains[-50:]

                self._save_url(url, domain, src_ip)

            time.sleep(random.uniform(1.5, 4.0))

    # ============================================
    # REAL CAPTURE
    # ============================================

    def _run_capture(self):
        """Run real packet capture"""
        logger.info("Starting REAL packet capture")
        try:
            sniff(
                prn=self._packet_handler,
                store=False,
                stop_filter=lambda x: self.stop_event.is_set(),
                filter="tcp port 80 or tcp port 443 or udp port 53"
            )
        except PermissionError:
            logger.warning("No admin privileges — falling back to simulation")
            with self.lock:
                self.use_simulation = True
            self._run_simulation()
        except Exception as e:
            logger.warning(f"Capture failed ({e}) — falling back to simulation")
            with self.lock:
                self.use_simulation = True
            self._run_simulation()

    # ============================================
    # PUBLIC API
    # ============================================

    def start(self, force_simulation=False):
        """Start monitoring in background thread"""
        if self.is_running:
            logger.info("Monitor already running")
            return False

        self.stop_event.clear()
        self.is_running = True
        self.total_packets = 0
        self.total_urls = 0
        self.total_alerts = 0
        self.domains_seen = set()
        self.recent_domains = []

        if force_simulation or not SCAPY_AVAILABLE:
            target = self._run_simulation
        else:
            target = self._run_capture

        self.thread = threading.Thread(target=target, daemon=True)
        self.thread.start()
        logger.info("Background live monitor started")
        return True

    def stop(self):
        """Stop monitoring"""
        if not self.is_running:
            return
        self.stop_event.set()
        self.is_running = False
        if self.thread:
            self.thread.join(timeout=3)
        logger.info("Background live monitor stopped")

    def get_stats(self):
        """Thread-safe stats snapshot"""
        with self.lock:
            return {
                'is_running': self.is_running,
                'mode': 'simulation' if self.use_simulation else 'live',
                'total_packets': self.total_packets,
                'total_urls': self.total_urls,
                'total_alerts': self.total_alerts,
                'unique_domains': len(self.domains_seen),
                'recent_domains': list(self.recent_domains[-20:])
            }


# Global singleton
_live_monitor_instance = None

def get_live_monitor():
    """Get or create the global live monitor instance"""
    global _live_monitor_instance
    if _live_monitor_instance is None:
        _live_monitor_instance = BackgroundLiveMonitor()
    return _live_monitor_instance