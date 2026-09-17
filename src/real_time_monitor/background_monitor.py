"""
Background Live Monitor
Runs packet capture in a thread so it can be started/stopped from the dashboard.
"""

import threading
import time
import random
import re
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
    """Thread-based live traffic monitor controllable from the dashboard"""

    def __init__(self):
        self.crud = CRUDOperations()
        self.thread = None
        self.stop_event = threading.Event()
        self.is_running = False
        self.use_simulation = False
        self.lock = threading.Lock()

        # ---------------- Counters ----------------
        self.total_packets = 0
        self.total_urls = 0
        self.total_alerts = 0

        # ---------------- Tracking buffers ----------------
        self.domains_seen = set()
        self.recent_domains = []       # last 50 URLs (dicts)
        self.recent_packets = []       # last 100 packets
        self.recent_threats = []       # last 50 threats

        # Max sizes
        self.MAX_PACKETS_BUFFER = 100
        self.MAX_URLS_BUFFER = 50
        self.MAX_THREATS_BUFFER = 50

        # ---------------- Pattern detection ----------------
        self.suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top',
            '.work', '.click', '.icu', '.cfd',
        ]
        self.suspicious_keywords = [
            'login', 'verify', 'paypal', 'banking', 'password',
            'account', 'confirm', 'secure', 'signin',
        ]

    # ============================================
    # PACKET PARSING (unchanged logic)
    # ============================================

    def _extract_http_url(self, packet):
        try:
            if packet.haslayer(HTTPRequest):
                http_layer = packet[HTTPRequest]
                host = http_layer.Host.decode() if http_layer.Host else ''
                path = http_layer.Path.decode() if http_layer.Path else '/'
                if host:
                    return f"http://{host}{path}", host
        except Exception:
            pass
        return None, None

    def _extract_https_sni(self, packet):
        try:
            if packet.haslayer(TCP) and packet.haslayer(Raw):
                raw = bytes(packet[Raw].load)
                if len(raw) > 5 and raw[0] == 0x16 and raw[1] == 0x03:
                    for i in range(len(raw) - 50):
                        if raw[i:i + 2] == b'\x00\x00':
                            try:
                                length = int.from_bytes(raw[i + 2:i + 4], 'big')
                                sni_data = raw[i + 4:i + 4 + length]
                                if len(sni_data) > 3:
                                    name_len = sni_data[2]
                                    name = sni_data[3:3 + name_len].decode(
                                        'utf-8', errors='ignore'
                                    )
                                    if '.' in name and 3 < len(name) < 100:
                                        if all(32 <= ord(c) < 127 for c in name):
                                            return f"https://{name}/", name
                            except Exception:
                                pass
        except Exception:
            pass
        return None, None

    def _extract_dns(self, packet):
        try:
            if packet.haslayer(DNS) and packet[DNS].qr == 0:
                for query in packet[DNS].qd:
                    domain = query.qname.decode('utf-8', errors='ignore').rstrip('.')
                    if '.' in domain and len(domain) > 3:
                        return f"dns://{domain}", domain
        except Exception:
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

    # ============================================
    # SAVE + TRACK
    # ============================================

    def _save_url(self, url, domain, src_ip, protocol='HTTP'):
        """Save URL to DB and track it in memory"""
        tld = domain.split('.')[-1] if '.' in domain else ''
        if len(tld) > 20:
            tld = tld[:20]

        # DB write
        try:
            self.crud.insert_url(
                full_url=url, domain=domain, path='/',
                protocol='https' if 'https' in url else 'http',
                tld=tld, url_length=len(url),
                source='live_traffic'
            )
        except Exception as e:
            logger.debug(f"DB insert skipped: {e}")

        # Memory tracking
        record = {
            'url': url,
            'domain': domain,
            'src_ip': src_ip,
            'protocol': protocol,
            'time': datetime.now().strftime('%H:%M:%S'),
        }
        with self.lock:
            self.recent_domains.append(record)
            self.recent_domains = self.recent_domains[-self.MAX_URLS_BUFFER:]

        # Threat check
        is_threat, reason = self._check_threat(url, domain)
        if is_threat:
            with self.lock:
                self.total_alerts += 1
                self.recent_threats.append({
                    'url': url,
                    'domain': domain,
                    'src_ip': src_ip,
                    'reason': reason,
                    'severity': 'high',
                    'time': datetime.now().strftime('%H:%M:%S'),
                })
                self.recent_threats = self.recent_threats[-self.MAX_THREATS_BUFFER:]

            # Persist alert to DB
            try:
                from src.real_time_monitor.alert_system import AlertSystem
                AlertSystem().create_alert(
                    alert_type='suspicious_url',
                    severity='high',
                    source_ip=src_ip,
                    description=f'Live: {domain} ({reason})'
                )
            except Exception:
                pass

    # ============================================
    # PACKET HANDLER
    # ============================================

    def _packet_handler(self, packet):
        try:
            if not IP in packet:
                return
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            protocol = 'OTHER'
            src_port = dst_port = 0
            payload_size = len(packet)

            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                if dst_port in (80, 8080):
                    protocol = 'HTTP'
                elif dst_port == 443:
                    protocol = 'HTTPS'
                else:
                    protocol = 'TCP'
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                protocol = 'DNS' if dst_port == 53 else 'UDP'

            with self.lock:
                self.total_packets += 1
                self.recent_packets.append({
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'protocol': protocol,
                    'size': payload_size,
                    'time': datetime.now().strftime('%H:%M:%S'),
                })
                self.recent_packets = self.recent_packets[-self.MAX_PACKETS_BUFFER:]

            # URL extraction
            url, domain = self._extract_http_url(packet)
            if not url:
                url, domain = self._extract_https_sni(packet)
            if not url:
                url, domain = self._extract_dns(packet)

            if url and domain and domain not in self.domains_seen:
                self.domains_seen.add(domain)
                with self.lock:
                    self.total_urls += 1
                self._save_url(url, domain, src_ip, protocol)

        except Exception as e:
            logger.debug(f"Packet error: {e}")

    # ============================================
    # SIMULATION MODE
    # ============================================

    def _run_simulation(self):
        fake_ips = [
            '192.168.1.100', '10.0.0.50', '45.155.205.233',
            '185.220.101.34', '8.8.8.8', '1.1.1.1',
        ]
        fake_domains = [
            ('https://www.google.com/search', 'google.com', 'HTTPS'),
            ('https://github.com/trending', 'github.com', 'HTTPS'),
            ('https://www.youtube.com/watch', 'youtube.com', 'HTTPS'),
            ('https://stackoverflow.com/questions', 'stackoverflow.com', 'HTTPS'),
            ('https://www.wikipedia.org/wiki', 'wikipedia.org', 'HTTPS'),
            ('http://suspicious-login.xyz/verify', 'suspicious-login.xyz', 'HTTP'),
            ('http://paypal-secure.ml/login', 'paypal-secure.ml', 'HTTP'),
            ('http://free-crypto.work/claim', 'free-crypto.work', 'HTTP'),
            ('https://www.netflix.com/browse', 'netflix.com', 'HTTPS'),
            ('https://www.linkedin.com/feed', 'linkedin.com', 'HTTPS'),
        ]

        while not self.stop_event.is_set():
            url, domain, proto = random.choice(fake_domains)
            src_ip = random.choice(fake_ips)
            dst_ip = random.choice(fake_ips)

            with self.lock:
                self.total_packets += 1
                self.recent_packets.append({
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': random.randint(1024, 65535),
                    'dst_port': 443 if proto == 'HTTPS' else 80,
                    'protocol': proto,
                    'size': random.randint(64, 1500),
                    'time': datetime.now().strftime('%H:%M:%S'),
                })
                self.recent_packets = self.recent_packets[-self.MAX_PACKETS_BUFFER:]

            if domain not in self.domains_seen:
                self.domains_seen.add(domain)
                with self.lock:
                    self.total_urls += 1
                self._save_url(url, domain, src_ip, proto)

            time.sleep(random.uniform(1.5, 4.0))

    # ============================================
    # REAL CAPTURE
    # ============================================

    def _run_capture(self):
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
        if self.is_running:
            return False

        # Reset counters for a fresh session
        self._reset_counters()
        self.stop_event.clear()
        self.is_running = True

        if force_simulation or not SCAPY_AVAILABLE:
            target = self._run_simulation
        else:
            target = self._run_capture

        self.thread = threading.Thread(target=target, daemon=True)
        self.thread.start()
        logger.info("Background live monitor started")
        return True

    def stop(self):
        if not self.is_running:
            return
        self.stop_event.set()
        self.is_running = False
        if self.thread:
            self.thread.join(timeout=3)
        logger.info("Background live monitor stopped")

    def reset_stats(self):
        """
        Clear all in-memory stats.

        IMPORTANT: Does NOT touch the MySQL database. URLs and alerts
        already persisted stay in the DB; this only clears the
        dashboard's live session counters.
        """
        self.stop()
        self._reset_counters()
        logger.info("In-memory live stats cleared (DB untouched)")

    def _reset_counters(self):
        with self.lock:
            self.total_packets = 0
            self.total_urls = 0
            self.total_alerts = 0
            self.domains_seen = set()
            self.recent_domains = []
            self.recent_packets = []
            self.recent_threats = []
            self.use_simulation = False

    def get_stats(self):
        """Thread-safe snapshot for the dashboard"""
        with self.lock:
            return {
                'is_running': self.is_running,
                'mode': 'simulation' if self.use_simulation else 'live',
                'total_packets': self.total_packets,
                'total_urls': self.total_urls,
                'total_alerts': self.total_alerts,
                'unique_domains': len(self.domains_seen),
                'recent_domains': list(self.recent_domains),
                'recent_packets': list(self.recent_packets),
                'recent_threats': list(self.recent_threats),
                'all_domains': sorted(self.domains_seen),
            }


# ============================================
# GLOBAL SINGLETON
# ============================================

_live_monitor_instance = None


def get_live_monitor():
    global _live_monitor_instance
    if _live_monitor_instance is None:
        _live_monitor_instance = BackgroundLiveMonitor()
    return _live_monitor_instance