"""
Network Packet Capture Module
Captures and analyzes network traffic using Scapy
"""

import time
import threading
from datetime import datetime
from collections import defaultdict
from loguru import logger
from database.crud_operations import CRUDOperations

# Scapy import with fallback
try:
    from scapy.all import sniff, IP, TCP, UDP, DNS, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("Scapy not available. Packet capture will use simulation mode.")

class PacketCapture:
    """Network packet capture and analysis"""
    
    def __init__(self, interface=None):
        self.crud = CRUDOperations()
        self.interface = interface
        self.is_capturing = False
        self.capture_thread = None
        self.packet_buffer = []
        self.buffer_lock = threading.Lock()
        self.stats = defaultdict(int)
        self.ip_frequency = defaultdict(list)
        
    def packet_callback(self, packet):
        """Callback function for each captured packet"""
        try:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                protocol = 'OTHER'
                src_port = None
                dst_port = None
                payload_size = len(packet)
                
                # Determine protocol
                if TCP in packet:
                    protocol = 'HTTPS' if packet[TCP].dport == 443 else 'HTTP'
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                elif UDP in packet:
                    protocol = 'DNS' if packet[UDP].dport == 53 else 'OTHER'
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                
                packet_data = {
                    'timestamp': datetime.now(),
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'protocol': protocol,
                    'payload_size': payload_size
                }
                
                with self.buffer_lock:
                    self.packet_buffer.append(packet_data)
                    self.stats['total_packets'] += 1
                    
                    # Track IP frequency
                    self.ip_frequency[src_ip].append(time.time())
                    
        except Exception as e:
            logger.debug(f"Packet processing error: {e}")
    
    def start_capture(self, duration=60, packet_count=100):
        """Start packet capture"""
        if SCAPY_AVAILABLE:
            self._start_real_capture(duration, packet_count)
        else:
            self._start_simulated_capture(duration, packet_count)
    
    def _start_real_capture(self, duration, packet_count):
        """Start real packet capture using Scapy"""
        logger.info(f"Starting real packet capture on {self.interface or 'default'}...")
        self.is_capturing = True
        
        try:
            sniff(
                iface=self.interface,
                prn=self.packet_callback,
                store=False,
                timeout=duration,
                count=packet_count
            )
        except PermissionError:
            logger.error("Permission denied. Run with sudo/administrator privileges.")
        except Exception as e:
            logger.error(f"Capture error: {e}")
        finally:
            self.is_capturing = False
            self._process_buffer()
    
    def _start_simulated_capture(self, duration, packet_count):
        """Simulate packet capture for testing"""
        logger.info(f"Starting simulated packet capture for {duration}s...")
        self.is_capturing = True
        
        import random
        
        # Simulated IPs
        simulated_ips = [
            '192.168.1.100', '10.0.0.50', '172.16.0.25',
            '8.8.8.8', '1.1.1.1', '192.168.1.1',
            '185.220.101.34', '23.129.64.210', '45.155.205.233'
        ]
        
        protocols = ['HTTP', 'HTTPS', 'DNS']
        
        start_time = time.time()
        packet_count = 0
        
        while time.time() - start_time < duration and packet_count < 200:
            src_ip = random.choice(simulated_ips)
            dst_ip = random.choice(simulated_ips)
            if src_ip == dst_ip:
                continue
                
            packet_data = {
                'timestamp': datetime.now(),
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': random.randint(1024, 65535),
                'dst_port': random.choice([80, 443, 53, 8080]),
                'protocol': random.choice(protocols),
                'payload_size': random.randint(64, 1500)
            }
            
            with self.buffer_lock:
                self.packet_buffer.append(packet_data)
                self.stats['total_packets'] += 1
                self.ip_frequency[src_ip].append(time.time())
            
            packet_count += 1
            time.sleep(random.uniform(0.01, 0.1))
        
        self.is_capturing = False
        logger.info(f"Simulated {packet_count} packets")
        self._process_buffer()
    
    def _process_buffer(self):
        """Process buffered packets and save to database"""
        logger.info(f"Processing {len(self.packet_buffer)} captured packets...")
        
        # Analyze IP frequencies for anomaly detection
        current_time = time.time()
        window = 60  # 1 minute window
        
        for ip, timestamps in self.ip_frequency.items():
            # Count requests in last minute
            recent_requests = [t for t in timestamps if current_time - t < window]
            request_count = len(recent_requests)
            
            # Update IP in database
            try:
                self.crud.insert_ip_address(
                    ip_address=ip,
                    ip_version='IPv4',
                    country=None,
                    city=None
                )
            except:
                pass
            
            # Check for high frequency (potential attack)
            if request_count > 50:
                logger.warning(f"High traffic from {ip}: {request_count} requests/min")
        
        # Save traffic logs in batches
        batch_size = 50
        for i in range(0, len(self.packet_buffer), batch_size):
            batch = self.packet_buffer[i:i+batch_size]
            
            for packet in batch:
                try:
                    self.crud.insert_traffic_log(
                        src_ip=packet['src_ip'],
                        dst_ip=packet['dst_ip'],
                        src_port=packet.get('src_port'),
                        dst_port=packet.get('dst_port'),
                        protocol=packet.get('protocol', 'HTTP'),
                        payload_size=packet.get('payload_size')
                    )
                except Exception as e:
                    logger.debug(f"Failed to save traffic log: {e}")
        
        logger.info(f"Buffer processing complete. Stats: {dict(self.stats)}")
        
        # Clear buffer
        with self.buffer_lock:
            self.packet_buffer.clear()
    
    def get_traffic_stats(self):
        """Get current traffic statistics"""
        return {
            'total_packets': self.stats['total_packets'],
            'unique_ips': len(self.ip_frequency),
            'is_capturing': self.is_capturing
        }
    
    def run_capture_session(self, duration=60):
        """Run a complete capture session"""
        logger.info("=" * 50)
        logger.info("Starting Packet Capture Session")
        logger.info("=" * 50)
        
        self.start_capture(duration=duration, packet_count=500)
        
        logger.info(f"Capture complete. Stats: {dict(self.stats)}")
        return self.stats