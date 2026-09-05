#!/usr/bin/env python3
"""Quick traffic monitor - Working with available methods"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time
import random
from datetime import datetime, timedelta
from src.real_time_monitor.traffic_monitor import TrafficMonitor
from src.real_time_monitor.alert_system import AlertSystem
from database.crud_operations import CRUDOperations

alert = AlertSystem()
crud = CRUDOperations()
monitor = TrafficMonitor()
monitor.set_alert_system(alert)

print("\n📡 Simulating network traffic for 30 seconds...")
print("   Press Ctrl+C to stop\n")

# Simulated data
ips = ['45.155.205.233', '185.220.101.34', '8.8.8.8', '1.1.1.1', '192.168.1.100', '10.0.0.50']
urls = [
    ('https://www.google.com/search?q=python', 'google.com'),
    ('https://github.com/torvalds/linux', 'github.com'),
    ('http://suspicious-login.xyz/verify.php', 'suspicious-login.xyz'),
    ('https://www.youtube.com/watch?v=dQw4w9WgXcQ', 'youtube.com'),
    ('http://paypal-secure.ml/login', 'paypal-secure.ml'),
    ('https://stackoverflow.com/questions', 'stackoverflow.com'),
    ('https://www.wikipedia.org', 'wikipedia.org'),
    ('http://free-crypto.work/claim', 'free-crypto.work'),
    ('http://banking-update.ga/secure/login.php', 'banking-update.ga'),
    ('https://www.netflix.com/browse', 'netflix.com'),
]

packet_count = 0
alert_count = 0
end_time = datetime.now() + timedelta(seconds=30)

try:
    while datetime.now() < end_time:
        src_ip = random.choice(ips)
        dst_ip = random.choice(ips)
        if src_ip == dst_ip:
            continue
        
        url, domain = random.choice(urls)
        
        # Save URL to database
        try:
            crud.insert_url(
                full_url=url, domain=domain,
                path='/' + '/'.join(url.split('/')[3:]) if len(url.split('/')) > 3 else '/',
                protocol='https' if 'https' in url else 'http',
                tld=domain.split('.')[-1] if '.' in domain else 'com',
                url_length=len(url),
                source='traffic_capture'
            )
        except:
            pass
        
        # Create alert for suspicious URLs
        suspicious_tlds = ['.xyz', '.ml', '.ga', '.cf', '.tk', '.work']
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            alert.create_alert(
                alert_type='suspicious_url',
                severity='high',
                source_ip=src_ip,
                description=f'Suspicious URL detected: {url[:100]}'
            )
            alert_count += 1
            print(f"  🚨 ALERT: {domain}")
        
        packet_count += 1
        if packet_count % 10 == 0:
            print(f"  📊 Packets: {packet_count} | Alerts: {alert_count}")
        
        time.sleep(random.uniform(0.2, 0.8))

except KeyboardInterrupt:
    print("\n⏹️ Stopped by user")

print(f"\n✅ Session complete!")
print(f"   Total packets: {packet_count}")
print(f"   Total alerts:  {alert_count}")
print(f"   URLs saved:    {packet_count}")