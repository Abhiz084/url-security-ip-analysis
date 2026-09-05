#!/usr/bin/env python3
"""
Start the real-time monitoring system
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time
import threading
from loguru import logger

from src.real_time_monitor.traffic_monitor import TrafficMonitor
from src.real_time_monitor.alert_system import AlertSystem
from src.real_time_monitor.ip_reputation import IPReputationChecker
from src.ml_pipeline.prediction import URLPredictor, find_latest_model

logger.add("logs/monitor.log", rotation="10 MB", level="INFO")

def main():
    logger.info("=" * 60)
    logger.info("🚀 Starting Real-Time Monitoring System")
    logger.info("=" * 60)
    
    # Initialize services
    logger.info("Initializing services...")
    
    # Alert system
    alert_system = AlertSystem()
    logger.info("✅ Alert System ready")
    
    # IP Reputation checker
    reputation_checker = IPReputationChecker()
    logger.info("✅ IP Reputation Checker ready")
    
    # URL Predictor
    model_path = find_latest_model('random_forest')
    predictor = URLPredictor(model_path) if model_path else URLPredictor()
    logger.info(f"✅ URL Predictor ready ({predictor.model_name})")
    
    # Traffic Monitor
    monitor = TrafficMonitor()
    monitor.set_alert_system(alert_system)
    logger.info("✅ Traffic Monitor ready")
    
    # Alert callback
    def on_alert(alert):
        if alert.get('source_ip'):
            rep = reputation_checker.check_ip(alert['source_ip'])
            if rep.get('is_malicious'):
                logger.warning(f"⚠️ Malicious IP: {alert['source_ip']} (score: {rep['threat_score']})")
    
    alert_system.register_callback(on_alert)
    
    # Start monitoring in a thread
    logger.info("\n" + "=" * 60)
    logger.info("📡 Starting traffic monitoring for 120 seconds...")
    logger.info("   Browse some websites to capture real traffic!")
    logger.info("=" * 60)
    
    def run_monitor():
        monitor.start_monitoring(duration=120)
    
    monitor_thread = threading.Thread(target=run_monitor, daemon=True)
    monitor_thread.start()
    
    try:
        # Display stats while running
        while monitor_thread.is_alive():
            stats = monitor.get_stats()
            logger.info(f"📊 Packets: {stats['total_packets']} | "
                       f"Alerts: {stats['total_alerts']} | "
                       f"IPs: {stats['unique_ips']}")
            time.sleep(10)
            
    except KeyboardInterrupt:
        logger.info("\n⏹️ Shutting down...")
        monitor.stop_monitoring()
    
    logger.info("\n" + "=" * 60)
    logger.info("✅ Monitoring session complete!")
    logger.info("=" * 60)
    
    # Final stats
    stats = monitor.get_stats()
    logger.info(f"📊 Final Stats:")
    logger.info(f"   Total packets: {stats['total_packets']}")
    logger.info(f"   Total alerts: {stats['total_alerts']}")
    logger.info(f"   Unique IPs: {stats['unique_ips']}")
    logger.info(f"   Duration: {stats['elapsed_seconds']:.0f}s")

if __name__ == "__main__":
    main()