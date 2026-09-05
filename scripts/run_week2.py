#!/usr/bin/env python3
"""
Week 2 Runner - Data Collection & Feature Engineering
"""

import sys
import os

# Add project root to path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from loguru import logger
from src.data_collector.url_scraper import URLScraper
from src.data_collector.threat_feeds import ThreatFeedCollector
from src.data_collector.packet_capture import PacketCapture
from src.feature_engineering.feature_pipeline import FeaturePipeline

logger.add("logs/week2.log", rotation="1 MB", level="INFO")

def main():
    logger.info("=" * 60)
    logger.info("WEEK 2: Data Collection & Feature Engineering")
    logger.info("=" * 60)
    
    # Step 1: Collect URLs
    logger.info("\n📥 STEP 1: URL Collection")
    scraper = URLScraper()
    urls_collected = scraper.run_collection_pipeline()
    
    # Step 2: Collect Threat Intelligence
    logger.info("\n🛡️ STEP 2: Threat Intelligence Collection")
    threat_collector = ThreatFeedCollector()
    threat_collector.run_threat_intel_pipeline()
    
    # Step 3: Capture Network Traffic
    logger.info("\n📡 STEP 3: Network Traffic Capture")
    capture = PacketCapture()
    capture.run_capture_session(duration=30)
    
    # Step 4: Extract Features
    logger.info("\n🔬 STEP 4: Feature Extraction")
    pipeline = FeaturePipeline()
    pipeline.run_pipeline(limit=50)
    
    logger.info("\n" + "=" * 60)
    logger.info("✅ Week 2 Pipeline Complete!")
    logger.info("=" * 60)

if __name__ == "__main__":
    main()