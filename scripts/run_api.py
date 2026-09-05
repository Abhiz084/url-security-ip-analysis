#!/usr/bin/env python3
"""
Start the FastAPI server
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import uvicorn
from loguru import logger
from config.settings import settings

from src.api.routes import app, init_services
from src.real_time_monitor.traffic_monitor import TrafficMonitor
from src.real_time_monitor.alert_system import AlertSystem
from src.real_time_monitor.ip_reputation import IPReputationChecker
from src.ml_pipeline.prediction import URLPredictor, find_latest_model

def main():
    logger.info("Initializing API services...")
    
    # Initialize all services
    alert_system = AlertSystem()
    reputation_checker = IPReputationChecker()
    monitor = TrafficMonitor()
    monitor.set_alert_system(alert_system)
    
    model_path = find_latest_model('random_forest')
    predictor = URLPredictor(model_path) if model_path else URLPredictor()
    
    # Initialize API
    init_services(predictor, monitor, alert_system, reputation_checker)
    
    port = settings.API_PORT if settings.API_PORT != 8000 else 8001
    
    logger.info(f"Starting API server on port {port}...")
    uvicorn.run(
        app,
        host=settings.API_HOST,
        port=port,
        log_level="info"
    )

if __name__ == "__main__":
    main()