"""
FastAPI Routes for URL Security System
"""

from fastapi import FastAPI, HTTPException, Query, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
from typing import Optional, List
from datetime import datetime
from loguru import logger

app = FastAPI(
    title="URL Security API",
    description="IP-Based URL Threat Analysis System",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global services (initialized later)
predictor = None
monitor = None
alert_system = None
reputation_checker = None

# ============================================
# Request/Response Models
# ============================================

class URLScanRequest(BaseModel):
    url: str
    save_result: bool = True

class URLScanResponse(BaseModel):
    url: str
    prediction: str
    confidence: float
    risk_level: str
    timestamp: str

class BatchScanRequest(BaseModel):
    urls: List[str]
    save_results: bool = False

class BatchScanResponse(BaseModel):
    results: List[URLScanResponse]
    total: int
    malicious_count: int
    benign_count: int

class AlertUpdateRequest(BaseModel):
    status: str
    resolved_by: Optional[str] = None
    resolution_notes: Optional[str] = None

class IPCheckRequest(BaseModel):
    ip_address: str

class IPCheckResponse(BaseModel):
    ip_address: str
    threat_score: float
    risk_level: str
    country: Optional[str] = None
    isp: Optional[str] = None
    alert_count: int
    is_malicious: bool

# ============================================
# API Endpoints
# ============================================

@app.get("/")
async def root():
    return {
        "name": "URL Security API",
        "version": "1.0.0",
        "status": "running",
        "timestamp": datetime.now().isoformat()
    }

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "services": {
            "predictor": predictor is not None,
            "monitor": monitor.is_running if monitor else False,
            "alert_system": alert_system is not None,
            "reputation_checker": reputation_checker is not None
        }
    }

# ============================================
# URL Scanning Endpoints
# ============================================

@app.post("/scan", response_model=URLScanResponse)
async def scan_url(request: URLScanRequest):
    """Scan a single URL for threats"""
    if predictor is None:
        raise HTTPException(status_code=503, detail="Prediction service not available")
    
    try:
        result = predictor.predict_url(request.url, save_to_db=request.save_result)
        
        if result.get('error'):
            raise HTTPException(status_code=500, detail=result['error'])
        
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/scan")
async def scan_url_get(
    url: str = Query(..., description="URL to scan"),
    save: bool = Query(False, description="Save result to database")
):
    """Scan a URL via GET request"""
    if predictor is None:
        raise HTTPException(status_code=503, detail="Prediction service not available")
    
    result = predictor.predict_url(url, save_to_db=save)
    return result

@app.post("/scan/batch", response_model=BatchScanResponse)
async def scan_batch(request: BatchScanRequest):
    """Scan multiple URLs"""
    if predictor is None:
        raise HTTPException(status_code=503, detail="Prediction service not available")
    
    results = predictor.predict_batch(request.urls)
    
    malicious = sum(1 for r in results if r['prediction'] == 'malicious')
    benign = sum(1 for r in results if r['prediction'] == 'benign')
    
    return BatchScanResponse(
        results=results,
        total=len(results),
        malicious_count=malicious,
        benign_count=benign
    )

# ============================================
# Alert Endpoints
# ============================================

@app.get("/alerts")
async def get_alerts(
    severity: Optional[str] = Query(None, description="Filter by severity"),
    status: Optional[str] = Query(None, description="Filter by status"),
    limit: int = Query(50, ge=1, le=500)
):
    """Get alerts with optional filters"""
    if alert_system is None:
        raise HTTPException(status_code=503, detail="Alert service not available")
    
    if severity:
        alerts = alert_system.get_alerts_by_severity(severity, limit)
    else:
        alerts = alert_system.get_active_alerts(limit)
    
    return {"alerts": alerts, "total": len(alerts)}

@app.put("/alerts/{alert_id}")
async def update_alert(alert_id: int, request: AlertUpdateRequest):
    """Update alert status"""
    if alert_system is None:
        raise HTTPException(status_code=503, detail="Alert service not available")
    
    alert_system.update_alert_status(
        alert_id=alert_id,
        status=request.status,
        resolved_by=request.resolved_by,
        notes=request.resolution_notes
    )
    
    return {"alert_id": alert_id, "status": request.status, "message": "Updated successfully"}

@app.get("/alerts/stats")
async def get_alert_stats():
    """Get alert statistics"""
    if alert_system is None:
        raise HTTPException(status_code=503, detail="Alert service not available")
    
    today = alert_system.get_today_summary()
    trends = alert_system.get_alert_trends(7)
    
    return {
        "today_summary": today,
        "trends": trends
    }

# ============================================
# IP Intelligence Endpoints
# ============================================

@app.get("/ip/{ip_address}")
async def check_ip(ip_address: str):
    """Check IP reputation"""
    if reputation_checker is None:
        raise HTTPException(status_code=503, detail="IP reputation service not available")
    
    try:
        result = reputation_checker.get_threat_summary(ip_address)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/ip/check", response_model=IPCheckResponse)
async def check_ip_post(request: IPCheckRequest):
    """Check IP reputation via POST"""
    if reputation_checker is None:
        raise HTTPException(status_code=503, detail="IP reputation service not available")
    
    result = reputation_checker.get_threat_summary(request.ip_address)
    return result

# ============================================
# Monitoring Endpoints
# ============================================

@app.get("/monitor/status")
async def get_monitor_status():
    """Get traffic monitor status"""
    if monitor is None:
        raise HTTPException(status_code=503, detail="Monitor service not available")
    
    return monitor.get_stats()

@app.post("/monitor/start")
async def start_monitor(duration: int = Query(60, description="Duration in seconds")):
    """Start traffic monitoring"""
    if monitor is None:
        raise HTTPException(status_code=503, detail="Monitor service not available")
    
    if monitor.is_running:
        return {"message": "Monitor already running"}
    
    import threading
    thread = threading.Thread(target=monitor.start_monitoring, args=(duration,), daemon=True)
    thread.start()
    
    return {"message": f"Monitor started for {duration} seconds"}

@app.post("/monitor/stop")
async def stop_monitor():
    """Stop traffic monitoring"""
    if monitor is None:
        raise HTTPException(status_code=503, detail="Monitor service not available")
    
    monitor.stop_monitoring()
    return {"message": "Monitor stopped"}

# ============================================
# Dashboard Stats Endpoint
# ============================================

@app.get("/dashboard/summary")
async def get_dashboard_summary():
    """Get comprehensive dashboard summary"""
    from database.queries import QueryBuilder
    qb = QueryBuilder()
    
    summary = qb.get_dashboard_summary()
    top_threats = qb.get_top_threat_ips(5)
    top_domains = qb.get_top_malicious_domains(5)
    traffic_heatmap = qb.get_traffic_heatmap(24)
    
    return {
        "summary": summary,
        "top_threat_ips": top_threats,
        "top_malicious_domains": top_domains,
        "traffic_heatmap": traffic_heatmap,
        "timestamp": datetime.now().isoformat()
    }


# ============================================
# Initialization
# ============================================

def init_services(pred=None, mon=None, alert=None, rep=None):
    """Initialize API services"""
    global predictor, monitor, alert_system, reputation_checker
    predictor = pred
    monitor = mon
    alert_system = alert
    reputation_checker = rep
    logger.info("API services initialized")