"""
Alert Generation & Management System
"""

import json
import threading
from datetime import datetime
from loguru import logger
from database.crud_operations import CRUDOperations
from database.connection import db_manager

class AlertSystem:
    """Alert management system"""
    
    def __init__(self):
        self.crud = CRUDOperations()
        self.alert_callbacks = []
        self.alert_buffer = []
        self.buffer_lock = threading.Lock()
        self.alert_count = 0
        
        # Alert deduplication
        self.recent_alerts = {}  # key -> timestamp
        
    def create_alert(self, alert_type, severity, source_ip, 
                     destination_ip=None, url_id=None, description=None):
        """Create a new alert"""
        
        # Deduplication check (same IP + type within 60 seconds)
        dedup_key = f"{source_ip}:{alert_type}"
        now = datetime.now()
        
        if dedup_key in self.recent_alerts:
            last_time = self.recent_alerts[dedup_key]
            if (now - last_time).total_seconds() < 60:
                return None  # Skip duplicate
        
        self.recent_alerts[dedup_key] = now
        
        # Clean old dedup entries
        self.recent_alerts = {
            k: v for k, v in self.recent_alerts.items()
            if (now - v).total_seconds() < 300
        }
        
        try:
            alert_id = self.crud.insert_alert(
                alert_type=alert_type,
                severity=severity,
                source_ip=source_ip,
                destination_ip=destination_ip,
                url_id=url_id,
                description=description
            )
            
            self.alert_count += 1
            
            alert = {
                'alert_id': alert_id,
                'timestamp': now.isoformat(),
                'alert_type': alert_type,
                'severity': severity,
                'source_ip': source_ip,
                'destination_ip': destination_ip,
                'url_id': url_id,
                'description': description,
                'status': 'new'
            }
            
            # Notify callbacks
            for callback in self.alert_callbacks:
                try:
                    callback(alert)
                except Exception as e:
                    logger.debug(f"Callback error: {e}")
            
            logger.info(f"🚨 ALERT [{severity}] {alert_type}: {description}")
            
            return alert_id
            
        except Exception as e:
            logger.error(f"Failed to create alert: {e}")
            return None
    
    def register_callback(self, callback):
        """Register a callback for new alerts"""
        self.alert_callbacks.append(callback)
    
    def get_active_alerts(self, limit=50):
        """Get active (unresolved) alerts"""
        query = """
        SELECT * FROM alerts 
        WHERE status IN ('new', 'acknowledged', 'investigating')
        ORDER BY 
            FIELD(severity, 'critical', 'high', 'medium', 'low'),
            timestamp DESC
        LIMIT %s
        """
        return db_manager.execute_query(query, (limit,))
    
    def get_alerts_by_severity(self, severity, limit=50):
        """Get alerts by severity level"""
        query = """
        SELECT * FROM alerts 
        WHERE severity = %s AND status != 'resolved'
        ORDER BY timestamp DESC
        LIMIT %s
        """
        return db_manager.execute_query(query, (severity, limit))
    
    def update_alert_status(self, alert_id, status, resolved_by=None, notes=None):
        """Update alert status"""
        return self.crud.update_alert_status(
            alert_id=alert_id,
            status=status,
            resolved_by=resolved_by,
            resolution_notes=notes
        )
    
    def get_alert_stats(self):
        """Get alert statistics"""
        query = """
        SELECT 
            severity,
            status,
            COUNT(*) as count,
            DATE(timestamp) as date
        FROM alerts 
        WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)
        GROUP BY severity, status, DATE(timestamp)
        ORDER BY date DESC, severity
        """
        return db_manager.execute_query(query)
    
    def get_today_summary(self):
        """Get today's alert summary"""
        query = """
        SELECT 
            COUNT(*) as total_alerts,
            SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
            SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high,
            SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium,
            SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low,
            SUM(CASE WHEN status = 'new' THEN 1 ELSE 0 END) as new_alerts,
            SUM(CASE WHEN status = 'resolved' THEN 1 ELSE 0 END) as resolved
        FROM alerts 
        WHERE DATE(timestamp) = CURDATE()
        """
        result = db_manager.execute_query(query)
        return result[0] if result else {}
    
    def get_alert_trends(self, days=7):
        """Get alert trends over time"""
        query = """
        SELECT 
            DATE(timestamp) as date,
            severity,
            COUNT(*) as count
        FROM alerts
        WHERE timestamp >= DATE_SUB(NOW(), INTERVAL %s DAY)
        GROUP BY DATE(timestamp), severity
        ORDER BY date DESC
        """
        return db_manager.execute_query(query, (days,))
    
    def resolve_all_for_ip(self, ip_address, notes="Bulk resolved"):
        """Resolve all alerts for an IP"""
        query = """
        UPDATE alerts 
        SET status = 'resolved', 
            resolved_at = NOW(), 
            resolution_notes = %s
        WHERE source_ip = %s AND status != 'resolved'
        """
        db_manager.execute_query(query, (notes, ip_address), fetch=False)