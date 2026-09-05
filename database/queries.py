from database.connection import db_manager
from loguru import logger

class QueryBuilder:
    """Complex SQL queries for analytics and reporting"""
    
    @staticmethod
    def get_dashboard_summary():
        """Get dashboard summary statistics"""
        query = """
        SELECT 
            (SELECT COUNT(*) FROM urls WHERE is_malicious = TRUE) as total_malicious_urls,
            (SELECT COUNT(*) FROM urls) as total_urls_scanned,
            (SELECT COUNT(*) FROM ip_addresses WHERE threat_score > 50) as high_threat_ips,
            (SELECT COUNT(*) FROM ip_addresses) as total_ips_tracked,
            (SELECT COUNT(*) FROM alerts WHERE status IN ('new', 'investigating')) as active_alerts,
            (SELECT COUNT(*) FROM alerts WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)) as alerts_last_24h,
            (SELECT COUNT(*) FROM traffic_logs WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)) as traffic_last_24h,
            (SELECT AVG(prediction_score) FROM model_predictions WHERE predicted_class = 'malicious' AND prediction_timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)) as avg_threat_score_7d,
            (SELECT COUNT(DISTINCT src_ip) FROM traffic_logs WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)) as unique_visitors_24h
        """
        result = db_manager.execute_query(query)
        return result[0] if result else None
    
    @staticmethod
    def get_threat_trends(days=7):
        """Get threat trends over time"""
        query = """
        SELECT 
            DATE(timestamp) as date,
            alert_type,
            severity,
            COUNT(*) as alert_count
        FROM alerts
        WHERE timestamp >= DATE_SUB(NOW(), INTERVAL %s DAY)
        GROUP BY DATE(timestamp), alert_type, severity
        ORDER BY date DESC, alert_count DESC
        """
        return db_manager.execute_query(query, (days,))
    
    @staticmethod
    def get_top_malicious_domains(limit=10):
        """Get top malicious domains"""
        query = """
        SELECT 
            domain,
            COUNT(*) as occurrence_count,
            AVG(mp.prediction_score) as avg_threat_score
        FROM urls u
        JOIN model_predictions mp ON u.url_id = mp.url_id
        WHERE u.is_malicious = TRUE OR mp.predicted_class = 'malicious'
        GROUP BY domain
        ORDER BY occurrence_count DESC
        LIMIT %s
        """
        return db_manager.execute_query(query, (limit,))
    
    @staticmethod
    def get_top_threat_ips(limit=10):
        """Get top threat IPs"""
        query = """
        SELECT 
            ip.ip_address,
            ip.country,
            ip.threat_score,
            COUNT(DISTINCT ti.threat_id) as threat_count,
            GROUP_CONCAT(DISTINCT ti.threat_type) as threat_types
        FROM ip_addresses ip
        LEFT JOIN threat_intelligence ti ON ip.ip_address = ti.ip_address AND ti.is_active = TRUE
        WHERE ip.threat_score > 0
        GROUP BY ip.ip_id
        ORDER BY ip.threat_score DESC
        LIMIT %s
        """
        return db_manager.execute_query(query, (limit,))
    
    @staticmethod
    def get_traffic_heatmap(hours=24):
        """Get traffic heatmap data"""
        query = """
        SELECT 
            HOUR(timestamp) as hour,
            COUNT(*) as request_count,
            COUNT(DISTINCT src_ip) as unique_ips,
            SUM(CASE WHEN protocol = 'HTTPS' THEN 1 ELSE 0 END) as https_count,
            SUM(CASE WHEN protocol = 'HTTP' THEN 1 ELSE 0 END) as http_count
        FROM traffic_logs
        WHERE timestamp >= DATE_SUB(NOW(), INTERVAL %s HOUR)
        GROUP BY HOUR(timestamp)
        ORDER BY hour
        """
        return db_manager.execute_query(query, (hours,))
    
    @staticmethod
    def get_alert_resolution_stats():
        """Get alert resolution statistics"""
        query = """
        SELECT 
            status,
            severity,
            COUNT(*) as count,
            AVG(TIMESTAMPDIFF(MINUTE, timestamp, resolved_at)) as avg_resolution_minutes
        FROM alerts
        WHERE resolved_at IS NOT NULL
        GROUP BY status, severity
        """
        return db_manager.execute_query(query)
    
    @staticmethod
    def get_geolocation_threat_distribution():
        """Get threat distribution by geolocation"""
        query = """
        SELECT 
            ip.country,
            ip.city,
            COUNT(DISTINCT a.alert_id) as alert_count,
            AVG(ip.threat_score) as avg_threat_score,
            GROUP_CONCAT(DISTINCT a.alert_type) as alert_types
        FROM ip_addresses ip
        JOIN alerts a ON ip.ip_address = a.source_ip
        WHERE a.timestamp >= DATE_SUB(NOW(), INTERVAL 30 DAY)
        GROUP BY ip.country, ip.city
        ORDER BY alert_count DESC
        LIMIT 20
        """
        return db_manager.execute_query(query)
    
    @staticmethod
    def get_model_performance_stats():
        """Get model performance statistics"""
        query = """
        SELECT 
            model_name,
            model_version,
            predicted_class,
            COUNT(*) as prediction_count,
            AVG(prediction_score) as avg_confidence,
            MIN(prediction_score) as min_confidence,
            MAX(prediction_score) as max_confidence
        FROM model_predictions
        WHERE prediction_timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)
        GROUP BY model_name, model_version, predicted_class
        ORDER BY model_name, prediction_count DESC
        """
        return db_manager.execute_query(query)
    
    @staticmethod
    def search_urls(search_term, limit=50):
        """Search URLs by term"""
        query = """
        SELECT u.*, mp.prediction_score, mp.predicted_class
        FROM urls u
        LEFT JOIN model_predictions mp ON u.url_id = mp.url_id
        WHERE u.full_url LIKE %s OR u.domain LIKE %s
        ORDER BY u.submission_date DESC
        LIMIT %s
        """
        search_pattern = f"%{search_term}%"
        return db_manager.execute_query(query, (search_pattern, search_pattern, limit))