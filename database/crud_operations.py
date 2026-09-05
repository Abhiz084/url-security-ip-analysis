"""
CRUD Operations for all database tables (MySQL 8.0+ compatible)
"""

from database.connection import db_manager
from loguru import logger
from datetime import datetime
import json

class CRUDOperations:
    """CRUD Operations for all database tables"""
    
    # ============================================
    # URLS TABLE OPERATIONS
    # ============================================
    
    @staticmethod
    def insert_url(full_url, domain, path=None, protocol=None, tld=None, 
                   url_length=None, source=None, is_malicious=None):
        """Insert a new URL record"""
        query = """
        INSERT INTO urls (full_url, domain, path, protocol, tld, url_length, source, is_malicious)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        AS new_row
        ON DUPLICATE KEY UPDATE 
            submission_date = CURRENT_TIMESTAMP,
            source = new_row.source,
            is_malicious = COALESCE(new_row.is_malicious, urls.is_malicious)
        """
        params = (full_url, domain, path, protocol, tld, url_length, source, is_malicious)
        return db_manager.execute_query(query, params, fetch=False)
    
    @staticmethod
    def get_url_by_id(url_id):
        """Get URL by ID"""
        query = "SELECT * FROM urls WHERE url_id = %s"
        result = db_manager.execute_query(query, (url_id,))
        return result[0] if result else None
    
    @staticmethod
    def get_url_by_domain(domain):
        """Get URLs by domain"""
        query = "SELECT * FROM urls WHERE domain = %s"
        return db_manager.execute_query(query, (domain,))
    
    @staticmethod
    def get_all_urls(limit=100, offset=0):
        """Get all URLs with pagination"""
        query = "SELECT * FROM urls ORDER BY submission_date DESC LIMIT %s OFFSET %s"
        return db_manager.execute_query(query, (limit, offset))
    
    @staticmethod
    def update_url_malicious_status(url_id, is_malicious):
        """Update URL malicious status"""
        query = "UPDATE urls SET is_malicious = %s WHERE url_id = %s"
        return db_manager.execute_query(query, (is_malicious, url_id), fetch=False)
    
    @staticmethod
    def get_malicious_urls(limit=100):
        """Get malicious URLs"""
        query = "SELECT * FROM urls WHERE is_malicious = TRUE ORDER BY submission_date DESC LIMIT %s"
        return db_manager.execute_query(query, (limit,))
    
    @staticmethod
    def get_url_count():
        """Get total URL count"""
        query = "SELECT COUNT(*) as count FROM urls"
        result = db_manager.execute_query(query)
        return result[0]['count'] if result else 0
    
    # ============================================
    # IP ADDRESSES TABLE OPERATIONS
    # ============================================
    
    @staticmethod
    def insert_ip_address(ip_address, ip_version='IPv4', country=None, city=None, 
                          region=None, latitude=None, longitude=None, isp=None,
                          organization=None, asn=None, threat_score=0.00):
        """Insert or update IP address"""
        # Truncate fields that might be too long
        if asn and len(str(asn)) > 50:
            asn = str(asn)[:50]
        if isp and len(str(isp)) > 255:
            isp = str(isp)[:255]
        if organization and len(str(organization)) > 255:
            organization = str(organization)[:255]
        if country and len(str(country)) > 100:
            country = str(country)[:100]
        if city and len(str(city)) > 100:
            city = str(city)[:100]
        if region and len(str(region)) > 100:
            region = str(region)[:100]
        
        query = """
        INSERT INTO ip_addresses (ip_address, ip_version, country, city, region, 
                                  latitude, longitude, isp, organization, asn, threat_score)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        AS new_row
        ON DUPLICATE KEY UPDATE 
            country = COALESCE(new_row.country, ip_addresses.country),
            city = COALESCE(new_row.city, ip_addresses.city),
            region = COALESCE(new_row.region, ip_addresses.region),
            latitude = COALESCE(new_row.latitude, ip_addresses.latitude),
            longitude = COALESCE(new_row.longitude, ip_addresses.longitude),
            isp = COALESCE(new_row.isp, ip_addresses.isp),
            organization = COALESCE(new_row.organization, ip_addresses.organization),
            asn = COALESCE(new_row.asn, ip_addresses.asn),
            threat_score = COALESCE(new_row.threat_score, ip_addresses.threat_score),
            last_seen = CURRENT_TIMESTAMP,
            total_requests = ip_addresses.total_requests + 1
        """
        params = (ip_address, ip_version, country, city, region, latitude, 
                 longitude, isp, organization, asn, threat_score)
        return db_manager.execute_query(query, params, fetch=False)
    
    @staticmethod
    def get_ip_info(ip_address):
        """Get IP address information"""
        query = "SELECT * FROM ip_addresses WHERE ip_address = %s"
        result = db_manager.execute_query(query, (ip_address,))
        return result[0] if result else None
    
    @staticmethod
    def get_high_threat_ips(threshold=50, limit=100):
        """Get IPs with high threat scores"""
        query = """
        SELECT * FROM ip_addresses 
        WHERE threat_score >= %s 
        ORDER BY threat_score DESC 
        LIMIT %s
        """
        return db_manager.execute_query(query, (threshold, limit))
    
    @staticmethod
    def update_threat_score(ip_address, threat_score):
        """Update IP threat score"""
        query = """
        UPDATE ip_addresses 
        SET threat_score = %s, last_seen = CURRENT_TIMESTAMP 
        WHERE ip_address = %s
        """
        return db_manager.execute_query(query, (threat_score, ip_address), fetch=False)
    
    @staticmethod
    def get_ips_by_country(country):
        """Get IPs by country"""
        query = "SELECT * FROM ip_addresses WHERE country = %s"
        return db_manager.execute_query(query, (country,))
    
    # ============================================
    # DNS RECORDS TABLE OPERATIONS
    # ============================================
    
    @staticmethod
    def insert_dns_record(domain, record_type, record_value, ttl=None, response_time_ms=None):
        """Insert DNS record"""
        query = """
        INSERT INTO dns_records (domain, record_type, record_value, ttl, response_time_ms)
        VALUES (%s, %s, %s, %s, %s)
        """
        params = (domain, record_type, str(record_value)[:65535], ttl, response_time_ms)
        return db_manager.execute_query(query, params, fetch=False)
    
    @staticmethod
    def get_dns_records(domain, record_type=None):
        """Get DNS records for domain"""
        if record_type:
            query = "SELECT * FROM dns_records WHERE domain = %s AND record_type = %s"
            params = (domain, record_type)
        else:
            query = "SELECT * FROM dns_records WHERE domain = %s"
            params = (domain,)
        return db_manager.execute_query(query, params)
    
    # ============================================
    # THREAT INTELLIGENCE TABLE OPERATIONS
    # ============================================
    
    @staticmethod
    def insert_threat_intel(ip_address, threat_type, confidence_score, 
                           source_feed, description=None):
        """Insert threat intelligence data"""
        if description and len(str(description)) > 65535:
            description = str(description)[:65535]
        
        query = """
        INSERT INTO threat_intelligence (ip_address, threat_type, confidence_score, 
                                        source_feed, description)
        VALUES (%s, %s, %s, %s, %s)
        AS new_row
        ON DUPLICATE KEY UPDATE 
            confidence_score = new_row.confidence_score,
            description = new_row.description,
            last_updated = CURRENT_TIMESTAMP
        """
        params = (ip_address, threat_type, confidence_score, source_feed, description)
        return db_manager.execute_query(query, params, fetch=False)
    
    @staticmethod
    def get_threats_for_ip(ip_address):
        """Get threat intelligence for specific IP"""
        query = """
        SELECT * FROM threat_intelligence 
        WHERE ip_address = %s AND is_active = TRUE
        ORDER BY last_updated DESC
        """
        return db_manager.execute_query(query, (ip_address,))
    
    @staticmethod
    def get_active_threats(limit=100):
        """Get all active threats"""
        query = """
        SELECT * FROM threat_intelligence 
        WHERE is_active = TRUE 
        ORDER BY confidence_score DESC 
        LIMIT %s
        """
        return db_manager.execute_query(query, (limit,))
    
    # ============================================
    # TRAFFIC LOGS TABLE OPERATIONS
    # ============================================
    
    @staticmethod
    def insert_traffic_log(src_ip, dst_ip, src_port=None, dst_port=None, 
                          url_id=None, protocol='HTTP', request_method=None,
                          user_agent=None, response_code=None, payload_size=None,
                          connection_duration_ms=None):
        """Insert traffic log entry"""
        if user_agent and len(str(user_agent)) > 65535:
            user_agent = str(user_agent)[:65535]
        
        query = """
        INSERT INTO traffic_logs (src_ip, dst_ip, src_port, dst_port, url_id, 
                                 protocol, request_method, user_agent, response_code,
                                 payload_size, connection_duration_ms)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        params = (src_ip, dst_ip, src_port, dst_port, url_id, protocol,
                 request_method, user_agent, response_code, payload_size,
                 connection_duration_ms)
        return db_manager.execute_query(query, params, fetch=False)
    
    @staticmethod
    def get_traffic_by_ip(ip_address, limit=100):
        """Get traffic logs for specific IP"""
        query = """
        SELECT * FROM traffic_logs 
        WHERE src_ip = %s OR dst_ip = %s 
        ORDER BY timestamp DESC 
        LIMIT %s
        """
        return db_manager.execute_query(query, (ip_address, ip_address, limit))
    
    @staticmethod
    def get_traffic_stats(hours=24):
        """Get traffic statistics for last N hours"""
        query = """
        SELECT 
            protocol,
            COUNT(*) as request_count,
            COUNT(DISTINCT src_ip) as unique_sources,
            COUNT(DISTINCT dst_ip) as unique_destinations
        FROM traffic_logs 
        WHERE timestamp >= DATE_SUB(NOW(), INTERVAL %s HOUR)
        GROUP BY protocol
        """
        return db_manager.execute_query(query, (hours,))
    
    # ============================================
    # ALERTS TABLE OPERATIONS
    # ============================================
    
    @staticmethod
    def insert_alert(alert_type, severity, source_ip, destination_ip=None,
                    url_id=None, description=None):
        """Insert new alert"""
        if description and len(str(description)) > 65535:
            description = str(description)[:65535]
        
        query = """
        INSERT INTO alerts (alert_type, severity, source_ip, destination_ip, 
                           url_id, description)
        VALUES (%s, %s, %s, %s, %s, %s)
        """
        params = (alert_type, severity, source_ip, destination_ip, url_id, description)
        return db_manager.execute_query(query, params, fetch=False)
    
    @staticmethod
    def update_alert_status(alert_id, status, resolved_by=None, resolution_notes=None):
        """Update alert status"""
        if status in ('resolved', 'false_positive'):
            query = """
            UPDATE alerts 
            SET status = %s, resolved_by = %s, resolution_notes = %s, resolved_at = NOW()
            WHERE alert_id = %s
            """
            params = (status, resolved_by, resolution_notes, alert_id)
        else:
            query = "UPDATE alerts SET status = %s WHERE alert_id = %s"
            params = (status, alert_id)
        return db_manager.execute_query(query, params, fetch=False)
    
    @staticmethod
    def get_active_alerts(severity=None, limit=100):
        """Get active alerts"""
        if severity:
            query = """
            SELECT * FROM alerts 
            WHERE status IN ('new', 'investigating') AND severity = %s
            ORDER BY timestamp DESC LIMIT %s
            """
            params = (severity, limit)
        else:
            query = """
            SELECT * FROM alerts 
            WHERE status IN ('new', 'investigating')
            ORDER BY timestamp DESC LIMIT %s
            """
            params = (limit,)
        return db_manager.execute_query(query, params)
    
    @staticmethod
    def get_alert_stats():
        """Get alert statistics"""
        query = """
        SELECT 
            severity,
            status,
            COUNT(*) as count
        FROM alerts 
        WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)
        GROUP BY severity, status
        """
        return db_manager.execute_query(query)
    
    # ============================================
    # MODEL PREDICTIONS TABLE OPERATIONS
    # ============================================
    
    @staticmethod
    def insert_prediction(url_id, prediction_score, predicted_class, 
                         model_name, model_version, ip_id=None, features_used=None):
        """Insert model prediction"""
        query = """
        INSERT INTO model_predictions (url_id, ip_id, prediction_score, predicted_class,
                                      model_name, model_version, features_used)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        params = (url_id, ip_id, prediction_score, predicted_class,
                 model_name, model_version, features_used)
        return db_manager.execute_query(query, params, fetch=False)
    
    @staticmethod
    def get_predictions_for_url(url_id):
        """Get predictions for specific URL"""
        query = """
        SELECT * FROM model_predictions 
        WHERE url_id = %s 
        ORDER BY prediction_timestamp DESC
        """
        return db_manager.execute_query(query, (url_id,))
    
    # ============================================
    # USERS TABLE OPERATIONS
    # ============================================
    
    @staticmethod
    def create_user(username, email, password_hash, role='viewer'):
        """Create new user"""
        query = """
        INSERT INTO users (username, email, password_hash, role)
        VALUES (%s, %s, %s, %s)
        """
        params = (username, email, password_hash, role)
        return db_manager.execute_query(query, params, fetch=False)
    
    @staticmethod
    def get_user_by_username(username):
        """Get user by username"""
        query = "SELECT * FROM users WHERE username = %s AND is_active = TRUE"
        result = db_manager.execute_query(query, (username,))
        return result[0] if result else None
    
    @staticmethod
    def update_last_login(user_id):
        """Update user's last login timestamp"""
        query = "UPDATE users SET last_login = NOW() WHERE user_id = %s"
        return db_manager.execute_query(query, (user_id,), fetch=False)
    
    # ============================================
    # AUDIT LOGS TABLE OPERATIONS
    # ============================================
    
    @staticmethod
    def insert_audit_log(user_id, action, table_affected=None, record_id=None,
                        old_values=None, new_values=None, ip_address=None):
        """Insert audit log entry"""
        query = """
        INSERT INTO audit_logs (user_id, action, table_affected, record_id,
                               old_values, new_values, ip_address)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        params = (user_id, action, table_affected, record_id,
                 old_values, new_values, ip_address)
        return db_manager.execute_query(query, params, fetch=False)
    
    # ============================================
    # FEATURE CACHE TABLE OPERATIONS
    # ============================================
    
    @staticmethod
    def insert_feature_cache(url_id, feature_vector, feature_count, processing_time_ms=None):
        """Insert feature cache entry"""
        if isinstance(feature_vector, dict):
            feature_vector = json.dumps(feature_vector)
        
        query = """
        INSERT INTO feature_cache (url_id, feature_vector, feature_count, processing_time_ms)
        VALUES (%s, %s, %s, %s)
        AS new_row
        ON DUPLICATE KEY UPDATE 
            feature_vector = new_row.feature_vector,
            feature_count = new_row.feature_count,
            extraction_timestamp = CURRENT_TIMESTAMP,
            processing_time_ms = COALESCE(new_row.processing_time_ms, feature_cache.processing_time_ms)
        """
        params = (url_id, feature_vector, feature_count, processing_time_ms)
        return db_manager.execute_query(query, params, fetch=False)
    
    @staticmethod
    def get_feature_cache(url_id):
        """Get cached features for URL"""
        query = "SELECT * FROM feature_cache WHERE url_id = %s"
        result = db_manager.execute_query(query, (url_id,))
        return result[0] if result else None