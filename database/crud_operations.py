"""
CRUD Operations for all database tables
MySQL 8.0+ compatible (uses ON DUPLICATE KEY UPDATE with alias syntax)

Enhanced version:
- update_alert_status returns rowcount for verification
- All insert methods return lastrowid
- Graceful error handling with debug logging
- Truncation guards for VARCHAR columns
"""

from database.connection import db_manager
from loguru import logger
from datetime import datetime
import json


class CRUDOperations:
    """CRUD Operations for all database tables"""

    # ============================================
    # URLS TABLE
    # ============================================

    @staticmethod
    def insert_url(full_url, domain, path=None, protocol=None, tld=None,
                   url_length=None, source=None, is_malicious=None):
        """Insert a new URL record. Returns url_id (or existing url_id on duplicate)."""
        # Truncation guards
        if full_url and len(full_url) > 2048:
            full_url = full_url[:2048]
        if domain and len(domain) > 255:
            domain = domain[:255]
        if tld and len(tld) > 100:
            tld = tld[:100]
        if protocol and len(protocol) > 10:
            protocol = protocol[:10]
        if source and len(source) > 100:
            source = source[:100]

        query = """
        INSERT INTO urls (full_url, domain, path, protocol, tld, url_length, source, is_malicious)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        AS new_row
        ON DUPLICATE KEY UPDATE
            submission_date = CURRENT_TIMESTAMP,
            source = new_row.source,
            is_malicious = COALESCE(new_row.is_malicious, urls.is_malicious),
            url_id = LAST_INSERT_ID(url_id)
        """
        params = (full_url, domain, path, protocol, tld, url_length, source, is_malicious)
        try:
            return db_manager.execute_query(query, params, fetch=False)
        except Exception as e:
            logger.debug(f"insert_url failed for {full_url[:80]}: {e}")
            return None

    @staticmethod
    def get_url_by_id(url_id):
        query = "SELECT * FROM urls WHERE url_id = %s"
        result = db_manager.execute_query(query, (url_id,))
        return result[0] if result else None

    @staticmethod
    def get_url_by_domain(domain):
        query = "SELECT * FROM urls WHERE domain = %s"
        return db_manager.execute_query(query, (domain,))

    @staticmethod
    def get_all_urls(limit=100, offset=0):
        query = """
            SELECT * FROM urls
            ORDER BY submission_date DESC
            LIMIT %s OFFSET %s
        """
        return db_manager.execute_query(query, (limit, offset))

    @staticmethod
    def update_url_malicious_status(url_id, is_malicious):
        query = "UPDATE urls SET is_malicious = %s WHERE url_id = %s"
        return db_manager.execute_query(query, (is_malicious, url_id), fetch=False)

    @staticmethod
    def get_malicious_urls(limit=100):
        query = """
            SELECT * FROM urls
            WHERE is_malicious = TRUE
            ORDER BY submission_date DESC
            LIMIT %s
        """
        return db_manager.execute_query(query, (limit,))

    @staticmethod
    def get_url_count():
        query = "SELECT COUNT(*) as count FROM urls"
        result = db_manager.execute_query(query)
        return result[0]['count'] if result else 0

    # ============================================
    # IP ADDRESSES TABLE
    # ============================================

    @staticmethod
    def insert_ip_address(ip_address, ip_version='IPv4', country=None, city=None,
                          region=None, latitude=None, longitude=None, isp=None,
                          organization=None, asn=None, threat_score=0.00):
        """Insert or update IP address. Truncates fields to avoid DB errors."""
        # Truncation guards
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
        try:
            return db_manager.execute_query(query, params, fetch=False)
        except Exception as e:
            logger.debug(f"insert_ip_address failed for {ip_address}: {e}")
            return None

    @staticmethod
    def get_ip_info(ip_address):
        query = "SELECT * FROM ip_addresses WHERE ip_address = %s"
        result = db_manager.execute_query(query, (ip_address,))
        return result[0] if result else None

    @staticmethod
    def get_high_threat_ips(threshold=50, limit=100):
        query = """
            SELECT * FROM ip_addresses
            WHERE threat_score >= %s
            ORDER BY threat_score DESC
            LIMIT %s
        """
        return db_manager.execute_query(query, (threshold, limit))

    @staticmethod
    def update_threat_score(ip_address, threat_score):
        query = """
            UPDATE ip_addresses
            SET threat_score = %s, last_seen = CURRENT_TIMESTAMP
            WHERE ip_address = %s
        """
        return db_manager.execute_query(query, (threat_score, ip_address), fetch=False)

    @staticmethod
    def get_ips_by_country(country):
        query = "SELECT * FROM ip_addresses WHERE country = %s"
        return db_manager.execute_query(query, (country,))

    # ============================================
    # DNS RECORDS TABLE
    # ============================================

    @staticmethod
    def insert_dns_record(domain, record_type, record_value, ttl=None,
                          response_time_ms=None):
        # Truncate record_value if extremely long
        if record_value and len(str(record_value)) > 60000:
            record_value = str(record_value)[:60000]

        query = """
            INSERT INTO dns_records (domain, record_type, record_value, ttl, response_time_ms)
            VALUES (%s, %s, %s, %s, %s)
        """
        params = (domain, record_type, record_value, ttl, response_time_ms)
        try:
            return db_manager.execute_query(query, params, fetch=False)
        except Exception as e:
            logger.debug(f"insert_dns_record failed for {domain}/{record_type}: {e}")
            return None

    @staticmethod
    def get_dns_records(domain, record_type=None):
        if record_type:
            query = "SELECT * FROM dns_records WHERE domain = %s AND record_type = %s"
            params = (domain, record_type)
        else:
            query = "SELECT * FROM dns_records WHERE domain = %s"
            params = (domain,)
        return db_manager.execute_query(query, params)

    # ============================================
    # THREAT INTELLIGENCE TABLE
    # ============================================

    @staticmethod
    def insert_threat_intel(ip_address, threat_type, confidence_score,
                            source_feed, description=None):
        if description and len(str(description)) > 65000:
            description = str(description)[:65000]

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
        try:
            return db_manager.execute_query(query, params, fetch=False)
        except Exception as e:
            logger.debug(f"insert_threat_intel failed for {ip_address}: {e}")
            return None

    @staticmethod
    def get_threats_for_ip(ip_address):
        query = """
            SELECT * FROM threat_intelligence
            WHERE ip_address = %s AND is_active = TRUE
            ORDER BY last_updated DESC
        """
        return db_manager.execute_query(query, (ip_address,))

    @staticmethod
    def get_active_threats(limit=100):
        query = """
            SELECT * FROM threat_intelligence
            WHERE is_active = TRUE
            ORDER BY confidence_score DESC
            LIMIT %s
        """
        return db_manager.execute_query(query, (limit,))

    # ============================================
    # TRAFFIC LOGS TABLE
    # ============================================

    @staticmethod
    def insert_traffic_log(src_ip, dst_ip, src_port=None, dst_port=None,
                           url_id=None, protocol='HTTP', request_method=None,
                           user_agent=None, response_code=None, payload_size=None,
                           connection_duration_ms=None):
        if user_agent and len(str(user_agent)) > 60000:
            user_agent = str(user_agent)[:60000]

        query = """
            INSERT INTO traffic_logs (src_ip, dst_ip, src_port, dst_port, url_id,
                                      protocol, request_method, user_agent, response_code,
                                      payload_size, connection_duration_ms)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        params = (src_ip, dst_ip, src_port, dst_port, url_id, protocol,
                  request_method, user_agent, response_code, payload_size,
                  connection_duration_ms)
        try:
            return db_manager.execute_query(query, params, fetch=False)
        except Exception as e:
            logger.debug(f"insert_traffic_log failed: {e}")
            return None

    @staticmethod
    def get_traffic_by_ip(ip_address, limit=100):
        query = """
            SELECT * FROM traffic_logs
            WHERE src_ip = %s OR dst_ip = %s
            ORDER BY timestamp DESC
            LIMIT %s
        """
        return db_manager.execute_query(query, (ip_address, ip_address, limit))

    @staticmethod
    def get_traffic_stats(hours=24):
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
    # ALERTS TABLE
    # ============================================

        # ENUM validation sets (must match schema)
    _VALID_ALERT_TYPES = {
        'malicious_url', 'suspicious_ip', 'high_traffic',
        'dns_anomaly', 'geolocation_mismatch',
        'frequency_attack', 'other',
    }
    _VALID_SEVERITIES = {'low', 'medium', 'high', 'critical'}

    @staticmethod
    def insert_alert(alert_type, severity, source_ip, destination_ip=None,
                     url_id=None, description=None):
        """Insert a new alert. Validates ENUM values before hitting DB."""

        # ---- ENUM validation ----
        if alert_type not in CRUDOperations._VALID_ALERT_TYPES:
            logger.warning(
                f"Invalid alert_type '{alert_type}'. "
                f"Falling back to 'other'. Valid: {CRUDOperations._VALID_ALERT_TYPES}"
            )
            alert_type = 'other'

        if severity not in CRUDOperations._VALID_SEVERITIES:
            logger.warning(
                f"Invalid severity '{severity}'. "
                f"Falling back to 'low'. Valid: {CRUDOperations._VALID_SEVERITIES}"
            )
            severity = 'low'

        # ---- Truncation guard ----
        if description and len(str(description)) > 65000:
            description = str(description)[:65000]

        query = """
            INSERT INTO alerts (alert_type, severity, source_ip, destination_ip,
                                url_id, description)
            VALUES (%s, %s, %s, %s, %s, %s)
        """
        params = (alert_type, severity, source_ip, destination_ip, url_id, description)

        try:
            return db_manager.execute_query(query, params, fetch=False)
        except Exception as e:
            logger.error(f"insert_alert failed: {e}")
            return None
    @staticmethod
    def get_active_alerts(severity=None, limit=100):
        if severity:
            query = """
                SELECT * FROM alerts
                WHERE status IN ('new', 'investigating') AND severity = %s
                ORDER BY timestamp DESC
                LIMIT %s
            """
            params = (severity, limit)
        else:
            query = """
                SELECT * FROM alerts
                WHERE status IN ('new', 'investigating')
                ORDER BY timestamp DESC
                LIMIT %s
            """
            params = (limit,)
        return db_manager.execute_query(query, params)

    @staticmethod
    def get_alert_stats():
        query = """
            SELECT severity, status, COUNT(*) as count
            FROM alerts
            WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)
            GROUP BY severity, status
        """
        return db_manager.execute_query(query)

    @staticmethod
    def get_alert_by_id(alert_id):
        query = "SELECT * FROM alerts WHERE alert_id = %s"
        result = db_manager.execute_query(query, (alert_id,))
        return result[0] if result else None

    @staticmethod
    def update_alert_status(alert_id, status, resolved_by=None, resolution_notes=None):
        """
        Update alert status.

        Returns:
            int: number of rows affected (0 = not found, 1 = success)
        """
        try:
            if status in ('resolved', 'false_positive'):
                query = """
                    UPDATE alerts
                    SET status = %s,
                        resolved_by = %s,
                        resolution_notes = %s,
                        resolved_at = NOW()
                    WHERE alert_id = %s
                """
                params = (status, resolved_by, resolution_notes, alert_id)
            else:
                query = "UPDATE alerts SET status = %s WHERE alert_id = %s"
                params = (status, alert_id)

            # Manual connection so we can read rowcount
            conn = db_manager.get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute(query, params)
                conn.commit()
                rowcount = cursor.rowcount
                cursor.close()
                logger.debug(f"Alert {alert_id} → status={status}, rows={rowcount}")
                return rowcount
            finally:
                conn.close()

        except Exception as e:
            logger.error(f"update_alert_status failed for alert {alert_id}: {e}")
            return 0

    # ============================================
    # MODEL PREDICTIONS TABLE
    # ============================================

    @staticmethod
    def insert_prediction(url_id, prediction_score, predicted_class,
                          model_name, model_version, ip_id=None, features_used=None):
        if features_used and isinstance(features_used, dict):
            features_used = json.dumps(features_used)
        if features_used and len(str(features_used)) > 60000:
            features_used = str(features_used)[:60000]

        query = """
            INSERT INTO model_predictions (url_id, ip_id, prediction_score, predicted_class,
                                           model_name, model_version, features_used)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        params = (url_id, ip_id, prediction_score, predicted_class,
                  model_name, model_version, features_used)
        try:
            return db_manager.execute_query(query, params, fetch=False)
        except Exception as e:
            logger.debug(f"insert_prediction failed for url_id={url_id}: {e}")
            return None

    @staticmethod
    def get_predictions_for_url(url_id):
        query = """
            SELECT * FROM model_predictions
            WHERE url_id = %s
            ORDER BY prediction_timestamp DESC
        """
        return db_manager.execute_query(query, (url_id,))

    # ============================================
    # USERS TABLE
    # ============================================

    @staticmethod
    def create_user(username, email, password_hash, role='viewer'):
        query = """
            INSERT INTO users (username, email, password_hash, role)
            VALUES (%s, %s, %s, %s)
        """
        params = (username, email, password_hash, role)
        try:
            return db_manager.execute_query(query, params, fetch=False)
        except Exception as e:
            logger.debug(f"create_user failed: {e}")
            return None

    @staticmethod
    def get_user_by_username(username):
        query = "SELECT * FROM users WHERE username = %s AND is_active = TRUE"
        result = db_manager.execute_query(query, (username,))
        return result[0] if result else None

    @staticmethod
    def update_last_login(user_id):
        query = "UPDATE users SET last_login = NOW() WHERE user_id = %s"
        return db_manager.execute_query(query, (user_id,), fetch=False)

    # ============================================
    # AUDIT LOGS TABLE
    # ============================================

    @staticmethod
    def insert_audit_log(user_id, action, table_affected=None, record_id=None,
                         old_values=None, new_values=None, ip_address=None):
        # JSON-encode dicts
        if old_values is not None and not isinstance(old_values, str):
            old_values = json.dumps(old_values, default=str)
        if new_values is not None and not isinstance(new_values, str):
            new_values = json.dumps(new_values, default=str)

        # Truncate if extremely large
        if old_values and len(old_values) > 60000:
            old_values = old_values[:60000]
        if new_values and len(new_values) > 60000:
            new_values = new_values[:60000]

        query = """
            INSERT INTO audit_logs (user_id, action, table_affected, record_id,
                                    old_values, new_values, ip_address)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        params = (user_id, action, table_affected, record_id,
                  old_values, new_values, ip_address)
        try:
            return db_manager.execute_query(query, params, fetch=False)
        except Exception as e:
            logger.debug(f"insert_audit_log failed: {e}")
            return None

    @staticmethod
    def get_audit_logs(limit=100, offset=0):
        query = """
            SELECT * FROM audit_logs
            ORDER BY timestamp DESC
            LIMIT %s OFFSET %s
        """
        return db_manager.execute_query(query, (limit, offset))

    @staticmethod
    def get_audit_logs_for_record(table_name, record_id):
        query = """
            SELECT * FROM audit_logs
            WHERE table_affected = %s AND record_id = %s
            ORDER BY timestamp DESC
        """
        return db_manager.execute_query(query, (table_name, record_id))

    # ============================================
    # FEATURE CACHE TABLE
    # ============================================

    @staticmethod
    def insert_feature_cache(url_id, feature_vector, feature_count,
                             processing_time_ms=None):
        if isinstance(feature_vector, dict):
            feature_vector = json.dumps(feature_vector)

        # Truncate if exceeding JSON column limits
        if feature_vector and len(feature_vector) > 60000:
            # Try compacting first
            try:
                parsed = json.loads(feature_vector)
                # Round floats to save space
                parsed = {
                    k: round(v, 4) if isinstance(v, float) else v
                    for k, v in parsed.items()
                }
                feature_vector = json.dumps(parsed)
            except Exception:
                pass
            # If still too big, truncate
            if len(feature_vector) > 60000:
                feature_vector = feature_vector[:60000]

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
        try:
            return db_manager.execute_query(query, params, fetch=False)
        except Exception as e:
            logger.debug(f"insert_feature_cache failed for url_id={url_id}: {e}")
            return None

    @staticmethod
    def get_feature_cache(url_id):
        query = "SELECT * FROM feature_cache WHERE url_id = %s"
        result = db_manager.execute_query(query, (url_id,))
        return result[0] if result else None

    @staticmethod
    def get_all_features(limit=500):
        """Bulk fetch features for ML training"""
        query = """
            SELECT u.url_id, u.full_url, u.domain, u.is_malicious, fc.feature_vector
            FROM urls u
            LEFT JOIN feature_cache fc ON u.url_id = fc.url_id
            WHERE u.is_malicious IS NOT NULL
            ORDER BY u.submission_date DESC
            LIMIT %s
        """
        return db_manager.execute_query(query, (limit,))

    # ============================================
    # UTILITY / MAINTENANCE
    # ============================================

    @staticmethod
    def get_database_stats():
        """Get overall DB stats"""
        stats = {}
        tables = ['urls', 'ip_addresses', 'alerts', 'traffic_logs',
                  'threat_intelligence', 'model_predictions']
        for t in tables:
            try:
                r = db_manager.execute_query(f"SELECT COUNT(*) as cnt FROM {t}")
                stats[t] = r[0]['cnt'] if r else 0
            except Exception:
                stats[t] = -1
        return stats

    @staticmethod
    def cleanup_old_traffic_logs(days_to_keep=30):
        """Delete traffic logs older than N days"""
        query = """
            DELETE FROM traffic_logs
            WHERE timestamp < DATE_SUB(NOW(), INTERVAL %s DAY)
        """
        try:
            return db_manager.execute_query(query, (days_to_keep,), fetch=False)
        except Exception as e:
            logger.error(f"cleanup_old_traffic_logs failed: {e}")
            return 0