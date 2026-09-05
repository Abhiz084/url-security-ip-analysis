-- ============================================
-- Stored Procedures and Views
-- ============================================

USE url_threat_analysis;

-- Drop existing procedures if they exist
DROP PROCEDURE IF EXISTS sp_get_threat_stats;
DROP PROCEDURE IF EXISTS sp_insert_alert;
DROP PROCEDURE IF EXISTS sp_update_ip_reputation;
DROP PROCEDURE IF EXISTS sp_cleanup_old_logs;
DROP PROCEDURE IF EXISTS sp_get_ip_threat_summary;

-- Drop existing views if they exist
DROP VIEW IF EXISTS vw_dashboard_summary;
DROP VIEW IF EXISTS vw_recent_threats;
DROP VIEW IF EXISTS vw_traffic_summary;

DELIMITER //

-- ============================================
-- Get threat statistics by time range
-- ============================================
CREATE PROCEDURE sp_get_threat_stats(
    IN start_date TIMESTAMP,
    IN end_date TIMESTAMP
)
BEGIN
    SELECT 
        alert_type,
        severity,
        COUNT(*) as alert_count,
        DATE(timestamp) as alert_date
    FROM alerts
    WHERE timestamp BETWEEN start_date AND end_date
    GROUP BY alert_type, severity, DATE(timestamp)
    ORDER BY alert_date DESC, alert_count DESC;
END //

-- ============================================
-- Insert new alert with IP validation
-- ============================================
CREATE PROCEDURE sp_insert_alert(
    IN p_alert_type VARCHAR(50),
    IN p_severity VARCHAR(20),
    IN p_source_ip VARCHAR(45),
    IN p_destination_ip VARCHAR(45),
    IN p_url_id INT,
    IN p_description TEXT
)
BEGIN
    DECLARE ip_exists INT;
    
    -- Check if source IP exists
    SELECT COUNT(*) INTO ip_exists FROM ip_addresses WHERE ip_address = p_source_ip;
    
    -- Insert IP if not exists
    IF ip_exists = 0 THEN
        INSERT INTO ip_addresses (ip_address, ip_version)
        VALUES (p_source_ip, IF(INET6_ATON(p_source_ip) IS NOT NULL, 'IPv6', 'IPv4'));
    END IF;
    
    -- Check destination IP
    IF p_destination_ip IS NOT NULL THEN
        SELECT COUNT(*) INTO ip_exists FROM ip_addresses WHERE ip_address = p_destination_ip;
        
        IF ip_exists = 0 THEN
            INSERT INTO ip_addresses (ip_address, ip_version)
            VALUES (p_destination_ip, IF(INET6_ATON(p_destination_ip) IS NOT NULL, 'IPv6', 'IPv4'));
        END IF;
    END IF;
    
    -- Insert the alert
    INSERT INTO alerts (alert_type, severity, source_ip, destination_ip, url_id, description)
    VALUES (p_alert_type, p_severity, p_source_ip, p_destination_ip, p_url_id, p_description);
    
    -- Return the new alert ID
    SELECT LAST_INSERT_ID() as new_alert_id;
END //

-- ============================================
-- Update IP reputation score
-- ============================================
CREATE PROCEDURE sp_update_ip_reputation(
    IN p_ip_address VARCHAR(45),
    IN p_threat_score DECIMAL(5,2)
)
BEGIN
    UPDATE ip_addresses 
    SET threat_score = p_threat_score,
        last_seen = CURRENT_TIMESTAMP
    WHERE ip_address = p_ip_address;
    
    -- If threat score is high, update threat intelligence
    IF p_threat_score > 70 THEN
        INSERT INTO threat_intelligence (ip_address, threat_type, confidence_score, source_feed, description)
        VALUES (p_ip_address, 'other', p_threat_score, 'internal_model', 'Automated threat score update')
        ON DUPLICATE KEY UPDATE confidence_score = p_threat_score, last_updated = CURRENT_TIMESTAMP;
    END IF;
END //

-- ============================================
-- Clean up old logs
-- ============================================
CREATE PROCEDURE sp_cleanup_old_logs(
    IN days_to_keep INT
)
BEGIN
    DECLARE deleted_count INT DEFAULT 0;
    
    DELETE FROM traffic_logs 
    WHERE timestamp < DATE_SUB(NOW(), INTERVAL days_to_keep DAY);
    SET deleted_count = ROW_COUNT();
    
    DELETE FROM audit_logs 
    WHERE timestamp < DATE_SUB(NOW(), INTERVAL days_to_keep DAY);
    SET deleted_count = deleted_count + ROW_COUNT();
    
    SELECT deleted_count as deleted_rows;
END //

-- ============================================
-- Get IP threat summary
-- ============================================
CREATE PROCEDURE sp_get_ip_threat_summary(
    IN p_ip_address VARCHAR(45)
)
BEGIN
    SELECT 
        ip.ip_address,
        ip.country,
        ip.city,
        ip.threat_score,
        ip.total_requests,
        COUNT(DISTINCT ti.threat_id) as threat_count,
        GROUP_CONCAT(DISTINCT ti.threat_type) as threat_types,
        COUNT(DISTINCT a.alert_id) as alert_count,
        COUNT(DISTINCT tl.log_id) as traffic_count
    FROM ip_addresses ip
    LEFT JOIN threat_intelligence ti ON ip.ip_address = ti.ip_address AND ti.is_active = TRUE
    LEFT JOIN alerts a ON ip.ip_address = a.source_ip
    LEFT JOIN traffic_logs tl ON ip.ip_address = tl.src_ip OR ip.ip_address = tl.dst_ip
    WHERE ip.ip_address = p_ip_address
    GROUP BY ip.ip_id;
END //

DELIMITER ;

-- ============================================
-- VIEWS
-- ============================================

-- Dashboard summary view
CREATE OR REPLACE VIEW vw_dashboard_summary AS
SELECT 
    (SELECT COUNT(*) FROM urls WHERE is_malicious = TRUE) as total_malicious_urls,
    (SELECT COUNT(*) FROM urls) as total_urls_scanned,
    (SELECT COUNT(*) FROM ip_addresses WHERE threat_score > 50) as high_threat_ips,
    (SELECT COUNT(*) FROM ip_addresses) as total_ips_tracked,
    (SELECT COUNT(*) FROM alerts WHERE status IN ('new', 'investigating')) as active_alerts,
    (SELECT COUNT(*) FROM alerts WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)) as alerts_last_24h,
    (SELECT COUNT(*) FROM traffic_logs WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)) as traffic_last_24h;

-- Recent threats view
CREATE OR REPLACE VIEW vw_recent_threats AS
SELECT 
    a.alert_id,
    a.timestamp,
    a.alert_type,
    a.severity,
    a.source_ip,
    ip.country as source_country,
    a.description,
    a.status,
    u.full_url,
    mp.prediction_score,
    mp.predicted_class
FROM alerts a
LEFT JOIN ip_addresses ip ON a.source_ip = ip.ip_address
LEFT JOIN urls u ON a.url_id = u.url_id
LEFT JOIN model_predictions mp ON u.url_id = mp.url_id
ORDER BY a.timestamp DESC
LIMIT 100;

-- Traffic summary view
CREATE OR REPLACE VIEW vw_traffic_summary AS
SELECT 
    DATE(timestamp) as date,
    HOUR(timestamp) as hour,
    protocol,
    COUNT(*) as request_count,
    COUNT(DISTINCT src_ip) as unique_sources,
    COUNT(DISTINCT dst_ip) as unique_destinations,
    AVG(payload_size) as avg_payload_size,
    AVG(connection_duration_ms) as avg_duration
FROM traffic_logs
WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)
GROUP BY DATE(timestamp), HOUR(timestamp), protocol
ORDER BY date DESC, hour DESC;