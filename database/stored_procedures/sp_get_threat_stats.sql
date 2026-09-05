DELIMITER //

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

DELIMITER ;