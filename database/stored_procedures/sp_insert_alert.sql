DELIMITER //

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
    
    SELECT COUNT(*) INTO ip_exists FROM ip_addresses WHERE ip_address = p_source_ip;
    
    IF ip_exists = 0 THEN
        INSERT INTO ip_addresses (ip_address, ip_version)
        VALUES (p_source_ip, IF(INET6_ATON(p_source_ip) IS NOT NULL, 'IPv6', 'IPv4'));
    END IF;
    
    IF p_destination_ip IS NOT NULL THEN
        SELECT COUNT(*) INTO ip_exists FROM ip_addresses WHERE ip_address = p_destination_ip;
        
        IF ip_exists = 0 THEN
            INSERT INTO ip_addresses (ip_address, ip_version)
            VALUES (p_destination_ip, IF(INET6_ATON(p_destination_ip) IS NOT NULL, 'IPv6', 'IPv4'));
        END IF;
    END IF;
    
    INSERT INTO alerts (alert_type, severity, source_ip, destination_ip, url_id, description)
    VALUES (p_alert_type, p_severity, p_source_ip, p_destination_ip, p_url_id, p_description);
    
    SELECT LAST_INSERT_ID() as new_alert_id;
END //

DELIMITER ;