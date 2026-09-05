DELIMITER //

CREATE PROCEDURE sp_update_ip_reputation(
    IN p_ip_address VARCHAR(45),
    IN p_threat_score DECIMAL(5,2)
)
BEGIN
    UPDATE ip_addresses 
    SET threat_score = p_threat_score,
        last_seen = CURRENT_TIMESTAMP
    WHERE ip_address = p_ip_address;
    
    IF p_threat_score > 70 THEN
        INSERT INTO threat_intelligence (ip_address, threat_type, confidence_score, source_feed, description)
        VALUES (p_ip_address, 'other', p_threat_score, 'internal_model', 'Automated threat score update')
        ON DUPLICATE KEY UPDATE confidence_score = p_threat_score, last_updated = CURRENT_TIMESTAMP;
    END IF;
END //

DELIMITER ;