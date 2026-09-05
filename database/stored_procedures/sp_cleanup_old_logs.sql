DELIMITER //

CREATE PROCEDURE sp_cleanup_old_logs(
    IN days_to_keep INT
)
BEGIN
    DELETE FROM traffic_logs 
    WHERE timestamp < DATE_SUB(NOW(), INTERVAL days_to_keep DAY);
    
    DELETE FROM audit_logs 
    WHERE timestamp < DATE_SUB(NOW(), INTERVAL days_to_keep DAY);
    
    SELECT ROW_COUNT() as deleted_rows;
END //

DELIMITER ;