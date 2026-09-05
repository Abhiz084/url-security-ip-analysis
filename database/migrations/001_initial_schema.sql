-- ============================================
-- URL Security Using IP-Based Threat Analysis
-- Initial Database Schema
-- Version: 1.0
-- ============================================

CREATE DATABASE IF NOT EXISTS url_threat_analysis
CHARACTER SET utf8mb4
COLLATE utf8mb4_unicode_ci;

USE url_threat_analysis;

-- ============================================
-- 1. URLS TABLE
-- ============================================
CREATE TABLE urls (
    url_id INT AUTO_INCREMENT PRIMARY KEY,
    full_url VARCHAR(2048) NOT NULL,
    domain VARCHAR(255) NOT NULL,
    path TEXT,
    protocol VARCHAR(10),
    tld VARCHAR(20),
    url_length INT,
    submission_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    source VARCHAR(100),
    is_malicious BOOLEAN DEFAULT NULL,
    INDEX idx_domain (domain),
    INDEX idx_submission_date (submission_date),
    INDEX idx_is_malicious (is_malicious),
    UNIQUE KEY unique_url (full_url(768))
) ENGINE=InnoDB;

-- ============================================
-- 2. IP ADDRESSES TABLE
-- ============================================
CREATE TABLE ip_addresses (
    ip_id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    ip_version ENUM('IPv4', 'IPv6') NOT NULL,
    country VARCHAR(100),
    city VARCHAR(100),
    region VARCHAR(100),
    latitude DECIMAL(10, 7),
    longitude DECIMAL(10, 7),
    isp VARCHAR(255),
    organization VARCHAR(255),
    asn VARCHAR(20),
    threat_score DECIMAL(5, 2) DEFAULT 0.00,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    total_requests INT DEFAULT 0,
    INDEX idx_ip_address (ip_address),
    INDEX idx_threat_score (threat_score),
    INDEX idx_country (country),
    UNIQUE KEY unique_ip (ip_address)
) ENGINE=InnoDB;

-- ============================================
-- 3. DNS RECORDS TABLE
-- ============================================
CREATE TABLE dns_records (
    record_id INT AUTO_INCREMENT PRIMARY KEY,
    domain VARCHAR(255) NOT NULL,
    record_type ENUM('A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA') NOT NULL,
    record_value TEXT NOT NULL,
    ttl INT,
    query_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    response_time_ms INT,
    INDEX idx_domain (domain),
    INDEX idx_record_type (record_type),
    INDEX idx_query_timestamp (query_timestamp)
) ENGINE=InnoDB;

-- ============================================
-- 4. THREAT INTELLIGENCE TABLE
-- ============================================
CREATE TABLE threat_intelligence (
    threat_id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    threat_type ENUM('malware', 'phishing', 'botnet', 'c2_server', 'proxy', 'tor_exit', 'scanner', 'spam', 'other') NOT NULL,
    confidence_score DECIMAL(5, 2) NOT NULL,
    source_feed VARCHAR(255) NOT NULL,
    description TEXT,
    first_reported TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    INDEX idx_ip_threat (ip_address),
    INDEX idx_threat_type (threat_type),
    INDEX idx_confidence (confidence_score),
    FOREIGN KEY (ip_address) REFERENCES ip_addresses(ip_address) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ============================================
-- 5. TRAFFIC LOGS TABLE
-- ============================================
CREATE TABLE traffic_logs (
    log_id BIGINT AUTO_INCREMENT PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    src_ip VARCHAR(45) NOT NULL,
    dst_ip VARCHAR(45) NOT NULL,
    src_port INT,
    dst_port INT,
    url_id INT,
    protocol ENUM('HTTP', 'HTTPS', 'DNS', 'FTP', 'SMTP', 'OTHER') DEFAULT 'HTTP',
    request_method VARCHAR(10),
    user_agent TEXT,
    response_code INT,
    payload_size INT,
    connection_duration_ms INT,
    INDEX idx_timestamp (timestamp),
    INDEX idx_src_ip (src_ip),
    INDEX idx_dst_ip (dst_ip),
    INDEX idx_url_id (url_id),
    INDEX idx_protocol (protocol),
    FOREIGN KEY (url_id) REFERENCES urls(url_id) ON DELETE SET NULL,
    FOREIGN KEY (src_ip) REFERENCES ip_addresses(ip_address) ON DELETE CASCADE,
    FOREIGN KEY (dst_ip) REFERENCES ip_addresses(ip_address) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ============================================
-- 6. ALERTS TABLE
-- ============================================
CREATE TABLE alerts (
    alert_id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    alert_type ENUM('malicious_url', 'suspicious_ip', 'high_traffic', 'dns_anomaly', 'geolocation_mismatch', 'frequency_attack', 'other') NOT NULL,
    severity ENUM('low', 'medium', 'high', 'critical') NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    destination_ip VARCHAR(45),
    url_id INT,
    description TEXT,
    status ENUM('new', 'acknowledged', 'investigating', 'resolved', 'false_positive') DEFAULT 'new',
    resolved_by VARCHAR(100),
    resolution_notes TEXT,
    resolved_at TIMESTAMP NULL,
    INDEX idx_timestamp (timestamp),
    INDEX idx_severity (severity),
    INDEX idx_status (status),
    INDEX idx_alert_type (alert_type),
    FOREIGN KEY (url_id) REFERENCES urls(url_id) ON DELETE SET NULL,
    FOREIGN KEY (source_ip) REFERENCES ip_addresses(ip_address) ON DELETE CASCADE,
    FOREIGN KEY (destination_ip) REFERENCES ip_addresses(ip_address) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ============================================
-- 7. MODEL PREDICTIONS TABLE
-- ============================================
CREATE TABLE model_predictions (
    prediction_id INT AUTO_INCREMENT PRIMARY KEY,
    url_id INT NOT NULL,
    ip_id INT,
    prediction_score DECIMAL(5, 4) NOT NULL,
    predicted_class ENUM('benign', 'malicious', 'suspicious') NOT NULL,
    model_name VARCHAR(100) NOT NULL,
    model_version VARCHAR(20) NOT NULL,
    prediction_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    features_used JSON,
    confidence_interval_lower DECIMAL(5, 4),
    confidence_interval_upper DECIMAL(5, 4),
    INDEX idx_url_prediction (url_id),
    INDEX idx_ip_prediction (ip_id),
    INDEX idx_prediction_timestamp (prediction_timestamp),
    INDEX idx_predicted_class (predicted_class),
    FOREIGN KEY (url_id) REFERENCES urls(url_id) ON DELETE CASCADE,
    FOREIGN KEY (ip_id) REFERENCES ip_addresses(ip_id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- ============================================
-- 8. FEATURE CACHE TABLE
-- ============================================
CREATE TABLE feature_cache (
    feature_id INT AUTO_INCREMENT PRIMARY KEY,
    url_id INT NOT NULL,
    feature_vector JSON NOT NULL,
    feature_count INT NOT NULL,
    extraction_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    processing_time_ms INT,
    INDEX idx_url_feature (url_id),
    INDEX idx_extraction_timestamp (extraction_timestamp),
    FOREIGN KEY (url_id) REFERENCES urls(url_id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ============================================
-- 9. USERS TABLE
-- ============================================
CREATE TABLE users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('admin', 'analyst', 'viewer') DEFAULT 'viewer',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL,
    INDEX idx_username (username),
    INDEX idx_email (email)
) ENGINE=InnoDB;

-- ============================================
-- 10. AUDIT LOGS TABLE
-- ============================================
CREATE TABLE audit_logs (
    audit_id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    action VARCHAR(100) NOT NULL,
    table_affected VARCHAR(50),
    record_id INT,
    old_values JSON,
    new_values JSON,
    ip_address VARCHAR(45),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user_audit (user_id),
    INDEX idx_timestamp (timestamp),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE SET NULL
) ENGINE=InnoDB;