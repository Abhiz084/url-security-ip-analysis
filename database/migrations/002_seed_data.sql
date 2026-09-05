-- ============================================
-- Seed Data for Testing
-- ============================================

USE url_threat_analysis;

-- Insert default admin user (password: admin123)
INSERT INTO users (username, email, password_hash, role) VALUES
('admin', 'admin@urlsecurity.com', '$2b$12$LJ3m4ys3Lk0TSwHCpNqrNeqkYH7mPqZ0RQKVVwZCqMGVIgQpN7zOe', 'admin'),
('analyst1', 'analyst1@urlsecurity.com', '$2b$12$LJ3m4ys3Lk0TSwHCpNqrNeqkYH7mPqZ0RQKVVwZCqMGVIgQpN7zOe', 'analyst'),
('viewer1', 'viewer1@urlsecurity.com', '$2b$12$LJ3m4ys3Lk0TSwHCpNqrNeqkYH7mPqZ0RQKVVwZCqMGVIgQpN7zOe', 'viewer');

-- Insert sample malicious URLs
INSERT INTO urls (full_url, domain, path, protocol, tld, url_length, source, is_malicious) VALUES
('http://phishing-example.com/login.php', 'phishing-example.com', '/login.php', 'http', 'com', 38, 'test_data', TRUE),
('https://malware-download.net/payload.exe', 'malware-download.net', '/payload.exe', 'https', 'net', 42, 'test_data', TRUE),
('http://suspicious-site.ru/verify', 'suspicious-site.ru', '/verify', 'http', 'ru', 33, 'test_data', TRUE),
('https://google.com/search', 'google.com', '/search', 'https', 'com', 24, 'test_data', FALSE),
('https://github.com', 'github.com', '/', 'https', 'com', 19, 'test_data', FALSE);

-- Insert sample IP addresses
INSERT INTO ip_addresses (ip_address, ip_version, country, city, threat_score) VALUES
('192.168.1.100', 'IPv4', 'United States', 'New York', 85.50),
('10.0.0.50', 'IPv4', 'Russia', 'Moscow', 92.00),
('172.16.0.25', 'IPv4', 'China', 'Beijing', 75.30),
('8.8.8.8', 'IPv4', 'United States', 'Mountain View', 5.00),
('1.1.1.1', 'IPv4', 'Australia', 'Sydney', 2.00);

-- Insert sample threat intelligence
INSERT INTO threat_intelligence (ip_address, threat_type, confidence_score, source_feed, description) VALUES
('192.168.1.100', 'phishing', 85.00, 'AbuseIPDB', 'Known phishing server'),
('10.0.0.50', 'malware', 92.00, 'VirusTotal', 'Malware distribution center'),
('172.16.0.25', 'botnet', 75.00, 'AlienVault', 'Botnet command and control server');

-- Insert sample alerts
INSERT INTO alerts (alert_type, severity, source_ip, destination_ip, url_id, description, status) VALUES
('malicious_url', 'high', '192.168.1.100', '8.8.8.8', 1, 'Phishing URL detected in network traffic', 'new'),
('suspicious_ip', 'critical', '10.0.0.50', '8.8.8.8', 2, 'Malware distribution IP detected', 'investigating'),
('high_traffic', 'medium', '172.16.0.25', '1.1.1.1', NULL, 'Unusual traffic pattern detected', 'acknowledged');

-- Insert sample traffic logs
INSERT INTO traffic_logs (src_ip, dst_ip, src_port, dst_port, url_id, protocol, request_method, response_code) VALUES
('192.168.1.100', '8.8.8.8', 54321, 80, 1, 'HTTP', 'GET', 200),
('10.0.0.50', '8.8.8.8', 12345, 443, 2, 'HTTPS', 'POST', 200),
('172.16.0.25', '1.1.1.1', 33445, 80, 3, 'HTTP', 'GET', 403),
('8.8.8.8', '1.1.1.1', 443, 443, 4, 'HTTPS', 'GET', 200);