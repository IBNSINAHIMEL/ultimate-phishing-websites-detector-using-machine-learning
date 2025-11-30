-- Create Database
CREATE DATABASE IF NOT EXISTS phishing_detector_db;
USE phishing_detector_db;

-- Users Table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(80) UNIQUE NOT NULL,
    email VARCHAR(120) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL,
    is_active BOOLEAN DEFAULT TRUE,
    INDEX idx_username (username),
    INDEX idx_email (email)
);

-- Scan History Table
CREATE TABLE IF NOT EXISTS scan_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    url TEXT NOT NULL,
    is_phishing BOOLEAN NOT NULL,
    confidence FLOAT NOT NULL,
    scan_method VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_created_at (created_at),
    INDEX idx_is_phishing (is_phishing)
);

-- Threat Intelligence Cache Table (Optional - for performance)
CREATE TABLE IF NOT EXISTS threat_intelligence_cache (
    id INT AUTO_INCREMENT PRIMARY KEY,
    url_hash VARCHAR(64) UNIQUE NOT NULL,
    url TEXT NOT NULL,
    safe_browsing_result JSON,
    threat_types JSON,
    is_threat BOOLEAN,
    last_checked TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NULL,
    INDEX idx_url_hash (url_hash),
    INDEX idx_expires_at (expires_at)
);

-- Insert sample user (optional - for testing)
INSERT INTO users (username, email, password_hash) VALUES 
('demo_user', 'demo@example.com', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj89tiM7FEyK');

-- Display table structure
DESCRIBE users;
DESCRIBE scan_history;
DESCRIBE threat_intelligence_cache;

-- Show sample data
SELECT 'Users Table:' AS '';
SELECT * FROM users;

SELECT 'Scan History Table:' AS '';
SELECT * FROM scan_history;