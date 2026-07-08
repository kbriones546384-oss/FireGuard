-- FireGuard Database Schema for MySQL (PythonAnywhere)
-- Use this script in the PythonAnywhere MySQL console to initialize the tables.

CREATE TABLE IF NOT EXISTS users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100),
    password VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    failed_attempts INT NOT NULL DEFAULT 0,
    locked_until DATETIME NULL,
    totp_secret VARCHAR(64) NULL,
    totp_enabled TINYINT(1) NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS firewall_rules (
    rule_id INT AUTO_INCREMENT PRIMARY KEY,
    rule_name VARCHAR(100) NOT NULL,
    ip_address VARCHAR(45),
    port INT,
    protocol VARCHAR(10) NOT NULL,
    action_type VARCHAR(10) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'Active',
    created_by INT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS blocked_ips (
    block_id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL UNIQUE,
    reason VARCHAR(255),
    blocked_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id INT AUTO_INCREMENT PRIMARY KEY,
    alert_type VARCHAR(50) NOT NULL,
    ip_address VARCHAR(45),
    description VARCHAR(255) NOT NULL,
    alert_time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS traffic_logs (
    log_id INT AUTO_INCREMENT PRIMARY KEY,
    source_ip VARCHAR(45) NOT NULL,
    destination_ip VARCHAR(45) NOT NULL,
    port INT,
    protocol VARCHAR(10) NOT NULL,
    action_type VARCHAR(10) NOT NULL,
    log_time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS reports (
    report_id INT AUTO_INCREMENT PRIMARY KEY,
    report_name VARCHAR(100) NOT NULL,
    generated_by INT,
    report_type VARCHAR(20) NOT NULL,
    generated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS endpoints (
    endpoint_id INT AUTO_INCREMENT PRIMARY KEY,
    hostname VARCHAR(100) NOT NULL,
    ip_address VARCHAR(45),
    agent_token VARCHAR(100) NOT NULL UNIQUE,
    os_info VARCHAR(200),
    status VARCHAR(20) NOT NULL DEFAULT 'Offline',
    registered_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME NULL,
    mac_address VARCHAR(50) NULL,
    agent_version VARCHAR(20) NULL
);

CREATE TABLE IF NOT EXISTS endpoint_heartbeats (
    heartbeat_id INT AUTO_INCREMENT PRIMARY KEY,
    endpoint_id INT NOT NULL,
    cpu_percent DOUBLE,
    memory_percent DOUBLE,
    connection_count INT,
    firewall_active TINYINT(1) DEFAULT 0,
    reported_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (endpoint_id) REFERENCES endpoints(endpoint_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS endpoint_rule_deployments (
    deployment_id INT AUTO_INCREMENT PRIMARY KEY,
    endpoint_id INT NOT NULL,
    rule_id INT NOT NULL,
    deployed_by INT NULL,
    deployed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) NOT NULL DEFAULT 'Pending',
    result_message VARCHAR(500) NULL,
    FOREIGN KEY (endpoint_id) REFERENCES endpoints(endpoint_id) ON DELETE CASCADE,
    FOREIGN KEY (rule_id) REFERENCES firewall_rules(rule_id) ON DELETE CASCADE
);
