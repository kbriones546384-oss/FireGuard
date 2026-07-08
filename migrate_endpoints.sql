-- FireGuard Endpoints Migration Script
-- Run in SQL Server Management Studio or via sqlcmd AFTER the original schema is in place.
-- Safe to re-run: uses IF NOT EXISTS guards.

USE fireguard_db;
GO

-- Table 1: endpoints
IF NOT EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = 'endpoints')
BEGIN
    CREATE TABLE endpoints (
        endpoint_id   INT IDENTITY(1,1) PRIMARY KEY,
        hostname      VARCHAR(100) NOT NULL,
        ip_address    VARCHAR(45),
        agent_token   VARCHAR(100) NOT NULL UNIQUE,
        os_info       VARCHAR(200),
        status        VARCHAR(20)  NOT NULL DEFAULT 'Offline',
        registered_at DATETIME     NOT NULL DEFAULT GETDATE(),
        last_seen     DATETIME
    );
    PRINT 'Created table: endpoints';
END
GO

-- Table 2: endpoint_heartbeats
IF NOT EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = 'endpoint_heartbeats')
BEGIN
    CREATE TABLE endpoint_heartbeats (
        heartbeat_id     INT IDENTITY(1,1) PRIMARY KEY,
        endpoint_id      INT     NOT NULL REFERENCES endpoints(endpoint_id) ON DELETE CASCADE,
        cpu_percent      FLOAT,
        memory_percent   FLOAT,
        connection_count INT,
        firewall_active  BIT,
        reported_at      DATETIME NOT NULL DEFAULT GETDATE()
    );
    PRINT 'Created table: endpoint_heartbeats';
END
GO

-- Table 3: endpoint_rule_deployments
IF NOT EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = 'endpoint_rule_deployments')
BEGIN
    CREATE TABLE endpoint_rule_deployments (
        deployment_id  INT IDENTITY(1,1) PRIMARY KEY,
        endpoint_id    INT NOT NULL REFERENCES endpoints(endpoint_id) ON DELETE CASCADE,
        rule_id        INT NOT NULL REFERENCES firewall_rules(rule_id),
        deployed_by    INT REFERENCES users(user_id),
        deployed_at    DATETIME NOT NULL DEFAULT GETDATE(),
        status         VARCHAR(20) NOT NULL DEFAULT 'Pending',
        result_message VARCHAR(500)
    );
    PRINT 'Created table: endpoint_rule_deployments';
END
GO

PRINT 'FireGuard endpoint migration complete.';
GO
