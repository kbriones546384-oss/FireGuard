-- FireGuard Database Fix Script
-- Run this in SQL Server Management Studio or sqlcmd
-- This fixes the ip_address column to support IPv6 addresses (up to 45 chars)

USE fireguard_db;
GO

-- Fix firewall_rules table
ALTER TABLE firewall_rules
    ALTER COLUMN ip_address VARCHAR(45);
GO

-- Fix blocked_ips table
ALTER TABLE blocked_ips
    ALTER COLUMN ip_address VARCHAR(45);
GO

-- Fix alerts table
ALTER TABLE alerts
    ALTER COLUMN ip_address VARCHAR(45);
GO

-- Fix traffic_logs source and destination IPs
ALTER TABLE traffic_logs
    ALTER COLUMN source_ip VARCHAR(45);
GO

ALTER TABLE traffic_logs
    ALTER COLUMN destination_ip VARCHAR(45);
GO

PRINT 'All ip_address columns updated to VARCHAR(45). IPv6 is now supported!';
GO
