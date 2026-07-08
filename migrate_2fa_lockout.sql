-- FireGuard Migration: Login attempt lockout + Two-Factor Authentication (TOTP)
-- Run this in SQL Server Management Studio or sqlcmd against fireguard_db.

USE fireguard_db;
GO

IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('users') AND name = 'failed_attempts')
    ALTER TABLE users ADD failed_attempts INT NOT NULL DEFAULT 0;
GO

IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('users') AND name = 'locked_until')
    ALTER TABLE users ADD locked_until DATETIME NULL;
GO

IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('users') AND name = 'totp_secret')
    ALTER TABLE users ADD totp_secret VARCHAR(64) NULL;
GO

IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('users') AND name = 'totp_enabled')
    ALTER TABLE users ADD totp_enabled BIT NOT NULL DEFAULT 0;
GO

PRINT 'users table updated: failed_attempts, locked_until, totp_secret, totp_enabled added.';
GO
