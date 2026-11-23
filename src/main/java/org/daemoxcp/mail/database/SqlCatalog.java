package org.daemoxcp.mail.database;

/**
 * Every SQL statement the panel runs, written once and fixed: the code uses
 * them by name and never builds SQL while it runs. A constant here is made only of text (and of other
 * constants of this file): SqlCatalogTest fails if one is built with a variable, or if SQL text appears
 * anywhere else in the panel. Values always go in as parameters (?), never into the text.
 */
public final class SqlCatalog {

    private SqlCatalog() {}

    /** MailDatabase.createDatabaseAndUser */
    public static final String MAIL_CREATE_PANEL_DATABASE = "CREATE DATABASE IF NOT EXISTS daemoxcp_mail CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci";

    /** MailDatabase.createDatabaseAndUser */
    public static final String MAIL_GRANT_PANEL_USER = "GRANT ALL PRIVILEGES ON daemoxcp_mail.* TO 'daemoxcp_mail'@'127.0.0.1'";

    /**
     * MailDatabase.createDatabaseAndUser; MailDbUsers, after changing the per-column privileges. Measured on the VM
     * on 2026-11-08 with MySQL 8.4.11 from the packages: a column revoked and granted again to a user who still has the
     * other columns of the same table shows up in mysql.columns_priv and in information_schema, but MySQL keeps
     * refusing it (1143) until the privileges are reloaded.
     */
    public static final String MAIL_FLUSH_PRIVILEGES = "FLUSH PRIVILEGES";

    /** MailDatabase.panelTables */
    public static final String MAIL_PANEL_TABLES = "SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE() ORDER BY table_name";

    /** MailDatabase.createSchema */
    public static final String MAIL_CREATE_SCHEMA = "CREATE TABLE IF NOT EXISTS panel_admin (\n"
            + "    id INT AUTO_INCREMENT PRIMARY KEY,\n"
            + "    username VARCHAR(50) NOT NULL UNIQUE,\n"
            + "    email_enc VARCHAR(512) NULL,\n"
            + "    email_index CHAR(64) CHARACTER SET ascii NULL,\n"
            + "    user_handle VARCHAR(64) CHARACTER SET ascii NULL,\n"
            + "    created_at DATETIME NULL,\n"
            + "    last_login DATETIME NULL,\n"
            + "    active BOOLEAN DEFAULT TRUE,\n"
            + "    role ENUM('superadmin', 'admin', 'operator', 'viewer') DEFAULT 'admin',\n"
            + "    theme VARCHAR(10) DEFAULT 'auto',\n"
            + "    language VARCHAR(5) NULL,\n"
            + "    UNIQUE KEY uq_admin_email_index (email_index),\n"
            + "    UNIQUE KEY uq_admin_user_handle (user_handle)\n"
            + ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4\n";

    /** MailDatabase.createSchema */
    public static final String MAIL_CREATE_SCHEMA_2 = "CREATE TABLE IF NOT EXISTS panel_settings (\n"
            + "    setting_key VARCHAR(64) PRIMARY KEY,\n"
            + "    setting_value TEXT NOT NULL,\n"
            + "    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP\n"
            + ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4\n";

    /** MailDatabase.createSchema */
    public static final String MAIL_CREATE_SCHEMA_3 = "CREATE TABLE IF NOT EXISTS installed_components (\n"
            + "    id INT AUTO_INCREMENT PRIMARY KEY,\n"
            + "    component_name VARCHAR(50) NOT NULL UNIQUE,\n"
            + "    version VARCHAR(20),\n"
            + "    installed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,\n"
            + "    status ENUM('installed', 'uninstalled', 'failed') DEFAULT 'installed'\n"
            + ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4\n";

    /** MailDatabase.createSchema */
    public static final String MAIL_CREATE_SCHEMA_4 = "CREATE TABLE IF NOT EXISTS cloudflare_accounts (\n"
            + "    id INT AUTO_INCREMENT PRIMARY KEY,\n"
            + "    label VARCHAR(100) NOT NULL,\n"
            + "    email VARCHAR(255) NULL,\n"
            + "    api_token TEXT NOT NULL,\n"
            + "    verified_at TIMESTAMP NULL,\n"
            + "    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP\n"
            + ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4\n";

    /** MailDatabase.createSchema */
    public static final String MAIL_CREATE_SCHEMA_5 = "CREATE TABLE IF NOT EXISTS dkim_rotation_history (\n"
            + "    id INT AUTO_INCREMENT PRIMARY KEY,\n"
            + "    domain_id INT NOT NULL,\n"
            + "    domain VARCHAR(255) NOT NULL,\n"
            + "    event_type VARCHAR(32) NOT NULL,\n"
            + "    selector VARCHAR(50) NULL,\n"
            + "    mode VARCHAR(16) NULL,\n"
            + "    triggered_by VARCHAR(16) NULL,\n"
            + "    cloudflare_account_id INT NULL,\n"
            + "    cloudflare_account_label VARCHAR(100) NULL,\n"
            + "    success BOOLEAN DEFAULT TRUE,\n"
            + "    message TEXT NULL,\n"
            + "    occurred_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,\n"
            + "    INDEX idx_domain_time (domain_id, occurred_at)\n"
            + ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4\n";

    /** MailDatabase.createSchema */
    public static final String MAIL_CREATE_SCHEMA_6 = "CREATE TABLE IF NOT EXISTS domains (\n"
            + "    id INT AUTO_INCREMENT PRIMARY KEY,\n"
            + "    domain VARCHAR(255) NOT NULL UNIQUE,\n"
            + "    description TEXT,\n"
            + "    active BOOLEAN DEFAULT TRUE,\n"
            + "    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,\n"
            + "    dkim_selector VARCHAR(50) DEFAULT 'mail',\n"
            + "    dkim_private_key TEXT,\n"
            + "    dkim_public_key TEXT,\n"
            + "    -- DKIM rotation (selector \"pending\" while the current key stays in dkim_*)\n"
            + "    dkim_pending_selector VARCHAR(50) NULL,\n"
            + "    dkim_pending_private_key TEXT NULL,\n"
            + "    dkim_pending_public_key TEXT NULL,\n"
            + "    dkim_rotation_state VARCHAR(32) NULL,           -- 'pending_dns', 'propagated', 'active_grace', 'completed'\n"
            + "    dkim_rotation_started_at TIMESTAMP NULL,\n"
            + "    dkim_rotation_activated_at TIMESTAMP NULL,\n"
            + "    -- Old key kept during the grace period (to validate mail in transit)\n"
            + "    dkim_previous_selector VARCHAR(50) NULL,\n"
            + "    dkim_previous_private_key TEXT NULL,\n"
            + "    dkim_previous_public_key TEXT NULL,\n"
            + "    -- Cloudflare automation (DNS zone and ids of the TXT records created through the API)\n"
            + "    dkim_dns_zone_id VARCHAR(64) NULL,\n"
            + "    dkim_pending_dns_record_id VARCHAR(64) NULL,\n"
            + "    dkim_previous_dns_record_id VARCHAR(64) NULL,\n"
            + "    -- Cloudflare account assigned (NULL = none, manual rotation)\n"
            + "    cloudflare_account_id INT NULL,\n"
            + "    -- Scheduled rotation: every how many days the key is regenerated (0 = off)\n"
            + "    dkim_rotation_interval_days INT NOT NULL DEFAULT 0,\n"
            + "    -- Timestamp of the last rotation completed successfully (set at key_activated)\n"
            + "    dkim_last_rotation_at TIMESTAMP NULL,\n"
            + "    -- Mode of the current rotation (\"automatic\"/\"manual\"), inherited by every event of the chain\n"
            + "    dkim_rotation_mode VARCHAR(16) NULL\n"
            + ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4\n";

    /** MailDatabase.createSchema */
    public static final String MAIL_CREATE_SCHEMA_7 = "CREATE TABLE IF NOT EXISTS mailboxes (\n"
            + "    id INT AUTO_INCREMENT PRIMARY KEY,\n"
            + "    domain_id INT NOT NULL,\n"
            + "    email VARCHAR(255) NOT NULL UNIQUE,\n"
            + "    password VARCHAR(255) NOT NULL,\n"
            + "    password_encrypted TEXT NULL,\n"
            + "    password_encrypted_at TIMESTAMP NULL,\n"
            + "    name VARCHAR(255),\n"
            + "    quota_mb INT DEFAULT 1024,\n"
            + "    active BOOLEAN DEFAULT TRUE,\n"
            + "    receive_enabled BOOLEAN DEFAULT TRUE,\n"
            + "    junk_expunge_days SMALLINT UNSIGNED NOT NULL DEFAULT 0,\n"
            + "    trash_expunge_days SMALLINT UNSIGNED NOT NULL DEFAULT 0,\n"
            + "    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,\n"
            + "    last_login TIMESTAMP NULL,\n"
            + "    FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE\n"
            + ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4\n";

    /** MailDatabase.createSchema */
    public static final String MAIL_CREATE_SCHEMA_8 = "CREATE TABLE IF NOT EXISTS aliases (\n"
            + "    id INT AUTO_INCREMENT PRIMARY KEY,\n"
            + "    domain_id INT NOT NULL,\n"
            + "    source VARCHAR(255) NOT NULL,\n"
            + "    destination VARCHAR(255) NOT NULL,\n"
            + "    active BOOLEAN DEFAULT TRUE,\n"
            + "    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,\n"
            + "    FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE,\n"
            + "    UNIQUE KEY unique_alias (source, destination)\n"
            + ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4\n";

    /** MailDatabase.createSchema */
    public static final String MAIL_CREATE_SCHEMA_9 = "CREATE TABLE IF NOT EXISTS roundcube_tokens (\n"
            + "    token VARCHAR(64) PRIMARY KEY,\n"
            + "    mailbox_id INT NOT NULL,\n"
            + "    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,\n"
            + "    expires_at TIMESTAMP NOT NULL,\n"
            + "    used BOOLEAN DEFAULT FALSE,\n"
            + "    FOREIGN KEY (mailbox_id) REFERENCES mailboxes(id) ON DELETE CASCADE\n"
            + ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4\n";

    /** MailDatabase.createSchema */
    public static final String MAIL_CREATE_SCHEMA_10 = "CREATE TABLE IF NOT EXISTS auto_responders (\n"
            + "    id INT AUTO_INCREMENT PRIMARY KEY,\n"
            + "    mailbox_id INT NOT NULL UNIQUE,\n"
            + "    enabled BOOLEAN DEFAULT FALSE,\n"
            + "    subject VARCHAR(255) NOT NULL DEFAULT 'Out of Office',\n"
            + "    body TEXT NOT NULL,\n"
            + "    start_date DATE NULL,\n"
            + "    end_date DATE NULL,\n"
            + "    interval_hours INT DEFAULT 24,\n"
            + "    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,\n"
            + "    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,\n"
            + "    FOREIGN KEY (mailbox_id) REFERENCES mailboxes(id) ON DELETE CASCADE\n"
            + ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4\n";

    /** MailDatabase.createSchema */
    public static final String MAIL_CREATE_SCHEMA_11 = "CREATE TABLE IF NOT EXISTS sieve_filters (\n"
            + "    id INT AUTO_INCREMENT PRIMARY KEY,\n"
            + "    mailbox_id INT NOT NULL,\n"
            + "    name VARCHAR(100) NOT NULL,\n"
            + "    priority INT DEFAULT 0,\n"
            + "    enabled BOOLEAN DEFAULT TRUE,\n"
            + "    conditions JSON NOT NULL,\n"
            + "    actions JSON NOT NULL,\n"
            + "    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,\n"
            + "    FOREIGN KEY (mailbox_id) REFERENCES mailboxes(id) ON DELETE CASCADE\n"
            + ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4\n";

    /** MailDatabase.createSchema */
    public static final String MAIL_CREATE_SCHEMA_12 = "CREATE TABLE IF NOT EXISTS forwarding_rules (\n"
            + "    id INT AUTO_INCREMENT PRIMARY KEY,\n"
            + "    mailbox_id INT NOT NULL,\n"
            + "    destination VARCHAR(255) NOT NULL,\n"
            + "    keep_copy BOOLEAN DEFAULT TRUE,\n"
            + "    enabled BOOLEAN DEFAULT TRUE,\n"
            + "    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,\n"
            + "    FOREIGN KEY (mailbox_id) REFERENCES mailboxes(id) ON DELETE CASCADE\n"
            + ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4\n";

    /** MailDatabase.createSchema */
    public static final String MAIL_CREATE_SCHEMA_13 = "CREATE TABLE IF NOT EXISTS rate_limits (\n"
            + "    id INT AUTO_INCREMENT PRIMARY KEY,\n"
            + "    target_type ENUM('global', 'domain', 'mailbox') NOT NULL,\n"
            + "    target_id INT NULL,\n"
            + "    max_per_hour INT DEFAULT 100,\n"
            + "    max_per_day INT DEFAULT 1000,\n"
            + "    max_recipients INT DEFAULT 50,\n"
            + "    enabled BOOLEAN DEFAULT TRUE,\n"
            + "    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,\n"
            + "    UNIQUE KEY unique_target (target_type, target_id)\n"
            + ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4\n";

    /** MailDatabase.createSchema */
    public static final String MAIL_CREATE_SCHEMA_14 = "CREATE TABLE IF NOT EXISTS email_statistics (\n"
            + "    id INT AUTO_INCREMENT PRIMARY KEY,\n"
            + "    stat_date DATE NOT NULL,\n"
            + "    mailbox_id INT NULL,\n"
            + "    domain_id INT NULL,\n"
            + "    sent_count INT DEFAULT 0,\n"
            + "    received_count INT DEFAULT 0,\n"
            + "    spam_count INT DEFAULT 0,\n"
            + "    virus_count INT DEFAULT 0,\n"
            + "    bounced_count INT DEFAULT 0,\n"
            + "    bytes_sent BIGINT DEFAULT 0,\n"
            + "    bytes_received BIGINT DEFAULT 0,\n"
            + "    UNIQUE KEY unique_daily_stat (stat_date, mailbox_id, domain_id),\n"
            + "    FOREIGN KEY (mailbox_id) REFERENCES mailboxes(id) ON DELETE SET NULL,\n"
            + "    FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE SET NULL\n"
            + ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4\n";

    /** MailDatabase.createSchema */
    public static final String MAIL_CREATE_SCHEMA_15 = "CREATE TABLE IF NOT EXISTS rspamd_training (\n"
            + "    id INT AUTO_INCREMENT PRIMARY KEY,\n"
            + "    message_id VARCHAR(255) NOT NULL,\n"
            + "    trained_as ENUM('spam', 'ham') NOT NULL,\n"
            + "    trained_by INT NOT NULL,\n"
            + "    trained_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,\n"
            + "    FOREIGN KEY (trained_by) REFERENCES panel_admin(id)\n"
            + ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4\n";

    /** MailDatabase.createSchema */
    public static final String MAIL_CREATE_SCHEMA_16 = "CREATE TABLE IF NOT EXISTS audit_log (\n"
            + "    id INT AUTO_INCREMENT PRIMARY KEY,\n"
            + "    action VARCHAR(100) NOT NULL,\n"
            + "    username VARCHAR(255),\n"
            + "    ip_address VARCHAR(45) NOT NULL,\n"
            + "    details TEXT,\n"
            + "    user_agent VARCHAR(512),\n"
            + "    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,\n"
            + "    INDEX idx_action (action),\n"
            + "    INDEX idx_username (username),\n"
            + "    INDEX idx_ip (ip_address),\n"
            + "    INDEX idx_created (created_at)\n"
            + ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4\n";

    /** MailDatabase.createSchema */
    public static final String MAIL_CREATE_SCHEMA_17 = "CREATE TABLE IF NOT EXISTS admin_passkeys (\n"
            + "    id INT AUTO_INCREMENT PRIMARY KEY,\n"
            + "    admin_id INT NOT NULL,\n"
            + "    credential_id VARBINARY(1024) NOT NULL,\n"
            + "    public_key_cose VARBINARY(2048) NOT NULL,\n"
            + "    sign_count BIGINT DEFAULT 0,\n"
            + "    name VARCHAR(100) DEFAULT 'Passkey',\n"
            + "    aaguid VARBINARY(16) NULL,\n"
            + "    user_handle VARCHAR(64) CHARACTER SET ascii NULL,\n"
            + "    rp_id VARCHAR(253) CHARACTER SET ascii NULL,\n"
            + "    created_at DATETIME NULL,\n"
            + "    last_used DATETIME NULL,\n"
            + "    FOREIGN KEY (admin_id) REFERENCES panel_admin(id) ON DELETE CASCADE,\n"
            + "    UNIQUE KEY unique_credential (credential_id(255))\n"
            + ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4\n";

    /** MailDatabase.ensurePasswordlessSchema */
    public static final String MAIL_ENSURE_PASSWORDLESS_SCHEMA = "SET time_zone = '+00:00'";

    /** MailDatabase.ensurePasswordlessSchema */
    public static final String MAIL_ENSURE_PASSWORDLESS_SCHEMA_2 = "ALTER TABLE panel_admin ADD COLUMN email_enc VARCHAR(512) NULL";

    /** MailDatabase.ensurePasswordlessSchema */
    public static final String MAIL_ENSURE_PASSWORDLESS_SCHEMA_3 = "ALTER TABLE panel_admin ADD COLUMN email_index CHAR(64) CHARACTER SET ascii NULL, ADD UNIQUE KEY uq_admin_email_index (email_index)";

    /** MailDatabase.ensurePasswordlessSchema */
    public static final String MAIL_ENSURE_PASSWORDLESS_SCHEMA_4 = "ALTER TABLE panel_admin ADD COLUMN user_handle VARCHAR(64) CHARACTER SET ascii NULL, ADD UNIQUE KEY uq_admin_user_handle (user_handle)";

    /** MailDatabase.ensurePasswordlessSchema */
    public static final String MAIL_ENSURE_PASSWORDLESS_SCHEMA_5 = "ALTER TABLE panel_admin MODIFY created_at DATETIME NULL";

    /** MailDatabase.ensurePasswordlessSchema */
    public static final String MAIL_ENSURE_PASSWORDLESS_SCHEMA_6 = "ALTER TABLE panel_admin MODIFY last_login DATETIME NULL";

    /** MailDatabase.ensurePasswordlessSchema */
    public static final String MAIL_ENSURE_PASSWORDLESS_SCHEMA_7 = "ALTER TABLE admin_passkeys ADD COLUMN user_handle VARCHAR(64) CHARACTER SET ascii NULL";

    /** MailDatabase.ensurePasswordlessSchema */
    public static final String MAIL_ENSURE_PASSWORDLESS_SCHEMA_8 = "ALTER TABLE admin_passkeys ADD COLUMN rp_id VARCHAR(253) CHARACTER SET ascii NULL";

    /** MailDatabase.ensurePasswordlessSchema */
    public static final String MAIL_ENSURE_PASSWORDLESS_SCHEMA_9 = "ALTER TABLE admin_passkeys MODIFY created_at DATETIME NULL";

    /** MailDatabase.ensurePasswordlessSchema */
    public static final String MAIL_ENSURE_PASSWORDLESS_SCHEMA_10 = "ALTER TABLE admin_passkeys MODIFY last_used DATETIME NULL";

    /** MailDatabase.columnType */
    public static final String MAIL_COLUMN_TYPE = "SELECT DATA_TYPE FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ?";

    /** MailDatabase.hasAdminUser */
    public static final String MAIL_HAS_ADMIN_USER = "SELECT 1 FROM panel_admin WHERE active = TRUE LIMIT 1";

    /** MailDatabase.getAdminTheme */
    public static final String MAIL_GET_ADMIN_THEME = "SELECT theme FROM panel_admin WHERE username = ?";

    /** MailDatabase.setAdminTheme */
    public static final String MAIL_SET_ADMIN_THEME = "UPDATE panel_admin SET theme = ? WHERE username = ?";

    /** MailDatabase.getAdminLanguage */
    public static final String MAIL_GET_ADMIN_LANGUAGE = "SELECT language FROM panel_admin WHERE username = ?";

    /** MailDatabase.getPanelLanguage: the console language, that of the first active administrator who has chosen one. */
    public static final String MAIL_GET_PANEL_LANGUAGE = "SELECT language FROM panel_admin WHERE language IS NOT NULL AND active = TRUE ORDER BY id LIMIT 1";

    /** MailDatabase.setAdminLanguage */
    public static final String MAIL_SET_ADMIN_LANGUAGE = "UPDATE panel_admin SET language = ? WHERE username = ?";

    /** MailDatabase.ensureLanguageColumn */
    public static final String MAIL_ENSURE_LANGUAGE_COLUMN = "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'panel_admin' AND column_name = 'language'";

    /** MailDatabase.ensureLanguageColumn */
    public static final String MAIL_ENSURE_LANGUAGE_COLUMN_2 = "ALTER TABLE panel_admin ADD COLUMN language VARCHAR(5) NULL";

    /** MailDatabase.ensureCloudflareAccountsSchema */
    public static final String MAIL_ENSURE_CLOUDFLARE_ACCOUNTS_SCHEMA = "CREATE TABLE IF NOT EXISTS cloudflare_accounts (id INT AUTO_INCREMENT PRIMARY KEY, label VARCHAR(100) NOT NULL, email VARCHAR(255) NULL, api_token TEXT NOT NULL, verified_at TIMESTAMP NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";

    /** MailDatabase.ensureCloudflareAccountsSchema */
    public static final String MAIL_ENSURE_CLOUDFLARE_ACCOUNTS_SCHEMA_2 = "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'domains' AND column_name = 'cloudflare_account_id'";

    /** MailDatabase.ensureCloudflareAccountsSchema */
    public static final String MAIL_ENSURE_CLOUDFLARE_ACCOUNTS_SCHEMA_3 = "ALTER TABLE domains ADD COLUMN cloudflare_account_id INT NULL";

    /** MailDatabase.ensureCloudflareAccountsSchema */
    public static final String MAIL_ENSURE_CLOUDFLARE_ACCOUNTS_SCHEMA_4 = "SELECT COUNT(*) FROM cloudflare_accounts";

    /** MailDatabase.ensureCloudflareAccountsSchema */
    public static final String MAIL_ENSURE_CLOUDFLARE_ACCOUNTS_SCHEMA_5 = "INSERT INTO cloudflare_accounts (label, email, api_token, verified_at) VALUES (?, NULL, ?, CURRENT_TIMESTAMP)";

    /** MailDatabase.ensureCloudflareAccountsSchema */
    public static final String MAIL_ENSURE_CLOUDFLARE_ACCOUNTS_SCHEMA_6 = "UPDATE domains SET cloudflare_account_id = ? WHERE cloudflare_account_id IS NULL";

    /** MailDatabase.ensureDkimRotationHistoryTable */
    public static final String MAIL_ENSURE_DKIM_ROTATION_HISTORY_TABLE = "CREATE TABLE IF NOT EXISTS dkim_rotation_history (id INT AUTO_INCREMENT PRIMARY KEY, domain_id INT NOT NULL, domain VARCHAR(255) NOT NULL, event_type VARCHAR(32) NOT NULL, selector VARCHAR(50) NULL, previous_selector VARCHAR(50) NULL, mode VARCHAR(16) NULL, triggered_by VARCHAR(16) NULL, cloudflare_account_id INT NULL, cloudflare_account_label VARCHAR(100) NULL, success BOOLEAN DEFAULT TRUE, message TEXT NULL, occurred_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, INDEX idx_domain_time (domain_id, occurred_at), INDEX idx_prev_selector (domain_id, previous_selector)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";

    /** MailDatabase.ensureDkimRotationHistoryTable */
    public static final String MAIL_ENSURE_DKIM_ROTATION_HISTORY_TABLE_2 = "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'dkim_rotation_history' AND column_name = 'triggered_by'";

    /** MailDatabase.ensureDkimRotationHistoryTable */
    public static final String MAIL_ENSURE_DKIM_ROTATION_HISTORY_TABLE_3 = "ALTER TABLE dkim_rotation_history ADD COLUMN triggered_by VARCHAR(16) NULL AFTER mode";

    /** MailDatabase.ensureDkimRotationHistoryTable */
    public static final String MAIL_ENSURE_DKIM_ROTATION_HISTORY_TABLE_4 = "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'dkim_rotation_history' AND column_name = 'previous_selector'";

    /** MailDatabase.ensureDkimRotationHistoryTable */
    public static final String MAIL_ENSURE_DKIM_ROTATION_HISTORY_TABLE_5 = "ALTER TABLE dkim_rotation_history ADD COLUMN previous_selector VARCHAR(50) NULL AFTER selector";

    /** MailDatabase.ensureDkimRotationHistoryTable */
    public static final String MAIL_ENSURE_DKIM_ROTATION_HISTORY_TABLE_6 = "ALTER TABLE dkim_rotation_history ADD INDEX idx_prev_selector (domain_id, previous_selector)";

    /** MailDatabase.logDkimRotationEvent */
    public static final String MAIL_LOG_DKIM_ROTATION_EVENT = "INSERT INTO dkim_rotation_history (domain_id, domain, event_type, selector, previous_selector, mode, triggered_by, cloudflare_account_id, cloudflare_account_label, success, message, occurred_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

    /** MailDatabase.findSelectorDeactivationTime */
    public static final String MAIL_FIND_SELECTOR_DEACTIVATION_TIME = "SELECT occurred_at FROM dkim_rotation_history WHERE domain_id = ? AND event_type = 'key_activated' AND previous_selector = ? ORDER BY occurred_at DESC, id DESC LIMIT 1";

    /** MailDatabase.getDkimRotationHistory */
    public static final String MAIL_GET_DKIM_ROTATION_HISTORY = "SELECT * FROM dkim_rotation_history WHERE domain_id = ? ORDER BY occurred_at DESC, id DESC LIMIT ?";

    /** MailDatabase.ensureThemeColumn */
    public static final String MAIL_ENSURE_THEME_COLUMN = "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'panel_admin' AND column_name = 'theme'";

    /** MailDatabase.ensureThemeColumn */
    public static final String MAIL_ENSURE_THEME_COLUMN_2 = "ALTER TABLE panel_admin ADD COLUMN theme VARCHAR(10) DEFAULT 'auto'";

    /** MailDatabase.getSetting */
    public static final String MAIL_GET_SETTING = "SELECT setting_value FROM panel_settings WHERE setting_key = ?";

    /** MailDatabase.setSetting */
    public static final String MAIL_SET_SETTING = "INSERT INTO panel_settings (setting_key, setting_value) VALUES (?, ?)\n"
            + "ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)\n";

    /** MailDatabase.deleteSetting */
    public static final String MAIL_DELETE_SETTING = "DELETE FROM panel_settings WHERE setting_key = ?";

    /** MailDatabase.addCloudflareAccount */
    public static final String MAIL_ADD_CLOUDFLARE_ACCOUNT = "INSERT INTO cloudflare_accounts (label, email, api_token, verified_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)";

    /** MailDatabase.updateCloudflareAccount */
    public static final String MAIL_UPDATE_CLOUDFLARE_ACCOUNT = "UPDATE cloudflare_accounts SET label = ?, email = ? WHERE id = ?";

    /** MailDatabase.updateCloudflareAccountToken */
    public static final String MAIL_UPDATE_CLOUDFLARE_ACCOUNT_TOKEN = "UPDATE cloudflare_accounts SET api_token = ?, verified_at = CURRENT_TIMESTAMP WHERE id = ?";

    /** MailDatabase.cloudflareStoredTokens */
    public static final String MAIL_LIST_CLOUDFLARE_STORED_TOKENS = "SELECT id, api_token FROM cloudflare_accounts ORDER BY id";

    /** MailDatabase.replaceCloudflareStoredToken */
    public static final String MAIL_REPLACE_CLOUDFLARE_STORED_TOKEN = "UPDATE cloudflare_accounts SET api_token = ? WHERE id = ? AND api_token = ?";

    /** MailDatabase.deleteCloudflareAccount */
    public static final String MAIL_DELETE_CLOUDFLARE_ACCOUNT = "UPDATE domains SET cloudflare_account_id = NULL WHERE cloudflare_account_id = ?";

    /** MailDatabase.deleteCloudflareAccount */
    public static final String MAIL_DELETE_CLOUDFLARE_ACCOUNT_2 = "DELETE FROM cloudflare_accounts WHERE id = ?";

    /** MailDatabase.getCloudflareAccount */
    public static final String MAIL_GET_CLOUDFLARE_ACCOUNT = "SELECT * FROM cloudflare_accounts WHERE id = ?";

    /** MailDatabase.listCloudflareAccounts */
    public static final String MAIL_LIST_CLOUDFLARE_ACCOUNTS = "SELECT * FROM cloudflare_accounts ORDER BY id ASC";

    /** MailDatabase.getCloudflareAccountForDomain */
    public static final String MAIL_GET_CLOUDFLARE_ACCOUNT_FOR_DOMAIN = "SELECT c.* FROM cloudflare_accounts c INNER JOIN domains d ON d.cloudflare_account_id = c.id WHERE d.id = ?";

    /** MailDatabase.assignCloudflareAccountToDomain */
    public static final String MAIL_ASSIGN_CLOUDFLARE_ACCOUNT_TO_DOMAIN = "UPDATE domains SET cloudflare_account_id = ? WHERE id = ?";

    /** MailDatabase.isComponentInstalled */
    public static final String MAIL_IS_COMPONENT_INSTALLED = "SELECT 1 FROM installed_components WHERE component_name = ? AND status = 'installed'";

    /** MailDatabase.markComponentInstalled */
    public static final String MAIL_MARK_COMPONENT_INSTALLED = "INSERT INTO installed_components (component_name, version, status)\n"
            + "VALUES (?, ?, 'installed')\n"
            + "ON DUPLICATE KEY UPDATE\n"
            + "    version = VALUES(version),\n"
            + "    installed_at = CURRENT_TIMESTAMP,\n"
            + "    status = 'installed'\n";

    /** MailDatabase.markComponentUninstalled */
    public static final String MAIL_MARK_COMPONENT_UNINSTALLED = "UPDATE installed_components SET status = 'uninstalled' WHERE component_name = ?";

    /** MailDatabase.getInstalledComponentsJson */
    public static final String MAIL_GET_INSTALLED_COMPONENTS_JSON = "SELECT component_name, version, installed_at FROM installed_components WHERE status = 'installed'";

    /** MailDatabase.addDomain */
    public static final String MAIL_ADD_DOMAIN = "INSERT INTO domains (domain, description) VALUES (?, ?)";

    /** MailDatabase.deleteDomain */
    public static final String MAIL_DELETE_DOMAIN = "DELETE FROM domains WHERE id = ?";

    /** MailDatabase.updateDomainStatus */
    public static final String MAIL_UPDATE_DOMAIN_STATUS = "UPDATE domains SET active = ? WHERE id = ?";

    /** MailDatabase.updateDomainDescription */
    public static final String MAIL_UPDATE_DOMAIN_DESCRIPTION = "UPDATE domains SET description = ? WHERE id = ?";

    /** MailDatabase.getDomain */
    public static final String MAIL_GET_DOMAIN = "SELECT * FROM domains WHERE id = ?";

    /** MailDatabase.getDomainByName */
    public static final String MAIL_GET_DOMAIN_BY_NAME = "SELECT * FROM domains WHERE domain = ?";

    /** MailDatabase.getDomains */
    /**
     * DomainCache: the names of the hosted domains, for autoconfig and MTA-STS (in the web part, the public procedure
     * list_domain_names)
     */
    public static final String MAIL_GET_DOMAIN_NAMES = "SELECT domain FROM domains ORDER BY domain";

    public static final String MAIL_GET_DOMAINS = "SELECT d.*,\n"
            + "       (SELECT COUNT(*) FROM mailboxes m WHERE m.domain_id = d.id) as mailbox_count,\n"
            + "       (SELECT COUNT(*) FROM aliases a WHERE a.domain_id = d.id) as alias_count\n"
            + "FROM domains d ORDER BY d.domain\n";

    /** MailDatabase.setDkim */
    public static final String MAIL_SET_DKIM = "UPDATE domains SET dkim_selector = ?, dkim_private_key = ?, dkim_public_key = ? WHERE id = ?";

    /** MailDatabase.setDkimPending */
    public static final String MAIL_SET_DKIM_PENDING = "UPDATE domains SET dkim_pending_selector = ?, dkim_pending_private_key = ?, dkim_pending_public_key = ?, dkim_rotation_state = ?, dkim_rotation_mode = ?, dkim_rotation_started_at = ?, dkim_rotation_activated_at = NULL WHERE id = ?";

    /** MailDatabase.setDkimRotationState */
    public static final String MAIL_SET_DKIM_ROTATION_STATE = "UPDATE domains SET dkim_rotation_state = ? WHERE id = ?";

    /** MailDatabase.promotePendingToActive */
    public static final String MAIL_PROMOTE_PENDING_TO_ACTIVE = "UPDATE domains SET dkim_previous_selector = dkim_selector, dkim_previous_private_key = dkim_private_key, dkim_previous_public_key = dkim_public_key, dkim_previous_dns_record_id = NULL, dkim_selector = dkim_pending_selector, dkim_private_key = dkim_pending_private_key, dkim_public_key = dkim_pending_public_key, dkim_pending_selector = NULL, dkim_pending_private_key = NULL, dkim_pending_public_key = NULL, dkim_pending_dns_record_id = NULL, dkim_rotation_state = 'active_grace', dkim_rotation_activated_at = ? WHERE id = ?";

    /** MailDatabase.setDkimPendingCloudflareIds */
    public static final String MAIL_SET_DKIM_PENDING_CLOUDFLARE_IDS = "UPDATE domains SET dkim_dns_zone_id = ?, dkim_pending_dns_record_id = ? WHERE id = ?";

    /** MailDatabase.clearDkimPending */
    public static final String MAIL_CLEAR_DKIM_PENDING = "UPDATE domains SET dkim_pending_selector = NULL, dkim_pending_private_key = NULL, dkim_pending_public_key = NULL, dkim_rotation_state = NULL, dkim_rotation_mode = NULL, dkim_rotation_started_at = NULL, dkim_rotation_activated_at = NULL WHERE id = ?";

    /** MailDatabase.clearDkimPrevious */
    public static final String MAIL_CLEAR_DKIM_PREVIOUS = "UPDATE domains SET dkim_previous_selector = NULL, dkim_previous_private_key = NULL, dkim_previous_public_key = NULL, dkim_rotation_state = NULL, dkim_rotation_mode = NULL, dkim_rotation_started_at = NULL, dkim_rotation_activated_at = NULL WHERE id = ?";

    /** MailDatabase.setDkimRotationInterval */
    public static final String MAIL_SET_DKIM_ROTATION_INTERVAL = "UPDATE domains SET dkim_rotation_interval_days = ? WHERE id = ?";

    /** MailDatabase.markDkimRotationActivated */
    public static final String MAIL_MARK_DKIM_ROTATION_ACTIVATED = "UPDATE domains SET dkim_last_rotation_at = ? WHERE id = ?";

    /** MailDatabase.clearDkimLastRotation */
    public static final String MAIL_CLEAR_DKIM_LAST_ROTATION = "UPDATE domains SET dkim_last_rotation_at = NULL WHERE id = ?";

    /** MailDatabase.getDomainsWithRotationSchedule */
    public static final String MAIL_GET_DOMAINS_WITH_ROTATION_SCHEDULE = "SELECT * FROM domains WHERE dkim_rotation_interval_days > 0";

    /** MailDatabase.getDomainsInRotation */
    public static final String MAIL_GET_DOMAINS_IN_ROTATION = "SELECT * FROM domains WHERE dkim_rotation_state IS NOT NULL";

    /** MailDatabase.insertMailbox */
    public static final String MAIL_INSERT_MAILBOX = "INSERT INTO mailboxes (domain_id, email, password, password_encrypted, password_encrypted_at, name, quota_mb, receive_enabled) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";

    /** MailDatabase.deleteMailbox */
    public static final String MAIL_DELETE_MAILBOX = "DELETE FROM mailboxes WHERE id = ?";

    /** MailDatabase.updateMailboxPassword */
    public static final String MAIL_UPDATE_MAILBOX_PASSWORD = "UPDATE mailboxes SET password = ?, password_encrypted = ?, password_encrypted_at = ? WHERE id = ?";

    /** MailDatabase.mailboxPasswordMatches */
    public static final String MAIL_MAILBOX_PASSWORD_MATCHES = "SELECT password FROM mailboxes WHERE id = ?";

    /** MailDatabase.fillMissingVaultCopy */
    public static final String MAIL_FILL_MISSING_VAULT_COPY = "UPDATE mailboxes SET password_encrypted = ?, password_encrypted_at = ? WHERE id = ?";

    /** MailDatabase.repairPlaintextMailboxPasswords */
    public static final String MAIL_REPAIR_PLAINTEXT_MAILBOX_PASSWORDS = "SELECT id, password FROM mailboxes";

    /** MailDatabase.repairPlaintextMailboxPasswords */
    public static final String MAIL_REPAIR_PLAINTEXT_MAILBOX_PASSWORDS_2 = "UPDATE mailboxes SET password = ?, password_encrypted = ?, password_encrypted_at = ? WHERE id = ? AND password = ?";

    /** MailDatabase.getMailboxPasswordEncrypted */
    public static final String MAIL_GET_MAILBOX_PASSWORD_ENCRYPTED = "SELECT password_encrypted FROM mailboxes WHERE id = ?";

    /** MailDatabase.mailboxHasEncryptedPassword */
    public static final String MAIL_MAILBOX_HAS_ENCRYPTED_PASSWORD = "SELECT 1 FROM mailboxes WHERE id = ? AND password_encrypted IS NOT NULL AND password_encrypted <> ''";

    /** MailDatabase.listMailboxesWithEncryptedPassword */
    public static final String MAIL_LIST_MAILBOXES_WITH_ENCRYPTED_PASSWORD = "SELECT id FROM mailboxes WHERE password_encrypted IS NOT NULL AND password_encrypted <> ''";

    /** MailDatabase.listMailboxesWithEncryptedPasswordAndBlob */
    public static final String MAIL_LIST_MAILBOXES_WITH_ENCRYPTED_PASSWORD_AND_BLOB = "SELECT id, password_encrypted FROM mailboxes WHERE password_encrypted IS NOT NULL AND password_encrypted <> ''";

    /** MailDatabase.updateMailboxStatus */
    public static final String MAIL_UPDATE_MAILBOX_STATUS = "UPDATE mailboxes SET active = ? WHERE id = ?";

    /** MailDatabase.updateMailboxQuota */
    public static final String MAIL_UPDATE_MAILBOX_QUOTA = "UPDATE mailboxes SET quota_mb = ? WHERE id = ?";

    /** MailDatabase.updateMailboxReceiveEnabled */
    public static final String MAIL_UPDATE_MAILBOX_RECEIVE_ENABLED = "UPDATE mailboxes SET receive_enabled = ? WHERE id = ?";

    /** MailDatabase.updateMailbox */
    public static final String MAIL_UPDATE_MAILBOX = "UPDATE mailboxes SET name = ?, quota_mb = ?, active = ?, receive_enabled = ?,"
            + " junk_expunge_days = ?, trash_expunge_days = ? WHERE id = ?";

    /**
     * MailDatabase.ensureMailboxCleanupColumns: after how many days Dovecot empties the mailbox's Junk and Trash by
     * itself (mailbox_autoexpunge, from the sql userdb of DovecotQuota); 0 = never, and that is the default: it is
     * turned on only on request, from the panel or from the webmail.
     */
    public static final String MAIL_ADD_MAILBOXES_JUNK_EXPUNGE_DAYS = "ALTER TABLE mailboxes ADD COLUMN junk_expunge_days SMALLINT UNSIGNED NOT NULL DEFAULT 0";

    /** MailDatabase.ensureMailboxCleanupColumns */
    public static final String MAIL_ADD_MAILBOXES_TRASH_EXPUNGE_DAYS = "ALTER TABLE mailboxes ADD COLUMN trash_expunge_days SMALLINT UNSIGNED NOT NULL DEFAULT 0";

    /** MailDatabase.setMailboxCleanup: the webmail (root part only, Roundcube's internal route) for its own mailbox. */
    public static final String MAIL_UPDATE_MAILBOX_CLEANUP = "UPDATE mailboxes SET junk_expunge_days = ?, trash_expunge_days = ? WHERE email = ? AND active = 1";

    /** MailDatabase.ensureMailboxReceiveEnabledColumn */
    public static final String MAIL_ENSURE_MAILBOX_RECEIVE_ENABLED_COLUMN = "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'mailboxes' AND column_name = 'receive_enabled'";

    /** MailDatabase.ensureMailboxReceiveEnabledColumn */
    public static final String MAIL_ENSURE_MAILBOX_RECEIVE_ENABLED_COLUMN_2 = "ALTER TABLE mailboxes ADD COLUMN receive_enabled BOOLEAN DEFAULT TRUE AFTER active";

    /** MailDatabase.getMailbox */
    public static final String MAIL_GET_MAILBOX = "SELECT m.*, d.domain as domain_name FROM mailboxes m JOIN domains d ON m.domain_id = d.id WHERE m.id = ?";

    /** MailDatabase.getMailboxByEmail */
    public static final String MAIL_GET_MAILBOX_BY_EMAIL = "SELECT m.*, d.domain as domain_name FROM mailboxes m JOIN domains d ON m.domain_id = d.id WHERE m.email = ?";

    /** MailDatabase.getMailboxes */
    public static final String MAIL_GET_MAILBOXES = "SELECT m.*, d.domain as domain_name FROM mailboxes m JOIN domains d ON m.domain_id = d.id WHERE m.domain_id = ? ORDER BY m.email";

    /** MailDatabase.getAllMailboxes */
    public static final String MAIL_GET_ALL_MAILBOXES = "SELECT m.*, d.domain as domain_name,\n"
            + "    (SELECT COUNT(*) FROM forwarding_rules fr WHERE fr.mailbox_id = m.id AND fr.enabled = 1) as forwarding_count,\n"
            + "    (SELECT COUNT(*) FROM sieve_filters sf WHERE sf.mailbox_id = m.id AND sf.enabled = 1) as filters_count,\n"
            + "    (SELECT COALESCE(ar.enabled, 0) FROM auto_responders ar WHERE ar.mailbox_id = m.id) as autoresponder_enabled\n"
            + "FROM mailboxes m\n"
            + "JOIN domains d ON m.domain_id = d.id\n"
            + "ORDER BY m.email\n";

    /** MailDatabase.transformAliasToMailbox */
    public static final String MAIL_TRANSFORM_ALIAS_TO_MAILBOX = "INSERT INTO aliases (domain_id, source, destination, active) VALUES (?, ?, ?, 1) ON DUPLICATE KEY UPDATE active = 1";

    /** MailDatabase.transformAliasToMailbox */
    public static final String MAIL_TRANSFORM_ALIAS_TO_MAILBOX_2 = "DELETE FROM aliases WHERE source = ?";

    /** MailDatabase.transformMailboxToAlias */
    public static final String MAIL_TRANSFORM_MAILBOX_TO_ALIAS = "DELETE FROM aliases WHERE source = ? AND destination = ?";

    /** MailDatabase.transformMailboxToAlias */
    public static final String MAIL_TRANSFORM_MAILBOX_TO_ALIAS_2 = "DELETE FROM rate_limits WHERE target_type = 'mailbox' AND target_id = ?";

    /** MailDatabase.transformMailboxToAlias */
    public static final String MAIL_TRANSFORM_MAILBOX_TO_ALIAS_3 = "DELETE FROM mailboxes WHERE id = ? AND email = ?";

    /** MailDatabase.getAliasesBySource */
    public static final String MAIL_GET_ALIASES_BY_SOURCE = "SELECT a.*, d.domain as domain_name FROM aliases a JOIN domains d ON a.domain_id = d.id WHERE a.source = ? ORDER BY a.destination";

    /** MailDatabase.getAliasesByDestination */
    public static final String MAIL_GET_ALIASES_BY_DESTINATION = "SELECT a.*, d.domain as domain_name FROM aliases a JOIN domains d ON a.domain_id = d.id WHERE a.destination = ? ORDER BY a.source";

    /** MailDatabase.addAlias */
    public static final String MAIL_ADD_ALIAS = "INSERT INTO aliases (domain_id, source, destination) VALUES (?, ?, ?)";

    /** MailDatabase.deleteAlias */
    public static final String MAIL_DELETE_ALIAS = "DELETE FROM aliases WHERE id = ?";

    /** MailDatabase.updateAliasDestination */
    public static final String MAIL_UPDATE_ALIAS_DESTINATION = "UPDATE aliases SET destination = ? WHERE id = ?";

    /** MailDatabase.getAliasById */
    public static final String MAIL_GET_ALIAS_BY_ID = "SELECT * FROM aliases WHERE id = ?";

    /** MailDatabase.updateAliasStatus */
    public static final String MAIL_UPDATE_ALIAS_STATUS = "UPDATE aliases SET active = ? WHERE id = ?";

    /** MailDatabase.getAliases */
    public static final String MAIL_GET_ALIASES = "SELECT * FROM aliases WHERE domain_id = ? ORDER BY source";

    /** MailDatabase.getAllAliases */
    public static final String MAIL_GET_ALL_ALIASES = "SELECT a.*, d.domain as domain_name FROM aliases a JOIN domains d ON a.domain_id = d.id ORDER BY a.source";

    /** MailDatabase.createAutoLoginToken */
    public static final String MAIL_CREATE_AUTO_LOGIN_TOKEN = "INSERT INTO roundcube_tokens (token, mailbox_id, expires_at) VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 5 MINUTE))";

    /** MailDatabase.validateAutoLoginToken */
    public static final String MAIL_VALIDATE_AUTO_LOGIN_TOKEN = "SELECT m.*, d.domain as domain_name FROM mailboxes m\n"
            + "JOIN roundcube_tokens t ON t.mailbox_id = m.id\n"
            + "JOIN domains d ON m.domain_id = d.id\n"
            + "WHERE t.token = ? AND t.expires_at > NOW() AND t.used = FALSE\n";

    /** MailDatabase.validateAutoLoginToken */
    public static final String MAIL_VALIDATE_AUTO_LOGIN_TOKEN_2 = "UPDATE roundcube_tokens SET used = TRUE WHERE token = ?";

    /** MailDatabase.cleanupExpiredTokens */
    public static final String MAIL_CLEANUP_EXPIRED_TOKENS = "DELETE FROM roundcube_tokens WHERE expires_at < NOW() OR used = TRUE";

    /** MailDatabase.serverVersion */
    public static final String MAIL_SERVER_VERSION = "SELECT VERSION()";

    /** MailDatabase.getAutoResponder */
    public static final String MAIL_GET_AUTO_RESPONDER = "SELECT ar.*, m.email FROM auto_responders ar\n"
            + "JOIN mailboxes m ON ar.mailbox_id = m.id\n"
            + "WHERE ar.mailbox_id = ?\n";

    /** MailDatabase.saveAutoResponder */
    public static final String MAIL_SAVE_AUTO_RESPONDER = "INSERT INTO auto_responders (mailbox_id, enabled, subject, body, start_date, end_date, interval_hours)\n"
            + "VALUES (?, ?, ?, ?, ?, ?, ?)\n"
            + "ON DUPLICATE KEY UPDATE enabled = ?, subject = ?, body = ?, start_date = ?, end_date = ?, interval_hours = ?\n";

    /** MailDatabase.getActiveAutoResponders */
    public static final String MAIL_GET_ACTIVE_AUTO_RESPONDERS = "SELECT ar.*, m.email FROM auto_responders ar\n"
            + "JOIN mailboxes m ON ar.mailbox_id = m.id\n"
            + "WHERE ar.enabled = TRUE\n"
            + "AND (ar.start_date IS NULL OR ar.start_date <= CURDATE())\n"
            + "AND (ar.end_date IS NULL OR ar.end_date >= CURDATE())\n";

    /** MailDatabase.getSieveFilters */
    public static final String MAIL_GET_SIEVE_FILTERS = "SELECT sf.*, m.email FROM sieve_filters sf\n"
            + "JOIN mailboxes m ON sf.mailbox_id = m.id\n"
            + "WHERE sf.mailbox_id = ?\n"
            + "ORDER BY sf.priority, sf.id\n";

    /**
     * MailDatabase.getSieveFilter: a single filter, for the window that edits it and to know which mailbox's rules to
     * rewrite (the one on the row, not the one the request names: finding 224).
     */
    public static final String MAIL_GET_SIEVE_FILTER = "SELECT sf.*, m.email FROM sieve_filters sf\n"
            + "JOIN mailboxes m ON sf.mailbox_id = m.id\n"
            + "WHERE sf.id = ?\n";

    /** MailDatabase.createSieveFilter */
    public static final String MAIL_CREATE_SIEVE_FILTER = "INSERT INTO sieve_filters (mailbox_id, name, priority, enabled, conditions, actions) VALUES (?, ?, ?, ?, ?, ?)";

    /** MailDatabase.updateSieveFilter */
    public static final String MAIL_UPDATE_SIEVE_FILTER = "UPDATE sieve_filters SET name = ?, priority = ?, enabled = ?, conditions = ?, actions = ? WHERE id = ?";

    /** MailDatabase.deleteSieveFilter */
    public static final String MAIL_DELETE_SIEVE_FILTER = "DELETE FROM sieve_filters WHERE id = ?";

    /** MailDatabase.getForwardingRules */
    public static final String MAIL_GET_FORWARDING_RULES = "SELECT fr.*, m.email FROM forwarding_rules fr\n"
            + "JOIN mailboxes m ON fr.mailbox_id = m.id\n"
            + "WHERE fr.mailbox_id = ?\n";

    /** MailDatabase.getForwardingRule: a single forward, to know which mailbox's rules to rewrite (finding 224). */
    public static final String MAIL_GET_FORWARDING_RULE = "SELECT fr.*, m.email FROM forwarding_rules fr\n"
            + "JOIN mailboxes m ON fr.mailbox_id = m.id\n"
            + "WHERE fr.id = ?\n";

    /** MailDatabase.createForwardingRule */
    public static final String MAIL_CREATE_FORWARDING_RULE = "INSERT INTO forwarding_rules (mailbox_id, destination, keep_copy) VALUES (?, ?, ?)";

    /** MailDatabase.updateForwardingRule */
    public static final String MAIL_UPDATE_FORWARDING_RULE = "UPDATE forwarding_rules SET destination = ?, keep_copy = ?, enabled = ? WHERE id = ?";

    /** MailDatabase.deleteForwardingRule */
    public static final String MAIL_DELETE_FORWARDING_RULE = "DELETE FROM forwarding_rules WHERE id = ?";

    /** MailDatabase.getRateLimits */
    public static final String MAIL_GET_RATE_LIMITS = "SELECT rl.*,\n"
            + "    CASE\n"
            + "        WHEN rl.target_type = 'domain' THEN (SELECT domain FROM domains WHERE id = rl.target_id)\n"
            + "        WHEN rl.target_type = 'mailbox' THEN (SELECT email FROM mailboxes WHERE id = rl.target_id)\n"
            + "        ELSE 'Global'\n"
            + "    END as target_name\n"
            + "FROM rate_limits rl\n"
            + "ORDER BY rl.target_type, rl.target_id\n";

    /** MailDatabase.saveRateLimit */
    public static final String MAIL_SAVE_RATE_LIMIT = "INSERT INTO rate_limits (target_type, target_id, max_per_hour, max_per_day, max_recipients, enabled)\n"
            + "VALUES (?, ?, ?, ?, ?, ?)\n"
            + "ON DUPLICATE KEY UPDATE max_per_hour = VALUES(max_per_hour), max_per_day = VALUES(max_per_day),\n"
            + "                        max_recipients = VALUES(max_recipients), enabled = VALUES(enabled)\n";

    /** MailDatabase.saveRateLimit */
    public static final String MAIL_SAVE_RATE_LIMIT_2 = "DELETE FROM rate_limits WHERE target_type = 'global' AND target_id IS NULL";

    /** MailDatabase.deleteRateLimit */
    public static final String MAIL_DELETE_RATE_LIMIT = "DELETE FROM rate_limits WHERE id = ?";

    /** MailDatabase.getEmailStatistics */
    public static final String MAIL_GET_EMAIL_STATISTICS = "SELECT es.*,\n"
            + "    COALESCE(m.email, d.domain, 'Total') as name\n"
            + "FROM email_statistics es\n"
            + "LEFT JOIN mailboxes m ON es.mailbox_id = m.id\n"
            + "LEFT JOIN domains d ON es.domain_id = d.id\n"
            + "WHERE es.stat_date >= DATE_SUB(CURDATE(), INTERVAL ? DAY)\n"
            + "ORDER BY es.stat_date DESC, es.domain_id, es.mailbox_id\n";

    /** MailDatabase.getTodayStats */
    public static final String MAIL_GET_TODAY_STATS = "SELECT\n"
            + "    CURDATE() as stat_date,\n"
            + "    SUM(sent_count) as sent_count,\n"
            + "    SUM(received_count) as received_count,\n"
            + "    SUM(spam_count) as spam_count,\n"
            + "    SUM(virus_count) as virus_count,\n"
            + "    SUM(bounced_count) as bounced_count,\n"
            + "    SUM(bytes_sent) as bytes_sent,\n"
            + "    SUM(bytes_received) as bytes_received\n"
            + "FROM email_statistics\n"
            + "WHERE stat_date = CURDATE()\n";

    /** MailDatabase.logRspamdTraining */
    public static final String MAIL_LOG_RSPAMD_TRAINING = "INSERT INTO rspamd_training (message_id, trained_as, trained_by) VALUES (?, ?, ?)";

    /** MailDatabase.getTrainingCount */
    public static final String MAIL_GET_TRAINING_COUNT = "SELECT COUNT(*) FROM rspamd_training WHERE trained_as = ? AND trained_at >= DATE_SUB(NOW(), INTERVAL ? DAY)";

    /** MailDatabase.logAuditEvent */
    public static final String MAIL_LOG_AUDIT_EVENT = "INSERT INTO audit_log (action, username, ip_address, details) VALUES (?, ?, ?, ?)";

    /** MailDatabase.logAuditEventFull */
    public static final String MAIL_LOG_AUDIT_EVENT_FULL = "INSERT INTO audit_log (action, username, ip_address, details, user_agent) VALUES (?, ?, ?, ?, ?)";

    /** MailDatabase.getAuditStats */
    public static final String MAIL_GET_AUDIT_STATS = "SELECT action, COUNT(*) as count\n"
            + "FROM audit_log\n"
            + "WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)\n"
            + "GROUP BY action\n"
            + "ORDER BY count DESC\n";

    /** MailDatabase.cleanupAuditLog */
    public static final String MAIL_CLEANUP_AUDIT_LOG = "DELETE FROM audit_log WHERE created_at < DATE_SUB(NOW(), INTERVAL ? DAY)";

    /** MailDatabase.getRecentLoginFailures */
    public static final String MAIL_GET_RECENT_LOGIN_FAILURES = "SELECT COUNT(*) FROM audit_log\n"
            + "WHERE action = 'LOGIN_FAILURE'\n"
            + "AND ip_address = ?\n"
            + "AND created_at >= DATE_SUB(NOW(), INTERVAL ? MINUTE)\n";

    /** AuthStore.assignUserHandles */
    public static final String AUTH_ASSIGN_USER_HANDLES = "SELECT id FROM panel_admin WHERE user_handle IS NULL";

    /** AuthStore.assignUserHandles */
    public static final String AUTH_ASSIGN_USER_HANDLES_2 = "UPDATE panel_admin SET user_handle = ? WHERE id = ? AND user_handle IS NULL";

    /** AuthStore.linkOldPasskeys */
    public static final String AUTH_LINK_OLD_PASSKEYS = "UPDATE admin_passkeys k JOIN panel_admin a ON a.id = k.admin_id SET k.user_handle = a.user_handle WHERE k.user_handle IS NULL";

    /** AuthStore.ensureSuperadmin */
    public static final String AUTH_ENSURE_SUPERADMIN = "SELECT 1 FROM panel_admin WHERE role = 'superadmin' AND active = TRUE LIMIT 1";

    /** AuthStore.ensureSuperadmin */
    public static final String AUTH_ENSURE_SUPERADMIN_2 = "UPDATE panel_admin SET role = 'superadmin' WHERE active = TRUE ORDER BY id LIMIT 1";

    /** AuthStore.createAdmin */
    public static final String AUTH_CREATE_ADMIN = "INSERT INTO panel_admin (username, role, active, email_enc, email_index, user_handle, created_at) VALUES (?, ?, TRUE, ?, ?, ?, ?)";

    /** AuthStore.renameAdmin */
    public static final String AUTH_RENAME_ADMIN = "UPDATE panel_admin SET username = ? WHERE id = ?";

    /** AuthStore.setEmail */
    public static final String AUTH_SET_EMAIL = "UPDATE panel_admin SET email_enc = ?, email_index = ? WHERE id = ?";

    /** AuthStore.setRole */
    public static final String AUTH_SET_ROLE = "UPDATE panel_admin SET role = ? WHERE id = ?";

    /** AuthStore.deleteAdmin */
    public static final String AUTH_DELETE_ADMIN = "DELETE FROM panel_admin WHERE id = ?";

    /** AuthStore.activeSuperadmins */
    public static final String AUTH_ACTIVE_SUPERADMINS = "SELECT COUNT(*) FROM panel_admin WHERE role = 'superadmin' AND active = TRUE";

    /** AuthStore.loggedIn */
    public static final String AUTH_LOGGED_IN = "UPDATE panel_admin SET last_login = ? WHERE id = ?";

    /** AuthStore.addPasskey */
    public static final String AUTH_ADD_PASSKEY = "INSERT INTO admin_passkeys (admin_id, credential_id, public_key_cose, sign_count, name, created_at, rp_id, user_handle) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";

    /** AuthStore.passkeyUsed */
    public static final String AUTH_PASSKEY_USED = "UPDATE admin_passkeys SET sign_count = ?, last_used = ? WHERE credential_id = ?";

    /** AuthStore.renamePasskey */
    public static final String AUTH_RENAME_PASSKEY = "UPDATE admin_passkeys SET name = ? WHERE id = ? AND admin_id = ?";

    /** AuthStore.deletePasskey */
    public static final String AUTH_DELETE_PASSKEY = "DELETE FROM admin_passkeys WHERE id = ? AND admin_id = ?";

    /** AuthStore.purgeExpired */
    public static final String AUTH_PURGE_EXPIRED = "DELETE FROM panel_sessions WHERE expires_at < ? OR last_seen_at < ?";

    /** WebSessions.create */
    public static final String SESSION_CREATE = "INSERT INTO panel_sessions (token_hash, admin_id, ua_hash, ua_enc, ip_enc, created_at, last_seen_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";

    /** WebSessions.check */
    public static final String SESSION_CHECK = "SELECT id, admin_id, ua_hash, last_seen_at, reauth_at FROM panel_sessions WHERE token_hash = ? AND expires_at > ? AND last_seen_at > ?";

    /** WebSessions.forwarded */
    public static final String SESSION_FORWARDED = "SELECT admin_id, reauth_at FROM panel_sessions WHERE id = ? AND expires_at > ? AND last_seen_at > ?";

    /** WebSessions.touch */
    public static final String SESSION_TOUCH = "UPDATE panel_sessions SET last_seen_at = ? WHERE id = ?";

    /** WebSessions.markReauthenticated */
    public static final String SESSION_MARK_REAUTHENTICATED = "UPDATE panel_sessions SET reauth_at = ? WHERE id = ?";

    /** WebSessions.beginRun */
    public static final String SESSION_BEGIN_RUN = "DELETE FROM panel_sessions";

    /** WebSessions.revoke */
    public static final String SESSION_REVOKE = "DELETE FROM panel_sessions WHERE token_hash = ?";

    /** WebSessions.revokeById */
    public static final String SESSION_REVOKE_BY_ID = "DELETE FROM panel_sessions WHERE id = ? AND admin_id = ?";

    /** WebSessions.revokeOthers */
    public static final String SESSION_REVOKE_OTHERS = "DELETE FROM panel_sessions WHERE admin_id = ? AND id <> ?";

    /** WebSessions.list */
    public static final String SESSION_LIST = "SELECT id, ip_enc, ua_enc, created_at, last_seen_at FROM panel_sessions WHERE admin_id = ? AND expires_at > ? AND last_seen_at > ? ORDER BY last_seen_at DESC";

    /** WebSessions.count */
    public static final String SESSION_COUNT = "SELECT COUNT(*) FROM panel_sessions WHERE expires_at > ? AND last_seen_at > ?";

    /** SSLMailServer.handleApiTimezoneDiag */
    public static final String SERVER_HANDLE_API_TIMEZONE_DIAG = "SET GLOBAL time_zone = ?";

    /** SSLMailServer.handleApiTimezoneDiag */
    public static final String SERVER_HANDLE_API_TIMEZONE_DIAG_2 = "SET SESSION time_zone = ?";

    /** SSLMailServer.fillTimezoneDiagnostics */
    public static final String SERVER_FILL_TIMEZONE_DIAGNOSTICS = "SELECT @@global.time_zone, @@session.time_zone, NOW(), UTC_TIMESTAMP(), @@system_time_zone, UNIX_TIMESTAMP() AS unix_ts";

    /** dataBaseManager.update_panel_config */
    public static final String CONFIG_UPDATE_PANEL_CONFIG = "UPDATE config SET panel_host = ?, panel_port = ?, panel_ssl_cert = ?, panel_ssl_cert_key = ?, panel_ssl_chain = ?, panel_sessions_prefix = ? WHERE id = 1";

    /** dataBaseManager.update_mysql_config */
    /** MysqlRename: the panel's database and user under the current name; the password stays */
    public static final String CONFIG_RENAME_MYSQL = "UPDATE config SET mysql_user = ?, mysql_database = ? WHERE id = 1";

    public static final String CONFIG_UPDATE_MYSQL_CONFIG = "UPDATE config SET mysql_host = ?, mysql_port = ?, mysql_user = ?, mysql_password = ?, mysql_database = ? WHERE id = 1";

    /** dataBaseManager.insert_data_default */
    public static final String CONFIG_INSERT_DATA_DEFAULT = "INSERT INTO config (panel_port, panel_host, panel_ssl_cert, panel_ssl_cert_key, panel_ssl_chain, panel_sessions_prefix, mysql_host, mysql_port, mysql_user, mysql_password, mysql_database, postfix_installed, dovecot_installed, rspamd_installed, clamav_installed, roundcube_installed, roundcube_domain, roundcube_port, roundcube_ssl_cert, roundcube_ssl_key) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";

    /** dataBaseManager.get_data_config */
    public static final String CONFIG_GET_DATA_CONFIG = "SELECT * FROM config WHERE id = 1";

    /** dataBaseManager.resetAllServices */
    public static final String CONFIG_RESET_ALL_SERVICES = "UPDATE config SET postfix_installed = 0, dovecot_installed = 0, rspamd_installed = 0, clamav_installed = 0, roundcube_installed = 0 WHERE id = 1";

    /** dataBaseManager.getMailHostname */
    public static final String CONFIG_GET_MAIL_HOSTNAME = "SELECT mail_hostname FROM config WHERE id = 1";

    /** dataBaseManager.setMailHostname */
    public static final String CONFIG_SET_MAIL_HOSTNAME = "UPDATE config SET mail_hostname = ? WHERE id = 1";

    /** dataBaseManager.getRoundcubeDomain */
    public static final String CONFIG_GET_ROUNDCUBE_DOMAIN = "SELECT roundcube_domain FROM config WHERE id = 1";

    /** dataBaseManager.getRoundcubePort */
    public static final String CONFIG_GET_ROUNDCUBE_PORT = "SELECT roundcube_port FROM config WHERE id = 1";

    /** dataBaseManager.getRoundcubeSslCert */
    public static final String CONFIG_GET_ROUNDCUBE_SSL_CERT = "SELECT roundcube_ssl_cert FROM config WHERE id = 1";

    /** dataBaseManager.getRoundcubeSslKey */
    public static final String CONFIG_GET_ROUNDCUBE_SSL_KEY = "SELECT roundcube_ssl_key FROM config WHERE id = 1";

    /** dataBaseManager.updateRoundcubeConfig */
    public static final String CONFIG_UPDATE_ROUNDCUBE_CONFIG = "UPDATE config SET roundcube_domain = ?, roundcube_port = ?, roundcube_ssl_cert = ?, roundcube_ssl_key = ?, roundcube_ssl_chain = ? WHERE id = 1";

    /** dataBaseManager.getRoundcubeSslChain */
    public static final String CONFIG_GET_ROUNDCUBE_SSL_CHAIN = "SELECT roundcube_ssl_chain FROM config WHERE id = 1";

    /** PublicSurfaceRename.moveJailState */
    public static final String RENAME_BUSY_TIMEOUT = "PRAGMA busy_timeout = 10000";

    // ===== Written by hand from the previously composed SQL =====

    /** MailDatabase.createDatabaseAndUser: the password is a parameter, which the driver quotes with the right escaping */
    public static final String MAIL_CREATE_PANEL_USER = "CREATE USER IF NOT EXISTS 'daemoxcp_mail'@'127.0.0.1' IDENTIFIED BY ?";


    /** MailDatabase.dropAllTables: the tables of MailDatabase.PANEL_TABLES, in the same order (checked by SqlCatalogTest) */
    public static final String MAIL_DROP_PANEL_TABLES = "DROP TABLE IF EXISTS admin_passkeys, rspamd_training, panel_sessions, login_code_email, login_code_console, stepup_code, email_change_code, roundcube_tokens, auto_responders, sieve_filters, forwarding_rules, email_statistics, aliases, mailboxes, dkim_rotation_history, domains, cloudflare_accounts, audit_log, rate_limits, panel_settings, panel_role_permissions, installed_components, panel_admin, virtual_aliases, virtual_users, virtual_domains";

    /** MailDatabase.createAuthTables */
    public static final String MAIL_CREATE_PANEL_SESSIONS = "CREATE TABLE IF NOT EXISTS panel_sessions (\n"
            + "    id BIGINT AUTO_INCREMENT PRIMARY KEY,\n"
            + "    token_hash CHAR(64) CHARACTER SET ascii NOT NULL,\n"
            + "    admin_id INT NOT NULL,\n"
            + "    ua_hash CHAR(64) CHARACTER SET ascii NOT NULL,\n"
            + "    ua_enc VARCHAR(1024) NULL,\n"
            + "    ip_enc VARCHAR(256) NULL,\n"
            + "    created_at DATETIME NOT NULL,\n"
            + "    last_seen_at DATETIME NOT NULL,\n"
            + "    expires_at DATETIME NOT NULL,\n"
            + "    reauth_at DATETIME NULL,\n"
            + "    UNIQUE KEY uq_session_token (token_hash),\n"
            + "    KEY idx_session_admin (admin_id),\n"
            + "    KEY idx_session_expires (expires_at),\n"
            + "    CONSTRAINT fk_session_admin FOREIGN KEY (admin_id) REFERENCES panel_admin(id) ON DELETE CASCADE\n"
            + ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4\n";

    /** MailDatabase.createAuthTables */
    public static final String MAIL_CREATE_LOGIN_CODE_EMAIL = "CREATE TABLE IF NOT EXISTS login_code_email (id BIGINT AUTO_INCREMENT PRIMARY KEY, admin_id INT NOT NULL, code_hash CHAR(64) CHARACTER SET ascii NOT NULL,  attempts INT NOT NULL DEFAULT 0, created_at DATETIME NOT NULL, expires_at DATETIME NOT NULL, used_at DATETIME NULL, KEY idx_login_code_email_admin (admin_id, expires_at), CONSTRAINT fk_login_code_email_admin FOREIGN KEY (admin_id) REFERENCES panel_admin(id) ON DELETE CASCADE) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";

    /** MailDatabase.createAuthTables */
    public static final String MAIL_CREATE_LOGIN_CODE_CONSOLE = "CREATE TABLE IF NOT EXISTS login_code_console (id BIGINT AUTO_INCREMENT PRIMARY KEY, admin_id INT NOT NULL, code_hash CHAR(64) CHARACTER SET ascii NOT NULL,  attempts INT NOT NULL DEFAULT 0, created_at DATETIME NOT NULL, expires_at DATETIME NOT NULL, used_at DATETIME NULL, KEY idx_login_code_console_admin (admin_id, expires_at), CONSTRAINT fk_login_code_console_admin FOREIGN KEY (admin_id) REFERENCES panel_admin(id) ON DELETE CASCADE) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";

    /** MailDatabase.createAuthTables */
    public static final String MAIL_CREATE_STEPUP_CODE = "CREATE TABLE IF NOT EXISTS stepup_code (id BIGINT AUTO_INCREMENT PRIMARY KEY, admin_id INT NOT NULL, code_hash CHAR(64) CHARACTER SET ascii NOT NULL,  attempts INT NOT NULL DEFAULT 0, created_at DATETIME NOT NULL, expires_at DATETIME NOT NULL, used_at DATETIME NULL, KEY idx_stepup_code_admin (admin_id, expires_at), CONSTRAINT fk_stepup_code_admin FOREIGN KEY (admin_id) REFERENCES panel_admin(id) ON DELETE CASCADE) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";

    /** MailDatabase.createAuthTables */
    public static final String MAIL_CREATE_EMAIL_CHANGE_CODE = "CREATE TABLE IF NOT EXISTS email_change_code (id BIGINT AUTO_INCREMENT PRIMARY KEY, admin_id INT NOT NULL, code_hash CHAR(64) CHARACTER SET ascii NOT NULL, target_enc VARCHAR(512) NOT NULL, target_index CHAR(64) CHARACTER SET ascii NOT NULL, attempts INT NOT NULL DEFAULT 0, created_at DATETIME NOT NULL, expires_at DATETIME NOT NULL, used_at DATETIME NULL, KEY idx_email_change_code_admin (admin_id, expires_at), CONSTRAINT fk_email_change_code_admin FOREIGN KEY (admin_id) REFERENCES panel_admin(id) ON DELETE CASCADE) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";

    /** MailDatabase.ensurePasswordlessSchema */
    public static final String MAIL_DROP_ADMIN_PASSWORD_HASH = "ALTER TABLE panel_admin DROP COLUMN password_hash";

    /** MailDatabase.ensurePasswordlessSchema */
    public static final String MAIL_DROP_ADMIN_TOTP_SECRET = "ALTER TABLE panel_admin DROP COLUMN totp_secret";

    /** MailDatabase.ensurePasswordlessSchema */
    public static final String MAIL_DROP_ADMIN_TOTP_ENABLED = "ALTER TABLE panel_admin DROP COLUMN totp_enabled";

    /** MailDatabase.ensurePasswordlessSchema */
    public static final String MAIL_DROP_ADMIN_BACKUP_CODES = "ALTER TABLE panel_admin DROP COLUMN backup_codes";

    /** MailDatabase.ensureDkimRotationColumns */
    public static final String MAIL_ADD_DOMAINS_DKIM_PENDING_SELECTOR = "ALTER TABLE domains ADD COLUMN dkim_pending_selector VARCHAR(50) NULL";

    /** MailDatabase.ensureDkimRotationColumns */
    public static final String MAIL_ADD_DOMAINS_DKIM_PENDING_PRIVATE_KEY = "ALTER TABLE domains ADD COLUMN dkim_pending_private_key TEXT NULL";

    /** MailDatabase.ensureDkimRotationColumns */
    public static final String MAIL_ADD_DOMAINS_DKIM_PENDING_PUBLIC_KEY = "ALTER TABLE domains ADD COLUMN dkim_pending_public_key TEXT NULL";

    /** MailDatabase.ensureDkimRotationColumns */
    public static final String MAIL_ADD_DOMAINS_DKIM_ROTATION_STATE = "ALTER TABLE domains ADD COLUMN dkim_rotation_state VARCHAR(32) NULL";

    /** MailDatabase.ensureDkimRotationColumns */
    public static final String MAIL_ADD_DOMAINS_DKIM_ROTATION_STARTED_AT = "ALTER TABLE domains ADD COLUMN dkim_rotation_started_at TIMESTAMP NULL";

    /** MailDatabase.ensureDkimRotationColumns */
    public static final String MAIL_ADD_DOMAINS_DKIM_ROTATION_ACTIVATED_AT = "ALTER TABLE domains ADD COLUMN dkim_rotation_activated_at TIMESTAMP NULL";

    /** MailDatabase.ensureDkimRotationColumns */
    public static final String MAIL_ADD_DOMAINS_DKIM_PREVIOUS_SELECTOR = "ALTER TABLE domains ADD COLUMN dkim_previous_selector VARCHAR(50) NULL";

    /** MailDatabase.ensureDkimRotationColumns */
    public static final String MAIL_ADD_DOMAINS_DKIM_PREVIOUS_PRIVATE_KEY = "ALTER TABLE domains ADD COLUMN dkim_previous_private_key TEXT NULL";

    /** MailDatabase.ensureDkimRotationColumns */
    public static final String MAIL_ADD_DOMAINS_DKIM_PREVIOUS_PUBLIC_KEY = "ALTER TABLE domains ADD COLUMN dkim_previous_public_key TEXT NULL";

    /** MailDatabase.ensureDkimRotationColumns */
    public static final String MAIL_ADD_DOMAINS_DKIM_DNS_ZONE_ID = "ALTER TABLE domains ADD COLUMN dkim_dns_zone_id VARCHAR(64) NULL";

    /** MailDatabase.ensureDkimRotationColumns */
    public static final String MAIL_ADD_DOMAINS_DKIM_PENDING_DNS_RECORD_ID = "ALTER TABLE domains ADD COLUMN dkim_pending_dns_record_id VARCHAR(64) NULL";

    /** MailDatabase.ensureDkimRotationColumns */
    public static final String MAIL_ADD_DOMAINS_DKIM_PREVIOUS_DNS_RECORD_ID = "ALTER TABLE domains ADD COLUMN dkim_previous_dns_record_id VARCHAR(64) NULL";

    /** MailDatabase.ensureDkimRotationColumns */
    public static final String MAIL_ADD_DOMAINS_DKIM_ROTATION_INTERVAL_DAYS = "ALTER TABLE domains ADD COLUMN dkim_rotation_interval_days INT NOT NULL DEFAULT 0";

    /** MailDatabase.ensureDkimRotationColumns */
    public static final String MAIL_ADD_DOMAINS_DKIM_LAST_ROTATION_AT = "ALTER TABLE domains ADD COLUMN dkim_last_rotation_at TIMESTAMP NULL";

    /** MailDatabase.ensureDkimRotationColumns */
    public static final String MAIL_ADD_DOMAINS_DKIM_ROTATION_MODE = "ALTER TABLE domains ADD COLUMN dkim_rotation_mode VARCHAR(16) NULL";

    /** MailDatabase.ensureMailboxPasswordVaultColumns */
    public static final String MAIL_ADD_MAILBOXES_PASSWORD_ENCRYPTED = "ALTER TABLE mailboxes ADD COLUMN password_encrypted TEXT NULL";

    /** MailDatabase.ensureMailboxPasswordVaultColumns */
    public static final String MAIL_ADD_MAILBOXES_PASSWORD_ENCRYPTED_AT = "ALTER TABLE mailboxes ADD COLUMN password_encrypted_at TIMESTAMP NULL";

    /** MailDatabase.getDomainCount */
    public static final String MAIL_COUNT_ACTIVE_DOMAINS = "SELECT COUNT(*) FROM domains WHERE active = TRUE";

    /** MailDatabase.getMailboxCount */
    public static final String MAIL_COUNT_ACTIVE_MAILBOXES = "SELECT COUNT(*) FROM mailboxes WHERE active = TRUE";

    /** MailDatabase.getAliasCount */
    public static final String MAIL_COUNT_ACTIVE_ALIASES = "SELECT COUNT(*) FROM aliases WHERE active = TRUE";

    /** MailDatabase.incrementEmailStat */
    public static final String MAIL_ADD_STAT_SENT = "INSERT INTO email_statistics (stat_date, mailbox_id, domain_id, sent_count, bytes_sent)\n"
            + "VALUES (CURDATE(), ?, ?, ?, ?)\n"
            + "ON DUPLICATE KEY UPDATE sent_count = sent_count + ?, bytes_sent = bytes_sent + ?\n";

    /** MailDatabase.incrementEmailStat */
    public static final String MAIL_ADD_STAT_RECEIVED = "INSERT INTO email_statistics (stat_date, mailbox_id, domain_id, received_count, bytes_received)\n"
            + "VALUES (CURDATE(), ?, ?, ?, ?)\n"
            + "ON DUPLICATE KEY UPDATE received_count = received_count + ?, bytes_received = bytes_received + ?\n";

    /** MailDatabase.incrementEmailStat */
    public static final String MAIL_ADD_STAT_SPAM = "INSERT INTO email_statistics (stat_date, mailbox_id, domain_id, spam_count, bytes_received)\n"
            + "VALUES (CURDATE(), ?, ?, ?, ?)\n"
            + "ON DUPLICATE KEY UPDATE spam_count = spam_count + ?, bytes_received = bytes_received + ?\n";

    /** MailDatabase.incrementEmailStat */
    public static final String MAIL_ADD_STAT_VIRUS = "INSERT INTO email_statistics (stat_date, mailbox_id, domain_id, virus_count, bytes_received)\n"
            + "VALUES (CURDATE(), ?, ?, ?, ?)\n"
            + "ON DUPLICATE KEY UPDATE virus_count = virus_count + ?, bytes_received = bytes_received + ?\n";

    /** MailDatabase.incrementEmailStat */
    public static final String MAIL_ADD_STAT_BOUNCED = "INSERT INTO email_statistics (stat_date, mailbox_id, domain_id, bounced_count, bytes_received)\n"
            + "VALUES (CURDATE(), ?, ?, ?, ?)\n"
            + "ON DUPLICATE KEY UPDATE bounced_count = bounced_count + ?, bytes_received = bytes_received + ?\n";

    /** MailDatabase.incrementEmailStatOn: the day of the message (UTC), not the day it is counted on (MailLogStats) */
    public static final String MAIL_ADD_STAT_SENT_ON = "INSERT INTO email_statistics (stat_date, mailbox_id, domain_id, sent_count, bytes_sent)\n"
            + "VALUES (?, ?, ?, ?, ?)\n"
            + "ON DUPLICATE KEY UPDATE sent_count = sent_count + ?, bytes_sent = bytes_sent + ?\n";

    /** MailDatabase.incrementEmailStatOn */
    public static final String MAIL_ADD_STAT_RECEIVED_ON = "INSERT INTO email_statistics (stat_date, mailbox_id, domain_id, received_count, bytes_received)\n"
            + "VALUES (?, ?, ?, ?, ?)\n"
            + "ON DUPLICATE KEY UPDATE received_count = received_count + ?, bytes_received = bytes_received + ?\n";

    /** MailDatabase.incrementEmailStatOn */
    public static final String MAIL_ADD_STAT_SPAM_ON = "INSERT INTO email_statistics (stat_date, mailbox_id, domain_id, spam_count, bytes_received)\n"
            + "VALUES (?, ?, ?, ?, ?)\n"
            + "ON DUPLICATE KEY UPDATE spam_count = spam_count + ?, bytes_received = bytes_received + ?\n";

    /** MailDatabase.incrementEmailStatOn */
    public static final String MAIL_ADD_STAT_VIRUS_ON = "INSERT INTO email_statistics (stat_date, mailbox_id, domain_id, virus_count, bytes_received)\n"
            + "VALUES (?, ?, ?, ?, ?)\n"
            + "ON DUPLICATE KEY UPDATE virus_count = virus_count + ?, bytes_received = bytes_received + ?\n";

    /** MailDatabase.incrementEmailStatOn */
    public static final String MAIL_ADD_STAT_BOUNCED_ON = "INSERT INTO email_statistics (stat_date, mailbox_id, domain_id, bounced_count, bytes_received)\n"
            + "VALUES (?, ?, ?, ?, ?)\n"
            + "ON DUPLICATE KEY UPDATE bounced_count = bounced_count + ?, bytes_received = bytes_received + ?\n";

    /** MailDatabase.deleteEmailStatsBefore: the counts kept for a defined time (MailLogStats.KEEP_DAYS) */
    public static final String MAIL_DELETE_STATS_BEFORE = "DELETE FROM email_statistics WHERE stat_date < ?";

    /** MailDatabase.getAuditLog: an empty filter (NULL) takes everything, instead of composing the WHERE */
    public static final String MAIL_GET_AUDIT_LOG = "SELECT * FROM audit_log WHERE (? IS NULL OR action = ?) AND (? IS NULL OR username = ?) AND (? IS NULL OR ip_address = ?) ORDER BY created_at DESC LIMIT ?";

    /**
     * AuthStore: the columns of an administrator. A fragment, not a statement: private, the guard does not accept it on
     * its own
     */
    private static final String AUTH_ADMIN_SELECT = "SELECT id, username, role, active, email_enc, user_handle, created_at, last_login FROM panel_admin ";

    /** AuthStore.admins */
    public static final String AUTH_LIST_ADMINS = AUTH_ADMIN_SELECT + "ORDER BY id";

    /** AuthStore.adminById */
    public static final String AUTH_ADMIN_BY_ID = AUTH_ADMIN_SELECT + "WHERE id = ? AND active = TRUE";

    /** AuthStore.adminByUsername */
    public static final String AUTH_ADMIN_BY_USERNAME = AUTH_ADMIN_SELECT + "WHERE username = ? AND active = TRUE";

    /** AuthStore.adminByEmail */
    public static final String AUTH_ADMIN_BY_EMAIL_INDEX = AUTH_ADMIN_SELECT + "WHERE email_index = ? AND active = TRUE";

    /** AuthStore.adminByUserHandle */
    public static final String AUTH_ADMIN_BY_USER_HANDLE = AUTH_ADMIN_SELECT + "WHERE user_handle = ? AND active = TRUE";

    /** AuthStore: the columns of a passkey. A fragment, private like AUTH_ADMIN_SELECT */
    private static final String AUTH_PASSKEY_SELECT = "SELECT id, admin_id, credential_id, public_key_cose, sign_count, name, created_at, last_used, user_handle FROM admin_passkeys ";

    /** AuthStore.passkeysOf */
    public static final String AUTH_PASSKEYS_OF_ADMIN = AUTH_PASSKEY_SELECT + "WHERE admin_id = ? AND user_handle IS NOT NULL ORDER BY id";

    /** AuthStore.passkeysByCredentialId */
    public static final String AUTH_PASSKEYS_BY_CREDENTIAL_ID = AUTH_PASSKEY_SELECT + "WHERE credential_id = ? AND user_handle IS NOT NULL";

    /** AuthStore.CodeFlow.EMAIL_LOGIN */
    public static final String AUTH_CODE_EMAIL_LOGIN_INVALIDATE = "UPDATE login_code_email SET used_at = ? WHERE admin_id = ? AND used_at IS NULL";

    /** AuthStore.CodeFlow.EMAIL_LOGIN */
    public static final String AUTH_CODE_EMAIL_LOGIN_INSERT = "INSERT INTO login_code_email (admin_id, code_hash, created_at, expires_at) VALUES (?, ?, ?, ?)";

    /** AuthStore.CodeFlow.EMAIL_LOGIN */
    public static final String AUTH_CODE_EMAIL_LOGIN_ACTIVE_OF = "SELECT id, admin_id, code_hash, attempts, NULL, NULL FROM login_code_email WHERE admin_id = ? AND used_at IS NULL AND expires_at > ? ORDER BY id DESC";

    /** AuthStore.CodeFlow.EMAIL_LOGIN */
    public static final String AUTH_CODE_EMAIL_LOGIN_ACTIVE_ALL = "SELECT id, admin_id, code_hash, attempts, NULL, NULL FROM login_code_email WHERE used_at IS NULL AND expires_at > ? ORDER BY id DESC";

    /** AuthStore.CodeFlow.EMAIL_LOGIN */
    public static final String AUTH_CODE_EMAIL_LOGIN_ATTEMPT = "UPDATE login_code_email SET attempts = attempts + 1 WHERE id = ?";

    /** AuthStore.CodeFlow.EMAIL_LOGIN */
    public static final String AUTH_CODE_EMAIL_LOGIN_CONSUME = "UPDATE login_code_email SET used_at = ? WHERE id = ? AND used_at IS NULL AND attempts <= ?";

    /** AuthStore.CodeFlow.EMAIL_LOGIN */
    public static final String AUTH_CODE_EMAIL_LOGIN_PURGE = "DELETE FROM login_code_email WHERE expires_at < ?";

    /** AuthStore.CodeFlow.CONSOLE_LOGIN */
    public static final String AUTH_CODE_CONSOLE_LOGIN_INVALIDATE = "UPDATE login_code_console SET used_at = ? WHERE admin_id = ? AND used_at IS NULL";

    /** AuthStore.CodeFlow.CONSOLE_LOGIN */
    public static final String AUTH_CODE_CONSOLE_LOGIN_INSERT = "INSERT INTO login_code_console (admin_id, code_hash, created_at, expires_at) VALUES (?, ?, ?, ?)";

    /** AuthStore.CodeFlow.CONSOLE_LOGIN */
    public static final String AUTH_CODE_CONSOLE_LOGIN_ACTIVE_OF = "SELECT id, admin_id, code_hash, attempts, NULL, NULL FROM login_code_console WHERE admin_id = ? AND used_at IS NULL AND expires_at > ? ORDER BY id DESC";

    /** AuthStore.CodeFlow.CONSOLE_LOGIN */
    public static final String AUTH_CODE_CONSOLE_LOGIN_ACTIVE_ALL = "SELECT id, admin_id, code_hash, attempts, NULL, NULL FROM login_code_console WHERE used_at IS NULL AND expires_at > ? ORDER BY id DESC";

    /** AuthStore.CodeFlow.CONSOLE_LOGIN */
    public static final String AUTH_CODE_CONSOLE_LOGIN_ATTEMPT = "UPDATE login_code_console SET attempts = attempts + 1 WHERE id = ?";

    /** AuthStore.CodeFlow.CONSOLE_LOGIN */
    public static final String AUTH_CODE_CONSOLE_LOGIN_CONSUME = "UPDATE login_code_console SET used_at = ? WHERE id = ? AND used_at IS NULL AND attempts <= ?";

    /** AuthStore.CodeFlow.CONSOLE_LOGIN */
    public static final String AUTH_CODE_CONSOLE_LOGIN_PURGE = "DELETE FROM login_code_console WHERE expires_at < ?";

    /** AuthStore.CodeFlow.STEP_UP */
    public static final String AUTH_CODE_STEP_UP_INVALIDATE = "UPDATE stepup_code SET used_at = ? WHERE admin_id = ? AND used_at IS NULL";

    /** AuthStore.CodeFlow.STEP_UP */
    public static final String AUTH_CODE_STEP_UP_INSERT = "INSERT INTO stepup_code (admin_id, code_hash, created_at, expires_at) VALUES (?, ?, ?, ?)";

    /** AuthStore.CodeFlow.STEP_UP */
    public static final String AUTH_CODE_STEP_UP_ACTIVE_OF = "SELECT id, admin_id, code_hash, attempts, NULL, NULL FROM stepup_code WHERE admin_id = ? AND used_at IS NULL AND expires_at > ? ORDER BY id DESC";

    /** AuthStore.CodeFlow.STEP_UP */
    public static final String AUTH_CODE_STEP_UP_ACTIVE_ALL = "SELECT id, admin_id, code_hash, attempts, NULL, NULL FROM stepup_code WHERE used_at IS NULL AND expires_at > ? ORDER BY id DESC";

    /** AuthStore.CodeFlow.STEP_UP */
    public static final String AUTH_CODE_STEP_UP_ATTEMPT = "UPDATE stepup_code SET attempts = attempts + 1 WHERE id = ?";

    /** AuthStore.CodeFlow.STEP_UP */
    public static final String AUTH_CODE_STEP_UP_CONSUME = "UPDATE stepup_code SET used_at = ? WHERE id = ? AND used_at IS NULL AND attempts <= ?";

    /** AuthStore.CodeFlow.STEP_UP */
    public static final String AUTH_CODE_STEP_UP_PURGE = "DELETE FROM stepup_code WHERE expires_at < ?";

    /** AuthStore.CodeFlow.EMAIL_CHANGE */
    public static final String AUTH_CODE_EMAIL_CHANGE_INVALIDATE = "UPDATE email_change_code SET used_at = ? WHERE admin_id = ? AND used_at IS NULL";

    /** AuthStore.CodeFlow.EMAIL_CHANGE */
    public static final String AUTH_CODE_EMAIL_CHANGE_INSERT = "INSERT INTO email_change_code (admin_id, code_hash, created_at, expires_at, target_enc, target_index) VALUES (?, ?, ?, ?, ?, ?)";

    /** AuthStore.CodeFlow.EMAIL_CHANGE */
    public static final String AUTH_CODE_EMAIL_CHANGE_ACTIVE_OF = "SELECT id, admin_id, code_hash, attempts, target_enc, target_index FROM email_change_code WHERE admin_id = ? AND used_at IS NULL AND expires_at > ? ORDER BY id DESC";

    /** AuthStore.CodeFlow.EMAIL_CHANGE */
    public static final String AUTH_CODE_EMAIL_CHANGE_ACTIVE_ALL = "SELECT id, admin_id, code_hash, attempts, target_enc, target_index FROM email_change_code WHERE used_at IS NULL AND expires_at > ? ORDER BY id DESC";

    /** AuthStore.CodeFlow.EMAIL_CHANGE */
    public static final String AUTH_CODE_EMAIL_CHANGE_ATTEMPT = "UPDATE email_change_code SET attempts = attempts + 1 WHERE id = ?";

    /** AuthStore.CodeFlow.EMAIL_CHANGE */
    public static final String AUTH_CODE_EMAIL_CHANGE_CONSUME = "UPDATE email_change_code SET used_at = ? WHERE id = ? AND used_at IS NULL AND attempts <= ?";

    /** AuthStore.CodeFlow.EMAIL_CHANGE */
    public static final String AUTH_CODE_EMAIL_CHANGE_PURGE = "DELETE FROM email_change_code WHERE expires_at < ?";

    /** dataBaseManager: the secret's column, empty after the move into the file */
    public static final String CONFIG_GET_MYSQL_PASSWORD = "SELECT mysql_password FROM config WHERE id = 1";

    /** dataBaseManager.migrateSecrets */
    public static final String CONFIG_CLEAR_MYSQL_PASSWORD = "UPDATE config SET mysql_password = '' WHERE id = 1";

    /** dataBaseManager: the secret's column, empty after the move into the file */
    public static final String CONFIG_GET_PANEL_TLS_KEY = "SELECT panel_ssl_cert_key FROM config WHERE id = 1";

    /** dataBaseManager.migrateSecrets */
    public static final String CONFIG_CLEAR_PANEL_TLS_KEY = "UPDATE config SET panel_ssl_cert_key = '' WHERE id = 1";

    /** dataBaseManager.setMysqlPassword e updateMySQLPassword */
    public static final String CONFIG_SET_MYSQL_PASSWORD = "UPDATE config SET mysql_password = ? WHERE id = 1";

    /** dataBaseManager.isServiceInstalled */
    public static final String CONFIG_GET_POSTFIX_INSTALLED = "SELECT postfix_installed FROM config WHERE id = 1";

    /** dataBaseManager.setServiceInstalled */
    public static final String CONFIG_SET_POSTFIX_INSTALLED = "UPDATE config SET postfix_installed = ? WHERE id = 1";

    /** dataBaseManager.isServiceInstalled */
    public static final String CONFIG_GET_DOVECOT_INSTALLED = "SELECT dovecot_installed FROM config WHERE id = 1";

    /** dataBaseManager.setServiceInstalled */
    public static final String CONFIG_SET_DOVECOT_INSTALLED = "UPDATE config SET dovecot_installed = ? WHERE id = 1";

    /** dataBaseManager.isServiceInstalled */
    public static final String CONFIG_GET_RSPAMD_INSTALLED = "SELECT rspamd_installed FROM config WHERE id = 1";

    /** dataBaseManager.setServiceInstalled */
    public static final String CONFIG_SET_RSPAMD_INSTALLED = "UPDATE config SET rspamd_installed = ? WHERE id = 1";

    /** dataBaseManager.isServiceInstalled */
    public static final String CONFIG_GET_CLAMAV_INSTALLED = "SELECT clamav_installed FROM config WHERE id = 1";

    /** dataBaseManager.setServiceInstalled */
    public static final String CONFIG_SET_CLAMAV_INSTALLED = "UPDATE config SET clamav_installed = ? WHERE id = 1";

    /** dataBaseManager.isServiceInstalled */
    public static final String CONFIG_GET_ROUNDCUBE_INSTALLED = "SELECT roundcube_installed FROM config WHERE id = 1";

    /** dataBaseManager.setServiceInstalled */
    public static final String CONFIG_SET_ROUNDCUBE_INSTALLED = "UPDATE config SET roundcube_installed = ? WHERE id = 1";

    /** database: the same value as database.BUSY_TIMEOUT_MS (checked by SqlCatalogTest) */
    public static final String CONFIG_DB_BUSY_TIMEOUT = "PRAGMA busy_timeout = 15000";

    /** database.columnExists: the columns of config, instead of trying to read one by name */
    public static final String CONFIG_DB_COLUMNS = "PRAGMA table_info(config)";

    /** database.create_tables */
    public static final String CONFIG_DB_CREATE_TABLE = "CREATE TABLE config (\n"
            + "    id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
            + "    panel_port TEXT DEFAULT '2096',\n"
            + "    panel_host TEXT DEFAULT '127.0.0.1',\n"
            + "    panel_ssl_cert TEXT DEFAULT '',\n"
            + "    panel_ssl_cert_key TEXT DEFAULT '',\n"
            + "    panel_ssl_chain TEXT DEFAULT '',\n"
            + "    panel_sessions_prefix TEXT DEFAULT 'daemoxcp-mail-',\n"
            + "    mysql_host TEXT DEFAULT '127.0.0.1',\n"
            + "    mysql_port TEXT DEFAULT '3306',\n"
            + "    mysql_user TEXT DEFAULT 'daemoxcp_mail',\n"
            + "    mysql_password TEXT DEFAULT '',\n"
            + "    mysql_database TEXT DEFAULT 'daemoxcp_mail',\n"
            + "    mail_hostname TEXT DEFAULT '',\n"
            + "    postfix_installed INTEGER DEFAULT 0,\n"
            + "    dovecot_installed INTEGER DEFAULT 0,\n"
            + "    rspamd_installed INTEGER DEFAULT 0,\n"
            + "    clamav_installed INTEGER DEFAULT 0,\n"
            + "    roundcube_installed INTEGER DEFAULT 0,\n"
            + "    roundcube_domain TEXT DEFAULT 'webmail.example.com',\n"
            + "    roundcube_port TEXT DEFAULT '8443',\n"
            + "    roundcube_ssl_cert TEXT DEFAULT '',\n"
            + "    roundcube_ssl_key TEXT DEFAULT '',\n"
            + "    roundcube_ssl_chain TEXT DEFAULT ''\n"
            + ")\n";

    /** database: the columns added after the first version */
    public static final String CONFIG_DB_ADD_MAIL_HOSTNAME = "ALTER TABLE config ADD COLUMN mail_hostname TEXT DEFAULT ''";

    /** database: the columns added after the first version */
    /**
     * database: the configuration columns under the product's previous name (2026-11-17); a column name is not a
     * parameter
     */
    public static final String CONFIG_DB_RENAME_MAIL_PANEL_SSL_CERT_KEY = "ALTER TABLE config RENAME COLUMN mail_panel_ssl_cert_key TO panel_ssl_cert_key";
    public static final String CONFIG_DB_RENAME_MAIL_PANEL_SSL_CHAIN = "ALTER TABLE config RENAME COLUMN mail_panel_ssl_chain TO panel_ssl_chain";
    public static final String CONFIG_DB_RENAME_MAIL_PANEL_SSL_CERT = "ALTER TABLE config RENAME COLUMN mail_panel_ssl_cert TO panel_ssl_cert";
    public static final String CONFIG_DB_RENAME_MAIL_PANEL_SESSIONS_PREFIX = "ALTER TABLE config RENAME COLUMN mail_panel_sessions_prefix TO panel_sessions_prefix";
    public static final String CONFIG_DB_RENAME_MAIL_PANEL_HOST = "ALTER TABLE config RENAME COLUMN mail_panel_host TO panel_host";
    public static final String CONFIG_DB_RENAME_MAIL_PANEL_PORT = "ALTER TABLE config RENAME COLUMN mail_panel_port TO panel_port";

    public static final String CONFIG_DB_ADD_PANEL_SSL_CHAIN = "ALTER TABLE config ADD COLUMN panel_ssl_chain TEXT DEFAULT ''";

    /** database: the columns added after the first version */
    public static final String CONFIG_DB_ADD_ROUNDCUBE_DOMAIN = "ALTER TABLE config ADD COLUMN roundcube_domain TEXT DEFAULT 'webmail.example.com'";

    /** database: the columns added after the first version */
    public static final String CONFIG_DB_ADD_ROUNDCUBE_PORT = "ALTER TABLE config ADD COLUMN roundcube_port TEXT DEFAULT '8443'";

    /** database: the columns added after the first version */
    public static final String CONFIG_DB_ADD_ROUNDCUBE_SSL_CERT = "ALTER TABLE config ADD COLUMN roundcube_ssl_cert TEXT DEFAULT ''";

    /** database: the columns added after the first version */
    public static final String CONFIG_DB_ADD_ROUNDCUBE_SSL_KEY = "ALTER TABLE config ADD COLUMN roundcube_ssl_key TEXT DEFAULT ''";

    /** database: the columns added after the first version */
    public static final String CONFIG_DB_ADD_ROUNDCUBE_SSL_CHAIN = "ALTER TABLE config ADD COLUMN roundcube_ssl_chain TEXT DEFAULT ''";

    /** database: the columns added after the first version */
    public static final String CONFIG_DB_ADD_POSTFIX_INSTALLED = "ALTER TABLE config ADD COLUMN postfix_installed INTEGER DEFAULT 0";

    /** database.ensurePostfixColumn */
    public static final String CONFIG_DB_COPY_OPENSMTPD_INSTALLED = "UPDATE config SET postfix_installed = opensmtpd_installed";

    /** PublicSurfaceRename.moveJailState, in fail2ban's database (server/database.py) */
    public static final String RENAME_ADD_JAIL = "INSERT OR IGNORE INTO jails(name, enabled) VALUES (?, 0)";

    /** PublicSurfaceRename.moveJailState */
    public static final String RENAME_MOVE_JAIL_BIPS = "UPDATE OR IGNORE bips SET jail = ? WHERE jail = ?";

    /** PublicSurfaceRename.moveJailState */
    public static final String RENAME_MOVE_JAIL_BANS = "UPDATE OR IGNORE bans SET jail = ? WHERE jail = ?";

    /** PublicSurfaceRename.moveJailState */
    public static final String RENAME_MOVE_JAIL_LOGS = "UPDATE OR IGNORE logs SET jail = ?, path = ? WHERE jail = ? AND path = ?";

    // ========== The role permissions and the MySQL users of the web part (WebDbAccess) ==========

    /**
     * WebDbAccess: the permissions of each role, for the procedures of the web part. The root part writes them at every
     * boot from the Java permissions (AuthStore): the table is a copy, the web part neither writes nor reads it. ASCII,
     * like the parameter it is compared with (web_session_admin): same collation, whatever the database's one is.
     */
    public static final String ROLES_CREATE_TABLE = "CREATE TABLE IF NOT EXISTS panel_role_permissions (\n"
            + "    role VARCHAR(16) CHARACTER SET ascii NOT NULL,\n"
            + "    permission VARCHAR(32) CHARACTER SET ascii NOT NULL,\n"
            + "    PRIMARY KEY (role, permission)\n"
            + ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4\n";

    /** WebDbAccess */
    public static final String ROLES_LIST = "SELECT role, permission FROM panel_role_permissions";

    /** WebDbAccess */
    public static final String ROLES_CLEAR = "DELETE FROM panel_role_permissions";

    /** WebDbAccess */
    public static final String ROLES_ADD = "INSERT INTO panel_role_permissions (role, permission) VALUES (?, ?)";

    /** WebDbAccess, as MySQL root: the two new users, whether they exist and whether they are locked */
    public static final String WEB_DB_USERS = "SELECT user, host, account_locked FROM mysql.user WHERE user IN ('daemoxcp_mail_routines', 'daemoxcp_mail_web')";

    /**
     * WebDbAccess: who owns the procedures. Locked (nobody logs in as it), and with a password that is not written
     * anywhere: if someone unlocked it, they still would not know what to log in with.
     */
    public static final String WEB_DB_CREATE_ROUTINES_USER = "CREATE USER IF NOT EXISTS 'daemoxcp_mail_routines'@'localhost' IDENTIFIED BY ? ACCOUNT LOCK";

    /** WebDbAccess */
    public static final String WEB_DB_LOCK_ROUTINES_USER = "ALTER USER 'daemoxcp_mail_routines'@'localhost' ACCOUNT LOCK";

    /**
     * WebDbAccess: the permissions of daemoxcp_mail_routines, the ones the procedures need and nothing more, in the
     * panel's database (the one of the connection). EXECUTE on the database: MySQL requires it even from whoever
     * defined a procedure, to run it (and for web_session_admin, which the others call). The UPDATEs only on the
     * columns the procedures change; SELECT also where they write, because MySQL requires it for the columns of the
     * WHERE.
     */
    public static final String WEB_DB_GRANT_ROUTINES_EXECUTE = "GRANT EXECUTE ON * TO 'daemoxcp_mail_routines'@'localhost'";

    /** WebDbAccess */
    public static final String WEB_DB_GRANT_ROUTINES_SESSIONS = "GRANT SELECT, UPDATE (last_seen_at) ON panel_sessions TO 'daemoxcp_mail_routines'@'localhost'";

    /** WebDbAccess */
    public static final String WEB_DB_GRANT_ROUTINES_ADMINS = "GRANT SELECT, UPDATE (theme, language) ON panel_admin TO 'daemoxcp_mail_routines'@'localhost'";

    /** WebDbAccess */
    public static final String WEB_DB_GRANT_ROUTINES_ROLES = "GRANT SELECT ON panel_role_permissions TO 'daemoxcp_mail_routines'@'localhost'";

    /** WebDbAccess */
    public static final String WEB_DB_GRANT_ROUTINES_SETTINGS = "GRANT SELECT ON panel_settings TO 'daemoxcp_mail_routines'@'localhost'";

    /** WebDbAccess */
    public static final String WEB_DB_GRANT_ROUTINES_AUDIT = "GRANT INSERT ON audit_log TO 'daemoxcp_mail_routines'@'localhost'";

    /** WebDbAccess */
    public static final String WEB_DB_GRANT_ROUTINES_DOMAINS = "GRANT SELECT, INSERT, UPDATE (description), DELETE ON domains TO 'daemoxcp_mail_routines'@'localhost'";

    /** WebDbAccess */
    public static final String WEB_DB_GRANT_ROUTINES_MAILBOXES = "GRANT SELECT, INSERT, UPDATE (name, quota_mb, active, receive_enabled, junk_expunge_days, trash_expunge_days, password, password_encrypted, password_encrypted_at), DELETE ON mailboxes TO 'daemoxcp_mail_routines'@'localhost'";

    /** WebDbAccess */
    public static final String WEB_DB_GRANT_ROUTINES_ALIASES = "GRANT SELECT, INSERT, UPDATE (active), DELETE ON aliases TO 'daemoxcp_mail_routines'@'localhost'";

    /** WebDbAccess */
    public static final String WEB_DB_GRANT_ROUTINES_RATE_LIMITS = "GRANT SELECT, DELETE ON rate_limits TO 'daemoxcp_mail_routines'@'localhost'";

    /** WebDbAccess */
    public static final String WEB_DB_GRANT_ROUTINES_AUTO_RESPONDERS = "GRANT SELECT ON auto_responders TO 'daemoxcp_mail_routines'@'localhost'";

    /** WebDbAccess */
    public static final String WEB_DB_GRANT_ROUTINES_FORWARDING = "GRANT SELECT ON forwarding_rules TO 'daemoxcp_mail_routines'@'localhost'";

    /** WebDbAccess */
    public static final String WEB_DB_GRANT_ROUTINES_FILTERS = "GRANT SELECT ON sieve_filters TO 'daemoxcp_mail_routines'@'localhost'";

    /** WebDbAccess */
    public static final String WEB_DB_GRANT_ROUTINES_STATISTICS = "GRANT SELECT ON email_statistics TO 'daemoxcp_mail_routines'@'localhost'";

    /** WebDbAccess */
    public static final String WEB_DB_GRANT_ROUTINES_TRAINING = "GRANT SELECT ON rspamd_training TO 'daemoxcp_mail_routines'@'localhost'";

    /** WebDbAccess */
    public static final String WEB_DB_GRANT_ROUTINES_WEBMAIL_TOKENS = "GRANT INSERT ON roundcube_tokens TO 'daemoxcp_mail_routines'@'localhost'";

    /**
     * WebDbAccess: the procedures of the panel's database, with their comment (the fingerprint of the text) and who
     * defined them
     */
    public static final String WEB_DB_ROUTINES = "SELECT routine_name, routine_comment, definer, security_type FROM information_schema.routines WHERE routine_schema = DATABASE() AND routine_type = 'PROCEDURE'";

    /** WebDbAccess: the user of the web part, with the two names it logs into MySQL with (like the panel's user) */
    public static final String WEB_DB_CREATE_WEB_USER = "CREATE USER IF NOT EXISTS 'daemoxcp_mail_web'@'localhost' IDENTIFIED BY ?, 'daemoxcp_mail_web'@'127.0.0.1' IDENTIFIED BY ?";

    /** WebDbAccess */
    public static final String WEB_DB_SET_WEB_PASSWORD = "ALTER USER 'daemoxcp_mail_web'@'localhost' IDENTIFIED BY ?, 'daemoxcp_mail_web'@'127.0.0.1' IDENTIFIED BY ?";

    /** WebDbAccess: the web user's permissions that are not the EXECUTE of a procedure (there must be zero of them) */
    public static final String WEB_DB_WEB_OTHER_PRIVILEGES = "SELECT privilege_type FROM information_schema.user_privileges WHERE grantee IN (?, ?) AND privilege_type <> 'USAGE'\n"
            + "UNION ALL SELECT privilege_type FROM information_schema.schema_privileges WHERE grantee IN (?, ?)\n"
            + "UNION ALL SELECT privilege_type FROM information_schema.table_privileges WHERE grantee IN (?, ?)\n"
            + "UNION ALL SELECT privilege_type FROM information_schema.column_privileges WHERE grantee IN (?, ?)\n"
            + "UNION ALL SELECT priv FROM mysql.global_grants WHERE user = 'daemoxcp_mail_web'\n"
            + "UNION ALL SELECT from_user FROM mysql.role_edges WHERE to_user = 'daemoxcp_mail_web'";

    /** WebDbAccess: the procedures on which the web user has a permission, in which database, and which permission */
    public static final String WEB_DB_WEB_ROUTINE_PRIVILEGES = "SELECT host, db, routine_name, routine_type, proc_priv FROM mysql.procs_priv WHERE user = 'daemoxcp_mail_web'";

    /** WebDbAccess: if the web user had anything else, everything is revoked and only the procedures are granted again */
    public static final String WEB_DB_REVOKE_WEB = "REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'daemoxcp_mail_web'@'localhost', 'daemoxcp_mail_web'@'127.0.0.1'";

    // ========== MySQL root and the queries of the updates (MysqlRoot, MysqlListen, UpdateManager) ==========
    //
    // MysqlRoot.query sends to the mysql client (root over the socket, with the password from the secrets file) only
    // these fixed statements, without values: CatalogGuard.allowed checks this. Queries with a value go through JDBC,
    // with the value as a parameter.

    /** MysqlRoot, MysqlListen, UpdateManager: does root answer? */
    public static final String MYSQL_ROOT_PING = "SELECT 1";

    /** MysqlRoot: the root accounts without a password (host only, no data) */
    public static final String MYSQL_ROOT_EMPTY_HOSTS = "SELECT host FROM mysql.user WHERE user = 'root' AND authentication_string = '' ORDER BY host";

    /** MysqlRoot, via JDBC as root: the password of a root account, host and password as parameters */
    public static final String MYSQL_ROOT_SET_PASSWORD = "ALTER USER 'root'@? IDENTIFIED BY ?";

    /** UpdateManager: an active mailbox, for the tests after an update */
    public static final String UM_FIRST_ACTIVE_MAILBOX = "SELECT email FROM mailboxes WHERE active = 1 LIMIT 1";

    /** UpdateManager: the same condition as Dovecot's password_query, without reading the password */
    public static final String UM_ACTIVE_MAILBOX_COUNT = "SELECT COUNT(*) FROM mailboxes WHERE email = ? AND active = 1";

    /** UpdateManager: can whoever is asking read the accounts table? */
    public static final String UM_CAN_READ_ACCOUNTS = "SELECT 1 FROM mysql.user LIMIT 1";

    /** UpdateManager: the accounts with mysql_native_password, which MySQL 8.4 no longer loads */
    public static final String UM_NATIVE_PASSWORD_ACCOUNTS = "SELECT CONCAT(user, '@', host) FROM mysql.user WHERE plugin = 'mysql_native_password'";

    /** UpdateManager: the authentication plugins in use, with how many accounts each */
    public static final String UM_AUTH_PLUGINS = "SELECT CONCAT(plugin, ' ', COUNT(*)) FROM mysql.user GROUP BY plugin";

    /** UpdateManager: how many databases, before and after the MySQL migration */
    public static final String UM_COUNT_SCHEMATA = "SELECT COUNT(*) FROM information_schema.schemata";

    /** UpdateManager: how many tables outside the system ones, before and after the MySQL migration */
    public static final String UM_COUNT_USER_TABLES = "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema NOT IN ('information_schema', 'performance_schema', 'mysql', 'sys')";

    /** UpdateManager: how many mailboxes, before and after the MySQL migration */
    public static final String UM_COUNT_MAILBOXES = "SELECT COUNT(*) FROM mailboxes";

    /** UpdateManager, with the Roundcube user: the tables of its database, before and after the update */
    public static final String UM_COUNT_SCHEMA_TABLES = "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = ?";

    /** UpdateManager, as root: because mysqldump asks for a FLUSH */
    public static final String UM_GTID_STATE = "SELECT CONCAT('gtid_mode=', @@gtid_mode, '  log_bin=', @@log_bin, '  enforce_gtid_consistency=', @@enforce_gtid_consistency)";

    // ========== The pkg database, in the plan's COPY (PackagePlan) ==========
    //
    // Only on the copy of /var/db/pkg made to compute a plan, never on the real database: a package that the job
    // will remove (pkg delete, even -f) is forgotten in the copy, rows and not files, and then pkg is asked with -n
    // what it would install. The rows that depend on the package (files, dependencies, options) go away with it:
    // pkg's tables have ON DELETE CASCADE, which SQLite applies only with foreign keys turned on.

    /** PackagePlan, on the copy of the pkg database */
    public static final String PKGDB_FOREIGN_KEYS_ON = "PRAGMA foreign_keys = ON";

    /** PackagePlan, on the copy of the pkg database: a forgotten package */
    public static final String PKGDB_FORGET_PACKAGE = "DELETE FROM packages WHERE name = ?";

    // ========== The webmail with its own MySQL user (RoundcubeDbUser) ==========
    //
    // Via JDBC, as root or with the user of the webmail and of the panel: the account names and the passwords as
    // parameters (Connector/J quotes them, and the account syntax accepts them that way). The statements with
    // "ON *" apply to the connection's database: the webmail's one, in the URL. What MySQL prints
    // (SHOW GRANTS) is only read, never re-executed.

    /** RoundcubeDbUser: does the webmail account exist on that host? */
    public static final String RC_ACCOUNT_EXISTS = "SELECT COUNT(*) FROM mysql.user WHERE user = 'roundcube' AND host = ?";

    /** RoundcubeDbUser: the privileges of an account, user and host as parameters; they are read, not re-executed */
    public static final String RC_SHOW_GRANTS = "SHOW GRANTS FOR ?@?";

    /** RoundcubeDbUser: the hosts of the panel's user */
    public static final String RC_PANEL_HOSTS = "SELECT host FROM mysql.user WHERE user = ? ORDER BY host";

    // PanelDbPassword (finding 232): the password of the panel's user changed once, with MySQL's dual password
    // (8.0.14 and later). User and host as parameters, in the order of ALTER USER ?@?.

    /** PanelDbPassword: the accounts of the panel's user, and whether they already have a second password */
    public static final String PDP_ACCOUNTS = "SELECT host, JSON_EXTRACT(User_attributes, '$.additional_password') IS NOT NULL FROM mysql.user WHERE user = ? ORDER BY host";

    /** PanelDbPassword: the new password; the current one stays valid alongside it */
    public static final String PDP_RETAIN = "ALTER USER ?@? IDENTIFIED BY ? RETAIN CURRENT PASSWORD";

    /** PanelDbPassword: to go back, the previous password made primary again (the second one stays) */
    public static final String PDP_SET = "ALTER USER ?@? IDENTIFIED BY ?";

    /** PanelDbPassword: the second password removed */
    public static final String PDP_DISCARD = "ALTER USER ?@? DISCARD OLD PASSWORD";

    /** RoundcubeDbUser */
    public static final String RC_CREATE_USER = "CREATE USER IF NOT EXISTS 'roundcube'@? IDENTIFIED BY ?";

    /** RoundcubeDbUser: the new password, or, to go back, the one the webmail was using */
    public static final String RC_SET_PASSWORD = "ALTER USER 'roundcube'@? IDENTIFIED BY ?";

    /** RoundcubeDbUser, on the webmail's database: all of that database, and only that, to the webmail */
    public static final String RC_GRANT_DATABASE = "GRANT ALL PRIVILEGES ON * TO 'roundcube'@?";

    /** RoundcubeDbUser: to go back, if the account did not exist before */
    public static final String RC_DROP_USER = "DROP USER IF EXISTS 'roundcube'@?";

    /** RoundcubeDbUser, on the webmail's database: the webmail's database taken away from the panel's user */
    public static final String RC_REVOKE_PANEL = "REVOKE IF EXISTS ALL PRIVILEGES ON * FROM ?@? IGNORE UNKNOWN USER";

    /** RoundcubeDbUser, on the webmail's database: to go back, given back to the panel's user as the installer gives it */
    public static final String RC_GRANT_PANEL = "GRANT ALL PRIVILEGES ON * TO ?@?";

    /** RoundcubeDbUser, on the webmail's database: has the session opened by the login page arrived? */
    public static final String RC_SESSION_EXISTS = "SELECT COUNT(*) FROM session WHERE sess_id = ?";

    /** RoundcubeDbUser, with the webmail's user: can it read its sessions? */
    public static final String RC_SESSIONS_READABLE = "SELECT COUNT(*) FROM session";

    /** RoundcubeDbUser: the webmail's connections as seen by MySQL; -1 if performance_schema is off */
    public static final String RC_CONNECTIONS = "SELECT IF(@@performance_schema, (SELECT COALESCE(SUM(TOTAL_CONNECTIONS), 0) FROM performance_schema.accounts WHERE USER = 'roundcube'), -1)";

    /**
     * RoundcubeDbUser, on the webmail's database: the mailboxes that have already logged in with the panel's SSO
     * ("mailbox*admin")
     */
    public static final String RC_SSO_USERS = "SELECT username FROM users WHERE username LIKE ?";

    // ========== The MySQL users of Postfix and Dovecot (MailDbUsers) ==========
    //
    // Postfix and Dovecot only read, each one its own columns: Postfix domains, mailboxes and aliases, never the
    // passwords; Dovecot address, password hash and state of the mailboxes. Before, they logged in with the panel's
    // user, which can do anything in the database. The names are fixed, the two hosts as for the panel's user.

    /** MailDbUsers, as MySQL root: the two users, if they exist */
    public static final String MAILDB_USERS = "SELECT user, host FROM mysql.user WHERE user IN ('daemoxcp_mail_postfix', 'daemoxcp_mail_dovecot')";

    /** MailDbUsers */
    public static final String MAILDB_CREATE_POSTFIX_USER = "CREATE USER IF NOT EXISTS 'daemoxcp_mail_postfix'@'localhost' IDENTIFIED BY ?, 'daemoxcp_mail_postfix'@'127.0.0.1' IDENTIFIED BY ?";

    /** MailDbUsers */
    public static final String MAILDB_SET_POSTFIX_PASSWORD = "ALTER USER 'daemoxcp_mail_postfix'@'localhost' IDENTIFIED BY ?, 'daemoxcp_mail_postfix'@'127.0.0.1' IDENTIFIED BY ?";

    /** MailDbUsers */
    public static final String MAILDB_CREATE_DOVECOT_USER = "CREATE USER IF NOT EXISTS 'daemoxcp_mail_dovecot'@'localhost' IDENTIFIED BY ?, 'daemoxcp_mail_dovecot'@'127.0.0.1' IDENTIFIED BY ?";

    /** MailDbUsers */
    public static final String MAILDB_SET_DOVECOT_PASSWORD = "ALTER USER 'daemoxcp_mail_dovecot'@'localhost' IDENTIFIED BY ?, 'daemoxcp_mail_dovecot'@'127.0.0.1' IDENTIFIED BY ?";

    /** MailDbUsers: Postfix, the domains (virtual_mailbox_domains) */
    public static final String MAILDB_GRANT_POSTFIX_DOMAINS = "GRANT SELECT (domain, active) ON domains TO 'daemoxcp_mail_postfix'@'localhost', 'daemoxcp_mail_postfix'@'127.0.0.1'";

    /** MailDbUsers: Postfix, the mailboxes (virtual_mailbox_maps): no passwords */
    public static final String MAILDB_GRANT_POSTFIX_MAILBOXES = "GRANT SELECT (email, active, receive_enabled) ON mailboxes TO 'daemoxcp_mail_postfix'@'localhost', 'daemoxcp_mail_postfix'@'127.0.0.1'";

    /** MailDbUsers: Postfix, the aliases (virtual_alias_maps) */
    public static final String MAILDB_GRANT_POSTFIX_ALIASES = "GRANT SELECT (source, destination, active) ON aliases TO 'daemoxcp_mail_postfix'@'localhost', 'daemoxcp_mail_postfix'@'127.0.0.1'";

    /** MailDbUsers: Dovecot, the access to the mailboxes (passdb) and their limit (sql userdb, DovecotQuota) */
    public static final String MAILDB_GRANT_DOVECOT_MAILBOXES = "GRANT SELECT (email, password, active, quota_mb, junk_expunge_days, trash_expunge_days) ON mailboxes TO 'daemoxcp_mail_dovecot'@'localhost', 'daemoxcp_mail_dovecot'@'127.0.0.1'";

    /** MailDbUsers: a user's permissions that are not per-column ones (there must be zero of them) */
    public static final String MAILDB_OTHER_PRIVILEGES = "SELECT privilege_type FROM information_schema.user_privileges WHERE grantee IN (?, ?) AND privilege_type <> 'USAGE'\n"
            + "UNION ALL SELECT privilege_type FROM information_schema.schema_privileges WHERE grantee IN (?, ?)\n"
            + "UNION ALL SELECT privilege_type FROM information_schema.table_privileges WHERE grantee IN (?, ?)\n"
            + "UNION ALL SELECT priv FROM mysql.global_grants WHERE user = ?\n"
            + "UNION ALL SELECT from_user FROM mysql.role_edges WHERE to_user = ?\n"
            + "UNION ALL SELECT routine_name FROM mysql.procs_priv WHERE user = ?";

    /** MailDbUsers: a user's per-column permissions, with the database, the table and the column */
    public static final String MAILDB_COLUMN_PRIVILEGES = "SELECT grantee, table_schema, table_name, column_name, privilege_type FROM information_schema.column_privileges WHERE grantee IN (?, ?)";

    /** MailDbUsers */
    public static final String MAILDB_REVOKE_POSTFIX = "REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'daemoxcp_mail_postfix'@'localhost', 'daemoxcp_mail_postfix'@'127.0.0.1'";

    /** MailDbUsers */
    public static final String MAILDB_REVOKE_DOVECOT = "REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'daemoxcp_mail_dovecot'@'localhost', 'daemoxcp_mail_dovecot'@'127.0.0.1'";

    /** MailDbUsers, as MySQL root: the connections a user has open right now (Dovecot keeps its own open) */
    public static final String MAILDB_CONNECTIONS = "SELECT COUNT(*) FROM information_schema.processlist WHERE user = ?";

    /** MailDbUsers, as Postfix's user: the query of mysql-virtual-domains.cf */
    public static final String MAILDB_POSTFIX_DOMAIN_LOOKUP = "SELECT domain FROM domains WHERE domain = ? AND active = 1";

    /** MailDbUsers, as Postfix's user: the query of mysql-virtual-mailboxes.cf */
    public static final String MAILDB_POSTFIX_MAILBOX_LOOKUP = "SELECT CONCAT(SUBSTRING_INDEX(email, '@', -1), '/', SUBSTRING_INDEX(email, '@', 1), '/') FROM mailboxes WHERE email = ? AND active = 1 AND receive_enabled = 1";

    /** MailDbUsers, as Postfix's user: the query of mysql-virtual-aliases.cf */
    public static final String MAILDB_POSTFIX_ALIAS_LOOKUP = "SELECT destination FROM aliases WHERE source = ? AND active = 1";

    /** MailDbUsers, as Postfix's user: the query of mysql-virtual-mailbox-addresses.cf (MailboxAddressMap) */
    public static final String MAILDB_POSTFIX_ADDRESS_LOOKUP = "SELECT email FROM mailboxes WHERE email = ? AND active = 1 AND receive_enabled = 1";

    /** MailDbUsers, as Postfix's user: the query of mysql-sender-login-maps.cf (SenderLoginMap) */
    public static final String MAILDB_POSTFIX_SENDER_LOOKUP = "SELECT email FROM mailboxes WHERE email = ? AND active = 1 UNION SELECT destination FROM aliases WHERE source = ? AND active = 1";

    /** MailDbUsers, as Postfix's user: the password of a mailbox, which must be refused */
    public static final String MAILDB_POSTFIX_PASSWORD_REFUSED = "SELECT password FROM mailboxes WHERE email = ?";

    /** MailDbUsers, as Dovecot's user: the passdb query */
    public static final String MAILDB_DOVECOT_PASSWORD_LOOKUP = "SELECT email AS user, password FROM mailboxes WHERE email = ? AND active = 1";

    /** MailDbUsers, as Dovecot's user: the query of the quota userdb (DovecotConfig.QUOTA_USERDB) */
    public static final String MAILDB_DOVECOT_QUOTA_LOOKUP = "SELECT CONCAT(quota_mb, 'M') AS quota_storage_size,"
            + " IF(junk_expunge_days > 0, CONCAT(junk_expunge_days, 'd'), NULL) AS 'namespace/inbox/mailbox/Junk/mailbox_autoexpunge',"
            + " IF(trash_expunge_days > 0, CONCAT(trash_expunge_days, 'd'), NULL) AS 'namespace/inbox/mailbox/Trash/mailbox_autoexpunge'"
            + " FROM mailboxes WHERE email = ? AND active = 1";

    /** MailDbUsers, as Dovecot's user: an alias, which must be refused */
    public static final String MAILDB_DOVECOT_ALIAS_REFUSED = "SELECT destination FROM aliases WHERE source = ?";

    // ========== The procedures of the web part ==========
    //
    // Every MySQL statement of the web part has its own procedure: the web connection (CatalogGuard,
    // routines) calls it instead of sending the statement, with the fingerprint of the request's session
    // in front of the same parameters. The procedures belong to daemoxcp_mail_routines, locked, and run with its
    // permissions; the web part's MySQL user has only EXECUTE on them (WebDbAccess). Each one has four texts:
    // the call, the creation (with the comment as a parameter: the fingerprint of the text itself), the
    // drop and the grant.

    /** The start of every procedure of the web part: owned by daemoxcp_mail_routines. */
    private static final String WEB_CREATE = "CREATE DEFINER = 'daemoxcp_mail_routines'@'localhost' PROCEDURE ";
    /**
     * After the parameters: the comment (the fingerprint of the text, WebDbAccess) and the permissions of whoever
     * defined it.
     */
    private static final String WEB_BEGIN = " COMMENT ? SQL SECURITY DEFINER\nBEGIN\n";
    /**
     * The first parameter of every procedure: the fingerprint of the token of the request's session, or NULL.
     *
     * <p>The parameters compared with a column (fingerprints, names, addresses, keys, permissions) are
     * CHARACTER SET ascii. Without it, they would take the database's collation (utf8mb4_unicode_ci, as the
     * installer creates it), different from the tables' one (utf8mb4_0900_ai_ci), and MySQL refuses the comparison
     * (Illegal mix of collations, seen on the VM on 2026-11-08). With one side in ASCII, the Unicode column wins.
     */
    private static final String WEB_SESSION = "IN p_session CHAR(64) CHARACTER SET ascii";
    /** Who can call them: the user of the web part, under both names it logs in with. */
    private static final String WEB_TO = " TO 'daemoxcp_mail_web'@'localhost', 'daemoxcp_mail_web'@'127.0.0.1'";
    /**
     * The request's session s: it exists, has not expired and has not been idle for more than 30 minutes
     * (WebSessions.IDLE_SECONDS, checked by SqlCatalogTest), by the database's clock.
     */
    private static final String WEB_SESSION_VALID = "s.token_hash = p_session AND s.expires_at > UTC_TIMESTAMP()"
            + " AND s.last_seen_at > UTC_TIMESTAMP() - INTERVAL 1800 SECOND";

    /**
     * WebDbAccess: the administrator of the request's session, if the session is valid, the administrator is active
     * and their role has one of the permissions (names separated by commas; empty: the session is enough). Otherwise
     * it stops the procedure that calls it. The roles are written by the root part at every boot
     * (panel_role_permissions). It does not belong to the web part.
     */
    public static final String WEB_CREATE_SESSION_ADMIN = WEB_CREATE + "web_session_admin(" + WEB_SESSION
            + ", IN p_permissions VARCHAR(255) CHARACTER SET ascii, OUT p_admin INT)" + WEB_BEGIN
            + "    SET p_admin = (SELECT a.id FROM panel_sessions s JOIN panel_admin a ON a.id = s.admin_id\n"
            + "        WHERE " + WEB_SESSION_VALID + " AND a.active = TRUE\n"
            + "        AND (p_permissions = '' OR EXISTS (SELECT 1 FROM panel_role_permissions rp\n"
            + "            WHERE rp.role = a.role AND FIND_IN_SET(rp.permission, p_permissions) > 0))\n"
            + "        LIMIT 1);\n"
            + "    IF p_admin IS NULL THEN\n"
            + "        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Not allowed for this session';\n"
            + "    END IF;\n"
            + "END";

    /** WebDbAccess */
    public static final String WEB_DROP_SESSION_ADMIN = "DROP PROCEDURE IF EXISTS web_session_admin";

    /**
     * SESSION_CHECK in the web part, public: the session of a token's fingerprint, the check itself: by the
     * database's clock, not the time that comes in.
     */
    public static final String WEB_CALL_CHECK_SESSION = "CALL check_session(?, ?, ?, ?)";

    /** WebDbAccess: the procedure of WEB_CALL_CHECK_SESSION. */
    public static final String WEB_CREATE_CHECK_SESSION = WEB_CREATE + "check_session(" + WEB_SESSION
            + ", IN p_token_hash CHAR(64) CHARACTER SET ascii, IN p_now DATETIME"
            + ", IN p_idle_since DATETIME)" + WEB_BEGIN
            + "    SELECT s.id, s.admin_id, s.ua_hash, s.last_seen_at, s.reauth_at FROM panel_sessions s\n"
            + "        WHERE s.token_hash = p_token_hash AND s.expires_at > UTC_TIMESTAMP()\n"
            + "        AND s.last_seen_at > UTC_TIMESTAMP() - INTERVAL 1800 SECOND;\n"
            + "END";

    /** WebDbAccess */
    public static final String WEB_DROP_CHECK_SESSION = "DROP PROCEDURE IF EXISTS check_session";

    /** WebDbAccess */
    public static final String WEB_GRANT_CHECK_SESSION = "GRANT EXECUTE ON PROCEDURE check_session" + WEB_TO;

    /**
     * SESSION_TOUCH in the web part, only for the request's session: its last activity, by the database's
     * clock.
     */
    public static final String WEB_CALL_TOUCH_SESSION = "CALL touch_session(?, ?, ?)";

    /** WebDbAccess: the procedure of WEB_CALL_TOUCH_SESSION. */
    public static final String WEB_CREATE_TOUCH_SESSION = WEB_CREATE + "touch_session(" + WEB_SESSION
            + ", IN p_time DATETIME, IN p_id BIGINT)" + WEB_BEGIN
            + "    UPDATE panel_sessions s SET s.last_seen_at = UTC_TIMESTAMP() WHERE s.id = p_id AND " + WEB_SESSION_VALID + ";\n"
            + "    SELECT ROW_COUNT() AS affected;\n"
            + "END";

    /** WebDbAccess */
    public static final String WEB_DROP_TOUCH_SESSION = "DROP PROCEDURE IF EXISTS touch_session";

    /** WebDbAccess */
    public static final String WEB_GRANT_TOUCH_SESSION = "GRANT EXECUTE ON PROCEDURE touch_session" + WEB_TO;

    /**
     * AUTH_ADMIN_BY_ID in the web part, only for the request's session: its administrator, and nobody
     * else (empty if the id is not its own).
     */
    public static final String WEB_CALL_GET_SESSION_ADMIN = "CALL get_session_admin(?, ?)";

    /** WebDbAccess: the procedure of WEB_CALL_GET_SESSION_ADMIN. */
    public static final String WEB_CREATE_GET_SESSION_ADMIN = WEB_CREATE + "get_session_admin(" + WEB_SESSION
            + ", IN p_id INT)" + WEB_BEGIN
            + "    SELECT a.id, a.username, a.role, a.active, a.email_enc, a.user_handle, a.created_at, a.last_login\n"
            + "        FROM panel_admin a JOIN panel_sessions s ON s.admin_id = a.id\n"
            + "        WHERE a.id = p_id AND a.active = TRUE AND " + WEB_SESSION_VALID + ";\n"
            + "END";

    /** WebDbAccess */
    public static final String WEB_DROP_GET_SESSION_ADMIN = "DROP PROCEDURE IF EXISTS get_session_admin";

    /** WebDbAccess */
    public static final String WEB_GRANT_GET_SESSION_ADMIN = "GRANT EXECUTE ON PROCEDURE get_session_admin" + WEB_TO;

    /** MAIL_GET_ADMIN_LANGUAGE in the web part, only for the request's session: its language. */
    public static final String WEB_CALL_GET_ADMIN_LANGUAGE = "CALL get_admin_language(?, ?)";

    /** WebDbAccess: the procedure of WEB_CALL_GET_ADMIN_LANGUAGE. */
    public static final String WEB_CREATE_GET_ADMIN_LANGUAGE = WEB_CREATE + "get_admin_language(" + WEB_SESSION
            + ", IN p_username VARCHAR(50) CHARACTER SET ascii)" + WEB_BEGIN
            + "    SELECT a.language FROM panel_admin a JOIN panel_sessions s ON s.admin_id = a.id\n"
            + "        WHERE a.username = p_username AND a.active = TRUE AND " + WEB_SESSION_VALID + ";\n"
            + "END";

    /** WebDbAccess */
    public static final String WEB_DROP_GET_ADMIN_LANGUAGE = "DROP PROCEDURE IF EXISTS get_admin_language";

    /** WebDbAccess */
    public static final String WEB_GRANT_GET_ADMIN_LANGUAGE = "GRANT EXECUTE ON PROCEDURE get_admin_language" + WEB_TO;

    /**
     * MAIL_SET_ADMIN_LANGUAGE in the web part, only for the session's administrator: their language, only one
     * of the panel's languages. The list is written here, because the catalog is only text: a new language (a file
     * in lang/) must be added here too, and I18nTest fails until the list equals I18n.LANGUAGES. The changed
     * text makes the procedure get recreated by itself at the first boot (WebDbAccess compares the fingerprint).
     */
    public static final String WEB_CALL_SET_ADMIN_LANGUAGE = "CALL set_admin_language(?, ?, ?)";

    /** WebDbAccess: the procedure of WEB_CALL_SET_ADMIN_LANGUAGE. */
    public static final String WEB_CREATE_SET_ADMIN_LANGUAGE = WEB_CREATE + "set_admin_language(" + WEB_SESSION
            + ", IN p_language VARCHAR(5), IN p_username VARCHAR(50) CHARACTER SET ascii)" + WEB_BEGIN
            + "    DECLARE v_admin INT;\n"
            + "    CALL web_session_admin(p_session, '', v_admin);\n"
            + "    IF p_language IS NOT NULL AND p_language NOT IN ('it', 'en') THEN\n"
            + "        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Language not allowed';\n"
            + "    END IF;\n"
            + "    UPDATE panel_admin SET language = p_language WHERE id = v_admin AND username = p_username;\n"
            + "    SELECT ROW_COUNT() AS affected;\n"
            + "END";

    /** WebDbAccess */
    public static final String WEB_DROP_SET_ADMIN_LANGUAGE = "DROP PROCEDURE IF EXISTS set_admin_language";

    /** WebDbAccess */
    public static final String WEB_GRANT_SET_ADMIN_LANGUAGE = "GRANT EXECUTE ON PROCEDURE set_admin_language" + WEB_TO;

    /** MAIL_GET_ADMIN_THEME in the web part, only for the request's session: its theme. */
    public static final String WEB_CALL_GET_ADMIN_THEME = "CALL get_admin_theme(?, ?)";

    /** WebDbAccess: the procedure of WEB_CALL_GET_ADMIN_THEME. */
    public static final String WEB_CREATE_GET_ADMIN_THEME = WEB_CREATE + "get_admin_theme(" + WEB_SESSION
            + ", IN p_username VARCHAR(50) CHARACTER SET ascii)" + WEB_BEGIN
            + "    SELECT a.theme FROM panel_admin a JOIN panel_sessions s ON s.admin_id = a.id\n"
            + "        WHERE a.username = p_username AND a.active = TRUE AND " + WEB_SESSION_VALID + ";\n"
            + "END";

    /** WebDbAccess */
    public static final String WEB_DROP_GET_ADMIN_THEME = "DROP PROCEDURE IF EXISTS get_admin_theme";

    /** WebDbAccess */
    public static final String WEB_GRANT_GET_ADMIN_THEME = "GRANT EXECUTE ON PROCEDURE get_admin_theme" + WEB_TO;

    /**
     * MAIL_SET_ADMIN_THEME in the web part, only for the session's administrator: their theme, only auto,
     * light or dark.
     */
    public static final String WEB_CALL_SET_ADMIN_THEME = "CALL set_admin_theme(?, ?, ?)";

    /** WebDbAccess: the procedure of WEB_CALL_SET_ADMIN_THEME. */
    public static final String WEB_CREATE_SET_ADMIN_THEME = WEB_CREATE + "set_admin_theme(" + WEB_SESSION
            + ", IN p_theme VARCHAR(10), IN p_username VARCHAR(50) CHARACTER SET ascii)" + WEB_BEGIN
            + "    DECLARE v_admin INT;\n"
            + "    CALL web_session_admin(p_session, '', v_admin);\n"
            + "    IF p_theme IS NULL OR p_theme NOT IN ('auto', 'light', 'dark') THEN\n"
            + "        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Theme not allowed';\n"
            + "    END IF;\n"
            + "    UPDATE panel_admin SET theme = p_theme WHERE id = v_admin AND username = p_username;\n"
            + "    SELECT ROW_COUNT() AS affected;\n"
            + "END";

    /** WebDbAccess */
    public static final String WEB_DROP_SET_ADMIN_THEME = "DROP PROCEDURE IF EXISTS set_admin_theme";

    /** WebDbAccess */
    public static final String WEB_GRANT_SET_ADMIN_THEME = "GRANT EXECUTE ON PROCEDURE set_admin_theme" + WEB_TO;

    /**
     * MAIL_HAS_ADMIN_USER in the web part, public: is there already an administrator? Public: the login page
     * needs to know.
     */
    public static final String WEB_CALL_HAS_ADMIN = "CALL has_admin(?)";

    /** WebDbAccess: the procedure of WEB_CALL_HAS_ADMIN. */
    public static final String WEB_CREATE_HAS_ADMIN = WEB_CREATE + "has_admin(" + WEB_SESSION + ")" + WEB_BEGIN
            + "    SELECT 1 FROM panel_admin WHERE active = TRUE LIMIT 1;\n"
            + "END";

    /** WebDbAccess */
    public static final String WEB_DROP_HAS_ADMIN = "DROP PROCEDURE IF EXISTS has_admin";

    /** WebDbAccess */
    public static final String WEB_GRANT_HAS_ADMIN = "GRANT EXECUTE ON PROCEDURE has_admin" + WEB_TO;

    /**
     * MAIL_GET_SETTING in the web part, public: a setting, only among those the web part reads: never the
     * Cloudflare token or the DNS challenges.
     */
    public static final String WEB_CALL_GET_SETTING = "CALL get_setting(?, ?)";

    /** WebDbAccess: the procedure of WEB_CALL_GET_SETTING. */
    public static final String WEB_CREATE_GET_SETTING = WEB_CREATE + "get_setting(" + WEB_SESSION
            + ", IN p_key VARCHAR(64) CHARACTER SET ascii)" + WEB_BEGIN
            + "    SELECT setting_value FROM panel_settings\n"
            + "        WHERE setting_key = p_key AND setting_key IN ('mail_hostname', 'mta_sts_mode', 'pop3_enabled', 'audit_log_file_path');\n"
            + "END";

    /** WebDbAccess */
    public static final String WEB_DROP_GET_SETTING = "DROP PROCEDURE IF EXISTS get_setting";

    /** WebDbAccess */
    public static final String WEB_GRANT_GET_SETTING = "GRANT EXECUTE ON PROCEDURE get_setting" + WEB_TO;

    /**
     * MAIL_LOG_AUDIT_EVENT in the web part, public: a row in the audit log: public, the web part also
     * logs those who have not logged in.
     */
    public static final String WEB_CALL_LOG_AUDIT_EVENT = "CALL log_audit_event(?, ?, ?, ?, ?)";

    /** WebDbAccess: the procedure of WEB_CALL_LOG_AUDIT_EVENT. */
    public static final String WEB_CREATE_LOG_AUDIT_EVENT = WEB_CREATE + "log_audit_event(" + WEB_SESSION
            + ", IN p_action VARCHAR(100), IN p_username VARCHAR(255), IN p_ip VARCHAR(45)"
            + ", IN p_details TEXT)" + WEB_BEGIN
            + "    INSERT INTO audit_log (action, username, ip_address, details) VALUES (p_action, p_username, p_ip, p_details);\n"
            + "    SELECT ROW_COUNT() AS affected;\n"
            + "END";

    /** WebDbAccess */
    public static final String WEB_DROP_LOG_AUDIT_EVENT = "DROP PROCEDURE IF EXISTS log_audit_event";

    /** WebDbAccess */
    public static final String WEB_GRANT_LOG_AUDIT_EVENT = "GRANT EXECUTE ON PROCEDURE log_audit_event" + WEB_TO;

    /**
     * MAIL_GET_DOMAIN_NAMES in the web part, public: the names of the hosted domains, for autoconfig and MTA-STS:
     * public, they are already in the DNS.
     */
    public static final String WEB_CALL_LIST_DOMAIN_NAMES = "CALL list_domain_names(?)";

    /** WebDbAccess: the procedure of WEB_CALL_LIST_DOMAIN_NAMES. */
    public static final String WEB_CREATE_LIST_DOMAIN_NAMES = WEB_CREATE + "list_domain_names(" + WEB_SESSION + ")" + WEB_BEGIN
            + "    SELECT domain FROM domains ORDER BY domain;\n"
            + "END";

    /** WebDbAccess */
    public static final String WEB_DROP_LIST_DOMAIN_NAMES = "DROP PROCEDURE IF EXISTS list_domain_names";

    /** WebDbAccess */
    public static final String WEB_GRANT_LIST_DOMAIN_NAMES = "GRANT EXECUTE ON PROCEDURE list_domain_names" + WEB_TO;

    /**
     * MAIL_GET_DOMAINS in the web part, with mail.view or security.view: the domains, without the private DKIM keys
     * (has_dkim says whether there is one).
     */
    public static final String WEB_CALL_LIST_DOMAINS = "CALL list_domains(?)";

    /** WebDbAccess: the procedure of WEB_CALL_LIST_DOMAINS. */
    public static final String WEB_CREATE_LIST_DOMAINS = WEB_CREATE + "list_domains(" + WEB_SESSION + ")" + WEB_BEGIN
            + "    DECLARE v_admin INT;\n"
            + "    CALL web_session_admin(p_session, 'mail.view,security.view', v_admin);\n"
            + "    SELECT d.id, d.domain, d.description, d.active, d.created_at, d.dkim_selector, d.dkim_public_key,\n"
            + "            (d.dkim_private_key IS NOT NULL AND d.dkim_private_key <> '') AS has_dkim,\n"
            + "            d.dkim_pending_selector, d.dkim_pending_public_key, d.dkim_rotation_state, d.dkim_rotation_started_at,\n"
            + "            d.dkim_rotation_activated_at, d.dkim_previous_selector, d.dkim_previous_public_key, d.dkim_dns_zone_id,\n"
            + "            d.dkim_pending_dns_record_id, d.dkim_previous_dns_record_id, d.dkim_rotation_interval_days,\n"
            + "            d.dkim_last_rotation_at, d.dkim_rotation_mode, d.cloudflare_account_id,\n"
            + "            (SELECT COUNT(*) FROM mailboxes m WHERE m.domain_id = d.id) AS mailbox_count,\n"
            + "            (SELECT COUNT(*) FROM aliases a WHERE a.domain_id = d.id) AS alias_count\n"
            + "        FROM domains d ORDER BY d.domain;\n"
            + "END";

    /** WebDbAccess */
    public static final String WEB_DROP_LIST_DOMAINS = "DROP PROCEDURE IF EXISTS list_domains";

    /** WebDbAccess */
    public static final String WEB_GRANT_LIST_DOMAINS = "GRANT EXECUTE ON PROCEDURE list_domains" + WEB_TO;

    /** MAIL_GET_DOMAIN_BY_NAME in the web part, with mail.view: a domain by name, without the private DKIM keys. */
    public static final String WEB_CALL_GET_DOMAIN_BY_NAME = "CALL get_domain_by_name(?, ?)";

    /** WebDbAccess: the procedure of WEB_CALL_GET_DOMAIN_BY_NAME. */
    public static final String WEB_CREATE_GET_DOMAIN_BY_NAME = WEB_CREATE + "get_domain_by_name(" + WEB_SESSION
            + ", IN p_domain VARCHAR(255) CHARACTER SET ascii)" + WEB_BEGIN
            + "    DECLARE v_admin INT;\n"
            + "    CALL web_session_admin(p_session, 'mail.view', v_admin);\n"
            + "    SELECT d.id, d.domain, d.description, d.active, d.created_at, d.dkim_selector, d.dkim_public_key,\n"
            + "            (d.dkim_private_key IS NOT NULL AND d.dkim_private_key <> '') AS has_dkim,\n"
            + "            d.dkim_pending_selector, d.dkim_pending_public_key, d.dkim_rotation_state, d.dkim_rotation_started_at,\n"
            + "            d.dkim_rotation_activated_at, d.dkim_previous_selector, d.dkim_previous_public_key, d.dkim_dns_zone_id,\n"
            + "            d.dkim_pending_dns_record_id, d.dkim_previous_dns_record_id, d.dkim_rotation_interval_days,\n"
            + "            d.dkim_last_rotation_at, d.dkim_rotation_mode, d.cloudflare_account_id\n"
            + "        FROM domains d WHERE d.domain = p_domain;\n"
            + "END";

    /** WebDbAccess */
    public static final String WEB_DROP_GET_DOMAIN_BY_NAME = "DROP PROCEDURE IF EXISTS get_domain_by_name";

    /** WebDbAccess */
    public static final String WEB_GRANT_GET_DOMAIN_BY_NAME = "GRANT EXECUTE ON PROCEDURE get_domain_by_name" + WEB_TO;

    /** MAIL_ADD_DOMAIN in the web part, with domains.manage: a new domain. */
    public static final String WEB_CALL_ADD_DOMAIN = "CALL add_domain(?, ?, ?)";

    /** WebDbAccess: the procedure of WEB_CALL_ADD_DOMAIN. */
    public static final String WEB_CREATE_ADD_DOMAIN = WEB_CREATE + "add_domain(" + WEB_SESSION
            + ", IN p_domain VARCHAR(255), IN p_description TEXT)" + WEB_BEGIN
            + "    DECLARE v_admin INT;\n"
            + "    CALL web_session_admin(p_session, 'domains.manage', v_admin);\n"
            + "    INSERT INTO domains (domain, description) VALUES (p_domain, p_description);\n"
            + "    SELECT ROW_COUNT() AS affected, LAST_INSERT_ID() AS id;\n"
            + "END";

    /** WebDbAccess */
    public static final String WEB_DROP_ADD_DOMAIN = "DROP PROCEDURE IF EXISTS add_domain";

    /** WebDbAccess */
    public static final String WEB_GRANT_ADD_DOMAIN = "GRANT EXECUTE ON PROCEDURE add_domain" + WEB_TO;

    /** MAIL_UPDATE_DOMAIN_DESCRIPTION in the web part, with domains.manage: the description of a domain. */
    public static final String WEB_CALL_SET_DOMAIN_DESCRIPTION = "CALL set_domain_description(?, ?, ?)";

    /** WebDbAccess: the procedure of WEB_CALL_SET_DOMAIN_DESCRIPTION. */
    public static final String WEB_CREATE_SET_DOMAIN_DESCRIPTION = WEB_CREATE + "set_domain_description(" + WEB_SESSION
            + ", IN p_description TEXT, IN p_id INT)" + WEB_BEGIN
            + "    DECLARE v_admin INT;\n"
            + "    CALL web_session_admin(p_session, 'domains.manage', v_admin);\n"
            + "    UPDATE domains SET description = p_description WHERE id = p_id;\n"
            + "    SELECT ROW_COUNT() AS affected;\n"
            + "END";

    /** WebDbAccess */
    public static final String WEB_DROP_SET_DOMAIN_DESCRIPTION = "DROP PROCEDURE IF EXISTS set_domain_description";

    /** WebDbAccess */
    public static final String WEB_GRANT_SET_DOMAIN_DESCRIPTION = "GRANT EXECUTE ON PROCEDURE set_domain_description" + WEB_TO;

    /** MAIL_DELETE_DOMAIN in the web part, with domains.manage: a domain, and, through the foreign keys, what it has. */
    public static final String WEB_CALL_DELETE_DOMAIN = "CALL delete_domain(?, ?)";

    /** WebDbAccess: the procedure of WEB_CALL_DELETE_DOMAIN. */
    public static final String WEB_CREATE_DELETE_DOMAIN = WEB_CREATE + "delete_domain(" + WEB_SESSION
            + ", IN p_id INT)" + WEB_BEGIN
            + "    DECLARE v_admin INT;\n"
            + "    CALL web_session_admin(p_session, 'domains.manage', v_admin);\n"
            + "    DELETE FROM domains WHERE id = p_id;\n"
            + "    SELECT ROW_COUNT() AS affected;\n"
            + "END";

    /** WebDbAccess */
    public static final String WEB_DROP_DELETE_DOMAIN = "DROP PROCEDURE IF EXISTS delete_domain";

    /** WebDbAccess */
    public static final String WEB_GRANT_DELETE_DOMAIN = "GRANT EXECUTE ON PROCEDURE delete_domain" + WEB_TO;

    /**
     * MAIL_GET_MAILBOXES in the web part, with mail.view: the mailboxes of a domain, without the hashes and copies of
     * the passwords.
     */
    public static final String WEB_CALL_LIST_DOMAIN_MAILBOXES = "CALL list_domain_mailboxes(?, ?)";

    /** WebDbAccess: the procedure of WEB_CALL_LIST_DOMAIN_MAILBOXES. */
    public static final String WEB_CREATE_LIST_DOMAIN_MAILBOXES = WEB_CREATE + "list_domain_mailboxes(" + WEB_SESSION
            + ", IN p_domain_id INT)" + WEB_BEGIN
            + "    DECLARE v_admin INT;\n"
            + "    CALL web_session_admin(p_session, 'mail.view', v_admin);\n"
            + "    SELECT m.id, m.domain_id, d.domain AS domain_name, m.email, m.name, m.quota_mb, m.active, m.receive_enabled,\n"
            + "            m.junk_expunge_days, m.trash_expunge_days, m.created_at, m.last_login\n"
            + "        FROM mailboxes m JOIN domains d ON m.domain_id = d.id WHERE m.domain_id = p_domain_id ORDER BY m.email;\n"
            + "END";

    /** WebDbAccess */
    public static final String WEB_DROP_LIST_DOMAIN_MAILBOXES = "DROP PROCEDURE IF EXISTS list_domain_mailboxes";

    /** WebDbAccess */
    public static final String WEB_GRANT_LIST_DOMAIN_MAILBOXES = "GRANT EXECUTE ON PROCEDURE list_domain_mailboxes" + WEB_TO;

    /**
     * MAIL_GET_ALL_MAILBOXES in the web part, with mail.view: all the mailboxes, without the hashes and copies of the
     * passwords.
     */
    public static final String WEB_CALL_LIST_MAILBOXES = "CALL list_mailboxes(?)";

    /** WebDbAccess: the procedure of WEB_CALL_LIST_MAILBOXES. */
    public static final String WEB_CREATE_LIST_MAILBOXES = WEB_CREATE + "list_mailboxes(" + WEB_SESSION + ")" + WEB_BEGIN
            + "    DECLARE v_admin INT;\n"
            + "    CALL web_session_admin(p_session, 'mail.view', v_admin);\n"
            + "    SELECT m.id, m.domain_id, d.domain AS domain_name, m.email, m.name, m.quota_mb, m.active, m.receive_enabled,\n"
            + "            m.junk_expunge_days, m.trash_expunge_days, m.created_at, m.last_login,\n"
            + "            (SELECT COUNT(*) FROM forwarding_rules fr WHERE fr.mailbox_id = m.id AND fr.enabled = 1) AS forwarding_count,\n"
            + "            (SELECT COUNT(*) FROM sieve_filters sf WHERE sf.mailbox_id = m.id AND sf.enabled = 1) AS filters_count,\n"
            + "            (SELECT COALESCE(ar.enabled, 0) FROM auto_responders ar WHERE ar.mailbox_id = m.id) AS autoresponder_enabled\n"
            + "        FROM mailboxes m JOIN domains d ON m.domain_id = d.id ORDER BY m.email;\n"
            + "END";

    /** WebDbAccess */
    public static final String WEB_DROP_LIST_MAILBOXES = "DROP PROCEDURE IF EXISTS list_mailboxes";

    /** WebDbAccess */
    public static final String WEB_GRANT_LIST_MAILBOXES = "GRANT EXECUTE ON PROCEDURE list_mailboxes" + WEB_TO;

    /** MAIL_GET_MAILBOX in the web part, with mail.view: a mailbox by id. */
    public static final String WEB_CALL_GET_MAILBOX = "CALL get_mailbox(?, ?)";

    /** WebDbAccess: the procedure of WEB_CALL_GET_MAILBOX. */
    public static final String WEB_CREATE_GET_MAILBOX = WEB_CREATE + "get_mailbox(" + WEB_SESSION
            + ", IN p_id INT)" + WEB_BEGIN
            + "    DECLARE v_admin INT;\n"
            + "    CALL web_session_admin(p_session, 'mail.view', v_admin);\n"
            + "    SELECT m.id, m.domain_id, d.domain AS domain_name, m.email, m.name, m.quota_mb, m.active, m.receive_enabled,\n"
            + "            m.junk_expunge_days, m.trash_expunge_days, m.created_at, m.last_login\n"
            + "        FROM mailboxes m JOIN domains d ON m.domain_id = d.id WHERE m.id = p_id;\n"
            + "END";

    /** WebDbAccess */
    public static final String WEB_DROP_GET_MAILBOX = "DROP PROCEDURE IF EXISTS get_mailbox";

    /** WebDbAccess */
    public static final String WEB_GRANT_GET_MAILBOX = "GRANT EXECUTE ON PROCEDURE get_mailbox" + WEB_TO;

    /** MAIL_GET_MAILBOX_BY_EMAIL in the web part, with mail.view: a mailbox by address. */
    public static final String WEB_CALL_GET_MAILBOX_BY_EMAIL = "CALL get_mailbox_by_email(?, ?)";

    /** WebDbAccess: the procedure of WEB_CALL_GET_MAILBOX_BY_EMAIL. */
    public static final String WEB_CREATE_GET_MAILBOX_BY_EMAIL = WEB_CREATE + "get_mailbox_by_email(" + WEB_SESSION
            + ", IN p_email VARCHAR(255) CHARACTER SET ascii)" + WEB_BEGIN
            + "    DECLARE v_admin INT;\n"
            + "    CALL web_session_admin(p_session, 'mail.view', v_admin);\n"
            + "    SELECT m.id, m.domain_id, d.domain AS domain_name, m.email, m.name, m.quota_mb, m.active, m.receive_enabled,\n"
            + "            m.junk_expunge_days, m.trash_expunge_days, m.created_at, m.last_login\n"
            + "        FROM mailboxes m JOIN domains d ON m.domain_id = d.id WHERE m.email = p_email;\n"
            + "END";

    /** WebDbAccess */
    public static final String WEB_DROP_GET_MAILBOX_BY_EMAIL = "DROP PROCEDURE IF EXISTS get_mailbox_by_email";

    /** WebDbAccess */
    public static final String WEB_GRANT_GET_MAILBOX_BY_EMAIL = "GRANT EXECUTE ON PROCEDURE get_mailbox_by_email" + WEB_TO;

    /** MAIL_INSERT_MAILBOX in the web part, with mailboxes.manage: a new mailbox. */
    public static final String WEB_CALL_ADD_MAILBOX = "CALL add_mailbox(?, ?, ?, ?, ?, ?, ?, ?, ?)";

    /** WebDbAccess: the procedure of WEB_CALL_ADD_MAILBOX. */
    public static final String WEB_CREATE_ADD_MAILBOX = WEB_CREATE + "add_mailbox(" + WEB_SESSION
            + ", IN p_domain_id INT, IN p_email VARCHAR(255), IN p_password VARCHAR(255)"
            + ", IN p_password_encrypted TEXT, IN p_password_encrypted_at DATETIME"
            + ", IN p_name VARCHAR(255), IN p_quota_mb INT, IN p_receive_enabled BOOLEAN)" + WEB_BEGIN
            + "    DECLARE v_admin INT;\n"
            + "    CALL web_session_admin(p_session, 'mailboxes.manage', v_admin);\n"
            + "    INSERT INTO mailboxes (domain_id, email, password, password_encrypted, password_encrypted_at, name, quota_mb, receive_enabled)\n"
            + "        VALUES (p_domain_id, p_email, p_password, p_password_encrypted, p_password_encrypted_at, p_name, p_quota_mb, p_receive_enabled);\n"
            + "    SELECT ROW_COUNT() AS affected, LAST_INSERT_ID() AS id;\n"
            + "END";

    /** WebDbAccess */
    public static final String WEB_DROP_ADD_MAILBOX = "DROP PROCEDURE IF EXISTS add_mailbox";

    /** WebDbAccess */
    public static final String WEB_GRANT_ADD_MAILBOX = "GRANT EXECUTE ON PROCEDURE add_mailbox" + WEB_TO;

    /** MAIL_UPDATE_MAILBOX in the web part, with mailboxes.manage: name, space and state of a mailbox. */
    public static final String WEB_CALL_UPDATE_MAILBOX = "CALL update_mailbox(?, ?, ?, ?, ?, ?, ?, ?)";

    /** WebDbAccess: the procedure of WEB_CALL_UPDATE_MAILBOX. */
    public static final String WEB_CREATE_UPDATE_MAILBOX = WEB_CREATE + "update_mailbox(" + WEB_SESSION
            + ", IN p_name VARCHAR(255), IN p_quota_mb INT, IN p_active BOOLEAN"
            + ", IN p_receive_enabled BOOLEAN, IN p_junk_expunge_days SMALLINT UNSIGNED, IN p_trash_expunge_days SMALLINT UNSIGNED"
            + ", IN p_id INT)" + WEB_BEGIN
            + "    DECLARE v_admin INT;\n"
            + "    CALL web_session_admin(p_session, 'mailboxes.manage', v_admin);\n"
            + "    UPDATE mailboxes SET name = p_name, quota_mb = p_quota_mb, active = p_active, receive_enabled = p_receive_enabled,\n"
            + "        junk_expunge_days = p_junk_expunge_days, trash_expunge_days = p_trash_expunge_days WHERE id = p_id;\n"
            + "    SELECT ROW_COUNT() AS affected;\n"
            + "END";

    /** WebDbAccess */
    public static final String WEB_DROP_UPDATE_MAILBOX = "DROP PROCEDURE IF EXISTS update_mailbox";

    /** WebDbAccess */
    public static final String WEB_GRANT_UPDATE_MAILBOX = "GRANT EXECUTE ON PROCEDURE update_mailbox" + WEB_TO;

    /**
     * MAIL_UPDATE_MAILBOX_PASSWORD in the web part, with mailboxes.manage: the password of a mailbox: the hash and
     * the copy together.
     */
    public static final String WEB_CALL_SET_MAILBOX_PASSWORD = "CALL set_mailbox_password(?, ?, ?, ?, ?)";

    /** WebDbAccess: the procedure of WEB_CALL_SET_MAILBOX_PASSWORD. */
    public static final String WEB_CREATE_SET_MAILBOX_PASSWORD = WEB_CREATE + "set_mailbox_password(" + WEB_SESSION
            + ", IN p_password VARCHAR(255), IN p_password_encrypted TEXT"
            + ", IN p_password_encrypted_at DATETIME, IN p_id INT)" + WEB_BEGIN
            + "    DECLARE v_admin INT;\n"
            + "    CALL web_session_admin(p_session, 'mailboxes.manage', v_admin);\n"
            + "    UPDATE mailboxes SET password = p_password, password_encrypted = p_password_encrypted,\n"
            + "        password_encrypted_at = p_password_encrypted_at WHERE id = p_id;\n"
            + "    SELECT ROW_COUNT() AS affected;\n"
            + "END";

    /** WebDbAccess */
    public static final String WEB_DROP_SET_MAILBOX_PASSWORD = "DROP PROCEDURE IF EXISTS set_mailbox_password";

    /** WebDbAccess */
    public static final String WEB_GRANT_SET_MAILBOX_PASSWORD = "GRANT EXECUTE ON PROCEDURE set_mailbox_password" + WEB_TO;

    /** MAIL_DELETE_MAILBOX in the web part, with mailboxes.manage: a mailbox. */
    public static final String WEB_CALL_DELETE_MAILBOX = "CALL delete_mailbox(?, ?)";

    /** WebDbAccess: the procedure of WEB_CALL_DELETE_MAILBOX. */
    public static final String WEB_CREATE_DELETE_MAILBOX = WEB_CREATE + "delete_mailbox(" + WEB_SESSION
            + ", IN p_id INT)" + WEB_BEGIN
            + "    DECLARE v_admin INT;\n"
            + "    CALL web_session_admin(p_session, 'mailboxes.manage', v_admin);\n"
            + "    DELETE FROM mailboxes WHERE id = p_id;\n"
            + "    SELECT ROW_COUNT() AS affected;\n"
            + "END";

    /** WebDbAccess */
    public static final String WEB_DROP_DELETE_MAILBOX = "DROP PROCEDURE IF EXISTS delete_mailbox";

    /** WebDbAccess */
    public static final String WEB_GRANT_DELETE_MAILBOX = "GRANT EXECUTE ON PROCEDURE delete_mailbox" + WEB_TO;

    /**
     * MAIL_MAILBOX_HAS_ENCRYPTED_PASSWORD in the web part, with mail.view: whether a mailbox has the copy of the
     * password.
     */
    public static final String WEB_CALL_MAILBOX_HAS_VAULT_COPY = "CALL mailbox_has_vault_copy(?, ?)";

    /** WebDbAccess: the procedure of WEB_CALL_MAILBOX_HAS_VAULT_COPY. */
    public static final String WEB_CREATE_MAILBOX_HAS_VAULT_COPY = WEB_CREATE + "mailbox_has_vault_copy(" + WEB_SESSION
            + ", IN p_id INT)" + WEB_BEGIN
            + "    DECLARE v_admin INT;\n"
            + "    CALL web_session_admin(p_session, 'mail.view', v_admin);\n"
            + "    SELECT 1 FROM mailboxes WHERE id = p_id AND password_encrypted IS NOT NULL AND password_encrypted <> '';\n"
            + "END";

    /** WebDbAccess */
    public static final String WEB_DROP_MAILBOX_HAS_VAULT_COPY = "DROP PROCEDURE IF EXISTS mailbox_has_vault_copy";

    /** WebDbAccess */
    public static final String WEB_GRANT_MAILBOX_HAS_VAULT_COPY = "GRANT EXECUTE ON PROCEDURE mailbox_has_vault_copy" + WEB_TO;

    /** MAIL_GET_ALIASES_BY_SOURCE in the web part, with mail.view: the aliases with this source. */
    public static final String WEB_CALL_LIST_ALIASES_BY_SOURCE = "CALL list_aliases_by_source(?, ?)";

    /** WebDbAccess: the procedure of WEB_CALL_LIST_ALIASES_BY_SOURCE. */
    public static final String WEB_CREATE_LIST_ALIASES_BY_SOURCE = WEB_CREATE + "list_aliases_by_source(" + WEB_SESSION
            + ", IN p_source VARCHAR(255) CHARACTER SET ascii)" + WEB_BEGIN
            + "    DECLARE v_admin INT;\n"
            + "    CALL web_session_admin(p_session, 'mail.view', v_admin);\n"
            + "    SELECT a.id, a.domain_id, a.source, a.destination, a.active, a.created_at, d.domain AS domain_name\n"
            + "        FROM aliases a JOIN domains d ON a.domain_id = d.id WHERE a.source = p_source ORDER BY a.destination;\n"
            + "END";

    /** WebDbAccess */
    public static final String WEB_DROP_LIST_ALIASES_BY_SOURCE = "DROP PROCEDURE IF EXISTS list_aliases_by_source";

    /** WebDbAccess */
    public static final String WEB_GRANT_LIST_ALIASES_BY_SOURCE = "GRANT EXECUTE ON PROCEDURE list_aliases_by_source" + WEB_TO;

    /** MAIL_GET_ALIASES_BY_DESTINATION in the web part, with mail.view: the aliases towards this address. */
    public static final String WEB_CALL_LIST_ALIASES_BY_DESTINATION = "CALL list_aliases_by_destination(?, ?)";

    /** WebDbAccess: the procedure of WEB_CALL_LIST_ALIASES_BY_DESTINATION. */
    public static final String WEB_CREATE_LIST_ALIASES_BY_DESTINATION = WEB_CREATE + "list_aliases_by_destination(" + WEB_SESSION
            + ", IN p_destination VARCHAR(255) CHARACTER SET ascii)" + WEB_BEGIN
            + "    DECLARE v_admin INT;\n"
            + "    CALL web_session_admin(p_session, 'mail.view', v_admin);\n"
            + "    SELECT a.id, a.domain_id, a.source, a.destination, a.active, a.created_at, d.domain AS domain_name\n"
            + "        FROM aliases a JOIN domains d ON a.domain_id = d.id WHERE a.destination = p_destination ORDER BY a.source;\n"
            + "END";

    /** WebDbAccess */
    public static final String WEB_DROP_LIST_ALIASES_BY_DESTINATION = "DROP PROCEDURE IF EXISTS list_aliases_by_destination";

    /** WebDbAccess */
    public static final String WEB_GRANT_LIST_ALIASES_BY_DESTINATION = "GRANT EXECUTE ON PROCEDURE list_aliases_by_destination" + WEB_TO;

    /** MAIL_GET_AUTO_RESPONDER in the web part, with mail.view: the auto-reply of a mailbox. */
    public static final String WEB_CALL_GET_AUTO_RESPONDER = "CALL get_auto_responder(?, ?)";

    /** WebDbAccess: the procedure of WEB_CALL_GET_AUTO_RESPONDER. */
    public static final String WEB_CREATE_GET_AUTO_RESPONDER = WEB_CREATE + "get_auto_responder(" + WEB_SESSION
            + ", IN p_mailbox_id INT)" + WEB_BEGIN
            + "    DECLARE v_admin INT;\n"
            + "    CALL web_session_admin(p_session, 'mail.view', v_admin);\n"
            + "    SELECT ar.id, ar.mailbox_id, ar.enabled, ar.subject, ar.body, ar.start_date, ar.end_date, ar.interval_hours, m.email\n"
            + "        FROM auto_responders ar JOIN mailboxes m ON ar.mailbox_id = m.id WHERE ar.mailbox_id = p_mailbox_id;\n"
            + "END";

    /** WebDbAccess */
    public static final String WEB_DROP_GET_AUTO_RESPONDER = "DROP PROCEDURE IF EXISTS get_auto_responder";

    /** WebDbAccess */
    public static final String WEB_GRANT_GET_AUTO_RESPONDER = "GRANT EXECUTE ON PROCEDURE get_auto_responder" + WEB_TO;

    /** MAIL_GET_FORWARDING_RULES in the web part, with mail.view: the forwards of a mailbox. */
    public static final String WEB_CALL_LIST_FORWARDING_RULES = "CALL list_forwarding_rules(?, ?)";

    /** WebDbAccess: the procedure of WEB_CALL_LIST_FORWARDING_RULES. */
    public static final String WEB_CREATE_LIST_FORWARDING_RULES = WEB_CREATE + "list_forwarding_rules(" + WEB_SESSION
            + ", IN p_mailbox_id INT)" + WEB_BEGIN
            + "    DECLARE v_admin INT;\n"
            + "    CALL web_session_admin(p_session, 'mail.view', v_admin);\n"
            + "    SELECT fr.id, fr.mailbox_id, fr.destination, fr.keep_copy, fr.enabled, m.email\n"
            + "        FROM forwarding_rules fr JOIN mailboxes m ON fr.mailbox_id = m.id WHERE fr.mailbox_id = p_mailbox_id;\n"
            + "END";

    /** WebDbAccess */
    public static final String WEB_DROP_LIST_FORWARDING_RULES = "DROP PROCEDURE IF EXISTS list_forwarding_rules";

    /** WebDbAccess */
    public static final String WEB_GRANT_LIST_FORWARDING_RULES = "GRANT EXECUTE ON PROCEDURE list_forwarding_rules" + WEB_TO;

    /** MAIL_GET_SIEVE_FILTERS in the web part, with mail.view: the filters of a mailbox. */
    public static final String WEB_CALL_LIST_SIEVE_FILTERS = "CALL list_sieve_filters(?, ?)";

    /** WebDbAccess: the procedure of WEB_CALL_LIST_SIEVE_FILTERS. */
    public static final String WEB_CREATE_LIST_SIEVE_FILTERS = WEB_CREATE + "list_sieve_filters(" + WEB_SESSION
            + ", IN p_mailbox_id INT)" + WEB_BEGIN
            + "    DECLARE v_admin INT;\n"
            + "    CALL web_session_admin(p_session, 'mail.view', v_admin);\n"
            + "    SELECT sf.id, sf.mailbox_id, sf.name, sf.priority, sf.enabled, sf.conditions, sf.actions, m.email\n"
            + "        FROM sieve_filters sf JOIN mailboxes m ON sf.mailbox_id = m.id WHERE sf.mailbox_id = p_mailbox_id ORDER BY sf.priority, sf.id;\n"
            + "END";

    /** WebDbAccess */
    public static final String WEB_DROP_LIST_SIEVE_FILTERS = "DROP PROCEDURE IF EXISTS list_sieve_filters";

    /** WebDbAccess */
    public static final String WEB_GRANT_LIST_SIEVE_FILTERS = "GRANT EXECUTE ON PROCEDURE list_sieve_filters" + WEB_TO;

    /**
     * MAIL_TRANSFORM_MAILBOX_TO_ALIAS in the web part, with mailboxes.manage: an alias (a mailbox that becomes
     * an alias).
     */
    public static final String WEB_CALL_DELETE_ALIAS = "CALL delete_alias(?, ?, ?)";

    /** WebDbAccess: the procedure of WEB_CALL_DELETE_ALIAS. */
    public static final String WEB_CREATE_DELETE_ALIAS = WEB_CREATE + "delete_alias(" + WEB_SESSION
            + ", IN p_source VARCHAR(255) CHARACTER SET ascii"
            + ", IN p_destination VARCHAR(255) CHARACTER SET ascii)" + WEB_BEGIN
            + "    DECLARE v_admin INT;\n"
            + "    CALL web_session_admin(p_session, 'mailboxes.manage', v_admin);\n"
            + "    DELETE FROM aliases WHERE source = p_source AND destination = p_destination;\n"
            + "    SELECT ROW_COUNT() AS affected;\n"
            + "END";

    /** WebDbAccess */
    public static final String WEB_DROP_DELETE_ALIAS = "DROP PROCEDURE IF EXISTS delete_alias";

    /** WebDbAccess */
    public static final String WEB_GRANT_DELETE_ALIAS = "GRANT EXECUTE ON PROCEDURE delete_alias" + WEB_TO;

    /**
     * MAIL_TRANSFORM_MAILBOX_TO_ALIAS_2 in the web part, with mailboxes.manage: the sending limit of a mailbox
     * (a mailbox that becomes an alias).
     */
    public static final String WEB_CALL_DELETE_MAILBOX_RATE_LIMIT = "CALL delete_mailbox_rate_limit(?, ?)";

    /** WebDbAccess: the procedure of WEB_CALL_DELETE_MAILBOX_RATE_LIMIT. */
    public static final String WEB_CREATE_DELETE_MAILBOX_RATE_LIMIT = WEB_CREATE + "delete_mailbox_rate_limit(" + WEB_SESSION
            + ", IN p_mailbox_id INT)" + WEB_BEGIN
            + "    DECLARE v_admin INT;\n"
            + "    CALL web_session_admin(p_session, 'mailboxes.manage', v_admin);\n"
            + "    DELETE FROM rate_limits WHERE target_type = 'mailbox' AND target_id = p_mailbox_id;\n"
            + "    SELECT ROW_COUNT() AS affected;\n"
            + "END";

    /** WebDbAccess */
    public static final String WEB_DROP_DELETE_MAILBOX_RATE_LIMIT = "DROP PROCEDURE IF EXISTS delete_mailbox_rate_limit";

    /** WebDbAccess */
    public static final String WEB_GRANT_DELETE_MAILBOX_RATE_LIMIT = "GRANT EXECUTE ON PROCEDURE delete_mailbox_rate_limit" + WEB_TO;

    /**
     * MAIL_TRANSFORM_MAILBOX_TO_ALIAS_3 in the web part, with mailboxes.manage: a mailbox with this id and this
     * address (a mailbox that becomes an alias).
     */
    public static final String WEB_CALL_DELETE_MAILBOX_BY_ADDRESS = "CALL delete_mailbox_by_address(?, ?, ?)";

    /** WebDbAccess: the procedure of WEB_CALL_DELETE_MAILBOX_BY_ADDRESS. */
    public static final String WEB_CREATE_DELETE_MAILBOX_BY_ADDRESS = WEB_CREATE + "delete_mailbox_by_address(" + WEB_SESSION
            + ", IN p_id INT, IN p_email VARCHAR(255) CHARACTER SET ascii)" + WEB_BEGIN
            + "    DECLARE v_admin INT;\n"
            + "    CALL web_session_admin(p_session, 'mailboxes.manage', v_admin);\n"
            + "    DELETE FROM mailboxes WHERE id = p_id AND email = p_email;\n"
            + "    SELECT ROW_COUNT() AS affected;\n"
            + "END";

    /** WebDbAccess */
    public static final String WEB_DROP_DELETE_MAILBOX_BY_ADDRESS = "DROP PROCEDURE IF EXISTS delete_mailbox_by_address";

    /** WebDbAccess */
    public static final String WEB_GRANT_DELETE_MAILBOX_BY_ADDRESS = "GRANT EXECUTE ON PROCEDURE delete_mailbox_by_address" + WEB_TO;

    /**
     * MAIL_TRANSFORM_ALIAS_TO_MAILBOX in the web part, with mailboxes.manage: an active alias (a mailbox that
     * becomes an alias).
     */
    public static final String WEB_CALL_ADD_ALIAS = "CALL add_alias(?, ?, ?, ?)";

    /** WebDbAccess: the procedure of WEB_CALL_ADD_ALIAS. */
    public static final String WEB_CREATE_ADD_ALIAS = WEB_CREATE + "add_alias(" + WEB_SESSION
            + ", IN p_domain_id INT, IN p_source VARCHAR(255), IN p_destination VARCHAR(255))" + WEB_BEGIN
            + "    DECLARE v_admin INT;\n"
            + "    CALL web_session_admin(p_session, 'mailboxes.manage', v_admin);\n"
            + "    INSERT INTO aliases (domain_id, source, destination, active) VALUES (p_domain_id, p_source, p_destination, 1)\n"
            + "        ON DUPLICATE KEY UPDATE active = 1;\n"
            + "    SELECT ROW_COUNT() AS affected;\n"
            + "END";

    /** WebDbAccess */
    public static final String WEB_DROP_ADD_ALIAS = "DROP PROCEDURE IF EXISTS add_alias";

    /** WebDbAccess */
    public static final String WEB_GRANT_ADD_ALIAS = "GRANT EXECUTE ON PROCEDURE add_alias" + WEB_TO;

    /**
     * MAIL_CREATE_AUTO_LOGIN_TOKEN in the web part, with mailboxes.manage: the login token for the webmail of
     * a mailbox.
     */
    public static final String WEB_CALL_CREATE_WEBMAIL_TOKEN = "CALL create_webmail_token(?, ?, ?)";

    /** WebDbAccess: the procedure of WEB_CALL_CREATE_WEBMAIL_TOKEN. */
    public static final String WEB_CREATE_CREATE_WEBMAIL_TOKEN = WEB_CREATE + "create_webmail_token(" + WEB_SESSION
            + ", IN p_token VARCHAR(64), IN p_mailbox_id INT)" + WEB_BEGIN
            + "    DECLARE v_admin INT;\n"
            + "    CALL web_session_admin(p_session, 'mailboxes.manage', v_admin);\n"
            + "    INSERT INTO roundcube_tokens (token, mailbox_id, expires_at) VALUES (p_token, p_mailbox_id, DATE_ADD(NOW(), INTERVAL 5 MINUTE));\n"
            + "    SELECT ROW_COUNT() AS affected;\n"
            + "END";

    /** WebDbAccess */
    public static final String WEB_DROP_CREATE_WEBMAIL_TOKEN = "DROP PROCEDURE IF EXISTS create_webmail_token";

    /** WebDbAccess */
    public static final String WEB_GRANT_CREATE_WEBMAIL_TOKEN = "GRANT EXECUTE ON PROCEDURE create_webmail_token" + WEB_TO;

    /** MAIL_GET_EMAIL_STATISTICS in the web part, with mail.view: the statistics of the last few days. */
    public static final String WEB_CALL_LIST_EMAIL_STATISTICS = "CALL list_email_statistics(?, ?)";

    /** WebDbAccess: the procedure of WEB_CALL_LIST_EMAIL_STATISTICS. */
    public static final String WEB_CREATE_LIST_EMAIL_STATISTICS = WEB_CREATE + "list_email_statistics(" + WEB_SESSION
            + ", IN p_days INT)" + WEB_BEGIN
            + "    DECLARE v_admin INT;\n"
            + "    CALL web_session_admin(p_session, 'mail.view', v_admin);\n"
            + "    SELECT es.stat_date, es.mailbox_id, es.domain_id, es.sent_count, es.received_count, es.spam_count, es.virus_count,\n"
            + "            es.bounced_count, es.bytes_sent, es.bytes_received, COALESCE(m.email, d.domain, 'Total') AS name\n"
            + "        FROM email_statistics es LEFT JOIN mailboxes m ON es.mailbox_id = m.id LEFT JOIN domains d ON es.domain_id = d.id\n"
            + "        WHERE es.stat_date >= DATE_SUB(CURDATE(), INTERVAL p_days DAY)\n"
            + "        ORDER BY es.stat_date DESC, es.domain_id, es.mailbox_id;\n"
            + "END";

    /** WebDbAccess */
    public static final String WEB_DROP_LIST_EMAIL_STATISTICS = "DROP PROCEDURE IF EXISTS list_email_statistics";

    /** WebDbAccess */
    public static final String WEB_GRANT_LIST_EMAIL_STATISTICS = "GRANT EXECUTE ON PROCEDURE list_email_statistics" + WEB_TO;

    /** MAIL_GET_TRAINING_COUNT in the web part, with mail.view: how many messages rspamd has learned. */
    public static final String WEB_CALL_COUNT_TRAINING = "CALL count_training(?, ?, ?)";

    /** WebDbAccess: the procedure of WEB_CALL_COUNT_TRAINING. */
    public static final String WEB_CREATE_COUNT_TRAINING = WEB_CREATE + "count_training(" + WEB_SESSION
            + ", IN p_trained_as VARCHAR(4) CHARACTER SET ascii, IN p_days INT)" + WEB_BEGIN
            + "    DECLARE v_admin INT;\n"
            + "    CALL web_session_admin(p_session, 'mail.view', v_admin);\n"
            + "    SELECT COUNT(*) FROM rspamd_training WHERE trained_as = p_trained_as AND trained_at >= DATE_SUB(NOW(), INTERVAL p_days DAY);\n"
            + "END";

    /** WebDbAccess */
    public static final String WEB_DROP_COUNT_TRAINING = "DROP PROCEDURE IF EXISTS count_training";

    /** WebDbAccess */
    public static final String WEB_GRANT_COUNT_TRAINING = "GRANT EXECUTE ON PROCEDURE count_training" + WEB_TO;

    /**
     * WebDbAccess: the procedures the web part no longer has, which are dropped where they exist, with their grant.
     * The copies of the passwords and their hashes ("Show password"): from the asymmetric-key vault only the root
     * part reads them.
     */
    public static final String WEB_DROP_RETIRED_GET_MAILBOX_VAULT_COPY = "DROP PROCEDURE IF EXISTS get_mailbox_vault_copy";

    /** WebDbAccess: see WEB_DROP_RETIRED_GET_MAILBOX_VAULT_COPY. */
    public static final String WEB_DROP_RETIRED_GET_MAILBOX_PASSWORD_HASH = "DROP PROCEDURE IF EXISTS get_mailbox_password_hash";

    // =============== MysqlRename: the database and the users under the DaemoxCP Mail name (2026-11-17) ===============
    // In SQL an identifier is not a parameter: the users' previous names are here, in the text of the statements, and
    // they are the only previous names in the code (the other migrations read them from legacy-names.json). The
    // previous database's name is not here: the tables are moved with the connection opened on it
    // (RENAME TABLE tabella TO daemoxcp_mail.tabella).

    /** MysqlRename: the two databases, if they exist, with character set and collation */
    public static final String RENAME_SCHEMAS = "SELECT schema_name, default_character_set_name, default_collation_name FROM information_schema.schemata WHERE schema_name IN (?, ?)";

    /** MysqlRename: the tables and views of a database */
    public static final String RENAME_TABLES_OF = "SELECT table_name, table_type FROM information_schema.tables WHERE table_schema = ?";

    /** MysqlRename: triggers and events of a database (they cannot be moved: with one of them, nothing is moved) */
    public static final String RENAME_OTHER_OBJECTS_OF = "SELECT (SELECT COUNT(*) FROM information_schema.triggers WHERE trigger_schema = ?) + (SELECT COUNT(*) FROM information_schema.events WHERE event_schema = ?)";

    /** MysqlRename: the procedures and functions of a database */
    public static final String RENAME_ROUTINES_OF = "SELECT routine_name FROM information_schema.routines WHERE routine_schema = ?";

    /** MysqlRename: the panel's users, with the previous names and with the current ones */
    public static final String RENAME_USERS = "SELECT user, host FROM mysql.user WHERE user IN ('mailpanel', 'daemoxcp_mail', 'mailpanel_web', 'daemoxcp_mail_web', 'mailpanel_routines', 'daemoxcp_mail_routines', 'mailpanel_postfix', 'daemoxcp_mail_postfix', 'mailpanel_dovecot', 'daemoxcp_mail_dovecot')";

    /** MysqlRename: the database with the current name, as the installer creates it */
    public static final String RENAME_CREATE_DATABASE = "CREATE DATABASE daemoxcp_mail CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci";

    /** MysqlRename, to go back: the new database, if it has been left empty */
    public static final String RENAME_DROP_NEW_DATABASE = "DROP DATABASE daemoxcp_mail";

    /** MysqlRename: the previous database, under the installer's name, when it has been left empty */
    public static final String RENAME_DROP_OLD_DEFAULT_DATABASE = "DROP DATABASE mailserver";
    /** MysqlRename (connection on the previous database) */
    public static final String RENAME_TABLE_ADMIN_PASSKEYS = "RENAME TABLE admin_passkeys TO daemoxcp_mail.admin_passkeys";
    /** MysqlRename, to go back (connection on the previous database) */
    public static final String RENAME_BACK_TABLE_ADMIN_PASSKEYS = "RENAME TABLE daemoxcp_mail.admin_passkeys TO admin_passkeys";
    /** MysqlRename (connection on the previous database) */
    public static final String RENAME_TABLE_RSPAMD_TRAINING = "RENAME TABLE rspamd_training TO daemoxcp_mail.rspamd_training";
    /** MysqlRename, to go back (connection on the previous database) */
    public static final String RENAME_BACK_TABLE_RSPAMD_TRAINING = "RENAME TABLE daemoxcp_mail.rspamd_training TO rspamd_training";
    /** MysqlRename (connection on the previous database) */
    public static final String RENAME_TABLE_PANEL_SESSIONS = "RENAME TABLE panel_sessions TO daemoxcp_mail.panel_sessions";
    /** MysqlRename, to go back (connection on the previous database) */
    public static final String RENAME_BACK_TABLE_PANEL_SESSIONS = "RENAME TABLE daemoxcp_mail.panel_sessions TO panel_sessions";
    /** MysqlRename (connection on the previous database) */
    public static final String RENAME_TABLE_LOGIN_CODE_EMAIL = "RENAME TABLE login_code_email TO daemoxcp_mail.login_code_email";
    /** MysqlRename, to go back (connection on the previous database) */
    public static final String RENAME_BACK_TABLE_LOGIN_CODE_EMAIL = "RENAME TABLE daemoxcp_mail.login_code_email TO login_code_email";
    /** MysqlRename (connection on the previous database) */
    public static final String RENAME_TABLE_LOGIN_CODE_CONSOLE = "RENAME TABLE login_code_console TO daemoxcp_mail.login_code_console";
    /** MysqlRename, to go back (connection on the previous database) */
    public static final String RENAME_BACK_TABLE_LOGIN_CODE_CONSOLE = "RENAME TABLE daemoxcp_mail.login_code_console TO login_code_console";
    /** MysqlRename (connection on the previous database) */
    public static final String RENAME_TABLE_STEPUP_CODE = "RENAME TABLE stepup_code TO daemoxcp_mail.stepup_code";
    /** MysqlRename, to go back (connection on the previous database) */
    public static final String RENAME_BACK_TABLE_STEPUP_CODE = "RENAME TABLE daemoxcp_mail.stepup_code TO stepup_code";
    /** MysqlRename (connection on the previous database) */
    public static final String RENAME_TABLE_EMAIL_CHANGE_CODE = "RENAME TABLE email_change_code TO daemoxcp_mail.email_change_code";
    /** MysqlRename, to go back (connection on the previous database) */
    public static final String RENAME_BACK_TABLE_EMAIL_CHANGE_CODE = "RENAME TABLE daemoxcp_mail.email_change_code TO email_change_code";
    /** MysqlRename (connection on the previous database) */
    public static final String RENAME_TABLE_ROUNDCUBE_TOKENS = "RENAME TABLE roundcube_tokens TO daemoxcp_mail.roundcube_tokens";
    /** MysqlRename, to go back (connection on the previous database) */
    public static final String RENAME_BACK_TABLE_ROUNDCUBE_TOKENS = "RENAME TABLE daemoxcp_mail.roundcube_tokens TO roundcube_tokens";
    /** MysqlRename (connection on the previous database) */
    public static final String RENAME_TABLE_AUTO_RESPONDERS = "RENAME TABLE auto_responders TO daemoxcp_mail.auto_responders";
    /** MysqlRename, to go back (connection on the previous database) */
    public static final String RENAME_BACK_TABLE_AUTO_RESPONDERS = "RENAME TABLE daemoxcp_mail.auto_responders TO auto_responders";
    /** MysqlRename (connection on the previous database) */
    public static final String RENAME_TABLE_SIEVE_FILTERS = "RENAME TABLE sieve_filters TO daemoxcp_mail.sieve_filters";
    /** MysqlRename, to go back (connection on the previous database) */
    public static final String RENAME_BACK_TABLE_SIEVE_FILTERS = "RENAME TABLE daemoxcp_mail.sieve_filters TO sieve_filters";
    /** MysqlRename (connection on the previous database) */
    public static final String RENAME_TABLE_FORWARDING_RULES = "RENAME TABLE forwarding_rules TO daemoxcp_mail.forwarding_rules";
    /** MysqlRename, to go back (connection on the previous database) */
    public static final String RENAME_BACK_TABLE_FORWARDING_RULES = "RENAME TABLE daemoxcp_mail.forwarding_rules TO forwarding_rules";
    /** MysqlRename (connection on the previous database) */
    public static final String RENAME_TABLE_EMAIL_STATISTICS = "RENAME TABLE email_statistics TO daemoxcp_mail.email_statistics";
    /** MysqlRename, to go back (connection on the previous database) */
    public static final String RENAME_BACK_TABLE_EMAIL_STATISTICS = "RENAME TABLE daemoxcp_mail.email_statistics TO email_statistics";
    /** MysqlRename (connection on the previous database) */
    public static final String RENAME_TABLE_ALIASES = "RENAME TABLE aliases TO daemoxcp_mail.aliases";
    /** MysqlRename, to go back (connection on the previous database) */
    public static final String RENAME_BACK_TABLE_ALIASES = "RENAME TABLE daemoxcp_mail.aliases TO aliases";
    /** MysqlRename (connection on the previous database) */
    public static final String RENAME_TABLE_MAILBOXES = "RENAME TABLE mailboxes TO daemoxcp_mail.mailboxes";
    /** MysqlRename, to go back (connection on the previous database) */
    public static final String RENAME_BACK_TABLE_MAILBOXES = "RENAME TABLE daemoxcp_mail.mailboxes TO mailboxes";
    /** MysqlRename (connection on the previous database) */
    public static final String RENAME_TABLE_DKIM_ROTATION_HISTORY = "RENAME TABLE dkim_rotation_history TO daemoxcp_mail.dkim_rotation_history";
    /** MysqlRename, to go back (connection on the previous database) */
    public static final String RENAME_BACK_TABLE_DKIM_ROTATION_HISTORY = "RENAME TABLE daemoxcp_mail.dkim_rotation_history TO dkim_rotation_history";
    /** MysqlRename (connection on the previous database) */
    public static final String RENAME_TABLE_DOMAINS = "RENAME TABLE domains TO daemoxcp_mail.domains";
    /** MysqlRename, to go back (connection on the previous database) */
    public static final String RENAME_BACK_TABLE_DOMAINS = "RENAME TABLE daemoxcp_mail.domains TO domains";
    /** MysqlRename (connection on the previous database) */
    public static final String RENAME_TABLE_CLOUDFLARE_ACCOUNTS = "RENAME TABLE cloudflare_accounts TO daemoxcp_mail.cloudflare_accounts";
    /** MysqlRename, to go back (connection on the previous database) */
    public static final String RENAME_BACK_TABLE_CLOUDFLARE_ACCOUNTS = "RENAME TABLE daemoxcp_mail.cloudflare_accounts TO cloudflare_accounts";
    /** MysqlRename (connection on the previous database) */
    public static final String RENAME_TABLE_AUDIT_LOG = "RENAME TABLE audit_log TO daemoxcp_mail.audit_log";
    /** MysqlRename, to go back (connection on the previous database) */
    public static final String RENAME_BACK_TABLE_AUDIT_LOG = "RENAME TABLE daemoxcp_mail.audit_log TO audit_log";
    /** MysqlRename (connection on the previous database) */
    public static final String RENAME_TABLE_RATE_LIMITS = "RENAME TABLE rate_limits TO daemoxcp_mail.rate_limits";
    /** MysqlRename, to go back (connection on the previous database) */
    public static final String RENAME_BACK_TABLE_RATE_LIMITS = "RENAME TABLE daemoxcp_mail.rate_limits TO rate_limits";
    /** MysqlRename (connection on the previous database) */
    public static final String RENAME_TABLE_PANEL_SETTINGS = "RENAME TABLE panel_settings TO daemoxcp_mail.panel_settings";
    /** MysqlRename, to go back (connection on the previous database) */
    public static final String RENAME_BACK_TABLE_PANEL_SETTINGS = "RENAME TABLE daemoxcp_mail.panel_settings TO panel_settings";
    /** MysqlRename (connection on the previous database) */
    public static final String RENAME_TABLE_PANEL_ROLE_PERMISSIONS = "RENAME TABLE panel_role_permissions TO daemoxcp_mail.panel_role_permissions";
    /** MysqlRename, to go back (connection on the previous database) */
    public static final String RENAME_BACK_TABLE_PANEL_ROLE_PERMISSIONS = "RENAME TABLE daemoxcp_mail.panel_role_permissions TO panel_role_permissions";
    /** MysqlRename (connection on the previous database) */
    public static final String RENAME_TABLE_INSTALLED_COMPONENTS = "RENAME TABLE installed_components TO daemoxcp_mail.installed_components";
    /** MysqlRename, to go back (connection on the previous database) */
    public static final String RENAME_BACK_TABLE_INSTALLED_COMPONENTS = "RENAME TABLE daemoxcp_mail.installed_components TO installed_components";
    /** MysqlRename (connection on the previous database) */
    public static final String RENAME_TABLE_PANEL_ADMIN = "RENAME TABLE panel_admin TO daemoxcp_mail.panel_admin";
    /** MysqlRename, to go back (connection on the previous database) */
    public static final String RENAME_BACK_TABLE_PANEL_ADMIN = "RENAME TABLE daemoxcp_mail.panel_admin TO panel_admin";
    /** MysqlRename (connection on the previous database) */
    public static final String RENAME_TABLE_VIRTUAL_ALIASES = "RENAME TABLE virtual_aliases TO daemoxcp_mail.virtual_aliases";
    /** MysqlRename, to go back (connection on the previous database) */
    public static final String RENAME_BACK_TABLE_VIRTUAL_ALIASES = "RENAME TABLE daemoxcp_mail.virtual_aliases TO virtual_aliases";
    /** MysqlRename (connection on the previous database) */
    public static final String RENAME_TABLE_VIRTUAL_USERS = "RENAME TABLE virtual_users TO daemoxcp_mail.virtual_users";
    /** MysqlRename, to go back (connection on the previous database) */
    public static final String RENAME_BACK_TABLE_VIRTUAL_USERS = "RENAME TABLE daemoxcp_mail.virtual_users TO virtual_users";
    /** MysqlRename (connection on the previous database) */
    public static final String RENAME_TABLE_VIRTUAL_DOMAINS = "RENAME TABLE virtual_domains TO daemoxcp_mail.virtual_domains";
    /** MysqlRename, to go back (connection on the previous database) */
    public static final String RENAME_BACK_TABLE_VIRTUAL_DOMAINS = "RENAME TABLE daemoxcp_mail.virtual_domains TO virtual_domains";
    /** MysqlRename */
    public static final String RENAME_USER_MAILPANEL_LOCALHOST = "RENAME USER 'mailpanel'@'localhost' TO 'daemoxcp_mail'@'localhost'";
    /** MysqlRename, for the way back */
    public static final String RENAME_BACK_USER_MAILPANEL_LOCALHOST = "RENAME USER 'daemoxcp_mail'@'localhost' TO 'mailpanel'@'localhost'";
    /** MysqlRename */
    public static final String RENAME_USER_MAILPANEL_LOOPBACK = "RENAME USER 'mailpanel'@'127.0.0.1' TO 'daemoxcp_mail'@'127.0.0.1'";
    /** MysqlRename, for the way back */
    public static final String RENAME_BACK_USER_MAILPANEL_LOOPBACK = "RENAME USER 'daemoxcp_mail'@'127.0.0.1' TO 'mailpanel'@'127.0.0.1'";
    /** MysqlRename */
    public static final String RENAME_USER_MAILPANEL_WEB_LOCALHOST = "RENAME USER 'mailpanel_web'@'localhost' TO 'daemoxcp_mail_web'@'localhost'";
    /** MysqlRename, for the way back */
    public static final String RENAME_BACK_USER_MAILPANEL_WEB_LOCALHOST = "RENAME USER 'daemoxcp_mail_web'@'localhost' TO 'mailpanel_web'@'localhost'";
    /** MysqlRename */
    public static final String RENAME_USER_MAILPANEL_WEB_LOOPBACK = "RENAME USER 'mailpanel_web'@'127.0.0.1' TO 'daemoxcp_mail_web'@'127.0.0.1'";
    /** MysqlRename, for the way back */
    public static final String RENAME_BACK_USER_MAILPANEL_WEB_LOOPBACK = "RENAME USER 'daemoxcp_mail_web'@'127.0.0.1' TO 'mailpanel_web'@'127.0.0.1'";
    /** MysqlRename */
    public static final String RENAME_USER_MAILPANEL_ROUTINES_LOCALHOST = "RENAME USER 'mailpanel_routines'@'localhost' TO 'daemoxcp_mail_routines'@'localhost'";
    /** MysqlRename, for the way back */
    public static final String RENAME_BACK_USER_MAILPANEL_ROUTINES_LOCALHOST = "RENAME USER 'daemoxcp_mail_routines'@'localhost' TO 'mailpanel_routines'@'localhost'";
    /** MysqlRename */
    public static final String RENAME_USER_MAILPANEL_POSTFIX_LOCALHOST = "RENAME USER 'mailpanel_postfix'@'localhost' TO 'daemoxcp_mail_postfix'@'localhost'";
    /** MysqlRename, for the way back */
    public static final String RENAME_BACK_USER_MAILPANEL_POSTFIX_LOCALHOST = "RENAME USER 'daemoxcp_mail_postfix'@'localhost' TO 'mailpanel_postfix'@'localhost'";
    /** MysqlRename */
    public static final String RENAME_USER_MAILPANEL_POSTFIX_LOOPBACK = "RENAME USER 'mailpanel_postfix'@'127.0.0.1' TO 'daemoxcp_mail_postfix'@'127.0.0.1'";
    /** MysqlRename, for the way back */
    public static final String RENAME_BACK_USER_MAILPANEL_POSTFIX_LOOPBACK = "RENAME USER 'daemoxcp_mail_postfix'@'127.0.0.1' TO 'mailpanel_postfix'@'127.0.0.1'";
    /** MysqlRename */
    public static final String RENAME_USER_MAILPANEL_DOVECOT_LOCALHOST = "RENAME USER 'mailpanel_dovecot'@'localhost' TO 'daemoxcp_mail_dovecot'@'localhost'";
    /** MysqlRename, for the way back */
    public static final String RENAME_BACK_USER_MAILPANEL_DOVECOT_LOCALHOST = "RENAME USER 'daemoxcp_mail_dovecot'@'localhost' TO 'mailpanel_dovecot'@'localhost'";
    /** MysqlRename */
    public static final String RENAME_USER_MAILPANEL_DOVECOT_LOOPBACK = "RENAME USER 'mailpanel_dovecot'@'127.0.0.1' TO 'daemoxcp_mail_dovecot'@'127.0.0.1'";
    /** MysqlRename, for the way back */
    public static final String RENAME_BACK_USER_MAILPANEL_DOVECOT_LOOPBACK = "RENAME USER 'daemoxcp_mail_dovecot'@'127.0.0.1' TO 'mailpanel_dovecot'@'127.0.0.1'";
    /** MysqlRename: the panel's user, everything on the database with the current name (as the installer does) */
    public static final String RENAME_GRANT_PANEL_LOCALHOST = "GRANT ALL PRIVILEGES ON daemoxcp_mail.* TO 'daemoxcp_mail'@'localhost'";

    /** MysqlRename: the permissions left on the previous database, under the installer's name */
    public static final String RENAME_REVOKE_OLD_DEFAULT_LOCALHOST = "REVOKE ALL PRIVILEGES ON mailserver.* FROM 'daemoxcp_mail'@'localhost'";

    /** MysqlRename */
    public static final String RENAME_REVOKE_OLD_DEFAULT_LOOPBACK = "REVOKE ALL PRIVILEGES ON mailserver.* FROM 'daemoxcp_mail'@'127.0.0.1'";

    /**
     * MysqlRename: the permissions of the procedures' owner on the previous tables (WebDbAccess grants them again on
     * the new ones)
     */
    public static final String RENAME_REVOKE_ROUTINES = "REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'daemoxcp_mail_routines'@'localhost'";
}
