package org.mail_panel.database;

/**
 * Every SQL statement the panel runs, written once and fixed: the code uses
 * them by name and never builds SQL while it runs. A constant here is made only of text (and of other
 * constants of this file): SqlCatalogTest fails if one is built with a variable, or if SQL text appears
 * anywhere else in the panel. Values always go in as parameters (?), never into the text.
 */
public final class SqlCatalog {

    private SqlCatalog() {}

    /** MailDatabase.createDatabaseAndUser */
    public static final String MAIL_CREATE_DATABASE_AND_USER = "CREATE DATABASE IF NOT EXISTS mailpanel CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci";

    /** MailDatabase.createDatabaseAndUser */
    public static final String MAIL_CREATE_DATABASE_AND_USER_2 = "GRANT ALL PRIVILEGES ON mailpanel.* TO 'mailpanel'@'127.0.0.1'";

    /** MailDatabase.createDatabaseAndUser */
    public static final String MAIL_CREATE_DATABASE_AND_USER_3 = "CREATE DATABASE IF NOT EXISTS mailserver CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci";

    /** MailDatabase.createDatabaseAndUser */
    public static final String MAIL_CREATE_DATABASE_AND_USER_4 = "GRANT ALL PRIVILEGES ON mailserver.* TO 'mailserver'@'127.0.0.1'";

    /** MailDatabase.createDatabaseAndUser */
    public static final String MAIL_CREATE_DATABASE_AND_USER_5 = "FLUSH PRIVILEGES";

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
            + "    -- DKIM rotation (selector \"pending\" mentre la chiave attuale resta in dkim_*)\n"
            + "    dkim_pending_selector VARCHAR(50) NULL,\n"
            + "    dkim_pending_private_key TEXT NULL,\n"
            + "    dkim_pending_public_key TEXT NULL,\n"
            + "    dkim_rotation_state VARCHAR(32) NULL,           -- 'pending_dns', 'propagated', 'active_grace', 'completed'\n"
            + "    dkim_rotation_started_at TIMESTAMP NULL,\n"
            + "    dkim_rotation_activated_at TIMESTAMP NULL,\n"
            + "    -- Vecchia chiave conservata durante il grace period (per validare mail in transito)\n"
            + "    dkim_previous_selector VARCHAR(50) NULL,\n"
            + "    dkim_previous_private_key TEXT NULL,\n"
            + "    dkim_previous_public_key TEXT NULL,\n"
            + "    -- Cloudflare automation (zona DNS e id dei record TXT creati via API)\n"
            + "    dkim_dns_zone_id VARCHAR(64) NULL,\n"
            + "    dkim_pending_dns_record_id VARCHAR(64) NULL,\n"
            + "    dkim_previous_dns_record_id VARCHAR(64) NULL,\n"
            + "    -- Account Cloudflare assegnato (NULL = nessuno, rotazione manuale)\n"
            + "    cloudflare_account_id INT NULL,\n"
            + "    -- Rotazione programmata: ogni quanti giorni rigenerare la chiave (0 = off)\n"
            + "    dkim_rotation_interval_days INT NOT NULL DEFAULT 0,\n"
            + "    -- Timestamp ultima rotazione completata con successo (set al key_activated)\n"
            + "    dkim_last_rotation_at TIMESTAMP NULL,\n"
            + "    -- Modalità della rotazione corrente (\"automatic\"/\"manual\"), ereditata da tutti gli eventi della catena\n"
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
    public static final String MAIL_UPDATE_MAILBOX = "UPDATE mailboxes SET name = ?, quota_mb = ?, active = ?, receive_enabled = ? WHERE id = ?";

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

    /** MailDatabase.createSieveFilter */
    public static final String MAIL_CREATE_SIEVE_FILTER = "INSERT INTO sieve_filters (mailbox_id, name, priority, conditions, actions) VALUES (?, ?, ?, ?, ?)";

    /** MailDatabase.updateSieveFilter */
    public static final String MAIL_UPDATE_SIEVE_FILTER = "UPDATE sieve_filters SET name = ?, priority = ?, enabled = ?, conditions = ?, actions = ? WHERE id = ?";

    /** MailDatabase.deleteSieveFilter */
    public static final String MAIL_DELETE_SIEVE_FILTER = "DELETE FROM sieve_filters WHERE id = ?";

    /** MailDatabase.getForwardingRules */
    public static final String MAIL_GET_FORWARDING_RULES = "SELECT fr.*, m.email FROM forwarding_rules fr\n"
            + "JOIN mailboxes m ON fr.mailbox_id = m.id\n"
            + "WHERE fr.mailbox_id = ?\n";

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
    public static final String CONFIG_UPDATE_PANEL_CONFIG = "UPDATE config SET mail_panel_host = ?, mail_panel_port = ?, mail_panel_ssl_cert = ?, mail_panel_ssl_cert_key = ?, mail_panel_ssl_chain = ?, mail_panel_sessions_prefix = ? WHERE id = 1";

    /** dataBaseManager.update_mysql_config */
    public static final String CONFIG_UPDATE_MYSQL_CONFIG = "UPDATE config SET mysql_host = ?, mysql_port = ?, mysql_user = ?, mysql_password = ?, mysql_database = ? WHERE id = 1";

    /** dataBaseManager.insert_data_default */
    public static final String CONFIG_INSERT_DATA_DEFAULT = "INSERT INTO config (mail_panel_port, mail_panel_host, mail_panel_ssl_cert, mail_panel_ssl_cert_key, mail_panel_ssl_chain, mail_panel_sessions_prefix, mysql_host, mysql_port, mysql_user, mysql_password, mysql_database, postfix_installed, dovecot_installed, rspamd_installed, clamav_installed, roundcube_installed, roundcube_domain, roundcube_port, roundcube_ssl_cert, roundcube_ssl_key) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";

    /** dataBaseManager.get_data_config */
    public static final String CONFIG_GET_DATA_CONFIG = "SELECT * FROM config WHERE id = 1";

    /** dataBaseManager.updateMySQLPassword */
    public static final String CONFIG_UPDATE_MY_SQLPASSWORD = "UPDATE config SET mysql_password = ? WHERE id = 1";

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
    public static final String RENAME_MOVE_JAIL_STATE = "PRAGMA busy_timeout = 10000";

}
