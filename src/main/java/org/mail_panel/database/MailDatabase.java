package org.mail_panel.database;

import org.mindrot.jbcrypt.BCrypt;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Unified MySQL database for Mail Panel
 * Handles both panel state (admin, settings, components) and mail data (domains, mailboxes, aliases)
 *
 * Database: mailpanel
 *
 * Tables:
 * - panel_admin: Admin user authentication
 * - panel_settings: Key-value settings
 * - installed_components: Installed mail stack components
 * - domains: Mail domains
 * - mailboxes: Virtual mailboxes
 * - aliases: Email aliases
 * - roundcube_tokens: Auto-login tokens for webmail
 */
public class MailDatabase {

    private Connection connection;
    private String host = "127.0.0.1";
    private int port = 3306;
    private String database = "mailpanel";
    private String username = "mailpanel";
    private String password;

    // Flag to track if database is available
    private boolean connected = false;

    public MailDatabase() {
        // Default constructor - password will be set later or read from config
    }

    public MailDatabase(String password) {
        this.password = password;
    }

    public void setCredentials(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public void setConnection(String host, int port, String database) {
        this.host = host;
        this.port = port;
        this.database = database;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public void setDatabase(String database) {
        this.database = database;
    }

    public boolean isConnected() {
        return connected;
    }

    /**
     * Try to connect to MySQL. Returns false if MySQL is not available.
     */
    public boolean connect() {
        try {
            String url = String.format(
                "jdbc:mysql://%s:%d/%s?useSSL=true&requireSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC&createDatabaseIfNotExist=true",
                host, port, database
            );
            connection = DriverManager.getConnection(url, username, password);
            connected = true;
            return true;
        } catch (SQLException e) {
            System.err.println("MySQL not available: " + e.getMessage());
            connected = false;
            return false;
        }
    }

    /**
     * Try to connect with root credentials to create database and user
     */
    public boolean connectAsRoot(String rootPassword) {
        try {
            String url = String.format(
                "jdbc:mysql://%s:%d/?useSSL=true&requireSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC",
                host, port
            );
            connection = DriverManager.getConnection(url, "root", rootPassword);
            connected = true;
            return true;
        } catch (SQLException e) {
            System.err.println("Cannot connect as root: " + e.getMessage());
            connected = false;
            return false;
        }
    }

    /**
     * Try to connect as root via socket authentication (no password required when running as root on FreeBSD)
     * This is the default MySQL configuration on FreeBSD - root can connect without password via unix socket
     */
    public boolean connectAsRootSocket() {
        // Try multiple connection methods for FreeBSD MySQL
        String[] socketPaths = {
            "/var/run/mysql/mysql.sock",
            "/tmp/mysql.sock",
            "/var/db/mysql/mysql.sock"
        };

        // First try TCP with empty password (some FreeBSD MySQL configs allow this)
        try {
            String url = String.format(
                "jdbc:mysql://%s:%d/?useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC",
                host, port
            );
            connection = DriverManager.getConnection(url, "root", "");
            connected = true;
            System.out.println("Connected to MySQL as root via TCP (no password)");
            return true;
        } catch (SQLException e) {
            // Try socket paths
        }

        // Try unix socket connections
        for (String socketPath : socketPaths) {
            try {
                String url = String.format(
                    "jdbc:mysql://localhost/?socket=%s&useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC",
                    socketPath
                );
                connection = DriverManager.getConnection(url, "root", "");
                connected = true;
                System.out.println("Connected to MySQL as root via socket: " + socketPath);
                return true;
            } catch (SQLException e) {
                // Try next socket
            }
        }

        System.err.println("Cannot connect as root via socket authentication. MySQL may require a password.");
        connected = false;
        return false;
    }

    /**
     * Create the mailpanel database and user (run as root)
     */
    public void createDatabaseAndUser(String panelPassword) throws SQLException {
        try (Statement stmt = connection.createStatement()) {
            // Create database
            stmt.execute("CREATE DATABASE IF NOT EXISTS mailpanel CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");

            // Create user
            stmt.execute("CREATE USER IF NOT EXISTS 'mailpanel'@'127.0.0.1' IDENTIFIED BY '" + panelPassword.replace("'", "''") + "'");
            stmt.execute("GRANT ALL PRIVILEGES ON mailpanel.* TO 'mailpanel'@'127.0.0.1'");

            // Create mailserver database for Dovecot
            stmt.execute("CREATE DATABASE IF NOT EXISTS mailserver CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
            stmt.execute("CREATE USER IF NOT EXISTS 'mailserver'@'127.0.0.1' IDENTIFIED BY '" + panelPassword.replace("'", "''") + "'");
            stmt.execute("GRANT ALL PRIVILEGES ON mailserver.* TO 'mailserver'@'127.0.0.1'");

            stmt.execute("FLUSH PRIVILEGES");
        }

        // Store the password for later use
        this.password = panelPassword;
    }

    /**
     * Drop all tables - used for full reset
     */
    public void dropAllTables() throws SQLException {
        if (!connected || connection == null) return;

        Statement stmt = connection.createStatement();

        // Drop in reverse order of dependencies
        // Includes both current table names AND legacy names for migration cleanup
        String[] tables = {
            "audit_log",
            "rspamd_training",
            "email_statistics",
            "roundcube_tokens",
            "aliases",              // Current table name
            "mailboxes",            // Current table name
            "domains",              // Current table name
            "virtual_aliases",      // Legacy table name (for cleanup)
            "virtual_users",        // Legacy table name (for cleanup)
            "virtual_domains",      // Legacy table name (for cleanup)
            "rate_limits",
            "forwarding_rules",
            "sieve_filters",
            "auto_responders",
            "panel_settings",
            "panel_admin",
            "installed_components"
        };

        for (String table : tables) {
            try {
                stmt.executeUpdate("DROP TABLE IF EXISTS " + table);
                System.out.println("Dropped table: " + table);
            } catch (SQLException e) {
                System.out.println("Warning: Could not drop table " + table + ": " + e.getMessage());
            }
        }

        stmt.close();
    }

    /**
     * Create all tables for the mail panel
     */
    public void createSchema() throws SQLException {
        // ========== PANEL TABLES ==========

        // Admin users table
        String createPanelAdmin = """
            CREATE TABLE IF NOT EXISTS panel_admin (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) NOT NULL UNIQUE,
                password_hash VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP NULL,
                active BOOLEAN DEFAULT TRUE,
                totp_secret VARCHAR(64) NULL,
                totp_enabled BOOLEAN DEFAULT FALSE,
                backup_codes TEXT NULL,
                role ENUM('superadmin', 'admin', 'operator', 'viewer') DEFAULT 'admin'
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """;

        // Settings table
        String createSettings = """
            CREATE TABLE IF NOT EXISTS panel_settings (
                setting_key VARCHAR(64) PRIMARY KEY,
                setting_value TEXT NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """;

        // Installed components
        String createComponents = """
            CREATE TABLE IF NOT EXISTS installed_components (
                id INT AUTO_INCREMENT PRIMARY KEY,
                component_name VARCHAR(50) NOT NULL UNIQUE,
                version VARCHAR(20),
                installed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status ENUM('installed', 'uninstalled', 'failed') DEFAULT 'installed'
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """;

        // ========== MAIL TABLES ==========

        // Domains table
        String createDomains = """
            CREATE TABLE IF NOT EXISTS domains (
                id INT AUTO_INCREMENT PRIMARY KEY,
                domain VARCHAR(255) NOT NULL UNIQUE,
                description TEXT,
                active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                dkim_selector VARCHAR(50) DEFAULT 'mail',
                dkim_private_key TEXT,
                dkim_public_key TEXT
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """;

        // Mailboxes table (virtual users)
        String createMailboxes = """
            CREATE TABLE IF NOT EXISTS mailboxes (
                id INT AUTO_INCREMENT PRIMARY KEY,
                domain_id INT NOT NULL,
                email VARCHAR(255) NOT NULL UNIQUE,
                password VARCHAR(255) NOT NULL,
                name VARCHAR(255),
                quota_mb INT DEFAULT 1024,
                active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP NULL,
                FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """;

        // Aliases table
        String createAliases = """
            CREATE TABLE IF NOT EXISTS aliases (
                id INT AUTO_INCREMENT PRIMARY KEY,
                domain_id INT NOT NULL,
                source VARCHAR(255) NOT NULL,
                destination VARCHAR(255) NOT NULL,
                active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE,
                UNIQUE KEY unique_alias (source, destination)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """;

        // Auto-login tokens for Roundcube SSO
        String createTokens = """
            CREATE TABLE IF NOT EXISTS roundcube_tokens (
                token VARCHAR(64) PRIMARY KEY,
                mailbox_id INT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                used BOOLEAN DEFAULT FALSE,
                FOREIGN KEY (mailbox_id) REFERENCES mailboxes(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """;

        // Auto-responder (vacation messages)
        String createAutoResponder = """
            CREATE TABLE IF NOT EXISTS auto_responders (
                id INT AUTO_INCREMENT PRIMARY KEY,
                mailbox_id INT NOT NULL UNIQUE,
                enabled BOOLEAN DEFAULT FALSE,
                subject VARCHAR(255) NOT NULL DEFAULT 'Out of Office',
                body TEXT NOT NULL,
                start_date DATE NULL,
                end_date DATE NULL,
                interval_hours INT DEFAULT 24,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (mailbox_id) REFERENCES mailboxes(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """;

        // Sieve filters
        String createSieveFilters = """
            CREATE TABLE IF NOT EXISTS sieve_filters (
                id INT AUTO_INCREMENT PRIMARY KEY,
                mailbox_id INT NOT NULL,
                name VARCHAR(100) NOT NULL,
                priority INT DEFAULT 0,
                enabled BOOLEAN DEFAULT TRUE,
                conditions JSON NOT NULL,
                actions JSON NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (mailbox_id) REFERENCES mailboxes(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """;

        // Forwarding rules
        String createForwarding = """
            CREATE TABLE IF NOT EXISTS forwarding_rules (
                id INT AUTO_INCREMENT PRIMARY KEY,
                mailbox_id INT NOT NULL,
                destination VARCHAR(255) NOT NULL,
                keep_copy BOOLEAN DEFAULT TRUE,
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (mailbox_id) REFERENCES mailboxes(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """;

        // Rate limits
        String createRateLimits = """
            CREATE TABLE IF NOT EXISTS rate_limits (
                id INT AUTO_INCREMENT PRIMARY KEY,
                target_type ENUM('global', 'domain', 'mailbox') NOT NULL,
                target_id INT NULL,
                max_per_hour INT DEFAULT 100,
                max_per_day INT DEFAULT 1000,
                max_recipients INT DEFAULT 50,
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE KEY unique_target (target_type, target_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """;

        // Email statistics
        String createEmailStats = """
            CREATE TABLE IF NOT EXISTS email_statistics (
                id INT AUTO_INCREMENT PRIMARY KEY,
                stat_date DATE NOT NULL,
                mailbox_id INT NULL,
                domain_id INT NULL,
                sent_count INT DEFAULT 0,
                received_count INT DEFAULT 0,
                spam_count INT DEFAULT 0,
                virus_count INT DEFAULT 0,
                bounced_count INT DEFAULT 0,
                bytes_sent BIGINT DEFAULT 0,
                bytes_received BIGINT DEFAULT 0,
                UNIQUE KEY unique_daily_stat (stat_date, mailbox_id, domain_id),
                FOREIGN KEY (mailbox_id) REFERENCES mailboxes(id) ON DELETE SET NULL,
                FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE SET NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """;

        // Rspamd training log
        String createRspamdTraining = """
            CREATE TABLE IF NOT EXISTS rspamd_training (
                id INT AUTO_INCREMENT PRIMARY KEY,
                message_id VARCHAR(255) NOT NULL,
                trained_as ENUM('spam', 'ham') NOT NULL,
                trained_by INT NOT NULL,
                trained_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (trained_by) REFERENCES panel_admin(id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """;

        String createAuditLog = """
            CREATE TABLE IF NOT EXISTS audit_log (
                id INT AUTO_INCREMENT PRIMARY KEY,
                action VARCHAR(100) NOT NULL,
                username VARCHAR(255),
                ip_address VARCHAR(45) NOT NULL,
                details TEXT,
                user_agent VARCHAR(512),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_action (action),
                INDEX idx_username (username),
                INDEX idx_ip (ip_address),
                INDEX idx_created (created_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """;

        // Passkeys (WebAuthn) for passwordless login
        String createPasskeys = """
            CREATE TABLE IF NOT EXISTS admin_passkeys (
                id INT AUTO_INCREMENT PRIMARY KEY,
                admin_id INT NOT NULL,
                credential_id VARBINARY(1024) NOT NULL,
                public_key_cose VARBINARY(2048) NOT NULL,
                sign_count BIGINT DEFAULT 0,
                name VARCHAR(100) DEFAULT 'Passkey',
                aaguid VARBINARY(16) NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_used TIMESTAMP NULL,
                FOREIGN KEY (admin_id) REFERENCES panel_admin(id) ON DELETE CASCADE,
                UNIQUE KEY unique_credential (credential_id(255))
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """;

        try (Statement stmt = connection.createStatement()) {
            stmt.execute(createPanelAdmin);
            stmt.execute(createSettings);
            stmt.execute(createComponents);
            stmt.execute(createDomains);
            stmt.execute(createMailboxes);
            stmt.execute(createAliases);
            stmt.execute(createTokens);
            stmt.execute(createAutoResponder);
            stmt.execute(createSieveFilters);
            stmt.execute(createForwarding);
            stmt.execute(createRateLimits);
            stmt.execute(createEmailStats);
            stmt.execute(createRspamdTraining);
            stmt.execute(createAuditLog);
            stmt.execute(createPasskeys);
        }
    }

    // ========== ADMIN AUTHENTICATION ==========

    /**
     * Create admin user with hashed password
     */
    public boolean createAdminUser(String username, String password) {
        String hashedPassword = BCrypt.hashpw(password, BCrypt.gensalt(12));
        String sql = """
            INSERT INTO panel_admin (username, password_hash) VALUES (?, ?)
            ON DUPLICATE KEY UPDATE password_hash = VALUES(password_hash)
            """;
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, username);
            stmt.setString(2, hashedPassword);
            stmt.executeUpdate();
            return true;
        } catch (SQLException e) {
            System.err.println("Failed to create admin user: " + e.getMessage());
            return false;
        }
    }

    /**
     * Validate admin login credentials
     */
    public boolean validateAdminLogin(String username, String password) {
        return getAdminIdIfValidLogin(username, password) > 0;
    }

    /**
     * Validate admin login and return admin ID (or 0 if invalid)
     */
    public int getAdminIdIfValidLogin(String username, String password) {
        String sql = "SELECT id, password_hash FROM panel_admin WHERE username = ? AND active = TRUE";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, username);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                int adminId = rs.getInt("id");
                String hashedPassword = rs.getString("password_hash");
                if (BCrypt.checkpw(password, hashedPassword)) {
                    // Update last login
                    updateAdminLastLogin(username);
                    return adminId;
                }
            }
        } catch (SQLException e) {
            System.err.println("Login validation error: " + e.getMessage());
        }
        return 0;
    }

    private void updateAdminLastLogin(String username) {
        String sql = "UPDATE panel_admin SET last_login = CURRENT_TIMESTAMP WHERE username = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, username);
            stmt.executeUpdate();
        } catch (SQLException e) {
            // ignore
        }
    }

    /**
     * Change admin password
     */
    public boolean changeAdminPassword(String username, String newPassword) {
        String hashedPassword = BCrypt.hashpw(newPassword, BCrypt.gensalt(12));
        String sql = "UPDATE panel_admin SET password_hash = ? WHERE username = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, hashedPassword);
            stmt.setString(2, username);
            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            System.err.println("Failed to change password: " + e.getMessage());
            return false;
        }
    }

    /**
     * Verify admin password by admin ID
     */
    public boolean verifyAdminPassword(int adminId, String password) {
        String sql = "SELECT password_hash FROM panel_admin WHERE id = ? AND active = TRUE";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, adminId);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                String hashedPassword = rs.getString("password_hash");
                return BCrypt.checkpw(password, hashedPassword);
            }
        } catch (SQLException e) {
            System.err.println("Password verification error: " + e.getMessage());
        }
        return false;
    }

    /**
     * Update admin password by admin ID
     */
    public boolean updateAdminPassword(int adminId, String newPassword) {
        String hashedPassword = BCrypt.hashpw(newPassword, BCrypt.gensalt(12));
        String sql = "UPDATE panel_admin SET password_hash = ? WHERE id = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, hashedPassword);
            stmt.setInt(2, adminId);
            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            System.err.println("Failed to update password: " + e.getMessage());
            return false;
        }
    }

    /**
     * Check if any admin exists
     */
    public boolean hasAdminUser() {
        String sql = "SELECT 1 FROM panel_admin WHERE active = TRUE LIMIT 1";
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            return rs.next();
        } catch (SQLException e) {
            return false;
        }
    }

    // ========== PASSKEY (WebAuthn) MANAGEMENT ==========

    /**
     * Ensure the passkeys table exists (for upgrades from older versions)
     */
    public void ensurePasskeysTable() {
        String createPasskeys = """
            CREATE TABLE IF NOT EXISTS admin_passkeys (
                id INT AUTO_INCREMENT PRIMARY KEY,
                admin_id INT NOT NULL,
                credential_id VARBINARY(1024) NOT NULL,
                public_key_cose VARBINARY(2048) NOT NULL,
                sign_count BIGINT DEFAULT 0,
                name VARCHAR(100) DEFAULT 'Passkey',
                aaguid VARBINARY(16) NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_used TIMESTAMP NULL,
                FOREIGN KEY (admin_id) REFERENCES panel_admin(id) ON DELETE CASCADE,
                UNIQUE KEY unique_credential (credential_id(255))
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """;
        try (Statement stmt = connection.createStatement()) {
            stmt.execute(createPasskeys);
        } catch (SQLException e) {
            System.out.println("Error ensuring passkeys table: " + e.getMessage());
        }
    }

    /**
     * Passkey record
     */
    public static class Passkey {
        public int id;
        public int adminId;
        public byte[] credentialId;
        public byte[] publicKeyCose;
        public long signCount;
        public String name;
        public byte[] aaguid;
        public java.sql.Timestamp createdAt;
        public java.sql.Timestamp lastUsed;
    }

    /**
     * Check if admin has any passkeys configured
     */
    public boolean hasPasskey(int adminId) {
        String sql = "SELECT 1 FROM admin_passkeys WHERE admin_id = ? LIMIT 1";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, adminId);
            ResultSet rs = stmt.executeQuery();
            return rs.next();
        } catch (SQLException e) {
            return false;
        }
    }

    /**
     * Check if username has passkey (for login flow)
     */
    public boolean usernameHasPasskey(String username) {
        String sql = """
            SELECT 1 FROM admin_passkeys ap
            JOIN panel_admin pa ON ap.admin_id = pa.id
            WHERE pa.username = ? AND pa.active = TRUE
            LIMIT 1
            """;
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, username);
            ResultSet rs = stmt.executeQuery();
            return rs.next();
        } catch (SQLException e) {
            return false;
        }
    }

    /**
     * Get all passkeys for an admin
     */
    public java.util.List<Passkey> getPasskeys(int adminId) {
        java.util.List<Passkey> passkeys = new java.util.ArrayList<>();
        String sql = "SELECT * FROM admin_passkeys WHERE admin_id = ? ORDER BY created_at DESC";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, adminId);
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                Passkey p = new Passkey();
                p.id = rs.getInt("id");
                p.adminId = rs.getInt("admin_id");
                p.credentialId = rs.getBytes("credential_id");
                p.publicKeyCose = rs.getBytes("public_key_cose");
                p.signCount = rs.getLong("sign_count");
                p.name = rs.getString("name");
                p.aaguid = rs.getBytes("aaguid");
                p.createdAt = rs.getTimestamp("created_at");
                p.lastUsed = rs.getTimestamp("last_used");
                passkeys.add(p);
            }
        } catch (SQLException e) {
            System.err.println("Error getting passkeys: " + e.getMessage());
        }
        return passkeys;
    }

    /**
     * Get passkeys by username (for login)
     */
    public java.util.List<Passkey> getPasskeysByUsername(String username) {
        java.util.List<Passkey> passkeys = new java.util.ArrayList<>();
        String sql = """
            SELECT ap.* FROM admin_passkeys ap
            JOIN panel_admin pa ON ap.admin_id = pa.id
            WHERE pa.username = ? AND pa.active = TRUE
            """;
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, username);
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                Passkey p = new Passkey();
                p.id = rs.getInt("id");
                p.adminId = rs.getInt("admin_id");
                p.credentialId = rs.getBytes("credential_id");
                p.publicKeyCose = rs.getBytes("public_key_cose");
                p.signCount = rs.getLong("sign_count");
                p.name = rs.getString("name");
                p.aaguid = rs.getBytes("aaguid");
                p.createdAt = rs.getTimestamp("created_at");
                p.lastUsed = rs.getTimestamp("last_used");
                passkeys.add(p);
            }
        } catch (SQLException e) {
            System.err.println("Error getting passkeys by username: " + e.getMessage());
        }
        return passkeys;
    }

    /**
     * Get passkey by credential ID
     */
    public Passkey getPasskeyByCredentialId(byte[] credentialId) {
        String sql = "SELECT * FROM admin_passkeys WHERE credential_id = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setBytes(1, credentialId);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                Passkey p = new Passkey();
                p.id = rs.getInt("id");
                p.adminId = rs.getInt("admin_id");
                p.credentialId = rs.getBytes("credential_id");
                p.publicKeyCose = rs.getBytes("public_key_cose");
                p.signCount = rs.getLong("sign_count");
                p.name = rs.getString("name");
                p.aaguid = rs.getBytes("aaguid");
                p.createdAt = rs.getTimestamp("created_at");
                p.lastUsed = rs.getTimestamp("last_used");
                return p;
            }
        } catch (SQLException e) {
            System.err.println("Error getting passkey: " + e.getMessage());
        }
        return null;
    }

    /**
     * Save a new passkey
     */
    public boolean savePasskey(int adminId, byte[] credentialId, byte[] publicKeyCose, long signCount, String name, byte[] aaguid) {
        String sql = "INSERT INTO admin_passkeys (admin_id, credential_id, public_key_cose, sign_count, name, aaguid) VALUES (?, ?, ?, ?, ?, ?)";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, adminId);
            stmt.setBytes(2, credentialId);
            stmt.setBytes(3, publicKeyCose);
            stmt.setLong(4, signCount);
            stmt.setString(5, name != null ? name : "Passkey");
            stmt.setBytes(6, aaguid);
            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            System.err.println("Error saving passkey: " + e.getMessage());
            return false;
        }
    }

    /**
     * Update passkey sign count and last used after successful auth
     */
    public boolean updatePasskeySignCount(byte[] credentialId, long newSignCount) {
        String sql = "UPDATE admin_passkeys SET sign_count = ?, last_used = CURRENT_TIMESTAMP WHERE credential_id = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setLong(1, newSignCount);
            stmt.setBytes(2, credentialId);
            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            System.err.println("Error updating passkey sign count: " + e.getMessage());
            return false;
        }
    }

    /**
     * Rename a passkey
     */
    public boolean renamePasskey(int passkeyId, int adminId, String newName) {
        String sql = "UPDATE admin_passkeys SET name = ? WHERE id = ? AND admin_id = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, newName);
            stmt.setInt(2, passkeyId);
            stmt.setInt(3, adminId);
            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            System.err.println("Error renaming passkey: " + e.getMessage());
            return false;
        }
    }

    /**
     * Delete a passkey
     */
    public boolean deletePasskey(int passkeyId, int adminId) {
        String sql = "DELETE FROM admin_passkeys WHERE id = ? AND admin_id = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, passkeyId);
            stmt.setInt(2, adminId);
            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            System.err.println("Error deleting passkey: " + e.getMessage());
            return false;
        }
    }

    /**
     * Get admin ID by username (for passkey login)
     */
    public int getAdminIdByUsername(String username) {
        String sql = "SELECT id FROM panel_admin WHERE username = ? AND active = TRUE";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, username);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return rs.getInt("id");
            }
        } catch (SQLException e) {
            System.err.println("Error getting admin ID: " + e.getMessage());
        }
        return 0;
    }

    /**
     * Check what auth methods a user has
     */
    public static class AuthMethods {
        public boolean exists;
        public boolean hasPassword;
        public boolean hasPasskey;
        public boolean has2FA;
    }

    public AuthMethods getAuthMethods(String username) {
        AuthMethods methods = new AuthMethods();
        String sql = "SELECT id, password_hash, totp_enabled FROM panel_admin WHERE username = ? AND active = TRUE";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, username);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                methods.exists = true;
                methods.hasPassword = rs.getString("password_hash") != null && !rs.getString("password_hash").isEmpty();
                methods.has2FA = rs.getBoolean("totp_enabled");
                int adminId = rs.getInt("id");
                methods.hasPasskey = hasPasskey(adminId);
            }
        } catch (SQLException e) {
            System.err.println("Error getting auth methods: " + e.getMessage());
        }
        return methods;
    }

    // ========== SETTINGS MANAGEMENT ==========

    public String getSetting(String key, String defaultValue) {
        String sql = "SELECT setting_value FROM panel_settings WHERE setting_key = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, key);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return rs.getString("setting_value");
            }
        } catch (SQLException e) {
            // ignore
        }
        return defaultValue;
    }

    public void setSetting(String key, String value) {
        String sql = """
            INSERT INTO panel_settings (setting_key, setting_value) VALUES (?, ?)
            ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)
            """;
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, key);
            stmt.setString(2, value);
            stmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("Failed to set setting: " + e.getMessage());
        }
    }

    public void deleteSetting(String key) {
        String sql = "DELETE FROM panel_settings WHERE setting_key = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, key);
            stmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("Failed to delete setting: " + e.getMessage());
        }
    }

    // ========== COMPONENT MANAGEMENT ==========

    public boolean isComponentInstalled(String componentName) {
        String sql = "SELECT 1 FROM installed_components WHERE component_name = ? AND status = 'installed'";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, componentName);
            ResultSet rs = stmt.executeQuery();
            return rs.next();
        } catch (SQLException e) {
            return false;
        }
    }

    public void markComponentInstalled(String componentName, String version) {
        String sql = """
            INSERT INTO installed_components (component_name, version, status)
            VALUES (?, ?, 'installed')
            ON DUPLICATE KEY UPDATE
                version = VALUES(version),
                installed_at = CURRENT_TIMESTAMP,
                status = 'installed'
            """;
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, componentName);
            stmt.setString(2, version);
            stmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("Failed to mark component installed: " + e.getMessage());
        }
    }

    public void markComponentUninstalled(String componentName) {
        String sql = "UPDATE installed_components SET status = 'uninstalled' WHERE component_name = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, componentName);
            stmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("Failed to mark component uninstalled: " + e.getMessage());
        }
    }

    public String getInstalledComponentsJson() {
        StringBuilder json = new StringBuilder("[");
        String sql = "SELECT component_name, version, installed_at FROM installed_components WHERE status = 'installed'";
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            boolean first = true;
            while (rs.next()) {
                if (!first) json.append(",");
                json.append("{")
                    .append("\"name\":\"").append(escapeJson(rs.getString("component_name"))).append("\",")
                    .append("\"version\":\"").append(escapeJson(rs.getString("version"))).append("\",")
                    .append("\"installed_at\":\"").append(rs.getString("installed_at")).append("\"")
                    .append("}");
                first = false;
            }
        } catch (SQLException e) {
            // ignore
        }
        json.append("]");
        return json.toString();
    }

    // ========== DOMAIN MANAGEMENT ==========

    public int addDomain(String domain, String description) throws SQLException {
        String sql = "INSERT INTO domains (domain, description) VALUES (?, ?)";
        try (PreparedStatement stmt = connection.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            stmt.setString(1, domain.toLowerCase());
            stmt.setString(2, description);
            stmt.executeUpdate();
            ResultSet rs = stmt.getGeneratedKeys();
            if (rs.next()) {
                int newId = rs.getInt(1);
                // Postfix uses MySQL directly - no file sync needed
                return newId;
            }
        }
        return -1;
    }

    public boolean deleteDomain(int domainId) throws SQLException {
        String sql = "DELETE FROM domains WHERE id = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, domainId);
            return stmt.executeUpdate() > 0;
            // Postfix uses MySQL directly - no file sync needed
        }
    }

    public boolean updateDomainStatus(int domainId, boolean active) throws SQLException {
        String sql = "UPDATE domains SET active = ? WHERE id = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setBoolean(1, active);
            stmt.setInt(2, domainId);
            return stmt.executeUpdate() > 0;
            // Postfix uses MySQL directly - no file sync needed
        }
    }

    public Domain getDomain(int domainId) throws SQLException {
        String sql = "SELECT * FROM domains WHERE id = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, domainId);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return mapDomain(rs);
            }
        }
        return null;
    }

    public Domain getDomainByName(String domainName) throws SQLException {
        String sql = "SELECT * FROM domains WHERE domain = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, domainName.toLowerCase());
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return mapDomain(rs);
            }
        }
        return null;
    }

    public List<Domain> getDomains() throws SQLException {
        List<Domain> domains = new ArrayList<>();
        String sql = """
            SELECT d.*,
                   (SELECT COUNT(*) FROM mailboxes m WHERE m.domain_id = d.id) as mailbox_count,
                   (SELECT COUNT(*) FROM aliases a WHERE a.domain_id = d.id) as alias_count
            FROM domains d ORDER BY d.domain
            """;
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            while (rs.next()) {
                Domain d = mapDomain(rs);
                d.mailboxCount = rs.getInt("mailbox_count");
                d.aliasCount = rs.getInt("alias_count");
                domains.add(d);
            }
        }
        return domains;
    }

    private Domain mapDomain(ResultSet rs) throws SQLException {
        Domain d = new Domain();
        d.id = rs.getInt("id");
        d.domain = rs.getString("domain");
        d.description = rs.getString("description");
        d.active = rs.getBoolean("active");
        d.createdAt = rs.getTimestamp("created_at");
        d.dkimSelector = rs.getString("dkim_selector");
        d.dkimPrivateKey = rs.getString("dkim_private_key");
        d.dkimPublicKey = rs.getString("dkim_public_key");
        d.hasDkim = d.dkimPrivateKey != null && !d.dkimPrivateKey.isEmpty();
        return d;
    }

    public void setDkim(int domainId, String selector, String privateKey, String publicKey) throws SQLException {
        String sql = "UPDATE domains SET dkim_selector = ?, dkim_private_key = ?, dkim_public_key = ? WHERE id = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, selector);
            stmt.setString(2, privateKey);
            stmt.setString(3, publicKey);
            stmt.setInt(4, domainId);
            stmt.executeUpdate();
        }
    }

    // ========== MAILBOX MANAGEMENT ==========

    public int addMailbox(int domainId, String email, String password, String name, int quotaMb) throws SQLException {
        // Hash password with bcrypt (compatible with Dovecot)
        // Dovecot uses default_pass_scheme = BLF-CRYPT, so no prefix needed
        // Postfix authenticates via Dovecot SASL
        String hashedPassword = BCrypt.hashpw(password, BCrypt.gensalt(12));

        String sql = "INSERT INTO mailboxes (domain_id, email, password, name, quota_mb) VALUES (?, ?, ?, ?, ?)";
        try (PreparedStatement stmt = connection.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            stmt.setInt(1, domainId);
            stmt.setString(2, email.toLowerCase());
            stmt.setString(3, hashedPassword);
            stmt.setString(4, name);
            stmt.setInt(5, quotaMb);
            stmt.executeUpdate();
            ResultSet rs = stmt.getGeneratedKeys();
            if (rs.next()) {
                int newId = rs.getInt(1);
                // Postfix uses MySQL directly - no file sync needed
                return newId;
            }
        }
        return -1;
    }

    public boolean deleteMailbox(int mailboxId) throws SQLException {
        String sql = "DELETE FROM mailboxes WHERE id = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, mailboxId);
            return stmt.executeUpdate() > 0;
            // Postfix uses MySQL directly - no file sync needed
        }
    }

    public boolean updateMailboxPassword(int mailboxId, String newPassword) throws SQLException {
        // Bcrypt hash (compatible with Dovecot)
        String hashedPassword = BCrypt.hashpw(newPassword, BCrypt.gensalt(12));
        String sql = "UPDATE mailboxes SET password = ? WHERE id = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, hashedPassword);
            stmt.setInt(2, mailboxId);
            return stmt.executeUpdate() > 0;
            // Postfix uses MySQL directly - no file sync needed
        }
    }

    public boolean updateMailboxStatus(int mailboxId, boolean active) throws SQLException {
        String sql = "UPDATE mailboxes SET active = ? WHERE id = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setBoolean(1, active);
            stmt.setInt(2, mailboxId);
            return stmt.executeUpdate() > 0;
            // Postfix uses MySQL directly - no file sync needed
        }
    }

    public boolean updateMailboxQuota(int mailboxId, int quotaMb) throws SQLException {
        String sql = "UPDATE mailboxes SET quota_mb = ? WHERE id = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, quotaMb);
            stmt.setInt(2, mailboxId);
            return stmt.executeUpdate() > 0;
        }
    }

    /**
     * Reload Postfix configuration
     * Postfix uses MySQL directly for virtual users, so no file sync is needed.
     * This just tells Postfix to reload if any configuration changes were made.
     *
     * Postfix queries MySQL directly via:
     * - mysql-virtual-domains.cf → SELECT domain FROM domains WHERE domain='%s' AND active=1
     * - mysql-virtual-mailboxes.cf → SELECT ... FROM mailboxes WHERE email='%s' AND active=1
     * - mysql-virtual-aliases.cf → SELECT destination FROM aliases WHERE source='%s' AND active=1
     */
    public boolean reloadPostfix() {
        try {
            ProcessBuilder pb = new ProcessBuilder("sh", "-c", "service postfix reload 2>/dev/null || true");
            pb.redirectErrorStream(true);
            Process p = pb.start();
            p.waitFor();
            System.out.println("Postfix configuration reloaded");
            return true;
        } catch (Exception e) {
            System.err.println("Failed to reload Postfix: " + e.getMessage());
            return false;
        }
    }

    /**
     * Sync mail server configuration after changes
     * With Postfix + MySQL, database changes are picked up automatically.
     * This method is kept for API compatibility.
     */
    public void syncAllSmtpFiles() {
        // Postfix uses MySQL directly - no file sync needed
        // Database changes are picked up automatically on next query
        System.out.println("Postfix uses MySQL directly - no sync needed");
    }

    public Mailbox getMailbox(int mailboxId) throws SQLException {
        String sql = "SELECT m.*, d.domain as domain_name FROM mailboxes m JOIN domains d ON m.domain_id = d.id WHERE m.id = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, mailboxId);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return mapMailbox(rs);
            }
        }
        return null;
    }

    public Mailbox getMailboxByEmail(String email) throws SQLException {
        String sql = "SELECT m.*, d.domain as domain_name FROM mailboxes m JOIN domains d ON m.domain_id = d.id WHERE m.email = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, email.toLowerCase());
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return mapMailbox(rs);
            }
        }
        return null;
    }

    public Mailbox getMailboxById(int id) {
        String sql = "SELECT m.*, d.domain as domain_name FROM mailboxes m JOIN domains d ON m.domain_id = d.id WHERE m.id = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, id);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return mapMailbox(rs);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }

    public List<Mailbox> getMailboxes(int domainId) throws SQLException {
        List<Mailbox> mailboxes = new ArrayList<>();
        String sql = "SELECT m.*, d.domain as domain_name FROM mailboxes m JOIN domains d ON m.domain_id = d.id WHERE m.domain_id = ? ORDER BY m.email";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, domainId);
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                mailboxes.add(mapMailbox(rs));
            }
        }
        return mailboxes;
    }

    public List<Mailbox> getAllMailboxes() throws SQLException {
        List<Mailbox> mailboxes = new ArrayList<>();
        String sql = """
            SELECT m.*, d.domain as domain_name,
                (SELECT COUNT(*) FROM forwarding_rules fr WHERE fr.mailbox_id = m.id AND fr.enabled = 1) as forwarding_count,
                (SELECT COUNT(*) FROM sieve_filters sf WHERE sf.mailbox_id = m.id AND sf.enabled = 1) as filters_count,
                (SELECT COALESCE(ar.enabled, 0) FROM auto_responders ar WHERE ar.mailbox_id = m.id) as autoresponder_enabled
            FROM mailboxes m
            JOIN domains d ON m.domain_id = d.id
            ORDER BY m.email
            """;
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            while (rs.next()) {
                mailboxes.add(mapMailbox(rs));
            }
        }
        return mailboxes;
    }

    private Mailbox mapMailbox(ResultSet rs) throws SQLException {
        Mailbox m = new Mailbox();
        m.id = rs.getInt("id");
        m.domainId = rs.getInt("domain_id");
        m.domainName = rs.getString("domain_name");
        m.email = rs.getString("email");
        m.name = rs.getString("name");
        m.quotaMb = rs.getInt("quota_mb");
        m.active = rs.getBoolean("active");
        m.createdAt = rs.getTimestamp("created_at");
        m.lastLogin = rs.getTimestamp("last_login");
        // Additional UI counts (may not be present in all queries)
        try {
            m.forwardingCount = rs.getInt("forwarding_count");
            m.filtersCount = rs.getInt("filters_count");
            m.autoresponderEnabled = rs.getBoolean("autoresponder_enabled");
        } catch (SQLException ignored) {
            // Fields not present in simpler queries
        }
        return m;
    }

    // ========== ALIAS MANAGEMENT ==========

    public int addAlias(int domainId, String source, String destination) throws SQLException {
        String sql = "INSERT INTO aliases (domain_id, source, destination) VALUES (?, ?, ?)";
        try (PreparedStatement stmt = connection.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            stmt.setInt(1, domainId);
            stmt.setString(2, source.toLowerCase());
            stmt.setString(3, destination.toLowerCase());
            stmt.executeUpdate();
            ResultSet rs = stmt.getGeneratedKeys();
            if (rs.next()) {
                int newId = rs.getInt(1);
                // Postfix uses MySQL directly - no file sync needed
                return newId;
            }
        }
        return -1;
    }

    public boolean deleteAlias(int aliasId) throws SQLException {
        String sql = "DELETE FROM aliases WHERE id = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, aliasId);
            return stmt.executeUpdate() > 0;
            // Postfix uses MySQL directly - no file sync needed
        }
    }

    public boolean updateAliasStatus(int aliasId, boolean active) throws SQLException {
        String sql = "UPDATE aliases SET active = ? WHERE id = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setBoolean(1, active);
            stmt.setInt(2, aliasId);
            return stmt.executeUpdate() > 0;
            // Postfix uses MySQL directly - no file sync needed
        }
    }

    public List<Alias> getAliases(int domainId) throws SQLException {
        List<Alias> aliases = new ArrayList<>();
        String sql = "SELECT * FROM aliases WHERE domain_id = ? ORDER BY source";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, domainId);
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                aliases.add(mapAlias(rs));
            }
        }
        return aliases;
    }

    public List<Alias> getAllAliases() throws SQLException {
        List<Alias> aliases = new ArrayList<>();
        String sql = "SELECT a.*, d.domain as domain_name FROM aliases a JOIN domains d ON a.domain_id = d.id ORDER BY a.source";
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            while (rs.next()) {
                Alias a = mapAlias(rs);
                a.domainName = rs.getString("domain_name");
                aliases.add(a);
            }
        }
        return aliases;
    }

    private Alias mapAlias(ResultSet rs) throws SQLException {
        Alias a = new Alias();
        a.id = rs.getInt("id");
        a.domainId = rs.getInt("domain_id");
        a.source = rs.getString("source");
        a.destination = rs.getString("destination");
        a.active = rs.getBoolean("active");
        a.createdAt = rs.getTimestamp("created_at");
        return a;
    }

    // ========== ROUNDCUBE AUTO-LOGIN ==========

    public String createAutoLoginToken(int mailboxId) throws SQLException {
        String token = UUID.randomUUID().toString().replace("-", "");
        String sql = "INSERT INTO roundcube_tokens (token, mailbox_id, expires_at) VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 5 MINUTE))";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, token);
            stmt.setInt(2, mailboxId);
            stmt.executeUpdate();
            return token;
        }
    }

    public Mailbox validateAutoLoginToken(String token) throws SQLException {
        String sql = """
            SELECT m.*, d.domain as domain_name FROM mailboxes m
            JOIN roundcube_tokens t ON t.mailbox_id = m.id
            JOIN domains d ON m.domain_id = d.id
            WHERE t.token = ? AND t.expires_at > NOW() AND t.used = FALSE
            """;
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, token);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                // Mark token as used
                try (PreparedStatement update = connection.prepareStatement(
                        "UPDATE roundcube_tokens SET used = TRUE WHERE token = ?")) {
                    update.setString(1, token);
                    update.executeUpdate();
                }
                return mapMailbox(rs);
            }
        }
        return null;
    }

    public void cleanupExpiredTokens() throws SQLException {
        String sql = "DELETE FROM roundcube_tokens WHERE expires_at < NOW() OR used = TRUE";
        try (Statement stmt = connection.createStatement()) {
            stmt.executeUpdate(sql);
        }
    }

    // ========== STATISTICS ==========

    public int getDomainCount() {
        return getCount("SELECT COUNT(*) FROM domains WHERE active = TRUE");
    }

    public int getMailboxCount() {
        return getCount("SELECT COUNT(*) FROM mailboxes WHERE active = TRUE");
    }

    public int getAliasCount() {
        return getCount("SELECT COUNT(*) FROM aliases WHERE active = TRUE");
    }

    private int getCount(String sql) {
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            if (rs.next()) {
                return rs.getInt(1);
            }
        } catch (SQLException e) {
            // ignore
        }
        return 0;
    }

    // ========== UTILITY ==========

    private String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    public void close() {
        try {
            if (connection != null && !connection.isClosed()) {
                connection.close();
            }
        } catch (SQLException e) {
            // ignore
        }
        connected = false;
    }

    public Connection getConnection() {
        return connection;
    }

    // ========== MODEL CLASSES ==========

    public static class Domain {
        public int id;
        public String domain;
        public String description;
        public boolean active;
        public Timestamp createdAt;
        public int mailboxCount;
        public int aliasCount;
        public String dkimSelector;
        public String dkimPrivateKey;
        public String dkimPublicKey;
        public boolean hasDkim;
    }

    public static class Mailbox {
        public int id;
        public int domainId;
        public String domainName;
        public String email;
        public String name;
        public int quotaMb;
        public boolean active;
        public Timestamp createdAt;
        public Timestamp lastLogin;
        // Additional counts for UI display
        public boolean autoresponderEnabled;
        public int forwardingCount;
        public int filtersCount;
    }

    public static class Alias {
        public int id;
        public int domainId;
        public String domainName;
        public String source;
        public String destination;
        public boolean active;
        public Timestamp createdAt;
    }

    // ========== 2FA / TOTP METHODS ==========

    public boolean enable2FA(int adminId, String totpSecret, String backupCodes) {
        String sql = "UPDATE panel_admin SET totp_secret = ?, totp_enabled = TRUE, backup_codes = ? WHERE id = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, totpSecret);
            stmt.setString(2, backupCodes);
            stmt.setInt(3, adminId);
            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }

    public boolean disable2FA(int adminId) {
        String sql = "UPDATE panel_admin SET totp_secret = NULL, totp_enabled = FALSE, backup_codes = NULL WHERE id = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, adminId);
            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }

    public String getTotpSecret(int adminId) {
        String sql = "SELECT totp_secret FROM panel_admin WHERE id = ? AND totp_enabled = TRUE";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, adminId);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return rs.getString("totp_secret");
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }

    public boolean is2FAEnabled(int adminId) {
        String sql = "SELECT totp_enabled FROM panel_admin WHERE id = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, adminId);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return rs.getBoolean("totp_enabled");
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return false;
    }

    public String getBackupCodes(int adminId) {
        String sql = "SELECT backup_codes FROM panel_admin WHERE id = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, adminId);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return rs.getString("backup_codes");
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }

    public boolean updateBackupCodes(int adminId, String backupCodes) {
        String sql = "UPDATE panel_admin SET backup_codes = ? WHERE id = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, backupCodes);
            stmt.setInt(2, adminId);
            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * Try to use a backup code for 2FA. Returns true if valid and removes it.
     */
    public boolean useBackupCode(int adminId, String code) {
        if (code == null || code.isEmpty()) return false;

        String codesJson = getBackupCodes(adminId);
        if (codesJson == null || codesJson.isEmpty()) return false;

        try {
            org.json.JSONArray codes = new org.json.JSONArray(codesJson);
            String hashedInput = org.mail_panel.security.TotpManager.hashBackupCode(code);

            for (int i = 0; i < codes.length(); i++) {
                if (codes.getString(i).equals(hashedInput)) {
                    // Found - remove it and save
                    codes.remove(i);
                    updateBackupCodes(adminId, codes.toString());
                    return true;
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    // ========== MULTI-ADMIN / ROLES ==========

    public static class AdminUser {
        public int id;
        public String username;
        public String role;
        public boolean active;
        public boolean totpEnabled;
        public Timestamp createdAt;
        public Timestamp lastLogin;
    }

    public List<AdminUser> getAdminUsers() {
        List<AdminUser> admins = new ArrayList<>();
        String sql = "SELECT id, username, role, active, totp_enabled, created_at, last_login FROM panel_admin ORDER BY id";
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            while (rs.next()) {
                AdminUser admin = new AdminUser();
                admin.id = rs.getInt("id");
                admin.username = rs.getString("username");
                admin.role = rs.getString("role");
                admin.active = rs.getBoolean("active");
                admin.totpEnabled = rs.getBoolean("totp_enabled");
                admin.createdAt = rs.getTimestamp("created_at");
                admin.lastLogin = rs.getTimestamp("last_login");
                admins.add(admin);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return admins;
    }

    public AdminUser getAdminUserById(int adminId) {
        String sql = "SELECT id, username, role, active, totp_enabled, created_at, last_login FROM panel_admin WHERE id = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, adminId);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    AdminUser admin = new AdminUser();
                    admin.id = rs.getInt("id");
                    admin.username = rs.getString("username");
                    admin.role = rs.getString("role");
                    admin.active = rs.getBoolean("active");
                    admin.totpEnabled = rs.getBoolean("totp_enabled");
                    admin.createdAt = rs.getTimestamp("created_at");
                    admin.lastLogin = rs.getTimestamp("last_login");
                    return admin;
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }

    public boolean createAdmin(String username, String password, String role) {
        String sql = "INSERT INTO panel_admin (username, password_hash, role) VALUES (?, ?, ?)";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, username);
            stmt.setString(2, BCrypt.hashpw(password, BCrypt.gensalt(12)));
            stmt.setString(3, role);
            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }

    public boolean updateAdminRole(int adminId, String role) {
        String sql = "UPDATE panel_admin SET role = ? WHERE id = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, role);
            stmt.setInt(2, adminId);
            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }

    public boolean deleteAdmin(int adminId) {
        String sql = "DELETE FROM panel_admin WHERE id = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, adminId);
            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }

    public String getAdminRole(int adminId) {
        String sql = "SELECT role FROM panel_admin WHERE id = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, adminId);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return rs.getString("role");
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }

    // ========== AUTO-RESPONDER ==========

    public static class AutoResponder {
        public int id;
        public int mailboxId;
        public String email;
        public boolean enabled;
        public String subject;
        public String body;
        public java.sql.Date startDate;
        public java.sql.Date endDate;
        public int intervalHours;
    }

    public AutoResponder getAutoResponder(int mailboxId) {
        String sql = """
            SELECT ar.*, m.email FROM auto_responders ar
            JOIN mailboxes m ON ar.mailbox_id = m.id
            WHERE ar.mailbox_id = ?
            """;
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, mailboxId);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                AutoResponder ar = new AutoResponder();
                ar.id = rs.getInt("id");
                ar.mailboxId = rs.getInt("mailbox_id");
                ar.email = rs.getString("email");
                ar.enabled = rs.getBoolean("enabled");
                ar.subject = rs.getString("subject");
                ar.body = rs.getString("body");
                ar.startDate = rs.getDate("start_date");
                ar.endDate = rs.getDate("end_date");
                ar.intervalHours = rs.getInt("interval_hours");
                return ar;
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }

    public boolean saveAutoResponder(int mailboxId, boolean enabled, String subject, String body,
                                     java.sql.Date startDate, java.sql.Date endDate, int intervalHours) {
        String sql = """
            INSERT INTO auto_responders (mailbox_id, enabled, subject, body, start_date, end_date, interval_hours)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE enabled = ?, subject = ?, body = ?, start_date = ?, end_date = ?, interval_hours = ?
            """;
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, mailboxId);
            stmt.setBoolean(2, enabled);
            stmt.setString(3, subject);
            stmt.setString(4, body);
            stmt.setDate(5, startDate);
            stmt.setDate(6, endDate);
            stmt.setInt(7, intervalHours);
            // For UPDATE
            stmt.setBoolean(8, enabled);
            stmt.setString(9, subject);
            stmt.setString(10, body);
            stmt.setDate(11, startDate);
            stmt.setDate(12, endDate);
            stmt.setInt(13, intervalHours);
            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }

    public List<AutoResponder> getActiveAutoResponders() {
        List<AutoResponder> list = new ArrayList<>();
        String sql = """
            SELECT ar.*, m.email FROM auto_responders ar
            JOIN mailboxes m ON ar.mailbox_id = m.id
            WHERE ar.enabled = TRUE
            AND (ar.start_date IS NULL OR ar.start_date <= CURDATE())
            AND (ar.end_date IS NULL OR ar.end_date >= CURDATE())
            """;
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            while (rs.next()) {
                AutoResponder ar = new AutoResponder();
                ar.id = rs.getInt("id");
                ar.mailboxId = rs.getInt("mailbox_id");
                ar.email = rs.getString("email");
                ar.enabled = rs.getBoolean("enabled");
                ar.subject = rs.getString("subject");
                ar.body = rs.getString("body");
                ar.startDate = rs.getDate("start_date");
                ar.endDate = rs.getDate("end_date");
                ar.intervalHours = rs.getInt("interval_hours");
                list.add(ar);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return list;
    }

    // ========== SIEVE FILTERS ==========

    public static class SieveFilter {
        public int id;
        public int mailboxId;
        public String email;
        public String name;
        public int priority;
        public boolean enabled;
        public String conditions; // JSON
        public String actions; // JSON
    }

    public List<SieveFilter> getSieveFilters(int mailboxId) {
        List<SieveFilter> filters = new ArrayList<>();
        String sql = """
            SELECT sf.*, m.email FROM sieve_filters sf
            JOIN mailboxes m ON sf.mailbox_id = m.id
            WHERE sf.mailbox_id = ?
            ORDER BY sf.priority, sf.id
            """;
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, mailboxId);
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                SieveFilter f = new SieveFilter();
                f.id = rs.getInt("id");
                f.mailboxId = rs.getInt("mailbox_id");
                f.email = rs.getString("email");
                f.name = rs.getString("name");
                f.priority = rs.getInt("priority");
                f.enabled = rs.getBoolean("enabled");
                f.conditions = rs.getString("conditions");
                f.actions = rs.getString("actions");
                filters.add(f);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return filters;
    }

    public boolean createSieveFilter(int mailboxId, String name, int priority, String conditions, String actions) {
        String sql = "INSERT INTO sieve_filters (mailbox_id, name, priority, conditions, actions) VALUES (?, ?, ?, ?, ?)";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, mailboxId);
            stmt.setString(2, name);
            stmt.setInt(3, priority);
            stmt.setString(4, conditions);
            stmt.setString(5, actions);
            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }

    public boolean updateSieveFilter(int filterId, String name, int priority, boolean enabled, String conditions, String actions) {
        String sql = "UPDATE sieve_filters SET name = ?, priority = ?, enabled = ?, conditions = ?, actions = ? WHERE id = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, name);
            stmt.setInt(2, priority);
            stmt.setBoolean(3, enabled);
            stmt.setString(4, conditions);
            stmt.setString(5, actions);
            stmt.setInt(6, filterId);
            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }

    public boolean deleteSieveFilter(int filterId) {
        String sql = "DELETE FROM sieve_filters WHERE id = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, filterId);
            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }

    // ========== FORWARDING RULES ==========

    public static class ForwardingRule {
        public int id;
        public int mailboxId;
        public String email;
        public String destination;
        public boolean keepCopy;
        public boolean enabled;
    }

    public List<ForwardingRule> getForwardingRules(int mailboxId) {
        List<ForwardingRule> rules = new ArrayList<>();
        String sql = """
            SELECT fr.*, m.email FROM forwarding_rules fr
            JOIN mailboxes m ON fr.mailbox_id = m.id
            WHERE fr.mailbox_id = ?
            """;
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, mailboxId);
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                ForwardingRule r = new ForwardingRule();
                r.id = rs.getInt("id");
                r.mailboxId = rs.getInt("mailbox_id");
                r.email = rs.getString("email");
                r.destination = rs.getString("destination");
                r.keepCopy = rs.getBoolean("keep_copy");
                r.enabled = rs.getBoolean("enabled");
                rules.add(r);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return rules;
    }

    public boolean createForwardingRule(int mailboxId, String destination, boolean keepCopy) {
        String sql = "INSERT INTO forwarding_rules (mailbox_id, destination, keep_copy) VALUES (?, ?, ?)";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, mailboxId);
            stmt.setString(2, destination);
            stmt.setBoolean(3, keepCopy);
            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }

    public boolean updateForwardingRule(int ruleId, String destination, boolean keepCopy, boolean enabled) {
        String sql = "UPDATE forwarding_rules SET destination = ?, keep_copy = ?, enabled = ? WHERE id = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, destination);
            stmt.setBoolean(2, keepCopy);
            stmt.setBoolean(3, enabled);
            stmt.setInt(4, ruleId);
            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }

    public boolean deleteForwardingRule(int ruleId) {
        String sql = "DELETE FROM forwarding_rules WHERE id = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, ruleId);
            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }

    // ========== RATE LIMITS ==========

    public static class RateLimit {
        public int id;
        public String targetType;
        public Integer targetId;
        public String targetName;
        public int maxPerHour;
        public int maxPerDay;
        public int maxRecipients;
        public boolean enabled;
    }

    public List<RateLimit> getRateLimits() {
        List<RateLimit> limits = new ArrayList<>();
        String sql = """
            SELECT rl.*,
                CASE
                    WHEN rl.target_type = 'domain' THEN (SELECT domain FROM domains WHERE id = rl.target_id)
                    WHEN rl.target_type = 'mailbox' THEN (SELECT email FROM mailboxes WHERE id = rl.target_id)
                    ELSE 'Global'
                END as target_name
            FROM rate_limits rl
            ORDER BY rl.target_type, rl.target_id
            """;
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            while (rs.next()) {
                RateLimit rl = new RateLimit();
                rl.id = rs.getInt("id");
                rl.targetType = rs.getString("target_type");
                rl.targetId = rs.getObject("target_id") != null ? rs.getInt("target_id") : null;
                rl.targetName = rs.getString("target_name");
                rl.maxPerHour = rs.getInt("max_per_hour");
                rl.maxPerDay = rs.getInt("max_per_day");
                rl.maxRecipients = rs.getInt("max_recipients");
                rl.enabled = rs.getBoolean("enabled");
                limits.add(rl);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return limits;
    }

    public boolean saveRateLimit(String targetType, Integer targetId, int maxPerHour, int maxPerDay, int maxRecipients, boolean enabled) {
        String sql = """
            INSERT INTO rate_limits (target_type, target_id, max_per_hour, max_per_day, max_recipients, enabled)
            VALUES (?, ?, ?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE max_per_hour = ?, max_per_day = ?, max_recipients = ?, enabled = ?
            """;
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, targetType);
            if (targetId != null) {
                stmt.setInt(2, targetId);
            } else {
                stmt.setNull(2, java.sql.Types.INTEGER);
            }
            stmt.setInt(3, maxPerHour);
            stmt.setInt(4, maxPerDay);
            stmt.setInt(5, maxRecipients);
            stmt.setBoolean(6, enabled);
            stmt.setInt(7, maxPerHour);
            stmt.setInt(8, maxPerDay);
            stmt.setInt(9, maxRecipients);
            stmt.setBoolean(10, enabled);
            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }

    public boolean deleteRateLimit(int limitId) {
        String sql = "DELETE FROM rate_limits WHERE id = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, limitId);
            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }

    // ========== EMAIL STATISTICS ==========

    public static class EmailStat {
        public java.sql.Date statDate;
        public Integer mailboxId;
        public Integer domainId;
        public String name;
        public int sentCount;
        public int receivedCount;
        public int spamCount;
        public int virusCount;
        public int bouncedCount;
        public long bytesSent;
        public long bytesReceived;
    }

    public List<EmailStat> getEmailStatistics(int days) {
        List<EmailStat> stats = new ArrayList<>();
        String sql = """
            SELECT es.*,
                COALESCE(m.email, d.domain, 'Total') as name
            FROM email_statistics es
            LEFT JOIN mailboxes m ON es.mailbox_id = m.id
            LEFT JOIN domains d ON es.domain_id = d.id
            WHERE es.stat_date >= DATE_SUB(CURDATE(), INTERVAL ? DAY)
            ORDER BY es.stat_date DESC, es.domain_id, es.mailbox_id
            """;
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, days);
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                EmailStat stat = new EmailStat();
                stat.statDate = rs.getDate("stat_date");
                stat.mailboxId = rs.getObject("mailbox_id") != null ? rs.getInt("mailbox_id") : null;
                stat.domainId = rs.getObject("domain_id") != null ? rs.getInt("domain_id") : null;
                stat.name = rs.getString("name");
                stat.sentCount = rs.getInt("sent_count");
                stat.receivedCount = rs.getInt("received_count");
                stat.spamCount = rs.getInt("spam_count");
                stat.virusCount = rs.getInt("virus_count");
                stat.bouncedCount = rs.getInt("bounced_count");
                stat.bytesSent = rs.getLong("bytes_sent");
                stat.bytesReceived = rs.getLong("bytes_received");
                stats.add(stat);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return stats;
    }

    public EmailStat getTodayStats() {
        String sql = """
            SELECT
                CURDATE() as stat_date,
                SUM(sent_count) as sent_count,
                SUM(received_count) as received_count,
                SUM(spam_count) as spam_count,
                SUM(virus_count) as virus_count,
                SUM(bounced_count) as bounced_count,
                SUM(bytes_sent) as bytes_sent,
                SUM(bytes_received) as bytes_received
            FROM email_statistics
            WHERE stat_date = CURDATE()
            """;
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            if (rs.next()) {
                EmailStat stat = new EmailStat();
                stat.statDate = rs.getDate("stat_date");
                stat.name = "Today";
                stat.sentCount = rs.getInt("sent_count");
                stat.receivedCount = rs.getInt("received_count");
                stat.spamCount = rs.getInt("spam_count");
                stat.virusCount = rs.getInt("virus_count");
                stat.bouncedCount = rs.getInt("bounced_count");
                stat.bytesSent = rs.getLong("bytes_sent");
                stat.bytesReceived = rs.getLong("bytes_received");
                return stat;
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }

    public void incrementEmailStat(Integer mailboxId, Integer domainId, String statType, int count, long bytes) {
        String column = switch (statType) {
            case "sent" -> "sent_count";
            case "received" -> "received_count";
            case "spam" -> "spam_count";
            case "virus" -> "virus_count";
            case "bounced" -> "bounced_count";
            default -> null;
        };
        String bytesColumn = statType.equals("sent") ? "bytes_sent" : "bytes_received";

        if (column == null) return;

        String sql = String.format("""
            INSERT INTO email_statistics (stat_date, mailbox_id, domain_id, %s, %s)
            VALUES (CURDATE(), ?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE %s = %s + ?, %s = %s + ?
            """, column, bytesColumn, column, column, bytesColumn, bytesColumn);

        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            if (mailboxId != null) {
                stmt.setInt(1, mailboxId);
            } else {
                stmt.setNull(1, java.sql.Types.INTEGER);
            }
            if (domainId != null) {
                stmt.setInt(2, domainId);
            } else {
                stmt.setNull(2, java.sql.Types.INTEGER);
            }
            stmt.setInt(3, count);
            stmt.setLong(4, bytes);
            stmt.setInt(5, count);
            stmt.setLong(6, bytes);
            stmt.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    // ========== RSPAMD TRAINING ==========

    public boolean logRspamdTraining(String messageId, String trainedAs, int trainedBy) {
        String sql = "INSERT INTO rspamd_training (message_id, trained_as, trained_by) VALUES (?, ?, ?)";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, messageId);
            stmt.setString(2, trainedAs);
            stmt.setInt(3, trainedBy);
            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }

    public int getTrainingCount(String trainedAs, int days) {
        String sql = "SELECT COUNT(*) FROM rspamd_training WHERE trained_as = ? AND trained_at >= DATE_SUB(NOW(), INTERVAL ? DAY)";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, trainedAs);
            stmt.setInt(2, days);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return rs.getInt(1);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return 0;
    }

    // ========== AUDIT LOGGING ==========

    /**
     * Log an audit event for security tracking
     * @param action The action type (LOGIN_SUCCESS, LOGIN_FAILURE, DOMAIN_CREATED, etc.)
     * @param ipAddress Client IP address
     * @param details Additional details about the action
     * @param username The username performing the action (null for anonymous)
     */
    public void logAuditEvent(String action, String ipAddress, String details, String username) {
        String sql = "INSERT INTO audit_log (action, username, ip_address, details) VALUES (?, ?, ?, ?)";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, action);
            stmt.setString(2, username);
            stmt.setString(3, ipAddress);
            stmt.setString(4, details);
            stmt.executeUpdate();
        } catch (SQLException e) {
            // Don't propagate - audit logging should not break the application
            System.err.println("Failed to log audit event: " + e.getMessage());
        }
    }

    /**
     * Log an audit event with user agent
     */
    public void logAuditEventFull(String action, String ipAddress, String details, String username, String userAgent) {
        String sql = "INSERT INTO audit_log (action, username, ip_address, details, user_agent) VALUES (?, ?, ?, ?, ?)";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, action);
            stmt.setString(2, username);
            stmt.setString(3, ipAddress);
            stmt.setString(4, details);
            stmt.setString(5, userAgent);
            stmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("Failed to log audit event: " + e.getMessage());
        }
    }

    /**
     * Data class for audit log entries
     */
    public static class AuditLogEntry {
        public int id;
        public String action;
        public String username;
        public String ipAddress;
        public String details;
        public String userAgent;
        public java.sql.Timestamp createdAt;
    }

    /**
     * Get audit log entries with optional filters
     * @param action Filter by action type (null for all)
     * @param username Filter by username (null for all)
     * @param ipAddress Filter by IP address (null for all)
     * @param limit Maximum number of entries to return
     * @return List of audit log entries
     */
    public java.util.List<AuditLogEntry> getAuditLog(String action, String username, String ipAddress, int limit) {
        StringBuilder sql = new StringBuilder("SELECT * FROM audit_log WHERE 1=1");
        java.util.List<Object> params = new java.util.ArrayList<>();

        if (action != null && !action.isEmpty()) {
            sql.append(" AND action = ?");
            params.add(action);
        }
        if (username != null && !username.isEmpty()) {
            sql.append(" AND username = ?");
            params.add(username);
        }
        if (ipAddress != null && !ipAddress.isEmpty()) {
            sql.append(" AND ip_address = ?");
            params.add(ipAddress);
        }

        sql.append(" ORDER BY created_at DESC LIMIT ?");
        params.add(limit);

        java.util.List<AuditLogEntry> entries = new java.util.ArrayList<>();

        try (PreparedStatement stmt = connection.prepareStatement(sql.toString())) {
            for (int i = 0; i < params.size(); i++) {
                Object param = params.get(i);
                if (param instanceof String) {
                    stmt.setString(i + 1, (String) param);
                } else if (param instanceof Integer) {
                    stmt.setInt(i + 1, (Integer) param);
                }
            }

            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                AuditLogEntry entry = new AuditLogEntry();
                entry.id = rs.getInt("id");
                entry.action = rs.getString("action");
                entry.username = rs.getString("username");
                entry.ipAddress = rs.getString("ip_address");
                entry.details = rs.getString("details");
                entry.userAgent = rs.getString("user_agent");
                entry.createdAt = rs.getTimestamp("created_at");
                entries.add(entry);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }

        return entries;
    }

    /**
     * Get count of audit events by action type in the last N days
     */
    public java.util.Map<String, Integer> getAuditStats(int days) {
        String sql = """
            SELECT action, COUNT(*) as count
            FROM audit_log
            WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
            GROUP BY action
            ORDER BY count DESC
            """;
        java.util.Map<String, Integer> stats = new java.util.LinkedHashMap<>();

        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, days);
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                stats.put(rs.getString("action"), rs.getInt("count"));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }

        return stats;
    }

    /**
     * Clean up old audit log entries (older than N days)
     * @param days Number of days to keep
     * @return Number of deleted entries
     */
    public int cleanupAuditLog(int days) {
        String sql = "DELETE FROM audit_log WHERE created_at < DATE_SUB(NOW(), INTERVAL ? DAY)";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, days);
            return stmt.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
            return 0;
        }
    }

    /**
     * Get recent login attempts for an IP address
     * @param ipAddress The IP address to check
     * @param minutes Time window in minutes
     * @return Number of failed login attempts
     */
    public int getRecentLoginFailures(String ipAddress, int minutes) {
        String sql = """
            SELECT COUNT(*) FROM audit_log
            WHERE action = 'LOGIN_FAILURE'
            AND ip_address = ?
            AND created_at >= DATE_SUB(NOW(), INTERVAL ? MINUTE)
            """;
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, ipAddress);
            stmt.setInt(2, minutes);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return rs.getInt(1);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return 0;
    }
}
