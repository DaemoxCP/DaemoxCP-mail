package org.mail_panel.database;

import org.mindrot.jbcrypt.BCrypt;

import java.sql.*;
import java.util.logging.Level;
import java.util.logging.Logger;
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
    private static final Logger LOGGER = Logger.getLogger(MailDatabase.class.getName());


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
            connection = DriverManager.getConnection(databaseUrl(), username, password);
            connected = true;
            return true;
        } catch (SQLException e) {
            System.err.println("MySQL not available: " + e.getMessage());
            connected = false;
            return false;
        }
    }

    private String databaseUrl() {
        return String.format(
            "jdbc:mysql://%s:%d/%s?useSSL=true&requireSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC&createDatabaseIfNotExist=true&autoReconnect=true",
            host, port, database
        );
    }

    /**
     * Una connessione tutta per chi la chiede, che la chiude. Serve alle transazioni: la
     * connessione condivisa la usano anche i lavori in background (rapporto, DKIM, MTA-STS), e con
     * l'autocommit spento i loro comandi finirebbero dentro la transazione di un altro.
     */
    private Connection ownConnection() throws SQLException {
        return DriverManager.getConnection(databaseUrl(), username, password);
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
        try (Statement stmt = getConnection().createStatement()) {
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
     * Tutte le tabelle che il pannello crea (createSchema e le migrazioni), piu' quelle di versioni
     * vecchie (virtual_*): le cancella il reset, e nessun'altra del database. Prima le tabelle che
     * puntano ad altre con una chiave esterna, poi quelle a cui si punta.
     */
    static final List<String> PANEL_TABLES = List.of(
        "admin_passkeys", "rspamd_training", "panel_sessions",                // -> panel_admin
        "login_code_email", "login_code_console", "stepup_code", "email_change_code",
        "roundcube_tokens", "auto_responders", "sieve_filters", "forwarding_rules",
        "email_statistics",                                                   // -> mailboxes, domains
        "aliases", "mailboxes",                                               // -> domains
        "dkim_rotation_history", "domains", "cloudflare_accounts",
        "audit_log", "rate_limits", "panel_settings", "installed_components", "panel_admin",
        "virtual_aliases", "virtual_users", "virtual_domains"
    );

    /**
     * Svuota il database del pannello per il reset: cancella tutte le sue tabelle e torna solo se
     * non ne resta nessuna. Restituisce quelle che c'erano.
     *
     * Un solo DROP con tutte le tabelle: MySQL toglie insieme quelle legate da chiavi esterne senza
     * spegnere i controlli, e su InnoDB il comando e' atomico, o le cancella tutte o nessuna. Il
     * vecchio reset le cancellava una alla volta: quelle a cui un'altra puntava (mailboxes, domains,
     * panel_admin) restavano, con i loro dati, e mancavano admin_passkeys, cloudflare_accounts e
     * dkim_rotation_history. Su una connessione tutta sua, perche' un DROP chiude la transazione
     * della connessione su cui gira.
     */
    public List<String> dropAllTables() throws SQLException {
        if (!connected) throw new SQLException("Not connected to MySQL: the reset did not start.");
        try (Connection c = ownConnection()) {
            List<String> before = panelTables(c);
            try (Statement st = c.createStatement()) {
                // Nomi fissi, scritti qui sopra, non input: un DROP non prende parametri.
                st.executeUpdate("DROP TABLE IF EXISTS " + String.join(", ", PANEL_TABLES));
            } catch (SQLException e) {
                String present;
                try {
                    List<String> t = panelTables(c);
                    present = t.isEmpty() ? "none" : String.join(", ", t);
                } catch (SQLException lost) {
                    present = "unknown, MySQL does not answer";
                }
                throw new SQLException("Reset failed: " + e.getMessage()
                        + " Panel tables still present: " + present + ".", e);
            }
            List<String> remain = panelTables(c);
            if (!remain.isEmpty()) {
                throw new SQLException("Reset not complete: these tables remain: " + String.join(", ", remain) + ".");
            }
            return before;
        }
    }

    /** Le tabelle del pannello che ci sono adesso nel database della connessione. */
    private static List<String> panelTables(Connection c) throws SQLException {
        List<String> found = new ArrayList<>();
        try (PreparedStatement ps = c.prepareStatement(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE() ORDER BY table_name");
             ResultSet r = ps.executeQuery()) {
            while (r.next()) {
                String name = r.getString(1);
                if (PANEL_TABLES.contains(name)) found.add(name);
            }
        }
        return found;
    }

    /**
     * Create all tables for the mail panel
     */
    public void createSchema() throws SQLException {
        // ========== PANEL TABLES ==========

        // Admin users table
        // theme: 'auto' = follow browser, 'light' = always light, 'dark' = always dark
        String createPanelAdmin = """
            CREATE TABLE IF NOT EXISTS panel_admin (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) NOT NULL UNIQUE,
                email_enc VARCHAR(512) NULL,
                email_index CHAR(64) CHARACTER SET ascii NULL,
                user_handle VARCHAR(64) CHARACTER SET ascii NULL,
                created_at DATETIME NULL,
                last_login DATETIME NULL,
                active BOOLEAN DEFAULT TRUE,
                role ENUM('superadmin', 'admin', 'operator', 'viewer') DEFAULT 'admin',
                theme VARCHAR(10) DEFAULT 'auto',
                language VARCHAR(5) NULL,
                UNIQUE KEY uq_admin_email_index (email_index),
                UNIQUE KEY uq_admin_user_handle (user_handle)
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
                dkim_public_key TEXT,
                -- DKIM rotation (selector "pending" mentre la chiave attuale resta in dkim_*)
                dkim_pending_selector VARCHAR(50) NULL,
                dkim_pending_private_key TEXT NULL,
                dkim_pending_public_key TEXT NULL,
                dkim_rotation_state VARCHAR(32) NULL,           -- 'pending_dns', 'propagated', 'active_grace', 'completed'
                dkim_rotation_started_at TIMESTAMP NULL,
                dkim_rotation_activated_at TIMESTAMP NULL,
                -- Vecchia chiave conservata durante il grace period (per validare mail in transito)
                dkim_previous_selector VARCHAR(50) NULL,
                dkim_previous_private_key TEXT NULL,
                dkim_previous_public_key TEXT NULL,
                -- Cloudflare automation (zona DNS e id dei record TXT creati via API)
                dkim_dns_zone_id VARCHAR(64) NULL,
                dkim_pending_dns_record_id VARCHAR(64) NULL,
                dkim_previous_dns_record_id VARCHAR(64) NULL,
                -- Account Cloudflare assegnato (NULL = nessuno, rotazione manuale)
                cloudflare_account_id INT NULL,
                -- Rotazione programmata: ogni quanti giorni rigenerare la chiave (0 = off)
                dkim_rotation_interval_days INT NOT NULL DEFAULT 0,
                -- Timestamp ultima rotazione completata con successo (set al key_activated)
                dkim_last_rotation_at TIMESTAMP NULL,
                -- Modalità della rotazione corrente ("automatic"/"manual"), ereditata da tutti gli eventi della catena
                dkim_rotation_mode VARCHAR(16) NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """;

        // Cloudflare accounts table (un account = un token + label informativa)
        String createCfAccounts = """
            CREATE TABLE IF NOT EXISTS cloudflare_accounts (
                id INT AUTO_INCREMENT PRIMARY KEY,
                label VARCHAR(100) NOT NULL,
                email VARCHAR(255) NULL,
                api_token TEXT NOT NULL,
                verified_at TIMESTAMP NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """;

        // DKIM rotation history (audit log: ogni evento del workflow viene registrato)
        String createDkimHistory = """
            CREATE TABLE IF NOT EXISTS dkim_rotation_history (
                id INT AUTO_INCREMENT PRIMARY KEY,
                domain_id INT NOT NULL,
                domain VARCHAR(255) NOT NULL,
                event_type VARCHAR(32) NOT NULL,
                selector VARCHAR(50) NULL,
                mode VARCHAR(16) NULL,
                triggered_by VARCHAR(16) NULL,
                cloudflare_account_id INT NULL,
                cloudflare_account_label VARCHAR(100) NULL,
                success BOOLEAN DEFAULT TRUE,
                message TEXT NULL,
                occurred_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_domain_time (domain_id, occurred_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """;

        // Mailboxes table (virtual users)
        // quota_mb: 0 = unlimited, >0 = limit in MB
        // receive_enabled: false = no-reply account (can only send, not receive)
        String createMailboxes = """
            CREATE TABLE IF NOT EXISTS mailboxes (
                id INT AUTO_INCREMENT PRIMARY KEY,
                domain_id INT NOT NULL,
                email VARCHAR(255) NOT NULL UNIQUE,
                password VARCHAR(255) NOT NULL,
                password_encrypted TEXT NULL,
                password_encrypted_at TIMESTAMP NULL,
                name VARCHAR(255),
                quota_mb INT DEFAULT 1024,
                active BOOLEAN DEFAULT TRUE,
                receive_enabled BOOLEAN DEFAULT TRUE,
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
                user_handle VARCHAR(64) CHARACTER SET ascii NULL,
                rp_id VARCHAR(253) CHARACTER SET ascii NULL,
                created_at DATETIME NULL,
                last_used DATETIME NULL,
                FOREIGN KEY (admin_id) REFERENCES panel_admin(id) ON DELETE CASCADE,
                UNIQUE KEY unique_credential (credential_id(255))
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """;

        try (Statement stmt = getConnection().createStatement()) {
            stmt.execute(createPanelAdmin);
            stmt.execute(createSettings);
            stmt.execute(createComponents);
            stmt.execute(createCfAccounts);
            stmt.execute(createDkimHistory);
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
            for (String t : AUTH_TABLES) stmt.execute(t);
        }
    }

    /**
     * Le tabelle dell'accesso senza password: le sessioni e i codici monouso, una tabella per
     * flusso (accesso via email, accesso dalla console, cambio dell'email, conferma di
     * un'operazione delicata). Nei codici c'e' solo l'fingerprint HMAC, mai il codice; della sessione
     * c'e' solo l'fingerprint SHA-256 del token. Date in UTC, colonne DATETIME.
     */
    private static final List<String> AUTH_TABLES = List.of(
        """
        CREATE TABLE IF NOT EXISTS panel_sessions (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            token_hash CHAR(64) CHARACTER SET ascii NOT NULL,
            admin_id INT NOT NULL,
            ua_hash CHAR(64) CHARACTER SET ascii NOT NULL,
            ua_enc VARCHAR(1024) NULL,
            ip_enc VARCHAR(256) NULL,
            created_at DATETIME NOT NULL,
            last_seen_at DATETIME NOT NULL,
            expires_at DATETIME NOT NULL,
            reauth_at DATETIME NULL,
            UNIQUE KEY uq_session_token (token_hash),
            KEY idx_session_admin (admin_id),
            KEY idx_session_expires (expires_at),
            CONSTRAINT fk_session_admin FOREIGN KEY (admin_id) REFERENCES panel_admin(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """,
        codeTable("login_code_email", ""),
        codeTable("login_code_console", ""),
        codeTable("stepup_code", ""),
        codeTable("email_change_code",
            "target_enc VARCHAR(512) NOT NULL, target_index CHAR(64) CHARACTER SET ascii NOT NULL,")
    );

    private static String codeTable(String name, String extra) {
        return "CREATE TABLE IF NOT EXISTS " + name + " ("
             + "id BIGINT AUTO_INCREMENT PRIMARY KEY, admin_id INT NOT NULL,"
             + " code_hash CHAR(64) CHARACTER SET ascii NOT NULL, " + extra
             + " attempts INT NOT NULL DEFAULT 0, created_at DATETIME NOT NULL, expires_at DATETIME NOT NULL,"
             + " used_at DATETIME NULL, KEY idx_" + name + "_admin (admin_id, expires_at),"
             + " CONSTRAINT fk_" + name + "_admin FOREIGN KEY (admin_id) REFERENCES panel_admin(id) ON DELETE CASCADE"
             + ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";
    }

    /**
     * Da un'installazione con le password a quella senza. Si puo' ripetere: ogni passo guarda prima
     * se serve. Su una connessione sua con il fuso UTC, perche' passare da TIMESTAMP a DATETIME
     * converte con il fuso della sessione, e le date devono restare in UTC.
     *
     *  - via password_hash, totp_secret, totp_enabled, backup_codes: nessun hash nel database;
     *  - email cifrata, indice cieco, user handle delle passkey;
     *  - le passkey sanno a quale user handle e a quale nome (rpId) appartengono;
     *  - le date dell'accesso in DATETIME.
     */
    public void ensurePasswordlessSchema() throws SQLException {
        try (Connection c = ownConnection(); Statement st = c.createStatement()) {
            st.execute("SET time_zone = '+00:00'");
            for (String t : AUTH_TABLES) st.execute(t);
            for (String col : List.of("password_hash", "totp_secret", "totp_enabled", "backup_codes")) {
                if (columnType(c, "panel_admin", col) != null) {
                    // Nome fisso, preso dall'elenco qui sopra: un ALTER non prende parametri.
                    st.executeUpdate("ALTER TABLE panel_admin DROP COLUMN " + col);
                    LOGGER.info("Removed panel_admin." + col);
                }
            }
            if (columnType(c, "panel_admin", "email_enc") == null)
                st.executeUpdate("ALTER TABLE panel_admin ADD COLUMN email_enc VARCHAR(512) NULL");
            if (columnType(c, "panel_admin", "email_index") == null)
                st.executeUpdate("ALTER TABLE panel_admin ADD COLUMN email_index CHAR(64) CHARACTER SET ascii NULL,"
                        + " ADD UNIQUE KEY uq_admin_email_index (email_index)");
            if (columnType(c, "panel_admin", "user_handle") == null)
                st.executeUpdate("ALTER TABLE panel_admin ADD COLUMN user_handle VARCHAR(64) CHARACTER SET ascii NULL,"
                        + " ADD UNIQUE KEY uq_admin_user_handle (user_handle)");
            if ("timestamp".equals(columnType(c, "panel_admin", "created_at")))
                st.executeUpdate("ALTER TABLE panel_admin MODIFY created_at DATETIME NULL");
            if ("timestamp".equals(columnType(c, "panel_admin", "last_login")))
                st.executeUpdate("ALTER TABLE panel_admin MODIFY last_login DATETIME NULL");
            if (columnType(c, "admin_passkeys", "user_handle") == null)
                st.executeUpdate("ALTER TABLE admin_passkeys ADD COLUMN user_handle VARCHAR(64) CHARACTER SET ascii NULL");
            if (columnType(c, "admin_passkeys", "rp_id") == null)
                st.executeUpdate("ALTER TABLE admin_passkeys ADD COLUMN rp_id VARCHAR(253) CHARACTER SET ascii NULL");
            if ("timestamp".equals(columnType(c, "admin_passkeys", "created_at")))
                st.executeUpdate("ALTER TABLE admin_passkeys MODIFY created_at DATETIME NULL");
            if ("timestamp".equals(columnType(c, "admin_passkeys", "last_used")))
                st.executeUpdate("ALTER TABLE admin_passkeys MODIFY last_used DATETIME NULL");
        }
    }

    /** Il tipo di una colonna (minuscolo, "datetime", "varchar"...) o null se la colonna non c'e'. */
    private static String columnType(Connection c, String table, String column) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement("SELECT DATA_TYPE FROM information_schema.columns "
                + "WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ?")) {
            ps.setString(1, table);
            ps.setString(2, column);
            try (ResultSet r = ps.executeQuery()) {
                return r.next() ? r.getString(1).toLowerCase(java.util.Locale.ROOT) : null;
            }
        }
    }

    // ========== ADMIN ==========

    /**
     * Check if any admin exists
     */
    public boolean hasAdminUser() {
        String sql = "SELECT 1 FROM panel_admin WHERE active = TRUE LIMIT 1";
        try (Statement stmt = getConnection().createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            return rs.next();
        } catch (SQLException e) {
            return false;
        }
    }

    // ========== THEME MANAGEMENT ==========

    /**
     * Get admin theme preference
     * @return 'auto', 'light', or 'dark'
     */
    public String getAdminTheme(String username) {
        String sql = "SELECT theme FROM panel_admin WHERE username = ?";
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setString(1, username);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                String theme = rs.getString("theme");
                return (theme != null && !theme.isEmpty()) ? theme : "auto";
            }
        } catch (SQLException e) {
            System.err.println("Error getting theme: " + e.getMessage());
        }
        return "auto";
    }

    /**
     * Set admin theme preference
     */
    public boolean setAdminTheme(String username, String theme) {
        // Validate theme value
        if (!theme.equals("auto") && !theme.equals("light") && !theme.equals("dark")) {
            theme = "auto";
        }
        String sql = "UPDATE panel_admin SET theme = ? WHERE username = ?";
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setString(1, theme);
            stmt.setString(2, username);
            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            System.err.println("Error setting theme: " + e.getMessage());
            return false;
        }
    }

    /**
     * La lingua scelta dall'amministratore ("it" o "en"), o null se non l'ha mai scelta: allora
     * vale quella del browser. Lo segue su ogni browser, come il tema.
     */
    public String getAdminLanguage(String username) {
        if (username == null) return null;
        String sql = "SELECT language FROM panel_admin WHERE username = ?";
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setString(1, username);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    String lang = rs.getString("language");
                    return "it".equals(lang) || "en".equals(lang) ? lang : null;
                }
            }
        } catch (SQLException e) {
            LOGGER.log(Level.WARNING, "Cannot read the admin language", e);
        }
        return null;
    }

    /** Salva la lingua dell'amministratore: solo "it" o "en". */
    public boolean setAdminLanguage(String username, String lang) {
        if (username == null || !("it".equals(lang) || "en".equals(lang))) return false;
        String sql = "UPDATE panel_admin SET language = ? WHERE username = ?";
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setString(1, lang);
            stmt.setString(2, username);
            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            LOGGER.log(Level.WARNING, "Cannot save the admin language", e);
            return false;
        }
    }

    /** La colonna della lingua in panel_admin, per le installazioni di prima (NULL: mai scelta). */
    public void ensureLanguageColumn() {
        String check = "SELECT COUNT(*) FROM information_schema.columns "
                     + "WHERE table_schema = DATABASE() AND table_name = 'panel_admin' AND column_name = 'language'";
        try (Statement stmt = getConnection().createStatement(); ResultSet rs = stmt.executeQuery(check)) {
            if (rs.next() && rs.getInt(1) == 0) {
                try (Statement alter = getConnection().createStatement()) {
                    alter.executeUpdate("ALTER TABLE panel_admin ADD COLUMN language VARCHAR(5) NULL");
                }
                LOGGER.info("Added language column to panel_admin");
            }
        } catch (SQLException e) {
            LOGGER.log(Level.WARNING, "Cannot add the language column", e);
        }
    }

    /**
     * Ensure DKIM rotation columns exist in domains table (for database migration).
     * Aggiunge in modo idempotente i campi dkim_pending_*, dkim_previous_*,
     * dkim_rotation_state, dkim_rotation_started_at, dkim_rotation_activated_at.
     */
    public void ensureDkimRotationColumns() {
        String[][] cols = {
            {"dkim_pending_selector",       "VARCHAR(50) NULL"},
            {"dkim_pending_private_key",    "TEXT NULL"},
            {"dkim_pending_public_key",     "TEXT NULL"},
            {"dkim_rotation_state",         "VARCHAR(32) NULL"},
            {"dkim_rotation_started_at",    "TIMESTAMP NULL"},
            {"dkim_rotation_activated_at",  "TIMESTAMP NULL"},
            {"dkim_previous_selector",      "VARCHAR(50) NULL"},
            {"dkim_previous_private_key",   "TEXT NULL"},
            {"dkim_previous_public_key",    "TEXT NULL"},
            // Cloudflare automation: zone + ID dei record TXT, per cancellarli
            {"dkim_dns_zone_id",            "VARCHAR(64) NULL"},
            {"dkim_pending_dns_record_id", "VARCHAR(64) NULL"},
            {"dkim_previous_dns_record_id","VARCHAR(64) NULL"},
            // Rotazione programmata
            {"dkim_rotation_interval_days","INT NOT NULL DEFAULT 0"},
            {"dkim_last_rotation_at",      "TIMESTAMP NULL"},
            // Modalità rotazione (ereditata da tutti gli eventi della catena)
            {"dkim_rotation_mode",         "VARCHAR(16) NULL"}
        };
        try (Statement stmt = getConnection().createStatement()) {
            for (String[] col : cols) {
                String name = col[0];
                String type = col[1];
                ResultSet rs = stmt.executeQuery(
                    "SELECT COUNT(*) FROM information_schema.columns " +
                    "WHERE table_schema = DATABASE() AND table_name = 'domains' AND column_name = '" + name + "'"
                );
                if (rs.next() && rs.getInt(1) == 0) {
                    stmt.executeUpdate("ALTER TABLE domains ADD COLUMN " + name + " " + type);
                    System.out.println("Added " + name + " column to domains table");
                }
            }
        } catch (SQLException e) {
            System.err.println("Error ensuring DKIM rotation columns: " + e.getMessage());
        }
    }

    /**
     * Ensure cloudflare_accounts table + domains.cloudflare_account_id column exist.
     * Migra anche il token legacy (panel_settings.cloudflare_api_token) creando un
     * account "Account principale" e legandolo a tutti i domini esistenti.
     */
    public void ensureCloudflareAccountsSchema() {
        try (Statement stmt = getConnection().createStatement()) {
            // 1) tabella cloudflare_accounts
            stmt.execute("CREATE TABLE IF NOT EXISTS cloudflare_accounts (" +
                "id INT AUTO_INCREMENT PRIMARY KEY, " +
                "label VARCHAR(100) NOT NULL, " +
                "email VARCHAR(255) NULL, " +
                "api_token TEXT NOT NULL, " +
                "verified_at TIMESTAMP NULL, " +
                "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP" +
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

            // 2) colonna domains.cloudflare_account_id
            ResultSet rs = stmt.executeQuery(
                "SELECT COUNT(*) FROM information_schema.columns " +
                "WHERE table_schema = DATABASE() AND table_name = 'domains' AND column_name = 'cloudflare_account_id'"
            );
            if (rs.next() && rs.getInt(1) == 0) {
                stmt.executeUpdate("ALTER TABLE domains ADD COLUMN cloudflare_account_id INT NULL");
                System.out.println("Added cloudflare_account_id column to domains table");
            }

            // 3) migrazione token legacy
            String legacyToken = getSetting("cloudflare_api_token", "");
            String legacyEnabled = getSetting("cloudflare_enabled", "0");
            if (!legacyToken.isEmpty() && "1".equals(legacyEnabled)) {
                // Verifica che non ci siano già account: se la tabella è vuota, importa
                ResultSet cnt = stmt.executeQuery("SELECT COUNT(*) FROM cloudflare_accounts");
                if (cnt.next() && cnt.getInt(1) == 0) {
                    try (PreparedStatement ins = getConnection().prepareStatement(
                        "INSERT INTO cloudflare_accounts (label, email, api_token, verified_at) VALUES (?, NULL, ?, CURRENT_TIMESTAMP)",
                        Statement.RETURN_GENERATED_KEYS)) {
                        ins.setString(1, "Account principale");
                        ins.setString(2, legacyToken);
                        ins.executeUpdate();
                        ResultSet gk = ins.getGeneratedKeys();
                        if (gk.next()) {
                            int newId = gk.getInt(1);
                            // Lega tutti i domini esistenti a questo account (preserva il comportamento)
                            try (PreparedStatement upd = getConnection().prepareStatement(
                                "UPDATE domains SET cloudflare_account_id = ? WHERE cloudflare_account_id IS NULL")) {
                                upd.setInt(1, newId);
                                int affected = upd.executeUpdate();
                                System.out.println("Migrated legacy Cloudflare token to account '" + newId
                                    + "', assigned to " + affected + " domain(s)");
                            }
                        }
                    }
                    // Cancella il settings legacy così non viene più riusato
                    deleteSetting("cloudflare_api_token");
                    deleteSetting("cloudflare_enabled");
                }
            }
        } catch (SQLException e) {
            System.err.println("Error ensuring cloudflare accounts schema: " + e.getMessage());
        }
    }

    /**
     * Ensure dkim_rotation_history table exists (idempotente).
     */
    public void ensureDkimRotationHistoryTable() {
        try (Statement stmt = getConnection().createStatement()) {
            stmt.execute("CREATE TABLE IF NOT EXISTS dkim_rotation_history (" +
                "id INT AUTO_INCREMENT PRIMARY KEY, " +
                "domain_id INT NOT NULL, " +
                "domain VARCHAR(255) NOT NULL, " +
                "event_type VARCHAR(32) NOT NULL, " +
                "selector VARCHAR(50) NULL, " +
                "previous_selector VARCHAR(50) NULL, " +
                "mode VARCHAR(16) NULL, " +
                "triggered_by VARCHAR(16) NULL, " +
                "cloudflare_account_id INT NULL, " +
                "cloudflare_account_label VARCHAR(100) NULL, " +
                "success BOOLEAN DEFAULT TRUE, " +
                "message TEXT NULL, " +
                "occurred_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, " +
                "INDEX idx_domain_time (domain_id, occurred_at), " +
                "INDEX idx_prev_selector (domain_id, previous_selector)" +
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
            // Migrazione: aggiungi triggered_by se la tabella esiste già senza quel campo
            ResultSet rs = stmt.executeQuery(
                "SELECT COUNT(*) FROM information_schema.columns " +
                "WHERE table_schema = DATABASE() AND table_name = 'dkim_rotation_history' AND column_name = 'triggered_by'"
            );
            if (rs.next() && rs.getInt(1) == 0) {
                stmt.executeUpdate("ALTER TABLE dkim_rotation_history ADD COLUMN triggered_by VARCHAR(16) NULL AFTER mode");
                System.out.println("Added triggered_by column to dkim_rotation_history table");
            }
            // Migrazione: aggiungi previous_selector se la tabella esiste già senza quel campo
            ResultSet rs2 = stmt.executeQuery(
                "SELECT COUNT(*) FROM information_schema.columns " +
                "WHERE table_schema = DATABASE() AND table_name = 'dkim_rotation_history' AND column_name = 'previous_selector'"
            );
            if (rs2.next() && rs2.getInt(1) == 0) {
                stmt.executeUpdate("ALTER TABLE dkim_rotation_history ADD COLUMN previous_selector VARCHAR(50) NULL AFTER selector");
                stmt.executeUpdate("ALTER TABLE dkim_rotation_history ADD INDEX idx_prev_selector (domain_id, previous_selector)");
                System.out.println("Added previous_selector column + index to dkim_rotation_history table");
            }
        } catch (SQLException e) {
            System.err.println("Error ensuring dkim_rotation_history table: " + e.getMessage());
        }
    }

    /**
     * Registra un evento del workflow di rotazione DKIM.
     * @param triggeredBy "user" se avviato cliccando un bottone, "scheduler" se dal timer automatico,
     *                    null per eventi non avviati esplicitamente (verifiche, propagazione, ecc.)
     */
    public void logDkimRotationEvent(int domainId, String domain, String eventType,
                                      String selector, String mode, String triggeredBy,
                                      Integer cloudflareAccountId, String cloudflareAccountLabel,
                                      boolean success, String message) {
        logDkimRotationEvent(domainId, domain, eventType, selector, null, mode, triggeredBy,
                             cloudflareAccountId, cloudflareAccountLabel, success, message);
    }

    public void logDkimRotationEvent(int domainId, String domain, String eventType,
                                      String selector, String previousSelector,
                                      String mode, String triggeredBy,
                                      Integer cloudflareAccountId, String cloudflareAccountLabel,
                                      boolean success, String message) {
        String sql = "INSERT INTO dkim_rotation_history " +
                     "(domain_id, domain, event_type, selector, previous_selector, mode, triggered_by, cloudflare_account_id, " +
                     "cloudflare_account_label, success, message, occurred_at) " +
                     "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setInt(1, domainId);
            stmt.setString(2, domain == null ? "" : domain);
            stmt.setString(3, eventType);
            if (selector == null) stmt.setNull(4, Types.VARCHAR); else stmt.setString(4, selector);
            if (previousSelector == null) stmt.setNull(5, Types.VARCHAR); else stmt.setString(5, previousSelector);
            if (mode == null) stmt.setNull(6, Types.VARCHAR); else stmt.setString(6, mode);
            if (triggeredBy == null) stmt.setNull(7, Types.VARCHAR); else stmt.setString(7, triggeredBy);
            if (cloudflareAccountId == null) stmt.setNull(8, Types.INTEGER); else stmt.setInt(8, cloudflareAccountId);
            if (cloudflareAccountLabel == null) stmt.setNull(9, Types.VARCHAR); else stmt.setString(9, cloudflareAccountLabel);
            stmt.setBoolean(10, success);
            if (message == null) stmt.setNull(11, Types.LONGVARCHAR); else stmt.setString(11, message);
            stmt.setTimestamp(12, java.sql.Timestamp.from(java.time.Instant.now()));
            stmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("Failed to log DKIM rotation event: " + e.getMessage());
        }
    }

    /**
     * Trova il timestamp più recente di disattivazione di un selector per un dominio.
     * Un selector è considerato "disattivato" al momento di un evento key_activated dove
     * compare come previous_selector (cioè quando una nuova chiave l'ha sostituito).
     *
     * Ritorna null se il selector non è mai stato registrato come disattivato (probabilmente
     * non era mai stato il selector attivo nel pannello).
     */
    public Timestamp findSelectorDeactivationTime(int domainId, String selector) throws SQLException {
        String sql = "SELECT occurred_at FROM dkim_rotation_history " +
                     "WHERE domain_id = ? AND event_type = 'key_activated' AND previous_selector = ? " +
                     "ORDER BY occurred_at DESC, id DESC LIMIT 1";
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setInt(1, domainId);
            stmt.setString(2, selector);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) return rs.getTimestamp("occurred_at");
            }
        }
        return null;
    }

    /**
     * Storico eventi di rotazione DKIM per un dominio, dal più recente.
     */
    public List<DkimRotationEvent> getDkimRotationHistory(int domainId, int limit) throws SQLException {
        List<DkimRotationEvent> result = new ArrayList<>();
        String sql = "SELECT * FROM dkim_rotation_history WHERE domain_id = ? " +
                     "ORDER BY occurred_at DESC, id DESC LIMIT ?";
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setInt(1, domainId);
            stmt.setInt(2, Math.max(1, Math.min(500, limit)));
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    DkimRotationEvent e = new DkimRotationEvent();
                    e.id = rs.getInt("id");
                    e.domainId = rs.getInt("domain_id");
                    e.domain = rs.getString("domain");
                    e.eventType = rs.getString("event_type");
                    e.selector = rs.getString("selector");
                    try { e.previousSelector = rs.getString("previous_selector"); } catch (SQLException ignore) {}
                    e.mode = rs.getString("mode");
                    try { e.triggeredBy = rs.getString("triggered_by"); } catch (SQLException ignore) {}
                    int cfId = rs.getInt("cloudflare_account_id");
                    e.cloudflareAccountId = rs.wasNull() ? 0 : cfId;
                    e.cloudflareAccountLabel = rs.getString("cloudflare_account_label");
                    e.success = rs.getBoolean("success");
                    e.message = rs.getString("message");
                    e.occurredAt = rs.getTimestamp("occurred_at");
                    result.add(e);
                }
            }
        }
        return result;
    }

    public static class DkimRotationEvent {
        public int id;
        public int domainId;
        public String domain;
        public String eventType;
        public String selector;
        public String previousSelector;  // valorizzato per key_activated (vecchio selector che è stato rimpiazzato)
        public String mode;
        public String triggeredBy;   // "user" / "scheduler" / null
        public int cloudflareAccountId;
        public String cloudflareAccountLabel;
        public boolean success;
        public String message;
        public Timestamp occurredAt;
    }

    /**
     * Ensure theme column exists (for database migration)
     */
    public void ensureThemeColumn() {
        try (Statement stmt = getConnection().createStatement()) {
            ResultSet rs = stmt.executeQuery(
                "SELECT COUNT(*) FROM information_schema.columns " +
                "WHERE table_schema = DATABASE() AND table_name = 'panel_admin' AND column_name = 'theme'"
            );
            if (rs.next() && rs.getInt(1) == 0) {
                stmt.executeUpdate("ALTER TABLE panel_admin ADD COLUMN theme VARCHAR(10) DEFAULT 'auto'");
                System.out.println("Added theme column to panel_admin table");
            }
        } catch (SQLException e) {
            System.err.println("Error ensuring theme column: " + e.getMessage());
        }
    }

    // ========== SETTINGS MANAGEMENT ==========

    public String getSetting(String key, String defaultValue) {
        String sql = "SELECT setting_value FROM panel_settings WHERE setting_key = ?";
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
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
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setString(1, key);
            stmt.setString(2, value);
            stmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("Failed to set setting: " + e.getMessage());
        }
    }

    public void deleteSetting(String key) {
        String sql = "DELETE FROM panel_settings WHERE setting_key = ?";
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setString(1, key);
            stmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("Failed to delete setting: " + e.getMessage());
        }
    }

    // ========== CLOUDFLARE ACCOUNTS MANAGEMENT ==========

    public int addCloudflareAccount(String label, String email, String apiToken) throws SQLException {
        String sql = "INSERT INTO cloudflare_accounts (label, email, api_token, verified_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)";
        try (PreparedStatement stmt = getConnection().prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            stmt.setString(1, label);
            if (email == null || email.isEmpty()) stmt.setNull(2, Types.VARCHAR); else stmt.setString(2, email);
            stmt.setString(3, apiToken);
            stmt.executeUpdate();
            try (ResultSet rs = stmt.getGeneratedKeys()) {
                if (rs.next()) return rs.getInt(1);
            }
        }
        return -1;
    }

    public boolean updateCloudflareAccount(int id, String label, String email) throws SQLException {
        String sql = "UPDATE cloudflare_accounts SET label = ?, email = ? WHERE id = ?";
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setString(1, label);
            if (email == null || email.isEmpty()) stmt.setNull(2, Types.VARCHAR); else stmt.setString(2, email);
            stmt.setInt(3, id);
            return stmt.executeUpdate() > 0;
        }
    }

    public boolean updateCloudflareAccountToken(int id, String newToken) throws SQLException {
        String sql = "UPDATE cloudflare_accounts SET api_token = ?, verified_at = CURRENT_TIMESTAMP WHERE id = ?";
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setString(1, newToken);
            stmt.setInt(2, id);
            return stmt.executeUpdate() > 0;
        }
    }

    public boolean deleteCloudflareAccount(int id) throws SQLException {
        // Prima disassocia i domini, poi cancella l'account
        try (PreparedStatement upd = getConnection().prepareStatement(
            "UPDATE domains SET cloudflare_account_id = NULL WHERE cloudflare_account_id = ?")) {
            upd.setInt(1, id);
            upd.executeUpdate();
        }
        try (PreparedStatement stmt = getConnection().prepareStatement(
            "DELETE FROM cloudflare_accounts WHERE id = ?")) {
            stmt.setInt(1, id);
            return stmt.executeUpdate() > 0;
        }
    }

    public CloudflareAccount getCloudflareAccount(int id) throws SQLException {
        String sql = "SELECT * FROM cloudflare_accounts WHERE id = ?";
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setInt(1, id);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) return mapCloudflareAccount(rs);
            }
        }
        return null;
    }

    public List<CloudflareAccount> listCloudflareAccounts() throws SQLException {
        List<CloudflareAccount> result = new ArrayList<>();
        try (PreparedStatement stmt = getConnection().prepareStatement(
            "SELECT * FROM cloudflare_accounts ORDER BY id ASC");
             ResultSet rs = stmt.executeQuery()) {
            while (rs.next()) result.add(mapCloudflareAccount(rs));
        }
        return result;
    }

    /** Ritorna l'account CF assegnato a un dominio, o null. */
    public CloudflareAccount getCloudflareAccountForDomain(int domainId) throws SQLException {
        String sql = "SELECT c.* FROM cloudflare_accounts c " +
                     "INNER JOIN domains d ON d.cloudflare_account_id = c.id " +
                     "WHERE d.id = ?";
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setInt(1, domainId);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) return mapCloudflareAccount(rs);
            }
        }
        return null;
    }

    /** Assegna (o disassegna passando 0/-1) un account a un dominio. */
    public boolean assignCloudflareAccountToDomain(int domainId, int accountId) throws SQLException {
        String sql = "UPDATE domains SET cloudflare_account_id = ? WHERE id = ?";
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            if (accountId <= 0) stmt.setNull(1, Types.INTEGER);
            else                stmt.setInt(1, accountId);
            stmt.setInt(2, domainId);
            return stmt.executeUpdate() > 0;
        }
    }

    private CloudflareAccount mapCloudflareAccount(ResultSet rs) throws SQLException {
        CloudflareAccount a = new CloudflareAccount();
        a.id = rs.getInt("id");
        a.label = rs.getString("label");
        a.email = rs.getString("email");
        a.apiToken = rs.getString("api_token");
        a.verifiedAt = rs.getTimestamp("verified_at");
        a.createdAt = rs.getTimestamp("created_at");
        return a;
    }

    public static class CloudflareAccount {
        public int id;
        public String label;
        public String email;
        public String apiToken;
        public Timestamp verifiedAt;
        public Timestamp createdAt;
    }

    // ========== COMPONENT MANAGEMENT ==========

    public boolean isComponentInstalled(String componentName) {
        String sql = "SELECT 1 FROM installed_components WHERE component_name = ? AND status = 'installed'";
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
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
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setString(1, componentName);
            stmt.setString(2, version);
            stmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("Failed to mark component installed: " + e.getMessage());
        }
    }

    public void markComponentUninstalled(String componentName) {
        String sql = "UPDATE installed_components SET status = 'uninstalled' WHERE component_name = ?";
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setString(1, componentName);
            stmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("Failed to mark component uninstalled: " + e.getMessage());
        }
    }

    public String getInstalledComponentsJson() {
        StringBuilder json = new StringBuilder("[");
        String sql = "SELECT component_name, version, installed_at FROM installed_components WHERE status = 'installed'";
        try (Statement stmt = getConnection().createStatement();
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
        try (PreparedStatement stmt = getConnection().prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
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
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setInt(1, domainId);
            return stmt.executeUpdate() > 0;
            // Postfix uses MySQL directly - no file sync needed
        }
    }

    public boolean updateDomainStatus(int domainId, boolean active) throws SQLException {
        String sql = "UPDATE domains SET active = ? WHERE id = ?";
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setBoolean(1, active);
            stmt.setInt(2, domainId);
            return stmt.executeUpdate() > 0;
            // Postfix uses MySQL directly - no file sync needed
        }
    }

    public boolean updateDomainDescription(int domainId, String description) throws SQLException {
        String sql = "UPDATE domains SET description = ? WHERE id = ?";
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setString(1, description);
            stmt.setInt(2, domainId);
            return stmt.executeUpdate() > 0;
        }
    }

    public Domain getDomain(int domainId) throws SQLException {
        String sql = "SELECT * FROM domains WHERE id = ?";
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
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
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
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
        try (Statement stmt = getConnection().createStatement();
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
        // Pending rotation
        d.dkimPendingSelector = rs.getString("dkim_pending_selector");
        d.dkimPendingPrivateKey = rs.getString("dkim_pending_private_key");
        d.dkimPendingPublicKey = rs.getString("dkim_pending_public_key");
        d.dkimRotationState = rs.getString("dkim_rotation_state");
        d.dkimRotationStartedAt = rs.getTimestamp("dkim_rotation_started_at");
        d.dkimRotationActivatedAt = rs.getTimestamp("dkim_rotation_activated_at");
        // Previous key (grace period)
        d.dkimPreviousSelector = rs.getString("dkim_previous_selector");
        d.dkimPreviousPrivateKey = rs.getString("dkim_previous_private_key");
        d.dkimPreviousPublicKey = rs.getString("dkim_previous_public_key");
        // Cloudflare automation (può non esistere su DB legacy se ensureDkimRotationColumns non è ancora girato)
        try { d.dkimDnsZoneId            = rs.getString("dkim_dns_zone_id"); } catch (SQLException ignore) {}
        try { d.dkimPendingDnsRecordId   = rs.getString("dkim_pending_dns_record_id"); } catch (SQLException ignore) {}
        try { d.dkimPreviousDnsRecordId  = rs.getString("dkim_previous_dns_record_id"); } catch (SQLException ignore) {}
        try {
            int cfId = rs.getInt("cloudflare_account_id");
            d.cloudflareAccountId = rs.wasNull() ? 0 : cfId;
        } catch (SQLException ignore) {}
        try { d.dkimRotationIntervalDays = rs.getInt("dkim_rotation_interval_days"); } catch (SQLException ignore) {}
        try { d.dkimLastRotationAt       = rs.getTimestamp("dkim_last_rotation_at"); } catch (SQLException ignore) {}
        try { d.dkimRotationMode         = rs.getString("dkim_rotation_mode"); } catch (SQLException ignore) {}
        return d;
    }

    public void setDkim(int domainId, String selector, String privateKey, String publicKey) throws SQLException {
        String sql = "UPDATE domains SET dkim_selector = ?, dkim_private_key = ?, dkim_public_key = ? WHERE id = ?";
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setString(1, selector);
            stmt.setString(2, privateKey);
            stmt.setString(3, publicKey);
            stmt.setInt(4, domainId);
            stmt.executeUpdate();
        }
    }

    // ========== DKIM ROTATION ==========

    /**
     * Salva una chiave DKIM "pending" (nuovo selector + chiavi) e imposta lo stato di rotazione.
     * Lo stato iniziale è solitamente "pending_dns" (utente deve aggiungere il TXT in DNS).
     */
    public void setDkimPending(int domainId, String pendingSelector, String pendingPrivateKey,
                                String pendingPublicKey, String state) throws SQLException {
        setDkimPending(domainId, pendingSelector, pendingPrivateKey, pendingPublicKey, state, null);
    }

    public void setDkimPending(int domainId, String pendingSelector, String pendingPrivateKey,
                                String pendingPublicKey, String state, String rotationMode) throws SQLException {
        String sql = "UPDATE domains SET dkim_pending_selector = ?, dkim_pending_private_key = ?, " +
                     "dkim_pending_public_key = ?, dkim_rotation_state = ?, dkim_rotation_mode = ?, " +
                     "dkim_rotation_started_at = ?, dkim_rotation_activated_at = NULL " +
                     "WHERE id = ?";
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setString(1, pendingSelector);
            stmt.setString(2, pendingPrivateKey);
            stmt.setString(3, pendingPublicKey);
            stmt.setString(4, state);
            if (rotationMode == null) stmt.setNull(5, Types.VARCHAR); else stmt.setString(5, rotationMode);
            stmt.setTimestamp(6, java.sql.Timestamp.from(java.time.Instant.now()));
            stmt.setInt(7, domainId);
            stmt.executeUpdate();
        }
    }

    /**
     * Aggiorna solo lo stato della rotazione (es. da "pending_dns" a "propagated").
     */
    public void setDkimRotationState(int domainId, String state) throws SQLException {
        String sql = "UPDATE domains SET dkim_rotation_state = ? WHERE id = ?";
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setString(1, state);
            stmt.setInt(2, domainId);
            stmt.executeUpdate();
        }
    }

    /**
     * Promuove la chiave "pending" a "attiva":
     *  - attuale (dkim_*) → previous (dkim_previous_*)
     *  - pending (dkim_pending_*) → attuale (dkim_*)
     *  - pending campi puliti
     *  - stato → "active_grace"
     *  - dkim_rotation_activated_at = NOW
     */
    public void promotePendingToActive(int domainId) throws SQLException {
        String sql = "UPDATE domains SET " +
                     "dkim_previous_selector = dkim_selector, " +
                     "dkim_previous_private_key = dkim_private_key, " +
                     "dkim_previous_public_key = dkim_public_key, " +
                     "dkim_previous_dns_record_id = NULL, " + // record DNS della "vecchia" chiave attuale di solito NON è stato creato via CF
                     "dkim_selector = dkim_pending_selector, " +
                     "dkim_private_key = dkim_pending_private_key, " +
                     "dkim_public_key = dkim_pending_public_key, " +
                     "dkim_pending_selector = NULL, " +
                     "dkim_pending_private_key = NULL, " +
                     "dkim_pending_public_key = NULL, " +
                     // pending_dns_record_id ora rappresenta il record DEL NUOVO selector attivo,
                     // lo conserviamo come "current dns record id" muovendolo... ma non abbiamo un
                     // campo "current": lo lasciamo in pending_dns_record_id azzerandolo (la chiave
                     // attiva è già pubblicata in DNS, non ci serve più l'id finché non si rifa
                     // un'altra rotazione).
                     "dkim_pending_dns_record_id = NULL, " +
                     "dkim_rotation_state = 'active_grace', " +
                     "dkim_rotation_activated_at = ? " +
                     "WHERE id = ?";
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setTimestamp(1, java.sql.Timestamp.from(java.time.Instant.now()));
            stmt.setInt(2, domainId);
            stmt.executeUpdate();
        }
    }

    /**
     * Salva i metadati Cloudflare del record TXT pending (zone + record id),
     * così possiamo cancellarlo via API se la rotazione viene annullata o completata.
     */
    public void setDkimPendingCloudflareIds(int domainId, String zoneId, String recordId) throws SQLException {
        String sql = "UPDATE domains SET dkim_dns_zone_id = ?, dkim_pending_dns_record_id = ? WHERE id = ?";
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setString(1, zoneId);
            stmt.setString(2, recordId);
            stmt.setInt(3, domainId);
            stmt.executeUpdate();
        }
    }

    /**
     * Annulla una rotazione in corso (cancella la pending key senza promuoverla).
     */
    public void clearDkimPending(int domainId) throws SQLException {
        String sql = "UPDATE domains SET dkim_pending_selector = NULL, dkim_pending_private_key = NULL, " +
                     "dkim_pending_public_key = NULL, dkim_rotation_state = NULL, dkim_rotation_mode = NULL, " +
                     "dkim_rotation_started_at = NULL, dkim_rotation_activated_at = NULL " +
                     "WHERE id = ?";
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setInt(1, domainId);
            stmt.executeUpdate();
        }
    }

    /**
     * Completa la rotazione: rimuove la previous key e azzera lo stato di rotazione.
     * Dopo questa chiamata l'utente può rimuovere il vecchio record _domainkey TXT dal DNS.
     */
    public void clearDkimPrevious(int domainId) throws SQLException {
        String sql = "UPDATE domains SET dkim_previous_selector = NULL, dkim_previous_private_key = NULL, " +
                     "dkim_previous_public_key = NULL, dkim_rotation_state = NULL, dkim_rotation_mode = NULL, " +
                     "dkim_rotation_started_at = NULL, dkim_rotation_activated_at = NULL " +
                     "WHERE id = ?";
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setInt(1, domainId);
            stmt.executeUpdate();
        }
    }

    /**
     * Imposta l'intervallo di rotazione programmata (in giorni). 0 = disattivato.
     */
    public void setDkimRotationInterval(int domainId, int days) throws SQLException {
        String sql = "UPDATE domains SET dkim_rotation_interval_days = ? WHERE id = ?";
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setInt(1, Math.max(0, days));
            stmt.setInt(2, domainId);
            stmt.executeUpdate();
        }
    }

    /**
     * Aggiorna il timestamp dell'ultima rotazione (chiamato all'attivazione della chiave).
     * Usa Java Instant.now() (UTC, JVM clock) anziché MySQL CURRENT_TIMESTAMP per evitare
     * ambiguità di timezone tra MySQL session, JDBC e JVM.
     */
    public void markDkimRotationActivated(int domainId) throws SQLException {
        String sql = "UPDATE domains SET dkim_last_rotation_at = ? WHERE id = ?";
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setTimestamp(1, java.sql.Timestamp.from(java.time.Instant.now()));
            stmt.setInt(2, domainId);
            stmt.executeUpdate();
        }
    }

    /**
     * Forza il timestamp dell'ultima rotazione a una data specifica (epoch ms).
     * Utile per correggere valori "fossili" memorizzati prima del fix timezone.
     */
    public void setDkimLastRotationAtMs(int domainId, long epochMs) throws SQLException {
        String sql = "UPDATE domains SET dkim_last_rotation_at = ? WHERE id = ?";
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setTimestamp(1, java.sql.Timestamp.from(java.time.Instant.ofEpochMilli(epochMs)));
            stmt.setInt(2, domainId);
            stmt.executeUpdate();
        }
    }

    /**
     * Cancella il timestamp dell'ultima rotazione (NULL).
     * L'UI lo mostrerà come "Mai effettuata".
     */
    public void clearDkimLastRotation(int domainId) throws SQLException {
        String sql = "UPDATE domains SET dkim_last_rotation_at = NULL WHERE id = ?";
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setInt(1, domainId);
            stmt.executeUpdate();
        }
    }

    /**
     * Domini con rotazione programmata attiva (intervallo > 0).
     */
    public List<Domain> getDomainsWithRotationSchedule() throws SQLException {
        List<Domain> result = new ArrayList<>();
        String sql = "SELECT * FROM domains WHERE dkim_rotation_interval_days > 0";
        try (PreparedStatement stmt = getConnection().prepareStatement(sql);
             ResultSet rs = stmt.executeQuery()) {
            while (rs.next()) result.add(mapDomain(rs));
        }
        return result;
    }

    /**
     * Ritorna tutti i domini con una rotazione DKIM in corso
     * (stato non null), per i task di background.
     */
    public List<Domain> getDomainsInRotation() throws SQLException {
        List<Domain> result = new ArrayList<>();
        String sql = "SELECT * FROM domains WHERE dkim_rotation_state IS NOT NULL";
        try (PreparedStatement stmt = getConnection().prepareStatement(sql);
             ResultSet rs = stmt.executeQuery()) {
            while (rs.next()) {
                result.add(mapDomain(rs));
            }
        }
        return result;
    }

    // ========== MAILBOX MANAGEMENT ==========

    public int addMailbox(int domainId, String email, String password, String name, int quotaMb) throws SQLException {
        return addMailbox(domainId, email, password, name, quotaMb, true);
    }

    public int addMailbox(int domainId, String email, String password, String name, int quotaMb, boolean receiveEnabled) throws SQLException {
        return insertMailbox(getConnection(), domainId, email, password, name, quotaMb, receiveEnabled);
    }

    /** L'INSERT di una casella sulla connessione data: da sola, o dentro una transazione. */
    private int insertMailbox(Connection c, int domainId, String email, String password, String name, int quotaMb, boolean receiveEnabled) throws SQLException {
        // Hash password with bcrypt (compatible with Dovecot)
        String hashedPassword = BCrypt.hashpw(password, BCrypt.gensalt(12));
        // La copia cifrata che il pannello mostra quando serve: senza, la casella non si crea
        String encryptedPassword = vaultCopy(password);

        String sql = "INSERT INTO mailboxes (domain_id, email, password, password_encrypted, password_encrypted_at, name, quota_mb, receive_enabled) " +
                     "VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
        try (PreparedStatement stmt = c.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            stmt.setInt(1, domainId);
            stmt.setString(2, email.toLowerCase());
            stmt.setString(3, hashedPassword);
            stmt.setString(4, encryptedPassword);
            stmt.setTimestamp(5, java.sql.Timestamp.from(java.time.Instant.now()));
            stmt.setString(6, name);
            stmt.setInt(7, quotaMb);
            stmt.setBoolean(8, receiveEnabled);
            stmt.executeUpdate();
            ResultSet rs = stmt.getGeneratedKeys();
            if (rs.next()) {
                int newId = rs.getInt(1);
                return newId;
            }
        }
        return -1;
    }

    public boolean deleteMailbox(int mailboxId) throws SQLException {
        String sql = "DELETE FROM mailboxes WHERE id = ?";
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setInt(1, mailboxId);
            return stmt.executeUpdate() > 0;
            // Postfix uses MySQL directly - no file sync needed
        }
    }

    public boolean updateMailboxPassword(int mailboxId, String newPassword) throws SQLException {
        // Bcrypt hash (compatible with Dovecot)
        String hashedPassword = BCrypt.hashpw(newPassword, BCrypt.gensalt(12));
        // Hash e copia cambiano insieme: una copia vecchia accanto a un hash nuovo mostrerebbe la password sbagliata
        String encryptedPassword = vaultCopy(newPassword);

        String sql = "UPDATE mailboxes SET password = ?, password_encrypted = ?, password_encrypted_at = ? WHERE id = ?";
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setString(1, hashedPassword);
            stmt.setString(2, encryptedPassword);
            stmt.setTimestamp(3, java.sql.Timestamp.from(java.time.Instant.now()));
            stmt.setInt(4, mailboxId);
            return stmt.executeUpdate() > 0;
        }
    }

    /**
     * La copia cifrata (vault) di una password di casella. Le password delle caselle si devono
     * poter sempre rivedere dal pannello: se il vault non cifra, la password non si salva affatto,
     * invece di salvare l'hash da solo e scoprire dopo che la copia manca.
     */
    private static String vaultCopy(String password) throws SQLException {
        try {
            return org.mail_panel.security.PasswordVault.getInstance().encrypt(password);
        } catch (RuntimeException e) {
            throw new SQLException("Mailbox password not saved: the password vault could not encrypt it", e);
        }
    }

    /** Un hash bcrypt come lo scrivono il pannello ($2a$) e doveadm pw ($2y$, $2b$, anche con {BLF-CRYPT} davanti). */
    static String bcryptPart(String stored) {
        if (stored == null) return null;
        String s = stored;
        if (s.startsWith("{BLF-CRYPT}")) s = s.substring("{BLF-CRYPT}".length());
        else if (s.startsWith("{BLF}")) s = s.substring("{BLF}".length());
        if (s.length() == 60 && (s.startsWith("$2a$") || s.startsWith("$2b$") || s.startsWith("$2y$"))) {
            return "$2a$" + s.substring(4);     // jBCrypt 0.4 conosce solo $2a$: per password fino a 72 byte sono lo stesso algoritmo
        }
        return null;
    }

    /**
     * Il valore della colonna password e' testo in chiaro: niente hash bcrypt e niente schema
     * {NOME} di Dovecot davanti. Succedeva quando la webmail scriveva da se' nella tabella con
     * l'algoritmo predefinito del plugin password di Roundcube ('clear').
     */
    static boolean isPlaintextPassword(String stored) {
        return stored != null && !stored.isEmpty() && bcryptPart(stored) == null && !stored.startsWith("{");
    }

    /**
     * La password data e' quella della casella adesso? Confronta con l'hash bcrypt della colonna
     * password (o, per una riga rimasta in chiaro, confronta a tempo costante). Lo schema
     * sconosciuto risponde false: meglio dire "non so" che mostrare una password sbagliata.
     */
    public boolean mailboxPasswordMatches(int mailboxId, String plain) throws SQLException {
        if (plain == null) return false;
        String stored = null;
        try (PreparedStatement stmt = getConnection().prepareStatement("SELECT password FROM mailboxes WHERE id = ?")) {
            stmt.setInt(1, mailboxId);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) stored = rs.getString(1);
            }
        }
        return passwordMatchesStored(stored, plain);
    }

    static boolean passwordMatchesStored(String stored, String plain) {
        if (stored == null || plain == null) return false;
        String bcrypt = bcryptPart(stored);
        if (bcrypt != null) {
            try {
                return BCrypt.checkpw(plain, bcrypt);
            } catch (IllegalArgumentException e) {
                return false;
            }
        }
        if (isPlaintextPassword(stored)) {
            return java.security.MessageDigest.isEqual(stored.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                    plain.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        }
        return false;
    }

    /**
     * Il vault ha la copia di una password giusta ma la casella non l'ha (caselle di prima del
     * vault): la aggiunge, solo se la password corrisponde all'hash di adesso. Serve a chi entra
     * dalla webmail, che e' l'unico momento in cui la password vera passa dal server.
     * Ritorna true se ha scritto la copia.
     */
    public boolean fillMissingVaultCopy(int mailboxId, String plain) throws SQLException {
        if (!mailboxPasswordMatches(mailboxId, plain)) return false;
        String current = getMailboxPasswordEncrypted(mailboxId);
        if (current != null && !current.isEmpty()) {
            try {
                if (plain.equals(org.mail_panel.security.PasswordVault.getInstance().decrypt(current))) return false;
            } catch (RuntimeException e) {
                // copia illeggibile (chiave cambiata o blob rovinato): la si riscrive
            }
        }
        String sql = "UPDATE mailboxes SET password_encrypted = ?, password_encrypted_at = ? WHERE id = ?";
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setString(1, vaultCopy(plain));
            stmt.setTimestamp(2, java.sql.Timestamp.from(java.time.Instant.now()));
            stmt.setInt(3, mailboxId);
            return stmt.executeUpdate() > 0;
        }
    }

    /**
     * Le righe con la password in chiaro (vedi isPlaintextPassword): l'hash bcrypt al posto del
     * testo, e la copia nel vault. Dovecot legge BLF-CRYPT: con il testo in chiaro quelle caselle
     * non entravano piu'. Ritorna quante righe ha sistemato; mai le password nel log.
     */
    public int repairPlaintextMailboxPasswords() throws SQLException {
        java.util.List<Object[]> rows = new java.util.ArrayList<>();
        try (Statement stmt = getConnection().createStatement();
             ResultSet rs = stmt.executeQuery("SELECT id, password FROM mailboxes")) {
            while (rs.next()) {
                String stored = rs.getString(2);
                if (isPlaintextPassword(stored)) rows.add(new Object[]{rs.getInt(1), stored});
            }
        }
        int repaired = 0;
        String sql = "UPDATE mailboxes SET password = ?, password_encrypted = ?, password_encrypted_at = ? WHERE id = ? AND password = ?";
        for (Object[] row : rows) {
            String plain = (String) row[1];
            try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
                stmt.setString(1, BCrypt.hashpw(plain, BCrypt.gensalt(12)));
                stmt.setString(2, vaultCopy(plain));
                stmt.setTimestamp(3, java.sql.Timestamp.from(java.time.Instant.now()));
                stmt.setInt(4, (Integer) row[0]);
                stmt.setString(5, plain);
                repaired += stmt.executeUpdate();
            }
        }
        return repaired;
    }

    /**
     * Recupera la password cifrata di una casella (per la feature "rivela password").
     * Ritorna null se non c'è una password cifrata (caselle vecchie pre-vault, o vault non
     * funzionante al momento del set).
     */
    public String getMailboxPasswordEncrypted(int mailboxId) throws SQLException {
        String sql = "SELECT password_encrypted FROM mailboxes WHERE id = ?";
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setInt(1, mailboxId);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) return rs.getString("password_encrypted");
            }
        }
        return null;
    }

    /**
     * Ritorna true se la casella ha una password cifrata archiviata.
     * Usato dalla UI per decidere se mostrare l'icona "rivela".
     */
    public boolean mailboxHasEncryptedPassword(int mailboxId) throws SQLException {
        String sql = "SELECT 1 FROM mailboxes WHERE id = ? AND password_encrypted IS NOT NULL AND password_encrypted <> ''";
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setInt(1, mailboxId);
            try (ResultSet rs = stmt.executeQuery()) {
                return rs.next();
            }
        }
    }

    /**
     * Lista tutte le caselle che hanno una password cifrata archiviata, restituendo
     * solo id + blob cifrato. Usato per la rotazione della master key.
     */
    public java.util.List<int[]> listMailboxesWithEncryptedPassword() throws SQLException {
        // Wrapper semplice: ritorniamo coppie (id, ?) ma serviranno anche i blob.
        // Usa la variante più completa qui sotto.
        java.util.List<int[]> ids = new java.util.ArrayList<>();
        String sql = "SELECT id FROM mailboxes WHERE password_encrypted IS NOT NULL AND password_encrypted <> ''";
        try (Statement stmt = getConnection().createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            while (rs.next()) ids.add(new int[]{rs.getInt(1)});
        }
        return ids;
    }

    /**
     * Variante con blob cifrato: ritorna (id, encrypted_blob) per ogni casella con vault.
     */
    public java.util.List<Object[]> listMailboxesWithEncryptedPasswordAndBlob() throws SQLException {
        java.util.List<Object[]> rows = new java.util.ArrayList<>();
        String sql = "SELECT id, password_encrypted FROM mailboxes WHERE password_encrypted IS NOT NULL AND password_encrypted <> ''";
        try (Statement stmt = getConnection().createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            while (rs.next()) {
                rows.add(new Object[]{rs.getInt(1), rs.getString(2)});
            }
        }
        return rows;
    }

    /**
     * Aggiorna SOLO il blob cifrato di una casella (usato durante la rotazione master key,
     * dove non rigeneriamo bcrypt — la password resta logicamente la stessa).
     */
    public void setMailboxEncryptedPasswordOnly(int mailboxId, String newEncryptedBlob) throws SQLException {
        String sql = "UPDATE mailboxes SET password_encrypted = ?, password_encrypted_at = ? WHERE id = ?";
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setString(1, newEncryptedBlob);
            stmt.setTimestamp(2, java.sql.Timestamp.from(java.time.Instant.now()));
            stmt.setInt(3, mailboxId);
            stmt.executeUpdate();
        }
    }

    public boolean updateMailboxStatus(int mailboxId, boolean active) throws SQLException {
        String sql = "UPDATE mailboxes SET active = ? WHERE id = ?";
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setBoolean(1, active);
            stmt.setInt(2, mailboxId);
            return stmt.executeUpdate() > 0;
            // Postfix uses MySQL directly - no file sync needed
        }
    }

    public boolean updateMailboxQuota(int mailboxId, int quotaMb) throws SQLException {
        String sql = "UPDATE mailboxes SET quota_mb = ? WHERE id = ?";
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setInt(1, quotaMb);
            stmt.setInt(2, mailboxId);
            return stmt.executeUpdate() > 0;
        }
    }

    /**
     * Update mailbox receive_enabled status (no-reply toggle)
     */
    public boolean updateMailboxReceiveEnabled(int mailboxId, boolean receiveEnabled) throws SQLException {
        String sql = "UPDATE mailboxes SET receive_enabled = ? WHERE id = ?";
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setBoolean(1, receiveEnabled);
            stmt.setInt(2, mailboxId);
            return stmt.executeUpdate() > 0;
        }
    }

    /**
     * Full mailbox update - updates all editable fields
     * @param mailboxId The mailbox ID
     * @param name Display name
     * @param quotaMb Quota in MB (0 = unlimited)
     * @param active Account active status
     * @param receiveEnabled Can receive emails (false = no-reply)
     */
    public boolean updateMailbox(int mailboxId, String name, int quotaMb, boolean active, boolean receiveEnabled) throws SQLException {
        String sql = "UPDATE mailboxes SET name = ?, quota_mb = ?, active = ?, receive_enabled = ? WHERE id = ?";
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setString(1, name);
            stmt.setInt(2, quotaMb);
            stmt.setBoolean(3, active);
            stmt.setBoolean(4, receiveEnabled);
            stmt.setInt(5, mailboxId);
            return stmt.executeUpdate() > 0;
        }
    }

    /**
     * Ensure mailbox password vault columns exist (idempotente).
     * Aggiunge password_encrypted (TEXT) + password_encrypted_at (TIMESTAMP).
     * Le nuove password create/aggiornate dalla UI verranno cifrate e archiviate qui.
     */
    public void ensureMailboxPasswordVaultColumns() {
        String[][] cols = {
            {"password_encrypted",     "TEXT NULL"},
            {"password_encrypted_at",  "TIMESTAMP NULL"}
        };
        try (Statement stmt = getConnection().createStatement()) {
            for (String[] col : cols) {
                ResultSet rs = stmt.executeQuery(
                    "SELECT COUNT(*) FROM information_schema.columns " +
                    "WHERE table_schema = DATABASE() AND table_name = 'mailboxes' AND column_name = '" + col[0] + "'"
                );
                if (rs.next() && rs.getInt(1) == 0) {
                    stmt.executeUpdate("ALTER TABLE mailboxes ADD COLUMN " + col[0] + " " + col[1]);
                    System.out.println("Added " + col[0] + " column to mailboxes table");
                }
            }
        } catch (SQLException e) {
            System.err.println("Error ensuring mailbox password vault columns: " + e.getMessage());
        }
    }

    /**
     * Ensure receive_enabled column exists (for database migration)
     */
    public void ensureMailboxReceiveEnabledColumn() {
        try (Statement stmt = getConnection().createStatement()) {
            // Check if column exists
            ResultSet rs = stmt.executeQuery(
                "SELECT COUNT(*) FROM information_schema.columns " +
                "WHERE table_schema = DATABASE() AND table_name = 'mailboxes' AND column_name = 'receive_enabled'"
            );
            if (rs.next() && rs.getInt(1) == 0) {
                // Column doesn't exist, add it
                stmt.executeUpdate("ALTER TABLE mailboxes ADD COLUMN receive_enabled BOOLEAN DEFAULT TRUE AFTER active");
                System.out.println("Added receive_enabled column to mailboxes table");
            }
        } catch (SQLException e) {
            System.err.println("Error ensuring receive_enabled column: " + e.getMessage());
        }
    }

    /**
     * Reload Postfix configuration
     * Postfix uses MySQL directly for virtual users, so no file sync is needed.
     * This just tells Postfix to reload if any configuration changes were made.
     *
     * Postfix queries MySQL directly via:
     * - mysql-virtual-domains.cf → SELECT domain FROM domains WHERE domain='%s' AND active=1
     * - mysql-virtual-mailboxes.cf → SELECT ... FROM mailboxes WHERE email='%s' AND active=1 AND receive_enabled=1
     * - mysql-virtual-aliases.cf → SELECT destination FROM aliases WHERE source='%s' AND active=1
     *
     * Note: receive_enabled=1 ensures no-reply accounts (receive_enabled=0) reject incoming mail
     */
    public boolean reloadPostfix() {
        try {
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("sh", "-c", "service postfix reload 2>/dev/null || true");
            org.mail_panel.util.Shell.applyPath(pb);
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
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
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
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
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
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
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
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
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
        try (Statement stmt = getConnection().createStatement();
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
        // receive_enabled field (default true if column doesn't exist yet)
        try {
            m.receiveEnabled = rs.getBoolean("receive_enabled");
        } catch (SQLException ignored) {
            m.receiveEnabled = true; // Default for old databases
        }
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

    // ========== ALIAS <-> CASELLA ==========

    /**
     * Un indirizzo che oggi e' solo alias diventa una casella, in una transazione: per Postfix,
     * che legge le tabelle a ogni messaggio, si passa da "alias" a "casella" senza un istante in
     * mezzo in cui l'indirizzo non esiste o vale in tutti e due i modi.
     *
     * @param tieniInoltri false: le righe con questa sorgente se ne vanno e la posta resta nella
     *                     casella; true: restano, e un alias "indirizzo -> se stesso" attivo fa
     *                     arrivare una copia anche nella casella
     * @return l'id della casella nuova
     */
    public int transformAliasToMailbox(int domainId, String email, String password, String name, int quotaMb,
                                       boolean keepForwards) throws SQLException {
        try (Connection c = ownConnection()) {
            c.setAutoCommit(false);
            try {
                int id = insertMailbox(c, domainId, email, password, name, quotaMb, true);
                if (id <= 0) throw new SQLException("the mailbox was not created");
                if (keepForwards) {
                    try (PreparedStatement p = c.prepareStatement(
                            "INSERT INTO aliases (domain_id, source, destination, active) VALUES (?, ?, ?, 1) "
                          + "ON DUPLICATE KEY UPDATE active = 1")) {
                        p.setInt(1, domainId);
                        p.setString(2, email.toLowerCase());
                        p.setString(3, email.toLowerCase());
                        p.executeUpdate();
                    }
                } else {
                    try (PreparedStatement p = c.prepareStatement("DELETE FROM aliases WHERE source = ?")) {
                        p.setString(1, email.toLowerCase());
                        p.executeUpdate();
                    }
                }
                c.commit();
                return id;
            } catch (SQLException e) {
                c.rollback();
                throw e;
            }
        }
    }

    /**
     * Una casella diventa un alias verso le destinazioni date, in una transazione. Se ne vanno la
     * casella (e con lei, per le chiavi esterne, risposta automatica, filtri, inoltri, token della
     * webmail), il suo limite di invio e l'alias "se stessa -> se stessa": senza casella porterebbe
     * a un indirizzo che non esiste. Gli altri alias con questa sorgente restano. La posta gia'
     * arrivata non e' nel database: resta sul disco.
     */
    public void transformMailboxToAlias(int mailboxId, int domainId, String email, List<String> destinations) throws SQLException {
        String address = email.toLowerCase();
        try (Connection c = ownConnection()) {
            c.setAutoCommit(false);
            try {
                try (PreparedStatement p = c.prepareStatement(
                        "INSERT INTO aliases (domain_id, source, destination, active) VALUES (?, ?, ?, 1) "
                      + "ON DUPLICATE KEY UPDATE active = 1")) {
                    for (String d : destinations) {
                        p.setInt(1, domainId);
                        p.setString(2, address);
                        p.setString(3, d.toLowerCase());
                        p.executeUpdate();
                    }
                }
                try (PreparedStatement p = c.prepareStatement("DELETE FROM aliases WHERE source = ? AND destination = ?")) {
                    p.setString(1, address);
                    p.setString(2, address);
                    p.executeUpdate();
                }
                try (PreparedStatement p = c.prepareStatement("DELETE FROM rate_limits WHERE target_type = 'mailbox' AND target_id = ?")) {
                    p.setInt(1, mailboxId);
                    p.executeUpdate();
                }
                try (PreparedStatement p = c.prepareStatement("DELETE FROM mailboxes WHERE id = ? AND email = ?")) {
                    p.setInt(1, mailboxId);
                    p.setString(2, address);
                    if (p.executeUpdate() != 1) throw new SQLException("the mailbox no longer exists");
                }
                c.commit();
            } catch (SQLException e) {
                c.rollback();
                throw e;
            }
        }
    }

    /** Gli alias con questa sorgente, attivi o no. */
    public List<Alias> getAliasesBySource(String source) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(
                "SELECT a.*, d.domain as domain_name FROM aliases a JOIN domains d ON a.domain_id = d.id "
              + "WHERE a.source = ? ORDER BY a.destination")) {
            stmt.setString(1, source.toLowerCase());
            return aliasWithDomain(stmt);
        }
    }

    /** Gli alias che portano a questo indirizzo, da qualunque dominio. */
    public List<Alias> getAliasesByDestination(String destination) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(
                "SELECT a.*, d.domain as domain_name FROM aliases a JOIN domains d ON a.domain_id = d.id "
              + "WHERE a.destination = ? ORDER BY a.source")) {
            stmt.setString(1, destination.toLowerCase());
            return aliasWithDomain(stmt);
        }
    }

    private List<Alias> aliasWithDomain(PreparedStatement stmt) throws SQLException {
        List<Alias> aliases = new ArrayList<>();
        try (ResultSet rs = stmt.executeQuery()) {
            while (rs.next()) {
                Alias a = mapAlias(rs);
                a.domainName = rs.getString("domain_name");
                aliases.add(a);
            }
        }
        return aliases;
    }

    // ========== ALIAS MANAGEMENT ==========

    public int addAlias(int domainId, String source, String destination) throws SQLException {
        String sql = "INSERT INTO aliases (domain_id, source, destination) VALUES (?, ?, ?)";
        try (PreparedStatement stmt = getConnection().prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
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
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setInt(1, aliasId);
            return stmt.executeUpdate() > 0;
            // Postfix uses MySQL directly - no file sync needed
        }
    }

    /**
     * Cambia la destinazione di un alias con un solo UPDATE: nessun momento in cui la sorgente
     * resta senza alias, come succederebbe eliminando e ricreando. Una coppia sorgente ->
     * destinazione gia' esistente fa scattare il vincolo UNIQUE (SQLIntegrityConstraintViolationException).
     */
    public boolean updateAliasDestination(int aliasId, String destination) throws SQLException {
        String sql = "UPDATE aliases SET destination = ? WHERE id = ?";
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setString(1, destination.toLowerCase());
            stmt.setInt(2, aliasId);
            return stmt.executeUpdate() > 0;
        }
    }

    /** Un alias per id, o null se non c'e'. */
    public Alias getAliasById(int aliasId) throws SQLException {
        String sql = "SELECT * FROM aliases WHERE id = ?";
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setInt(1, aliasId);
            try (ResultSet rs = stmt.executeQuery()) {
                return rs.next() ? mapAlias(rs) : null;
            }
        }
    }

    public boolean updateAliasStatus(int aliasId, boolean active) throws SQLException {
        String sql = "UPDATE aliases SET active = ? WHERE id = ?";
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setBoolean(1, active);
            stmt.setInt(2, aliasId);
            return stmt.executeUpdate() > 0;
            // Postfix uses MySQL directly - no file sync needed
        }
    }

    public List<Alias> getAliases(int domainId) throws SQLException {
        List<Alias> aliases = new ArrayList<>();
        String sql = "SELECT * FROM aliases WHERE domain_id = ? ORDER BY source";
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
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
        try (Statement stmt = getConnection().createStatement();
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
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
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
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setString(1, token);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                // Mark token as used
                try (PreparedStatement update = getConnection().prepareStatement(
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
        try (Statement stmt = getConnection().createStatement()) {
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
        try (Statement stmt = getConnection().createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            if (rs.next()) {
                return rs.getInt(1);
            }
        } catch (SQLException e) {
            // ignore
        }
        return 0;
    }

    /** La versione del server MySQL a cui il pannello e' collegato adesso (SELECT VERSION()), o null. */
    public String serverVersion() {
        try (PreparedStatement stmt = getConnection().prepareStatement("SELECT VERSION()");
             ResultSet rs = stmt.executeQuery()) {
            return rs.next() ? rs.getString(1) : null;
        } catch (Exception e) {
            return null;
        }
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
        // Check if connection is still valid, reconnect if needed
        try {
            if (connection == null || connection.isClosed() || !connection.isValid(5)) {
                System.out.println("Connection lost, attempting to reconnect...");
                connect();
            }
        } catch (SQLException e) {
            System.err.println("Error checking connection validity: " + e.getMessage());
            connect();
        }
        return connection;
    }

    /**
     * Ensure connection is valid before use
     */
    public void ensureConnection() {
        try {
            if (connection == null || connection.isClosed() || !connection.isValid(5)) {
                System.out.println("Reconnecting to MySQL...");
                connect();
            }
        } catch (SQLException e) {
            System.err.println("Error checking connection: " + e.getMessage());
            connect();
        }
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
        // DKIM rotation - pending key (in attesa di propagazione DNS)
        public String dkimPendingSelector;
        public String dkimPendingPrivateKey;
        public String dkimPendingPublicKey;
        // Stato rotazione: null (nessuna), "pending_dns", "propagated", "active_grace"
        public String dkimRotationState;
        public Timestamp dkimRotationStartedAt;
        public Timestamp dkimRotationActivatedAt;
        // Vecchia chiave conservata durante il grace period
        public String dkimPreviousSelector;
        public String dkimPreviousPrivateKey;
        public String dkimPreviousPublicKey;
        // Cloudflare automation
        public String dkimDnsZoneId;
        public String dkimPendingDnsRecordId;
        public String dkimPreviousDnsRecordId;
        // Account Cloudflare assegnato (0 = nessuno / manuale)
        public int cloudflareAccountId;
        // Rotazione programmata (0 = disattivata)
        public int dkimRotationIntervalDays;
        public Timestamp dkimLastRotationAt;
        // Modalità rotazione corrente (ereditata da eventi della catena)
        public String dkimRotationMode;
    }

    public static class Mailbox {
        public int id;
        public int domainId;
        public String domainName;
        public String email;
        public String name;
        public int quotaMb;  // 0 = unlimited
        public boolean active;
        public boolean receiveEnabled;  // false = no-reply (send only)
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
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
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
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
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
        try (Statement stmt = getConnection().createStatement();
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
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
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
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
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
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
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
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
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
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
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
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
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
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
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
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
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
        try (Statement stmt = getConnection().createStatement();
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

    /**
     * Salva un limite di invio, aggiornando la riga che c'e' gia' per lo stesso obiettivo.
     *
     * Il limite globale ha target_id 0 e non NULL: nell'indice UNIQUE (target_type, target_id) di
     * MySQL due NULL non sono uguali, e ogni salvataggio dei limiti globali aggiungeva una riga
     * invece di aggiornare quella che c'era. Le righe globali con NULL rimaste da prima si tolgono
     * nella stessa transazione.
     */
    public boolean saveRateLimit(String targetType, Integer targetId, int maxPerHour, int maxPerDay, int maxRecipients, boolean enabled) {
        boolean global = "global".equals(targetType);
        if (!global && targetId == null) return false;
        String sql = """
            INSERT INTO rate_limits (target_type, target_id, max_per_hour, max_per_day, max_recipients, enabled)
            VALUES (?, ?, ?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE max_per_hour = VALUES(max_per_hour), max_per_day = VALUES(max_per_day),
                                    max_recipients = VALUES(max_recipients), enabled = VALUES(enabled)
            """;
        try (Connection c = ownConnection()) {
            c.setAutoCommit(false);
            try {
                try (PreparedStatement stmt = c.prepareStatement(sql)) {
                    stmt.setString(1, targetType);
                    stmt.setInt(2, global ? 0 : targetId);
                    stmt.setInt(3, maxPerHour);
                    stmt.setInt(4, maxPerDay);
                    stmt.setInt(5, maxRecipients);
                    stmt.setBoolean(6, enabled);
                    stmt.executeUpdate();
                }
                if (global) {
                    try (PreparedStatement stmt = c.prepareStatement(
                            "DELETE FROM rate_limits WHERE target_type = 'global' AND target_id IS NULL")) {
                        stmt.executeUpdate();
                    }
                }
                c.commit();
                return true;
            } catch (SQLException e) {
                c.rollback();
                throw e;
            }
        } catch (SQLException e) {
            LOGGER.log(java.util.logging.Level.WARNING, "Saving a rate limit failed", e);
            return false;
        }
    }

    public boolean deleteRateLimit(int limitId) {
        String sql = "DELETE FROM rate_limits WHERE id = ?";
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
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
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
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
        try (Statement stmt = getConnection().createStatement();
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

        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
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
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
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
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
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
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
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
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
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

        try (PreparedStatement stmt = getConnection().prepareStatement(sql.toString())) {
            for (int i = 0; i < params.size(); i++) {
                // Pattern matching for instanceof (Java 16+): niente cast esplicito,
                // la variabile e' gia' tipata nello scope dell'if.
                switch (params.get(i)) {
                    case String s  -> stmt.setString(i + 1, s);
                    case Integer n -> stmt.setInt(i + 1, n);
                    case null      -> stmt.setNull(i + 1, java.sql.Types.NULL);
                    default        -> stmt.setObject(i + 1, params.get(i));
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

        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
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
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
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
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
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
