package org.daemoxcp.mail.database;

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
 * Database: daemoxcp_mail
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
    private String database = org.daemoxcp.mail.system.Product.ID;
    private String username = org.daemoxcp.mail.system.Product.ID;
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

    /**
     * Where to read the password again at every connection: the panel's, in the secrets file.
     *
     * <p>Without it, the panel reconnected with the password it had in memory since startup. A
     * full reinstallation from the menu changes the password of the panel's MySQL user (and
     * writes it in the secrets file when MySQL knows it, PendingDbPassword) and restarts MySQL: the
     * --web service running meanwhile lost the connection and retried forever with the
     * old one, "Access denied", until someone restarted it (finding 156).
     */
    public void setPasswordSource(java.util.function.Supplier<String> source) {
        this.passwordSource = source;
    }

    private java.util.function.Supplier<String> passwordSource;

    /**
     * The web part with its own MySQL user (WebDbAccess.WEB_USER): every statement becomes the call of its
     * procedure (CatalogGuard.openRoutines). The user can only call them: no creation of the database
     * when the connection starts, which the driver would do with createDatabaseIfNotExist.
     */
    private boolean routines;

    public void useRoutines(String user, java.util.function.Supplier<String> password) {
        this.routines = true;
        this.username = user;
        this.passwordSource = password;
        this.password = password.get();
    }

    /** True if the connection is the web part's procedure connection. */
    public boolean usesRoutines() {
        return routines;
    }

    /** The password for the next connection: the source's if it gives one, otherwise the last one. */
    private String currentPassword() {
        if (passwordSource != null) {
            try {
                String p = passwordSource.get();
                if (p != null && !p.isEmpty()) {
                    if (password != null && !password.isEmpty() && !p.equals(password))
                        LOGGER.info("The panel's MySQL password changed in the secrets file: connecting with the new one.");
                    password = p;
                }
            } catch (RuntimeException e) {
                LOGGER.warning("Cannot read the panel's MySQL password again, using the previous one: " + e.getMessage());
            }
        }
        return password;
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
        boolean again = connection != null;
        try {
            connection = open();
            connected = true;
            if (again) System.out.println("Connected to MySQL again.");
            return true;
        } catch (SQLException e) {
            System.err.println(unavailableMessage(java.nio.file.Files.isExecutable(java.nio.file.Path.of(MYSQLD)), e.getMessage()));
            connected = false;
            return false;
        }
    }

    static final String MYSQLD = "/usr/local/libexec/mysqld";

    /**
     * What to say when MySQL does not answer. On a new server the installation starts before MySQL is there,
     * and "MySQL not available: Could not create connection... Giving up" looked like a fault to whoever
     * installed from the README (2026-11-20): if MySQL is not installed, it says so. A pure function, so it can
     * be tested.
     */
    public static String unavailableMessage(boolean installed, String detail) {
        return installed ? "MySQL not available: " + detail
                         : "MySQL is not installed yet: nothing to read from it (normal on a new server, before the installation)";
    }

    private String databaseUrl() {
        return String.format(
            "jdbc:mysql://%s:%d/%s?useSSL=true&requireSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC&createDatabaseIfNotExist=true&autoReconnect=true",
            host, port, database
        );
    }

    /**
     * The panel's database for those who do not create it: the web part's user, and MySQL's root, which puts
     * procedures and permissions in it (WebDbAccess). The statements with no database written (GRANT ... ON *,
     * CREATE PROCEDURE) apply here.
     */
    public String existingDatabaseUrl() {
        return String.format(
            "jdbc:mysql://%s:%d/%s?useSSL=true&requireSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC&autoReconnect=true",
            host, port, database
        );
    }

    private Connection open() throws SQLException {
        return routines ? CatalogGuard.openRoutines(existingDatabaseUrl(), username, currentPassword())
                : CatalogGuard.open(databaseUrl(), username, currentPassword());
    }

    /**
     * A connection all for whoever asks for it, who closes it. It is needed for transactions: the
     * shared connection is also used by the background jobs (report, DKIM, MTA-STS), and with
     * autocommit off their commands would end up inside someone else's transaction.
     */
    private Connection ownConnection() throws SQLException {
        return open();
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
            connection = CatalogGuard.open(url, "root", rootPassword);
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
            connection = CatalogGuard.open(url, "root", "");
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
                connection = CatalogGuard.open(url, "root", "");
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
     * Create the daemoxcp_mail database and user (run as root)
     */
    public void createDatabaseAndUser(String panelPassword) throws SQLException {
        try (Statement stmt = getConnection().createStatement()) {
            // Create database
            stmt.execute(SqlCatalog.MAIL_CREATE_PANEL_DATABASE);

            // Create user: the password is a parameter, not a piece of the text
            createUser(SqlCatalog.MAIL_CREATE_PANEL_USER, panelPassword);
            stmt.execute(SqlCatalog.MAIL_GRANT_PANEL_USER);

            // Dovecot's database is this one: the second one, mailserver, with its user, no longer exists (2026-11-17:
            // MysqlRename moved its tables here on the servers installed before).

            stmt.execute(SqlCatalog.MAIL_FLUSH_PRIVILEGES);
        }

        // Store the password for later use
        this.password = panelPassword;
    }

    /**
     * CREATE USER with the password as a parameter. MySQL does not accept a placeholder in IDENTIFIED BY
     * when it prepares the statement itself; Connector/J however, unless asked otherwise, prepares on the
     * client side and puts the value in quotes with its own escaping, quotes and backslashes
     * included. Before, the password went into the text with only the quotes doubled.
     */
    private void createUser(String statement, String password) throws SQLException {
        try (PreparedStatement ps = getConnection().prepareStatement(statement)) {
            ps.setString(1, password);
            ps.execute();
        }
    }

    /**
     * All the tables the panel creates (createSchema and the migrations), plus those of old
     * versions (virtual_*): the reset deletes them, and no other table of the database. First the tables that
     * point to others with a foreign key, then those pointed to.
     */
    public static final List<String> PANEL_TABLES = List.of(
        "admin_passkeys", "rspamd_training", "panel_sessions",                // -> panel_admin
        "login_code_email", "login_code_console", "stepup_code", "email_change_code",
        "roundcube_tokens", "auto_responders", "sieve_filters", "forwarding_rules",
        "email_statistics",                                                   // -> mailboxes, domains
        "aliases", "mailboxes",                                               // -> domains
        "dkim_rotation_history", "domains", "cloudflare_accounts",
        "audit_log", "rate_limits", "panel_settings", "panel_role_permissions", "installed_components", "panel_admin",
        "virtual_aliases", "virtual_users", "virtual_domains"
    );

    /**
     * Empties the panel's database for the reset: deletes all its tables and returns only if
     * none is left. Returns those that were there.
     *
     * A single DROP with all the tables: MySQL removes together those linked by foreign keys without
     * turning off the checks, and on InnoDB the command is atomic, it deletes either all of them or none. The
     * old reset deleted them one at a time: those another one pointed to (mailboxes, domains,
     * panel_admin) remained, with their data, and admin_passkeys, cloudflare_accounts and
     * dkim_rotation_history were missing. On a connection all its own, because a DROP closes the transaction
     * of the connection it runs on.
     */
    public List<String> dropAllTables() throws SQLException {
        if (!connected) throw new SQLException("Not connected to MySQL: the reset did not start.");
        try (Connection c = ownConnection()) {
            List<String> before = panelTables(c);
            try (Statement st = c.createStatement()) {
                // A DROP takes no parameters: the list is fixed in the catalog, equal to PANEL_TABLES.
                st.executeUpdate(SqlCatalog.MAIL_DROP_PANEL_TABLES);
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

    /** The panel's tables that are now in the connection's database. */
    private static List<String> panelTables(Connection c) throws SQLException {
        List<String> found = new ArrayList<>();
        try (PreparedStatement ps = c.prepareStatement(SqlCatalog.MAIL_PANEL_TABLES);
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

        // Settings table

        // Installed components

        // ========== MAIL TABLES ==========

        // Domains table

        // Cloudflare accounts table (one account = one token + informational label)

        // DKIM rotation history (audit log: every workflow event is recorded)

        // Mailboxes table (virtual users)
        // quota_mb: 0 = unlimited, >0 = limit in MB
        // receive_enabled: false = no-reply account (can only send, not receive)

        // Aliases table

        // Auto-login tokens for Roundcube SSO

        // Auto-responder (vacation messages)

        // Sieve filters

        // Forwarding rules

        // Rate limits

        // Email statistics

        // Rspamd training log


        // Passkeys (WebAuthn) for passwordless login

        try (Statement stmt = getConnection().createStatement()) {
            stmt.execute(SqlCatalog.MAIL_CREATE_SCHEMA);
            stmt.execute(SqlCatalog.MAIL_CREATE_SCHEMA_2);
            stmt.execute(SqlCatalog.MAIL_CREATE_SCHEMA_3);
            stmt.execute(SqlCatalog.MAIL_CREATE_SCHEMA_4);
            stmt.execute(SqlCatalog.MAIL_CREATE_SCHEMA_5);
            stmt.execute(SqlCatalog.MAIL_CREATE_SCHEMA_6);
            stmt.execute(SqlCatalog.MAIL_CREATE_SCHEMA_7);
            stmt.execute(SqlCatalog.MAIL_CREATE_SCHEMA_8);
            stmt.execute(SqlCatalog.MAIL_CREATE_SCHEMA_9);
            stmt.execute(SqlCatalog.MAIL_CREATE_SCHEMA_10);
            stmt.execute(SqlCatalog.MAIL_CREATE_SCHEMA_11);
            stmt.execute(SqlCatalog.MAIL_CREATE_SCHEMA_12);
            stmt.execute(SqlCatalog.MAIL_CREATE_SCHEMA_13);
            stmt.execute(SqlCatalog.MAIL_CREATE_SCHEMA_14);
            stmt.execute(SqlCatalog.MAIL_CREATE_SCHEMA_15);
            stmt.execute(SqlCatalog.MAIL_CREATE_SCHEMA_16);
            stmt.execute(SqlCatalog.MAIL_CREATE_SCHEMA_17);
            createAuthTables(stmt);
        }
    }

    /**
     * The tables of passwordless access: the sessions and the one-time codes, one table per
     * flow (login via email, login from the console, email change, confirmation of
     * a sensitive operation). The codes hold only the HMAC fingerprint, never the code; of the session
     * there is only the SHA-256 fingerprint of the token. Dates in UTC, DATETIME columns.
     */
    private static void createAuthTables(Statement st) throws SQLException {
        st.execute(SqlCatalog.MAIL_CREATE_PANEL_SESSIONS);
        st.execute(SqlCatalog.MAIL_CREATE_LOGIN_CODE_EMAIL);
        st.execute(SqlCatalog.MAIL_CREATE_LOGIN_CODE_CONSOLE);
        st.execute(SqlCatalog.MAIL_CREATE_STEPUP_CODE);
        st.execute(SqlCatalog.MAIL_CREATE_EMAIL_CHANGE_CODE);
    }

    /**
     * From an installation with passwords to one without. It can be repeated: every step first checks
     * whether it is needed. On a connection of its own with the UTC time zone, because going from TIMESTAMP to DATETIME
     * converts with the session's time zone, and the dates must stay in UTC.
     *
     *  - away with password_hash, totp_secret, totp_enabled, backup_codes: no hash in the database;
     *  - encrypted email, blind index, user handle of the passkeys;
     *  - the passkeys know which user handle and which name (rpId) they belong to;
     *  - the access dates in DATETIME.
     */
    public void ensurePasswordlessSchema() throws SQLException {
        try (Connection c = ownConnection(); Statement st = c.createStatement()) {
            st.execute(SqlCatalog.MAIL_ENSURE_PASSWORDLESS_SCHEMA);
            createAuthTables(st);
            // An ALTER takes no parameters: one fixed statement per column.
            String[][] old = {
                {"password_hash", SqlCatalog.MAIL_DROP_ADMIN_PASSWORD_HASH},
                {"totp_secret", SqlCatalog.MAIL_DROP_ADMIN_TOTP_SECRET},
                {"totp_enabled", SqlCatalog.MAIL_DROP_ADMIN_TOTP_ENABLED},
                {"backup_codes", SqlCatalog.MAIL_DROP_ADMIN_BACKUP_CODES}};
            for (String[] col : old) {
                if (columnType(c, "panel_admin", col[0]) != null) {
                    st.executeUpdate(col[1]);
                    LOGGER.info("Removed panel_admin." + col[0]);
                }
            }
            if (columnType(c, "panel_admin", "email_enc") == null)
                st.executeUpdate(SqlCatalog.MAIL_ENSURE_PASSWORDLESS_SCHEMA_2);
            if (columnType(c, "panel_admin", "email_index") == null)
                st.executeUpdate(SqlCatalog.MAIL_ENSURE_PASSWORDLESS_SCHEMA_3);
            if (columnType(c, "panel_admin", "user_handle") == null)
                st.executeUpdate(SqlCatalog.MAIL_ENSURE_PASSWORDLESS_SCHEMA_4);
            if ("timestamp".equals(columnType(c, "panel_admin", "created_at")))
                st.executeUpdate(SqlCatalog.MAIL_ENSURE_PASSWORDLESS_SCHEMA_5);
            if ("timestamp".equals(columnType(c, "panel_admin", "last_login")))
                st.executeUpdate(SqlCatalog.MAIL_ENSURE_PASSWORDLESS_SCHEMA_6);
            if (columnType(c, "admin_passkeys", "user_handle") == null)
                st.executeUpdate(SqlCatalog.MAIL_ENSURE_PASSWORDLESS_SCHEMA_7);
            if (columnType(c, "admin_passkeys", "rp_id") == null)
                st.executeUpdate(SqlCatalog.MAIL_ENSURE_PASSWORDLESS_SCHEMA_8);
            if ("timestamp".equals(columnType(c, "admin_passkeys", "created_at")))
                st.executeUpdate(SqlCatalog.MAIL_ENSURE_PASSWORDLESS_SCHEMA_9);
            if ("timestamp".equals(columnType(c, "admin_passkeys", "last_used")))
                st.executeUpdate(SqlCatalog.MAIL_ENSURE_PASSWORDLESS_SCHEMA_10);
        }
    }

    /** The type of a column (lowercase, "datetime", "varchar"...) or null if the column does not exist. */
    private static String columnType(Connection c, String table, String column) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement(SqlCatalog.MAIL_COLUMN_TYPE)) {
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
        try (Statement stmt = getConnection().createStatement();
             ResultSet rs = stmt.executeQuery(SqlCatalog.MAIL_HAS_ADMIN_USER)) {
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
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_GET_ADMIN_THEME)) {
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
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_SET_ADMIN_THEME)) {
            stmt.setString(1, theme);
            stmt.setString(2, username);
            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            System.err.println("Error setting theme: " + e.getMessage());
            return false;
        }
    }

    /**
     * The language chosen by the administrator (one of the panel's languages), or null if they never chose one: then
     * the browser's applies. It follows them on every browser, like the theme.
     */
    public String getAdminLanguage(String username) {
        if (username == null) return null;
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_GET_ADMIN_LANGUAGE)) {
            stmt.setString(1, username);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    String lang = rs.getString("language");
                    return lang != null && org.daemoxcp.mail.i18n.I18n.LANGUAGES.contains(lang) ? lang : null;
                }
            }
        } catch (SQLException e) {
            LOGGER.log(Level.WARNING, "Cannot read the admin language", e);
        }
        return null;
    }

    /**
     * The console language (on-screen menu and commands): that of the first active administrator who has chosen one,
     * or null if nobody has. The console has no session: it speaks the language of whoever installed the panel.
     */
    public String getPanelLanguage() {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_GET_PANEL_LANGUAGE);
             ResultSet rs = stmt.executeQuery()) {
            if (rs.next()) {
                String lang = rs.getString("language");
                return lang != null && org.daemoxcp.mail.i18n.I18n.LANGUAGES.contains(lang) ? lang : null;
            }
        } catch (SQLException e) {
            LOGGER.log(Level.WARNING, "Cannot read the panel language", e);
        }
        return null;
    }

    /** Saves the administrator's language: only one of the panel's languages (I18n.LANGUAGES). */
    public boolean setAdminLanguage(String username, String lang) {
        if (username == null || lang == null || !org.daemoxcp.mail.i18n.I18n.LANGUAGES.contains(lang)) return false;
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_SET_ADMIN_LANGUAGE)) {
            stmt.setString(1, lang);
            stmt.setString(2, username);
            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            LOGGER.log(Level.WARNING, "Cannot save the admin language", e);
            return false;
        }
    }

    /** The language column in panel_admin, for earlier installations (NULL: never chosen). */
    /**
     * The columns and tables added by later versions, for earlier installations. The root calls them
     * at startup (SSLMailServer) and before preparing the web part's MySQL user (WebDbAccess), whose per-column
     * permissions want them already there. They do nothing if they are already there.
     */
    public void ensureColumnUpgrades() {
        ensureMailboxReceiveEnabledColumn();
        // The automatic emptying of Junk and Trash of every mailbox, off until it is asked for
        ensureMailboxCleanupColumns();
        // Mailbox password encryption for recovery from the panel
        ensureMailboxPasswordVaultColumns();
        ensureThemeColumn();
        // The language chosen by the administrator (for earlier installations)
        ensureLanguageColumn();
        ensureDkimRotationColumns();
        // Migrates the legacy Cloudflare token if present
        ensureCloudflareAccountsSchema();
        ensureDkimRotationHistoryTable();
    }

    public void ensureLanguageColumn() {
        try (Statement stmt = getConnection().createStatement(); ResultSet rs = stmt.executeQuery(SqlCatalog.MAIL_ENSURE_LANGUAGE_COLUMN)) {
            if (rs.next() && rs.getInt(1) == 0) {
                try (Statement alter = getConnection().createStatement()) {
                    alter.executeUpdate(SqlCatalog.MAIL_ENSURE_LANGUAGE_COLUMN_2);
                }
                LOGGER.info("Added language column to panel_admin");
            }
        } catch (SQLException e) {
            LOGGER.log(Level.WARNING, "Cannot add the language column", e);
        }
    }

    /**
     * Ensure DKIM rotation columns exist in domains table (for database migration).
     * Idempotently adds the fields dkim_pending_*, dkim_previous_*,
     * dkim_rotation_state, dkim_rotation_started_at, dkim_rotation_activated_at.
     */
    public void ensureDkimRotationColumns() {
        // Column name and its fixed statement: an ALTER takes no parameters.
        String[][] cols = {
            {"dkim_pending_selector", SqlCatalog.MAIL_ADD_DOMAINS_DKIM_PENDING_SELECTOR},
            {"dkim_pending_private_key", SqlCatalog.MAIL_ADD_DOMAINS_DKIM_PENDING_PRIVATE_KEY},
            {"dkim_pending_public_key", SqlCatalog.MAIL_ADD_DOMAINS_DKIM_PENDING_PUBLIC_KEY},
            {"dkim_rotation_state", SqlCatalog.MAIL_ADD_DOMAINS_DKIM_ROTATION_STATE},
            {"dkim_rotation_started_at", SqlCatalog.MAIL_ADD_DOMAINS_DKIM_ROTATION_STARTED_AT},
            {"dkim_rotation_activated_at", SqlCatalog.MAIL_ADD_DOMAINS_DKIM_ROTATION_ACTIVATED_AT},
            {"dkim_previous_selector", SqlCatalog.MAIL_ADD_DOMAINS_DKIM_PREVIOUS_SELECTOR},
            {"dkim_previous_private_key", SqlCatalog.MAIL_ADD_DOMAINS_DKIM_PREVIOUS_PRIVATE_KEY},
            {"dkim_previous_public_key", SqlCatalog.MAIL_ADD_DOMAINS_DKIM_PREVIOUS_PUBLIC_KEY},
            // Cloudflare automation: zone + IDs of the TXT records, to delete them
            {"dkim_dns_zone_id", SqlCatalog.MAIL_ADD_DOMAINS_DKIM_DNS_ZONE_ID},
            {"dkim_pending_dns_record_id", SqlCatalog.MAIL_ADD_DOMAINS_DKIM_PENDING_DNS_RECORD_ID},
            {"dkim_previous_dns_record_id", SqlCatalog.MAIL_ADD_DOMAINS_DKIM_PREVIOUS_DNS_RECORD_ID},
            // Scheduled rotation
            {"dkim_rotation_interval_days", SqlCatalog.MAIL_ADD_DOMAINS_DKIM_ROTATION_INTERVAL_DAYS},
            {"dkim_last_rotation_at", SqlCatalog.MAIL_ADD_DOMAINS_DKIM_LAST_ROTATION_AT},
            // Rotation mode (inherited by all the events of the chain)
            {"dkim_rotation_mode", SqlCatalog.MAIL_ADD_DOMAINS_DKIM_ROTATION_MODE}
        };
        try (Statement stmt = getConnection().createStatement()) {
            for (String[] col : cols) {
                if (columnType(getConnection(), "domains", col[0]) == null) {
                    stmt.executeUpdate(col[1]);
                    System.out.println("Added " + col[0] + " column to domains table");
                }
            }
        } catch (SQLException e) {
            System.err.println("Error ensuring DKIM rotation columns: " + e.getMessage());
        }
    }

    /**
     * Ensure cloudflare_accounts table + domains.cloudflare_account_id column exist.
     * Also migrates the legacy token (panel_settings.cloudflare_api_token) by creating an
     * account `Account principale` (main account) and linking it to all existing domains.
     */
    public void ensureCloudflareAccountsSchema() {
        try (Statement stmt = getConnection().createStatement()) {
            // 1) tabella cloudflare_accounts
            stmt.execute(SqlCatalog.MAIL_ENSURE_CLOUDFLARE_ACCOUNTS_SCHEMA);

            // 2) column domains.cloudflare_account_id
            ResultSet rs = stmt.executeQuery(SqlCatalog.MAIL_ENSURE_CLOUDFLARE_ACCOUNTS_SCHEMA_2);
            if (rs.next() && rs.getInt(1) == 0) {
                stmt.executeUpdate(SqlCatalog.MAIL_ENSURE_CLOUDFLARE_ACCOUNTS_SCHEMA_3);
                System.out.println("Added cloudflare_account_id column to domains table");
            }

            // 3) legacy token migration
            String legacyToken = getSetting("cloudflare_api_token", "");
            String legacyEnabled = getSetting("cloudflare_enabled", "0");
            if (!legacyToken.isEmpty() && "1".equals(legacyEnabled)) {
                // Check that there are no accounts yet: if the table is empty, import
                ResultSet cnt = stmt.executeQuery(SqlCatalog.MAIL_ENSURE_CLOUDFLARE_ACCOUNTS_SCHEMA_4);
                if (cnt.next() && cnt.getInt(1) == 0) {
                    try (PreparedStatement ins = getConnection().prepareStatement(SqlCatalog.MAIL_ENSURE_CLOUDFLARE_ACCOUNTS_SCHEMA_5,
                        Statement.RETURN_GENERATED_KEYS)) {
                        ins.setString(1, "Account principale");
                        ins.setString(2, org.daemoxcp.mail.security.CloudflareTokens.seal(legacyToken));
                        ins.executeUpdate();
                        ResultSet gk = ins.getGeneratedKeys();
                        if (gk.next()) {
                            int newId = gk.getInt(1);
                            // Link all existing domains to this account (preserves the behaviour)
                            try (PreparedStatement upd = getConnection().prepareStatement(SqlCatalog.MAIL_ENSURE_CLOUDFLARE_ACCOUNTS_SCHEMA_6)) {
                                upd.setInt(1, newId);
                                int affected = upd.executeUpdate();
                                System.out.println("Migrated legacy Cloudflare token to account '" + newId
                                    + "', assigned to " + affected + " domain(s)");
                            }
                        }
                    }
                    // Delete the legacy setting so it is no longer reused
                    deleteSetting("cloudflare_api_token");
                    deleteSetting("cloudflare_enabled");
                }
            }
        } catch (SQLException e) {
            System.err.println("Error ensuring cloudflare accounts schema: " + e.getMessage());
        }
    }

    /**
     * Ensure dkim_rotation_history table exists (idempotent).
     */
    public void ensureDkimRotationHistoryTable() {
        try (Statement stmt = getConnection().createStatement()) {
            stmt.execute(SqlCatalog.MAIL_ENSURE_DKIM_ROTATION_HISTORY_TABLE);
            // Migration: add triggered_by if the table already exists without that field
            ResultSet rs = stmt.executeQuery(SqlCatalog.MAIL_ENSURE_DKIM_ROTATION_HISTORY_TABLE_2);
            if (rs.next() && rs.getInt(1) == 0) {
                stmt.executeUpdate(SqlCatalog.MAIL_ENSURE_DKIM_ROTATION_HISTORY_TABLE_3);
                System.out.println("Added triggered_by column to dkim_rotation_history table");
            }
            // Migration: add previous_selector if the table already exists without that field
            ResultSet rs2 = stmt.executeQuery(SqlCatalog.MAIL_ENSURE_DKIM_ROTATION_HISTORY_TABLE_4);
            if (rs2.next() && rs2.getInt(1) == 0) {
                stmt.executeUpdate(SqlCatalog.MAIL_ENSURE_DKIM_ROTATION_HISTORY_TABLE_5);
                stmt.executeUpdate(SqlCatalog.MAIL_ENSURE_DKIM_ROTATION_HISTORY_TABLE_6);
                System.out.println("Added previous_selector column + index to dkim_rotation_history table");
            }
        } catch (SQLException e) {
            System.err.println("Error ensuring dkim_rotation_history table: " + e.getMessage());
        }
    }

    /**
     * Records an event of the DKIM rotation workflow.
     * @param triggeredBy "user" if started by clicking a button, "scheduler" if by the automatic timer,
     *                    null for events not explicitly started (checks, propagation, etc.)
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
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_LOG_DKIM_ROTATION_EVENT)) {
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
     * Finds the most recent deactivation timestamp of a selector for a domain.
     * A selector is considered "deactivated" at the moment of a key_activated event where
     * it appears as previous_selector (that is, when a new key replaced it).
     *
     * Returns null if the selector was never recorded as deactivated (probably
     * it had never been the active selector in the panel).
     */
    public Timestamp findSelectorDeactivationTime(int domainId, String selector) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_FIND_SELECTOR_DEACTIVATION_TIME)) {
            stmt.setInt(1, domainId);
            stmt.setString(2, selector);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) return rs.getTimestamp("occurred_at");
            }
        }
        return null;
    }

    /**
     * History of DKIM rotation events for a domain, most recent first.
     */
    public List<DkimRotationEvent> getDkimRotationHistory(int domainId, int limit) throws SQLException {
        List<DkimRotationEvent> result = new ArrayList<>();
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_GET_DKIM_ROTATION_HISTORY)) {
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
        public String previousSelector;  // set for key_activated (old selector that was replaced)
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
            ResultSet rs = stmt.executeQuery(SqlCatalog.MAIL_ENSURE_THEME_COLUMN);
            if (rs.next() && rs.getInt(1) == 0) {
                stmt.executeUpdate(SqlCatalog.MAIL_ENSURE_THEME_COLUMN_2);
                System.out.println("Added theme column to panel_admin table");
            }
        } catch (SQLException e) {
            System.err.println("Error ensuring theme column: " + e.getMessage());
        }
    }

    // ========== SETTINGS MANAGEMENT ==========

    public String getSetting(String key, String defaultValue) {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_GET_SETTING)) {
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
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_SET_SETTING)) {
            stmt.setString(1, key);
            stmt.setString(2, value);
            stmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("Failed to set setting: " + e.getMessage());
        }
    }

    public void deleteSetting(String key) {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_DELETE_SETTING)) {
            stmt.setString(1, key);
            stmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("Failed to delete setting: " + e.getMessage());
        }
    }

    // ========== CLOUDFLARE ACCOUNTS MANAGEMENT ==========

    public int addCloudflareAccount(String label, String email, String apiToken) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_ADD_CLOUDFLARE_ACCOUNT, Statement.RETURN_GENERATED_KEYS)) {
            stmt.setString(1, label);
            if (email == null || email.isEmpty()) stmt.setNull(2, Types.VARCHAR); else stmt.setString(2, email);
            // Encrypted: a Cloudflare token writes the DNS of all zones (CloudflareTokens)
            stmt.setString(3, org.daemoxcp.mail.security.CloudflareTokens.seal(apiToken));
            stmt.executeUpdate();
            try (ResultSet rs = stmt.getGeneratedKeys()) {
                if (rs.next()) return rs.getInt(1);
            }
        }
        return -1;
    }

    public boolean updateCloudflareAccount(int id, String label, String email) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_UPDATE_CLOUDFLARE_ACCOUNT)) {
            stmt.setString(1, label);
            if (email == null || email.isEmpty()) stmt.setNull(2, Types.VARCHAR); else stmt.setString(2, email);
            stmt.setInt(3, id);
            return stmt.executeUpdate() > 0;
        }
    }

    public boolean updateCloudflareAccountToken(int id, String newToken) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_UPDATE_CLOUDFLARE_ACCOUNT_TOKEN)) {
            stmt.setString(1, org.daemoxcp.mail.security.CloudflareTokens.seal(newToken));
            stmt.setInt(2, id);
            return stmt.executeUpdate() > 0;
        }
    }

    public boolean deleteCloudflareAccount(int id) throws SQLException {
        // First unlink the domains, then delete the account
        try (PreparedStatement upd = getConnection().prepareStatement(SqlCatalog.MAIL_DELETE_CLOUDFLARE_ACCOUNT)) {
            upd.setInt(1, id);
            upd.executeUpdate();
        }
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_DELETE_CLOUDFLARE_ACCOUNT_2)) {
            stmt.setInt(1, id);
            return stmt.executeUpdate() > 0;
        }
    }

    public CloudflareAccount getCloudflareAccount(int id) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_GET_CLOUDFLARE_ACCOUNT)) {
            stmt.setInt(1, id);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) return mapCloudflareAccount(rs);
            }
        }
        return null;
    }

    public List<CloudflareAccount> listCloudflareAccounts() throws SQLException {
        List<CloudflareAccount> result = new ArrayList<>();
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_LIST_CLOUDFLARE_ACCOUNTS);
             ResultSet rs = stmt.executeQuery()) {
            while (rs.next()) result.add(mapCloudflareAccount(rs));
        }
        return result;
    }

    /** Returns the CF account assigned to a domain, or null. */
    public CloudflareAccount getCloudflareAccountForDomain(int domainId) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_GET_CLOUDFLARE_ACCOUNT_FOR_DOMAIN)) {
            stmt.setInt(1, domainId);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) return mapCloudflareAccount(rs);
            }
        }
        return null;
    }

    /** The tokens as they are in the database (id, value), for their migration: CloudflareTokens.ensureAtBoot. */
    public List<String[]> cloudflareStoredTokens() throws SQLException {
        List<String[]> out = new ArrayList<>();
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_LIST_CLOUDFLARE_STORED_TOKENS);
             ResultSet rs = stmt.executeQuery()) {
            while (rs.next()) out.add(new String[] {String.valueOf(rs.getInt("id")), rs.getString("api_token")});
        }
        return out;
    }

    /** The encrypted token in place of the clear-text one, only if the row still has that one: true if it wrote it. */
    public boolean replaceCloudflareStoredToken(int id, String before, String sealed) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_REPLACE_CLOUDFLARE_STORED_TOKEN)) {
            stmt.setString(1, sealed);
            stmt.setInt(2, id);
            stmt.setString(3, before);
            return stmt.executeUpdate() == 1;
        }
    }

    /** Assigns (or unassigns, by passing 0/-1) an account to a domain. */
    public boolean assignCloudflareAccountToDomain(int domainId, int accountId) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_ASSIGN_CLOUDFLARE_ACCOUNT_TO_DOMAIN)) {
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
        a.apiToken = org.daemoxcp.mail.security.CloudflareTokens.open(a.id, rs.getString("api_token"));
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
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_IS_COMPONENT_INSTALLED)) {
            stmt.setString(1, componentName);
            ResultSet rs = stmt.executeQuery();
            return rs.next();
        } catch (SQLException e) {
            return false;
        }
    }

    public void markComponentInstalled(String componentName, String version) {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_MARK_COMPONENT_INSTALLED)) {
            stmt.setString(1, componentName);
            stmt.setString(2, version);
            stmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("Failed to mark component installed: " + e.getMessage());
        }
    }

    public void markComponentUninstalled(String componentName) {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_MARK_COMPONENT_UNINSTALLED)) {
            stmt.setString(1, componentName);
            stmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("Failed to mark component uninstalled: " + e.getMessage());
        }
    }

    public String getInstalledComponentsJson() {
        StringBuilder json = new StringBuilder("[");
        try (Statement stmt = getConnection().createStatement();
             ResultSet rs = stmt.executeQuery(SqlCatalog.MAIL_GET_INSTALLED_COMPONENTS_JSON)) {
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
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_ADD_DOMAIN, Statement.RETURN_GENERATED_KEYS)) {
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
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_DELETE_DOMAIN)) {
            stmt.setInt(1, domainId);
            return stmt.executeUpdate() > 0;
            // Postfix uses MySQL directly - no file sync needed
        }
    }

    public boolean updateDomainStatus(int domainId, boolean active) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_UPDATE_DOMAIN_STATUS)) {
            stmt.setBoolean(1, active);
            stmt.setInt(2, domainId);
            return stmt.executeUpdate() > 0;
            // Postfix uses MySQL directly - no file sync needed
        }
    }

    public boolean updateDomainDescription(int domainId, String description) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_UPDATE_DOMAIN_DESCRIPTION)) {
            stmt.setString(1, description);
            stmt.setInt(2, domainId);
            return stmt.executeUpdate() > 0;
        }
    }

    public Domain getDomain(int domainId) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_GET_DOMAIN)) {
            stmt.setInt(1, domainId);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return mapDomain(rs);
            }
        }
        return null;
    }

    public Domain getDomainByName(String domainName) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_GET_DOMAIN_BY_NAME)) {
            stmt.setString(1, domainName.toLowerCase());
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return mapDomain(rs);
            }
        }
        return null;
    }

    /** The names of the hosted domains, lowercase as they are in the database (autoconfig, MTA-STS: DomainCache). */
    public List<String> getDomainNames() throws SQLException {
        List<String> names = new ArrayList<>();
        try (Statement stmt = getConnection().createStatement();
             ResultSet rs = stmt.executeQuery(SqlCatalog.MAIL_GET_DOMAIN_NAMES)) {
            while (rs.next()) names.add(rs.getString(1));
        }
        return names;
    }

    public List<Domain> getDomains() throws SQLException {
        List<Domain> domains = new ArrayList<>();
        try (Statement stmt = getConnection().createStatement();
             ResultSet rs = stmt.executeQuery(SqlCatalog.MAIL_GET_DOMAINS)) {
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
        d.dkimPublicKey = rs.getString("dkim_public_key");
        // The private keys are there only for the root: the web part's procedures leave them in the database and
        // only say whether the key exists (has_dkim).
        boolean privateKeys = hasColumn(rs, "dkim_private_key");
        d.dkimPrivateKey = privateKeys ? rs.getString("dkim_private_key") : null;
        d.hasDkim = privateKeys ? d.dkimPrivateKey != null && !d.dkimPrivateKey.isEmpty() : rs.getBoolean("has_dkim");
        // Pending rotation
        d.dkimPendingSelector = rs.getString("dkim_pending_selector");
        d.dkimPendingPrivateKey = privateKeys ? rs.getString("dkim_pending_private_key") : null;
        d.dkimPendingPublicKey = rs.getString("dkim_pending_public_key");
        d.dkimRotationState = rs.getString("dkim_rotation_state");
        d.dkimRotationStartedAt = rs.getTimestamp("dkim_rotation_started_at");
        d.dkimRotationActivatedAt = rs.getTimestamp("dkim_rotation_activated_at");
        // Previous key (grace period)
        d.dkimPreviousSelector = rs.getString("dkim_previous_selector");
        d.dkimPreviousPrivateKey = privateKeys ? rs.getString("dkim_previous_private_key") : null;
        d.dkimPreviousPublicKey = rs.getString("dkim_previous_public_key");
        // Cloudflare automation (may not exist on a legacy DB if ensureDkimRotationColumns has not run yet)
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
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_SET_DKIM)) {
            stmt.setString(1, selector);
            stmt.setString(2, privateKey);
            stmt.setString(3, publicKey);
            stmt.setInt(4, domainId);
            stmt.executeUpdate();
        }
    }

    // ========== DKIM ROTATION ==========

    /**
     * Saves a "pending" DKIM key (new selector + keys) and sets the rotation state.
     * The initial state is usually "pending_dns" (the user must add the TXT in DNS).
     */
    public void setDkimPending(int domainId, String pendingSelector, String pendingPrivateKey,
                                String pendingPublicKey, String state) throws SQLException {
        setDkimPending(domainId, pendingSelector, pendingPrivateKey, pendingPublicKey, state, null);
    }

    public void setDkimPending(int domainId, String pendingSelector, String pendingPrivateKey,
                                String pendingPublicKey, String state, String rotationMode) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_SET_DKIM_PENDING)) {
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
     * Updates only the rotation state (e.g. from "pending_dns" to "propagated").
     */
    public void setDkimRotationState(int domainId, String state) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_SET_DKIM_ROTATION_STATE)) {
            stmt.setString(1, state);
            stmt.setInt(2, domainId);
            stmt.executeUpdate();
        }
    }

    /**
     * Promotes the "pending" key to "active":
     *  - current (dkim_*) -> previous (dkim_previous_*)
     *  - pending (dkim_pending_*) -> current (dkim_*)
     *  - pending fields cleared
     *  - state -> "active_grace"
     *  - dkim_rotation_activated_at = NOW
     */
    public void promotePendingToActive(int domainId) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_PROMOTE_PENDING_TO_ACTIVE)) {
            stmt.setTimestamp(1, java.sql.Timestamp.from(java.time.Instant.now()));
            stmt.setInt(2, domainId);
            stmt.executeUpdate();
        }
    }

    /**
     * Saves the Cloudflare metadata of the pending TXT record (zone + record id),
     * so we can delete it via API if the rotation is cancelled or completed.
     */
    public void setDkimPendingCloudflareIds(int domainId, String zoneId, String recordId) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_SET_DKIM_PENDING_CLOUDFLARE_IDS)) {
            stmt.setString(1, zoneId);
            stmt.setString(2, recordId);
            stmt.setInt(3, domainId);
            stmt.executeUpdate();
        }
    }

    /**
     * Cancels a rotation in progress (deletes the pending key without promoting it).
     */
    public void clearDkimPending(int domainId) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_CLEAR_DKIM_PENDING)) {
            stmt.setInt(1, domainId);
            stmt.executeUpdate();
        }
    }

    /**
     * Completes the rotation: removes the previous key and resets the rotation state.
     * After this call the user can remove the old _domainkey TXT record from DNS.
     */
    public void clearDkimPrevious(int domainId) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_CLEAR_DKIM_PREVIOUS)) {
            stmt.setInt(1, domainId);
            stmt.executeUpdate();
        }
    }

    /**
     * Sets the scheduled rotation interval (in days). 0 = disabled.
     */
    public void setDkimRotationInterval(int domainId, int days) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_SET_DKIM_ROTATION_INTERVAL)) {
            stmt.setInt(1, Math.max(0, days));
            stmt.setInt(2, domainId);
            stmt.executeUpdate();
        }
    }

    /**
     * Updates the timestamp of the last rotation (called on key activation).
     * Uses Java Instant.now() (UTC, JVM clock) instead of MySQL CURRENT_TIMESTAMP to avoid
     * timezone ambiguity between MySQL session, JDBC and JVM.
     */
    public void markDkimRotationActivated(int domainId) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_MARK_DKIM_ROTATION_ACTIVATED)) {
            stmt.setTimestamp(1, java.sql.Timestamp.from(java.time.Instant.now()));
            stmt.setInt(2, domainId);
            stmt.executeUpdate();
        }
    }

    /**
     * Forces the timestamp of the last rotation to a specific date (epoch ms).
     * Useful to correct "fossil" values stored before the timezone fix.
     */
    public void setDkimLastRotationAtMs(int domainId, long epochMs) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_MARK_DKIM_ROTATION_ACTIVATED)) {
            stmt.setTimestamp(1, java.sql.Timestamp.from(java.time.Instant.ofEpochMilli(epochMs)));
            stmt.setInt(2, domainId);
            stmt.executeUpdate();
        }
    }

    /**
     * Clears the timestamp of the last rotation (NULL).
     * The UI will show it as "Never done".
     */
    public void clearDkimLastRotation(int domainId) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_CLEAR_DKIM_LAST_ROTATION)) {
            stmt.setInt(1, domainId);
            stmt.executeUpdate();
        }
    }

    /**
     * Domains with scheduled rotation enabled (interval > 0).
     */
    public List<Domain> getDomainsWithRotationSchedule() throws SQLException {
        List<Domain> result = new ArrayList<>();
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_GET_DOMAINS_WITH_ROTATION_SCHEDULE);
             ResultSet rs = stmt.executeQuery()) {
            while (rs.next()) result.add(mapDomain(rs));
        }
        return result;
    }

    /**
     * Returns all the domains with a DKIM rotation in progress
     * (state not null), for the background tasks.
     */
    public List<Domain> getDomainsInRotation() throws SQLException {
        List<Domain> result = new ArrayList<>();
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_GET_DOMAINS_IN_ROTATION);
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

    /** The INSERT of a mailbox on the given connection: on its own, or inside a transaction. */
    private int insertMailbox(Connection c, int domainId, String email, String password, String name, int quotaMb, boolean receiveEnabled) throws SQLException {
        // Hash password with bcrypt (compatible with Dovecot)
        String hashedPassword = BCrypt.hashpw(password, BCrypt.gensalt(12));
        // The encrypted copy the panel shows when needed: without it, the mailbox is not created
        String encryptedPassword = vaultCopy(password);

        try (PreparedStatement stmt = c.prepareStatement(SqlCatalog.MAIL_INSERT_MAILBOX, Statement.RETURN_GENERATED_KEYS)) {
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
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_DELETE_MAILBOX)) {
            stmt.setInt(1, mailboxId);
            return stmt.executeUpdate() > 0;
            // Postfix uses MySQL directly - no file sync needed
        }
    }

    public boolean updateMailboxPassword(int mailboxId, String newPassword) throws SQLException {
        // Bcrypt hash (compatible with Dovecot)
        String hashedPassword = BCrypt.hashpw(newPassword, BCrypt.gensalt(12));
        // Hash and copy change together: an old copy next to a new hash would show the wrong password
        String encryptedPassword = vaultCopy(newPassword);

        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_UPDATE_MAILBOX_PASSWORD)) {
            stmt.setString(1, hashedPassword);
            stmt.setString(2, encryptedPassword);
            stmt.setTimestamp(3, java.sql.Timestamp.from(java.time.Instant.now()));
            stmt.setInt(4, mailboxId);
            return stmt.executeUpdate() > 0;
        }
    }

    /**
     * The encrypted copy (vault) of a mailbox password. Mailbox passwords must
     * always be viewable again from the panel: if the vault does not encrypt, the password is not saved at all,
     * instead of saving the hash alone and finding out later that the copy is missing.
     */
    private static String vaultCopy(String password) throws SQLException {
        try {
            return org.daemoxcp.mail.security.PasswordVault.getInstance().encrypt(password);
        } catch (RuntimeException e) {
            throw new SQLException("Mailbox password not saved: the password vault could not encrypt it", e);
        }
    }

    /**
     * A bcrypt hash as written by the panel ($2a$) and by doveadm pw ($2y$, $2b$, also with {BLF-CRYPT} in front).
     * Public because DovecotMasterUser needs it too, for the master user's hash in master-users.
     */
    public static String bcryptPart(String stored) {
        if (stored == null) return null;
        String s = stored;
        if (s.startsWith("{BLF-CRYPT}")) s = s.substring("{BLF-CRYPT}".length());
        else if (s.startsWith("{BLF}")) s = s.substring("{BLF}".length());
        if (s.length() == 60 && (s.startsWith("$2a$") || s.startsWith("$2b$") || s.startsWith("$2y$"))) {
            return "$2a$" + s.substring(4);     // jBCrypt 0.4 knows only $2a$: for passwords up to 72 bytes they are the same algorithm
        }
        return null;
    }

    /**
     * The value of the password column is clear text: no bcrypt hash and no Dovecot {NAME}
     * scheme in front. It happened when the webmail wrote into the table by itself with
     * the default algorithm of Roundcube's password plugin ('clear').
     */
    static boolean isPlaintextPassword(String stored) {
        return stored != null && !stored.isEmpty() && bcryptPart(stored) == null && !stored.startsWith("{");
    }

    /**
     * Is the given password the mailbox's password now? Compares with the bcrypt hash of the password
     * column (or, for a row left in clear text, compares in constant time). An unknown
     * scheme answers false: better to say "I don't know" than to show a wrong password.
     */
    public boolean mailboxPasswordMatches(int mailboxId, String plain) throws SQLException {
        if (plain == null) return false;
        String stored = null;
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_MAILBOX_PASSWORD_MATCHES)) {
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
     * The vault has a copy of a correct password but the mailbox does not (mailboxes from before the
     * vault): adds it, only if the password matches the current hash. It serves those who log in
     * from the webmail, which is the only moment the real password passes through the server.
     * Returns true if it wrote the copy.
     */
    public boolean fillMissingVaultCopy(int mailboxId, String plain) throws SQLException {
        if (!mailboxPasswordMatches(mailboxId, plain)) return false;
        String current = getMailboxPasswordEncrypted(mailboxId);
        if (current != null && !current.isEmpty()) {
            try {
                if (plain.equals(org.daemoxcp.mail.security.PasswordVault.getInstance().decrypt(current))) return false;
            } catch (RuntimeException e) {
                // unreadable copy (key changed or blob damaged): it is rewritten
            }
        }
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_FILL_MISSING_VAULT_COPY)) {
            stmt.setString(1, vaultCopy(plain));
            stmt.setTimestamp(2, java.sql.Timestamp.from(java.time.Instant.now()));
            stmt.setInt(3, mailboxId);
            return stmt.executeUpdate() > 0;
        }
    }

    /**
     * The rows with the password in clear text (see isPlaintextPassword): the bcrypt hash in place of the
     * text, and the copy in the vault. Dovecot reads BLF-CRYPT: with clear text those mailboxes
     * could no longer log in. Returns how many rows it fixed; never the passwords in the log.
     */
    public int repairPlaintextMailboxPasswords() throws SQLException {
        java.util.List<Object[]> rows = new java.util.ArrayList<>();
        try (Statement stmt = getConnection().createStatement();
             ResultSet rs = stmt.executeQuery(SqlCatalog.MAIL_REPAIR_PLAINTEXT_MAILBOX_PASSWORDS)) {
            while (rs.next()) {
                String stored = rs.getString(2);
                if (isPlaintextPassword(stored)) rows.add(new Object[]{rs.getInt(1), stored});
            }
        }
        int repaired = 0;
        for (Object[] row : rows) {
            String plain = (String) row[1];
            try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_REPAIR_PLAINTEXT_MAILBOX_PASSWORDS_2)) {
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
     * Retrieves the encrypted password of a mailbox (for the "reveal password" feature).
     * Returns null if there is no encrypted password (old pre-vault mailboxes, or vault not
     * working at the time of the set).
     */
    public String getMailboxPasswordEncrypted(int mailboxId) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_GET_MAILBOX_PASSWORD_ENCRYPTED)) {
            stmt.setInt(1, mailboxId);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) return rs.getString("password_encrypted");
            }
        }
        return null;
    }

    /**
     * Returns true if the mailbox has a stored encrypted password.
     * Used by the UI to decide whether to show the "reveal" icon.
     */
    public boolean mailboxHasEncryptedPassword(int mailboxId) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_MAILBOX_HAS_ENCRYPTED_PASSWORD)) {
            stmt.setInt(1, mailboxId);
            try (ResultSet rs = stmt.executeQuery()) {
                return rs.next();
            }
        }
    }

    /**
     * Lists all the mailboxes that have a stored encrypted password, returning
     * only id + encrypted blob. Used for the master key rotation.
     */
    public java.util.List<int[]> listMailboxesWithEncryptedPassword() throws SQLException {
        // Simple wrapper: we return pairs (id, ?) but the blobs will be needed too.
        // Use the more complete variant below.
        java.util.List<int[]> ids = new java.util.ArrayList<>();
        try (Statement stmt = getConnection().createStatement();
             ResultSet rs = stmt.executeQuery(SqlCatalog.MAIL_LIST_MAILBOXES_WITH_ENCRYPTED_PASSWORD)) {
            while (rs.next()) ids.add(new int[]{rs.getInt(1)});
        }
        return ids;
    }

    /**
     * Variant with the encrypted blob: returns (id, encrypted_blob) for every mailbox with a vault.
     */
    public java.util.List<Object[]> listMailboxesWithEncryptedPasswordAndBlob() throws SQLException {
        java.util.List<Object[]> rows = new java.util.ArrayList<>();
        try (Statement stmt = getConnection().createStatement();
             ResultSet rs = stmt.executeQuery(SqlCatalog.MAIL_LIST_MAILBOXES_WITH_ENCRYPTED_PASSWORD_AND_BLOB)) {
            while (rs.next()) {
                rows.add(new Object[]{rs.getInt(1), rs.getString(2)});
            }
        }
        return rows;
    }

    /**
     * Updates ONLY the encrypted blob of a mailbox (used during the master key rotation,
     * where we do not regenerate bcrypt -- the password logically stays the same).
     */
    public void setMailboxEncryptedPasswordOnly(int mailboxId, String newEncryptedBlob) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_FILL_MISSING_VAULT_COPY)) {
            stmt.setString(1, newEncryptedBlob);
            stmt.setTimestamp(2, java.sql.Timestamp.from(java.time.Instant.now()));
            stmt.setInt(3, mailboxId);
            stmt.executeUpdate();
        }
    }

    public boolean updateMailboxStatus(int mailboxId, boolean active) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_UPDATE_MAILBOX_STATUS)) {
            stmt.setBoolean(1, active);
            stmt.setInt(2, mailboxId);
            return stmt.executeUpdate() > 0;
            // Postfix uses MySQL directly - no file sync needed
        }
    }

    public boolean updateMailboxQuota(int mailboxId, int quotaMb) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_UPDATE_MAILBOX_QUOTA)) {
            stmt.setInt(1, quotaMb);
            stmt.setInt(2, mailboxId);
            return stmt.executeUpdate() > 0;
        }
    }

    /**
     * Update mailbox receive_enabled status (no-reply toggle)
     */
    public boolean updateMailboxReceiveEnabled(int mailboxId, boolean receiveEnabled) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_UPDATE_MAILBOX_RECEIVE_ENABLED)) {
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
    public boolean updateMailbox(int mailboxId, String name, int quotaMb, boolean active, boolean receiveEnabled,
                                 int junkExpungeDays, int trashExpungeDays) throws SQLException {
        if (!cleanupDaysAllowed(junkExpungeDays) || !cleanupDaysAllowed(trashExpungeDays))
            throw new IllegalArgumentException("cleanup days not allowed");
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_UPDATE_MAILBOX)) {
            stmt.setString(1, name);
            stmt.setInt(2, quotaMb);
            stmt.setBoolean(3, active);
            stmt.setBoolean(4, receiveEnabled);
            stmt.setInt(5, junkExpungeDays);
            stmt.setInt(6, trashExpungeDays);
            stmt.setInt(7, mailboxId);
            return stmt.executeUpdate() > 0;
        }
    }

    /**
     * The days that can be chosen for the automatic emptying of Junk and Trash: 0 = never (the default,
     * it is turned on only on request). The same list for the panel and for the webmail (plugin daemoxcp_mail_cleanup).
     */
    public static final java.util.List<Integer> CLEANUP_DAYS = java.util.List.of(0, 7, 14, 30, 60, 90);

    public static boolean cleanupDaysAllowed(int days) {
        return CLEANUP_DAYS.contains(days);
    }

    /**
     * The webmail for its own mailbox (Roundcube's internal route, root only): the days for Junk and Trash.
     * False if the mailbox does not exist or is not active.
     */
    public boolean setMailboxCleanup(String email, int junkExpungeDays, int trashExpungeDays) throws SQLException {
        if (!cleanupDaysAllowed(junkExpungeDays) || !cleanupDaysAllowed(trashExpungeDays))
            throw new IllegalArgumentException("cleanup days not allowed");
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_UPDATE_MAILBOX_CLEANUP)) {
            stmt.setInt(1, junkExpungeDays);
            stmt.setInt(2, trashExpungeDays);
            stmt.setString(3, email.toLowerCase(java.util.Locale.ROOT));
            return stmt.executeUpdate() > 0;
        }
    }

    /** The two columns of the automatic emptying, on earlier installations (0 = never). */
    public void ensureMailboxCleanupColumns() {
        String[][] cols = {
            {"junk_expunge_days", SqlCatalog.MAIL_ADD_MAILBOXES_JUNK_EXPUNGE_DAYS},
            {"trash_expunge_days", SqlCatalog.MAIL_ADD_MAILBOXES_TRASH_EXPUNGE_DAYS}
        };
        try (Statement stmt = getConnection().createStatement()) {
            for (String[] col : cols) {
                if (columnType(getConnection(), "mailboxes", col[0]) == null) {
                    stmt.executeUpdate(col[1]);
                    LOGGER.info("Added the " + col[0] + " column to mailboxes (automatic emptying, off until asked)");
                }
            }
        } catch (SQLException e) {
            LOGGER.log(Level.WARNING, "Cannot add the automatic emptying columns to mailboxes", e);
        }
    }

    /**
     * Ensure mailbox password vault columns exist (idempotent).
     * Adds password_encrypted (TEXT) + password_encrypted_at (TIMESTAMP).
     * New passwords created/updated from the UI will be encrypted and stored here.
     */
    public void ensureMailboxPasswordVaultColumns() {
        String[][] cols = {
            {"password_encrypted",     SqlCatalog.MAIL_ADD_MAILBOXES_PASSWORD_ENCRYPTED},
            {"password_encrypted_at",  SqlCatalog.MAIL_ADD_MAILBOXES_PASSWORD_ENCRYPTED_AT}
        };
        try (Statement stmt = getConnection().createStatement()) {
            for (String[] col : cols) {
                if (columnType(getConnection(), "mailboxes", col[0]) == null) {
                    stmt.executeUpdate(col[1]);
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
            ResultSet rs = stmt.executeQuery(SqlCatalog.MAIL_ENSURE_MAILBOX_RECEIVE_ENABLED_COLUMN);
            if (rs.next() && rs.getInt(1) == 0) {
                // Column doesn't exist, add it
                stmt.executeUpdate(SqlCatalog.MAIL_ENSURE_MAILBOX_RECEIVE_ENABLED_COLUMN_2);
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
            org.daemoxcp.mail.util.Shell.applyPath(pb);
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
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_GET_MAILBOX)) {
            stmt.setInt(1, mailboxId);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return mapMailbox(rs);
            }
        }
        return null;
    }

    public Mailbox getMailboxByEmail(String email) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_GET_MAILBOX_BY_EMAIL)) {
            stmt.setString(1, email.toLowerCase());
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return mapMailbox(rs);
            }
        }
        return null;
    }

    public Mailbox getMailboxById(int id) {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_GET_MAILBOX)) {
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
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_GET_MAILBOXES)) {
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
        try (Statement stmt = getConnection().createStatement();
             ResultSet rs = stmt.executeQuery(SqlCatalog.MAIL_GET_ALL_MAILBOXES)) {
            while (rs.next()) {
                mailboxes.add(mapMailbox(rs));
            }
        }
        return mailboxes;
    }

    /** Does the result have this column? */
    private static boolean hasColumn(ResultSet rs, String name) throws SQLException {
        java.sql.ResultSetMetaData md = rs.getMetaData();
        for (int i = 1; i <= md.getColumnCount(); i++) {
            if (name.equalsIgnoreCase(md.getColumnLabel(i))) return true;
        }
        return false;
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
        // The automatic emptying: 0 = never, even when the columns are not there yet
        m.junkExpungeDays = hasColumn(rs, "junk_expunge_days") ? rs.getInt("junk_expunge_days") : 0;
        m.trashExpungeDays = hasColumn(rs, "trash_expunge_days") ? rs.getInt("trash_expunge_days") : 0;
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

    // ========== ALIAS <-> MAILBOX ==========

    /**
     * An address that today is only an alias becomes a mailbox, in a transaction: for Postfix,
     * which reads the tables at every message, it goes from "alias" to "mailbox" without an instant in
     * between in which the address does not exist or counts both ways.
     *
     * @param keepForwards false: the rows with this source go away and the mail stays in the
     *                     mailbox; true: they stay, and an active "address -> itself" alias makes
     *                     a copy arrive in the mailbox too
     * @return the id of the new mailbox
     */
    public int transformAliasToMailbox(int domainId, String email, String password, String name, int quotaMb,
                                       boolean keepForwards) throws SQLException {
        try (Connection c = ownConnection()) {
            c.setAutoCommit(false);
            try {
                int id = insertMailbox(c, domainId, email, password, name, quotaMb, true);
                if (id <= 0) throw new SQLException("the mailbox was not created");
                if (keepForwards) {
                    try (PreparedStatement p = c.prepareStatement(SqlCatalog.MAIL_TRANSFORM_ALIAS_TO_MAILBOX)) {
                        p.setInt(1, domainId);
                        p.setString(2, email.toLowerCase());
                        p.setString(3, email.toLowerCase());
                        p.executeUpdate();
                    }
                } else {
                    try (PreparedStatement p = c.prepareStatement(SqlCatalog.MAIL_TRANSFORM_ALIAS_TO_MAILBOX_2)) {
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
     * A mailbox becomes an alias to the given destinations, in a transaction. Gone are the
     * mailbox (and with it, through the foreign keys, auto-reply, filters, forwards, webmail
     * tokens), its sending limit and the "itself -> itself" alias: without a mailbox it would lead
     * to an address that does not exist. The other aliases with this source stay. The mail already
     * arrived is not in the database: it stays on disk.
     */
    public void transformMailboxToAlias(int mailboxId, int domainId, String email, List<String> destinations) throws SQLException {
        String address = email.toLowerCase();
        try (Connection c = ownConnection()) {
            c.setAutoCommit(false);
            try {
                try (PreparedStatement p = c.prepareStatement(SqlCatalog.MAIL_TRANSFORM_ALIAS_TO_MAILBOX)) {
                    for (String d : destinations) {
                        p.setInt(1, domainId);
                        p.setString(2, address);
                        p.setString(3, d.toLowerCase());
                        p.executeUpdate();
                    }
                }
                try (PreparedStatement p = c.prepareStatement(SqlCatalog.MAIL_TRANSFORM_MAILBOX_TO_ALIAS)) {
                    p.setString(1, address);
                    p.setString(2, address);
                    p.executeUpdate();
                }
                try (PreparedStatement p = c.prepareStatement(SqlCatalog.MAIL_TRANSFORM_MAILBOX_TO_ALIAS_2)) {
                    p.setInt(1, mailboxId);
                    p.executeUpdate();
                }
                try (PreparedStatement p = c.prepareStatement(SqlCatalog.MAIL_TRANSFORM_MAILBOX_TO_ALIAS_3)) {
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

    /** The aliases with this source, active or not. */
    public List<Alias> getAliasesBySource(String source) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_GET_ALIASES_BY_SOURCE)) {
            stmt.setString(1, source.toLowerCase());
            return aliasWithDomain(stmt);
        }
    }

    /** The aliases that lead to this address, from any domain. */
    public List<Alias> getAliasesByDestination(String destination) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_GET_ALIASES_BY_DESTINATION)) {
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
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_ADD_ALIAS, Statement.RETURN_GENERATED_KEYS)) {
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
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_DELETE_ALIAS)) {
            stmt.setInt(1, aliasId);
            return stmt.executeUpdate() > 0;
            // Postfix uses MySQL directly - no file sync needed
        }
    }

    /**
     * Changes the destination of an alias with a single UPDATE: no moment in which the source
     * is left without an alias, as would happen by deleting and recreating. A source ->
     * destination pair that already exists triggers the UNIQUE constraint (SQLIntegrityConstraintViolationException).
     */
    public boolean updateAliasDestination(int aliasId, String destination) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_UPDATE_ALIAS_DESTINATION)) {
            stmt.setString(1, destination.toLowerCase());
            stmt.setInt(2, aliasId);
            return stmt.executeUpdate() > 0;
        }
    }

    /** An alias by id, or null if there is none. */
    public Alias getAliasById(int aliasId) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_GET_ALIAS_BY_ID)) {
            stmt.setInt(1, aliasId);
            try (ResultSet rs = stmt.executeQuery()) {
                return rs.next() ? mapAlias(rs) : null;
            }
        }
    }

    public boolean updateAliasStatus(int aliasId, boolean active) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_UPDATE_ALIAS_STATUS)) {
            stmt.setBoolean(1, active);
            stmt.setInt(2, aliasId);
            return stmt.executeUpdate() > 0;
            // Postfix uses MySQL directly - no file sync needed
        }
    }

    public List<Alias> getAliases(int domainId) throws SQLException {
        List<Alias> aliases = new ArrayList<>();
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_GET_ALIASES)) {
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
        try (Statement stmt = getConnection().createStatement();
             ResultSet rs = stmt.executeQuery(SqlCatalog.MAIL_GET_ALL_ALIASES)) {
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
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_CREATE_AUTO_LOGIN_TOKEN)) {
            stmt.setString(1, token);
            stmt.setInt(2, mailboxId);
            stmt.executeUpdate();
            return token;
        }
    }

    public Mailbox validateAutoLoginToken(String token) throws SQLException {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_VALIDATE_AUTO_LOGIN_TOKEN)) {
            stmt.setString(1, token);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                // Mark token as used
                try (PreparedStatement update = getConnection().prepareStatement(SqlCatalog.MAIL_VALIDATE_AUTO_LOGIN_TOKEN_2)) {
                    update.setString(1, token);
                    update.executeUpdate();
                }
                return mapMailbox(rs);
            }
        }
        return null;
    }

    public void cleanupExpiredTokens() throws SQLException {
        try (Statement stmt = getConnection().createStatement()) {
            stmt.executeUpdate(SqlCatalog.MAIL_CLEANUP_EXPIRED_TOKENS);
        }
    }

    // ========== STATISTICS ==========

    public int getDomainCount() {
        return getCount(SqlCatalog.MAIL_COUNT_ACTIVE_DOMAINS);
    }

    public int getMailboxCount() {
        return getCount(SqlCatalog.MAIL_COUNT_ACTIVE_MAILBOXES);
    }

    public int getAliasCount() {
        return getCount(SqlCatalog.MAIL_COUNT_ACTIVE_ALIASES);
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

    /** The version of the MySQL server the panel is connected to now (SELECT VERSION()), or null. */
    public String serverVersion() {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_SERVER_VERSION);
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
        // DKIM rotation - pending key (waiting for DNS propagation)
        public String dkimPendingSelector;
        public String dkimPendingPrivateKey;
        public String dkimPendingPublicKey;
        // Rotation state: null (none), "pending_dns", "propagated", "active_grace"
        public String dkimRotationState;
        public Timestamp dkimRotationStartedAt;
        public Timestamp dkimRotationActivatedAt;
        // Old key kept during the grace period
        public String dkimPreviousSelector;
        public String dkimPreviousPrivateKey;
        public String dkimPreviousPublicKey;
        // Cloudflare automation
        public String dkimDnsZoneId;
        public String dkimPendingDnsRecordId;
        public String dkimPreviousDnsRecordId;
        // Assigned Cloudflare account (0 = none / manual)
        public int cloudflareAccountId;
        // Scheduled rotation (0 = disabled)
        public int dkimRotationIntervalDays;
        public Timestamp dkimLastRotationAt;
        // Current rotation mode (inherited from events of the chain)
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
        public int junkExpungeDays;     // after how many days Dovecot empties Junk; 0 = never
        public int trashExpungeDays;    // after how many days Dovecot empties Trash; 0 = never
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
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_GET_AUTO_RESPONDER)) {
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
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_SAVE_AUTO_RESPONDER)) {
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
        try (Statement stmt = getConnection().createStatement();
             ResultSet rs = stmt.executeQuery(SqlCatalog.MAIL_GET_ACTIVE_AUTO_RESPONDERS)) {
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
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_GET_SIEVE_FILTERS)) {
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

    /** A single filter, with its mailbox; null if there is none (or the database does not answer). */
    public SieveFilter getSieveFilter(int filterId) {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_GET_SIEVE_FILTER)) {
            stmt.setInt(1, filterId);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                SieveFilter f = new SieveFilter();
                f.id = rs.getInt("id");
                f.mailboxId = rs.getInt("mailbox_id");
                f.email = rs.getString("email");
                f.name = rs.getString("name");
                f.priority = rs.getInt("priority");
                f.enabled = rs.getBoolean("enabled");
                f.conditions = rs.getString("conditions");
                f.actions = rs.getString("actions");
                return f;
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }

    public boolean createSieveFilter(int mailboxId, String name, int priority, boolean enabled, String conditions, String actions) {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_CREATE_SIEVE_FILTER)) {
            stmt.setInt(1, mailboxId);
            stmt.setString(2, name);
            stmt.setInt(3, priority);
            stmt.setBoolean(4, enabled);
            stmt.setString(5, conditions);
            stmt.setString(6, actions);
            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }

    public boolean updateSieveFilter(int filterId, String name, int priority, boolean enabled, String conditions, String actions) {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_UPDATE_SIEVE_FILTER)) {
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
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_DELETE_SIEVE_FILTER)) {
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
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_GET_FORWARDING_RULES)) {
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

    /** A single forward, with its mailbox; null if there is none (or the database does not answer). */
    public ForwardingRule getForwardingRule(int ruleId) {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_GET_FORWARDING_RULE)) {
            stmt.setInt(1, ruleId);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                ForwardingRule r = new ForwardingRule();
                r.id = rs.getInt("id");
                r.mailboxId = rs.getInt("mailbox_id");
                r.email = rs.getString("email");
                r.destination = rs.getString("destination");
                r.keepCopy = rs.getBoolean("keep_copy");
                r.enabled = rs.getBoolean("enabled");
                return r;
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }

    public boolean createForwardingRule(int mailboxId, String destination, boolean keepCopy) {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_CREATE_FORWARDING_RULE)) {
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
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_UPDATE_FORWARDING_RULE)) {
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
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_DELETE_FORWARDING_RULE)) {
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
        try (Statement stmt = getConnection().createStatement();
             ResultSet rs = stmt.executeQuery(SqlCatalog.MAIL_GET_RATE_LIMITS)) {
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
     * Saves a sending limit, updating the row that already exists for the same target.
     *
     * The global limit has target_id 0 and not NULL: in MySQL's UNIQUE index (target_type, target_id)
     * two NULLs are not equal, and every save of the global limits added a row
     * instead of updating the one that was there. The global rows with NULL left from before are removed
     * in the same transaction.
     */
    public boolean saveRateLimit(String targetType, Integer targetId, int maxPerHour, int maxPerDay, int maxRecipients, boolean enabled) {
        boolean global = "global".equals(targetType);
        if (!global && targetId == null) return false;
        try (Connection c = ownConnection()) {
            c.setAutoCommit(false);
            try {
                try (PreparedStatement stmt = c.prepareStatement(SqlCatalog.MAIL_SAVE_RATE_LIMIT)) {
                    stmt.setString(1, targetType);
                    stmt.setInt(2, global ? 0 : targetId);
                    stmt.setInt(3, maxPerHour);
                    stmt.setInt(4, maxPerDay);
                    stmt.setInt(5, maxRecipients);
                    stmt.setBoolean(6, enabled);
                    stmt.executeUpdate();
                }
                if (global) {
                    try (PreparedStatement stmt = c.prepareStatement(SqlCatalog.MAIL_SAVE_RATE_LIMIT_2)) {
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
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_DELETE_RATE_LIMIT)) {
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
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_GET_EMAIL_STATISTICS)) {
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
        try (Statement stmt = getConnection().createStatement();
             ResultSet rs = stmt.executeQuery(SqlCatalog.MAIL_GET_TODAY_STATS)) {
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
        // One fixed statement per type: the columns are not parameters.
        String sql = switch (statType) {
            case "sent" -> SqlCatalog.MAIL_ADD_STAT_SENT;
            case "received" -> SqlCatalog.MAIL_ADD_STAT_RECEIVED;
            case "spam" -> SqlCatalog.MAIL_ADD_STAT_SPAM;
            case "virus" -> SqlCatalog.MAIL_ADD_STAT_VIRUS;
            case "bounced" -> SqlCatalog.MAIL_ADD_STAT_BOUNCED;
            default -> null;
        };
        if (sql == null) return;

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

    /**
     * Like {@link #incrementEmailStat}, on the given day (UTC): that of the message read from Postfix's log
     * (MailLogStats), not the one on which it is counted. True if MySQL wrote it.
     */
    public boolean incrementEmailStatOn(java.time.LocalDate day, Integer mailboxId, Integer domainId, String statType, int count, long bytes) {
        String sql = switch (statType) {
            case "sent" -> SqlCatalog.MAIL_ADD_STAT_SENT_ON;
            case "received" -> SqlCatalog.MAIL_ADD_STAT_RECEIVED_ON;
            case "spam" -> SqlCatalog.MAIL_ADD_STAT_SPAM_ON;
            case "virus" -> SqlCatalog.MAIL_ADD_STAT_VIRUS_ON;
            case "bounced" -> SqlCatalog.MAIL_ADD_STAT_BOUNCED_ON;
            default -> null;
        };
        if (sql == null || day == null) return false;
        try (PreparedStatement stmt = getConnection().prepareStatement(sql)) {
            stmt.setDate(1, java.sql.Date.valueOf(day));
            if (mailboxId != null) stmt.setInt(2, mailboxId); else stmt.setNull(2, java.sql.Types.INTEGER);
            if (domainId != null) stmt.setInt(3, domainId); else stmt.setNull(3, java.sql.Types.INTEGER);
            stmt.setInt(4, count);
            stmt.setLong(5, bytes);
            stmt.setInt(6, count);
            stmt.setLong(7, bytes);
            stmt.executeUpdate();
            return true;
        } catch (SQLException e) {
            System.err.println("Failed to count a mail statistic: " + e.getMessage());
            return false;
        }
    }

    /** The counts before the given day: how many rows it removed. */
    public int deleteEmailStatsBefore(java.time.LocalDate day) {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_DELETE_STATS_BEFORE)) {
            stmt.setDate(1, java.sql.Date.valueOf(day));
            return stmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("Failed to remove old mail statistics: " + e.getMessage());
            return 0;
        }
    }

    // ========== RSPAMD TRAINING ==========

    public boolean logRspamdTraining(String messageId, String trainedAs, int trainedBy) {
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_LOG_RSPAMD_TRAINING)) {
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
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_GET_TRAINING_COUNT)) {
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
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_LOG_AUDIT_EVENT)) {
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
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_LOG_AUDIT_EVENT_FULL)) {
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
        // An empty filter is NULL, and (? IS NULL OR column = ?) lets it through: a single statement,
        // instead of composing the WHERE with the filters present.
        String[] filters = {
            action == null || action.isEmpty() ? null : action,
            username == null || username.isEmpty() ? null : username,
            ipAddress == null || ipAddress.isEmpty() ? null : ipAddress};

        java.util.List<AuditLogEntry> entries = new java.util.ArrayList<>();

        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_GET_AUDIT_LOG)) {
            for (int f = 0; f < filters.length; f++) {
                stmt.setString(2 * f + 1, filters[f]);
                stmt.setString(2 * f + 2, filters[f]);
            }
            stmt.setInt(7, limit);

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
        java.util.Map<String, Integer> stats = new java.util.LinkedHashMap<>();

        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_GET_AUDIT_STATS)) {
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
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_CLEANUP_AUDIT_LOG)) {
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
        try (PreparedStatement stmt = getConnection().prepareStatement(SqlCatalog.MAIL_GET_RECENT_LOGIN_FAILURES)) {
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
