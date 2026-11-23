package org.daemoxcp.mail.sqli;

import org.daemoxcp.mail.database.SqlCatalog;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;

/**
 * SQLite Database Manager for DaemoxCP Mail
 *
 * This class manages the SQLite database that stores PANEL configuration only.
 * Mail data (domains, users, aliases) is stored in MySQL.
 *
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │  TRACKED SERVICES (in 'config' table)                                       │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │  • postfix_installed    - Postfix SMTP server                               │
 * │  • dovecot_installed    - Dovecot IMAP/POP3 server                          │
 * │  • rspamd_installed     - Rspamd anti-spam                                  │
 * │  • clamav_installed     - ClamAV antivirus                                  │
 * │  • roundcube_installed  - Roundcube webmail                                 │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * @see org.daemoxcp.mail.Main for overall system architecture
 */
public class dataBaseManager {
    HashMap<Integer, database> database_;

    public dataBaseManager() {
        restrictFiles();
        this.database_ = new HashMap<Integer, database>();
        database data = new database();
        this.database_.putIfAbsent(1, data);
        restrictFiles();
        migrateSecrets();
    }

    private dataBaseManager(boolean readOnly) {
        this.database_ = new HashMap<Integer, database>();
        this.database_.putIfAbsent(1, new database(readOnly));
    }

    /**
     * For the web part of the separated panel: SQLite read-only, no permissions to fix nor
     * secrets to move (the root part does that at every startup, before starting it).
     */
    public static dataBaseManager readOnly() {
        return new dataBaseManager(true);
    }

    /** True if the file belongs to the group of the web part of the separated panel. */
    private static boolean webGroup(java.nio.file.Path p) throws java.io.IOException {
        return org.daemoxcp.mail.system.PanelSeparation.GROUP.equals(java.nio.file.Files.readAttributes(p,
                java.nio.file.attribute.PosixFileAttributes.class, java.nio.file.LinkOption.NOFOLLOW_LINKS).group().getName());
    }

    // ========== Secrets: in the secrets file, not in SQLite ==========

    /*
     * The panel's MySQL password and the TLS private key are in the secrets file
     * (PanelSecrets, /usr/local/etc/daemoxcp-mail, 600), not in the SQLite database: whoever copies
     * database/daemoxcp-mail.db does not carry away the keys. The columns stay (empty) for the earlier
     * versions. On a server already running the move happens by itself at the first startup of the
     * new version (even of a console command): if a column has a value, it is the most
     * recent one (the new versions no longer write there) and it goes into the file; then the column is emptied.
     */
    /** A secret's column: the name, the secret in the file, and the fixed statements that read it and empty it. */
    private record SecretColumn(String column, String secret, String read, String clear) {}

    private static final SecretColumn[] SECRET_COLUMNS = {
            new SecretColumn("mysql_password", org.daemoxcp.mail.security.PanelSecrets.MYSQL_PASSWORD,
                    SqlCatalog.CONFIG_GET_MYSQL_PASSWORD, SqlCatalog.CONFIG_CLEAR_MYSQL_PASSWORD),
            new SecretColumn("panel_ssl_cert_key", org.daemoxcp.mail.security.PanelSecrets.PANEL_TLS_KEY,
                    SqlCatalog.CONFIG_GET_PANEL_TLS_KEY, SqlCatalog.CONFIG_CLEAR_PANEL_TLS_KEY)};

    /** Moves into the secrets file what is still in SQLite. Returns how many values it moved. */
    public int migrateSecrets() {
        int moved = 0;
        Connection c = this.database_.get(1).connection;
        if (c == null) return 0;
        for (SecretColumn col : SECRET_COLUMNS) {
            String value;
            try (PreparedStatement ps = c.prepareStatement(col.read());
                 ResultSet rs = ps.executeQuery()) {
                value = rs.next() ? rs.getString(1) : null;
            } catch (SQLException e) {
                return moved;       // table not created yet: nothing to move
            }
            if (value == null || value.isEmpty()) continue;
            try {
                org.daemoxcp.mail.security.PanelSecrets.setText(col.secret(), value);
            } catch (RuntimeException e) {
                System.err.println("Secrets file not writable, " + col.column() + " stays in SQLite for now: " + e.getMessage());
                continue;
            }
            try (PreparedStatement ps = c.prepareStatement(col.clear())) {
                ps.executeUpdate();
                moved++;
            } catch (SQLException e) {
                System.err.println("Could not clear " + col.column() + " in SQLite: " + e.getMessage());
            }
        }
        return moved;
    }

    /** The panel's MySQL password: from the secrets file (or, if it could not be moved, from SQLite). */
    public String mysqlPassword() {
        return secret(0);
    }

    /**
     * From now on the panel logs in to MySQL with this password: in the secrets file, and the SQLite
     * column empty (a filled column would win over the file). If the file is not writable, in the column.
     * The column is rewritten only if it changes: with the --web service running from the same folder SQLite is
     * busy (SQLITE_BUSY, finding 156), and usually the column is already empty.
     */
    public void setMysqlPassword(String password) {
        String inSqlite = storeSecret(0, password);
        String column = null;
        try (PreparedStatement ps = this.database_.get(1).connection.prepareStatement(SqlCatalog.CONFIG_GET_MYSQL_PASSWORD);
             ResultSet rs = ps.executeQuery()) {
            column = rs.next() ? rs.getString(1) : null;
        } catch (SQLException e) {
            // table not created yet
        }
        if (column == null || column.equals(inSqlite)) return;
        try (PreparedStatement ps = this.database_.get(1).connection.prepareStatement(SqlCatalog.CONFIG_SET_MYSQL_PASSWORD)) {
            ps.setString(1, inSqlite);
            ps.executeUpdate();
        } catch (SQLException e) {
            System.err.println("Could not write " + SECRET_COLUMNS[0].column() + " in SQLite: " + e.getMessage());
        }
    }

    /** The panel's TLS private key (PEM): from the secrets file (or, if it could not be moved, from SQLite). */
    public String panelTlsKey() {
        return secret(1);
    }

    /** A non-empty column is the most recent value (not moved yet): it wins over the file. */
    private String secret(int i) {
        try (PreparedStatement ps = this.database_.get(1).connection.prepareStatement(SECRET_COLUMNS[i].read());
             ResultSet rs = ps.executeQuery()) {
            String v = rs.next() ? rs.getString(1) : null;
            if (v != null && !v.isEmpty()) return v;
        } catch (SQLException e) {
            // table not created yet
        }
        try {
            return org.daemoxcp.mail.security.PanelSecrets.text(SECRET_COLUMNS[i].secret());
        } catch (RuntimeException e) {
            System.err.println("Secrets file unreadable: " + e.getMessage());
            return "";
        }
    }

    /** Writes a secret into the file; if the file is not writable it stays in SQLite as before. */
    private String storeSecret(int i, String value) {
        try {
            org.daemoxcp.mail.security.PanelSecrets.setText(SECRET_COLUMNS[i].secret(), value);
            return "";
        } catch (RuntimeException e) {
            System.err.println("Secrets file not writable, " + SECRET_COLUMNS[i].column() + " saved in SQLite: " + e.getMessage());
            return value == null ? "" : value;
        }
    }

    /**
     * The database/ folder 700 and daemoxcp-mail.db 600 (also SQLite's -journal and -wal files):
     * besides the moved secrets, they hold the certificate, settings and state of the services.
     */
    static void restrictFiles() {
        java.nio.file.Path dir = java.nio.file.Paths.get("database");
        try {
            if (!java.nio.file.Files.isDirectory(dir)) java.nio.file.Files.createDirectories(dir);
            // With the separated panel the folder and the database belong to the web part's group, which reads them
            // (PanelSeparation): that group keeps reading, nobody else. Whoever runs as root without knowing
            // about the separation (the menu, a console command) used to leave it closed to the web part.
            boolean web = webGroup(dir);
            java.nio.file.Files.setPosixFilePermissions(dir, java.nio.file.attribute.PosixFilePermissions.fromString(web ? "rwxr-x---" : "rwx------"));
            for (String f : new String[]{"daemoxcp-mail.db", "daemoxcp-mail.db-journal", "daemoxcp-mail.db-wal", "daemoxcp-mail.db-shm"}) {
                java.nio.file.Path p = dir.resolve(f);
                if (java.nio.file.Files.exists(p))
                    java.nio.file.Files.setPosixFilePermissions(p, java.nio.file.attribute.PosixFilePermissions.fromString(
                            web && f.equals("daemoxcp-mail.db") && webGroup(p) ? "rw-r-----" : "rw-------"));
            }
        } catch (java.io.IOException | UnsupportedOperationException e) {
            // File system without POSIX permissions, or not ours: they stay as they are
        }
    }

    public Connection get_connection() {
        return this.database_.get(1).connection;
    }

    public boolean create_tables() {
        return this.database_.get(1).create_tables();
    }

    public Integer check_tables() {
        return this.database_.get(1).check_tables();
    }

    /**
     * Update panel-only configuration (no MySQL settings)
     */
    public boolean update_panel_config(String host, String port, String sslCert, String sslKey,
                                        String sslChain, String sessionPrefix) {
        try (PreparedStatement preparedStatement = this.database_.get(1).connection.prepareStatement(SqlCatalog.CONFIG_UPDATE_PANEL_CONFIG)) {

            preparedStatement.setString(1, host);
            preparedStatement.setString(2, port);
            preparedStatement.setString(3, sslCert);
            preparedStatement.setString(4, storeSecret(1, sslKey));     // the key goes into the secrets file
            preparedStatement.setString(5, sslChain);
            preparedStatement.setString(6, sessionPrefix);

            int res = preparedStatement.executeUpdate();
            return res > 0;
        } catch (SQLException e) {
            System.out.println("Error updating panel config: " + e.getMessage());
            return false;
        }
    }

    /** The panel's MySQL database and user with the current names (MysqlRename); the password does not change. */
    public boolean renameMysql(String mysqlUser, String mysqlDatabase) {
        try (PreparedStatement ps = this.database_.get(1).connection.prepareStatement(SqlCatalog.CONFIG_RENAME_MYSQL)) {
            ps.setString(1, mysqlUser);
            ps.setString(2, mysqlDatabase);
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            System.out.println("Error renaming the MySQL config: " + e.getMessage());
            return false;
        }
    }

    /**
     * Update MySQL configuration (used during mail server installation)
     */
    public boolean update_mysql_config(String mysqlHost, String mysqlPort, String mysqlUser,
                                        String mysqlPassword, String mysqlDatabase) {
        try (PreparedStatement preparedStatement = this.database_.get(1).connection.prepareStatement(SqlCatalog.CONFIG_UPDATE_MYSQL_CONFIG)) {

            preparedStatement.setString(1, mysqlHost);
            preparedStatement.setString(2, mysqlPort);
            preparedStatement.setString(3, mysqlUser);
            preparedStatement.setString(4, storeSecret(0, mysqlPassword));   // the password goes into the secrets file
            preparedStatement.setString(5, mysqlDatabase);

            int res = preparedStatement.executeUpdate();
            return res > 0;
        } catch (SQLException e) {
            System.out.println("Error updating MySQL config: " + e.getMessage());
            return false;
        }
    }

    public boolean insert_data_default() {
        try (PreparedStatement prepare = this.database_.get(1).connection.prepareStatement(SqlCatalog.CONFIG_INSERT_DATA_DEFAULT)) {

            prepare.setString(1, "2096");
            prepare.setString(2, "127.0.0.1");
            prepare.setString(3, "");
            prepare.setString(4, "");
            prepare.setString(5, "");
            prepare.setString(6, org.daemoxcp.mail.system.Product.SLUG + "-");
            prepare.setString(7, "127.0.0.1");
            prepare.setString(8, "3306");
            prepare.setString(9, org.daemoxcp.mail.system.Product.ID);
            prepare.setString(10, "");
            prepare.setString(11, org.daemoxcp.mail.system.Product.ID);
            prepare.setInt(12, 0);
            prepare.setInt(13, 0);
            prepare.setInt(14, 0);
            prepare.setInt(15, 0);
            prepare.setInt(16, 0);
            prepare.setString(17, "webmail.example.com");      // roundcube_domain
            prepare.setString(18, "8443");  // roundcube_port
            prepare.setString(19, "");      // roundcube_ssl_cert
            prepare.setString(20, "");      // roundcube_ssl_key

            Integer result_count = prepare.executeUpdate();
            return result_count > 0;
        } catch (SQLException e) {
            System.out.println("Error inserting default data: " + e.getMessage());
            return false;
        }
    }

    /**
     * A service's flag: the fixed statement that reads it and the one that writes it (the column is not
     * a parameter). Null if the service is not recognised.
     */
    private record ServiceFlag(String read, String write) {}

    private static ServiceFlag serviceFlag(String service) {
        if (service == null) return null;
        // Switch expression (Java 14+) -- no fall-through, direct return of the value.
        return switch (service.toLowerCase()) {
            case "postfix"   -> new ServiceFlag(SqlCatalog.CONFIG_GET_POSTFIX_INSTALLED, SqlCatalog.CONFIG_SET_POSTFIX_INSTALLED);
            case "dovecot"   -> new ServiceFlag(SqlCatalog.CONFIG_GET_DOVECOT_INSTALLED, SqlCatalog.CONFIG_SET_DOVECOT_INSTALLED);
            case "rspamd"    -> new ServiceFlag(SqlCatalog.CONFIG_GET_RSPAMD_INSTALLED, SqlCatalog.CONFIG_SET_RSPAMD_INSTALLED);
            case "clamav"    -> new ServiceFlag(SqlCatalog.CONFIG_GET_CLAMAV_INSTALLED, SqlCatalog.CONFIG_SET_CLAMAV_INSTALLED);
            case "roundcube" -> new ServiceFlag(SqlCatalog.CONFIG_GET_ROUNDCUBE_INSTALLED, SqlCatalog.CONFIG_SET_ROUNDCUBE_INSTALLED);
            default -> null;
        };
    }

    public boolean setServiceInstalled(String service, boolean installed) {
        ServiceFlag flag = serviceFlag(service);
        if (flag == null) return false;
        try (PreparedStatement prepare = this.database_.get(1).connection.prepareStatement(flag.write())) {
            prepare.setInt(1, installed ? 1 : 0);
            return prepare.executeUpdate() > 0;
        } catch (SQLException e) {
            System.out.println("Error updating service status: " + e.getMessage());
            return false;
        }
    }

    public boolean isServiceInstalled(String service) {
        ServiceFlag flag = serviceFlag(service);
        if (flag == null) return false;
        try (PreparedStatement prepare = this.database_.get(1).connection.prepareStatement(flag.read())) {
            ResultSet rs = prepare.executeQuery();
            if (rs.next()) {
                return rs.getInt(1) == 1;
            }
        } catch (SQLException e) {
            System.out.println("Error checking service status: " + e.getMessage());
        }
        return false;
    }

    public ResultSet get_data_config() {
        try {
            // Not in a try-with-resources: the ResultSet leaves this method. Whoever closes it (everyone reads it
            // in a try) also closes the statement, and with it the read that holds the lock.
            PreparedStatement prepare = this.database_.get(1).connection.prepareStatement(SqlCatalog.CONFIG_GET_DATA_CONFIG);
            prepare.closeOnCompletion();
            return prepare.executeQuery();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public boolean updateMySQLPassword(String newPassword) {
        try (PreparedStatement preparedStatement = this.database_.get(1).connection.prepareStatement(SqlCatalog.CONFIG_SET_MYSQL_PASSWORD)) {
            preparedStatement.setString(1, storeSecret(0, newPassword));
            return preparedStatement.executeUpdate() > 0;
        } catch (SQLException e) {
            System.out.println("Error updating MySQL password: " + e.getMessage());
            return false;
        }
    }

    public boolean resetAllServices() {
        try (PreparedStatement prepare = this.database_.get(1).connection.prepareStatement(SqlCatalog.CONFIG_RESET_ALL_SERVICES)) {
            return prepare.executeUpdate() > 0;
        } catch (SQLException e) {
            System.out.println("Error resetting services: " + e.getMessage());
            return false;
        }
    }

    /**
     * The configuration ready at startup: on a new server first the table (with the row of default values), then the
     * previous names and the columns added after the first version. The order matters: up to 0.9.0 Main created the
     * columns BEFORE creating the table, and on a new server the ALTERs failed silently on the table that did not
     * exist; the table was then born without roundcube_ssl_chain and menu option 3 did not save ("no such column"),
     * until a second startup added the column. On a server already installed the table is there and only the rest
     * remains, in the usual order: the previous names, then the missing columns.
     *
     * @return true if the table was created now (a new server)
     */
    public boolean prepareAtStartup() {
        boolean created = check_tables() < 1;
        if (created) {
            create_tables();
            insert_data_default();
        }
        renameProductColumns();
        ensureMailHostnameColumn();
        ensureSslChainColumn();
        ensureRoundcubeColumns();
        ensurePostfixColumn();
        return created;
    }

    public void ensureMailHostnameColumn() {
        this.database_.get(1).ensureMailHostnameColumn();
    }

    /** The configuration columns with the product's previous name: before every ensure*Column. */
    public void renameProductColumns() {
        this.database_.get(1).renameProductColumns();
    }

    public void ensureSslChainColumn() {
        this.database_.get(1).ensureSslChainColumn();
    }

    public void ensurePostfixColumn() {
        this.database_.get(1).ensurePostfixColumn();
    }

    public String getMailHostname() {
        try (PreparedStatement prepare = this.database_.get(1).connection.prepareStatement(SqlCatalog.CONFIG_GET_MAIL_HOSTNAME)) {
            ResultSet rs = prepare.executeQuery();
            if (rs.next()) {
                return rs.getString("mail_hostname");
            }
        } catch (SQLException e) {
            System.out.println("Error getting mail hostname: " + e.getMessage());
        }
        return "";
    }

    public boolean setMailHostname(String hostname) {
        try (PreparedStatement prepare = this.database_.get(1).connection.prepareStatement(SqlCatalog.CONFIG_SET_MAIL_HOSTNAME)) {
            prepare.setString(1, hostname);
            return prepare.executeUpdate() > 0;
        } catch (SQLException e) {
            System.out.println("Error setting mail hostname: " + e.getMessage());
            return false;
        }
    }

    // Roundcube configuration methods
    public void ensureRoundcubeColumns() {
        this.database_.get(1).ensureRoundcubeColumns();
    }

    public String getRoundcubeDomain() {
        try (PreparedStatement prepare = this.database_.get(1).connection.prepareStatement(SqlCatalog.CONFIG_GET_ROUNDCUBE_DOMAIN)) {
            ResultSet rs = prepare.executeQuery();
            if (rs.next()) {
                return rs.getString("roundcube_domain");
            }
        } catch (SQLException e) {
            System.out.println("Error getting Roundcube domain: " + e.getMessage());
        }
        return "";
    }

    public String getRoundcubePort() {
        try (PreparedStatement prepare = this.database_.get(1).connection.prepareStatement(SqlCatalog.CONFIG_GET_ROUNDCUBE_PORT)) {
            ResultSet rs = prepare.executeQuery();
            if (rs.next()) {
                String port = rs.getString("roundcube_port");
                return (port != null && !port.isEmpty()) ? port : "8443";
            }
        } catch (SQLException e) {
            System.out.println("Error getting Roundcube port: " + e.getMessage());
        }
        return "8443";
    }

    public String getRoundcubeSslCert() {
        try (PreparedStatement prepare = this.database_.get(1).connection.prepareStatement(SqlCatalog.CONFIG_GET_ROUNDCUBE_SSL_CERT)) {
            ResultSet rs = prepare.executeQuery();
            if (rs.next()) {
                return rs.getString("roundcube_ssl_cert");
            }
        } catch (SQLException e) {
            System.out.println("Error getting Roundcube SSL cert: " + e.getMessage());
        }
        return "";
    }

    public String getRoundcubeSslKey() {
        try (PreparedStatement prepare = this.database_.get(1).connection.prepareStatement(SqlCatalog.CONFIG_GET_ROUNDCUBE_SSL_KEY)) {
            ResultSet rs = prepare.executeQuery();
            if (rs.next()) {
                return rs.getString("roundcube_ssl_key");
            }
        } catch (SQLException e) {
            System.out.println("Error getting Roundcube SSL key: " + e.getMessage());
        }
        return "";
    }

    public boolean updateRoundcubeConfig(String domain, String port, String sslCert, String sslKey, String sslChain) {
        try (PreparedStatement prepare = this.database_.get(1).connection.prepareStatement(SqlCatalog.CONFIG_UPDATE_ROUNDCUBE_CONFIG)) {
            prepare.setString(1, domain);
            prepare.setString(2, port);
            prepare.setString(3, sslCert);
            prepare.setString(4, sslKey);
            prepare.setString(5, sslChain);
            return prepare.executeUpdate() > 0;
        } catch (SQLException e) {
            System.out.println("Error updating Roundcube config: " + e.getMessage());
            return false;
        }
    }

    public String getRoundcubeSslChain() {
        try (PreparedStatement prepare = this.database_.get(1).connection.prepareStatement(SqlCatalog.CONFIG_GET_ROUNDCUBE_SSL_CHAIN)) {
            ResultSet rs = prepare.executeQuery();
            if (rs.next()) {
                String chain = rs.getString("roundcube_ssl_chain");
                return (chain != null) ? chain : "";
            }
        } catch (SQLException e) {
            System.out.println("Error getting Roundcube SSL chain: " + e.getMessage());
        }
        return "";
    }
}
