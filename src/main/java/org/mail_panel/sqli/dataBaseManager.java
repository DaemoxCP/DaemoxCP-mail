package org.mail_panel.sqli;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;

/**
 * SQLite Database Manager for FreeBSD Mail Panel
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
 * @see org.mail_panel.Main for overall system architecture
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

    // ========== Segreti: nel file dei segreti, non in SQLite ==========

    /*
     * La password MySQL del pannello e la chiave privata TLS stanno nel file dei segreti
     * (PanelSecrets, /usr/local/etc/mail-panel, 600), non nel database SQLite: chi copia
     * database/mail_panel.db non porta via le chiavi. Le colonne restano (vuote) per le versioni
     * di prima. Su un server gia' avviato lo spostamento avviene da solo al primo avvio della
     * nuova versione (anche di un comando da console): se una colonna ha un valore, e' il piu'
     * recente (le versioni nuove non ci scrivono piu') e va nel file; poi la colonna si svuota.
     */
    private static final String[][] SECRET_COLUMNS = {
            {"mysql_password", org.mail_panel.security.PanelSecrets.MYSQL_PASSWORD},
            {"mail_panel_ssl_cert_key", org.mail_panel.security.PanelSecrets.PANEL_TLS_KEY}};

    /** Sposta nel file dei segreti quello che e' ancora in SQLite. Ritorna quanti valori ha spostato. */
    public int migrateSecrets() {
        int moved = 0;
        Connection c = this.database_.get(1).connection;
        if (c == null) return 0;
        for (String[] col : SECRET_COLUMNS) {
            String value;
            try (PreparedStatement ps = c.prepareStatement("SELECT " + col[0] + " FROM config WHERE id = 1");
                 ResultSet rs = ps.executeQuery()) {
                value = rs.next() ? rs.getString(1) : null;
            } catch (SQLException e) {
                return moved;       // tabella non ancora creata: niente da spostare
            }
            if (value == null || value.isEmpty()) continue;
            try {
                org.mail_panel.security.PanelSecrets.setText(col[1], value);
            } catch (RuntimeException e) {
                System.err.println("Secrets file not writable, " + col[0] + " stays in SQLite for now: " + e.getMessage());
                continue;
            }
            try (PreparedStatement ps = c.prepareStatement("UPDATE config SET " + col[0] + " = '' WHERE id = 1")) {
                ps.executeUpdate();
                moved++;
            } catch (SQLException e) {
                System.err.println("Could not clear " + col[0] + " in SQLite: " + e.getMessage());
            }
        }
        return moved;
    }

    /** La password MySQL del pannello: dal file dei segreti (o, se non si e' potuto spostarla, da SQLite). */
    public String mysqlPassword() {
        return secret(0);
    }

    /**
     * Da adesso il pannello entra in MySQL con questa password: nel file dei segreti, e la colonna di
     * SQLite vuota (una colonna piena vincerebbe sul file). Se il file non e' scrivibile, nella colonna.
     * La colonna si riscrive solo se cambia: col servizio --web acceso dalla stessa cartella SQLite e'
     * occupato (SQLITE_BUSY, reperto 156), e di solito la colonna e' gia' vuota.
     */
    public void setMysqlPassword(String password) {
        String inSqlite = storeSecret(0, password);
        String column = null;
        try (PreparedStatement ps = this.database_.get(1).connection.prepareStatement(
                "SELECT " + SECRET_COLUMNS[0][0] + " FROM config WHERE id = 1");
             ResultSet rs = ps.executeQuery()) {
            column = rs.next() ? rs.getString(1) : null;
        } catch (SQLException e) {
            // tabella non ancora creata
        }
        if (column == null || column.equals(inSqlite)) return;
        try (PreparedStatement ps = this.database_.get(1).connection.prepareStatement(
                "UPDATE config SET " + SECRET_COLUMNS[0][0] + " = ? WHERE id = 1")) {
            ps.setString(1, inSqlite);
            ps.executeUpdate();
        } catch (SQLException e) {
            System.err.println("Could not write " + SECRET_COLUMNS[0][0] + " in SQLite: " + e.getMessage());
        }
    }

    /** La chiave privata TLS (PEM) del pannello: dal file dei segreti (o, se non si e' potuto spostarla, da SQLite). */
    public String panelTlsKey() {
        return secret(1);
    }

    /** Una colonna non vuota e' il valore piu' recente (non ancora spostato): vince sul file. */
    private String secret(int i) {
        try (PreparedStatement ps = this.database_.get(1).connection.prepareStatement(
                "SELECT " + SECRET_COLUMNS[i][0] + " FROM config WHERE id = 1");
             ResultSet rs = ps.executeQuery()) {
            String v = rs.next() ? rs.getString(1) : null;
            if (v != null && !v.isEmpty()) return v;
        } catch (SQLException e) {
            // tabella non ancora creata
        }
        try {
            return org.mail_panel.security.PanelSecrets.text(SECRET_COLUMNS[i][1]);
        } catch (RuntimeException e) {
            System.err.println("Secrets file unreadable: " + e.getMessage());
            return "";
        }
    }

    /** Scrive un segreto nel file; se il file non e' scrivibile resta in SQLite come prima. */
    private String storeSecret(int i, String value) {
        try {
            org.mail_panel.security.PanelSecrets.setText(SECRET_COLUMNS[i][1], value);
            return "";
        } catch (RuntimeException e) {
            System.err.println("Secrets file not writable, " + SECRET_COLUMNS[i][0] + " saved in SQLite: " + e.getMessage());
            return value == null ? "" : value;
        }
    }

    /**
     * La cartella database/ 700 e mail_panel.db 600 (anche i file -journal e -wal di SQLite):
     * oltre ai segreti spostati, dentro ci sono certificato, impostazioni e stato dei servizi.
     */
    static void restrictFiles() {
        java.nio.file.Path dir = java.nio.file.Paths.get("database");
        try {
            if (!java.nio.file.Files.isDirectory(dir)) java.nio.file.Files.createDirectories(dir);
            java.nio.file.Files.setPosixFilePermissions(dir, java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"));
            for (String f : new String[]{"mail_panel.db", "mail_panel.db-journal", "mail_panel.db-wal", "mail_panel.db-shm"}) {
                java.nio.file.Path p = dir.resolve(f);
                if (java.nio.file.Files.exists(p))
                    java.nio.file.Files.setPosixFilePermissions(p, java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
            }
        } catch (java.io.IOException | UnsupportedOperationException e) {
            // File system senza permessi POSIX, o non nostri: restano come sono
        }
    }

    public Connection get_connection() {
        return this.database_.get(1).connection;
    }

    public Connection get_mysql_connection() {
        return this.database_.get(1).connection_mysql;
    }

    public void add_mysql_connection(String host, String user_, String password_, String port, String database) {
        this.database_.get(1).database_mysql(host, user_, password_, port, database);
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
        try {
            PreparedStatement preparedStatement = this.database_.get(1).connection.prepareStatement(
                    "UPDATE config SET " +
                    "mail_panel_host = ?, " +
                    "mail_panel_port = ?, " +
                    "mail_panel_ssl_cert = ?, " +
                    "mail_panel_ssl_cert_key = ?, " +
                    "mail_panel_ssl_chain = ?, " +
                    "mail_panel_sessions_prefix = ? " +
                    "WHERE id = 1");

            preparedStatement.setString(1, host);
            preparedStatement.setString(2, port);
            preparedStatement.setString(3, sslCert);
            preparedStatement.setString(4, storeSecret(1, sslKey));     // la chiave va nel file dei segreti
            preparedStatement.setString(5, sslChain);
            preparedStatement.setString(6, sessionPrefix);

            int res = preparedStatement.executeUpdate();
            return res > 0;
        } catch (SQLException e) {
            System.out.println("Error updating panel config: " + e.getMessage());
            return false;
        }
    }

    /**
     * Update MySQL configuration (used during mail server installation)
     */
    public boolean update_mysql_config(String mysqlHost, String mysqlPort, String mysqlUser,
                                        String mysqlPassword, String mysqlDatabase) {
        try {
            PreparedStatement preparedStatement = this.database_.get(1).connection.prepareStatement(
                    "UPDATE config SET " +
                    "mysql_host = ?, " +
                    "mysql_port = ?, " +
                    "mysql_user = ?, " +
                    "mysql_password = ?, " +
                    "mysql_database = ? " +
                    "WHERE id = 1");

            preparedStatement.setString(1, mysqlHost);
            preparedStatement.setString(2, mysqlPort);
            preparedStatement.setString(3, mysqlUser);
            preparedStatement.setString(4, storeSecret(0, mysqlPassword));   // la password va nel file dei segreti
            preparedStatement.setString(5, mysqlDatabase);

            int res = preparedStatement.executeUpdate();
            return res > 0;
        } catch (SQLException e) {
            System.out.println("Error updating MySQL config: " + e.getMessage());
            return false;
        }
    }

    public boolean insert_data_default() {
        try {
            PreparedStatement prepare = this.database_.get(1).connection.prepareStatement(
                    "INSERT INTO config (" +
                    "mail_panel_port, " +
                    "mail_panel_host, " +
                    "mail_panel_ssl_cert, " +
                    "mail_panel_ssl_cert_key, " +
                    "mail_panel_ssl_chain, " +
                    "mail_panel_sessions_prefix, " +
                    "mysql_host, " +
                    "mysql_port, " +
                    "mysql_user, " +
                    "mysql_password, " +
                    "mysql_database, " +
                    "postfix_installed, " +
                    "dovecot_installed, " +
                    "rspamd_installed, " +
                    "clamav_installed, " +
                    "roundcube_installed, " +
                    "roundcube_domain, " +
                    "roundcube_port, " +
                    "roundcube_ssl_cert, " +
                    "roundcube_ssl_key) " +
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)");

            prepare.setString(1, "2096");
            prepare.setString(2, "127.0.0.1");
            prepare.setString(3, "");
            prepare.setString(4, "");
            prepare.setString(5, "");
            prepare.setString(6, "mailpanel-");
            prepare.setString(7, "127.0.0.1");
            prepare.setString(8, "3306");
            prepare.setString(9, "mailpanel");
            prepare.setString(10, "");
            prepare.setString(11, "mailserver");
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

    /** Mappa nome servizio → colonna DB. Null se servizio non riconosciuto. */
    private static String serviceColumn(String service) {
        if (service == null) return null;
        // Switch expression (Java 14+) — nessun fall-through, return diretto del valore.
        return switch (service.toLowerCase()) {
            case "postfix"   -> "postfix_installed";
            case "dovecot"   -> "dovecot_installed";
            case "rspamd"    -> "rspamd_installed";
            case "clamav"    -> "clamav_installed";
            case "roundcube" -> "roundcube_installed";
            default -> null;
        };
    }

    public boolean setServiceInstalled(String service, boolean installed) {
        String column = serviceColumn(service);
        if (column == null) return false;
        try {
            PreparedStatement prepare = this.database_.get(1).connection.prepareStatement(
                    "UPDATE config SET " + column + " = ? WHERE id = 1");
            prepare.setInt(1, installed ? 1 : 0);
            return prepare.executeUpdate() > 0;
        } catch (SQLException e) {
            System.out.println("Error updating service status: " + e.getMessage());
            return false;
        }
    }

    public boolean isServiceInstalled(String service) {
        String column = serviceColumn(service);
        if (column == null) return false;
        try {
            PreparedStatement prepare = this.database_.get(1).connection.prepareStatement(
                    "SELECT " + column + " FROM config WHERE id = 1");
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
            PreparedStatement prepare = this.database_.get(1).connection.prepareStatement(
                    "SELECT * FROM config WHERE id = 1");
            return prepare.executeQuery();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public boolean updateMySQLPassword(String newPassword) {
        try {
            PreparedStatement preparedStatement = this.database_.get(1).connection.prepareStatement(
                    "UPDATE config SET mysql_password = ? WHERE id = 1");
            preparedStatement.setString(1, storeSecret(0, newPassword));
            return preparedStatement.executeUpdate() > 0;
        } catch (SQLException e) {
            System.out.println("Error updating MySQL password: " + e.getMessage());
            return false;
        }
    }

    public boolean resetAllServices() {
        try {
            PreparedStatement prepare = this.database_.get(1).connection.prepareStatement(
                    "UPDATE config SET " +
                    "postfix_installed = 0, " +
                    "dovecot_installed = 0, " +
                    "rspamd_installed = 0, " +
                    "clamav_installed = 0, " +
                    "roundcube_installed = 0 " +
                    "WHERE id = 1");
            return prepare.executeUpdate() > 0;
        } catch (SQLException e) {
            System.out.println("Error resetting services: " + e.getMessage());
            return false;
        }
    }

    public void ensureMailHostnameColumn() {
        this.database_.get(1).ensureMailHostnameColumn();
    }

    public void ensureSslChainColumn() {
        this.database_.get(1).ensureSslChainColumn();
    }

    public void ensurePostfixColumn() {
        this.database_.get(1).ensurePostfixColumn();
    }

    public String getMailHostname() {
        try {
            PreparedStatement prepare = this.database_.get(1).connection.prepareStatement(
                    "SELECT mail_hostname FROM config WHERE id = 1");
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
        try {
            PreparedStatement prepare = this.database_.get(1).connection.prepareStatement(
                    "UPDATE config SET mail_hostname = ? WHERE id = 1");
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
        try {
            PreparedStatement prepare = this.database_.get(1).connection.prepareStatement(
                    "SELECT roundcube_domain FROM config WHERE id = 1");
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
        try {
            PreparedStatement prepare = this.database_.get(1).connection.prepareStatement(
                    "SELECT roundcube_port FROM config WHERE id = 1");
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
        try {
            PreparedStatement prepare = this.database_.get(1).connection.prepareStatement(
                    "SELECT roundcube_ssl_cert FROM config WHERE id = 1");
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
        try {
            PreparedStatement prepare = this.database_.get(1).connection.prepareStatement(
                    "SELECT roundcube_ssl_key FROM config WHERE id = 1");
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
        try {
            PreparedStatement prepare = this.database_.get(1).connection.prepareStatement(
                    "UPDATE config SET " +
                    "roundcube_domain = ?, " +
                    "roundcube_port = ?, " +
                    "roundcube_ssl_cert = ?, " +
                    "roundcube_ssl_key = ?, " +
                    "roundcube_ssl_chain = ? " +
                    "WHERE id = 1");
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
        try {
            PreparedStatement prepare = this.database_.get(1).connection.prepareStatement(
                    "SELECT roundcube_ssl_chain FROM config WHERE id = 1");
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
