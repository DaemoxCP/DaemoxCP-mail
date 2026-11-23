package org.daemoxcp.mail.sqli;

import org.daemoxcp.mail.database.CatalogGuard;
import org.daemoxcp.mail.database.SqlCatalog;

import java.sql.*;

public class database {
    Connection connection;

    /**
     * How long a write waits if the database is busy with another process, before
     * giving up with SQLITE_BUSY. The database is used together by the --web service and the menu (or a
     * console command) started from the same folder. sqlite-jdbc already waits 3 seconds on its own:
     * measured on the VM on 2026-11-06 (finding 160), the previous jar failed after 3 seconds per
     * write. The defect of finding 156 was not the wait but the lock held forever by the
     * reads left open (below). Fifteen seconds are the margin for a long write
     * by the other process: a 6-second hold passes with 15, not with 3 (measured).
     * The statement is SqlCatalog.CONFIG_DB_BUSY_TIMEOUT, with the same number (SqlCatalogTest checks it).
     */
    static final int BUSY_TIMEOUT_MS = 15_000;

    public database() {
        this(false);
    }

    /**
     * @param readOnly the web part of the separated panel (user daemoxcp_mail): it reads the configuration and never
     *                 writes it. The folder and the file belong to root (0750/0640 root:daemoxcp_mail): with
     *                 SQLITE_OPEN_READONLY SQLite does not even try to create a journal.
     */
    public database(boolean readOnly) {
        Connection conn = null;
        try {
            String url = "jdbc:sqlite:database/daemoxcp-mail.db";
            if (readOnly) {
                org.sqlite.SQLiteConfig config = new org.sqlite.SQLiteConfig();
                config.setReadOnly(true);
                conn = CatalogGuard.open(url, config.toProperties());
            } else {
                conn = CatalogGuard.open(url);
            }
            if (conn != null) {
                try (Statement s = conn.createStatement()) {
                    s.execute(SqlCatalog.CONFIG_DB_BUSY_TIMEOUT);
                }
            }
            this.connection = conn;
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    public Integer check_tables() {
        Integer count = 0;
        try (ResultSet resultSet = this.connection.getMetaData().getTables(null, null, "config", new String[]{"TABLE"})) {
            if (resultSet.next()) {
                count++;
            }
            return count;
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }
        return count;
    }

    /*
     * Every statement is closed, always, even the read-only ones. In SQLite a statement
     * left halfway (an executeQuery without closing, a ResultSet read up to the first row and
     * abandoned) keeps the read open, and with it the SHARED lock on the file: no other
     * process can write any more until the JVM collects it. The --web service calls these
     * methods at every startup and at every request, and the menu started from the same folder ended up in
     * SQLITE_BUSY on the server name, the service flags and the MySQL configuration (finding 156).
     */

    /**
     * True if the column exists: from the list of config's columns (a fixed statement, instead of
     * reading the column by name), and the statement is closed before returning.
     */
    boolean columnExists(String column) {
        try (PreparedStatement check = connection.prepareStatement(SqlCatalog.CONFIG_DB_COLUMNS);
             ResultSet rs = check.executeQuery()) {
            while (rs.next()) {
                if (column.equalsIgnoreCase(rs.getString("name"))) return true;
            }
            return false;
        } catch (SQLException e) {
            return false;
        }
    }

    /** A catalog command that reads nothing, closed immediately. */
    void execute(String sql) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.executeUpdate();
        }
    }

    public boolean create_tables() {
        try {
            execute(SqlCatalog.CONFIG_DB_CREATE_TABLE);
            return true;
        } catch (SQLException e) {
            System.out.println(e.getMessage());
            return false;
        }
    }

    /**
     * The configuration columns with the product's previous name (mail_panel_*, until 2026-11-17) take the current one
     * (panel_*): one column at a time, only if the old one is there and the new one is not. Before adding the missing
     * columns, which would otherwise be born empty next to those holding the values.
     */
    public void renameProductColumns() {
        // Previous name, current name, and the fixed statement: an ALTER takes no parameters.
        String[][] columns = {
            {"mail_panel_ssl_cert_key", "panel_ssl_cert_key", SqlCatalog.CONFIG_DB_RENAME_MAIL_PANEL_SSL_CERT_KEY},
            {"mail_panel_ssl_chain", "panel_ssl_chain", SqlCatalog.CONFIG_DB_RENAME_MAIL_PANEL_SSL_CHAIN},
            {"mail_panel_ssl_cert", "panel_ssl_cert", SqlCatalog.CONFIG_DB_RENAME_MAIL_PANEL_SSL_CERT},
            {"mail_panel_sessions_prefix", "panel_sessions_prefix", SqlCatalog.CONFIG_DB_RENAME_MAIL_PANEL_SESSIONS_PREFIX},
            {"mail_panel_host", "panel_host", SqlCatalog.CONFIG_DB_RENAME_MAIL_PANEL_HOST},
            {"mail_panel_port", "panel_port", SqlCatalog.CONFIG_DB_RENAME_MAIL_PANEL_PORT}
        };
        for (String[] c : columns) {
            if (!columnExists(c[0]) || columnExists(c[1])) continue;
            try {
                execute(c[2]);
                System.out.println("[ProductRename] DONE: config." + c[0] + " -> " + c[1]);
            } catch (SQLException e) {
                System.out.println("[ProductRename] LEFT: config." + c[0] + " not renamed: " + e.getMessage());
            }
        }
    }

    public void ensureMailHostnameColumn() {
        if (columnExists("mail_hostname")) return;
        try {
            execute(SqlCatalog.CONFIG_DB_ADD_MAIL_HOSTNAME);
        } catch (SQLException e2) {
            // Silent fail
        }
    }

    public void ensureSslChainColumn() {
        if (columnExists("panel_ssl_chain")) return;
        try {
            execute(SqlCatalog.CONFIG_DB_ADD_PANEL_SSL_CHAIN);
        } catch (SQLException e2) {
            // Silent fail
        }
    }

    public void ensureRoundcubeColumns() {
        // Column name and its fixed statement: an ALTER takes no parameters.
        String[][] columns = {
            {"roundcube_domain", SqlCatalog.CONFIG_DB_ADD_ROUNDCUBE_DOMAIN},
            {"roundcube_port", SqlCatalog.CONFIG_DB_ADD_ROUNDCUBE_PORT},
            {"roundcube_ssl_cert", SqlCatalog.CONFIG_DB_ADD_ROUNDCUBE_SSL_CERT},
            {"roundcube_ssl_key", SqlCatalog.CONFIG_DB_ADD_ROUNDCUBE_SSL_KEY},
            {"roundcube_ssl_chain", SqlCatalog.CONFIG_DB_ADD_ROUNDCUBE_SSL_CHAIN}
        };

        for (String[] col : columns) {
            if (columnExists(col[0])) continue;
            try {
                execute(col[1]);
            } catch (SQLException e2) {
                // Silent fail
            }
        }
    }

    public void ensurePostfixColumn() {
        // Ensure postfix_installed column exists
        // Migrate from old opensmtpd_installed if it exists
        if (columnExists("postfix_installed")) return;     // Column exists, nothing to do
        try {
            if (columnExists("opensmtpd_installed")) {
                // Old column exists - add new column and copy data
                execute(SqlCatalog.CONFIG_DB_ADD_POSTFIX_INSTALLED);
                execute(SqlCatalog.CONFIG_DB_COPY_OPENSMTPD_INSTALLED);
            } else {
                // Neither column exists, add postfix_installed
                execute(SqlCatalog.CONFIG_DB_ADD_POSTFIX_INSTALLED);
            }
        } catch (SQLException e3) {
            // Silent fail
        }
    }

    public void closeConnections() {
        try {
            if (this.connection != null) {
                this.connection.close();
            }
        } catch (SQLException e) {
            // Silent fail
        }
    }
}
