package org.mail_panel.sqli;

import java.sql.*;

public class database {
    Connection connection;
    Connection connection_mysql;

    /**
     * Quanto aspetta una scrittura se il database e' occupato da un altro processo, prima di
     * arrendersi con SQLITE_BUSY. Il database lo usano insieme il servizio --web e il menu (o un
     * comando da console) avviati dalla stessa cartella; una scrittura dura millisecondi. Senza
     * attesa, la prima scrittura dell'uno mentre l'altro legge falliva subito (reperto 156).
     */
    static final int BUSY_TIMEOUT_MS = 15_000;

    public database() {
        Connection conn = null;
        try {
            String url = "jdbc:sqlite:database/mail_panel.db";
            conn = DriverManager.getConnection(url);
            if (conn != null) {
                try (Statement s = conn.createStatement()) {
                    s.execute("PRAGMA busy_timeout = " + BUSY_TIMEOUT_MS);
                }
            }
            this.connection = conn;
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    public void database_mysql(String host, String user_, String password_, String port, String database) {
        Connection conn = null;
        try {
            // MySQL database parameters
            String url = "jdbc:mysql://" + host + ":" + port + "/" + database + "?allowPublicKeyRetrieval=true&useSSL=false";
            String user = user_;
            String password = password_;

            // create a connection to the MySQL database
            conn = DriverManager.getConnection(url, user, password);
            this.connection_mysql = conn;
        } catch (SQLException e) {
            // Silent fail - don't print to avoid terminal interference
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
     * Ogni statement si chiude, sempre, anche quelli di sola lettura. In SQLite uno statement
     * lasciato a meta' (un executeQuery senza chiusura, un ResultSet letto fino alla prima riga e
     * abbandonato) tiene aperta la lettura, e con lei il lock SHARED sul file: nessun altro
     * processo puo' piu' scrivere finche' la JVM non lo raccoglie. Il servizio --web chiama questi
     * metodi a ogni avvio e a ogni richiesta, e il menu avviato dalla stessa cartella finiva in
     * SQLITE_BUSY su nome del server, flag dei servizi e configurazione MySQL (reperto 156).
     */

    /** Vero se la colonna esiste: la si legge, e lo statement si chiude prima di tornare. */
    boolean columnExists(String column) {
        try (PreparedStatement check = connection.prepareStatement("SELECT " + column + " FROM config LIMIT 1");
             ResultSet rs = check.executeQuery()) {
            return true;
        } catch (SQLException e) {
            return false;
        }
    }

    /** Un comando che non legge niente, chiuso subito. */
    void execute(String sql) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.executeUpdate();
        }
    }

    public boolean create_tables() {
        try {
            execute("""
                CREATE TABLE config (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    mail_panel_port TEXT DEFAULT '2096',
                    mail_panel_host TEXT DEFAULT '127.0.0.1',
                    mail_panel_ssl_cert TEXT DEFAULT '',
                    mail_panel_ssl_cert_key TEXT DEFAULT '',
                    mail_panel_ssl_chain TEXT DEFAULT '',
                    mail_panel_sessions_prefix TEXT DEFAULT 'mailpanel-',
                    mysql_host TEXT DEFAULT '127.0.0.1',
                    mysql_port TEXT DEFAULT '3306',
                    mysql_user TEXT DEFAULT 'mailpanel',
                    mysql_password TEXT DEFAULT '',
                    mysql_database TEXT DEFAULT 'mailserver',
                    mail_hostname TEXT DEFAULT '',
                    postfix_installed INTEGER DEFAULT 0,
                    dovecot_installed INTEGER DEFAULT 0,
                    rspamd_installed INTEGER DEFAULT 0,
                    clamav_installed INTEGER DEFAULT 0,
                    roundcube_installed INTEGER DEFAULT 0,
                    roundcube_domain TEXT DEFAULT 'webmail.example.com',
                    roundcube_port TEXT DEFAULT '8443',
                    roundcube_ssl_cert TEXT DEFAULT '',
                    roundcube_ssl_key TEXT DEFAULT ''
                )
                """);
            return true;
        } catch (SQLException e) {
            System.out.println(e.getMessage());
            return false;
        }
    }

    public void ensureMailHostnameColumn() {
        if (columnExists("mail_hostname")) return;
        try {
            execute("ALTER TABLE config ADD COLUMN mail_hostname TEXT DEFAULT ''");
        } catch (SQLException e2) {
            // Silent fail
        }
    }

    public void ensureSslChainColumn() {
        if (columnExists("mail_panel_ssl_chain")) return;
        try {
            execute("ALTER TABLE config ADD COLUMN mail_panel_ssl_chain TEXT DEFAULT ''");
        } catch (SQLException e2) {
            // Silent fail
        }
    }

    public void ensureRoundcubeColumns() {
        String[] columns = {
            "roundcube_domain TEXT DEFAULT 'webmail.example.com'",
            "roundcube_port TEXT DEFAULT '8443'",
            "roundcube_ssl_cert TEXT DEFAULT ''",
            "roundcube_ssl_key TEXT DEFAULT ''",
            "roundcube_ssl_chain TEXT DEFAULT ''"
        };

        for (String colDef : columns) {
            String colName = colDef.split(" ")[0];
            if (columnExists(colName)) continue;
            try {
                execute("ALTER TABLE config ADD COLUMN " + colDef);
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
                execute("ALTER TABLE config ADD COLUMN postfix_installed INTEGER DEFAULT 0");
                execute("UPDATE config SET postfix_installed = opensmtpd_installed");
            } else {
                // Neither column exists, add postfix_installed
                execute("ALTER TABLE config ADD COLUMN postfix_installed INTEGER DEFAULT 0");
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
            if (this.connection_mysql != null) {
                this.connection_mysql.close();
            }
        } catch (SQLException e) {
            // Silent fail
        }
    }
}
