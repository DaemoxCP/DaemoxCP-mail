package org.mail_panel.sqli;

import java.sql.*;

public class database {
    Connection connection;
    Connection connection_mysql;

    public database() {
        Connection conn = null;
        try {
            String url = "jdbc:sqlite:database/mail_panel.db";
            conn = DriverManager.getConnection(url);
            if (conn != null) {
                DatabaseMetaData meta = conn.getMetaData();
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
        try {
            DatabaseMetaData meta = this.connection.getMetaData();
            ResultSet resultSet = meta.getTables(null, null, "config", new String[]{"TABLE"});
            if (resultSet.next()) {
                count++;
            }
            return count;
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }
        return count;
    }

    public boolean create_tables() {
        try {
            PreparedStatement preparedStatement = connection.prepareStatement("""
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
                    roundcube_domain TEXT DEFAULT '',
                    roundcube_port TEXT DEFAULT '8443',
                    roundcube_ssl_cert TEXT DEFAULT '',
                    roundcube_ssl_key TEXT DEFAULT ''
                )
                """);
            preparedStatement.executeUpdate();
            return true;
        } catch (SQLException e) {
            System.out.println(e.getMessage());
            return false;
        }
    }

    public void ensureMailHostnameColumn() {
        try {
            // Check if column exists
            PreparedStatement check = connection.prepareStatement(
                "SELECT mail_hostname FROM config LIMIT 1");
            check.executeQuery();
        } catch (SQLException e) {
            // Column doesn't exist, add it
            try {
                PreparedStatement alter = connection.prepareStatement(
                    "ALTER TABLE config ADD COLUMN mail_hostname TEXT DEFAULT ''");
                alter.executeUpdate();
            } catch (SQLException e2) {
                // Silent fail
            }
        }
    }

    public void ensureSslChainColumn() {
        try {
            // Check if column exists
            PreparedStatement check = connection.prepareStatement(
                "SELECT mail_panel_ssl_chain FROM config LIMIT 1");
            check.executeQuery();
        } catch (SQLException e) {
            // Column doesn't exist, add it
            try {
                PreparedStatement alter = connection.prepareStatement(
                    "ALTER TABLE config ADD COLUMN mail_panel_ssl_chain TEXT DEFAULT ''");
                alter.executeUpdate();
            } catch (SQLException e2) {
                // Silent fail
            }
        }
    }

    public void ensureRoundcubeColumns() {
        String[] columns = {
            "roundcube_domain TEXT DEFAULT ''",
            "roundcube_port TEXT DEFAULT '8443'",
            "roundcube_ssl_cert TEXT DEFAULT ''",
            "roundcube_ssl_key TEXT DEFAULT ''",
            "roundcube_ssl_chain TEXT DEFAULT ''"
        };

        for (String colDef : columns) {
            String colName = colDef.split(" ")[0];
            try {
                PreparedStatement check = connection.prepareStatement(
                    "SELECT " + colName + " FROM config LIMIT 1");
                check.executeQuery();
            } catch (SQLException e) {
                try {
                    PreparedStatement alter = connection.prepareStatement(
                        "ALTER TABLE config ADD COLUMN " + colDef);
                    alter.executeUpdate();
                } catch (SQLException e2) {
                    // Silent fail
                }
            }
        }
    }

    public void ensurePostfixColumn() {
        // Ensure postfix_installed column exists
        // Migrate from old opensmtpd_installed if it exists
        try {
            // Check if postfix_installed already exists
            PreparedStatement check = connection.prepareStatement(
                "SELECT postfix_installed FROM config LIMIT 1");
            check.executeQuery();
            // Column exists, nothing to do
        } catch (SQLException e) {
            // postfix_installed doesn't exist, check if old opensmtpd_installed exists
            try {
                PreparedStatement check2 = connection.prepareStatement(
                    "SELECT opensmtpd_installed FROM config LIMIT 1");
                check2.executeQuery();
                // Old column exists - add new column and copy data
                try {
                    connection.prepareStatement(
                        "ALTER TABLE config ADD COLUMN postfix_installed INTEGER DEFAULT 0").executeUpdate();
                    connection.prepareStatement(
                        "UPDATE config SET postfix_installed = opensmtpd_installed").executeUpdate();
                } catch (SQLException e3) {
                    // Silent fail
                }
            } catch (SQLException e2) {
                // Neither column exists, add postfix_installed
                try {
                    connection.prepareStatement(
                        "ALTER TABLE config ADD COLUMN postfix_installed INTEGER DEFAULT 0").executeUpdate();
                } catch (SQLException e3) {
                    // Silent fail
                }
            }
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
