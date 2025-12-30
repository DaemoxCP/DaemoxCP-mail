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
        this.database_ = new HashMap<Integer, database>();
        database data = new database();
        this.database_.putIfAbsent(1, data);
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
            preparedStatement.setString(4, sslKey);
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
            preparedStatement.setString(4, mysqlPassword);
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
            prepare.setString(17, "");      // roundcube_domain
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

    public boolean setServiceInstalled(String service, boolean installed) {
        String column;
        switch (service.toLowerCase()) {
            case "postfix": column = "postfix_installed"; break;
            case "dovecot": column = "dovecot_installed"; break;
            case "rspamd": column = "rspamd_installed"; break;
            case "clamav": column = "clamav_installed"; break;
            case "roundcube": column = "roundcube_installed"; break;
            default: return false;
        }
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
        String column;
        switch (service.toLowerCase()) {
            case "postfix": column = "postfix_installed"; break;
            case "dovecot": column = "dovecot_installed"; break;
            case "rspamd": column = "rspamd_installed"; break;
            case "clamav": column = "clamav_installed"; break;
            case "roundcube": column = "roundcube_installed"; break;
            default: return false;
        }
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
            preparedStatement.setString(1, newPassword);
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
