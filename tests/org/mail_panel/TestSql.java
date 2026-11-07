package org.mail_panel;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * The tests' own database connections. The panel's connections accept only the statements of its SQL
 * catalog (CatalogGuard): a test that plants a row, reads a column or holds a lock with SQL of its own
 * does it here, outside the panel, as anyone else with the database would.
 *
 *  - mysql(): the test MySQL, from the same properties the tests give the panel
 *    (-Dmysql.port, -Dmysql.user, -Dmysql.password, -Dmysql.database), one connection kept open;
 *  - sqlite(): a new connection to database/mail_panel.db in the working directory, the panel's
 *    SQLite file, for the caller to close.
 */
public final class TestSql {

    private TestSql() {}

    private static Connection mysql;

    public static synchronized Connection mysql() throws SQLException {
        if (mysql == null || mysql.isClosed()) {
            String url = "jdbc:mysql://127.0.0.1:" + System.getProperty("mysql.port") + "/"
                    + System.getProperty("mysql.database", "mailpanel_test")
                    + "?useSSL=true&requireSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC";
            mysql = DriverManager.getConnection(url, System.getProperty("mysql.user", "mailpanel"),
                    System.getProperty("mysql.password", ""));
        }
        return mysql;
    }

    public static Connection sqlite() throws SQLException {
        Connection c = DriverManager.getConnection("jdbc:sqlite:database/mail_panel.db");
        try (Statement s = c.createStatement()) {
            s.execute("PRAGMA busy_timeout = 15000");
        }
        return c;
    }
}
