package org.daemoxcp.mail.system;

import org.daemoxcp.mail.database.MailDatabase;
import org.daemoxcp.mail.database.SqlCatalog;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.util.List;

/**
 * The update manager's questions to MySQL through JDBC, on the test
 * MySQL. Before, they went to the mysql client inside "sh -c", with the SQL text in the command line and the values
 * written into it. Here, with UpdateManager.jdbcRows, every statement of the update manager:
 *  - answers what the client answered: one row per line, the columns separated by a tab, "" when MySQL refuses;
 *  - takes its values as parameters: a mailbox address with a quote in it finds nothing and breaks nothing;
 *  - as the panel's user it cannot read MySQL's accounts, as root it can (canReadMysqlUsers relies on that "");
 *  - a text that is not in the catalog never reaches MySQL, and a wrong password gives "".
 *
 * Usage (on the VM, with the test MySQL of tests/README.md, as root):
 *   java -Dmysql.port=33062 -Dmysql.user=daemoxcp_mail -Dmysql.password=... -Dmysql.database=daemoxcp_mail_test \
 *        -cp "tests:target/daemoxcp-mail-1.0.jar" org.daemoxcp.mail.system.UpdateManagerSqlTest
 */
public class UpdateManagerSqlTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    public static void main(String[] args) throws Exception {
        String port = System.getProperty("mysql.port");
        String db = System.getProperty("mysql.database", "daemoxcp_mail_test");
        String user = System.getProperty("mysql.user", "daemoxcp_mail"), password = System.getProperty("mysql.password", "");
        if (port == null) {
            System.out.println("No MySQL given (-Dmysql.port=...): this test needs the test MySQL, and its root.");
            System.exit(1);
        }
        MailDatabase mail = new MailDatabase();
        mail.setCredentials(user, password);
        mail.setConnection("127.0.0.1", Integer.parseInt(port), db);
        check("connected to MySQL as the panel user", mail.connect());
        mail.createSchema();
        mail.ensureColumnUpgrades();

        // I dati della prova, con una connessione propria (come chiunque abbia il database).
        try (Connection root = DriverManager.getConnection("jdbc:mysql://127.0.0.1:" + port + "/" + db
                + "?useSSL=true&requireSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC", "root", "")) {
            for (String sql : List.of(
                    "INSERT INTO domains (domain, active) VALUES ('umsql.test', 1)",
                    "INSERT INTO mailboxes (email, password, domain_id, active) SELECT 'on@umsql.test', 'x', id, 1 FROM domains WHERE domain = 'umsql.test'",
                    "INSERT INTO mailboxes (email, password, domain_id, active) SELECT 'off@umsql.test', 'x', id, 0 FROM domains WHERE domain = 'umsql.test'")) {
                try (PreparedStatement ps = root.prepareStatement(sql)) { ps.execute(); }
            }
        }

        System.out.println("== As the panel's user");
        String first = UpdateManager.jdbcRows("127.0.0.1", port, db, user, password, SqlCatalog.UM_FIRST_ACTIVE_MAILBOX);
        check("an active mailbox, one line (" + first + ")", first.matches("[^\\n\\t]+@[^\\n\\t]+"));
        check("an active mailbox: 1", "1".equals(UpdateManager.jdbcRows("127.0.0.1", port, db, user, password,
                SqlCatalog.UM_ACTIVE_MAILBOX_COUNT, "on@umsql.test")));
        check("an inactive one: 0", "0".equals(UpdateManager.jdbcRows("127.0.0.1", port, db, user, password,
                SqlCatalog.UM_ACTIVE_MAILBOX_COUNT, "off@umsql.test")));
        check("an address with a quote is a value, not SQL: 0", "0".equals(UpdateManager.jdbcRows("127.0.0.1", port, db, user,
                password, SqlCatalog.UM_ACTIVE_MAILBOX_COUNT, "x' OR '1'='1")));
        String mailboxes = UpdateManager.jdbcRows("127.0.0.1", port, db, user, password, SqlCatalog.UM_COUNT_MAILBOXES);
        check("the mailboxes counted (" + mailboxes + ")", mailboxes.matches("[0-9]+") && Long.parseLong(mailboxes) >= 2);
        String version = UpdateManager.jdbcRows("127.0.0.1", port, db, user, password, SqlCatalog.MAIL_SERVER_VERSION);
        check("the version (" + version + ")", version.matches("[0-9]+\\.[0-9]+\\.[0-9]+.*"));
        check("the accounts' table: refused to the panel's user, so \"\"",
                "".equals(UpdateManager.jdbcRows("127.0.0.1", port, db, user, password, SqlCatalog.UM_CAN_READ_ACCOUNTS)));
        String tables = UpdateManager.jdbcRows("127.0.0.1", port, db, user, password, SqlCatalog.UM_COUNT_SCHEMA_TABLES, db);
        check("the tables of its database, the name as a parameter (" + tables + ")", tables.matches("[0-9]+") && Long.parseLong(tables) > 10);
        check("a text that is not in the catalog never reaches MySQL: \"\"",
                "".equals(UpdateManager.jdbcRows("127.0.0.1", port, db, user, password, "SELECT 2")));
        check("a wrong password: \"\"",
                "".equals(UpdateManager.jdbcRows("127.0.0.1", port, db, user, password + "x", SqlCatalog.MAIL_SERVER_VERSION)));

        System.out.println("== As MySQL's root");
        check("root answers", "1".equals(UpdateManager.jdbcRows("127.0.0.1", port, db, "root", "", SqlCatalog.MYSQL_ROOT_PING)));
        check("root reads the accounts' table", "1".equals(UpdateManager.jdbcRows("127.0.0.1", port, db, "root", "", SqlCatalog.UM_CAN_READ_ACCOUNTS)));
        String plugins = UpdateManager.jdbcRows("127.0.0.1", port, db, "root", "", SqlCatalog.UM_AUTH_PLUGINS);
        check("the authentication plugins, \"plugin count\" one per line (" + plugins.replace('\n', '|') + ")",
                !plugins.isEmpty() && plugins.lines().allMatch(l -> l.matches("[a-z_0-9]+ [0-9]+")) && plugins.contains("caching_sha2_password "));
        String natives = UpdateManager.jdbcRows("127.0.0.1", port, db, "root", "", SqlCatalog.UM_NATIVE_PASSWORD_ACCOUNTS);
        check("the accounts with mysql_native_password, user@host per line (" + natives.replace('\n', '|') + ")",
                natives.isEmpty() || natives.lines().allMatch(l -> l.matches("[^@\\s]+@[^@\\s]+")));
        String schemata = UpdateManager.jdbcRows("127.0.0.1", port, db, "root", "", SqlCatalog.UM_COUNT_SCHEMATA);
        String userTables = UpdateManager.jdbcRows("127.0.0.1", port, db, "root", "", SqlCatalog.UM_COUNT_USER_TABLES);
        check("databases and user tables counted (" + schemata + ", " + userTables + ")", schemata.matches("[0-9]+")
                && Long.parseLong(schemata) >= 5 && userTables.matches("[0-9]+") && Long.parseLong(userTables) >= Long.parseLong(tables));
        String gtid = UpdateManager.jdbcRows("127.0.0.1", port, db, "root", "", SqlCatalog.UM_GTID_STATE);
        check("the GTID state, as mysqldump's check reads it (" + gtid + ")",
                gtid.matches("gtid_mode=\\S+  log_bin=\\S+  enforce_gtid_consistency=\\S+"));

        try (Connection root = DriverManager.getConnection("jdbc:mysql://127.0.0.1:" + port + "/" + db
                + "?useSSL=true&requireSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC", "root", "");
             PreparedStatement ps = root.prepareStatement("DELETE FROM domains WHERE domain = 'umsql.test'")) {
            ps.execute();
        }
        System.out.println(failed == 0 ? "ALL OK" : failed + " FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }
}
