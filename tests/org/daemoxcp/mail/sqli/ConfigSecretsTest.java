package org.daemoxcp.mail.sqli;

import org.daemoxcp.mail.TestSql;

import org.daemoxcp.mail.security.PanelSecrets;

import java.io.File;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

/**
 * The MySQL password and the TLS private key of the panel leave the SQLite configuration for the
 * panel secrets file, also on a server that is already running.
 *
 *  - An old database with both values in SQLite: the first start of the new version moves them to
 *    the secrets file (600, folder 700) and empties the columns; the accessors give them back.
 *  - What the panel saves later (installation, Edit Panel Configuration) goes to the file, never to
 *    the columns. A value written in a column by an older version wins at the next start.
 *  - A multi-line PEM key comes back byte for byte.
 *  - Secrets file not writable: the value stays in SQLite and is still read (nothing lost).
 *  - database/ is 700 and daemoxcp-mail.db 600.
 *
 * dataBaseManager works on database/daemoxcp-mail.db in the working directory, so the checks run in
 * a child JVM started in a temporary directory.
 *
 * Usage: java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.sqli.ConfigSecretsTest
 */
public class ConfigSecretsTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            Path dir = Files.createTempDirectory("config-secrets");
            String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
            Process child = new ProcessBuilder(java, "-Ddaemoxcp.mail.secrets.dir=" + dir.resolve("secrets"),
                    "-cp", absolute(System.getProperty("java.class.path")),
                    ConfigSecretsTest.class.getName(), "child")
                    .directory(dir.toFile()).inheritIO().start();
            int code = child.waitFor();
            // Inside are a test database and a test secrets file: in /tmp, outside the boot
            // environments, they stayed after every run (reperto 162).
            try (var walk = Files.walk(dir)) {
                for (Path q : walk.sorted((x, y) -> y.compareTo(x)).toList()) Files.deleteIfExists(q);   // children first
            }
            System.exit(code);
        }

        String key = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\nBKcwggSjAgEAAoIBAQC7\n-----END PRIVATE KEY-----\n";
        Path secrets = Path.of(System.getProperty("daemoxcp.mail.secrets.dir"));

        System.out.println("\n== A server that is already running: the values are still in SQLite ==");
        dataBaseManager old = new dataBaseManager();
        old.create_tables();
        old.insert_data_default();
        setColumns(old, "Old-Mysql-Password", key);
        check("before: both values in SQLite", "Old-Mysql-Password".equals(column(old, "mysql_password")) && key.equals(column(old, "panel_ssl_cert_key")));

        dataBaseManager db = new dataBaseManager();      // the first start of the new version
        check("after the start: the columns are empty", column(db, "mysql_password").isEmpty() && column(db, "panel_ssl_cert_key").isEmpty());
        check("the values are in the secrets file", "Old-Mysql-Password".equals(PanelSecrets.text(PanelSecrets.MYSQL_PASSWORD))
                && key.equals(PanelSecrets.text(PanelSecrets.PANEL_TLS_KEY)));
        check("the accessors give them back (the PEM byte for byte)", "Old-Mysql-Password".equals(db.mysqlPassword()) && key.equals(db.panelTlsKey()));
        check("the secrets file is 600, its folder 700", "rw-------".equals(perms(secrets.resolve("panel-secrets.properties")))
                && "rwx------".equals(perms(secrets)));
        check("database/ is 700, daemoxcp-mail.db 600", "rwx------".equals(perms(Path.of("database")))
                && "rw-------".equals(perms(Path.of("database", "daemoxcp-mail.db"))));
        check("a second start moves nothing", db.migrateSecrets() == 0);

        System.out.println("\n== What the panel saves goes to the file ==");
        db.update_mysql_config("127.0.0.1", "3306", "daemoxcp_mail", "New-Mysql-Password", "daemoxcp_mail");
        check("installation: the new MySQL password in the file, not in SQLite", "New-Mysql-Password".equals(db.mysqlPassword())
                && column(db, "mysql_password").isEmpty() && "daemoxcp_mail".equals(column(db, "mysql_user")));
        db.updateMySQLPassword("Cambiata-Password-Mysql");
        check("password change: the same", "Cambiata-Password-Mysql".equals(db.mysqlPassword()) && column(db, "mysql_password").isEmpty());
        String key2 = key.replace("BKcw", "ZZzz");
        db.update_panel_config("127.0.0.1", "2096", "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n", key2, "", "daemoxcp-mail-");
        check("Edit Panel Configuration: the key in the file, the certificate in SQLite", key2.equals(db.panelTlsKey())
                && column(db, "panel_ssl_cert_key").isEmpty() && column(db, "panel_ssl_cert").contains("BEGIN CERTIFICATE"));

        System.out.println("\n== An older version wrote a column after the move ==");
        setColumns(db, "Written-By-Old-Version", "");
        new dataBaseManager();
        check("at the next start the column wins and moves to the file", "Written-By-Old-Version".equals(db.mysqlPassword())
                && column(db, "mysql_password").isEmpty() && key2.equals(db.panelTlsKey()));

        System.out.println("\n== Secrets file not writable ==");
        Field dirField = PanelSecrets.class.getDeclaredField("dir");
        dirField.setAccessible(true);
        Object realDir = dirField.get(null);
        Path blocker = Files.createFile(Path.of("not-a-folder"));
        dirField.set(null, blocker.resolve("secrets"));
        Method reset = PanelSecrets.class.getDeclaredMethod("reset");
        reset.setAccessible(true);
        reset.invoke(null);
        db.updateMySQLPassword("Stays-In-Sqlite-2026");
        check("the value stays in SQLite and is still read", "Stays-In-Sqlite-2026".equals(column(db, "mysql_password"))
                && "Stays-In-Sqlite-2026".equals(db.mysqlPassword()));
        check("and the start leaves it there instead of losing it", db.migrateSecrets() == 0 && "Stays-In-Sqlite-2026".equals(column(db, "mysql_password")));
        dirField.set(null, realDir);
        reset.invoke(null);
        check("a readable file with an older value does not hide the newer one in SQLite",
                !"Stays-In-Sqlite-2026".equals(PanelSecrets.text(PanelSecrets.MYSQL_PASSWORD)) && "Stays-In-Sqlite-2026".equals(db.mysqlPassword()));
        check("once the file is writable again, the next start moves it", db.migrateSecrets() == 1
                && "Stays-In-Sqlite-2026".equals(PanelSecrets.text(PanelSecrets.MYSQL_PASSWORD)) && column(db, "mysql_password").isEmpty());

        System.out.println(failed == 0 ? "\nAll checks passed." : "\n" + failed + " checks FAILED.");
        System.exit(failed == 0 ? 0 : 1);
    }

    /** The class path with every entry absolute: the child runs in another directory. */
    static String absolute(String classPath) {
        StringBuilder sb = new StringBuilder();
        for (String entry : classPath.split(File.pathSeparator)) {
            if (sb.length() > 0) sb.append(File.pathSeparator);
            sb.append(Path.of(entry).toAbsolutePath());
        }
        return sb.toString();
    }

    static void setColumns(dataBaseManager db, String password, String key) throws Exception {
        try (java.sql.Connection c = TestSql.sqlite(); PreparedStatement p = c.prepareStatement(
                "UPDATE config SET mysql_password = ?, panel_ssl_cert_key = CASE WHEN ? = '' THEN panel_ssl_cert_key ELSE ? END WHERE id = 1")) {
            p.setString(1, password);
            p.setString(2, key);
            p.setString(3, key);
            p.executeUpdate();
        }
    }

    static String column(dataBaseManager db, String name) throws Exception {
        try (java.sql.Connection c = TestSql.sqlite(); PreparedStatement p = c.prepareStatement("SELECT " + name + " FROM config WHERE id = 1");
             ResultSet r = p.executeQuery()) {
            String v = r.next() ? r.getString(1) : null;
            return v == null ? "" : v;
        }
    }

    static String perms(Path p) throws Exception {
        return PosixFilePermissions.toString(Files.getPosixFilePermissions(p));
    }
}
