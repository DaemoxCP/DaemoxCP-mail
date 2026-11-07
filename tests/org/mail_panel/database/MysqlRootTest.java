package org.mail_panel.database;

import org.mail_panel.security.PanelSecrets;
import org.mail_panel.util.Shell;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.List;
import java.util.Properties;

/**
 * MySQL's root and its password (MysqlRoot).
 *
 * Measured on 07/11/2026 on the real server: root@localhost without a password, and any user of the
 * machine got in as root, from the socket and from 127.0.0.1. Here:
 *  1. pure: the option files and the ALTER USER statements, with a host that is not a host refused;
 *  2. with -De2e.vm=yes, as root, on the FreeBSD VM: a throwaway MySQL started by the test
 *     (--initialize-insecure, so root has no password, as on the server) on its own socket and port,
 *     and a secrets folder of its own. The repair sets the password and then root does not get in
 *     without it from the socket or from TCP; the second time it does nothing; a password set by hand
 *     is never replaced; a second root account without a password is fixed too; and with a secrets
 *     file that cannot be written MySQL is NOT touched (a password that exists only in MySQL would
 *     lock everybody out).
 *
 * Usage (on the VM):
 *   java -De2e.vm=yes -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.database.MysqlRootTest
 */
public class MysqlRootTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    public static void main(String[] args) throws Exception {
        System.out.println("== 1. Option files and statements ==");
        String none = MysqlRoot.options(null);
        check("without a password: user root and an empty password", none.contains("user=root\n") && none.contains("password=\n"));
        check("with a password: quoted, so a # is not a comment", MysqlRoot.options("a#b$c").contains("password=\"a#b$c\"\n"));
        check("TCP: 127.0.0.1 and the port", MysqlRoot.tcpOptions(null).contains("host=127.0.0.1\n") && MysqlRoot.tcpOptions(null).contains("protocol=TCP"));
        check("one ALTER USER per account", MysqlRoot.alterStatements(List.of("localhost", "127.0.0.1"), "Pw1!")
                .equals("ALTER USER 'root'@'localhost' IDENTIFIED BY 'Pw1!';\nALTER USER 'root'@'127.0.0.1' IDENTIFIED BY 'Pw1!';\n"));
        boolean refused = false;
        try { MysqlRoot.alterStatements(List.of("x'; DROP USER root; --"), "p"); } catch (IllegalArgumentException e) { refused = true; }
        check("a host that is not a host is refused before any SQL", refused);

        if (!"yes".equals(System.getProperty("e2e.vm"))) {
            System.out.println("\n  (part 2 skipped: it starts a MySQL, turned on with -De2e.vm=yes on the VM)");
            finish();
            return;
        }
        endToEnd();
        finish();
    }

    static void finish() {
        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }

    static Path base;
    static Process mysqld;

    static void endToEnd() throws Exception {
        System.out.println("\n== 2. A throwaway MySQL, root without a password as on the server ==");
        base = Files.createTempDirectory(Path.of("/var/tmp"), "mysql-root-test");
        Path secrets = Files.createDirectories(base.resolve("secrets"));
        System.setProperty("mailpanel.secrets.dir", secrets.toString());
        MysqlRoot.socket = base.resolve("m.sock").toString();
        MysqlRoot.port = "33063";
        MysqlRoot.workDir = base.toString();
        try {
            start();
            check("the throwaway MySQL lets root in without a password", MysqlRoot.entersWith(MysqlRoot.options(null)));

            check("the repair: DONE", MysqlRoot.repair() == MysqlRoot.Outcome.DONE);
            Properties p = new Properties();
            Path file = secrets.resolve("root-secrets.properties");
            try (var r = Files.newBufferedReader(file)) { p.load(r); }
            String pw = p.getProperty(PanelSecrets.MYSQL_ROOT_PASSWORD, "");
            check("the password is in the secrets file", pw.length() >= 20);
            check("  and the file is 600", PosixFilePermissions.toString(Files.getPosixFilePermissions(file)).equals("rw-------"));
            check("root no longer gets in without it, from the socket", !MysqlRoot.entersWith(MysqlRoot.options(null)));
            check("  nor from 127.0.0.1", !MysqlRoot.entersWith(MysqlRoot.tcpOptions(null)));
            check("  and gets in with it", MysqlRoot.entersWith(MysqlRoot.options(pw)));
            check("the panel's root queries use it", "1".equals(MysqlRoot.query("SELECT 1;")));
            check("the second time: nothing to do", MysqlRoot.repair() == MysqlRoot.Outcome.NOTHING);

            // A password set by hand, which the panel does not know: never replaced.
            MysqlRoot.mysql(MysqlRoot.options(pw), "ALTER USER 'root'@'localhost' IDENTIFIED BY 'Set-By-Hand-2026';");
            check("a password set by hand: nothing to do", MysqlRoot.repair() == MysqlRoot.Outcome.NOTHING);
            check("  and it is still the one set by hand", MysqlRoot.entersWith(MysqlRoot.options("Set-By-Hand-2026")));

            // Back to no password, with a second root account also without one.
            MysqlRoot.mysql(MysqlRoot.options("Set-By-Hand-2026"),
                    "ALTER USER 'root'@'localhost' IDENTIFIED BY ''; CREATE USER 'root'@'127.0.0.1' IDENTIFIED BY '';"
                    + " GRANT ALL ON *.* TO 'root'@'127.0.0.1';");
            check("two root accounts without a password", MysqlRoot.emptyRootHosts().equals(List.of("127.0.0.1", "localhost")));
            check("the repair fixes both: DONE", MysqlRoot.repair() == MysqlRoot.Outcome.DONE);
            check("  with the password already in the file, not a new one", MysqlRoot.entersWith(MysqlRoot.options(pw)));
            check("  and from 127.0.0.1 root needs it too", !MysqlRoot.entersWith(MysqlRoot.tcpOptions(null))
                    && MysqlRoot.entersWith(MysqlRoot.tcpOptions(pw)));

            // The secrets file cannot be written: MySQL must not be touched.
            MysqlRoot.mysql(MysqlRoot.options(pw), "ALTER USER 'root'@'localhost' IDENTIFIED BY ''; DROP USER 'root'@'127.0.0.1';");
            Files.delete(file);
            // The test runs as root, which ignores the permission bits: the immutable flag stops it.
            Shell.run(Duration.ofSeconds(10), "chflags", "schg", secrets.toString());
            resetSecrets();
            MysqlRoot.Outcome o = MysqlRoot.repair();
            check("secrets file not writable: NOT_APPLIED (" + o + ")", o == MysqlRoot.Outcome.NOT_APPLIED);
            check("  and MySQL untouched: root still gets in without a password", MysqlRoot.entersWith(MysqlRoot.options(null)));
            Shell.run(Duration.ofSeconds(10), "chflags", "noschg", secrets.toString());
        } finally {
            Shell.run(Duration.ofSeconds(10), "chflags", "-R", "noschg", base.toString());
            stop();
            Shell.run(Duration.ofSeconds(30), "rm", "-rf", base.toString());
        }
    }

    /** PanelSecrets keeps a copy in memory: the test that removes the file must drop it. */
    static void resetSecrets() throws Exception {
        var m = PanelSecrets.class.getDeclaredMethod("reset");
        m.setAccessible(true);
        m.invoke(null);
    }

    static void start() throws Exception {
        Path data = base.resolve("data");
        Shell.Result init = Shell.run(Duration.ofSeconds(180), "/usr/local/libexec/mysqld", "--user=root",
                "--initialize-insecure", "--datadir=" + data);
        if (!init.success()) throw new IllegalStateException("mysqld --initialize-insecure: " + init.outputTrim());
        mysqld = new ProcessBuilder("/usr/local/libexec/mysqld", "--user=root", "--datadir=" + data,
                "--socket=" + MysqlRoot.socket, "--port=33063", "--bind-address=127.0.0.1", "--mysqlx=OFF",
                "--secure-file-priv=", "--pid-file=" + base.resolve("m.pid"))
                .redirectErrorStream(true).redirectOutput(base.resolve("mysqld.log").toFile()).start();
        for (int i = 0; i < 60 && !MysqlRoot.entersWith(MysqlRoot.options(null)); i++) Thread.sleep(1000);
    }

    static void stop() throws Exception {
        if (mysqld == null) return;
        mysqld.destroy();
        if (!mysqld.waitFor(30, java.util.concurrent.TimeUnit.SECONDS)) mysqld.destroyForcibly();
    }
}
