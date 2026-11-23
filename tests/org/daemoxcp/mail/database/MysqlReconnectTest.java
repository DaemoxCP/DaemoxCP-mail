package org.daemoxcp.mail.database;

import org.daemoxcp.mail.Main;
import org.daemoxcp.mail.security.PanelSecrets;
import org.daemoxcp.mail.sqli.dataBaseManager;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

/**
 * The running panel reconnects to MySQL with the password that is in the secrets file NOW, not with
 * the one it had at start. Finding 156: a full reinstallation from the menu changes the password of
 * the panel's MySQL user and restarts MySQL; the running --web service lost the connection and
 * retried forever with the old one ("Access denied").
 *
 * With real MySQL and a test user (e2e_reconnect, with its database, removed at the end):
 *  1. a "service" process gets into MySQL the way the service and the console commands do
 *     (Main.connectFromConfig), and stays on;
 *  2. as the reinstallation does: the user's password changes in MySQL (as root), its connections
 *     drop (KILL, as when MySQL restarts), and another process ("menu") writes the new password to
 *     the secrets file;
 *  3. the "service" uses the database again: it must be in, as e2e_reconnect.
 * Then the same without the new password in the file: the service does NOT get in (the secrets
 * file decides the password, not another source), and as soon as the file has it, it gets in.
 *
 * MySQL root: with the password of the real secrets file, or without one if root gets in without
 * (the servers installed by the 11/10 version). It runs only with -De2e.vm=yes, as root, MySQL on:
 *   java -De2e.vm=yes -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.database.MysqlReconnectTest
 */
public class MysqlReconnectTest {

    static final String USER = "e2e_reconnect";
    static final String DB = "e2e_reconnect";

    static int failed = 0;
    static Path base, rootCnf;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    public static void main(String[] args) throws Exception {
        if (args.length > 0) { child(args); return; }
        if (!"yes".equals(System.getProperty("e2e.vm"))) {
            System.out.println("SKIPPED: it needs -De2e.vm=yes (FreeBSD VM, root, MySQL on).");
            System.exit(0);
        }
        base = Files.createTempDirectory("mysql-reconnect");
        rootCnf = base.resolve("root.cnf");
        Files.writeString(rootCnf, "[client]\nuser=root\npassword=\"" + PanelSecrets.text(PanelSecrets.MYSQL_ROOT_PASSWORD) + "\"\n");
        Files.setPosixFilePermissions(rootCnf, PosixFilePermissions.fromString("rw-------"));
        try {
            String a = "E2eRecA" + System.nanoTime() % 1_000_000_000L;
            String b = "E2eRecB" + System.nanoTime() % 1_000_000_000L;
            String c = "E2eRecC" + System.nanoTime() % 1_000_000_000L;
            check("test user created", rootSql("DROP USER IF EXISTS '" + USER + "'@'localhost', '" + USER + "'@'127.0.0.1';"
                    + "CREATE DATABASE IF NOT EXISTS " + DB + ";"
                    + "CREATE USER '" + USER + "'@'localhost' IDENTIFIED BY '" + a + "';"
                    + "CREATE USER '" + USER + "'@'127.0.0.1' IDENTIFIED BY '" + a + "';"
                    + "GRANT ALL PRIVILEGES ON " + DB + ".* TO '" + USER + "'@'localhost', '" + USER + "'@'127.0.0.1';"));
            check("the test panel has the current password", run("setup", a).code == 0);

            System.out.println("\n== The reinstallation changes the password while the service is on ==");
            Process service = start("service");
            BufferedReader out = new BufferedReader(new InputStreamReader(service.getInputStream(), StandardCharsets.UTF_8));
            check("the service got into MySQL", waitFor(out, "CONNECTED"));
            check("MySQL: new password, connections dropped", rootSql(alter(b)) && killAll());
            check("the menu writes the new password to the secrets file", run("write-secret", b).code == 0);
            say(service, "use");
            String line = waitLine(out, "USE ");
            check("the service uses the database again and is in, as " + USER, line != null && line.startsWith("USE ok " + USER + "@"));

            System.out.println("\n== MySQL changes, the secrets file not yet (the reinstallation has not decided yet) ==");
            check("MySQL: another password, connections dropped", rootSql(alter(c)) && killAll());
            say(service, "use");
            line = waitLine(out, "USE ");
            check("the service does NOT get in with a password the file does not have", line != null && line.startsWith("USE refused"));
            check("the menu writes the password to the file", run("write-secret", c).code == 0);
            say(service, "use");
            line = waitLine(out, "USE ");
            check("now the service gets in", line != null && line.startsWith("USE ok " + USER + "@"));
            say(service, "quit");
            service.waitFor();
        } finally {
            rootSql("DROP USER IF EXISTS '" + USER + "'@'localhost', '" + USER + "'@'127.0.0.1'; DROP DATABASE IF EXISTS " + DB + ";");
            removeTree(base);
        }
        System.out.println(failed == 0 ? "\nAll checks passed." : "\n" + failed + " checks FAILED.");
        System.exit(failed == 0 ? 0 : 1);
    }

    static String alter(String p) {
        return "ALTER USER '" + USER + "'@'localhost' IDENTIFIED BY '" + p + "';"
             + "ALTER USER '" + USER + "'@'127.0.0.1' IDENTIFIED BY '" + p + "';";
    }

    /** All the test user's connections drop, as when MySQL restarts. */
    static boolean killAll() throws Exception {
        Process p = new ProcessBuilder("mysql", "--defaults-extra-file=" + rootCnf, "-N", "-e",
                "SELECT id FROM information_schema.processlist WHERE user = '" + USER + "'").redirectErrorStream(true).start();
        String ids = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
        if (p.waitFor() != 0) return false;
        StringBuilder sql = new StringBuilder();
        for (String id : ids.split("\\s+")) if (id.matches("[0-9]+")) sql.append("KILL ").append(id).append(";");
        return sql.length() == 0 || rootSql(sql.toString());
    }

    // ---------------------------------------------------------------- the panel's processes

    static void child(String[] a) throws Exception {
        Main.dbManager = new dataBaseManager();
        if (Main.dbManager.check_tables() < 1) { Main.dbManager.create_tables(); Main.dbManager.insert_data_default(); }
        switch (a[0]) {
            case "setup" -> System.exit(Main.dbManager.update_mysql_config("127.0.0.1", "3306", USER, a[1], DB) ? 0 : 1);
            case "write-secret" -> {
                Main.dbManager.setMysqlPassword(a[1]);
                System.exit(a[1].equals(Main.dbManager.mysqlPassword()) ? 0 : 1);
            }
            case "service" -> {
                Method m = Main.class.getDeclaredMethod("connectFromConfig");
                m.setAccessible(true);
                String why = (String) m.invoke(null);
                System.out.println(why == null ? "CONNECTED" : "NOT CONNECTED " + why);
                System.out.flush();
                BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
                String cmd;
                while ((cmd = in.readLine()) != null && !cmd.equals("quit")) {
                    // Like the panel's handlers: getConnection(), which reconnects if needed.
                    String result;
                    try {
                        Connection c = Main.mailDatabase.getConnection();
                        if (c == null) result = "refused (no connection)";
                        // The panel's connection takes only its catalog's statements (CatalogGuard): the
                        // user comes from the driver's metadata, which asks MySQL (SELECT USER()).
                        else result = "ok " + c.getMetaData().getUserName();
                    } catch (Exception e) {
                        result = "refused (" + e.getMessage() + ")";
                    }
                    System.out.println("USE " + result);
                    System.out.flush();
                }
                System.exit(0);
            }
            default -> throw new IllegalArgumentException(a[0]);
        }
    }

    record Run(int code, String out) {}

    static Process start(String... step) throws Exception {
        String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
        List<String> cmd = new ArrayList<>(List.of(java, "-Ddaemoxcp.mail.secrets.dir=" + base.resolve("secrets"),
                "-cp", absolute(System.getProperty("java.class.path")), MysqlReconnectTest.class.getName()));
        cmd.addAll(List.of(step));
        return new ProcessBuilder(cmd).directory(base.toFile()).redirectErrorStream(true).start();
    }

    static Run run(String... step) throws Exception {
        Process p = start(step);
        p.getOutputStream().close();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        int code = p.waitFor();
        for (String l : out.split("\n")) if (!l.isBlank()) System.out.println("      | " + l);
        return new Run(code, out);
    }

    static void say(Process p, String cmd) throws Exception {
        OutputStream in = p.getOutputStream();
        in.write((cmd + "\n").getBytes(StandardCharsets.UTF_8));
        in.flush();
    }

    static boolean waitFor(BufferedReader out, String word) throws Exception {
        return waitLine(out, word) != null;
    }

    static String waitLine(BufferedReader out, String prefix) throws Exception {
        String line;
        while ((line = out.readLine()) != null) {
            System.out.println("      | " + line);
            int i = line.indexOf(prefix);
            if (i >= 0) return line.substring(i);
        }
        return null;
    }

    static boolean rootSql(String sql) throws Exception {
        Process p = new ProcessBuilder("mysql", "--defaults-extra-file=" + rootCnf, "-e", sql).redirectErrorStream(true).start();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        int code = p.waitFor();
        if (code != 0) System.out.println("  mysql: " + out.trim());
        return code == 0;
    }

    static String absolute(String cp) {
        StringBuilder b = new StringBuilder();
        for (String part : cp.split(java.io.File.pathSeparator)) {
            if (b.length() > 0) b.append(java.io.File.pathSeparator);
            b.append(Path.of(part).toAbsolutePath());
        }
        return b.toString();
    }

    static void removeTree(Path p) throws Exception {
        if (!Files.exists(p)) return;
        try (var walk = Files.walk(p)) {
            for (Path q : walk.sorted(java.util.Comparator.reverseOrder()).toList()) Files.deleteIfExists(q);
        }
    }
}
