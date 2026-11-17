package org.daemoxcp.mail.sqli;

import org.daemoxcp.mail.TestSql;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

/**
 * The panel's SQLite database used by two processes together, like the --web service and the menu
 * (or a console command) started from the same folder. Reperto 156: the menu with the service on
 * ended in SQLITE_BUSY on the server name, the flags of the services and the MySQL configuration.
 *
 *  A. A "service" process makes the reads the service makes (at start and at every request) and
 *     stays alive; a "menu" process writes everything the reinstallation writes. Every write
 *     succeeds, at once, and a third process reads the written values back.
 *  B. The "service" holds a write open for six seconds (a real transaction); meanwhile the "menu"
 *     writes: it waits and succeeds. Six and not three: sqlite-jdbc already waits 3 seconds on its
 *     own (default busy_timeout), and with three the test did not see the panel's wait removed.
 *
 * Everything in a temporary folder (dataBaseManager works on database/daemoxcp-mail.db of the current
 * folder, the secrets with -Ddaemoxcp.mail.secrets.dir), so the child processes start there.
 *
 * Usage: java -cp "tests:target/daemoxcp-mail-1.0.jar" org.daemoxcp.mail.sqli.SqliteSharedTest
 */
public class SqliteSharedTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    public static void main(String[] args) throws Exception {
        if (args.length > 0) { child(args); return; }
        Path d = Files.createTempDirectory("sqlite-shared");
        try {
            Run init = run(d, "init");
            check("database created", init.code == 0);

            System.out.println("\n== A. The service reads and stays on, the menu writes ==");
            Process service = start(d, "service-reads");
            BufferedReader out = new BufferedReader(new InputStreamReader(service.getInputStream(), StandardCharsets.UTF_8));
            check("the service made its reads and stays on", waitFor(out, "READY"));
            long t0 = System.nanoTime();
            Run w = run(d, "menu-writes", "A");
            long ms = (System.nanoTime() - t0) / 1_000_000;
            check("every write of the menu succeeds", w.code == 0 && w.out.contains("ALL WRITES OK"));
            check("no SQLITE_BUSY", !w.out.contains("SQLITE_BUSY") && !w.out.toLowerCase().contains("database is locked"));
            check("and without waiting (" + ms + " ms, the menu's JVM start included)", ms < 10_000);
            Run r = run(d, "read-back", "A");
            check("another process reads the written values back", r.code == 0 && r.out.contains("READ BACK OK"));
            stop(service);

            System.out.println("\n== B. The service holds a write open for six seconds, the menu writes meanwhile ==");
            service = start(d, "service-holds-write");
            out = new BufferedReader(new InputStreamReader(service.getInputStream(), StandardCharsets.UTF_8));
            check("the service opened the write", waitFor(out, "HOLDING"));
            t0 = System.nanoTime();
            w = run(d, "menu-writes", "B");
            ms = (System.nanoTime() - t0) / 1_000_000;
            check("the menu waits and succeeds (" + ms + " ms)", w.code == 0 && w.out.contains("ALL WRITES OK"));
            check("it really waited for the end of the other write", ms >= 5_000);
            check("the service closed its write", waitFor(out, "COMMITTED"));
            service.waitFor();
            r = run(d, "read-back", "B");
            check("the last write wins, the menu's", r.code == 0 && r.out.contains("READ BACK OK"));
        } finally {
            removeTree(d);
        }
        System.out.println(failed == 0 ? "\nAll checks passed." : "\n" + failed + " checks FAILED.");
        System.exit(failed == 0 ? 0 : 1);
    }

    // ---------------------------------------------------------------- the processes

    static void child(String[] a) throws Exception {
        dataBaseManager db = new dataBaseManager();
        switch (a[0]) {
            case "init" -> {
                db.ensureMailHostnameColumn();
                if (db.check_tables() < 1) { db.create_tables(); db.insert_data_default(); }
                db.ensureMailHostnameColumn();
                db.ensureSslChainColumn();
                db.ensureRoundcubeColumns();
                db.ensurePostfixColumn();
                System.exit(0);
            }
            case "service-reads" -> {
                // What the service does: the columns at start (Main.main), then the reads of the
                // requests and of the jobs.
                db.ensureMailHostnameColumn();
                db.ensureSslChainColumn();
                db.ensureRoundcubeColumns();
                db.ensurePostfixColumn();
                db.check_tables();
                db.getMailHostname();
                db.isServiceInstalled("postfix");
                db.isServiceInstalled("dovecot");
                db.getRoundcubeDomain();
                db.getRoundcubePort();
                db.getRoundcubeSslCert();
                db.getRoundcubeSslKey();
                db.getRoundcubeSslChain();
                db.mysqlPassword();
                db.panelTlsKey();
                try (ResultSet rs = db.get_data_config()) { if (rs.next()) rs.getString("mysql_host"); }
                System.out.println("READY");
                System.out.flush();
                System.in.read();      // until the parent closes
                System.exit(0);
            }
            case "service-holds-write" -> {
                try (java.sql.Connection own = TestSql.sqlite(); Statement s = own.createStatement()) {
                    s.execute("BEGIN IMMEDIATE");
                    s.executeUpdate("UPDATE config SET mail_hostname = 'held.by.service' WHERE id = 1");
                    System.out.println("HOLDING");
                    System.out.flush();
                    Thread.sleep(6000);
                    s.execute("COMMIT");
                }
                System.out.println("COMMITTED");
                System.out.flush();
                System.exit(0);
            }
            case "menu-writes" -> {
                String tag = a[1];
                // What the full reinstallation writes (Main.installOnTurn), plus the menu's
                // configuration pages.
                List<String> bad = new ArrayList<>();
                if (!db.setMailHostname("mail-" + tag + ".e2e.test")) bad.add("setMailHostname");
                if (!db.resetAllServices()) bad.add("resetAllServices");
                if (!db.update_mysql_config("127.0.0.1", "3306", "daemoxcp_mail", "Password" + tag, "mailserver")) bad.add("update_mysql_config");
                if (!db.setServiceInstalled("postfix", true)) bad.add("setServiceInstalled");
                if (!db.updateRoundcubeConfig("webmail-" + tag + ".e2e.test", "8443", "", "", "")) bad.add("updateRoundcubeConfig");
                if (!db.update_panel_config("0.0.0.0", "2096", "", "", "", "mailpanel-")) bad.add("update_panel_config");
                System.out.println(bad.isEmpty() ? "ALL WRITES OK" : "FAILED WRITES " + bad);
                System.exit(bad.isEmpty() ? 0 : 1);
            }
            case "read-back" -> {
                String tag = a[1];
                boolean ok = ("mail-" + tag + ".e2e.test").equals(db.getMailHostname())
                        && db.isServiceInstalled("postfix")
                        && ("webmail-" + tag + ".e2e.test").equals(db.getRoundcubeDomain())
                        && ("Password" + tag).equals(db.mysqlPassword());
                System.out.println(ok ? "READ BACK OK" : "READ BACK WRONG: " + db.getMailHostname() + " " + db.getRoundcubeDomain());
                System.exit(ok ? 0 : 1);
            }
            default -> throw new IllegalArgumentException(a[0]);
        }
    }

    record Run(int code, String out) {}

    static Process start(Path d, String... step) throws Exception {
        String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
        List<String> cmd = new ArrayList<>(List.of(java, "-Ddaemoxcp.mail.secrets.dir=" + d.resolve("secrets"),
                "-cp", absolute(System.getProperty("java.class.path")), SqliteSharedTest.class.getName()));
        cmd.addAll(List.of(step));
        return new ProcessBuilder(cmd).directory(d.toFile()).redirectErrorStream(true).start();
    }

    static Run run(Path d, String... step) throws Exception {
        Process p = start(d, step);
        p.getOutputStream().close();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        int code = p.waitFor();
        for (String line : out.split("\n")) if (!line.isBlank()) System.out.println("      | " + line);
        return new Run(code, out);
    }

    static boolean waitFor(BufferedReader out, String word) throws Exception {
        String line;
        while ((line = out.readLine()) != null) {
            System.out.println("      | " + line);
            if (line.contains(word)) return true;
        }
        return false;
    }

    static void stop(Process p) throws Exception {
        try (OutputStream in = p.getOutputStream()) { in.write('\n'); }
        p.waitFor();
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
