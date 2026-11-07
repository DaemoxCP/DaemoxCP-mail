package org.mail_panel.database;

import org.mail_panel.Main;
import org.mail_panel.security.PanelSecrets;
import org.mail_panel.sqli.dataBaseManager;

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
 * Il pannello acceso si ricollega a MySQL con la password che c'e' ADESSO nel file dei segreti, non
 * con quella che aveva all'avvio. Reperto 156: una reinstallazione completa dal menu cambia la
 * password dell'utente MySQL del pannello e riavvia MySQL; il servizio --web acceso perdeva la
 * connessione e riprovava per sempre con la vecchia («Access denied»).
 *
 * Con MySQL vero e un utente di prova (e2e_reconnect, col suo database, tolti alla fine):
 *  1. un processo «servizio» entra in MySQL come entrano il servizio e i comandi da console
 *     (Main.connectFromConfig), e resta acceso;
 *  2. come fa la reinstallazione: la password dell'utente cambia in MySQL (da root), le sue
 *     connessioni cadono (KILL, come quando MySQL riparte), e un altro processo («menu») scrive la
 *     password nuova nel file dei segreti;
 *  3. il «servizio» usa di nuovo il database: deve essere dentro, come e2e_reconnect.
 * Poi lo stesso senza la password nuova nel file: il servizio NON entra (la password la decide il
 * file dei segreti, non un'altra fonte), e appena il file la ha, entra.
 *
 * Root di MySQL: con la password del file dei segreti vero, o senza se root entra senza (i server
 * installati dalla versione dell'11/10). Si accende solo con -De2e.vm=yes, da root, MySQL acceso:
 *   java -De2e.vm=yes -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.database.MysqlReconnectTest
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
            System.out.println("SALTATA: serve -De2e.vm=yes (VM FreeBSD, root, MySQL acceso).");
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
            check("utente di prova creato", rootSql("DROP USER IF EXISTS '" + USER + "'@'localhost', '" + USER + "'@'127.0.0.1';"
                    + "CREATE DATABASE IF NOT EXISTS " + DB + ";"
                    + "CREATE USER '" + USER + "'@'localhost' IDENTIFIED BY '" + a + "';"
                    + "CREATE USER '" + USER + "'@'127.0.0.1' IDENTIFIED BY '" + a + "';"
                    + "GRANT ALL PRIVILEGES ON " + DB + ".* TO '" + USER + "'@'localhost', '" + USER + "'@'127.0.0.1';"));
            check("il pannello di prova ha la password di adesso", run("setup", a).code == 0);

            System.out.println("\n== La reinstallazione cambia la password mentre il servizio e' acceso ==");
            Process service = start("service");
            BufferedReader out = new BufferedReader(new InputStreamReader(service.getInputStream(), StandardCharsets.UTF_8));
            check("il servizio e' entrato in MySQL", waitFor(out, "CONNECTED"));
            check("MySQL: password nuova, connessioni cadute", rootSql(alter(b)) && killAll());
            check("il menu scrive la password nuova nel file dei segreti", run("write-secret", b).code == 0);
            say(service, "use");
            String line = waitLine(out, "USE ");
            check("il servizio usa di nuovo il database ed e' dentro, come " + USER, line != null && line.startsWith("USE ok " + USER + "@"));

            System.out.println("\n== MySQL cambia, il file dei segreti non ancora (la reinstallazione non ha ancora deciso) ==");
            check("MySQL: un'altra password, connessioni cadute", rootSql(alter(c)) && killAll());
            say(service, "use");
            line = waitLine(out, "USE ");
            check("il servizio NON entra con una password che il file non ha", line != null && line.startsWith("USE refused"));
            check("il menu scrive la password nel file", run("write-secret", c).code == 0);
            say(service, "use");
            line = waitLine(out, "USE ");
            check("adesso il servizio entra", line != null && line.startsWith("USE ok " + USER + "@"));
            say(service, "quit");
            service.waitFor();
        } finally {
            rootSql("DROP USER IF EXISTS '" + USER + "'@'localhost', '" + USER + "'@'127.0.0.1'; DROP DATABASE IF EXISTS " + DB + ";");
            removeTree(base);
        }
        System.out.println(failed == 0 ? "\nTutte le prove passate." : "\n" + failed + " prove FALLITE.");
        System.exit(failed == 0 ? 0 : 1);
    }

    static String alter(String p) {
        return "ALTER USER '" + USER + "'@'localhost' IDENTIFIED BY '" + p + "';"
             + "ALTER USER '" + USER + "'@'127.0.0.1' IDENTIFIED BY '" + p + "';";
    }

    /** Tutte le connessioni dell'utente di prova cadono, come quando MySQL riparte. */
    static boolean killAll() throws Exception {
        Process p = new ProcessBuilder("mysql", "--defaults-extra-file=" + rootCnf, "-N", "-e",
                "SELECT id FROM information_schema.processlist WHERE user = '" + USER + "'").redirectErrorStream(true).start();
        String ids = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
        if (p.waitFor() != 0) return false;
        StringBuilder sql = new StringBuilder();
        for (String id : ids.split("\\s+")) if (id.matches("[0-9]+")) sql.append("KILL ").append(id).append(";");
        return sql.length() == 0 || rootSql(sql.toString());
    }

    // ---------------------------------------------------------------- i processi del pannello

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
                    // Come i gestori del pannello: getConnection(), che si ricollega se serve.
                    String result;
                    try {
                        Connection c = Main.mailDatabase.getConnection();
                        if (c == null) result = "refused (no connection)";
                        else try (Statement s = c.createStatement(); ResultSet rs = s.executeQuery("SELECT CURRENT_USER()")) {
                            result = rs.next() ? "ok " + rs.getString(1) : "refused (no row)";
                        }
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
        List<String> cmd = new ArrayList<>(List.of(java, "-Dmailpanel.secrets.dir=" + base.resolve("secrets"),
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
