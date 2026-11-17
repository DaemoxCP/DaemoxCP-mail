package org.daemoxcp.mail.system;

import org.daemoxcp.mail.Main;
import org.daemoxcp.mail.security.PanelSecrets;
import org.daemoxcp.mail.sqli.dataBaseManager;

import java.io.Reader;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

/**
 * The real body of the full installation (Main.installOnTurn) with real MySQL, and in place of
 * install_mail_server.sh a planted script that exits before MySQL, after, or kills the panel
 * halfway. After every round: does the panel still get into MySQL? (Main.connectFromConfig, the same
 * connection as the console commands.)
 *
 * Reperto 156: before this fix the new password became the panel's BEFORE the script, and every
 * early exit left it with a password MySQL refuses.
 *
 * It does not touch the real panel's configuration: every round has a folder of its own (SQLite,
 * secrets file with -Ddaemoxcp.mail.secrets.dir, package turn, Postfix copy) and a test MySQL user,
 * e2e_pending, with its database; the real panel's user is not touched. For MySQL's root the test
 * writes a credentials file (600) with the password of the real secrets file
 * (/usr/local/etc/daemoxcp-mail), or empty if root gets in without (as on the servers installed by the
 * 11/10 version, measured on the rehearsal-after-pr91 bench): the planted script uses it, as the
 * real script uses its own, to change the password. At the end the test user and database are removed.
 *
 * It runs only with -De2e.vm=yes, as root, on FreeBSD with MySQL on (the test VM):
 *   java -De2e.vm=yes -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.PendingDbPasswordE2ETest
 */
public class PendingDbPasswordE2ETest {

    static final String USER = "e2e_pending";
    static final String DB = "e2e_pending";
    static final String DEAD_PORT = "1";        // nothing listens: MySQL "does not answer"

    static int failed = 0;
    static Path base;
    static Path rootCnf;
    static String rootPassword;
    static final SecureRandom RANDOM = new SecureRandom();

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    public static void main(String[] args) throws Exception {
        if (args.length > 0 && args[0].equals("child")) { child(args); return; }

        if (!"yes".equals(System.getProperty("e2e.vm"))) {
            System.out.println("SKIPPED: it needs -De2e.vm=yes (FreeBSD VM, root, MySQL on).");
            System.exit(0);
        }
        if (!System.getProperty("os.name").toLowerCase().contains("freebsd") || !"root".equals(System.getProperty("user.name"))) {
            System.out.println("FAILED: -De2e.vm=yes wants FreeBSD and root.");
            System.exit(1);
        }
        rootPassword = PanelSecrets.text(PanelSecrets.MYSQL_ROOT_PASSWORD);
        base = Files.createTempDirectory("pending-db-password-e2e");
        rootCnf = base.resolve("root.cnf");
        Files.writeString(rootCnf, "[client]\nuser=root\npassword=\"" + rootPassword + "\"\n");
        Files.setPosixFilePermissions(rootCnf, PosixFilePermissions.fromString("rw-------"));
        if (!rootSql("SELECT 1")) {
            System.out.println("FAILED: root gets into MySQL neither with the secrets file's password nor without.");
            System.exit(1);
        }
        System.out.println("MySQL root: " + (rootPassword.isEmpty() ? "without a password" : "with the secrets file's password"));

        String c = "E2eOld" + word(10);
        if (!rootSql("DROP USER IF EXISTS '" + USER + "'@'localhost', '" + USER + "'@'127.0.0.1';"
                + "CREATE DATABASE IF NOT EXISTS " + DB + ";"
                + "CREATE USER '" + USER + "'@'localhost' IDENTIFIED BY '" + c + "';"
                + "CREATE USER '" + USER + "'@'127.0.0.1' IDENTIFIED BY '" + c + "';"
                + "GRANT ALL PRIVILEGES ON " + DB + ".* TO '" + USER + "'@'localhost';"
                + "GRANT ALL PRIVILEGES ON " + DB + ".* TO '" + USER + "'@'127.0.0.1';")) {
            System.out.println("FAILED: I cannot create the test MySQL user.");
            System.exit(1);
        }
        try {
            scenarios();
        } finally {
            rootSql("DROP USER IF EXISTS '" + USER + "'@'localhost', '" + USER + "'@'127.0.0.1'; DROP DATABASE IF EXISTS " + DB + ";");
            removeTree(base);      // inside are the test secrets files and root's credentials
        }
        System.out.println(failed == 0 ? "\nAll checks passed." : "\n" + failed + " checks FAILED.");
        System.exit(failed == 0 ? 0 : 1);
    }

    static void scenarios() throws Exception {
        PendingDbPassword.Probe mysql = PendingDbPassword.mysqlProbe("127.0.0.1", "3306", USER);

        System.out.println("== E1. The script exits before MySQL (as for an unconfigured Roundcube) ==");
        String c = fresh();
        Path d = round("e1", c, "3306");
        Run r = child(d, "install", "early");
        check("the installation says it did not succeed", r.out.contains("RESULT installOnTurn=false"));
        check("the message says the old password is kept", r.out.contains("keeps the previous one"));
        check("the panel's password is the old one", c.equals(current(d)));
        check("no pending password", pending(d).isEmpty());
        check("MySQL still accepts the panel's", mysql.ask(current(d)) == PendingDbPassword.Answer.ACCEPTED);
        check("the panel gets into MySQL", connects(d));

        System.out.println("\n== E2. The script fails AFTER giving MySQL the password ==");
        c = fresh();
        d = round("e2", c, "3306");
        r = child(d, "install", "late");
        check("the installation says it did not succeed", r.out.contains("RESULT installOnTurn=false"));
        check("the panel's password is the new one", !current(d).isEmpty() && !c.equals(current(d)));
        check("no pending password", pending(d).isEmpty());
        check("MySQL accepts it", mysql.ask(current(d)) == PendingDbPassword.Answer.ACCEPTED);
        check("the panel gets into MySQL", connects(d));

        System.out.println("\n== E3. The script succeeds ==");
        c = fresh();
        d = round("e3", c, "3306");
        r = child(d, "install", "ok");
        check("the installation succeeded", r.out.contains("RESULT installOnTurn=true"));
        check("the panel's password is the new one", !current(d).isEmpty() && !c.equals(current(d)));
        check("no pending password", pending(d).isEmpty());
        check("the panel gets into MySQL", connects(d));

        System.out.println("\n== E4. The panel dies after MySQL has the new password ==");
        c = fresh();
        d = round("e4", c, "3306");
        r = child(d, "install", "kill-after");
        check("the panel really died (kill -9, no outcome)", r.code == 137 && !r.out.contains("RESULT"));
        String p = pending(d);
        check("on disk: the old one and the new one pending", c.equals(current(d)) && !p.isEmpty() && !p.equals(c));
        check("MySQL knows the new one, not the old one", mysql.ask(p) == PendingDbPassword.Answer.ACCEPTED
                && mysql.ask(c) == PendingDbPassword.Answer.REJECTED);
        r = child(d, "startup");
        check("at start the new one becomes the panel's", r.out.contains("OUTCOME NEW_ADOPTED") && p.equals(current(d)) && pending(d).isEmpty());
        check("the panel gets into MySQL", connects(d));

        System.out.println("\n== E5. The panel dies before the script reaches MySQL ==");
        c = fresh();
        d = round("e5", c, "3306");
        r = child(d, "install", "kill-before");
        check("the panel really died", r.code == 137 && !r.out.contains("RESULT"));
        check("on disk: the old one and a new one pending", c.equals(current(d)) && !pending(d).isEmpty());
        r = child(d, "startup");
        check("at start the old one is kept and the new one thrown away", r.out.contains("OUTCOME OLD_KEPT") && c.equals(current(d)) && pending(d).isEmpty());
        check("the panel gets into MySQL", connects(d));

        System.out.println("\n== E6. After the script MySQL does not answer the panel ==");
        c = fresh();
        d = round("e6", c, DEAD_PORT);
        r = child(d, "install", "late");
        p = pending(d);
        check("it is not decided: the old one stays, the new one pending", r.out.contains("RESULT installOnTurn=false")
                && c.equals(current(d)) && !p.isEmpty() && !p.equals(c));
        check("and it says so", r.out.contains("does not answer"));
        check("MySQL (the script got there) knows the new one", mysql.ask(p) == PendingDbPassword.Answer.ACCEPTED);
        child(d, "port", "3306");
        r = child(d, "startup");
        check("when MySQL answers, at start the new one becomes the panel's", r.out.contains("OUTCOME NEW_ADOPTED") && p.equals(current(d)) && pending(d).isEmpty());
        check("the panel gets into MySQL", connects(d));

        System.out.println("\n== E7. Two installations with MySQL silent: the second reuses the pending one ==");
        c = fresh();
        d = round("e7", c, DEAD_PORT);
        child(d, "install", "late");
        String first = pending(d);
        check("after the first: MySQL knows the pending one", !first.isEmpty() && mysql.ask(first) == PendingDbPassword.Answer.ACCEPTED);
        r = child(d, "install", "early");
        check("after the second (exit before MySQL): the same one is still pending", first.equals(pending(d)) && c.equals(current(d)));
        check("and it says so", r.out.contains("gives MySQL that one again"));
        child(d, "port", "3306");
        r = child(d, "startup");
        check("at start it becomes the panel's", r.out.contains("OUTCOME NEW_ADOPTED") && first.equals(current(d)));
        check("the panel gets into MySQL", connects(d));

        System.out.println("\n== E8. At start another process holds the package turn ==");
        c = fresh();
        d = round("e8", c, "3306");
        child(d, "install", "kill-after");
        p = pending(d);
        PackageQueue.list = d.resolve("maintenance-locks");
        PackageQueue.turnLock = d.resolve("package-turn.lock");
        check("here I take the turn (like an installation in progress)", PackageQueue.take("e2e-holder", "test installation") == null);
        r = child(d, "startup");
        check("the start decides nothing and touches nothing", r.out.contains("OUTCOME NOT_NOW") && c.equals(current(d)) && p.equals(pending(d)));
        check("and it says who holds the turn", r.out.contains("test installation"));
        PackageQueue.release("e2e-holder");
        r = child(d, "startup");
        check("with the turn released, the next start decides", r.out.contains("OUTCOME NEW_ADOPTED") && p.equals(current(d)));
        check("the panel gets into MySQL", connects(d));

        System.out.println("\n== E9. Server broken by the old version: MySQL refuses the panel's password ==");
        c = fresh();
        String broken = "E2eBroken" + word(10);
        d = round("e9", broken, "3306");     // MySQL has c, the panel broken
        check("before: the panel does NOT get in", !connects(d));
        r = child(d, "startup");
        check("without a Postfix copy: nothing changes", r.out.contains("OUTCOME NONE_ACCEPTED") && broken.equals(current(d)));
        Files.writeString(d.resolve("mysql-virtual-domains.cf"), "user = " + USER + "\npassword = " + c
                + "\nhosts = 127.0.0.1\ndbname = " + DB + "\nquery = SELECT 1\n");
        r = child(d, "startup");
        check("with the Postfix copy MySQL accepts: it becomes the panel's", r.out.contains("OUTCOME COPY_ADOPTED") && c.equals(current(d)));
        check("the panel gets into MySQL", connects(d));
        r = child(d, "startup");
        check("the start after does nothing", r.out.contains("OUTCOME NOTHING_TO_DO") && c.equals(current(d)));

        System.out.println("\n== E10. The new password cannot be kept pending ==");
        c = fresh();
        d = round("e10", c, "3306");
        Path blocker = d.resolve("secrets").resolve("panel-secrets.properties.tmp");
        Files.createDirectories(blocker);
        Files.writeString(blocker.resolve("x"), "the secrets file cannot be rewritten");
        r = child(d, "install", "ok");
        check("the installation does not start", r.out.contains("RESULT installOnTurn=false") && r.out.contains("STOPPED"));
        check("the script did NOT start", !Files.exists(d.resolve("script-ran")));
        check("MySQL still has the old one", mysql.ask(c) == PendingDbPassword.Answer.ACCEPTED);
        check("the panel gets into MySQL", connects(d));
    }

    // ---------------------------------------------------------------- a round

    /** The test MySQL password set back to 'c', and a new folder with the panel having 'current'. */
    static Path round(String name, String current, String port) throws Exception {
        Path d = base.resolve(name);
        Files.createDirectories(d);
        Run r = child(d, "setup", current, port);
        if (r.code != 0) throw new IllegalStateException("preparation of round " + name + " failed");
        return d;
    }

    /** A new password for MySQL, and MySQL set back to it. */
    static String fresh() throws Exception {
        String c = "E2eOld" + word(10);
        if (!rootSql("ALTER USER '" + USER + "'@'localhost' IDENTIFIED BY '" + c + "';"
                + "ALTER USER '" + USER + "'@'127.0.0.1' IDENTIFIED BY '" + c + "';"))
            throw new IllegalStateException("I cannot set the test password back");
        return c;
    }

    static void removeTree(Path p) throws Exception {
        if (!Files.exists(p)) return;
        try (var walk = Files.walk(p)) {
            for (Path q : walk.sorted(java.util.Comparator.reverseOrder()).toList()) Files.deleteIfExists(q);
        }
    }

    static String word(int n) {
        String a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < n; i++) b.append(a.charAt(RANDOM.nextInt(a.length())));
        return b.toString();
    }

    static Properties secrets(Path d) throws Exception {
        Properties p = new Properties();
        Path f = d.resolve("secrets").resolve("panel-secrets.properties");
        if (Files.exists(f)) try (Reader r = Files.newBufferedReader(f, StandardCharsets.UTF_8)) { p.load(r); }
        return p;
    }

    static String current(Path d) throws Exception { return secrets(d).getProperty(PanelSecrets.MYSQL_PASSWORD, ""); }
    static String pending(Path d) throws Exception { return secrets(d).getProperty(PanelSecrets.MYSQL_PASSWORD_PENDING, ""); }

    static boolean connects(Path d) throws Exception {
        return child(d, "connect").out.contains("CONNECT ok");
    }

    record Run(int code, String out) {}

    static Run child(Path d, String... step) throws Exception {
        String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
        List<String> cmd = new ArrayList<>(List.of(java, "-Ddaemoxcp.mail.secrets.dir=" + d.resolve("secrets"),
                "-cp", absolute(System.getProperty("java.class.path")),
                PendingDbPasswordE2ETest.class.getName(), "child"));
        cmd.addAll(List.of(step));
        ProcessBuilder pb = new ProcessBuilder(cmd).directory(d.toFile()).redirectErrorStream(true);
        pb.environment().put("E2E_ROOT_CNF", rootCnf.toString());   // the planted script inherits it
        pb.redirectInput(ProcessBuilder.Redirect.from(new java.io.File("/dev/null")));
        Process pr = pb.start();
        String out = new String(pr.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        int code = pr.waitFor();
        for (String line : out.split("\n")) System.out.println("      | " + line);
        return new Run(code, out);
    }

    static String absolute(String cp) {
        StringBuilder b = new StringBuilder();
        for (String part : cp.split(java.io.File.pathSeparator)) {
            if (b.length() > 0) b.append(java.io.File.pathSeparator);
            b.append(Path.of(part).toAbsolutePath());
        }
        return b.toString();
    }

    static boolean rootSql(String sql) throws Exception {
        Process p = new ProcessBuilder("mysql", "--defaults-extra-file=" + rootCnf, "-e", sql)
                .redirectErrorStream(true).start();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        int code = p.waitFor();
        if (code != 0) System.out.println("  mysql: " + out.trim());
        return code == 0;
    }

    // ---------------------------------------------------------------- the panel's process

    /** The script planted in place of install_mail_server.sh. */
    static String plantedScript(String kind) {
        String setPassword = """
                mysql --defaults-extra-file="$E2E_ROOT_CNF" -e "ALTER USER '$USER3'@'localhost' IDENTIFIED BY '$MYSQL_PASSWORD'; ALTER USER '$USER3'@'127.0.0.1' IDENTIFIED BY '$MYSQL_PASSWORD';" || exit 9
                echo "planted: MySQL has the new password"
                """;
        String body = switch (kind) {
            case "early" -> "echo \"planted: early exit, before MySQL\"\nexit 1\n";
            case "late" -> setPassword + "echo \"planted: failing after MySQL\"\nexit 1\n";
            case "ok" -> setPassword + "exit 0\n";
            case "kill-after" -> setPassword + "kill -9 $PPID\nsleep 3\nexit 0\n";
            case "kill-before" -> "kill -9 $PPID\nsleep 3\nexit 0\n";
            default -> throw new IllegalArgumentException(kind);
        };
        return "#!/bin/sh\n# test: planted in place of install_mail_server.sh\ntouch ./script-ran\nUSER3=\"$3\"\n" + body;
    }

    static void child(String[] a) throws Exception {
        Path cwd = Path.of("").toAbsolutePath();
        PackageQueue.list = cwd.resolve("maintenance-locks");
        PackageQueue.turnLock = cwd.resolve("package-turn.lock");
        PendingDbPassword.postfixMap = cwd.resolve("mysql-virtual-domains.cf");
        Main.dbManager = new dataBaseManager();
        Main.dbManager.ensureMailHostnameColumn();
        Main.dbManager.ensureSslChainColumn();
        Main.dbManager.ensureRoundcubeColumns();
        Main.dbManager.ensurePostfixColumn();
        if (Main.dbManager.check_tables() < 1) {
            Main.dbManager.create_tables();
            Main.dbManager.insert_data_default();
        }
        switch (a[1]) {
            case "setup" -> {
                Main.dbManager.update_mysql_config("127.0.0.1", a[3], USER, a[2], DB);
                System.exit(a[2].equals(Main.dbManager.mysqlPassword()) ? 0 : 1);
            }
            case "port" -> {
                Main.dbManager.update_mysql_config("127.0.0.1", a[2], USER, Main.dbManager.mysqlPassword(), DB);
                System.exit(0);
            }
            case "install" -> {
                Files.createDirectories(cwd.resolve("install_scripts"));
                Files.writeString(cwd.resolve("install_scripts/install_mail_server.sh"), plantedScript(a[2]));
                Files.deleteIfExists(cwd.resolve("script-ran"));
                String refusal = PackageQueue.take("reinstall", "test installation");
                if (refusal != null) { System.out.println("TURN " + refusal); System.exit(1); }
                boolean ok;
                try {
                    Method m = Main.class.getDeclaredMethod("installOnTurn", String.class);
                    m.setAccessible(true);
                    ok = (Boolean) m.invoke(null, "mail.e2e.test");
                } finally {
                    PackageQueue.release("reinstall");
                }
                System.out.println("RESULT installOnTurn=" + ok);
                System.exit(0);
            }
            case "startup" -> {
                org.daemoxcp.mail.i18n.I18n.setCurrent("en");
                PendingDbPassword.Result r = PendingDbPassword.settleAtStartup(Main.dbManager);
                System.out.println("OUTCOME " + r.outcome() + (r.message().isEmpty() ? "" : " " + r.message()));
                System.exit(0);
            }
            case "connect" -> {
                Method m = Main.class.getDeclaredMethod("connectFromConfig");
                m.setAccessible(true);
                String why = (String) m.invoke(null);
                System.out.println(why == null ? "CONNECT ok" : "CONNECT refused: " + why);
                if (Main.mailDatabase != null) Main.mailDatabase.close();
                System.exit(why == null ? 0 : 3);
            }
            default -> throw new IllegalArgumentException(a[1]);
        }
    }
}
