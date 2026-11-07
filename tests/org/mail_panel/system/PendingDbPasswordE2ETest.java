package org.mail_panel.system;

import org.mail_panel.Main;
import org.mail_panel.security.PanelSecrets;
import org.mail_panel.sqli.dataBaseManager;

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
 * Il corpo vero dell'installazione completa (Main.installOnTurn) con MySQL vero, e al posto di
 * install_mail_server.sh uno script piantato che esce prima di MySQL, dopo, o uccide il pannello a
 * meta'. Dopo ogni giro: il pannello entra ancora in MySQL? (Main.connectFromConfig, lo stesso
 * collegamento dei comandi da console.)
 *
 * Reperto 156: prima di questa correzione la password nuova diventava del pannello PRIMA dello
 * script, e ogni uscita anticipata lo lasciava con una password che MySQL rifiuta.
 *
 * Non tocca la configurazione del pannello vero: ogni giro ha una cartella sua (SQLite, file dei
 * segreti con -Dmailpanel.secrets.dir, turno dei pacchetti, copia di Postfix) e un utente MySQL di
 * prova, e2e_pending, col suo database; l'utente del pannello vero non si tocca. Per root di MySQL la
 * prova scrive un file di credenziali (600) con la password del file dei segreti vero
 * (/usr/local/etc/mail-panel), o vuota se root entra senza (come sui server installati dalla versione
 * dell'11/10, misurato sul banco rehearsal-after-pr91): lo script piantato lo usa, come lo script vero
 * usa il suo, per cambiare la password. Alla fine utente e database di prova si tolgono.
 *
 * Si accende solo con -De2e.vm=yes, da root, su FreeBSD con MySQL acceso (la VM di prova):
 *   java -De2e.vm=yes -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.PendingDbPasswordE2ETest
 */
public class PendingDbPasswordE2ETest {

    static final String USER = "e2e_pending";
    static final String DB = "e2e_pending";
    static final String DEAD_PORT = "1";        // niente ascolta: MySQL «non risponde»

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
            System.out.println("SALTATA: serve -De2e.vm=yes (VM FreeBSD, root, MySQL acceso).");
            System.exit(0);
        }
        if (!System.getProperty("os.name").toLowerCase().contains("freebsd") || !"root".equals(System.getProperty("user.name"))) {
            System.out.println("FALLITA: -De2e.vm=yes vuole FreeBSD e root.");
            System.exit(1);
        }
        rootPassword = PanelSecrets.text(PanelSecrets.MYSQL_ROOT_PASSWORD);
        base = Files.createTempDirectory("pending-db-password-e2e");
        rootCnf = base.resolve("root.cnf");
        Files.writeString(rootCnf, "[client]\nuser=root\npassword=\"" + rootPassword + "\"\n");
        Files.setPosixFilePermissions(rootCnf, PosixFilePermissions.fromString("rw-------"));
        if (!rootSql("SELECT 1")) {
            System.out.println("FALLITA: root non entra in MySQL ne' con la password del file dei segreti ne' senza.");
            System.exit(1);
        }
        System.out.println("root di MySQL: " + (rootPassword.isEmpty() ? "senza password" : "con la password del file dei segreti"));

        String c = "E2eVecchia" + word(10);
        if (!rootSql("DROP USER IF EXISTS '" + USER + "'@'localhost', '" + USER + "'@'127.0.0.1';"
                + "CREATE DATABASE IF NOT EXISTS " + DB + ";"
                + "CREATE USER '" + USER + "'@'localhost' IDENTIFIED BY '" + c + "';"
                + "CREATE USER '" + USER + "'@'127.0.0.1' IDENTIFIED BY '" + c + "';"
                + "GRANT ALL PRIVILEGES ON " + DB + ".* TO '" + USER + "'@'localhost';"
                + "GRANT ALL PRIVILEGES ON " + DB + ".* TO '" + USER + "'@'127.0.0.1';")) {
            System.out.println("FALLITA: non riesco a creare l'utente MySQL di prova.");
            System.exit(1);
        }
        try {
            scenarios();
        } finally {
            rootSql("DROP USER IF EXISTS '" + USER + "'@'localhost', '" + USER + "'@'127.0.0.1'; DROP DATABASE IF EXISTS " + DB + ";");
            removeTree(base);      // dentro ci sono i file dei segreti di prova e le credenziali di root
        }
        System.out.println(failed == 0 ? "\nTutte le prove passate." : "\n" + failed + " prove FALLITE.");
        System.exit(failed == 0 ? 0 : 1);
    }

    static void scenarios() throws Exception {
        PendingDbPassword.Probe mysql = PendingDbPassword.mysqlProbe("127.0.0.1", "3306", USER);

        System.out.println("== E1. Lo script esce prima di MySQL (come per Roundcube non configurato) ==");
        String c = fresh();
        Path d = round("e1", c, "3306");
        Run r = child(d, "install", "early");
        check("l'installazione dice di non essere riuscita", r.out.contains("RESULT installOnTurn=false"));
        check("il messaggio dice che si tiene la password di prima", r.out.contains("keeps the previous one"));
        check("la password del pannello e' quella di prima", c.equals(current(d)));
        check("nessuna password in attesa", pending(d).isEmpty());
        check("MySQL accetta ancora quella del pannello", mysql.ask(current(d)) == PendingDbPassword.Answer.ACCEPTED);
        check("il pannello entra in MySQL", connects(d));

        System.out.println("\n== E2. Lo script fallisce DOPO aver dato la password a MySQL ==");
        c = fresh();
        d = round("e2", c, "3306");
        r = child(d, "install", "late");
        check("l'installazione dice di non essere riuscita", r.out.contains("RESULT installOnTurn=false"));
        check("la password del pannello e' quella nuova", !current(d).isEmpty() && !c.equals(current(d)));
        check("nessuna password in attesa", pending(d).isEmpty());
        check("MySQL la accetta", mysql.ask(current(d)) == PendingDbPassword.Answer.ACCEPTED);
        check("il pannello entra in MySQL", connects(d));

        System.out.println("\n== E3. Lo script riesce ==");
        c = fresh();
        d = round("e3", c, "3306");
        r = child(d, "install", "ok");
        check("l'installazione e' riuscita", r.out.contains("RESULT installOnTurn=true"));
        check("la password del pannello e' quella nuova", !current(d).isEmpty() && !c.equals(current(d)));
        check("nessuna password in attesa", pending(d).isEmpty());
        check("il pannello entra in MySQL", connects(d));

        System.out.println("\n== E4. Il pannello muore dopo che MySQL ha la password nuova ==");
        c = fresh();
        d = round("e4", c, "3306");
        r = child(d, "install", "kill-after");
        check("il pannello e' morto davvero (kill -9, nessun esito)", r.code == 137 && !r.out.contains("RESULT"));
        String p = pending(d);
        check("sul disco: quella di prima e quella nuova in attesa", c.equals(current(d)) && !p.isEmpty() && !p.equals(c));
        check("MySQL conosce la nuova, non la vecchia", mysql.ask(p) == PendingDbPassword.Answer.ACCEPTED
                && mysql.ask(c) == PendingDbPassword.Answer.REJECTED);
        r = child(d, "startup");
        check("all'avvio la nuova diventa del pannello", r.out.contains("OUTCOME NEW_ADOPTED") && p.equals(current(d)) && pending(d).isEmpty());
        check("il pannello entra in MySQL", connects(d));

        System.out.println("\n== E5. Il pannello muore prima che lo script arrivi a MySQL ==");
        c = fresh();
        d = round("e5", c, "3306");
        r = child(d, "install", "kill-before");
        check("il pannello e' morto davvero", r.code == 137 && !r.out.contains("RESULT"));
        check("sul disco: quella di prima e una nuova in attesa", c.equals(current(d)) && !pending(d).isEmpty());
        r = child(d, "startup");
        check("all'avvio si tiene quella di prima e si butta la nuova", r.out.contains("OUTCOME OLD_KEPT") && c.equals(current(d)) && pending(d).isEmpty());
        check("il pannello entra in MySQL", connects(d));

        System.out.println("\n== E6. Dopo lo script MySQL non risponde al pannello ==");
        c = fresh();
        d = round("e6", c, DEAD_PORT);
        r = child(d, "install", "late");
        p = pending(d);
        check("non si decide: quella di prima resta, la nuova in attesa", r.out.contains("RESULT installOnTurn=false")
                && c.equals(current(d)) && !p.isEmpty() && !p.equals(c));
        check("e lo dice", r.out.contains("does not answer"));
        check("MySQL (lo script ci e' arrivato) conosce la nuova", mysql.ask(p) == PendingDbPassword.Answer.ACCEPTED);
        child(d, "port", "3306");
        r = child(d, "startup");
        check("quando MySQL risponde, all'avvio la nuova diventa del pannello", r.out.contains("OUTCOME NEW_ADOPTED") && p.equals(current(d)) && pending(d).isEmpty());
        check("il pannello entra in MySQL", connects(d));

        System.out.println("\n== E7. Due installazioni con MySQL muto: la seconda riusa quella in attesa ==");
        c = fresh();
        d = round("e7", c, DEAD_PORT);
        child(d, "install", "late");
        String first = pending(d);
        check("dopo la prima: MySQL conosce quella in attesa", !first.isEmpty() && mysql.ask(first) == PendingDbPassword.Answer.ACCEPTED);
        r = child(d, "install", "early");
        check("dopo la seconda (uscita prima di MySQL): in attesa c'e' ancora la stessa", first.equals(pending(d)) && c.equals(current(d)));
        check("e lo dice", r.out.contains("gives MySQL that one again"));
        child(d, "port", "3306");
        r = child(d, "startup");
        check("all'avvio diventa del pannello", r.out.contains("OUTCOME NEW_ADOPTED") && first.equals(current(d)));
        check("il pannello entra in MySQL", connects(d));

        System.out.println("\n== E8. All'avvio il turno dei pacchetti lo tiene un altro processo ==");
        c = fresh();
        d = round("e8", c, "3306");
        child(d, "install", "kill-after");
        p = pending(d);
        PackageQueue.list = d.resolve("maintenance-locks");
        PackageQueue.turnLock = d.resolve("package-turn.lock");
        check("qui prendo il turno (come un'installazione in corso)", PackageQueue.take("e2e-holder", "installazione di prova") == null);
        r = child(d, "startup");
        check("l'avvio non decide e non tocca niente", r.out.contains("OUTCOME NOT_NOW") && c.equals(current(d)) && p.equals(pending(d)));
        check("e dice chi tiene il turno", r.out.contains("installazione di prova"));
        PackageQueue.release("e2e-holder");
        r = child(d, "startup");
        check("rilasciato il turno, il prossimo avvio decide", r.out.contains("OUTCOME NEW_ADOPTED") && p.equals(current(d)));
        check("il pannello entra in MySQL", connects(d));

        System.out.println("\n== E9. Server rotto dalla versione di prima: MySQL rifiuta la password del pannello ==");
        c = fresh();
        String broken = "E2eRotta" + word(10);
        d = round("e9", broken, "3306");     // MySQL ha c, il pannello broken
        check("prima: il pannello NON entra", !connects(d));
        r = child(d, "startup");
        check("senza copia di Postfix: non cambia niente", r.out.contains("OUTCOME NONE_ACCEPTED") && broken.equals(current(d)));
        Files.writeString(d.resolve("mysql-virtual-domains.cf"), "user = " + USER + "\npassword = " + c
                + "\nhosts = 127.0.0.1\ndbname = " + DB + "\nquery = SELECT 1\n");
        r = child(d, "startup");
        check("con la copia di Postfix che MySQL accetta: diventa del pannello", r.out.contains("OUTCOME COPY_ADOPTED") && c.equals(current(d)));
        check("il pannello entra in MySQL", connects(d));
        r = child(d, "startup");
        check("l'avvio dopo non fa niente", r.out.contains("OUTCOME NOTHING_TO_DO") && c.equals(current(d)));

        System.out.println("\n== E10. La password nuova non si puo' tenere in attesa ==");
        c = fresh();
        d = round("e10", c, "3306");
        Path blocker = d.resolve("secrets").resolve("panel-secrets.properties.tmp");
        Files.createDirectories(blocker);
        Files.writeString(blocker.resolve("x"), "il file dei segreti non si riscrive");
        r = child(d, "install", "ok");
        check("l'installazione non parte", r.out.contains("RESULT installOnTurn=false") && r.out.contains("STOPPED"));
        check("lo script NON e' partito", !Files.exists(d.resolve("script-ran")));
        check("MySQL ha ancora quella di prima", mysql.ask(c) == PendingDbPassword.Answer.ACCEPTED);
        check("il pannello entra in MySQL", connects(d));
    }

    // ---------------------------------------------------------------- un giro

    /** La password di prova di MySQL rimessa a 'c', e una cartella nuova col pannello che ha 'current'. */
    static Path round(String name, String current, String port) throws Exception {
        Path d = base.resolve(name);
        Files.createDirectories(d);
        Run r = child(d, "setup", current, port);
        if (r.code != 0) throw new IllegalStateException("preparazione del giro " + name + " fallita");
        return d;
    }

    /** Una password nuova per MySQL, e MySQL rimesso su quella. */
    static String fresh() throws Exception {
        String c = "E2eVecchia" + word(10);
        if (!rootSql("ALTER USER '" + USER + "'@'localhost' IDENTIFIED BY '" + c + "';"
                + "ALTER USER '" + USER + "'@'127.0.0.1' IDENTIFIED BY '" + c + "';"))
            throw new IllegalStateException("non riesco a rimettere la password di prova");
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
        List<String> cmd = new ArrayList<>(List.of(java, "-Dmailpanel.secrets.dir=" + d.resolve("secrets"),
                "-cp", absolute(System.getProperty("java.class.path")),
                PendingDbPasswordE2ETest.class.getName(), "child"));
        cmd.addAll(List.of(step));
        ProcessBuilder pb = new ProcessBuilder(cmd).directory(d.toFile()).redirectErrorStream(true);
        pb.environment().put("E2E_ROOT_CNF", rootCnf.toString());   // lo eredita lo script piantato
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

    // ---------------------------------------------------------------- il processo del pannello

    /** Lo script piantato al posto di install_mail_server.sh. */
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
        return "#!/bin/sh\n# prova: piantato al posto di install_mail_server.sh\ntouch ./script-ran\nUSER3=\"$3\"\n" + body;
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
                String refusal = PackageQueue.take("reinstall", "installazione di prova");
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
                org.mail_panel.i18n.I18n.setCurrent("en");
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
