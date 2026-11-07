package org.mail_panel.sqli;

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
 * Il database SQLite del pannello usato da due processi insieme, come il servizio --web e il
 * menu (o un comando da console) avviati dalla stessa cartella. Reperto 156: il menu col servizio
 * acceso finiva in SQLITE_BUSY su nome del server, flag dei servizi e configurazione MySQL.
 *
 *  A. Un processo «servizio» fa le letture che fa il servizio (all'avvio e a ogni richiesta) e
 *     resta vivo; un processo «menu» scrive tutto quello che scrive la reinstallazione. Ogni
 *     scrittura riesce, subito, e un terzo processo rilegge i valori scritti.
 *  B. Il «servizio» tiene una scrittura aperta per sei secondi (una transazione vera); il «menu»
 *     scrive intanto: aspetta e riesce. Sei e non tre: sqlite-jdbc aspetta gia' 3 secondi di suo
 *     (busy_timeout predefinito), e con tre la prova non vedeva togliere quello del pannello.
 *
 * Tutto in una cartella temporanea (dataBaseManager lavora su database/mail_panel.db della cartella
 * corrente, i segreti con -Dmailpanel.secrets.dir), quindi i processi figli partono li'.
 *
 * Uso: java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.sqli.SqliteSharedTest
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
            check("database creato", init.code == 0);

            System.out.println("\n== A. Il servizio legge e resta acceso, il menu scrive ==");
            Process service = start(d, "service-reads");
            BufferedReader out = new BufferedReader(new InputStreamReader(service.getInputStream(), StandardCharsets.UTF_8));
            check("il servizio ha fatto le sue letture e resta acceso", waitFor(out, "READY"));
            long t0 = System.nanoTime();
            Run w = run(d, "menu-writes", "A");
            long ms = (System.nanoTime() - t0) / 1_000_000;
            check("ogni scrittura del menu riesce", w.code == 0 && w.out.contains("ALL WRITES OK"));
            check("nessun SQLITE_BUSY", !w.out.contains("SQLITE_BUSY") && !w.out.toLowerCase().contains("database is locked"));
            check("e senza aspettare (" + ms + " ms, il menu compreso l'avvio della JVM)", ms < 10_000);
            Run r = run(d, "read-back", "A");
            check("un altro processo rilegge i valori scritti", r.code == 0 && r.out.contains("READ BACK OK"));
            stop(service);

            System.out.println("\n== B. Il servizio tiene una scrittura aperta sei secondi, il menu scrive intanto ==");
            service = start(d, "service-holds-write");
            out = new BufferedReader(new InputStreamReader(service.getInputStream(), StandardCharsets.UTF_8));
            check("il servizio ha aperto la scrittura", waitFor(out, "HOLDING"));
            t0 = System.nanoTime();
            w = run(d, "menu-writes", "B");
            ms = (System.nanoTime() - t0) / 1_000_000;
            check("il menu aspetta e riesce (" + ms + " ms)", w.code == 0 && w.out.contains("ALL WRITES OK"));
            check("ha davvero aspettato la fine dell'altra scrittura", ms >= 5_000);
            check("il servizio ha chiuso la sua scrittura", waitFor(out, "COMMITTED"));
            service.waitFor();
            r = run(d, "read-back", "B");
            check("vince l'ultima scrittura, quella del menu", r.code == 0 && r.out.contains("READ BACK OK"));
        } finally {
            removeTree(d);
        }
        System.out.println(failed == 0 ? "\nTutte le prove passate." : "\n" + failed + " prove FALLITE.");
        System.exit(failed == 0 ? 0 : 1);
    }

    // ---------------------------------------------------------------- i processi

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
                // Quello che fa il servizio: le colonne all'avvio (Main.main), poi le letture delle
                // richieste e dei lavori.
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
                System.in.read();      // finche' il genitore non chiude
                System.exit(0);
            }
            case "service-holds-write" -> {
                try (Statement s = db.get_connection().createStatement()) {
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
                // Quello che scrive la reinstallazione completa (Main.installOnTurn), piu' le pagine
                // di configurazione del menu.
                List<String> bad = new ArrayList<>();
                if (!db.setMailHostname("mail-" + tag + ".e2e.test")) bad.add("setMailHostname");
                if (!db.resetAllServices()) bad.add("resetAllServices");
                if (!db.update_mysql_config("127.0.0.1", "3306", "mailpanel", "Password" + tag, "mailserver")) bad.add("update_mysql_config");
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
        List<String> cmd = new ArrayList<>(List.of(java, "-Dmailpanel.secrets.dir=" + d.resolve("secrets"),
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
