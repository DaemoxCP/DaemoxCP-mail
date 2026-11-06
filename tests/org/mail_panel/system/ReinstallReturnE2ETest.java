package org.mail_panel.system;

import org.json.JSONObject;
import org.mail_panel.i18n.I18n;
import org.mail_panel.util.Shell;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Tornare al server di prima di una reinstallazione senza perdere la posta arrivata dopo
 * (ReinstallReturn, reperto 169), con bectl vero, senza riavviare.
 *
 * Una casella di prova in /var/vmail con cinque messaggi «di prima» e un file di Dovecot; la via di
 * ritorno della reinstallazione; poi quello che fa una reinstallazione: i cinque cancellati, tre
 * messaggi nuovi arrivati dopo, il file di Dovecot cambiato. Il ritorno:
 *  - nella via di ritorno ci sono i cinque di prima E i tre nuovi;
 *  - il file di Dovecot e' quello di allora (un file che c'e' gia' non si sovrascrive);
 *  - la via di ritorno e' quella del prossimo avvio (bectl: R);
 *  - posta ferma fino al riavvio (Postfix e Dovecot spenti, come deve);
 *  - i rifiuti: un nome che non e' di una reinstallazione, una che non c'e' piu'; e li' la posta resta su.
 * Poi tutto rimesso: il boot environment di adesso di nuovo per il prossimo avvio, la via di ritorno
 * tolta, la casella di prova tolta, la posta riaccesa. SOLO su un clone di prova, -De2e.vm=yes, root.
 *   java -De2e.vm=yes -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.ReinstallReturnE2ETest
 */
public class ReinstallReturnE2ETest {

    static int failed = 0;
    static final Path PROBE = Path.of("/var/vmail/e2e-way-back.test/probe");

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static String sh(String cmd) {
        return Shell.runShell(Duration.ofSeconds(600), cmd).outputTrim();
    }

    static boolean up(String svc) {
        return Shell.runShell(Duration.ofSeconds(30), "service " + svc + " status").success();
    }

    public static void main(String[] args) throws Exception {
        if (!"yes".equals(System.getProperty("e2e.vm"))) {
            System.out.println("SALTATA: serve -De2e.vm=yes (un clone di prova sulla VM FreeBSD, da root).");
            System.exit(0);
        }
        for (String n : sh("bectl list -H | cut -f1").split("\n"))
            if (PackageWayBack.REINSTALL_OWN.matcher(n.trim()).matches()) {
                System.out.println("FERMATA: c'e' gia' una via di ritorno di reinstallazione (" + n.trim() + ").");
                System.exit(2);
            }
        if (!PackageWayBack.dataInside().contains("/var/vmail")) {
            System.out.println("FERMATA: /var/vmail non sta nel boot environment, qui non c'e' niente da fondere.");
            System.exit(2);
        }
        I18n.setCurrent("en");
        String running = "";
        for (String line : sh("bectl list -H").split("\n")) {
            String[] f = line.split("\t");
            if (f.length >= 2 && f[1].contains("N")) running = f[0].trim();
        }
        String nextBoot = "";
        for (String line : sh("bectl list -H").split("\n")) {
            String[] f = line.split("\t");
            if (f.length >= 2 && (f[1].contains("R") || f[1].contains("T"))) nextBoot = f[0].trim();
        }
        System.out.println("in uso: " + running + ", al prossimo avvio: " + nextBoot);
        List<String> log = new ArrayList<>();
        String name = "";
        try {
            for (String sub : List.of("cur", "new", "tmp")) Files.createDirectories(PROBE.resolve(sub));
            for (int i = 1; i <= 5; i++)
                Files.writeString(PROBE.resolve("cur/1700000000.M" + i + "P1.e2e:2,S"), "From: prova\nSubject: di prima " + i + "\n\nmessaggio di prima\n");
            Files.writeString(PROBE.resolve("dovecot-uidlist"), "3 V1 N6 di prima\n");
            sh("chown -R vmail:vmail /var/vmail/e2e-way-back.test 2>/dev/null");

            PackageWayBack.Prepared p = PackageWayBack.beforeInstallation(log::add);
            name = p.name();
            check("la via di ritorno della reinstallazione c'e': " + name, PackageWayBack.REINSTALL_OWN.matcher(name).matches());

            // Quello che fa una reinstallazione, e la posta che arriva dopo.
            for (int i = 1; i <= 5; i++) Files.delete(PROBE.resolve("cur/1700000000.M" + i + "P1.e2e:2,S"));
            for (int i = 1; i <= 3; i++)
                Files.writeString(PROBE.resolve("new/1800000000.M" + i + "P2.e2e"), "From: prova\nSubject: arrivato dopo " + i + "\n\nmessaggio nuovo\n");
            Files.writeString(PROBE.resolve("dovecot-uidlist"), "3 V2 N1 di dopo\n");

            System.out.println("\n== I rifiuti ==");
            boolean postfixUp = up("postfix");
            JSONObject r = ReinstallReturn.goBack("packages-before-2026-11-06-120000-e2e", log::add);
            check("un nome che non e' di una reinstallazione", !r.optBoolean("success") && r.optString("error").contains("not the way back of a complete reinstallation"));
            r = ReinstallReturn.goBack("reinstall-before-2000-01-01-000000", log::add);
            check("una che non c'e' piu'", !r.optBoolean("success") && r.optString("error").contains("not there any more"));
            check("e la posta resta come era", up("postfix") == postfixUp);

            System.out.println("\n== Il ritorno ==");
            log.clear();
            r = ReinstallReturn.goBack(name, log::add);
            for (String l : log) System.out.println("      | " + l);
            check("riuscito", r.optBoolean("success"));
            check("e dice quanti file ha aggiunto (almeno i tre nuovi): " + r.optInt("merged"), r.optInt("merged") >= 3);
            String state = "";
            for (String line : sh("bectl list -H").split("\n")) {
                String[] f = line.split("\t");
                if (f.length >= 2 && f[0].trim().equals(name)) state = f[1].trim();
            }
            check("la via di ritorno e' quella del prossimo avvio (" + state + ")", state.contains("R"));
            check("la posta e' ferma fino al riavvio", !up("postfix") && !up("dovecot"));
            Path mnt = Files.createTempDirectory(Path.of("/var/tmp"), "e2e-way-back-check");
            check("si monta per guardarci dentro", Shell.runShell(Duration.ofSeconds(120), "bectl mount " + name + " " + mnt).success());
            Path inside = Path.of(mnt + PROBE.toString());
            int oldOnes = 0, newOnes = 0;
            for (int i = 1; i <= 5; i++) if (Files.exists(inside.resolve("cur/1700000000.M" + i + "P1.e2e:2,S"))) oldOnes++;
            for (int i = 1; i <= 3; i++) if (Files.exists(inside.resolve("new/1800000000.M" + i + "P2.e2e"))) newOnes++;
            check("dentro ci sono i cinque messaggi di prima", oldOnes == 5);
            check("e i tre arrivati dopo", newOnes == 3);
            check("il file di Dovecot e' quello di allora", Files.readString(inside.resolve("dovecot-uidlist")).contains("di prima"));
            check("proprietario e permessi conservati", sh("stat -f %Su " + inside.resolve("new/1800000000.M1P2.e2e")).equals("vmail")
                    || sh("id vmail >/dev/null 2>&1 || echo nouser").equals("nouser"));
            Shell.runShell(Duration.ofSeconds(120), "bectl umount " + name);
            Files.deleteIfExists(mnt);
        } finally {
            // Rimettere. bectl activate PROMUOVE un clone: dopo il ritorno la via di ritorno possiede lo
            // snapshot e il boot environment in uso dipende da lei. Quindi: prima si riattiva quello in uso
            // (torna a possedere il suo snapshot), poi si toglie la via di ritorno (adesso e' una foglia),
            // poi il prossimo avvio torna quello di prima, che non e' un clone e non si promuove.
            if (!name.isEmpty() && !running.isEmpty()) System.out.println("      | " + sh("bectl activate " + running + " 2>&1"));
            if (!name.isEmpty()) System.out.println("      | tolta la via di ritorno: " + (PackageWayBack.destroy(name) == null));
            if (!nextBoot.isEmpty()) System.out.println("      | " + sh("bectl activate " + nextBoot + " 2>&1"));
            sh("rm -rf /var/vmail/e2e-way-back.test");
            sh("service dovecot start >/dev/null 2>&1; service postfix start >/dev/null 2>&1");
        }
        check("alla fine: la posta di nuovo su, la casella di prova tolta", up("postfix") && up("dovecot") && !Files.exists(PROBE));
        String after = "";
        for (String line : sh("bectl list -H").split("\n")) {
            String[] f = line.split("\t");
            if (f.length >= 2 && f[1].contains("R")) after = f[0].trim();
        }
        check("il prossimo avvio e' di nuovo " + nextBoot, after.equals(nextBoot) || nextBoot.isEmpty());
        check("nessuna via di ritorno rimasta", !sh("bectl list -H | cut -f1").contains("reinstall-before-"));
        System.out.println(failed == 0 ? "\nTutte le prove passate." : "\n" + failed + " prove FALLITE.");
        System.exit(failed == 0 ? 0 : 1);
    }
}
