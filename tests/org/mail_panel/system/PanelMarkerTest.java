package org.mail_panel.system;

import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;

/**
 * Le firme dei file del pannello passano all'inglese all'avvio (PanelMarker.migrate), in
 * cartelle temporanee e con un nginx finto che dice quali cartelle include.
 *
 * I file "di prima" si costruiscono da quelli di oggi rimettendo la firma di prima presa dal file
 * di dati: la prova non scrive nessun nome vecchio. Dopo la migrazione ogni file deve essere
 * identico byte per byte a quello che il codice di oggi scrive da zero, con gli stessi permessi;
 * una seconda passata non deve trovare niente. L'effetto sui servizi veri lo misura la prova
 * sulla VM (reperti).
 *
 *   java -cp "tests:&lt;dir&gt;/freebsd-mail-panel-1.0.jar" org.mail_panel.system.PanelMarkerTest
 */
public class PanelMarkerTest {

    static int failed = 0;
    static final PrintStream OUT = System.out;

    static void check(String what, boolean ok) {
        OUT.println((ok ? "  OK   " : "  FALLITO ") + what);
        if (!ok) failed++;
    }

    static final List<String> OLD = LegacyNames.oldNamesOf(PanelMarker.SIGNATURE, PanelMarker.WRITTEN);
    static final String DOVECOT_OLD = LegacyNames.oldNamesOf(PanelMarker.DOVECOT,
            org.mail_panel.scripts.DovecotConfig.SIGNATURE).get(0);

    static final String CONF = WebProtection.configuration("/usr/local/etc/ssl/mail/fullchain.pem",
            "/usr/local/etc/ssl/mail/privkey.pem");
    static final String DOVECOT_CONF = "# Dovecot — " + org.mail_panel.scripts.DovecotConfig.SIGNATURE
            + "\nprotocols = imap pop3 lmtp\n!include conf.d/*.conf\n";

    static String before(String now, String signature) { return now.replace(PanelMarker.WRITTEN, signature); }

    /** Un server: le cartelle di fail2ban, due cartelle di nginx e dovecot.conf. */
    static final class Server {
        final Path root, f2b, filter, jail, defaultFolder, otherFolder, dovecot;
        List<String> folders;
        int nginxCalls;

        Server() throws Exception {
            root = Files.createTempDirectory("panel-marker");
            f2b = root.resolve("fail2ban");
            filter = f2b.resolve("filter.d").resolve(WebProtection.FILE_NAME);
            jail = f2b.resolve("jail.d").resolve(WebProtection.FILE_NAME);
            defaultFolder = root.resolve("nginx/conf.d");
            otherFolder = root.resolve("nginx/sites-enabled");
            dovecot = root.resolve("dovecot/dovecot.conf");
            for (Path p : List.of(filter.getParent(), jail.getParent(), defaultFolder, otherFolder, dovecot.getParent()))
                Files.createDirectories(p);
            folders = List.of(defaultFolder.toString());
        }

        void writeOld(boolean conf, boolean f2bFiles, boolean dovecotToo) throws Exception {
            if (conf) write(defaultFolder.resolve(WebProtection.FILE_NAME), before(CONF, OLD.get(OLD.size() - 1)), "rw-r--r--");
            if (f2bFiles) {
                write(filter, before(WebProtection.filter(), OLD.get(0)), "rw-r--r--");
                write(jail, before(WebProtection.jail(), OLD.get(0)), "rw-r-----");
            }
            if (dovecotToo) write(dovecot, DOVECOT_CONF.replace(org.mail_panel.scripts.DovecotConfig.SIGNATURE, DOVECOT_OLD), "rw-r-----");
        }

        void write(Path p, String s, String perms) throws Exception {
            Files.writeString(p, s);
            Files.setPosixFilePermissions(p, PosixFilePermissions.fromString(perms));
        }

        PanelMarker.Report run() {
            return PanelMarker.migrate(new PanelMarker.Places(f2b, defaultFolder, dovecot), () -> {
                nginxCalls++;
                return folders;
            });
        }

        String read(Path p) throws Exception { return Files.exists(p) ? Files.readString(p) : null; }

        String perms(Path p) throws Exception { return PosixFilePermissions.toString(Files.getPosixFilePermissions(p)); }

        boolean leftovers() throws Exception {
            try (Stream<Path> s = Files.walk(root)) {
                return s.anyMatch(p -> p.getFileName().toString().endsWith(".mailpanel.tmp"));
            }
        }

        void close() throws Exception {
            try (Stream<Path> s = Files.walk(root)) {
                s.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
            }
        }
    }

    public static void main(String[] args) throws Exception {
        OUT.println("\n== Le firme ==");
        check("due firme di prima nel file di dati, quella di adesso diversa da tutte e due",
                OLD.size() == 2 && !OLD.contains(PanelMarker.WRITTEN));
        check("il codice di oggi firma i tre file della 443",
                CONF.contains(PanelMarker.WRITTEN) && WebProtection.filter().contains(PanelMarker.WRITTEN)
                        && WebProtection.jail().contains(PanelMarker.WRITTEN));

        OUT.println("\n== Un server senza niente di prima ==");
        Server s = new Server();
        PanelMarker.Report r = s.run();
        check("niente file: NOTHING, e nginx -T non si lancia", r.outcome() == PanelMarker.Outcome.NOTHING && s.nginxCalls == 0);
        s.write(s.defaultFolder.resolve(WebProtection.FILE_NAME), CONF, "rw-r--r--");
        s.write(s.filter, WebProtection.filter(), "rw-r--r--");
        s.write(s.jail, WebProtection.jail(), "rw-r-----");
        s.write(s.dovecot, DOVECOT_CONF, "rw-r-----");
        r = s.run();
        check("file gia' con la firma di adesso: NOTHING, e nginx -T non si lancia",
                r.outcome() == PanelMarker.Outcome.NOTHING && s.nginxCalls == 0);
        s.close();

        OUT.println("\n== Un server installato prima: le firme cambiano ==");
        s = new Server();
        s.writeOld(true, true, true);
        String jailBefore = s.read(s.jail);
        r = s.run();
        check("esito DONE: " + r.detail(), r.outcome() == PanelMarker.Outcome.DONE);
        check("il file di nginx e' quello che il pannello scrive oggi",
                CONF.equals(s.read(s.defaultFolder.resolve(WebProtection.FILE_NAME))));
        check("filtro e jail sono quelli di oggi", WebProtection.filter().equals(s.read(s.filter))
                && WebProtection.jail().equals(s.read(s.jail)));
        check("dovecot.conf ha la firma di adesso, e il resto com'era", DOVECOT_CONF.equals(s.read(s.dovecot)));
        check("  e cambia solo la riga della firma", PanelMarker.withoutComments(jailBefore).equals(PanelMarker.withoutComments(s.read(s.jail))));
        check("i permessi restano (jail 0640, filtro 0644, dovecot.conf 0640)",
                "rw-r-----".equals(s.perms(s.jail)) && "rw-r--r--".equals(s.perms(s.filter)) && "rw-r-----".equals(s.perms(s.dovecot)));
        check("nessun file temporaneo lasciato", !s.leftovers());
        int calls = s.nginxCalls;
        r = s.run();
        check("una seconda volta: NOTHING, e nginx -T non si lancia", r.outcome() == PanelMarker.Outcome.NOTHING && s.nginxCalls == calls);
        s.close();

        OUT.println("\n== Il file di nginx dove lo dice nginx ==");
        s = new Server();
        s.writeOld(false, true, false);
        s.write(s.otherFolder.resolve(WebProtection.FILE_NAME), before(CONF, OLD.get(1)), "rw-r--r--");
        s.folders = List.of(s.otherFolder.toString());
        r = s.run();
        check("in un'altra cartella inclusa: DONE e il file e' quello di oggi",
                r.outcome() == PanelMarker.Outcome.DONE && CONF.equals(s.read(s.otherFolder.resolve(WebProtection.FILE_NAME))));
        s.close();

        s = new Server();
        Path elsewhere = s.root.resolve("nginx/sites-available/" + WebProtection.FILE_NAME);
        Files.createDirectories(elsewhere.getParent());
        s.write(elsewhere, before(CONF, OLD.get(1)), "rw-r--r--");
        Files.createSymbolicLink(s.defaultFolder.resolve(WebProtection.FILE_NAME), elsewhere);
        r = s.run();
        check("un collegamento si segue: cambia il file a cui punta, il collegamento resta",
                r.outcome() == PanelMarker.Outcome.DONE && CONF.equals(s.read(elsewhere))
                        && Files.isSymbolicLink(s.defaultFolder.resolve(WebProtection.FILE_NAME)));
        s.close();

        OUT.println("\n== Quando qualcosa non va ==");
        s = new Server();
        s.writeOld(true, true, true);
        s.folders = null;
        String filterBefore = s.read(s.filter);
        r = s.run();
        check("nginx -T fallisce: NGINX_UNREADABLE, la 443 non si tocca", r.outcome() == PanelMarker.Outcome.NGINX_UNREADABLE
                && filterBefore.equals(s.read(s.filter)) && s.read(s.jail).contains(OLD.get(0)));
        check("  ma dovecot.conf, che non dipende da nginx, si", DOVECOT_CONF.equals(s.read(s.dovecot)));
        s.folders = List.of(s.defaultFolder.toString());
        r = s.run();
        check("  e all'avvio dopo, con nginx che risponde, si fa il resto", r.outcome() == PanelMarker.Outcome.DONE
                && WebProtection.jail().equals(s.read(s.jail)) && CONF.equals(s.read(s.defaultFolder.resolve(WebProtection.FILE_NAME))));
        s.close();

        s = new Server();
        s.writeOld(true, true, false);
        // Il file temporaneo di nginx non si puo' creare: al suo posto c'e' una cartella piena.
        Path blocker = s.defaultFolder.resolve("." + WebProtection.FILE_NAME + ".mailpanel.tmp");
        Files.createDirectories(blocker);
        Files.writeString(blocker.resolve("x"), "x");
        r = s.run();
        check("il file di nginx non si puo' scrivere: PARTIAL, e filtro e jail restano con la firma di prima",
                r.outcome() == PanelMarker.Outcome.PARTIAL && s.read(s.filter).contains(OLD.get(0)) && s.read(s.jail).contains(OLD.get(0)));
        check("  (cosi' all'avvio dopo si riprova tutto: " + r.detail() + ")", s.read(s.defaultFolder.resolve(WebProtection.FILE_NAME)).contains(OLD.get(1)));
        Files.delete(blocker.resolve("x"));
        Files.delete(blocker);
        r = s.run();
        check("  e tolto l'ostacolo va a fine", r.outcome() == PanelMarker.Outcome.DONE && WebProtection.jail().equals(s.read(s.jail)));
        s.close();

        s = new Server();
        String odd = "# " + OLD.get(0) + ".\n[" + WebProtection.NAME + "]\nenabled = true\nlogpath = /var/log/" + OLD.get(0) + "\n";
        s.write(s.jail, odd, "rw-r-----");
        s.write(s.defaultFolder.resolve(WebProtection.FILE_NAME), CONF, "rw-r--r--");
        r = s.run();
        String after = s.read(s.jail);
        check("la firma cambia solo nelle righe di commento: la riga del commento si', l'altra no",
                r.outcome() == PanelMarker.Outcome.DONE && after.startsWith("# " + PanelMarker.WRITTEN + ".\n")
                        && after.contains("logpath = /var/log/" + OLD.get(0) + "\n"));
        s.close();

        s = new Server();
        s.write(s.jail, "# il mio file\n[" + WebProtection.NAME + "]\nenabled = true\n", "rw-r-----");
        s.write(s.dovecot, "# il mio dovecot\nprotocols = imap\n", "rw-r-----");
        r = s.run();
        check("file senza firma (scritti a mano): NOTHING, non si toccano", r.outcome() == PanelMarker.Outcome.NOTHING
                && s.read(s.jail).startsWith("# il mio file") && s.read(s.dovecot).startsWith("# il mio dovecot"));
        s.close();

        OUT.println("\n" + (failed == 0 ? "TUTTO VERDE" : failed + " CONTROLLI FALLITI"));
        System.exit(failed == 0 ? 0 : 1);
    }
}
