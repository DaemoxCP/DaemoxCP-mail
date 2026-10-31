package org.mail_panel.system;

import org.mail_panel.util.Shell;

import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

/**
 * La superficie pubblica passa da "mailpanel-pubblico" a "mailpanel-public" sui server gia'
 * installati (PublicSurfaceRename.migrate), in cartelle temporanee e con un nginx e un fail2ban
 * finti. Il fail2ban finto fa come quello vero: tiene i ban in un database per nome di jail, e a
 * ogni reload attiva le jail che trova in jail.d riprendendo dal database i ban di ciascuna. Una
 * jail col nome nuovo ritrova i ban solo se lo stato nel database e' passato a lei. Conta anche
 * i ban dati a mano (le righe «Ban» che la jail recidive conta): una rinomina non ne deve dare.
 * Con la superficie si sposta la cartella dei suoi file (mta-sts.txt), che il file di nginx cita
 * per percorso: sul server vero, il 31/10/2026, quel percorso restava quello vecchio.
 * L'effetto su nginx, fail2ban e pf veri lo misura la prova sulla VM (reperti).
 *
 * Si lancia ovunque (non chiama niente):
 *   java -cp "tests:&lt;dir&gt;/freebsd-mail-panel-1.0.jar" org.mail_panel.system.PublicSurfaceRenameTest
 */
public class PublicSurfaceRenameTest {

    static int failed = 0;
    static final PrintStream OUT = System.out;

    static void check(String what, boolean ok) {
        OUT.println((ok ? "  OK   " : "  FALLITO ") + what);
        if (!ok) failed++;
    }

    /** Il nome di prima, dal file di dati: la prova non lo scrive. */
    static final String OLD = LegacyNames.single("publicSurface");
    static final String NEW = "mailpanel-public";
    static final String CERT = "/usr/local/etc/ssl/mail/fullchain.pem";
    static final String KEY = "/usr/local/etc/ssl/mail/privkey.pem";

    /**
     * Le firme di prima, dal file di dati: la piu' lunga ("... di posta") stava in filtro e jail,
     * la piu' corta nel file di nginx.
     */
    static final List<String> OLD_SIGNATURES = LegacyNames.oldNamesOf("panelSignature", PanelMarker.WRITTEN);
    static String signedBefore(String content, String signature) { return content.replace(PanelMarker.WRITTEN, signature); }

    /**
     * I tre file come li scriveva main prima della rinomina: quelli di oggi col nome e la firma di
     * ieri, e il file di nginx con la cartella dei file pubblici di ieri (folder).
     */
    static String oldConf(Path folder) {
        return signedBefore(WebProtection.configuration(CERT, KEY), OLD_SIGNATURES.get(OLD_SIGNATURES.size() - 1))
                .replace(NEW, OLD).replace(WebProtection.PUBLIC_DIR, folder.toString());
    }
    /** Il file di nginx di oggi, con la cartella dei file pubblici data. */
    static String conf(Path folder) { return WebProtection.configuration(CERT, KEY).replace(WebProtection.PUBLIC_DIR, folder.toString()); }
    /** Il nome della cartella dei file pubblici di prima, dal file di dati. */
    static final String OLD_FOLDER = Path.of(LegacyNames.single("publicFolder")).getFileName().toString();
    static String oldFilter() { return signedBefore(WebProtection.filter(), OLD_SIGNATURES.get(0)).replace(NEW, OLD); }
    static String oldJail() { return signedBefore(WebProtection.jail(), OLD_SIGNATURES.get(0)).replace(NEW, OLD); }

    static final class FakeServices implements PublicSurfaceRename.Services {
        final Path jailDir;
        List<String> folders;
        boolean nginxRunning = true, f2bRunning = true;
        boolean nginxTestFails, f2bReloadFails, f2bIgnoresNewJail, databaseFails;
        int foldersCalls, nginxTests, nginxReloads, f2bReloads, manualBans, stateMoves;
        /** Le jail attive, con i loro ban. */
        final Map<String, List<String>> jails = new LinkedHashMap<>();
        /** Il database di fail2ban: i ban per nome di jail, e la posizione nel log. */
        final Map<String, List<String>> database = new LinkedHashMap<>();
        final Map<String, String> logOf = new LinkedHashMap<>();

        FakeServices(Path jailDir, List<String> folders) { this.jailDir = jailDir; this.folders = folders; }

        static Shell.Result ok() { return new Shell.Result(0, "", false, List.of()); }
        static Shell.Result ko(String why) { return new Shell.Result(1, why, false, List.of()); }

        @Override public List<String> nginxFolders() { foldersCalls++; return folders; }
        @Override public boolean nginxRunning() { return nginxRunning; }
        @Override public Shell.Result nginxTest() { nginxTests++; return nginxTestFails ? ko("emerg: test fault") : ok(); }
        @Override public Shell.Result nginxReload() { nginxReloads++; return ok(); }
        @Override public boolean fail2banRunning() { return f2bRunning; }
        @Override public Shell.Result fail2banReload() {
            f2bReloads++;
            if (f2bReloadFails && f2bReloads == 1) return ko("ERROR test fault");
            jails.clear();
            try (Stream<Path> s = Files.list(jailDir)) {
                for (Path p : s.toList()) {
                    String n = p.getFileName().toString().replace(".conf", "");
                    if (f2bIgnoresNewJail && n.equals(NEW)) continue;
                    // Ogni jail che parte riprende dal database i suoi ban, e solo i suoi.
                    jails.put(n, database.computeIfAbsent(n, k -> new ArrayList<>()));
                }
            } catch (Exception e) { return ko(e.toString()); }
            return ok();
        }
        @Override public List<String> banned(String jail) {
            List<String> b = jails.get(jail);
            return b == null ? null : new ArrayList<>(b);
        }
        @Override public boolean moveJailState(String from, String to, String fromLog, String toLog) {
            stateMoves++;
            if (databaseFails) return false;
            List<String> b = database.remove(from);
            if (b != null) database.put(to, b);
            if (fromLog.equals(logOf.get(from))) { logOf.remove(from); logOf.put(to, toLog); }
            return true;
        }

        /** Un ban dato a mano: nel fail2ban vero scrive una riga «Ban» che recidive conta. */
        void manualBan(String jail, String ip) {
            manualBans++;
            database.computeIfAbsent(jail, k -> new ArrayList<>()).add(ip);
        }
    }

    /** Un server installato con main prima della rinomina, in una cartella temporanea. */
    static final class Server {
        final Path root, f2b, jailD, filterD, logs, confD, sites, oldFolder, newFolder;
        final PublicSurfaceRename.Places places;
        final FakeServices sv;

        Server(boolean withConf, boolean withJail, boolean withLog) throws Exception {
            root = Files.createTempDirectory("public-surface-rename");
            f2b = root.resolve("fail2ban");
            jailD = Files.createDirectories(f2b.resolve("jail.d"));
            filterD = Files.createDirectories(f2b.resolve("filter.d"));
            logs = Files.createDirectories(root.resolve("log/nginx"));
            confD = Files.createDirectories(root.resolve("nginx/conf.d"));
            sites = Files.createDirectories(root.resolve("nginx/sites-enabled"));
            oldFolder = root.resolve("db").resolve(OLD_FOLDER);
            newFolder = root.resolve("db").resolve(Path.of(WebProtection.PUBLIC_DIR).getFileName().toString());
            places = new PublicSurfaceRename.Places(f2b, logs, confD, oldFolder, newFolder);
            sv = new FakeServices(jailD, List.of(confD.toString()));
            // Le cose degli altri che non devono muoversi.
            Files.writeString(logs.resolve("access.log"), "webmail\n");
            Files.writeString(jailD.resolve("postfix-sasl.conf"), "[postfix-sasl]\n");
            if (withConf) {
                Files.writeString(confD.resolve(OLD + ".conf"), oldConf(oldFolder));
                Files.createDirectories(oldFolder);
                Files.writeString(oldFolder.resolve("mta-sts.txt"), "version: STSv1\nmode: enforce\n");
            }
            if (withJail) {
                Files.writeString(filterD.resolve(OLD + ".conf"), oldFilter());
                Path j = jailD.resolve(OLD + ".conf");
                Files.writeString(j, oldJail());
                Files.setPosixFilePermissions(j, PosixFilePermissions.fromString("rw-r-----"));
            }
            if (withLog) {
                Files.writeString(logs.resolve(OLD + "-access.log"), "1.2.3.4 - - \"GET /x\" 404\n");
                Files.writeString(logs.resolve(OLD + "-access.log.0.bz2"), "archive\n");
            }
            if (withJail) {
                sv.database.put(OLD, new ArrayList<>(List.of("203.0.113.7", "198.51.100.9")));
                sv.logOf.put(OLD, logs.resolve(OLD + "-access.log").toString());
            }
            sv.fail2banReload();   // fail2ban acceso con la jail vecchia e i suoi due ban
            sv.f2bReloads = 0;
        }

        PublicSurfaceRename.Report run() throws Exception {
            PublicSurfaceRename.Report r = PublicSurfaceRename.migrate(places, sv);
            OUT.println("        -> " + r.outcome() + ": " + r.detail());
            return r;
        }

        String read(Path p) throws Exception { return Files.exists(p) ? Files.readString(p) : null; }

        /** Tutti i file sotto la radice col loro contenuto: per dire "non e' cambiato niente". */
        Map<String, String> snapshot() throws Exception {
            Map<String, String> m = new LinkedHashMap<>();
            try (Stream<Path> s = Files.walk(root)) {
                for (Path p : s.sorted(Comparator.naturalOrder()).toList())
                    if (Files.isRegularFile(p)) m.put(root.relativize(p).toString(), Files.readString(p));
            }
            return m;
        }
    }

    public static void main(String[] args) throws Exception {
        OUT.println("\n== I nomi ==");
        // Per riflessione: javac copia le costanti dentro questa classe, e il confronto diretto
        // guarderebbe i nomi di quando la prova e' stata compilata, non quelli del jar.
        String oldName = (String) PublicSurfaceRename.class.getDeclaredField("OLD_NAME").get(null);
        String newName = (String) WebProtection.class.getDeclaredField("NAME").get(null);
        check("il nome vecchio viene dal file di dati e il nuovo e' diverso",
                !oldName.isEmpty() && oldName.equals(OLD) && newName.equals(NEW) && !oldName.equals(newName));
        check("il codice di oggi non scrive piu' il nome vecchio (configurazione, filtro, jail), ne' la cartella di prima",
                !WebProtection.configuration(CERT, KEY).contains(OLD) && !WebProtection.jail().contains(OLD)
                        && !WebProtection.filter().contains(OLD) && !WebProtection.ACCESS_LOG.contains(OLD)
                        && !WebProtection.configuration(CERT, KEY).contains(LegacyNames.single("publicFolder"))
                        && WebProtection.configuration(CERT, KEY).contains(WebProtection.PUBLIC_DIR + "/mta-sts.txt"));
        check("la jail di oggi: sezione, filtro, log e ancora pf col nome nuovo",
                WebProtection.jail().contains("[" + NEW + "]") && WebProtection.jail().contains("filter   = " + NEW + "\n")
                        && WebProtection.jail().contains("logpath  = /var/log/nginx/" + NEW + "-access.log")
                        && WebProtection.jail().contains("action   = pf[name=" + NEW + ", port=\"http,https\"]"));
        check("il file del database si legge da \"fail2ban-client get dbfile\"",
                "/var/db/fail2ban/fail2ban.sqlite3".equals(PublicSurfaceRename.fail2banDatabase(
                        "Current database file is:\n`- /var/db/fail2ban/fail2ban.sqlite3\n"))
                        && PublicSurfaceRename.fail2banDatabase("Database currently disabled") == null);
        check("i tre file di main hanno la firma di prima, e il pannello la riconosce",
                OLD_SIGNATURES.size() == 2 && !oldConf(Path.of("/x")).contains(PanelMarker.WRITTEN) && !oldJail().contains(PanelMarker.WRITTEN)
                        && !oldFilter().contains(PanelMarker.WRITTEN) && PanelMarker.writtenByPanel(oldConf(Path.of("/x")))
                        && PanelMarker.writtenByPanel(oldFilter()) && PanelMarker.writtenByPanel(oldJail()));
        check("la riga di fail2ban-client status si legge",
                PublicSurfaceRename.bannedFrom("|- Actions\n   |- Currently banned:\t2\n   |- Total banned:\t46\n"
                        + "   `- Banned IP list:\t203.0.113.7 198.51.100.9\n").equals(List.of("203.0.113.7", "198.51.100.9"))
                        && PublicSurfaceRename.bannedFrom("   `- Banned IP list:\t\n").isEmpty());

        OUT.println("\n== Un server installato con main: si sposta tutto ==");
        Server s = new Server(true, true, true);
        PublicSurfaceRename.Report r = s.run();
        check("esito DONE", r.outcome() == PublicSurfaceRename.Outcome.DONE);
        check("nginx: il file nuovo e' quello che scrive il pannello oggi, con la cartella nuova; il vecchio non c'e' piu'",
                conf(s.newFolder).equals(s.read(s.confD.resolve(NEW + ".conf")))
                        && !Files.exists(s.confD.resolve(OLD + ".conf")));
        check("la cartella dei file pubblici ha il nome nuovo, con mta-sts.txt dentro, e la vecchia non c'e' piu'",
                "version: STSv1\nmode: enforce\n".equals(s.read(s.newFolder.resolve("mta-sts.txt"))) && !Files.exists(s.oldFolder));
        check("fail2ban: jail e filtro nuovi uguali a quelli di oggi, i vecchi tolti",
                WebProtection.jail().equals(s.read(s.jailD.resolve(NEW + ".conf")))
                        && WebProtection.filter().equals(s.read(s.filterD.resolve(NEW + ".conf")))
                        && !Files.exists(s.jailD.resolve(OLD + ".conf")) && !Files.exists(s.filterD.resolve(OLD + ".conf")));
        check("la jail spostata tiene i suoi permessi (0640)",
                PosixFilePermissions.toString(Files.getPosixFilePermissions(s.jailD.resolve(NEW + ".conf"))).equals("rw-r-----"));
        check("il log e la sua copia ruotata col nome nuovo, contenuto intatto",
                "1.2.3.4 - - \"GET /x\" 404\n".equals(s.read(s.logs.resolve(NEW + "-access.log")))
                        && "archive\n".equals(s.read(s.logs.resolve(NEW + "-access.log.0.bz2")))
                        && !Files.exists(s.logs.resolve(OLD + "-access.log"))
                        && !Files.exists(s.logs.resolve(OLD + "-access.log.0.bz2")));
        check("i file degli altri non si muovono",
                "webmail\n".equals(s.read(s.logs.resolve("access.log"))) && Files.exists(s.jailD.resolve("postfix-sasl.conf")));
        check("nginx -t e reload di nginx e di fail2ban, una volta ciascuno",
                s.sv.nginxTests == 1 && s.sv.nginxReloads == 1 && s.sv.f2bReloads == 1);
        check("i due ban della jail vecchia sono nella nuova, la vecchia non c'e' piu'",
                s.sv.jails.containsKey(NEW) && s.sv.jails.get(NEW).equals(List.of("203.0.113.7", "198.51.100.9"))
                        && !s.sv.jails.containsKey(OLD));
        check("  ripresi dal database, senza nessun ban dato a mano (recidive non conta niente)",
                s.sv.stateMoves == 1 && s.sv.manualBans == 0);
        check("  e la jail nuova riprende il log dal punto in cui era la vecchia",
                s.logs.resolve(NEW + "-access.log").toString().equals(s.sv.logOf.get(NEW)) && !s.sv.logOf.containsKey(OLD));

        OUT.println("\n== Il secondo avvio ==");
        Map<String, String> after = s.snapshot();
        int calls = s.sv.foldersCalls;
        r = s.run();
        check("niente da fare, e nemmeno nginx -T", r.outcome() == PublicSurfaceRename.Outcome.NOTHING
                && s.sv.foldersCalls == calls && after.equals(s.snapshot()));

        OUT.println("\n== nginx rifiuta: si rimette tutto com'era ==");
        s = new Server(true, true, true);
        s.sv.nginxTestFails = true;
        Map<String, String> before = s.snapshot();
        r = s.run();
        check("esito ROLLED_BACK", r.outcome() == PublicSurfaceRename.Outcome.ROLLED_BACK);
        check("ogni file torna al suo nome e al suo contenuto", before.equals(s.snapshot()));
        check("niente reload: ne' nginx ne' fail2ban, e i ban restano dove erano",
                s.sv.nginxReloads == 0 && s.sv.f2bReloads == 0 && s.sv.jails.get(OLD).size() == 2);

        OUT.println("\n== fail2ban rifiuta il reload: si rimette tutto, nginx compreso ==");
        s = new Server(true, true, true);
        s.sv.f2bReloadFails = true;
        before = s.snapshot();
        r = s.run();
        check("esito ROLLED_BACK", r.outcome() == PublicSurfaceRename.Outcome.ROLLED_BACK);
        check("ogni file torna com'era", before.equals(s.snapshot()));
        check("nginx ricaricato due volte (avanti e indietro), fail2ban due (il rifiuto e il ritorno)",
                s.sv.nginxReloads == 2 && s.sv.f2bReloads == 2);
        check("la jail vecchia e' di nuovo attiva, coi suoi due ban ripresi dal database",
                s.sv.jails.containsKey(OLD) && !s.sv.jails.containsKey(NEW) && s.sv.jails.get(OLD).size() == 2
                        && s.sv.manualBans == 0);

        OUT.println("\n== fail2ban ricarica ma non vede la jail nuova: indietro ==");
        s = new Server(true, true, true);
        s.sv.f2bIgnoresNewJail = true;
        before = s.snapshot();
        r = s.run();
        check("esito ROLLED_BACK e file com'erano",
                r.outcome() == PublicSurfaceRename.Outcome.ROLLED_BACK && before.equals(s.snapshot()));
        check("dopo il ritorno la jail vecchia c'e' di nuovo, con i suoi due ban",
                s.sv.jails.containsKey(OLD) && s.sv.jails.get(OLD).equals(List.of("203.0.113.7", "198.51.100.9")));

        OUT.println("\n== Il database di fail2ban non si puo' aggiornare ==");
        s = new Server(true, true, true);
        s.sv.databaseFails = true;
        r = s.run();
        check("la rinomina va avanti lo stesso, e lo dice", r.outcome() == PublicSurfaceRename.Outcome.DONE
                && r.detail().contains("not carried over") && s.sv.jails.containsKey(NEW) && !s.sv.jails.containsKey(OLD));
        check("  senza ribannare a mano", s.sv.manualBans == 0);

        OUT.println("\n== Cose che non si toccano ==");
        s = new Server(true, true, true);
        Files.writeString(s.jailD.resolve(OLD + ".conf"), "[" + OLD + "]\nenabled = true\n# written by hand\n");
        before = s.snapshot();
        r = s.run();
        check("una jail scritta a mano: NOT_OURS, niente spostato, nessun servizio toccato",
                r.outcome() == PublicSurfaceRename.Outcome.NOT_OURS && before.equals(s.snapshot())
                        && s.sv.nginxTests == 0 && s.sv.f2bReloads == 0);

        s = new Server(true, true, true);
        Files.writeString(s.confD.resolve(NEW + ".conf"), conf(s.newFolder));
        before = s.snapshot();
        r = s.run();
        check("nome vecchio e nuovo insieme: BOTH_NAMES, niente spostato",
                r.outcome() == PublicSurfaceRename.Outcome.BOTH_NAMES && before.equals(s.snapshot()));

        s = new Server(true, true, true);
        Files.writeString(s.sites.resolve(OLD + ".conf"), oldConf(s.oldFolder));
        s.sv.folders = List.of(s.confD.toString(), s.sites.toString());
        before = s.snapshot();
        r = s.run();
        check("due file vecchi in due cartelle incluse: AMBIGUOUS, niente spostato",
                r.outcome() == PublicSurfaceRename.Outcome.AMBIGUOUS && before.equals(s.snapshot()));

        s = new Server(true, true, true);
        s.sv.folders = null;
        before = s.snapshot();
        r = s.run();
        check("nginx -T non risponde: NGINX_UNREADABLE, niente spostato",
                r.outcome() == PublicSurfaceRename.Outcome.NGINX_UNREADABLE && before.equals(s.snapshot()));

        OUT.println("\n== Servizi spenti o assenti ==");
        s = new Server(true, true, true);
        s.sv.f2bRunning = false;
        s.sv.nginxRunning = false;
        r = s.run();
        check("fail2ban e nginx spenti: si sposta tutto, nginx -t si', nessun reload",
                r.outcome() == PublicSurfaceRename.Outcome.DONE && Files.exists(s.jailD.resolve(NEW + ".conf"))
                        && Files.exists(s.confD.resolve(NEW + ".conf")) && s.sv.nginxTests == 1
                        && s.sv.nginxReloads == 0 && s.sv.f2bReloads == 0);

        s = new Server(false, true, true);
        s.sv.folders = List.of();
        r = s.run();
        check("senza nginx (solo jail e log): si spostano quelli, senza nginx -t",
                r.outcome() == PublicSurfaceRename.Outcome.DONE && WebProtection.jail().equals(s.read(s.jailD.resolve(NEW + ".conf")))
                        && Files.exists(s.logs.resolve(NEW + "-access.log")) && s.sv.nginxTests == 0
                        && s.sv.jails.get(NEW).size() == 2);

        s = new Server(true, false, true);
        r = s.run();
        check("senza jail (la 443 c'e', fail2ban non l'ha): si sposta nginx, fail2ban non si tocca",
                r.outcome() == PublicSurfaceRename.Outcome.DONE && Files.exists(s.confD.resolve(NEW + ".conf"))
                        && s.sv.f2bReloads == 0 && s.sv.nginxReloads == 1);

        OUT.println("\n== La cartella dei file pubblici ==");
        check("la cartella la sposta solo questa migrazione: non e' fra i file che sposta PathMigration",
                !LegacyNames.single("publicFolder").isEmpty()
                        && LegacyNames.pairs("files").stream().noneMatch(p -> p[0].equals(LegacyNames.single("publicFolder"))));
        s = new Server(true, true, true);
        Files.createDirectories(s.newFolder);
        before = s.snapshot();
        r = s.run();
        check("cartella vecchia e nuova insieme: BOTH_NAMES, niente spostato",
                r.outcome() == PublicSurfaceRename.Outcome.BOTH_NAMES && before.equals(s.snapshot()) && Files.exists(s.oldFolder));

        s = new Server(true, true, true);
        s.sv.nginxTestFails = true;
        r = s.run();
        check("nginx rifiuta: la cartella torna al nome vecchio, e nginx la cita ancora",
                r.outcome() == PublicSurfaceRename.Outcome.ROLLED_BACK && Files.exists(s.oldFolder.resolve("mta-sts.txt"))
                        && !Files.exists(s.newFolder) && oldConf(s.oldFolder).equals(s.read(s.confD.resolve(OLD + ".conf"))));

        // Un server che main ha gia' portato al nome nuovo prima di questa correzione: la cartella
        // l'ha spostata PathMigration, e il file di nginx cita ancora la vecchia.
        s = new Server(false, false, false);
        Files.createDirectories(s.newFolder);
        Files.writeString(s.newFolder.resolve("mta-sts.txt"), "version: STSv1\n");
        Files.writeString(s.confD.resolve(NEW + ".conf"), conf(s.oldFolder));
        r = s.run();
        check("gia' rinominato ma col percorso vecchio: si riscrive solo il file di nginx, nginx -t e reload",
                r.outcome() == PublicSurfaceRename.Outcome.DONE && conf(s.newFolder).equals(s.read(s.confD.resolve(NEW + ".conf")))
                        && s.sv.nginxTests == 1 && s.sv.nginxReloads == 1 && s.sv.f2bReloads == 0);
        calls = s.sv.foldersCalls;
        r = s.run();
        check("  e al secondo avvio non c'e' piu' niente da fare, nemmeno nginx -T",
                r.outcome() == PublicSurfaceRename.Outcome.NOTHING && s.sv.foldersCalls == calls);

        s = new Server(false, false, false);
        Files.createDirectories(s.newFolder);
        Files.writeString(s.confD.resolve(NEW + ".conf"), conf(s.oldFolder));
        s.sv.nginxTestFails = true;
        before = s.snapshot();
        r = s.run();
        check("  se nginx rifiuta il file riscritto, torna com'era", r.outcome() == PublicSurfaceRename.Outcome.ROLLED_BACK
                && before.equals(s.snapshot()));

        s = new Server(false, false, false);
        Files.createDirectories(s.oldFolder);
        Files.writeString(s.oldFolder.resolve("mta-sts.txt"), "version: STSv1\n");
        r = s.run();
        check("solo la cartella vecchia, nessun file di nginx che la cita: si sposta, senza nginx -t",
                r.outcome() == PublicSurfaceRename.Outcome.DONE && Files.exists(s.newFolder.resolve("mta-sts.txt"))
                        && !Files.exists(s.oldFolder) && s.sv.nginxTests == 0);

        check("il percorso conta solo intero: un'altra cartella che comincia allo stesso modo non cambia",
                PublicSurfaceRename.renamed("alias /d/" + OLD_FOLDER + "-bis/x;\n", Path.of("/d/" + OLD_FOLDER), Path.of("/d/public"))
                        .contains("/d/" + OLD_FOLDER + "-bis/x;")
                        && PublicSurfaceRename.renamed("alias /d/" + OLD_FOLDER + "/x;\n", Path.of("/d/" + OLD_FOLDER), Path.of("/d/public"))
                        .contains("/d/public/x;"));

        OUT.println(failed == 0 ? "\nTUTTO OK" : "\n" + failed + " PROVE FALLITE");
        if (failed > 0) System.exit(1);
    }
}
