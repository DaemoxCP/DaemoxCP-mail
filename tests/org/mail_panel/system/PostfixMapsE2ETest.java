package org.mail_panel.system;

import org.json.JSONArray;
import org.json.JSONObject;
import org.mail_panel.i18n.I18n;
import org.mail_panel.util.Shell;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * PostfixMaps con il Postfix vero della VM: la rigenerazione delle mappe quando cambia la libreria
 * che le legge.
 *
 * Si aggiungono a Postfix due tabelle lmdb della prova: una mappa di trasporto col suo testo
 * (e2e-transport, davanti a quelle che c'erano) e la cache della verifica degli indirizzi
 * (e2e-verify). Il cambio di libreria non lo si puo' provocare davvero (servirebbe un Postfix
 * costruito con LMDB 1.0): si da' a PostfixMaps una firma «di prima» diversa da quella vera, che e'
 * cio' che vedrebbe dopo il cambio, e il file della mappa lo si rovina, come lo vedrebbe una
 * libreria che non sa leggerlo. Cosi' si prova tutto il resto sul sistema vero: postmap, postalias,
 * la verifica, la cache, il ricaricamento di Postfix, e la previsione dal piano col catalogo vero.
 * Con una firma finta di hash si rigenera anche /etc/aliases, con postalias (e alla fine si rimette
 * il file di prima). Il confronto fra database e testo si prova con una mappa hash fuori dalla
 * configurazione (l'ordine delle voci, un valore cambiato, una riga in piu'). La ricostruzione dal
 * contenuto letto prima si prova senza il testo, con una voce aggiunta con postmap -i, con un
 * contenuto alterato (non deve andare in uso) e con un tetto alla memoria piu' basso (la mappa non
 * si tiene, e il piano si ferma). I tre lavori veri dell'updater li prova PostfixMapsJobsE2ETest.
 *
 * Tocca la configurazione di Postfix e la rimette com'era, e lo controlla: si accende solo con
 * -De2e.vm=yes, da root, su FreeBSD.
 *
 *   java -De2e.vm=yes -cp "tests:&lt;dir&gt;/freebsd-mail-panel-1.0.jar" org.mail_panel.system.PostfixMapsE2ETest
 */
public class PostfixMapsE2ETest {

    private static int failures = 0;

    static final String SOURCE = "/usr/local/etc/postfix/e2e-transport";
    static final String CACHE = "/var/db/postfix/e2e-verify";
    static final String ANSWER = "smtp:[127.0.0.1]:2525";
    /** Con una voce senza valore in testa: postmap la salta, e la verifica non deve cercarla. */
    static final String TEXT = "# prova di PostfixMaps\nbroken.invalid\nexample.invalid " + ANSWER + "\n";
    static final String ALIASES_BACKUP = "/var/tmp/postfix-maps-e2e-aliases.db";
    /** Una mappa hash fuori dalla configurazione, per il confronto indipendente dall'ordine. */
    static final String ORDER = "/var/tmp/postfix-maps-e2e-order";
    static final String EXTRA = "smtp:[127.0.0.1]:2527";

    public static void main(String[] args) throws Exception {
        if (!"yes".equals(System.getProperty("e2e.vm"))
                || !sh("uname -s").trim().equals("FreeBSD") || !sh("id -u").trim().equals("0")
                || !sh("postconf -m").contains("lmdb")) {
            System.out.println("SALTATA: serve -De2e.vm=yes, da root, su FreeBSD con Postfix che sa leggere lmdb");
            return;
        }
        String transportSet = sh("postconf -n transport_maps").trim();
        String verifySet = sh("postconf -n address_verify_map").trim();
        String transportOld = sh("postconf -h transport_maps").trim();
        String aliasesBefore = sh("stat -f %m /etc/aliases.db").trim();
        String aliasesOwner = sh("stat -f '%Su:%Sg %Lp' /etc/aliases.db").trim();
        sh("cp -p /etc/aliases.db " + ALIASES_BACKUP);
        List<String> log = new ArrayList<>();
        long budget = PostfixMaps.maxSavedBytes;
        String name = "lmdb:" + SOURCE, label = name + " (transport_maps)";
        try {
            Files.writeString(Path.of(SOURCE), TEXT);
            sh("postmap lmdb:" + SOURCE + " 2>/dev/null");
            sh("postconf -e 'transport_maps = lmdb:" + SOURCE + (transportOld.isEmpty() ? "" : ", " + transportOld) + "'");
            sh("postconf -e 'address_verify_map = lmdb:" + CACHE + "'");
            Files.writeString(Path.of(CACHE + ".lmdb"), "cache della prova");
            sh("postfix reload");
            check("la mappa della prova risponde, prima di tutto", lookup().equals(ANSWER));

            System.out.println("\n== Niente di cambiato ==");
            Map<String, String> real = PostfixMaps.librarySignature();
            System.out.println("     firme: " + real);
            check("lmdb e' letto da liblmdb.so.0 di lmdb0, hash dal sistema base",
                    String.valueOf(real.get("lmdb")).contains("liblmdb.so.0") && String.valueOf(real.get("lmdb")).contains("(lmdb0)")
                            && "base".equals(real.get("hash")));
            PostfixMaps.Before snap = PostfixMaps.before();
            System.out.println("     tenute da parte: " + snap.saved() + ", da non rigenerare: " + snap.lost());
            check("ogni mappa della VM coincide col suo testo: niente da tenere da parte, niente di perso",
                    snap.saved().isEmpty() && snap.lost().isEmpty());
            check("  e il confronto non lascia file accanto",
                    sh("ls " + SOURCE + ".panel-check* /etc/aliases.panel-check* 2>/dev/null").isBlank());
            PostfixMaps.Outcome o = PostfixMaps.afterUpgrade(snap, log::add);
            check("stessa libreria: niente da fare, niente scritto", o.ok() && log.isEmpty());
            check("  e la cache resta dov'e'", Files.exists(Path.of(CACHE + ".lmdb")));

            System.out.println("\n== Il database e il testo, confrontati ==");
            PostfixMaps.Table order = new PostfixMaps.Table("transport_maps", "hash", ORDER, PostfixMaps.Kind.PUBLIC);
            Files.writeString(Path.of(ORDER), "k1 v1\nk2 v2\nk3 v3\nk4 v4\nk5 v5\n");
            sh("postmap hash:" + ORDER);
            Files.writeString(Path.of(ORDER), "k5 v5\nk4 v4\nk3 v3\nk2 v2\nk1 v1\n");
            check("hash: le stesse voci scritte in un altro ordine coincidono col database (lo scarico esce in un altro ordine)",
                    PostfixMaps.outOfSync(order) == null);
            Files.writeString(Path.of(ORDER), "k5 v5\nk4 v4\nk3 altro\nk2 v2\nk1 v1\n");
            String values = PostfixMaps.outOfSync(order);
            check("un valore cambiato nel testo senza postmap: diverso, con le stesse 5 voci (" + values + ")",
                    values != null && values.contains("5"));
            Files.writeString(Path.of(ORDER), "k5 v5\nk4 v4\nk3 v3\nk2 v2\nk1 v1\nk6 v6\n");
            String counts = PostfixMaps.outOfSync(order);
            check("una riga in piu' nel testo senza postmap: diverso, 5 voci contro 6 (" + counts + ")",
                    counts != null && counts.contains("5") && counts.contains("6"));
            sh("rm -f " + ORDER + ".db");
            check("senza database c'e' solo il testo: niente da perdere, coincide", PostfixMaps.outOfSync(order) == null);
            sh("rm -f " + ORDER + " " + ORDER + ".db");

            System.out.println("\n== La libreria di lmdb cambiata: dal testo, che coincide ==");
            // Il database con un gruppo e dei permessi suoi: la mappa nuova deve averli uguali, non quelli del testo.
            sh("chown root:mail " + SOURCE + ".lmdb; chmod 640 " + SOURCE + ".lmdb");
            String mapOwner = stat(SOURCE + ".lmdb");
            PostfixMaps.Before fromText = PostfixMaps.before();
            Files.writeString(Path.of(SOURCE + ".lmdb"), "questo non e' un database lmdb");
            check("rovinato il file: la mappa non risponde piu'", !lookup().equals(ANSWER));
            Map<String, String> before = new TreeMap<>(real);
            before.put("lmdb", "liblmdb.so.0=/usr/local/lib/liblmdb.so.0(lmdb-di-prima)");
            int reloads = reloads();
            o = PostfixMaps.afterUpgrade(new PostfixMaps.Before(before, fromText.saved(), fromText.lost()), log::add);
            log.forEach(l -> System.out.println("       | " + l));
            check("la rigenerazione va a buon fine", o.ok());
            check("la mappa rigenerata risponde come prima", lookup().equals(ANSWER));
            check("  col proprietario e i permessi del database di prima (" + mapOwner + "), non quelli del testo",
                    mapOwner.equals("root:mail 640") && stat(SOURCE + ".lmdb").equals(mapOwner));
            check("  e nessun file della costruzione accanto", sh("ls " + SOURCE + ".panel-rebuild* 2>/dev/null").isBlank());
            check("Postfix e' stato ricaricato davvero (maillog: «refreshing the Postfix mail system»)", reloads() > reloads);
            check("la cache lmdb e' cancellata (Postfix la ricrea)", !Files.exists(Path.of(CACHE + ".lmdb")));
            check("il registro dice cosa ha rigenerato, con la chiave provata (non quella senza valore) e la cache",
                    String.join("\n", log).contains("e2e-transport") && String.join("\n", log).contains("«example.invalid»")
                            && !String.join("\n", log).contains("broken.invalid") && String.join("\n", log).contains("e2e-verify"));
            check("Postfix gira", sh("postfix status; echo $?").trim().endsWith("0"));
            check("le mappe hash non sono state toccate (/etc/aliases.db com'era)",
                    sh("stat -f %m /etc/aliases.db").trim().equals(aliasesBefore));

            System.out.println("\n== La libreria di hash cambiata: gli alias, con postalias ==");
            Map<String, String> hashBefore = new TreeMap<>(real);
            hashBefore.put("hash", "libdb.so.5=/usr/local/lib/db5/libdb.so.5(db5)");
            PostfixMaps.Before aliases = PostfixMaps.before();
            log.clear();
            o = PostfixMaps.afterUpgrade(new PostfixMaps.Before(hashBefore, aliases.saved(), aliases.lost()), log::add);
            log.forEach(l -> System.out.println("       | " + l));
            check("la rigenerazione degli alias va a buon fine", o.ok());
            check("  e il registro dice hash:/etc/aliases, provata con una sua chiave",
                    String.join("\n", log).contains("hash:/etc/aliases (alias_") && String.join("\n", log).contains("«MAILER-DAEMON»"));
            check("gli alias rispondono (postalias -q MAILER-DAEMON)",
                    sh("postalias -q MAILER-DAEMON hash:/etc/aliases").trim().equals("postmaster"));
            check("  con proprietario e permessi di prima (" + aliasesOwner + ")", stat("/etc/aliases.db").equals(aliasesOwner));
            check("  e le mappe lmdb non toccate questa volta", !String.join("\n", log).contains("e2e-transport"));

            System.out.println("\n== Una mappa senza il suo testo: dal contenuto letto prima ==");
            Files.delete(Path.of(SOURCE));
            PostfixMaps.Before noText = PostfixMaps.before();
            PostfixMaps.Saved saved = noText.saved().get(name);
            check("prima dell'aggiornamento il suo contenuto si tiene da parte: 1 voce", saved != null && saved.digest.entries() == 1);
            check("  e non finisce in nessun messaggio", !noText.toString().contains(ANSWER) && !noText.toString().contains("example.invalid"));
            check("la scheda non si ferma: la mappa si potrebbe rigenerare uguale", PostfixMaps.planBlocker(plan("remove lmdb0")) == null);
            Files.writeString(Path.of(SOURCE + ".lmdb"), "questo non e' un database lmdb");
            log.clear();
            o = PostfixMaps.afterUpgrade(new PostfixMaps.Before(before, noText.saved(), noText.lost()), log::add);
            log.forEach(l -> System.out.println("       | " + l));
            check("dopo il cambio di libreria si ricostruisce dal contenuto di prima, e risponde", o.ok() && lookup().equals(ANSWER));
            check("  col proprietario e i permessi di prima (" + mapOwner + ")", stat(SOURCE + ".lmdb").equals(mapOwner));
            check("  e il registro lo dice, e dice che il testo manca", String.join("\n", log).contains(
                    I18n.tr("server.maps.textMissing", Map.of("table", label))) && String.join("\n", log).contains(
                    I18n.tr("server.maps.rebuiltFromSaved", Map.of("table", label, "n", "1"))));
            check("  e il contenuto tenuto da parte si e' azzerato", saved.content() == null);
            check("  e nessun file della costruzione accanto", sh("ls " + SOURCE + ".panel-rebuild* 2>/dev/null").isBlank());
            log.clear();
            o = PostfixMaps.afterUpgrade(new PostfixMaps.Before(before), log::add);
            check("senza il contenuto letto prima (e senza testo): errore che la nomina", !o.ok() && o.problem().contains("e2e-transport"));

            System.out.println("\n== Quelle che non si potrebbero rigenerare, viste dal piano ==");
            PostfixMaps.maxSavedBytes = 1;
            String blocked = PostfixMaps.planBlocker(plan("remove lmdb0"));
            System.out.println("     " + blocked);
            check("senza testo e col contenuto piu' grande di quello che si tiene: si ferma prima, e nomina la mappa",
                    blocked != null && blocked.contains("e2e-transport") && blocked.contains(I18n.tr("server.maps.reasonNoSource")));
            JSONObject replacement = PackageReplacement.judge(PackageReplacement.facts("lmdb0", "0.9.35",
                    Map.of("lmdb0", "remove"), List.of())).toJson();
            check("il giudizio su lmdb0 tolto dice la mappa che si perderebbe",
                    replacement.getJSONArray("problems").toString().contains("e2e-transport") && !replacement.optBoolean("safe"));
            PostfixMaps.Before tight = PostfixMaps.before();
            check("  e before() non la tiene: la da' per persa", tight.saved().isEmpty() && tight.lost().containsKey(name));
            PostfixMaps.maxSavedBytes = budget;
            Files.writeString(Path.of(SOURCE + ".lmdb"), "questo non e' un database lmdb");
            String unreadable = PostfixMaps.planBlocker(plan("remove lmdb0"));
            check("un database che non si legge gia' adesso: si ferma prima",
                    unreadable != null && unreadable.contains("e2e-transport") && unreadable.contains(I18n.tr("server.maps.dbUnreadable")));
            check("un piano che aggiorna Postfix ma la versione nuova chiede ancora liblmdb.so.0: non si ferma",
                    PostfixMaps.planBlocker(plan("upgrade postfix-mysql")) == null);
            // postmap non riscrive un file che non sa leggere (misurato, vedi PostfixMaps): prima lo si toglie.
            Files.writeString(Path.of(SOURCE), TEXT);
            sh("rm -f " + SOURCE + ".lmdb; postmap lmdb:" + SOURCE + " 2>/dev/null");
            check("col testo rimesso e la mappa rigenerata: il piano non si ferma piu'", PostfixMaps.planBlocker(plan("remove lmdb0")) == null);

            System.out.println("\n== Una voce aggiunta con postmap -i, che il testo non ha ==");
            sh("echo 'extra.invalid " + EXTRA + "' | postmap -i lmdb:" + SOURCE);
            check("la voce aggiunta risponde", lookup("extra.invalid").equals(EXTRA));
            PostfixMaps.Before withExtra = PostfixMaps.before();
            PostfixMaps.Saved extra = withExtra.saved().get(name);
            System.out.println("     " + (extra == null ? "non tenuta" : extra.textDiffers));
            check("il confronto la vede, e il contenuto si tiene da parte: 2 voci, il testo ne darebbe 1",
                    extra != null && extra.digest.entries() == 2 && extra.textDiffers != null
                            && extra.textDiffers.contains("2") && extra.textDiffers.contains("1"));
            check("  e non tocca il database: la voce aggiunta risponde ancora", lookup("extra.invalid").equals(EXTRA));
            check("  e gli alias coincidono ancora", !withExtra.saved().containsKey("hash:/etc/aliases") && withExtra.lost().isEmpty());
            check("la scheda non si ferma", PostfixMaps.planBlocker(plan("remove lmdb0")) == null);
            Files.writeString(Path.of(SOURCE + ".lmdb"), "questo non e' un database lmdb");
            log.clear();
            o = PostfixMaps.afterUpgrade(new PostfixMaps.Before(before, withExtra.saved(), withExtra.lost()), log::add);
            log.forEach(l -> System.out.println("       | " + l));
            check("dopo il cambio: ricostruita dal contenuto di prima, con la voce aggiunta",
                    o.ok() && lookup("extra.invalid").equals(EXTRA) && lookup().equals(ANSWER));
            check("  e il registro dice che il testo e' diverso; il testo e' rimasto com'era",
                    String.join("\n", log).contains(I18n.tr("server.maps.textDiffers", Map.of("table", label, "why", String.valueOf(extra.textDiffers))))
                            && Files.readString(Path.of(SOURCE)).equals(TEXT));

            System.out.println("\n== Un contenuto tenuto da parte che non coincide piu' ==");
            PostfixMaps.Before tampered = PostfixMaps.before();
            byte[] content = tampered.saved().get(name).content();
            content[0] = (byte) (content[0] == 'e' ? 'f' : 'e');
            log.clear();
            o = PostfixMaps.afterUpgrade(new PostfixMaps.Before(before, tampered.saved(), tampered.lost()), log::add);
            log.forEach(l -> System.out.println("       | " + l));
            check("non la mette in uso: errore che la nomina", !o.ok() && o.problem().contains("e2e-transport"));
            check("  e la mappa e' quella di prima: rispondono tutte e due le voci", lookup().equals(ANSWER) && lookup("extra.invalid").equals(EXTRA));
            check("  e nessun file della costruzione accanto", sh("ls " + SOURCE + ".panel-rebuild* 2>/dev/null").isBlank());

            System.out.println("\n== Una voce aggiunta, e il contenuto troppo grande da tenere ==");
            PostfixMaps.maxSavedBytes = 1;
            PostfixMaps.Before big = PostfixMaps.before();
            check("non si tiene: data per persa, col perche' (2 voci contro 1)", big.saved().isEmpty()
                    && big.lost().getOrDefault(name, "").contains("2") && big.lost().getOrDefault(name, "").contains("1"));
            check("la scheda si ferma", PostfixMaps.planBlocker(plan("remove lmdb0")) != null);
            log.clear();
            o = PostfixMaps.afterUpgrade(new PostfixMaps.Before(before, big.saved(), big.lost()), log::add);
            check("se la libreria cambia lo stesso: non la rigenera, errore che la nomina, e la voce resta",
                    !o.ok() && o.problem().contains("e2e-transport") && lookup("extra.invalid").equals(EXTRA));
            PostfixMaps.maxSavedBytes = budget;
        } finally {
            PostfixMaps.maxSavedBytes = budget;
            if (transportSet.isEmpty()) sh("postconf -X transport_maps"); else sh("postconf -e '" + transportSet + "'");
            if (verifySet.isEmpty()) sh("postconf -X address_verify_map"); else sh("postconf -e '" + verifySet + "'");
            sh("rm -f " + SOURCE + " " + SOURCE + ".lmdb " + CACHE + ".lmdb " + CACHE + ".lmdb-lock");
            sh("rm -f " + ORDER + " " + ORDER + ".db");
            sh("[ -f " + ALIASES_BACKUP + " ] && cp -p " + ALIASES_BACKUP + " /etc/aliases.db && rm -f " + ALIASES_BACKUP);
            sh("postfix reload");
            check("alla fine: transport_maps e address_verify_map come prima",
                    sh("postconf -n transport_maps").trim().equals(transportSet) && sh("postconf -n address_verify_map").trim().equals(verifySet));
            check("alla fine: niente file della prova", !Files.exists(Path.of(SOURCE)) && !Files.exists(Path.of(SOURCE + ".lmdb"))
                    && !Files.exists(Path.of(CACHE + ".lmdb")));
            check("alla fine: Postfix gira", sh("postfix status; echo $?").trim().endsWith("0"));
            check("alla fine: /etc/aliases.db com'era", sh("stat -f %m /etc/aliases.db").trim().equals(aliasesBefore)
                    && sh("postalias -q MAILER-DAEMON hash:/etc/aliases").trim().equals("postmaster"));
        }
        System.out.println(failures == 0 ? "\nTUTTO OK" : "\n" + failures + " PROVE FALLITE");
        if (failures > 0) System.exit(1);
    }

    /** Quante volte Postfix e' stato ricaricato, secondo il maillog (syslog scrive con un attimo di ritardo). */
    static int reloads() {
        return Integer.parseInt(sh("sleep 1; grep -c 'refreshing the Postfix mail system' /var/log/maillog").trim());
    }

    static String stat(String file) {
        return sh("stat -f '%Su:%Sg %Lp' " + file).trim();
    }

    static String lookup() {
        return lookup("example.invalid");
    }

    static String lookup(String key) {
        return sh("postmap -q " + key + " lmdb:" + SOURCE + " 2>/dev/null").trim();
    }

    static JSONObject plan(String... typeAndName) {
        JSONArray c = new JSONArray();
        for (String s : typeAndName) {
            String[] p = s.split(" ");
            c.put(new JSONObject().put("type", p[0]).put("name", p[1]).put("from", "1").put("to", "2"));
        }
        return new JSONObject().put("changes", c);
    }

    static String sh(String cmd) {
        return Shell.runShell(Duration.ofSeconds(120), cmd).output();
    }

    static void check(String name, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + name);
        if (!ok) failures++;
    }
}
