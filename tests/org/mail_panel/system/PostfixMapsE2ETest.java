package org.mail_panel.system;

import org.json.JSONArray;
import org.json.JSONObject;
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
 * il file di prima). Il confronto fra database e testo si prova con una voce aggiunta con
 * postmap -i, e con una mappa hash fuori dalla configurazione (l'ordine delle voci, un valore
 * cambiato, una riga in piu'). I tre lavori veri dell'updater li prova PostfixMapsJobsE2ETest.
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
            PostfixMaps.Outcome o = PostfixMaps.afterUpgrade(snap, log::add);
            check("stessa libreria: niente da fare, niente scritto", o.ok() && log.isEmpty());
            check("  e la cache resta dov'e'", Files.exists(Path.of(CACHE + ".lmdb")));

            System.out.println("\n== Il database e il testo, confrontati prima ==");
            System.out.println("     diverse dal testo: " + snap.outOfSync());
            check("nessuna mappa della VM risulta diversa dal suo testo (gli alias, la mappa della prova)", snap.outOfSync().isEmpty());
            check("  e il confronto non lascia file accanto",
                    sh("ls " + SOURCE + ".panel-check* /etc/aliases.panel-check* 2>/dev/null").isBlank());
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

            System.out.println("\n== La libreria di lmdb cambiata, e il file non piu' leggibile ==");
            String mapOwner = sh("stat -f '%Su:%Sg %Lp' " + SOURCE + ".lmdb").trim();
            Files.writeString(Path.of(SOURCE + ".lmdb"), "questo non e' un database lmdb");
            check("rovinato il file: la mappa non risponde piu'", !lookup().equals(ANSWER));
            Map<String, String> before = new TreeMap<>(real);
            before.put("lmdb", "liblmdb.so.0=/usr/local/lib/liblmdb.so.0(lmdb-di-prima)");
            int reloads = reloads();
            // Il confronto e' quello di prima della rovina: prima di pkg upgrade il file si leggeva.
            o = PostfixMaps.afterUpgrade(new PostfixMaps.Before(before, snap.outOfSync()), log::add);
            log.forEach(l -> System.out.println("       | " + l));
            check("la rigenerazione va a buon fine", o.ok());
            check("la mappa rigenerata risponde come prima", lookup().equals(ANSWER));
            check("  con proprietario e permessi di prima (" + mapOwner + ")",
                    sh("stat -f '%Su:%Sg %Lp' " + SOURCE + ".lmdb").trim().equals(mapOwner));
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
            log.clear();
            o = PostfixMaps.afterUpgrade(new PostfixMaps.Before(hashBefore, snap.outOfSync()), log::add);
            log.forEach(l -> System.out.println("       | " + l));
            check("la rigenerazione degli alias va a buon fine", o.ok());
            check("  e il registro dice hash:/etc/aliases, provata con una sua chiave",
                    String.join("\n", log).contains("hash:/etc/aliases (alias_") && String.join("\n", log).contains("«MAILER-DAEMON»"));
            check("gli alias rispondono (postalias -q MAILER-DAEMON)",
                    sh("postalias -q MAILER-DAEMON hash:/etc/aliases").trim().equals("postmaster"));
            check("  con proprietario e permessi di prima (" + aliasesOwner + ")",
                    sh("stat -f '%Su:%Sg %Lp' /etc/aliases.db").trim().equals(aliasesOwner));
            check("  e le mappe lmdb non toccate questa volta", !String.join("\n", log).contains("e2e-transport"));

            System.out.println("\n== Una mappa senza il suo testo ==");
            Files.delete(Path.of(SOURCE));
            log.clear();
            o = PostfixMaps.afterUpgrade(new PostfixMaps.Before(before, Map.of()), log::add);
            check("non si puo' rigenerare: errore, e dice quale", !o.ok() && o.problem().contains("e2e-transport"));

            System.out.println("\n== La previsione dal piano, col catalogo vero ==");
            String blocked = PostfixMaps.planBlocker(plan("remove lmdb0"));
            check("un piano che toglie lmdb0, con la mappa senza testo: si ferma prima, e nomina la mappa",
                    blocked != null && blocked.contains("e2e-transport"));
            check("un piano che aggiorna Postfix ma la versione nuova chiede ancora liblmdb.so.0: non si ferma",
                    PostfixMaps.planBlocker(plan("upgrade postfix-mysql")) == null);
            JSONObject replacement = PackageReplacement.judge(PackageReplacement.facts("lmdb0", "0.9.35",
                    Map.of("lmdb0", "remove"), List.of())).toJson();
            check("il giudizio su lmdb0 tolto dice la mappa che si perderebbe",
                    replacement.getJSONArray("problems").toString().contains("e2e-transport") && !replacement.optBoolean("safe"));
            Files.writeString(Path.of(SOURCE), TEXT);
            check("col testo rimesso: lo stesso piano non si ferma piu'", PostfixMaps.planBlocker(plan("remove lmdb0")) == null);

            System.out.println("\n== Una voce aggiunta con postmap -i, che il testo non ha ==");
            sh("echo 'extra.invalid " + EXTRA + "' | postmap -i lmdb:" + SOURCE);
            check("la voce aggiunta risponde", lookup("extra.invalid").equals(EXTRA));
            PostfixMaps.Before withExtra = PostfixMaps.before();
            String why = withExtra.outOfSync().get("lmdb:" + SOURCE);
            System.out.println("     " + why);
            check("il confronto la vede: il database ha 2 voci, il testo ne darebbe 1", why != null && why.contains("2") && why.contains("1"));
            check("  e non tocca il database: la voce aggiunta risponde ancora", lookup("extra.invalid").equals(EXTRA));
            check("  e gli alias coincidono ancora", !withExtra.outOfSync().containsKey("hash:/etc/aliases"));
            String extraBlocked = PostfixMaps.planBlocker(plan("remove lmdb0"));
            check("un piano che toglie lmdb0: si ferma prima, nomina la mappa e dice perche'",
                    extraBlocked != null && extraBlocked.contains("e2e-transport") && extraBlocked.contains(why));
            check("il giudizio su lmdb0 tolto dice la mappa che si perderebbe",
                    PackageReplacement.judge(PackageReplacement.facts("lmdb0", "0.9.35", Map.of("lmdb0", "remove"), List.of()))
                            .toJson().getJSONArray("problems").toString().contains("e2e-transport"));
            log.clear();
            o = PostfixMaps.afterUpgrade(new PostfixMaps.Before(before, withExtra.outOfSync()), log::add);
            log.forEach(l -> System.out.println("       | " + l));
            check("se la libreria cambia lo stesso: non la rigenera, ed e' un errore che la nomina",
                    !o.ok() && o.problem().contains("e2e-transport") && !String.join("\n", log).contains("«example.invalid»"));
            check("  e la voce aggiunta c'e' ancora", lookup("extra.invalid").equals(EXTRA));
            sh("postmap lmdb:" + SOURCE + " 2>/dev/null");
            check("rigenerata a mano dal testo: coincide, e il piano non si ferma piu'",
                    !PostfixMaps.before().outOfSync().containsKey("lmdb:" + SOURCE) && PostfixMaps.planBlocker(plan("remove lmdb0")) == null);
        } finally {
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
