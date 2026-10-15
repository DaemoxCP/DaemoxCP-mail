package org.mail_panel.system;

import org.json.JSONArray;
import org.json.JSONObject;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

/**
 * Il piano esatto di un aggiornamento e la risposta a "la fix c'e'?".
 *
 * Le uscite qui sotto hanno la forma che il sorgente di pkg stampa (src/utils.c per il piano,
 * src/audit.c per il JSON): sezioni con le voci rientrate da un tab, i totali in fondo, " (vulnerable!)"
 * accanto alle versioni di arrivo ancora vulnerabili, gli ranges di VuXML come "&gt;= a : &lt; b".
 *
 * Il caso che ha motivato la classe e' in fondo al gruppo della fix: nginx 1.30.4,3,
 * catalogo fermo alla stessa, VuXML che dice "&lt; 1.30.5,3". La scheda diceva insieme "protetto: la
 * patch non verra' applicata" e "nessun aggiornamento nel tuo ramo", e non si capiva se la
 * patch ci fosse.
 *
 * Con l'argomento "simulazione" prova anche la copia del database, contro un pkg finto: va
 * lanciata da tests/pkg-simulation-test.sh, che mette il finto nel PATH.
 */
public class PackagePlanTest {

    private static int falliti = 0;

    /** Confronto semplificato per le prove: epoch dopo la virgola, revisione dopo "_", poi i numeri. */
    static final PackagePlan.Confronto CMP = (a, b) -> {
        String[] ea = a.split(","), eb = b.split(",");
        int epa = ea.length > 1 ? Integer.parseInt(ea[1]) : 0, epb = eb.length > 1 ? Integer.parseInt(eb[1]) : 0;
        if (epa != epb) return Integer.compare(epa, epb);
        String[] ra = ea[0].split("_"), rb = eb[0].split("_");
        String[] pa = ra[0].split("[.+]"), pb = rb[0].split("[.+]");
        for (int i = 0; i < Math.max(pa.length, pb.length); i++) {
            long x = i < pa.length ? Long.parseLong(pa[i]) : 0, y = i < pb.length ? Long.parseLong(pb[i]) : 0;
            if (x != y) return Long.compare(x, y);
        }
        int rva = ra.length > 1 ? Integer.parseInt(ra[1]) : 0, rvb = rb.length > 1 ? Integer.parseInt(rb[1]) : 0;
        return Integer.compare(rva, rvb);
    };

    public static void main(String[] args) throws Exception {
        if (args.length > 0 && args[0].equals("simulazione")) { simulazione(); fine(); return; }

        // ---------------- il piano ----------------

        JSONObject p = PackagePlan.leggiPiano(String.join("\n",
            "Updating database digests format: . done",
            "Checking integrity... done (0 conflicting)",
            "The following 1 package(s) will be affected (of 0 checked):",
            "",
            "Installed packages to be UPGRADED:",
            "\tkafka: 4.3.0 -> 4.3.1",
            "",
            "Number of packages to be upgraded: 1",
            "",
            "81 MiB to be downloaded."));
        vero("kafka da solo: measured", p.getBoolean("measured"));
        JSONObject k = p.getJSONArray("changes").getJSONObject(0);
        vero("kafka da solo: 4.3.0 -> 4.3.1",
            "aggiorna".equals(k.getString("tipo")) && "kafka".equals(k.getString("nome"))
            && "4.3.0".equals(k.getString("da")) && "4.3.1".equals(k.getString("a")));
        vero("kafka da solo: non ancora vulnerabile", !k.getBoolean("stillVulnerable"));

        String grande = String.join("\n",
            "The following 5 package(s) will be affected (of 0 checked):",
            "",
            "Installed packages to be REMOVED:",
            "\tphp84-pecl-rdkafka: 6.0.3_1 (conflicts with php84-pecl-rdkafka6)",
            "",
            "New packages to be INSTALLED:",
            "\tpcre2: 10.45",
            "",
            "Installed packages to be REINSTALLED:",
            "\tphp84-8.4.19 (direct dependency changed: pcre2)",
            "",
            "Installed packages to be UPGRADED:",
            "\tnginx: 1.30.4,3 -> 1.30.5,3",
            "\topenssl35: 3.5.2 -> 3.5.3 (vulnerable!)",
            "",
            "Number of packages to be removed: 1",
            "Number of packages to be installed: 1",
            "Number of packages to be upgraded: 2",
            "Number of packages to be reinstalled: 1",
            "",
            "The process will require 2 MiB more space.",
            "12 MiB to be downloaded.");
        p = PackagePlan.leggiPiano(grande);
        vero("piano grande: measured e con 5 changes", p.getBoolean("measured") && p.getJSONArray("changes").length() == 5);
        vero("piano grande: la rimozione ha nome, versione e motivo",
            trova(p, "php84-pecl-rdkafka").getString("tipo").equals("rimuove")
            && trova(p, "php84-pecl-rdkafka").getString("da").equals("6.0.3_1")
            && trova(p, "php84-pecl-rdkafka").getString("reason").startsWith("conflicts with"));
        vero("piano grande: l'installazione nuova", "10.45".equals(trova(p, "pcre2").getString("a")));
        vero("piano grande: la reinstallazione separa nome e versione",
            "8.4.19".equals(trova(p, "php84").getString("da")) && trova(p, "php84").getString("reason").contains("pcre2"));
        vero("piano grande: nginx con l'epoch", "1.30.5,3".equals(trova(p, "nginx").getString("a")));
        vero("piano grande: openssl ancora vulnerabile dopo l'aggiornamento",
            trova(p, "openssl35").getBoolean("stillVulnerable") && "3.5.3".equals(trova(p, "openssl35").getString("a")));

        p = PackagePlan.leggiPiano(String.join("\n",
            "Installed packages LOCKED:",
            "\tPackage openjdk21-21.0.8+9.1 is locked and may not be upgraded to version 21.0.9+10.1",
            "",
            "Installed packages to be UPGRADED:",
            "\tkafka: 4.3.0 -> 4.3.1",
            "",
            "Number of packages to be upgraded: 1"));
        vero("protetto nel piano: measured", p.getBoolean("measured"));
        JSONObject b = p.getJSONArray("lockedPackages").getJSONObject(0);
        vero("protetto nel piano: nome, versione e dove andrebbe",
            "openjdk21".equals(b.getString("nome")) && "21.0.8+9.1".equals(b.getString("versione"))
            && "21.0.9+10.1".equals(b.getString("verso")));

        p = PackagePlan.leggiPiano(String.join("\n",
            "Checking integrity... done (0 conflicting)",
            "",
            "php84-pecl-rdkafka-6.0.3_1 is locked and may not be modified",
            "Your packages are up to date."));
        vero("protetto come evento (pkg piu' vecchio): il nome con i trattini",
            p.getJSONArray("lockedPackages").length() == 1
            && "php84-pecl-rdkafka".equals(p.getJSONArray("lockedPackages").getJSONObject(0).getString("nome")));

        p = PackagePlan.leggiPiano("Checking for upgrades (1 candidates): 100%\nYour packages are up to date.");
        vero("niente da fare", p.getBoolean("measured") && p.getBoolean("nothingToDo") && p.getJSONArray("changes").isEmpty());

        p = PackagePlan.leggiPiano("pkg: No packages available to upgrade matching 'kafka' have been found in the repositories");
        vero("errore di pkg riportato, non taciuto", p.getJSONArray("erroriPkg").length() == 1);

        p = PackagePlan.leggiPiano(String.join("\n",
            "Installed packages to be UPGRADED:",
            "\tnginx: 1.30.4,3 -> 1.30.5,3 [FreeBSD-latest]",
            "",
            "Number of packages to be upgraded: 1"));
        vero("con piu' repository: il nome del repository", "FreeBSD-latest".equals(trova(p, "nginx").getString("repo")));

        // I conti che non tornano non diventano un piano "completo".
        p = PackagePlan.leggiPiano(String.join("\n",
            "Installed packages to be UPGRADED:",
            "\tkafka: 4.3.0 -> 4.3.1",
            "",
            "Number of packages to be upgraded: 2"));
        vero("totale diverso: non measured", !p.getBoolean("measured"));
        p = PackagePlan.leggiPiano(String.join("\n",
            "Installed packages to be UPGRADED:",
            "\tkafka 4.3.0 4.3.1",
            "",
            "Number of packages to be upgraded: 1"));
        vero("riga illeggibile: non measured", !p.getBoolean("measured") && p.getJSONArray("illeggibili").length() == 1);
        p = PackagePlan.leggiPiano(String.join("\n",
            "Installed packages to be UPGRADED:",
            "\tkafka: 4.3.0 -> 4.3.1"));
        vero("totale mancante: non measured", !p.getBoolean("measured"));

        // ---------------- l'fingerprint ----------------

        JSONObject a1 = PackagePlan.leggiPiano(grande).put("unlockedPackages", new JSONArray().put("nginx"));
        String g2 = grande.replace("\tnginx: 1.30.4,3 -> 1.30.5,3\n\topenssl35: 3.5.2 -> 3.5.3 (vulnerable!)",
                                   "\topenssl35: 3.5.2 -> 3.5.3 (vulnerable!)\n\tnginx: 1.30.4,3 -> 1.30.5,3");
        JSONObject a2 = PackagePlan.leggiPiano(g2).put("unlockedPackages", new JSONArray().put("nginx"));
        vero("fingerprint: stesso piano in altro ordine, stessa fingerprint", PackagePlan.signature(a1).equals(PackagePlan.signature(a2)));
        JSONObject a3 = PackagePlan.leggiPiano(grande.replace("1.30.5,3", "1.30.6,3")).put("unlockedPackages", new JSONArray().put("nginx"));
        vero("fingerprint: una versione diversa cambia l'fingerprint", !PackagePlan.signature(a1).equals(PackagePlan.signature(a3)));
        JSONObject a4 = PackagePlan.leggiPiano(grande).put("unlockedPackages", new JSONArray().put("nginx").put("php84"));
        vero("fingerprint: una protezione in piu' da togliere cambia l'fingerprint", !PackagePlan.signature(a1).equals(PackagePlan.signature(a4)));

        // ---------------- la fix c'e'? ----------------

        String audit = """
            {
                "pkg_count": 2,
                "packages": {
                    "nginx": {
                        "version": "1.30.4,3",
                        "issue_count": 1,
                        "issues": [
                            {
                                "Affected versions": [
                                    ">= 1.25.0 : < 1.30.5,3"
                                ],
                                "description": "nginx -- buffer overflow when using ngx_http_v3_module",
                                "cve": [
                                    "CVE-2026-90439"
                                ],
                                "url": "https://vuxml.FreeBSD.org/freebsd/0f2a9d3c-9a3d-11f1-9d0e-001b217b3468.html"
                            }
                        ],
                        "reverse dependencies": []
                    },
                    "curl": {
                        "version": "8.15.0",
                        "issue_count": 2,
                        "issues": [
                            { "Affected versions": ["< 8.16.0"], "description": "curl -- uno", "cve": ["CVE-2026-1"], "url": "u1" },
                            { "Affected versions": ["< 8.17.0"], "description": "curl -- due", "cve": ["CVE-2026-2"], "url": "u2" }
                        ],
                        "reverse dependencies": ["git"]
                    }
                }
            }""";
        JSONObject va = PackagePlan.leggiAudit(audit);
        vero("audit: due pacchetti letti", va.length() == 2);
        JSONArray nginxProblemi = va.getJSONObject("nginx").getJSONArray("issues");
        vero("audit: l'intervallo di nginx", ">= 1.25.0 : < 1.30.5,3".equals(nginxProblemi.getJSONObject(0).getJSONArray("ranges").getString(0)));
        vero("audit: nessun pacchetto vulnerabile", PackagePlan.leggiAudit("{\n    \"pkg_count\": 0\n}").length() == 0);

        // IL CASO VERO: installata 1.30.4,3, catalogo fermo alla stessa, VuXML "< 1.30.5,3".
        JSONObject v = PackagePlan.valutaCorrezione("1.30.4,3", "1.30.4,3", nginxProblemi, CMP);
        vero("nginx: la fix esiste ma non nel ramo", "fix-fuori-dal-ramo".equals(v.getString("verdict")));
        vero("nginx: dalla 1.30.5,3", "1.30.5,3".equals(v.getString("firstFixed")));
        vero("nginx: il testo dice che il lock non c'entra", v.getString("explanation").contains("la protezione non c'entra"));

        v = PackagePlan.valutaCorrezione("1.30.4,3", "1.30.5,3", nginxProblemi, CMP);
        vero("nginx con la 1.30.5,3 nel catalogo: si risolve aggiornando", "si-risolve-aggiornando".equals(v.getString("verdict")));

        JSONArray curl = va.getJSONObject("curl").getJSONArray("issues");
        v = PackagePlan.valutaCorrezione("8.15.0", "8.16.0", curl, CMP);
        vero("curl: la 8.16.0 chiude uno solo dei due", "aggiornamento-non-basta".equals(v.getString("verdict"))
            && "8.17.0".equals(v.getString("firstFixed")) && v.getString("explanation").contains("curl -- due"));
        v = PackagePlan.valutaCorrezione("8.15.0", "8.17.0", curl, CMP);
        vero("curl: la 8.17.0 li chiude tutti e due", "si-risolve-aggiornando".equals(v.getString("verdict")));
        v = PackagePlan.valutaCorrezione("8.15.0", "", curl, CMP);
        vero("curl: catalogo senza il pacchetto, fix dalla 8.17.0",
            "fix-fuori-dal-ramo".equals(v.getString("verdict")) && "8.17.0".equals(v.getString("firstFixed")));

        v = PackagePlan.valutaCorrezione("2.1", "2.1", issues(">= 0"), CMP);
        vero("senza limite superiore: nessuna fix", "nessuna-fix".equals(v.getString("verdict")));
        v = PackagePlan.valutaCorrezione("2.1", "2.1", issues("<= 2.1"), CMP);
        vero("'<=': fix non indicata", "fix-non-indicata".equals(v.getString("verdict")));
        v = PackagePlan.valutaCorrezione("2.1", "2.1", issues("= 2.1"), CMP);
        vero("'=': solo quella versione, ma il catalogo non ne ha un'altra", "fix-fuori-dal-ramo".equals(v.getString("verdict")));
        // Piu' ranges: conta quello in cui cade la versione installata, non il primo.
        v = PackagePlan.valutaCorrezione("1.27.5", "1.27.5", issues("< 1.26.3", ">= 1.27.0 : < 1.28.1"), CMP);
        vero("due rami di versioni: la fix del ramo giusto", "1.28.1".equals(v.getString("firstFixed")));
        v = PackagePlan.valutaCorrezione("1.27.5", "1.28.0", issues("< 1.26.3", ">= 1.27.0 : < 1.28.1"), CMP);
        vero("due rami di versioni: la 1.28.0 non basta", "aggiornamento-non-basta".equals(v.getString("verdict")));
        v = PackagePlan.valutaCorrezione("3.0", "3.0", issues("< 2.0"), CMP);
        vero("versione fuori da ogni intervallo: non so, non invento", "non-so".equals(v.getString("verdict")));
        PackagePlan.Confronto rotto = (x, y) -> { throw new IllegalStateException("pkg non risponde"); };
        v = PackagePlan.valutaCorrezione("1.30.4,3", "1.30.4,3", nginxProblemi, rotto);
        vero("confronto rotto: non so", "non-so".equals(v.getString("verdict")) && v.getString("explanation").contains("pkg non risponde"));

        vero("estremi: uno", PackagePlan.estremi("< 1.30.5,3").size() == 1);
        vero("estremi: due", PackagePlan.estremi(">= 1.25.0 : < 1.30.5,3").size() == 2);


        // ---------------- il quadro dei pacchetti ----------------
        // Righe prese da FreeBSD 15.1 (pkg 2.6): "<" con la versione del catalogo, "?" fuori
        // catalogo, ">" piu' nuovo, "=" non compare con -L=.
        java.util.Map<String, String> agg = PackagePlan.daAggiornare(String.join("\n",
            "FreeBSD-acct-15.1                  ?   orphaned: base/FreeBSD-acct",
            "nginx-1.30.4,3                     <   needs updating (remote has 1.30.5_1,3)",
            "dovecot-mysql-2.3.21.1_3           <   needs updating (remote has 2.3.21.1_4)",
            "openjdk25-25.0.3+9.f.1             <   needs updating (remote has 25.0.4+7.f.1_1)",
            "clamav-1.5.4_1,1                   >   succeeds remote (remote has 1.5.2_3,1)",
            "rotto-1.0                          <   needs updating (remote has ; rm -rf /)",
            ""));
        vero("quadro: le righe '<' danno nome e versione del catalogo", "1.30.5_1,3".equals(agg.get("nginx"))
            && "2.3.21.1_4".equals(agg.get("dovecot-mysql")) && "25.0.4+7.f.1_1".equals(agg.get("openjdk25")));
        vero("quadro: '?' e '>' non sono aggiornamenti", !agg.containsKey("FreeBSD-acct") && !agg.containsKey("clamav"));
        vero("quadro: una versione con caratteri strani resta fuori", !agg.containsKey("rotto") && agg.size() == 3);
        java.util.Map<String, String[]> ins = PackagePlan.installati("nginx\t1.30.4,3\t1\nclamav\t1.5.4_1,1\t0\nmale\t1 2\t0\n\n");
        vero("quadro: pkg query da' versione e blocco", ins.size() == 2 && "1".equals(ins.get("nginx")[1])
            && "1.5.4_1,1".equals(ins.get("clamav")[0]) && "0".equals(ins.get("clamav")[1]));
        org.mail_panel.i18n.I18n.setCurrent("en");
        vero("quadro: il tipo di cambiamento si legge nella lingua di chi guarda",
            "upgrade".equals(PackagePlan.typeName("aggiorna")) && "remove".equals(PackagePlan.typeName("rimuove")));

        fine();
    }

    /**
     * La copia del database contro un pkg finto: sblocca nella copia, allarga l'elenco con le
     * dipendenze protette che pkg nomina, lascia intatto il database vero e cancella la copia.
     */
    static void simulazione() throws Exception {
        String db = System.getenv("FINTO_DB");
        if (db == null) { vero("FINTO_DB impostato (lancia tests/pkg-simulation-test.sh)", false); return; }
        Path locked = Path.of(db, "locked");
        Set<String> protetti = Set.of("kafka", "openjdk21", "nginx");
        int copiePrima = copieRimaste();

        JSONObject p = PackagePlan.pianoPer(List.of("kafka"), protetti, x -> null);
        vero("simulazione: riuscita e misurata", p.optBoolean("success") && p.optBoolean("measured"));
        vero("simulazione: pkg ha nominato openjdk21 e l'ho aggiunto",
            p.getJSONArray("unlockedPackages").toList().equals(List.of("kafka", "openjdk21")));
        vero("simulazione: il piano finale aggiorna kafka e openjdk21",
            trova(p, "kafka") != null && trova(p, "openjdk21") != null && p.getJSONArray("lockedPackages").isEmpty());
        // pkg si aggiorna da solo prima di tutto, ma con -n non lo dice: il piano lo deve dire lui.
        JSONObject primo = p.getJSONArray("changes").getJSONObject(0);
        vero("simulazione: pkg che aggiorna se stesso e' in testa al piano",
            "pkg".equals(primo.getString("nome")) && "2.1.0".equals(primo.getString("da")) && "2.2.0".equals(primo.getString("a")));
        vero("simulazione: runnable e con fingerprint", p.getBoolean("runnable") && p.getString("signature").length() == 16);
        vero("simulazione: il database VERO e' ancora protetto",
            Files.exists(locked.resolve("kafka")) && Files.exists(locked.resolve("openjdk21")));
        vero("simulazione: la copia e' stata cancellata", copieRimaste() == copiePrima);

        p = PackagePlan.pianoPer(List.of("kafka"), protetti,
                x -> x.getString("nome").equals("openjdk21") && x.getString("verso").equals("21.0.9+10.1")
                     ? "e' il JDK su cui gira il pannello" : null);
        vero("simulazione: il JDK del pannello resta un impedimento con il suo motivo",
            p.getJSONArray("blockers").length() == 1
            && p.getJSONArray("blockers").getJSONObject(0).getString("reason").contains("JDK"));
        vero("simulazione: con un impedimento non e' runnable", !p.getBoolean("runnable"));
        vero("simulazione: anche qui la copia e' sparita", copieRimaste() == copiePrima);

        p = PackagePlan.pianoPer(List.of("nginx"), protetti, x -> null);
        vero("simulazione: nginx non ha aggiornamenti, e lo dice", p.getJSONArray("unchangedPackages").toList().equals(List.of("nginx"))
            && !p.getBoolean("runnable"));

        JSONObject s = PackagePlan.simula(List.of("ka fka"), List.of("kafka"));
        vero("simulazione: un nome con uno spazio non arriva alla shell", !s.optBoolean("success"));
    }

    private static int copieRimaste() throws Exception {
        try (var st = Files.list(Path.of("/var/tmp"))) {
            return (int) st.filter(x -> x.getFileName().toString().startsWith("pannello-simulazione.")).count();
        }
    }

    private static JSONArray issues(String... ranges) {
        return new JSONArray().put(new JSONObject().put("ranges", new JSONArray(List.of(ranges)))
                .put("description", "prova").put("cve", new JSONArray()).put("url", ""));
    }

    private static JSONObject trova(JSONObject piano, String nome) {
        JSONArray c = piano.getJSONArray("changes");
        for (int i = 0; i < c.length(); i++) if (nome.equals(c.getJSONObject(i).getString("nome"))) return c.getJSONObject(i);
        return null;
    }

    private static void fine() {
        System.out.println(falliti == 0 ? "\nTUTTO OK" : "\n" + falliti + " PROVE FALLITE");
        if (falliti > 0) System.exit(1);
    }

    private static void vero(String nome, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + nome);
        if (!ok) falliti++;
    }
}
