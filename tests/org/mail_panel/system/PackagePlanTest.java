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

    private static int failed = 0;

    /** Confronto semplificato per le prove: epoch dopo la virgola, revisione dopo "_", poi i numeri. */
    static final PackagePlan.VersionComparator CMP = (a, b) -> {
        String[] ea = a.split(","), eb = b.split(",");
        int epochA = ea.length > 1 ? Integer.parseInt(ea[1]) : 0, epochB = eb.length > 1 ? Integer.parseInt(eb[1]) : 0;
        if (epochA != epochB) return Integer.compare(epochA, epochB);
        String[] ra = ea[0].split("_"), rb = eb[0].split("_");
        String[] pa = ra[0].split("[.+]"), pb = rb[0].split("[.+]");
        for (int i = 0; i < Math.max(pa.length, pb.length); i++) {
            long x = i < pa.length ? Long.parseLong(pa[i]) : 0, y = i < pb.length ? Long.parseLong(pb[i]) : 0;
            if (x != y) return Long.compare(x, y);
        }
        int versionA = ra.length > 1 ? Integer.parseInt(ra[1]) : 0, versionB = rb.length > 1 ? Integer.parseInt(rb[1]) : 0;
        return Integer.compare(versionA, versionB);
    };

    public static void main(String[] args) throws Exception {
        if (args.length > 0 && args[0].equals("simulazione")) { simulation(); end(); return; }
        // I due casi del gemello di famiglia che hanno bisogno di un pkg finto diverso: lo
        // script li lancia a parte, con V_CAT e MYSQL97 (vedi tests/pkg-simulation-test.sh).
        if (args.length > 0 && args[0].equals("famiglia-catalogo-nuovo")) { familyNewCatalog(); end(); return; }
        if (args.length > 0 && args[0].equals("famiglia-conflitto-vero")) { familyRealConflict(); end(); return; }

        // ---------------- il piano ----------------

        JSONObject p = PackagePlan.readPlan(String.join("\n",
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
        real("kafka da solo: measured", p.getBoolean("measured"));
        JSONObject k = p.getJSONArray("changes").getJSONObject(0);
        real("kafka da solo: 4.3.0 -> 4.3.1",
            "upgrade".equals(k.getString("type")) && "kafka".equals(k.getString("name"))
            && "4.3.0".equals(k.getString("from")) && "4.3.1".equals(k.getString("to")));
        real("kafka da solo: non ancora vulnerabile", !k.getBoolean("stillVulnerable"));

        String large = String.join("\n",
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
        p = PackagePlan.readPlan(large);
        real("piano grande: measured e con 5 changes", p.getBoolean("measured") && p.getJSONArray("changes").length() == 5);
        real("piano grande: la rimozione ha nome, versione e motivo",
            find(p, "php84-pecl-rdkafka").getString("type").equals("remove")
            && find(p, "php84-pecl-rdkafka").getString("from").equals("6.0.3_1")
            && find(p, "php84-pecl-rdkafka").getString("reason").startsWith("conflicts with"));
        real("piano grande: l'installazione nuova", "10.45".equals(find(p, "pcre2").getString("to")));
        real("piano grande: la reinstallazione separa nome e versione",
            "8.4.19".equals(find(p, "php84").getString("from")) && find(p, "php84").getString("reason").contains("pcre2"));
        real("piano grande: nginx con l'epoch", "1.30.5,3".equals(find(p, "nginx").getString("to")));
        real("piano grande: openssl ancora vulnerabile dopo l'aggiornamento",
            find(p, "openssl35").getBoolean("stillVulnerable") && "3.5.3".equals(find(p, "openssl35").getString("to")));

        p = PackagePlan.readPlan(String.join("\n",
            "Installed packages LOCKED:",
            "\tPackage openjdk21-21.0.8+9.1 is locked and may not be upgraded to version 21.0.9+10.1",
            "",
            "Installed packages to be UPGRADED:",
            "\tkafka: 4.3.0 -> 4.3.1",
            "",
            "Number of packages to be upgraded: 1"));
        real("protetto nel piano: measured", p.getBoolean("measured"));
        JSONObject b = p.getJSONArray("lockedPackages").getJSONObject(0);
        real("protetto nel piano: nome, versione e dove andrebbe",
            "openjdk21".equals(b.getString("name")) && "21.0.8+9.1".equals(b.getString("version"))
            && "21.0.9+10.1".equals(b.getString("destination")));

        p = PackagePlan.readPlan(String.join("\n",
            "Checking integrity... done (0 conflicting)",
            "",
            "php84-pecl-rdkafka-6.0.3_1 is locked and may not be modified",
            "Your packages are up to date."));
        real("protetto come evento (pkg piu' vecchio): il nome con i trattini",
            p.getJSONArray("lockedPackages").length() == 1
            && "php84-pecl-rdkafka".equals(p.getJSONArray("lockedPackages").getJSONObject(0).getString("name")));

        p = PackagePlan.readPlan("Checking for upgrades (1 candidates): 100%\nYour packages are up to date.");
        real("niente da fare", p.getBoolean("measured") && p.getBoolean("nothingToDo") && p.getJSONArray("changes").isEmpty());

        p = PackagePlan.readPlan("pkg: No packages available to upgrade matching 'kafka' have been found in the repositories");
        real("errore di pkg riportato, non taciuto", p.getJSONArray("pkgErrors").length() == 1);

        p = PackagePlan.readPlan(String.join("\n",
            "Installed packages to be UPGRADED:",
            "\tnginx: 1.30.4,3 -> 1.30.5,3 [FreeBSD-latest]",
            "",
            "Number of packages to be upgraded: 1"));
        real("con piu' repository: il nome del repository", "FreeBSD-latest".equals(find(p, "nginx").getString("repo")));

        // I conti che non tornano non diventano un piano "completo".
        p = PackagePlan.readPlan(String.join("\n",
            "Installed packages to be UPGRADED:",
            "\tkafka: 4.3.0 -> 4.3.1",
            "",
            "Number of packages to be upgraded: 2"));
        real("totale diverso: non measured", !p.getBoolean("measured"));
        p = PackagePlan.readPlan(String.join("\n",
            "Installed packages to be UPGRADED:",
            "\tkafka 4.3.0 4.3.1",
            "",
            "Number of packages to be upgraded: 1"));
        real("riga illeggibile: non measured", !p.getBoolean("measured") && p.getJSONArray("unreadable").length() == 1);
        p = PackagePlan.readPlan(String.join("\n",
            "Installed packages to be UPGRADED:",
            "\tkafka: 4.3.0 -> 4.3.1"));
        real("totale mancante: non measured", !p.getBoolean("measured"));

        // ---------------- l'fingerprint ----------------

        JSONObject a1 = PackagePlan.readPlan(large).put("unlockedPackages", new JSONArray().put("nginx"));
        String g2 = large.replace("\tnginx: 1.30.4,3 -> 1.30.5,3\n\topenssl35: 3.5.2 -> 3.5.3 (vulnerable!)",
                                   "\topenssl35: 3.5.2 -> 3.5.3 (vulnerable!)\n\tnginx: 1.30.4,3 -> 1.30.5,3");
        JSONObject a2 = PackagePlan.readPlan(g2).put("unlockedPackages", new JSONArray().put("nginx"));
        real("fingerprint: stesso piano in altro ordine, stessa fingerprint", PackagePlan.signature(a1).equals(PackagePlan.signature(a2)));
        JSONObject a3 = PackagePlan.readPlan(large.replace("1.30.5,3", "1.30.6,3")).put("unlockedPackages", new JSONArray().put("nginx"));
        real("fingerprint: una versione diversa cambia l'fingerprint", !PackagePlan.signature(a1).equals(PackagePlan.signature(a3)));
        JSONObject a4 = PackagePlan.readPlan(large).put("unlockedPackages", new JSONArray().put("nginx").put("php84"));
        real("fingerprint: una protezione in piu' da togliere cambia l'fingerprint", !PackagePlan.signature(a1).equals(PackagePlan.signature(a4)));

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
        JSONObject va = PackagePlan.readAudit(audit);
        real("audit: due pacchetti letti", va.length() == 2);
        JSONArray nginxProblems = va.getJSONObject("nginx").getJSONArray("issues");
        real("audit: l'intervallo di nginx", ">= 1.25.0 : < 1.30.5,3".equals(nginxProblems.getJSONObject(0).getJSONArray("ranges").getString(0)));
        real("audit: nessun pacchetto vulnerabile", PackagePlan.readAudit("{\n    \"pkg_count\": 0\n}").length() == 0);

        // IL CASO VERO: installata 1.30.4,3, catalogo fermo alla stessa, VuXML "< 1.30.5,3".
        JSONObject v = PackagePlan.assessFix("1.30.4,3", "1.30.4,3", nginxProblems, CMP);
        real("nginx: la fix esiste ma non nel ramo", "fix-fuori-dal-ramo".equals(v.getString("verdict")));
        real("nginx: dalla 1.30.5,3", "1.30.5,3".equals(v.getString("firstFixed")));
        real("nginx: il testo dice che il lock non c'entra", v.getString("explanation").contains("la protezione non c'entra"));

        v = PackagePlan.assessFix("1.30.4,3", "1.30.5,3", nginxProblems, CMP);
        real("nginx con la 1.30.5,3 nel catalogo: si risolve aggiornando", "si-risolve-aggiornando".equals(v.getString("verdict")));

        JSONArray curl = va.getJSONObject("curl").getJSONArray("issues");
        v = PackagePlan.assessFix("8.15.0", "8.16.0", curl, CMP);
        real("curl: la 8.16.0 chiude uno solo dei due", "aggiornamento-non-basta".equals(v.getString("verdict"))
            && "8.17.0".equals(v.getString("firstFixed")) && v.getString("explanation").contains("curl -- due"));
        v = PackagePlan.assessFix("8.15.0", "8.17.0", curl, CMP);
        real("curl: la 8.17.0 li chiude tutti e due", "si-risolve-aggiornando".equals(v.getString("verdict")));
        v = PackagePlan.assessFix("8.15.0", "", curl, CMP);
        real("curl: catalogo senza il pacchetto, fix dalla 8.17.0",
            "fix-fuori-dal-ramo".equals(v.getString("verdict")) && "8.17.0".equals(v.getString("firstFixed")));

        v = PackagePlan.assessFix("2.1", "2.1", issues(">= 0"), CMP);
        real("senza limite superiore: nessuna fix", "nessuna-fix".equals(v.getString("verdict")));
        v = PackagePlan.assessFix("2.1", "2.1", issues("<= 2.1"), CMP);
        real("'<=': fix non indicata", "fix-non-indicata".equals(v.getString("verdict")));
        v = PackagePlan.assessFix("2.1", "2.1", issues("= 2.1"), CMP);
        real("'=': solo quella versione, ma il catalogo non ne ha un'altra", "fix-fuori-dal-ramo".equals(v.getString("verdict")));
        // Piu' ranges: conta quello in cui cade la versione installata, non il primo.
        v = PackagePlan.assessFix("1.27.5", "1.27.5", issues("< 1.26.3", ">= 1.27.0 : < 1.28.1"), CMP);
        real("due rami di versioni: la fix del ramo giusto", "1.28.1".equals(v.getString("firstFixed")));
        v = PackagePlan.assessFix("1.27.5", "1.28.0", issues("< 1.26.3", ">= 1.27.0 : < 1.28.1"), CMP);
        real("due rami di versioni: la 1.28.0 non basta", "aggiornamento-non-basta".equals(v.getString("verdict")));
        v = PackagePlan.assessFix("3.0", "3.0", issues("< 2.0"), CMP);
        real("versione fuori da ogni intervallo: non so, non invento", "non-so".equals(v.getString("verdict")));
        PackagePlan.VersionComparator broken = (x, y) -> { throw new IllegalStateException("pkg non risponde"); };
        v = PackagePlan.assessFix("1.30.4,3", "1.30.4,3", nginxProblems, broken);
        real("confronto rotto: non so", "non-so".equals(v.getString("verdict")) && v.getString("explanation").contains("pkg non risponde"));

        real("estremi: uno", PackagePlan.bounds("< 1.30.5,3").size() == 1);
        real("estremi: due", PackagePlan.bounds(">= 1.25.0 : < 1.30.5,3").size() == 2);


        // ---------------- il quadro dei pacchetti ----------------
        // Righe prese da FreeBSD 15.1 (pkg 2.6): "<" con la versione del catalogo, "?" fuori
        // catalogo, ">" piu' nuovo, "=" non compare con -L=.
        java.util.Map<String, String> update = PackagePlan.toUpdate(String.join("\n",
            "FreeBSD-acct-15.1                  ?   orphaned: base/FreeBSD-acct",
            "nginx-1.30.4,3                     <   needs updating (remote has 1.30.5_1,3)",
            "dovecot-mysql-2.3.21.1_3           <   needs updating (remote has 2.3.21.1_4)",
            "openjdk25-25.0.3+9.f.1             <   needs updating (remote has 25.0.4+7.f.1_1)",
            "clamav-1.5.4_1,1                   >   succeeds remote (remote has 1.5.2_3,1)",
            "rotto-1.0                          <   needs updating (remote has ; rm -rf /)",
            ""));
        real("quadro: le righe '<' danno nome e versione del catalogo", "1.30.5_1,3".equals(update.get("nginx"))
            && "2.3.21.1_4".equals(update.get("dovecot-mysql")) && "25.0.4+7.f.1_1".equals(update.get("openjdk25")));
        real("quadro: '?' e '>' non sono aggiornamenti", !update.containsKey("FreeBSD-acct") && !update.containsKey("clamav"));
        real("quadro: una versione con caratteri strani resta fuori", !update.containsKey("rotto") && update.size() == 3);
        java.util.Map<String, String[]> ins = PackagePlan.installed("nginx\t1.30.4,3\t1\nclamav\t1.5.4_1,1\t0\nmale\t1 2\t0\n\n");
        real("quadro: pkg query da' versione e blocco", ins.size() == 2 && "1".equals(ins.get("nginx")[1])
            && "1.5.4_1,1".equals(ins.get("clamav")[0]) && "0".equals(ins.get("clamav")[1]));
        org.mail_panel.i18n.I18n.setCurrent("en");
        real("quadro: il tipo di cambiamento si legge nella lingua di chi guarda",
            "upgrade".equals(PackagePlan.typeName("upgrade")) && "remove".equals(PackagePlan.typeName("remove")));

        end();
    }

    /**
     * La copia del database contro un pkg finto: sblocca nella copia, allarga l'elenco con le
     * dipendenze protette che pkg nomina, lascia intatto il database vero e cancella la copia.
     */
    static void simulation() throws Exception {
        String db = System.getenv("FINTO_DB");
        if (db == null) { real("FINTO_DB impostato (lancia tests/pkg-simulation-test.sh)", false); return; }
        Path locked = Path.of(db, "locked");
        Set<String> protectedNames = Set.of("kafka", "openjdk21", "nginx");
        int copiesBefore = remainingCopies();

        JSONObject p = PackagePlan.planFor(List.of("kafka"), protectedNames, x -> null);
        real("simulazione: riuscita e misurata", p.optBoolean("success") && p.optBoolean("measured"));
        real("simulazione: pkg ha nominato openjdk21 e l'ho aggiunto",
            p.getJSONArray("unlockedPackages").toList().equals(List.of("kafka", "openjdk21")));
        real("simulazione: il piano finale aggiorna kafka e openjdk21",
            find(p, "kafka") != null && find(p, "openjdk21") != null && p.getJSONArray("lockedPackages").isEmpty());
        // pkg si aggiorna da solo prima di tutto, ma con -n non lo dice: il piano lo deve dire lui.
        JSONObject first = p.getJSONArray("changes").getJSONObject(0);
        real("simulazione: pkg che aggiorna se stesso e' in testa al piano",
            "pkg".equals(first.getString("name")) && "2.1.0".equals(first.getString("from")) && "2.2.0".equals(first.getString("to")));
        real("simulazione: runnable e con fingerprint", p.getBoolean("runnable") && p.getString("signature").length() == 16);
        real("simulazione: il database VERO e' ancora protetto",
            Files.exists(locked.resolve("kafka")) && Files.exists(locked.resolve("openjdk21")));
        real("simulazione: la copia e' stata cancellata", remainingCopies() == copiesBefore);

        p = PackagePlan.planFor(List.of("kafka"), protectedNames,
                x -> x.getString("name").equals("openjdk21") && x.getString("destination").equals("21.0.9+10.1")
                     ? "e' il JDK su cui gira il pannello" : null);
        real("simulazione: il JDK del pannello resta un impedimento con il suo motivo",
            p.getJSONArray("blockers").length() == 1
            && p.getJSONArray("blockers").getJSONObject(0).getString("reason").contains("JDK"));
        real("simulazione: con un impedimento non e' runnable", !p.getBoolean("runnable"));
        real("simulazione: anche qui la copia e' sparita", remainingCopies() == copiesBefore);

        p = PackagePlan.planFor(List.of("nginx"), protectedNames, x -> null);
        real("simulazione: nginx non ha aggiornamenti, e lo dice", p.getJSONArray("unchangedPackages").toList().equals(List.of("nginx"))
            && !p.getBoolean("runnable"));

        // === Il gemello di famiglia: un blocco che fa SOSTITUIRE il pacchetto ===
        //
        // Per pkg un pacchetto protetto non e' "da non cambiare": e' non disponibile. Con
        // mysql84-client protetto, il piano per postfix-mysql propone "installa
        // mysql97-client" — i due forniscono la stessa libreria e si contendono gli stessi
        // file, quindi l'esecuzione muore a meta'. Misurato sulla VM il 23/10/2026: uscita 3,
        // «mysql97-client conflicts with mysql84-client (installs files into the same place)»;
        // e sbloccando anche mysql84-client, nella stessa simulazione mysql97-client sparisce.
        Set<String> mysqlProtected = Set.of("kafka", "openjdk21", "nginx",
                "mysql84-client", "mysql84-server", "postfix-mysql");

        p = PackagePlan.planFor(List.of("postfix-mysql"), mysqlProtected, x -> null,
                UpdateManager::installedFamilyTwin);
        real("famiglia: il piano e' misurato", p.optBoolean("measured"));
        real("famiglia: sblocca anche il gemello protetto",
            p.getJSONArray("unlockedPackages").toList().contains("mysql84-client"));
        real("famiglia: e cosi' mysql97-client SPARISCE dal piano", find(p, "mysql97-client") == null);
        real("famiglia: l'aggiornamento chiesto c'e' ancora", find(p, "postfix-mysql") != null);
        real("famiglia: nessun impedimento, quindi si puo' eseguire",
            p.getJSONArray("blockers").isEmpty() && p.getBoolean("runnable"));
        JSONArray familyUnlocked = p.getJSONArray("familyUnlocked");
        real("famiglia: il piano dice QUALE gemello ha sbloccato e perche'",
            familyUnlocked.length() == 1 && "mysql84-client".equals(familyUnlocked.getJSONObject(0).getString("installed"))
            && "mysql97-client".equals(familyUnlocked.getJSONObject(0).getString("wouldInstall")));
        real("famiglia: e a quale versione", "8.4.11_1".equals(familyUnlocked.getJSONObject(0).getString("version")));

        // Lo scheletro del nome: due condizioni, perche' una sola sbaglia.
        real("scheletro: le cifre diventano #",
            "mysql#-client".equals(UpdateManager.nameSkeleton("mysql84-client"))
            && "mysql#-client".equals(UpdateManager.nameSkeleton("mysql97-client")));
        real("scheletro: il server NON e' lo stesso posto del client",
            !UpdateManager.nameSkeleton("mysql84-server").equals(UpdateManager.nameSkeleton("mysql97-client")));
        real("gemello: mysql84-server non e' il gemello di mysql97-client",
            "mysql84-client".equals(UpdateManager.installedFamilyTwin("mysql97-client")));
        real("gemello: python312 non ha gemelli, non e' una famiglia dichiarata",
            UpdateManager.installedFamilyTwin("python313") == null);
        real("gemello: un nome che non passa il filtro non interroga niente",
            UpdateManager.installedFamilyTwin("mysql97-client; rm -rf /") == null);

        JSONObject s = PackagePlan.simulate(List.of("ka fka"), List.of("kafka"));
        real("simulazione: un nome con uno spazio non arriva alla shell", !s.optBoolean("success"));
    }

    /**
     * Il gemello protetto, ma con il catalogo che ne ha una versione PIU' RECENTE.
     *
     * Sbloccarlo per far vedere a pkg cio' che c'e' sarebbe sbloccarlo per aggiornarlo, cioe'
     * un cambiamento che nessuno ha chiesto — e per i client MySQL l'avvertenza del pannello
     * dice di aspettare. Allora resta un impedimento, col suo motivo. Il pkg finto lo dice
     * con V_CAT.
     */
    static void familyNewCatalog() throws Exception {
        if (System.getenv("FINTO_DB") == null) { real("FINTO_DB impostato", false); return; }
        Set<String> protectedNames = Set.of("kafka", "openjdk21", "nginx",
                "mysql84-client", "mysql84-server", "postfix-mysql");
        JSONObject p = PackagePlan.planFor(List.of("postfix-mysql"), protectedNames, x -> null,
                UpdateManager::installedFamilyTwin);
        real("catalogo nuovo: il gemello NON viene sbloccato", p.getJSONArray("familyUnlocked").isEmpty()
            && !p.getJSONArray("unlockedPackages").toList().contains("mysql84-client"));
        real("catalogo nuovo: c'e' un impedimento", p.getJSONArray("blockers").length() == 1);
        String reason = p.getJSONArray("blockers").length() == 1
                ? p.getJSONArray("blockers").getJSONObject(0).getString("reason") : "";
        real("catalogo nuovo: il motivo nomina le due versioni",
            reason.contains("8.4.11_1") && reason.contains("8.4.12"));
        real("catalogo nuovo: e dice che prima va aggiornato il gemello", reason.contains("mysql84-client"));
        real("catalogo nuovo: quindi non e' eseguibile", !p.getBoolean("runnable"));
        real("catalogo nuovo: e mysql97-client resta nel piano, non si finge che sia sparito",
            find(p, "mysql97-client") != null);
    }

    /**
     * Il gemello installato ma NON protetto, con pkg che propone l'altro membro comunque
     * (MYSQL97=sempre). Qui il blocco non c'entra: e' un conflitto vero fra due membri della
     * famiglia, e si dichiara invece di sbloccare qualcosa che non e' bloccato.
     */
    static void familyRealConflict() throws Exception {
        if (System.getenv("FINTO_DB") == null) { real("FINTO_DB impostato", false); return; }
        Set<String> protectedNames = Set.of("kafka", "openjdk21", "nginx", "postfix-mysql");
        JSONObject p = PackagePlan.planFor(List.of("postfix-mysql"), protectedNames, x -> null,
                UpdateManager::installedFamilyTwin);
        real("conflitto vero: non si sblocca niente", p.getJSONArray("familyUnlocked").isEmpty());
        real("conflitto vero: c'e' un impedimento", p.getJSONArray("blockers").length() == 1);
        String reason = p.getJSONArray("blockers").length() == 1
                ? p.getJSONArray("blockers").getJSONObject(0).getString("reason") : "";
        real("conflitto vero: il motivo nomina i due pacchetti",
            reason.contains("mysql97-client") && reason.contains("mysql84-client"));
        real("conflitto vero: e dice che il blocco non c'entra", !reason.isEmpty());
        real("conflitto vero: non e' eseguibile", !p.getBoolean("runnable"));
    }

    private static int remainingCopies() throws Exception {
        try (var st = Files.list(Path.of("/var/tmp"))) {
            return (int) st.filter(x -> x.getFileName().toString().startsWith("pannello-simulazione.")).count();
        }
    }

    private static JSONArray issues(String... ranges) {
        return new JSONArray().put(new JSONObject().put("ranges", new JSONArray(List.of(ranges)))
                .put("description", "prova").put("cve", new JSONArray()).put("url", ""));
    }

    private static JSONObject find(JSONObject plan, String name) {
        JSONArray c = plan.getJSONArray("changes");
        for (int i = 0; i < c.length(); i++) if (name.equals(c.getJSONObject(i).getString("name"))) return c.getJSONObject(i);
        return null;
    }

    private static void end() {
        System.out.println(failed == 0 ? "\nTUTTO OK" : "\n" + failed + " PROVE FALLITE");
        if (failed > 0) System.exit(1);
    }

    private static void real(String name, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + name);
        if (!ok) failed++;
    }
}
