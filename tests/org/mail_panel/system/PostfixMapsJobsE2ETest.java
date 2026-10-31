package org.mail_panel.system;

import org.json.JSONArray;
import org.json.JSONObject;
import org.mail_panel.util.Shell;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * I tre lavori veri dell'updater quando un aggiornamento cambia la libreria che legge le mappe lmdb
 * di Postfix.
 *
 * Il cambio lo fa un pacchetto finto, fakeshadow: la 1.1 installa in SHADOW una copia identica di
 * /usr/local/lib/liblmdb.so.0, la 1.0 e la 1.2 no. La prova gira con LD_LIBRARY_PATH=SHADOW, quindi
 * ldd (e postmap) prendono la copia quando c'e': per il pannello la libreria dietro lmdb passa da
 * quella di lmdb0 a quella di fakeshadow, come in un cambio vero, ma il formato dei file e' lo
 * stesso e Postfix non si rompe. I demoni di Postfix non la vedono (il comando postfix ripulisce
 * l'ambiente). A Postfix si aggiungono una mappa di trasporto lmdb col suo testo (davanti a quelle
 * che c'erano) e la cache della verifica degli indirizzi in lmdb.
 *
 *   rigenerata      fakeshadow 1.0 -> 1.1, la mappa ha il testo: ognuno dei tre lavori finisce, la
 *                   mappa e' rigenerata e risponde, la cache e' cancellata, Postfix ricaricato;
 *   prevista        fakeshadow 1.1 -> 1.2 (la copia se ne va), la mappa senza testo: la scheda non
 *                   lascia partire, il lavoro lanciato lo stesso si rifiuta, niente cambia;
 *   dopo il fatto   fakeshadow 1.0 -> 1.1, la mappa senza testo: la previsione non lo puo' vedere
 *                   (la libreria era di lmdb0, che il piano non tocca), il lavoro aggiorna e poi
 *                   finisce in errore nominando la mappa;
 *   solo nel db     come «dopo il fatto», ma la mappa ha il testo e in piu' una voce aggiunta con
 *                   postmap -i: il lavoro la confronta prima, non la rigenera (perderebbe la voce),
 *                   e finisce in errore nominandola; e con fakeshadow 1.1 -> 1.2 la scheda non
 *                   lascia partire.
 *
 * Durante la prova FreeBSD-ports e FreeBSD-ports-kmods sono spenti, e prima di ogni lavoro si
 * controlla che il piano tocchi solo fakeshadow. Alla fine la macchina e' com'era, e lo si
 * controlla. Tocca il sistema: si accende solo con -De2e.vm=yes, da root, su FreeBSD.
 *
 *   env LD_LIBRARY_PATH=/usr/local/lib/e2e-maps-shadow java -De2e.vm=yes \
 *       -cp "tests:&lt;dir&gt;/freebsd-mail-panel-1.0.jar" org.mail_panel.system.PostfixMapsJobsE2ETest
 */
public class PostfixMapsJobsE2ETest {

    private static int failures = 0;

    static final String SHADOW = "/usr/local/lib/e2e-maps-shadow";
    static final String REPO = "mapsjobs";
    static final String REPO_CONF = "/usr/local/etc/pkg/repos/zzz-mapsjobs.conf";
    static final Path WORK = Path.of("/var/tmp/maps-jobs-e2e");
    static final String FAKE = "fakeshadow";
    static final String SOURCE = "/usr/local/etc/postfix/e2e-jobs-transport";
    static final String CACHE = "/var/db/postfix/e2e-jobs-verify";
    static final String ANSWER = "smtp:[127.0.0.1]:2526";
    static final String EXTRA = "smtp:[127.0.0.1]:2528";
    static boolean createdReposDir;

    public static void main(String[] args) throws Exception {
        if (!"yes".equals(System.getProperty("e2e.vm"))
                || !sh("uname -s").trim().equals("FreeBSD") || !sh("id -u").trim().equals("0")
                || !sh("postconf -m").contains("lmdb")) {
            System.out.println("SALTATA: serve -De2e.vm=yes, da root, su FreeBSD con Postfix che sa leggere lmdb");
            return;
        }
        if (!SHADOW.equals(System.getenv("LD_LIBRARY_PATH"))) {
            System.out.println("SALTATA: va lanciata con LD_LIBRARY_PATH=" + SHADOW + " (vedi l'intestazione)");
            return;
        }
        String packagesBefore = sh("pkg query %n-%v | sort | sha256");
        Set<String> lockedBefore = locked();
        String transportSet = sh("postconf -n transport_maps").trim();
        String verifySet = sh("postconf -n address_verify_map").trim();
        String transportOld = sh("postconf -h transport_maps").trim();
        String lmdbBefore = PostfixMaps.librarySignature().get("lmdb");
        removeFake();
        try {
            build();
            if (!Files.isDirectory(Path.of(REPO_CONF).getParent())) {
                Files.createDirectories(Path.of(REPO_CONF).getParent());
                createdReposDir = true;
            }
            sh("postconf -e 'transport_maps = lmdb:" + SOURCE + (transportOld.isEmpty() ? "" : ", " + transportOld) + "'");
            sh("postconf -e 'address_verify_map = lmdb:" + CACHE + "'");
            sh("postfix reload");
            for (String flow : new String[]{"guided", "unprotected", "maintenance"}) rebuilt(flow);
            for (String flow : new String[]{"guided", "unprotected", "maintenance"}) predicted(flow);
            for (String flow : new String[]{"guided", "unprotected", "maintenance"}) afterTheFact(flow);
            for (String flow : new String[]{"guided", "unprotected", "maintenance"}) onlyInDatabase(flow);
            onlyInDatabasePredicted();
        } finally {
            removeFake();
            sh("rm -f " + REPO_CONF + "; rm -rf /var/db/pkg/repos/" + REPO + "; rm -f /var/cache/pkg/" + FAKE + "*; rm -rf " + WORK);
            if (createdReposDir) sh("rmdir " + Path.of(REPO_CONF).getParent());
            sh("rmdir " + SHADOW + " 2>/dev/null");
            if (transportSet.isEmpty()) sh("postconf -X transport_maps"); else sh("postconf -e '" + transportSet + "'");
            if (verifySet.isEmpty()) sh("postconf -X address_verify_map"); else sh("postconf -e '" + verifySet + "'");
            sh("rm -f " + SOURCE + " " + SOURCE + ".lmdb " + CACHE + ".lmdb " + CACHE + ".lmdb-lock");
            sh("postfix reload");
            UpdateManager.refreshLockTrace();
            check("alla fine: gli stessi pacchetti di prima, alle stesse versioni",
                    sh("pkg query %n-%v | sort | sha256").equals(packagesBefore));
            check("alla fine: gli stessi pacchetti protetti di prima", locked().equals(lockedBefore));
            check("alla fine: FreeBSD-ports di nuovo acceso",
                    sh("pkg -vv 2>/dev/null | grep -A3 '^  FreeBSD-ports: {' | grep -c 'enabled *: yes'").trim().equals("1"));
            check("alla fine: la libreria di lmdb e' di nuovo quella di prima, e la copia non c'e' piu'",
                    String.valueOf(PostfixMaps.librarySignature().get("lmdb")).equals(lmdbBefore) && !Files.exists(Path.of(SHADOW)));
            check("alla fine: transport_maps e address_verify_map come prima",
                    sh("postconf -n transport_maps").trim().equals(transportSet) && sh("postconf -n address_verify_map").trim().equals(verifySet));
            check("alla fine: Postfix gira", sh("postfix status; echo $?").trim().endsWith("0"));
        }
        System.out.println(failures == 0 ? "\nTUTTO OK" : "\n" + failures + " PROVE FALLITE");
        if (failures > 0) System.exit(1);
    }

    /* ===================================================================
     * I tre casi
     * =================================================================== */

    static void rebuilt(String flow) throws Exception {
        System.out.println("\n  --- " + flow + ": la libreria di lmdb cambia, la mappa ha il suo testo ---");
        setUp(flow, "v10", "1.0", "repo11");
        maps(true);
        String label = flow + " rigenerata: ";
        check(label + "prima del lavoro lmdb e' letto dalla libreria di lmdb0",
                String.valueOf(PostfixMaps.librarySignature().get("lmdb")).contains("(lmdb0)"));
        int reloads = reloads();
        JSONObject r = runFlow(flow);
        if (r == null) return;
        String log = r.optString("consoleLog");
        check(label + "il lavoro finisce (" + r.optString("status") + ")", "completed".equals(r.optString("status")));
        check(label + "fakeshadow 1.1, e lmdb adesso e' letto dalla sua copia",
                sh("pkg query %v " + FAKE).trim().equals("1.1")
                        && String.valueOf(PostfixMaps.librarySignature().get("lmdb")).contains(SHADOW + "/liblmdb.so.0(" + FAKE + ")"));
        check(label + "il registro del lavoro dice la mappa rigenerata, con la chiave provata, e la cache",
                log.contains("lmdb:" + SOURCE) && log.contains("«example.invalid»") && log.contains("lmdb:" + CACHE));
        check(label + "la mappa risponde", lookup().equals(ANSWER));
        check(label + "la cache e' cancellata", !Files.exists(Path.of(CACHE + ".lmdb")));
        check(label + "Postfix ricaricato (maillog) e acceso", reloads() > reloads && sh("postfix status; echo $?").trim().endsWith("0"));
        check(label + "fakeshadow di nuovo protetto come prima", flow.equals("unprotected") || locked().contains(FAKE));
    }

    static void predicted(String flow) throws Exception {
        System.out.println("\n  --- " + flow + ": il piano toglie la copia di liblmdb, la mappa non ha il testo ---");
        setUp(flow, "repo11", "1.1", "repo12");
        maps(false);
        String label = flow + " prevista: ";
        check(label + "prima: lmdb e' letto dalla copia di fakeshadow",
                String.valueOf(PostfixMaps.librarySignature().get("lmdb")).contains("(" + FAKE + ")"));
        String before = sh("pkg query %n-%v | sort");
        JSONObject pv = preview(flow);
        JSONObject plan = pv.optJSONObject("plan");
        check(label + "il piano e' fakeshadow 1.1 -> 1.2", plan != null && plan.optJSONArray("changes") != null
                && plan.getJSONArray("changes").length() == 1
                && plan.getJSONArray("changes").getJSONObject(0).optString("name").equals(FAKE));
        String reason;
        if (flow.equals("guided")) {
            String m = "";
            JSONArray ck = pv.optJSONArray("checks");
            for (int i = 0; ck != null && i < ck.length(); i++)
                if ("plan-maps".equals(ck.getJSONObject(i).optString("id")) && "block".equals(ck.getJSONObject(i).optString("level")))
                    m = ck.getJSONObject(i).toString();
            reason = m;
            check(label + "la scheda non lascia partire", !pv.optBoolean("canProceed"));
        } else {
            reason = pv.optString("blockedReason");
        }
        System.out.println("     motivo: " + reason);
        check(label + "e il motivo nomina la mappa senza testo", reason.contains(SOURCE));
        JSONObject start = switch (flow) {
            case "guided" -> UpdateManager.startGuidedUpdate(FAKE, pv.optString("signature"), Set.of());
            case "unprotected" -> UpdateManager.startUnlockedPackagesUpdate(pv.optString("signature"), Set.of());
            default -> UpdateManager.startMaintenance(pv.optString("signature"), Set.of());
        };
        String id = start.optString("jobId");
        long deadline = System.currentTimeMillis() + 600_000;
        while (!id.isEmpty() && PackageQueue.holder() != null && System.currentTimeMillis() < deadline) Thread.sleep(1000);
        JSONObject job = id.isEmpty() ? new JSONObject() : UpdateManager.jobStatus(id).getJSONObject("job");
        System.out.println("     esito: " + (id.isEmpty() ? start.toString() : job.optString("status") + " " + job.optString("errorMessage")));
        check(label + "il lavoro lanciato lo stesso si rifiuta", id.isEmpty() || "error".equals(job.optString("status")));
        check(label + "nessun pacchetto cambiato", sh("pkg query %n-%v | sort").equals(before));
        check(label + "la mappa che c'era risponde ancora", lookup().equals(ANSWER));
    }

    static void afterTheFact(String flow) throws Exception {
        System.out.println("\n  --- " + flow + ": la libreria cambia senza che il piano lo dica, la mappa non ha il testo ---");
        setUp(flow, "v10", "1.0", "repo11");
        maps(false);
        JSONObject r = runFlow(flow);
        if (r == null) return;
        String label = flow + " dopo il fatto: ";
        check(label + "l'aggiornamento c'e' stato (fakeshadow 1.1)", sh("pkg query %v " + FAKE).trim().equals("1.1"));
        check(label + "il lavoro finisce in errore (" + r.optString("status") + ")", "error".equals(r.optString("status")));
        check(label + "e l'errore nomina la mappa senza testo", r.optString("errorMessage").contains(SOURCE));
        check(label + "Postfix gira", sh("postfix status; echo $?").trim().endsWith("0"));
        check(label + "fakeshadow di nuovo protetto come prima", flow.equals("unprotected") || locked().contains(FAKE));
    }

    /** La mappa ha il testo, ma anche una voce che il testo non ha: rigenerarla la perderebbe. */
    static void onlyInDatabase(String flow) throws Exception {
        System.out.println("\n  --- " + flow + ": la libreria cambia, la mappa ha una voce aggiunta con postmap -i ---");
        setUp(flow, "v10", "1.0", "repo11");
        maps(true);
        sh("echo 'extra.invalid " + EXTRA + "' | postmap -i lmdb:" + SOURCE);
        String label = flow + " solo nel db: ";
        check(label + "prima del lavoro la voce aggiunta risponde", lookup("extra.invalid").equals(EXTRA));
        JSONObject r = runFlow(flow);
        if (r == null) return;
        check(label + "l'aggiornamento c'e' stato (fakeshadow 1.1)", sh("pkg query %v " + FAKE).trim().equals("1.1"));
        check(label + "il lavoro finisce in errore (" + r.optString("status") + ")", "error".equals(r.optString("status")));
        check(label + "e l'errore nomina la mappa", r.optString("errorMessage").contains(SOURCE));
        check(label + "la mappa non e' stata rigenerata: la voce aggiunta risponde ancora", lookup("extra.invalid").equals(EXTRA));
        check(label + "Postfix gira", sh("postfix status; echo $?").trim().endsWith("0"));
    }

    static void onlyInDatabasePredicted() throws Exception {
        System.out.println("\n  --- guided: il piano toglie la copia di liblmdb, la mappa ha una voce aggiunta con postmap -i ---");
        setUp("guided", "repo11", "1.1", "repo12");
        maps(true);
        sh("echo 'extra.invalid " + EXTRA + "' | postmap -i lmdb:" + SOURCE);
        String before = sh("pkg query %n-%v | sort");
        JSONObject pv = preview("guided");
        String m = "";
        JSONArray ck = pv.optJSONArray("checks");
        for (int i = 0; ck != null && i < ck.length(); i++)
            if ("plan-maps".equals(ck.getJSONObject(i).optString("id")) && "block".equals(ck.getJSONObject(i).optString("level")))
                m = ck.getJSONObject(i).optString("detail");
        System.out.println("     motivo: " + m);
        check("solo nel db, prevista: la scheda non lascia partire", !pv.optBoolean("canProceed"));
        check("solo nel db, prevista: e il motivo nomina la mappa", m.contains(SOURCE));
        JSONObject start = UpdateManager.startGuidedUpdate(FAKE, pv.optString("signature"), Set.of());
        String id = start.optString("jobId");
        long deadline = System.currentTimeMillis() + 600_000;
        while (!id.isEmpty() && PackageQueue.holder() != null && System.currentTimeMillis() < deadline) Thread.sleep(1000);
        JSONObject job = id.isEmpty() ? new JSONObject() : UpdateManager.jobStatus(id).getJSONObject("job");
        check("solo nel db, prevista: il lavoro lanciato lo stesso si rifiuta", id.isEmpty() || "error".equals(job.optString("status")));
        check("solo nel db, prevista: nessun pacchetto cambiato", sh("pkg query %n-%v | sort").equals(before));
        check("solo nel db, prevista: la voce aggiunta risponde ancora", lookup("extra.invalid").equals(EXTRA));
    }

    /* ===================================================================
     * Il banco
     * =================================================================== */

    /** fakeshadow alla versione data, dal file del catalogo dato, e il catalogo di prova acceso su repo. */
    static void setUp(String flow, String fromDir, String version, String repo) {
        removeFake();
        sh("rm -f /var/cache/pkg/" + FAKE + "*");
        sh("pkg add " + WORK + "/" + fromDir + "/" + FAKE + "-" + version + ".pkg 2>&1");
        if (!flow.equals("unprotected")) sh("pkg lock -y " + FAKE);
        try {
            Files.writeString(Path.of(REPO_CONF), "FreeBSD-ports: { enabled: no }\nFreeBSD-ports-kmods: { enabled: no }\n"
                    + REPO + ": { url: \"file://" + WORK + "/" + repo + "\", signature_type: \"none\", enabled: yes }\n");
        } catch (Exception e) { throw new IllegalStateException(e); }
        sh("pkg update -f -r " + REPO + " 2>&1");
    }

    /** La mappa della prova costruita dal suo testo (che poi resta o se ne va), e una cache da cancellare. */
    static void maps(boolean keepText) throws Exception {
        Files.writeString(Path.of(SOURCE), "# prova dei lavori\nexample.invalid " + ANSWER + "\n");
        sh("postmap lmdb:" + SOURCE);
        if (!keepText) Files.delete(Path.of(SOURCE));
        Files.writeString(Path.of(CACHE + ".lmdb"), "cache della prova");
        sh("postfix reload");
    }

    static JSONObject preview(String flow) {
        return switch (flow) {
            case "guided" -> UpdateManager.packagePreflight(FAKE, Set.of());
            case "unprotected" -> UpdateManager.updatesStatus(Set.of());
            default -> UpdateManager.maintenancePreview(Set.of());
        };
    }

    /** Il lavoro intero, come da pagina: anteprima, controllo del piano, via, attesa. null se non e' partito. */
    static JSONObject runFlow(String flow) throws Exception {
        JSONObject pv = preview(flow);
        JSONObject plan = pv.optJSONObject("plan");
        Set<String> inPlan = new TreeSet<>();
        JSONArray ch = plan == null ? null : plan.optJSONArray("changes");
        for (int i = 0; ch != null && i < ch.length(); i++) inPlan.add(ch.getJSONObject(i).optString("name"));
        if (!inPlan.equals(Set.of(FAKE))) {
            check(flow + ": il piano tocca solo fakeshadow (trovato " + inPlan + ")", false);
            return null;
        }
        if (flow.equals("guided") && !pv.optBoolean("canProceed")) {
            check(flow + ": la scheda lascia partire", false);
            System.out.println("     " + pv.optJSONArray("checks"));
            return null;
        }
        String signature = pv.optString("signature");
        JSONObject start = switch (flow) {
            case "guided" -> UpdateManager.startGuidedUpdate(FAKE, signature, Set.of());
            case "unprotected" -> UpdateManager.startUnlockedPackagesUpdate(signature, Set.of());
            default -> UpdateManager.startMaintenance(signature, Set.of());
        };
        String id = start.optString("jobId");
        if (id.isEmpty()) { check(flow + ": il lavoro parte (" + start + ")", false); return null; }
        long deadline = System.currentTimeMillis() + 600_000;
        while (PackageQueue.holder() != null && System.currentTimeMillis() < deadline) Thread.sleep(1000);
        JSONObject job = UpdateManager.jobStatus(id).getJSONObject("job");
        System.out.println("     esito: " + job.optString("status")
                + (job.optString("errorMessage").isEmpty() ? "" : "\n     errore: " + job.optString("errorMessage")));
        for (String l : job.optString("consoleLog").split("\n")) System.out.println("       | " + l);
        return job;
    }

    static void removeFake() {
        sh("pkg unlock -y " + FAKE + " 2>/dev/null; pkg delete -y -f " + FAKE + " 2>/dev/null");
    }

    /** Le tre versioni di fakeshadow: la 1.1 con la copia di liblmdb.so.0. */
    static void build() throws Exception {
        String script = """
                set -eu
                W=%s
                rm -rf "$W"; mkdir -p "$W/v10" "$W/repo11" "$W/repo12" "$W/stage"
                mk() {
                    ver=$1; out=$2; withLib=$3
                    root="$W/stage/$ver"; plist="$W/stage/$ver.plist"
                    rm -rf "$root"; mkdir -p "$root/usr/local/share/fakeshadow"
                    echo "fakeshadow $ver" > "$root/usr/local/share/fakeshadow/version"
                    echo /usr/local/share/fakeshadow/version > "$plist"
                    if [ "$withLib" = yes ]; then
                        mkdir -p "$root%s"; cp /usr/local/lib/liblmdb.so.0 "$root%s/liblmdb.so.0"
                        echo "%s/liblmdb.so.0" >> "$plist"
                    fi
                    printf 'name: "fakeshadow"\\nversion: "%%s"\\norigin: "test/fakeshadow"\\ncomment: "fake package for the Postfix maps test"\\nwww: "https://example.invalid/"\\nmaintainer: "test@example.invalid"\\nprefix: "/usr/local"\\ndesc: "Fake package for the Postfix maps test: do not use."\\n' "$ver" > "$W/stage/$ver.ucl"
                    pkg create -M "$W/stage/$ver.ucl" -r "$root" -p "$plist" -o "$out" >/dev/null
                }
                mk 1.0 "$W/v10" no
                mk 1.1 "$W/repo11" yes
                mk 1.2 "$W/repo12" no
                pkg repo "$W/repo11" >/dev/null
                pkg repo "$W/repo12" >/dev/null
                echo BUILT
                """.formatted(WORK, SHADOW, SHADOW, SHADOW);
        Files.createDirectories(WORK.getParent());
        Path f = Files.createTempFile("maps-jobs-build", ".sh");
        Files.writeString(f, script);
        Shell.Result r = Shell.run(Duration.ofSeconds(300), "sh", f.toString());
        Files.deleteIfExists(f);
        check("le tre versioni di fakeshadow costruite", r.success() && r.output().contains("BUILT"));
        if (!r.success()) System.out.println(r.output());
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

    static Set<String> locked() {
        Set<String> s = new TreeSet<>();
        for (String l : sh("pkg lock -l 2>/dev/null").split("\n")) {
            String t = l.trim();
            if (!t.isEmpty() && !t.endsWith(":") && !t.startsWith("No locked")) s.add(PackageReplacement.nameOf(t));
        }
        return s;
    }

    static String sh(String cmd) {
        return Shell.runShell(Duration.ofSeconds(300), cmd).output();
    }

    static void check(String name, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + name);
        if (!ok) failures++;
    }
}
