package org.mail_panel.system;

import org.json.JSONArray;
import org.json.JSONObject;
import org.mail_panel.util.Shell;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Set;
import java.util.TreeSet;

/**
 * I tre lavori veri dell'updater su una libreria che un aggiornamento sostituisce con un'altra,
 * come lmdb con lmdb0 per Postfix a fine ottobre 2026.
 *
 * Pacchetti finti, costruiti qui con librerie ELF vere (serve cc): fakelib 1.0 (libfake.so.1 e
 * /usr/local/bin/fake-tool), fakelib0 0.9 (libfake0.so.0 e lo stesso fake-tool), fakeapp 1.0 che
 * usa fakelib e 1.1 che passa a fakelib0, fakeother 1.0 che usa fakelib e non cambia. Il catalogo
 * nuovo e' servito via http da un nginx a parte: come con un repository vero, pkg vede il
 * conflitto sui file solo dopo aver scaricato, e il piano cresce della rimozione durante il lavoro.
 *
 *   innocuo        fakeapp 1.0 + fakelib: ognuno dei tre lavori toglie fakelib da solo, mette
 *                  fakelib0, fakeapp 1.1 gira, e il registro del lavoro ha le prove;
 *   altro utente   anche fakeother, che usa ancora fakelib: pkg lo toglierebbe in silenzio.
 *                  Ognuno dei tre lavori si ferma e non cambia niente; la scheda, a pacchetti
 *                  scaricati, mostra le due rimozioni, che il pannello non esegue;
 *   lanciato       lo stesso a pacchetti scaricati, col via dato comunque con la firma della
 *                  scheda: la scheda non lascia partire, il lavoro si rifiuta, fakeother resta;
 *   plugin rotto   fakeplugin usa libfake.so.1 senza dichiarare fakelib: pkg toglierebbe fakelib
 *                  e lo lascerebbe ROTTO. Il lavoro si ferma, fake-plugin gira ancora.
 *
 * Durante la prova FreeBSD-ports e FreeBSD-ports-kmods sono spenti, e prima di ogni lavoro si
 * controlla che il piano tocchi solo i pacchetti finti. Alla fine la macchina e' com'era, e lo si
 * controlla. Tocca il sistema: si accende solo con -De2e.vm=yes, da root, su FreeBSD.
 *
 *   java -De2e.vm=yes -cp "tests:&lt;dir&gt;/freebsd-mail-panel-1.0.jar" org.mail_panel.system.PackageReplacementE2ETest
 */
public class PackageReplacementE2ETest {

    private static int failures = 0;

    static final String REPO = "sost";
    static final String REPO_CONF = "/usr/local/etc/pkg/repos/zzz-sost.conf";
    static final Path WORK = Path.of("/var/tmp/sost-e2e");
    static final int PORT = 8099;
    static final Set<String> FAKES = Set.of("fakeapp", "fakelib", "fakelib0", "fakeother", "fakeplugin");
    static boolean createdReposDir;

    public static void main(String[] args) throws Exception {
        if (!"yes".equals(System.getProperty("e2e.vm"))
                || !sh("uname -s").trim().equals("FreeBSD") || !sh("id -u").trim().equals("0")) {
            System.out.println("SALTATA: serve -De2e.vm=yes, da root, su FreeBSD (tocca il sistema)");
            return;
        }
        String packagesBefore = sh("pkg query %n-%v | sort | sha256");
        String bootEnvironmentsBefore = sh("bectl list -H 2>/dev/null | cut -f1 | sort");
        Set<String> lockedBefore = locked();
        removeFakes();
        try {
            build();
            if (!Files.isDirectory(Path.of(REPO_CONF).getParent())) {
                Files.createDirectories(Path.of(REPO_CONF).getParent());
                createdReposDir = true;
            }
            Files.writeString(Path.of(REPO_CONF), "FreeBSD-ports: { enabled: no }\nFreeBSD-ports-kmods: { enabled: no }\n"
                    + REPO + ": { url: \"http://127.0.0.1:" + PORT + "/repoB\", signature_type: \"none\", enabled: yes }\n");
            sh("pkg update -f -r " + REPO + " 2>&1");
            String repos = sh("pkg -vv 2>/dev/null | sed -n '/^Repositories/,$p'");
            long enabled = repos.lines().filter(l -> l.contains("enabled") && l.contains("yes")).count();
            if (enabled != 1 || !repos.contains(REPO + ": {")) {
                check("i repository veri sono spenti per la prova (altrimenti non si parte)", false);
                System.out.println(repos);
                return;
            }
            for (String flow : new String[]{"guided", "unprotected", "maintenance"}) innocuous(flow);
            innocuousCached();
            for (String flow : new String[]{"guided", "unprotected", "maintenance"}) otherUserStops(flow);
            otherUserStartedAnyway();
            pluginBreaks();
        } finally {
            removeWayBacks(bootEnvironmentsBefore);
            removeFakes();
            sh("rm -f " + REPO_CONF + "; rm -rf /var/db/pkg/repos/" + REPO + "; rm -f /var/cache/pkg/fake*");
            if (createdReposDir) sh("rmdir " + Path.of(REPO_CONF).getParent());
            sh("[ -f " + WORK + "/nginx.pid ] && kill $(cat " + WORK + "/nginx.pid); sleep 1; rm -rf " + WORK);
            UpdateManager.refreshLockTrace();
            check("alla fine: gli stessi boot environment di prima",
                    sh("bectl list -H 2>/dev/null | cut -f1 | sort").equals(bootEnvironmentsBefore));
            check("alla fine: gli stessi pacchetti di prima, alle stesse versioni",
                    sh("pkg query %n-%v | sort | sha256").equals(packagesBefore));
            check("alla fine: gli stessi pacchetti protetti di prima", locked().equals(lockedBefore));
            check("alla fine: FreeBSD-ports di nuovo acceso",
                    sh("pkg -vv 2>/dev/null | grep -A3 '^  FreeBSD-ports: {' | grep -c 'enabled *: yes'").trim().equals("1"));
            check("alla fine: nessun nginx della prova in ascolto", sh("sockstat -4lq -P tcp -p " + PORT).trim().isEmpty());
        }
        System.out.println(failures == 0 ? "\nTUTTO OK" : "\n" + failures + " PROVE FALLITE");
        if (failures > 0) System.exit(1);
    }

    /* ===================================================================
     * I tre casi
     * =================================================================== */

    static void innocuous(String flow) throws Exception {
        System.out.println("\n  --- " + flow + ": fakelib sostituito da fakelib0, nessun altro lo usa ---");
        setUp(flow, null);
        JSONObject r = runFlow(flow);
        if (r == null) return;
        String label = flow + " innocuo: ";
        check(label + "il lavoro finisce (" + r.optString("status") + ")", "completed".equals(r.optString("status")));
        check(label + "fakeapp 1.1, fakelib0 al posto di fakelib", sh("pkg query '%n %v' fakeapp fakelib0 fakelib 2>/dev/null")
                .trim().equals("fakeapp 1.1\nfakelib0 0.9"));
        check(label + "fake-app gira con la libreria nuova", sh("/usr/local/bin/fake-app; echo $?").trim().equals("0"));
        String log = r.optString("consoleLog");
        check(label + "il registro del lavoro dice cosa ha tolto e con quali prove",
                log.contains("fakelib 1.0") && log.contains("fakelib0") && log.contains("ok  "));
        check(label + "fakeapp di nuovo protetto come prima", flow.equals("unprotected") || locked().contains("fakeapp"));
    }

    /** A pacchetti gia' scaricati la scheda vede la rimozione: innocua, la lascia partire con un avviso. */
    static void innocuousCached() throws Exception {
        System.out.println("\n  --- guided: innocuo, a pacchetti gia' scaricati ---");
        setUp("guided", null);
        sh("pkg unlock -y fakeapp; pkg upgrade -F -y fakeapp 2>&1; pkg lock -y fakeapp");
        JSONObject pf = preview("guided");
        JSONArray v = pf.optJSONObject("plan") == null ? null : pf.getJSONObject("plan").optJSONArray("replacements");
        check("scaricato: la scheda vede fakelib, innocuo",
                v != null && v.length() == 1 && v.getJSONObject(0).optString("name").equals("fakelib") && v.getJSONObject(0).optBoolean("safe"));
        String review = "";
        JSONArray ck = pf.optJSONArray("checks");
        for (int i = 0; ck != null && i < ck.length(); i++)
            if ("plan-removals".equals(ck.getJSONObject(i).optString("id"))) review = ck.getJSONObject(i).optString("level");
        check("scaricato: e lascia partire, con un avviso invece di un blocco (" + review + ")",
                pf.optBoolean("canProceed") && "review".equals(review));
        JSONObject r = runFlow("guided");
        if (r == null) return;
        check("scaricato: il lavoro finisce (" + r.optString("status") + ")", "completed".equals(r.optString("status")));
        check("scaricato: fakeapp 1.1, fakelib0 al posto di fakelib", sh("pkg query '%n %v' fakeapp fakelib0 fakelib 2>/dev/null")
                .trim().equals("fakeapp 1.1\nfakelib0 0.9"));
    }

    static void otherUserStops(String flow) throws Exception {
        System.out.println("\n  --- " + flow + ": anche fakeother usa fakelib, e pkg lo toglierebbe ---");
        setUp(flow, "fakeother");
        String before = sh("pkg query %n-%v | sort");
        JSONObject r = runFlow(flow);
        if (r == null) return;
        String label = flow + " altro utente: ";
        check(label + "il lavoro si ferma (" + r.optString("status") + ")", "error".equals(r.optString("status")));
        check(label + "e il motivo dell'arresto dice quali rimozioni il pannello non esegue", r.optString("errorMessage").contains("fakeother 1.0")
                && r.optString("errorMessage").contains("fakelib 1.0"));
        check(label + "nessun pacchetto cambiato", sh("pkg query %n-%v | sort").equals(before));
        check(label + "fake-other gira ancora", sh("/usr/local/bin/fake-other; echo $?").trim().equals("0"));
        check(label + "fakeapp di nuovo protetto come prima", flow.equals("unprotected") || locked().contains("fakeapp"));
        // A pacchetti scaricati la scheda vede le due rimozioni, e dice che non le esegue.
        JSONObject preview = preview(flow);
        JSONArray v = preview.optJSONObject("plan") == null ? null : preview.getJSONObject("plan").optJSONArray("replacements");
        Set<String> never = new TreeSet<>();
        for (int i = 0; v != null && i < v.length(); i++)
            if (!v.getJSONObject(i).optBoolean("safe"))
                never.add(v.getJSONObject(i).optString("name"));
        check(label + "la scheda mostra fakelib e fakeother, che il pannello non toglie (trovato " + never + ")",
                never.equals(Set.of("fakelib", "fakeother")));
        boolean blocked = flow.equals("guided") ? !preview.optBoolean("canProceed") : !preview.optString("blockedReason").isEmpty();
        check(label + "e non lascia partire", blocked);
    }

    /**
     * A pacchetti scaricati la scheda vede le due rimozioni e non lascia partire; il via dato lo
     * stesso, con la firma vera della scheda, come se qualcuno scavalcasse la pagina: il lavoro si
     * rifiuta. Non c'e' piu' nessuna conferma da mandare. fakeother resta e gira.
     */
    static void otherUserStartedAnyway() throws Exception {
        System.out.println("\n  --- guided: a pacchetti scaricati, il via dato lo stesso ---");
        setUp("guided", "fakeother");
        // A pacchetti scaricati, come dopo il primo tentativo; da protetto pkg non lo scaricherebbe.
        sh("pkg unlock -y fakeapp; pkg upgrade -F -y fakeapp 2>&1; pkg lock -y fakeapp");
        String before = sh("pkg query %n-%v | sort");
        JSONObject pf = preview("guided");
        check("lanciato lo stesso: la scheda non lascia partire", !pf.optBoolean("canProceed"));
        JSONObject start = UpdateManager.startGuidedUpdate("fakeapp", pf.optString("signature"));
        String id = start.optString("jobId");
        long deadline = System.currentTimeMillis() + 600_000;
        while (!id.isEmpty() && PackageQueue.holder() != null && System.currentTimeMillis() < deadline) Thread.sleep(1000);
        JSONObject job = id.isEmpty() ? new JSONObject() : UpdateManager.jobStatus(id).getJSONObject("job");
        System.out.println("     esito: " + job.optString("status") + " " + job.optString("errorMessage"));
        check("lanciato lo stesso: il lavoro si rifiuta", id.isEmpty() || "error".equals(job.optString("status")));
        check("lanciato lo stesso: nessun pacchetto cambiato", sh("pkg query %n-%v | sort").equals(before));
        check("lanciato lo stesso: fake-other gira", sh("/usr/local/bin/fake-other; echo $?").trim().equals("0"));
    }

    /** fakeplugin usa libfake.so.1 senza dichiarare fakelib: pkg lo lascerebbe rotto. */
    static void pluginBreaks() throws Exception {
        System.out.println("\n  --- guided: fakeplugin usa libfake.so.1 senza dichiararlo ---");
        setUp("guided", "fakeplugin");
        String before = sh("pkg query %n-%v | sort");
        JSONObject r = runFlow("guided");
        if (r == null) return;
        check("plugin: il lavoro si ferma (" + r.optString("status") + ")", "error".equals(r.optString("status")));
        check("plugin: nessun pacchetto cambiato", sh("pkg query %n-%v | sort").equals(before));
        check("plugin: fake-plugin gira ancora", sh("/usr/local/bin/fake-plugin; echo $?").trim().equals("0"));
        JSONObject pf = preview("guided");
        JSONArray v = pf.optJSONObject("plan") == null ? null : pf.getJSONObject("plan").optJSONArray("replacements");
        JSONObject fl = null;
        for (int i = 0; v != null && i < v.length(); i++) if (v.getJSONObject(i).optString("name").equals("fakelib")) fl = v.getJSONObject(i);
        check("plugin: la scheda dice che fakelib non si toglie, perche' fakeplugin usa libfake.so.1",
                fl != null && !fl.optBoolean("safe")
                        && fl.optJSONArray("problems").toString().contains("fakeplugin")
                        && fl.optJSONArray("problems").toString().contains("libfake.so.1"));
        check("plugin: e non lascia partire", !pf.optBoolean("canProceed"));
    }

    /* ===================================================================
     * Il banco
     * =================================================================== */

    /** I pacchetti finti del catalogo di prima, installati; il catalogo nuovo, non ancora scaricato. */
    static void setUp(String flow, String extra) {
        removeFakes();
        sh("rm -f /var/cache/pkg/fake*");
        sh("pkg add " + WORK + "/repoA/fakeapp-1.0.pkg 2>&1");
        if (extra != null) sh("pkg add " + WORK + "/repoA/" + extra + "-1.0.pkg 2>&1");
        if (!flow.equals("unprotected")) sh("pkg lock -y fakeapp");
        sh("pkg update -f -r " + REPO + " 2>&1");
    }

    /** L'anteprima della scheda del lavoro. */
    static JSONObject preview(String flow) {
        return switch (flow) {
            case "guided" -> UpdateManager.packagePreflight("fakeapp");
            case "unprotected" -> UpdateManager.updatesStatus();
            default -> UpdateManager.maintenancePreview();
        };
    }

    /** Il lavoro intero, come da pagina: anteprima, controllo del piano, via, attesa. null se non e' partito. */
    static JSONObject runFlow(String flow) throws Exception {
        JSONObject pv = preview(flow);
        JSONObject plan = pv.optJSONObject("plan");
        Set<String> inPlan = new TreeSet<>();
        JSONArray ch = plan == null ? null : plan.optJSONArray("changes");
        for (int i = 0; ch != null && i < ch.length(); i++) inPlan.add(ch.getJSONObject(i).optString("name"));
        if (inPlan.isEmpty() || !FAKES.containsAll(inPlan)) {
            check(flow + ": il piano tocca solo i pacchetti finti (trovato " + inPlan + ")", false);
            return null;
        }
        if (flow.equals("guided") && !pv.optBoolean("canProceed")) {
            check(flow + ": la scheda lascia partire", false);
            System.out.println("     " + pv.optJSONArray("checks"));
            return null;
        }
        String signature = pv.optString("signature");
        JSONObject start = switch (flow) {
            case "guided" -> UpdateManager.startGuidedUpdate("fakeapp", signature);
            case "unprotected" -> UpdateManager.startUnlockedPackagesUpdate(signature);
            default -> UpdateManager.startMaintenance(signature);
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

    static void removeFakes() {
        sh("pkg unlock -y fakeapp fakeother fakeplugin fakelib fakelib0 2>/dev/null; pkg delete -y -f fakeapp fakeother fakeplugin fakelib fakelib0 2>/dev/null");
    }

    /** I pacchetti con librerie ELF vere, e nginx che serve il catalogo nuovo sulla 8099. */
    static void build() throws Exception {
        String script = """
                set -eu
                W=%s
                rm -rf "$W"; mkdir -p "$W/repoA" "$W/repoB" "$W/stage" "$W/src" "$W/www"
                cd "$W/src"
                printf 'int fake_version(void) { return 1; }\\n' > lib1.c
                printf 'int fake0_version(void) { return 0; }\\n' > lib0.c
                printf 'int fake_version(void);\\nint main(void) { return fake_version() == 1 ? 0 : 1; }\\n' > app1.c
                printf 'int fake0_version(void);\\nint main(void) { return fake0_version() == 0 ? 0 : 1; }\\n' > app0.c
                cc -shared -fPIC -Wl,-soname,libfake.so.1 -o libfake.so.1 lib1.c
                cc -shared -fPIC -Wl,-soname,libfake0.so.0 -o libfake0.so.0 lib0.c
                ln -sf libfake.so.1 libfake.so; ln -sf libfake0.so.0 libfake0.so
                cc -o fake-app-1.0 app1.c -L. -lfake
                cc -o fake-app-1.1 app0.c -L. -lfake0
                cc -o fake-other app1.c -L. -lfake
                cc -o fake-plugin app1.c -L. -lfake
                mk() {
                    name=$1; ver=$2; origin=$3; out=$4; shift 4
                    root="$W/stage/$name-$ver"; rm -rf "$root"; mkdir -p "$root"
                    plist="$W/stage/$name-$ver.plist"; : > "$plist"
                    while [ "$1" != "--" ]; do
                        s=${1%%%%:*}; d=${1#*:}
                        mkdir -p "$root$(dirname "$d")"
                        if [ "$s" = text ]; then echo "$name $ver" > "$root$d"; else cp "$W/src/$s" "$root$d"; fi
                        echo "$d" >> "$plist"; shift
                    done; shift
                    deps=""; while [ $# -gt 0 ]; do
                        n=${1%%%%:*}; rest=${1#*:}; v=${rest%%%%:*}; o=${rest#*:}
                        deps="$deps \\"$n\\": { origin: \\"$o\\", version: \\"$v\\" },"; shift
                    done
                    printf 'name: "%%s"\\nversion: "%%s"\\norigin: "%%s"\\ncomment: "fake package for the replacement test"\\nwww: "https://example.invalid/"\\nmaintainer: "test@example.invalid"\\nprefix: "/usr/local"\\ndesc: "Fake package for the library replacement test: do not use."\\ndeps: { %%s }\\n' "$name" "$ver" "$origin" "$deps" > "$W/stage/$name-$ver.ucl"
                    pkg create -M "$W/stage/$name-$ver.ucl" -r "$root" -p "$plist" -o "$out" >/dev/null
                }
                for R in repoA repoB; do
                    mk fakelib 1.0 test/fakelib "$W/$R" text:/usr/local/bin/fake-tool libfake.so.1:/usr/local/lib/libfake.so.1 --
                    mk fakeother 1.0 test/fakeother "$W/$R" fake-other:/usr/local/bin/fake-other -- fakelib:1.0:test/fakelib
                    mk fakeplugin 1.0 test/fakeplugin "$W/$R" fake-plugin:/usr/local/bin/fake-plugin --
                done
                mk fakeapp 1.0 test/fakeapp "$W/repoA" fake-app-1.0:/usr/local/bin/fake-app -- fakelib:1.0:test/fakelib
                mk fakelib0 0.9 test/fakelib0 "$W/repoB" text:/usr/local/bin/fake-tool libfake0.so.0:/usr/local/lib/libfake0.so.0 --
                mk fakeapp 1.1 test/fakeapp "$W/repoB" fake-app-1.1:/usr/local/bin/fake-app -- fakelib0:0.9:test/fakelib0
                pkg repo "$W/repoA" >/dev/null
                pkg repo "$W/repoB" >/dev/null
                cp -R "$W/repoB" "$W/www/repoB"; chmod -R a+rX "$W"
                printf 'pid %%s/nginx.pid;\\nerror_log %%s/nginx-error.log;\\nevents { worker_connections 64; }\\nhttp { access_log off; server { listen 127.0.0.1:%d; root %%s/www; } }\\n' "$W" "$W" "$W" > "$W/nginx.conf"
                nginx -c "$W/nginx.conf"
                echo BUILT
                """.formatted(WORK, PORT);
        Files.createDirectories(WORK.getParent());
        Path f = Files.createTempFile("sost-build", ".sh");
        Files.writeString(f, script);
        Shell.Result r = Shell.run(Duration.ofSeconds(300), "sh", f.toString());
        Files.deleteIfExists(f);
        check("pacchetti finti costruiti e catalogo nuovo servito via http", r.success() && r.output().contains("BUILT"));
        if (!r.success()) System.out.println(r.output());
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

    /**
     * I boot environment che i lavori della prova hanno creato prima di toccare i pacchetti
     * (PackageWayBack, dal 06/11/2026): si tolgono, come si rimette tutto il resto.
     */
    private static void removeWayBacks(String before) {
        for (String n : sh("bectl list -H 2>/dev/null | cut -f1").split("\n"))
            if (n.trim().startsWith(PackageWayBack.PREFIX) && !before.contains(n.trim())) PackageWayBack.destroy(n.trim());
    }
}
