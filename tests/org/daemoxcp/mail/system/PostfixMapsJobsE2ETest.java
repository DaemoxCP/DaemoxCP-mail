package org.daemoxcp.mail.system;

import org.json.JSONArray;
import org.json.JSONObject;
import org.daemoxcp.mail.i18n.I18n;
import org.daemoxcp.mail.util.Shell;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * The updater's three real jobs when an update changes the library that reads Postfix's lmdb maps.
 *
 * The change is made by a fake package, fakeshadow: 1.1 installs in SHADOW an identical copy of
 * /usr/local/lib/liblmdb.so.0, 1.0 and 1.2 do not. The test runs with LD_LIBRARY_PATH=SHADOW, so ldd
 * (and postmap) take the copy when it is there: for the panel the library behind lmdb moves from
 * lmdb0's to fakeshadow's, as in a real change, but the file format is the same and Postfix does
 * not break. Postfix's daemons do not see it (the postfix command cleans the environment). An lmdb
 * transport map with its text (in front of the ones that were there) and the address verification
 * cache in lmdb are added to Postfix.
 *
 *   regenerated     fakeshadow 1.0 -> 1.1, the map has its text: each of the three jobs ends, the
 *                   map is regenerated and answers, the cache is deleted, Postfix reloaded;
 *   no text         the same, but the map has no text: the job reads its content before pkg
 *                   upgrade, rebuilds it from there, and ends;
 *   only in the db  the same, but the map has its text plus an entry added with postmap -i: rebuilt
 *                   from the old content, the entry is still there, the text stays as it was.
 *
 * Then with the memory ceiling lowered (PostfixMaps.maxSavedBytes), so that the content cannot be
 * kept aside:
 *   predicted       fakeshadow 1.1 -> 1.2 (the copy goes away), the map without text: the card does
 *                   not let it start, the job started anyway refuses, nothing changes;
 *   after the fact  fakeshadow 1.0 -> 1.1, the map without text: the forecast cannot see it (the
 *                   library was lmdb0's, which the plan does not touch), the job upgrades and then
 *                   ends in error naming the map;
 *   only in the db  with fakeshadow 1.1 -> 1.2 and an entry added with postmap -i: the card does not
 *                   let it start.
 *
 * During the test FreeBSD-ports and FreeBSD-ports-kmods are off, and before every job it is checked
 * that the plan touches only fakeshadow. At the end the machine is as it was, and it is checked. It
 * touches the system: it runs only with -De2e.vm=yes, as root, on FreeBSD.
 *
 *   env LD_LIBRARY_PATH=/usr/local/lib/e2e-maps-shadow java -De2e.vm=yes \
 *       -cp "tests:&lt;dir&gt;/daemoxcp-mail-1.0.jar" org.daemoxcp.mail.system.PostfixMapsJobsE2ETest
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
    static final String TEXT = "# jobs test\nexample.invalid " + ANSWER + "\n";
    static boolean createdReposDir;

    public static void main(String[] args) throws Exception {
        if (!"yes".equals(System.getProperty("e2e.vm"))
                || !sh("uname -s").trim().equals("FreeBSD") || !sh("id -u").trim().equals("0")
                || !sh("postconf -m").contains("lmdb")) {
            System.out.println("SKIPPED: it needs -De2e.vm=yes, as root, on FreeBSD with a Postfix that can read lmdb");
            return;
        }
        if (!SHADOW.equals(System.getenv("LD_LIBRARY_PATH"))) {
            System.out.println("SKIPPED: it must be run with LD_LIBRARY_PATH=" + SHADOW + " (see the header)");
            return;
        }
        String packagesBefore = sh("pkg query %n-%v | sort | sha256");
        String bootEnvironmentsBefore = sh("bectl list -H 2>/dev/null | cut -f1 | sort");
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
            for (String flow : new String[]{"guided", "unprotected", "maintenance"}) fromSaved(flow, false);
            for (String flow : new String[]{"guided", "unprotected", "maintenance"}) fromSaved(flow, true);
            long budget = PostfixMaps.maxSavedBytes;
            PostfixMaps.maxSavedBytes = 1;
            try {
                for (String flow : new String[]{"guided", "unprotected", "maintenance"}) predicted(flow);
                for (String flow : new String[]{"guided", "unprotected", "maintenance"}) afterTheFact(flow);
                onlyInDatabasePredicted();
            } finally {
                PostfixMaps.maxSavedBytes = budget;
            }
        } finally {
            removeFake();
            removeWayBacks(bootEnvironmentsBefore);
            sh("rm -f " + REPO_CONF + "; rm -rf /var/db/pkg/repos/" + REPO + "; rm -f /var/cache/pkg/" + FAKE + "*; rm -rf " + WORK);
            if (createdReposDir) sh("rmdir " + Path.of(REPO_CONF).getParent());
            sh("rmdir " + SHADOW + " 2>/dev/null");
            if (transportSet.isEmpty()) sh("postconf -X transport_maps"); else sh("postconf -e '" + transportSet + "'");
            if (verifySet.isEmpty()) sh("postconf -X address_verify_map"); else sh("postconf -e '" + verifySet + "'");
            sh("rm -f " + SOURCE + " " + SOURCE + ".lmdb " + CACHE + ".lmdb " + CACHE + ".lmdb-lock");
            sh("postfix reload");
            UpdateManager.refreshLockTrace();
            check("at the end: the same boot environments as before",
                    sh("bectl list -H 2>/dev/null | cut -f1 | sort").equals(bootEnvironmentsBefore));
            check("at the end: the same packages as before, at the same versions",
                    sh("pkg query %n-%v | sort | sha256").equals(packagesBefore));
            check("at the end: the same protected packages as before", locked().equals(lockedBefore));
            check("at the end: FreeBSD-ports on again",
                    sh("pkg -vv 2>/dev/null | grep -A3 '^  FreeBSD-ports: {' | grep -c 'enabled *: yes'").trim().equals("1"));
            check("at the end: the lmdb library is the old one again, and the copy is gone",
                    String.valueOf(PostfixMaps.librarySignature().get("lmdb")).equals(lmdbBefore) && !Files.exists(Path.of(SHADOW)));
            check("at the end: transport_maps and address_verify_map as before",
                    sh("postconf -n transport_maps").trim().equals(transportSet) && sh("postconf -n address_verify_map").trim().equals(verifySet));
            check("at the end: Postfix runs", sh("postfix status; echo $?").trim().endsWith("0"));
        }
        System.out.println(failures == 0 ? "\nALL OK" : "\n" + failures + " CHECKS FAILED");
        if (failures > 0) System.exit(1);
    }

    /* ===================================================================
     * The three cases
     * =================================================================== */

    static void rebuilt(String flow) throws Exception {
        System.out.println("\n  --- " + flow + ": the lmdb library changes, the map has its text ---");
        setUp(flow, "v10", "1.0", "repo11");
        maps(true);
        String label = flow + " regenerated: ";
        check(label + "before the job lmdb is read by lmdb0's library",
                String.valueOf(PostfixMaps.librarySignature().get("lmdb")).contains("(lmdb0)"));
        int reloads = reloads();
        JSONObject r = runFlow(flow);
        if (r == null) return;
        String log = r.optString("consoleLog");
        check(label + "the job ends (" + r.optString("status") + ")", "completed".equals(r.optString("status")));
        check(label + "fakeshadow 1.1, and lmdb is now read from its copy",
                sh("pkg query %v " + FAKE).trim().equals("1.1")
                        && String.valueOf(PostfixMaps.librarySignature().get("lmdb")).contains(SHADOW + "/liblmdb.so.0(" + FAKE + ")"));
        check(label + "the job's log names the regenerated map, with the key tried, and the cache",
                log.contains("lmdb:" + SOURCE) && log.contains("«example.invalid»") && log.contains("lmdb:" + CACHE));
        check(label + "the map answers", lookup().equals(ANSWER));
        check(label + "the cache is deleted", !Files.exists(Path.of(CACHE + ".lmdb")));
        check(label + "Postfix reloaded (maillog) and running", reloads() > reloads && sh("postfix status; echo $?").trim().endsWith("0"));
        check(label + "fakeshadow protected again as before", flow.equals("unprotected") || locked().contains(FAKE));
    }

    static void predicted(String flow) throws Exception {
        System.out.println("\n  --- " + flow + ": the plan removes the liblmdb copy, the map has no text, and it does not fit in memory ---");
        setUp(flow, "repo11", "1.1", "repo12");
        maps(false);
        String label = flow + " predicted: ";
        check(label + "before: lmdb is read by fakeshadow's copy",
                String.valueOf(PostfixMaps.librarySignature().get("lmdb")).contains("(" + FAKE + ")"));
        String before = sh("pkg query %n-%v | sort");
        JSONObject pv = preview(flow);
        JSONObject plan = pv.optJSONObject("plan");
        check(label + "the plan is fakeshadow 1.1 -> 1.2", plan != null && plan.optJSONArray("changes") != null
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
            check(label + "the card does not let it start", !pv.optBoolean("canProceed"));
        } else {
            reason = pv.optString("blockedReason");
        }
        System.out.println("     reason: " + reason);
        check(label + "and the reason names the map without text", reason.contains(SOURCE));
        JSONObject start = switch (flow) {
            case "guided" -> UpdateManager.startGuidedUpdate(FAKE, pv.optString("signature"));
            case "unprotected" -> UpdateManager.startUnlockedPackagesUpdate(pv.optString("signature"));
            default -> UpdateManager.startMaintenance(pv.optString("signature"));
        };
        String id = start.optString("jobId");
        long deadline = System.currentTimeMillis() + 600_000;
        while (!id.isEmpty() && PackageQueue.holder() != null && System.currentTimeMillis() < deadline) Thread.sleep(1000);
        JSONObject job = id.isEmpty() ? new JSONObject() : UpdateManager.jobStatus(id).getJSONObject("job");
        System.out.println("     outcome: " + (id.isEmpty() ? start.toString() : job.optString("status") + " " + job.optString("errorMessage")));
        check(label + "the job started anyway refuses", id.isEmpty() || "error".equals(job.optString("status")));
        check(label + "no package changed", sh("pkg query %n-%v | sort").equals(before));
        check(label + "the map that was there still answers", lookup().equals(ANSWER));
    }

    static void afterTheFact(String flow) throws Exception {
        System.out.println("\n  --- " + flow + ": the library changes without the plan saying so, the map has no text, and it does not fit in memory ---");
        setUp(flow, "v10", "1.0", "repo11");
        maps(false);
        JSONObject r = runFlow(flow);
        if (r == null) return;
        String label = flow + " after the fact: ";
        check(label + "the upgrade happened (fakeshadow 1.1)", sh("pkg query %v " + FAKE).trim().equals("1.1"));
        check(label + "the job ends in error (" + r.optString("status") + ")", "error".equals(r.optString("status")));
        check(label + "and the error names the map without text", r.optString("errorMessage").contains(SOURCE));
        check(label + "Postfix runs", sh("postfix status; echo $?").trim().endsWith("0"));
        check(label + "fakeshadow protected again as before", flow.equals("unprotected") || locked().contains(FAKE));
    }

    /**
     * The map without text (withExtra false), or with the text and an entry the text does not have
     * (true): the job reads its content before pkg upgrade and rebuilds it from there.
     */
    static void fromSaved(String flow, boolean withExtra) throws Exception {
        System.out.println("\n  --- " + flow + ": the library changes, " + (withExtra
                ? "the map has an entry added with postmap -i ---" : "the map has no text ---"));
        setUp(flow, "v10", "1.0", "repo11");
        maps(withExtra);
        if (withExtra) sh("echo 'extra.invalid " + EXTRA + "' | postmap -i lmdb:" + SOURCE);
        String label = flow + (withExtra ? " only in the db: " : " no text: ");
        String table = "lmdb:" + SOURCE + " (transport_maps)";
        if (withExtra) check(label + "before the job the added entry answers", lookup("extra.invalid").equals(EXTRA));
        JSONObject r = runFlow(flow);
        if (r == null) return;
        String log = r.optString("consoleLog");
        check(label + "the job ends (" + r.optString("status") + ")", "completed".equals(r.optString("status")));
        check(label + "the upgrade happened (fakeshadow 1.1)", sh("pkg query %v " + FAKE).trim().equals("1.1"));
        check(label + "the log says it rebuilt it from the old content, with its entries",
                log.contains(I18n.tr("server.maps.rebuiltFromSaved", Map.of("table", table, "n", withExtra ? "2" : "1"))));
        check(label + "the map answers" + (withExtra ? ", the added entry too" : ""),
                lookup().equals(ANSWER) && (!withExtra || lookup("extra.invalid").equals(EXTRA)));
        check(label + "the text is as it was" + (withExtra ? "" : " (that is, not there)"),
                withExtra ? Files.readString(Path.of(SOURCE)).equals(TEXT) : !Files.exists(Path.of(SOURCE)));
        check(label + "the cache is deleted", !Files.exists(Path.of(CACHE + ".lmdb")));
        check(label + "Postfix gira", sh("postfix status; echo $?").trim().endsWith("0"));
        check(label + "fakeshadow protected again as before", flow.equals("unprotected") || locked().contains(FAKE));
    }

    static void onlyInDatabasePredicted() throws Exception {
        System.out.println("\n  --- guided: the plan removes the liblmdb copy, the map has an entry added with postmap -i, and it does not fit in memory ---");
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
        System.out.println("     reason: " + m);
        check("only in the db, predicted: the card does not let it start", !pv.optBoolean("canProceed"));
        check("only in the db, predicted: and the reason names the map", m.contains(SOURCE));
        JSONObject start = UpdateManager.startGuidedUpdate(FAKE, pv.optString("signature"));
        String id = start.optString("jobId");
        long deadline = System.currentTimeMillis() + 600_000;
        while (!id.isEmpty() && PackageQueue.holder() != null && System.currentTimeMillis() < deadline) Thread.sleep(1000);
        JSONObject job = id.isEmpty() ? new JSONObject() : UpdateManager.jobStatus(id).getJSONObject("job");
        check("only in the db, predicted: the job started anyway refuses", id.isEmpty() || "error".equals(job.optString("status")));
        check("only in the db, predicted: no package changed", sh("pkg query %n-%v | sort").equals(before));
        check("only in the db, predicted: the added entry still answers", lookup("extra.invalid").equals(EXTRA));
    }

    /* ===================================================================
     * The bench
     * =================================================================== */

    /** fakeshadow at the given version, from the given catalog file, and the test catalog on repo. */
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

    /** The test map built from its text (which then stays or goes), and a cache to delete. */
    static void maps(boolean keepText) throws Exception {
        Files.writeString(Path.of(SOURCE), TEXT);
        sh("postmap lmdb:" + SOURCE);
        if (!keepText) Files.delete(Path.of(SOURCE));
        Files.writeString(Path.of(CACHE + ".lmdb"), "test cache");
        sh("postfix reload");
    }

    static JSONObject preview(String flow) {
        return switch (flow) {
            case "guided" -> UpdateManager.packagePreflight(FAKE);
            case "unprotected" -> UpdateManager.updatesStatus();
            default -> UpdateManager.maintenancePreview();
        };
    }

    /** The whole job, as from the page: preview, plan check, go, wait. null if it did not start. */
    static JSONObject runFlow(String flow) throws Exception {
        JSONObject pv = preview(flow);
        JSONObject plan = pv.optJSONObject("plan");
        Set<String> inPlan = new TreeSet<>();
        JSONArray ch = plan == null ? null : plan.optJSONArray("changes");
        for (int i = 0; ch != null && i < ch.length(); i++) inPlan.add(ch.getJSONObject(i).optString("name"));
        if (!inPlan.equals(Set.of(FAKE))) {
            check(flow + ": the plan touches only fakeshadow (found " + inPlan + ")", false);
            return null;
        }
        if (flow.equals("guided") && !pv.optBoolean("canProceed")) {
            check(flow + ": the card lets it start", false);
            System.out.println("     " + pv.optJSONArray("checks"));
            return null;
        }
        String signature = pv.optString("signature");
        JSONObject start = switch (flow) {
            case "guided" -> UpdateManager.startGuidedUpdate(FAKE, signature);
            case "unprotected" -> UpdateManager.startUnlockedPackagesUpdate(signature);
            default -> UpdateManager.startMaintenance(signature);
        };
        String id = start.optString("jobId");
        if (id.isEmpty()) { check(flow + ": the job starts (" + start + ")", false); return null; }
        long deadline = System.currentTimeMillis() + 600_000;
        while (PackageQueue.holder() != null && System.currentTimeMillis() < deadline) Thread.sleep(1000);
        JSONObject job = UpdateManager.jobStatus(id).getJSONObject("job");
        System.out.println("     outcome: " + job.optString("status")
                + (job.optString("errorMessage").isEmpty() ? "" : "\n     error: " + job.optString("errorMessage")));
        for (String l : job.optString("consoleLog").split("\n")) System.out.println("       | " + l);
        return job;
    }

    static void removeFake() {
        sh("pkg unlock -y " + FAKE + " 2>/dev/null; pkg delete -y -f " + FAKE + " 2>/dev/null");
    }

    /** The three versions of fakeshadow: 1.1 with the liblmdb.so.0 copy. */
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
        check("the three versions of fakeshadow built", r.success() && r.output().contains("BUILT"));
        if (!r.success()) System.out.println(r.output());
    }

    /** How many times Postfix was reloaded, according to the maillog (syslog writes with a short delay). */
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

    /**
     * The boot environments the test's jobs created before touching the packages (PackageWayBack,
     * since 06/11/2026): they are removed, as everything else is put back.
     */
    private static void removeWayBacks(String before) {
        for (String n : sh("bectl list -H 2>/dev/null | cut -f1").split("\n"))
            if (n.trim().startsWith(PackageWayBack.PREFIX) && !before.contains(n.trim())) PackageWayBack.destroy(n.trim());
    }
}
