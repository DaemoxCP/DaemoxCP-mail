package org.daemoxcp.mail.system;

import org.json.JSONArray;
import org.json.JSONObject;
import org.daemoxcp.mail.util.Shell;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Set;
import java.util.TreeSet;

/**
 * The updater's three real jobs on a library an update replaces with another, like lmdb with lmdb0
 * for Postfix in late October 2026.
 *
 * Fake packages, built here with real ELF libraries (cc is needed): fakelib 1.0 (libfake.so.1 and
 * /usr/local/bin/fake-tool), fakelib0 0.9 (libfake0.so.0 and the same fake-tool), fakeapp 1.0 that
 * uses fakelib and 1.1 that moves to fakelib0, fakeother 1.0 that uses fakelib and does not change.
 * The new catalog is served over http by a separate nginx: as with a real repository, pkg sees the
 * conflict on the files only after downloading, and the plan grows by the removal during the job.
 *
 *   harmless       fakeapp 1.0 + fakelib: each of the three jobs removes fakelib by itself, puts
 *                  in fakelib0, fakeapp 1.1 runs, and the job's log has the evidence;
 *   other user     fakeother too, which still uses fakelib. Before 2.9 pkg would remove it silently;
 *                  pkg 2.9.2 holds fakeapp back instead (measured 22/11/2026). Each of the three jobs
 *                  stops and changes nothing; the card, with the packages downloaded, says why: the two
 *                  removals the panel does not run, or what pkg holds back, what is in the way and who
 *                  still needs it;
 *   started        the same with the packages downloaded, with the go given anyway with the card's
 *                  signature: the card does not let it start, the job refuses, fakeother stays;
 *   broken plugin  fakeplugin uses libfake.so.1 without declaring fakelib: pkg would remove fakelib
 *                  and leave it BROKEN. The job stops, fake-plugin still runs.
 *
 * During the test FreeBSD-ports and FreeBSD-ports-kmods are off, and before every job it is checked
 * that the plan touches only the fake packages. At the end the machine is as it was, and it is
 * checked. It touches the system: it runs only with -De2e.vm=yes, as root, on FreeBSD.
 *
 *   java -De2e.vm=yes -cp "tests:&lt;dir&gt;/daemoxcp-mail.jar" org.daemoxcp.mail.system.PackageReplacementE2ETest
 */
public class PackageReplacementE2ETest {

    private static int failures = 0;

    static final String REPO = "replacement";
    static final String REPO_CONF = "/usr/local/etc/pkg/repos/zzz-replacement.conf";
    static final Path WORK = Path.of("/var/tmp/replacement-e2e");
    static final int PORT = 8099;
    static final Set<String> FAKES = Set.of("fakeapp", "fakelib", "fakelib0", "fakeother", "fakeplugin");
    static boolean createdReposDir;

    public static void main(String[] args) throws Exception {
        if (!"yes".equals(System.getProperty("e2e.vm"))
                || !sh("uname -s").trim().equals("FreeBSD") || !sh("id -u").trim().equals("0")) {
            System.out.println("SKIPPED: it needs -De2e.vm=yes, as root, on FreeBSD (it touches the system)");
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
                check("the real repositories are off for the test (otherwise it does not start)", false);
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
            check("at the end: the same boot environments as before",
                    sh("bectl list -H 2>/dev/null | cut -f1 | sort").equals(bootEnvironmentsBefore));
            check("at the end: the same packages as before, at the same versions",
                    sh("pkg query %n-%v | sort | sha256").equals(packagesBefore));
            check("at the end: the same protected packages as before", locked().equals(lockedBefore));
            check("at the end: FreeBSD-ports on again",
                    sh("pkg -vv 2>/dev/null | grep -A3 '^  FreeBSD-ports: {' | grep -c 'enabled *: yes'").trim().equals("1"));
            check("at the end: no test nginx listening", sh("sockstat -4lq -P tcp -p " + PORT).trim().isEmpty());
        }
        System.out.println(failures == 0 ? "\nALL OK" : "\n" + failures + " CHECKS FAILED");
        if (failures > 0) System.exit(1);
    }

    /* ===================================================================
     * The three cases
     * =================================================================== */

    static void innocuous(String flow) throws Exception {
        System.out.println("\n  --- " + flow + ": fakelib replaced by fakelib0, nobody else uses it ---");
        setUp(flow, null);
        JSONObject r = runFlow(flow);
        if (r == null) return;
        String label = flow + " harmless: ";
        check(label + "the job ends (" + r.optString("status") + ")", "completed".equals(r.optString("status")));
        check(label + "fakeapp 1.1, fakelib0 in place of fakelib", sh("pkg query '%n %v' fakeapp fakelib0 fakelib 2>/dev/null")
                .trim().equals("fakeapp 1.1\nfakelib0 0.9"));
        check(label + "fake-app runs with the new library", sh("/usr/local/bin/fake-app; echo $?").trim().equals("0"));
        String log = r.optString("consoleLog");
        check(label + "the job's log says what it removed and with what evidence",
                log.contains("fakelib 1.0") && log.contains("fakelib0") && log.contains("ok  "));
        check(label + "fakeapp protected again as before", flow.equals("unprotected") || locked().contains("fakeapp"));
    }

    /** With the packages already downloaded the card sees the removal: harmless, it lets it start with a warning. */
    static void innocuousCached() throws Exception {
        System.out.println("\n  --- guided: harmless, with the packages already downloaded ---");
        setUp("guided", null);
        sh("pkg unlock -y fakeapp; pkg upgrade -F -y fakeapp 2>&1; pkg lock -y fakeapp");
        JSONObject pf = preview("guided");
        JSONArray v = pf.optJSONObject("plan") == null ? null : pf.getJSONObject("plan").optJSONArray("replacements");
        check("downloaded: the card sees fakelib, harmless",
                v != null && v.length() == 1 && v.getJSONObject(0).optString("name").equals("fakelib") && v.getJSONObject(0).optBoolean("safe"));
        String review = "";
        JSONArray ck = pf.optJSONArray("checks");
        for (int i = 0; ck != null && i < ck.length(); i++)
            if ("plan-removals".equals(ck.getJSONObject(i).optString("id"))) review = ck.getJSONObject(i).optString("level");
        check("downloaded: and it lets it start, with a warning instead of a block (" + review + ")",
                pf.optBoolean("canProceed") && "review".equals(review));
        JSONObject r = runFlow("guided");
        if (r == null) return;
        check("downloaded: the job ends (" + r.optString("status") + ")", "completed".equals(r.optString("status")));
        check("downloaded: fakeapp 1.1, fakelib0 in place of fakelib", sh("pkg query '%n %v' fakeapp fakelib0 fakelib 2>/dev/null")
                .trim().equals("fakeapp 1.1\nfakelib0 0.9"));
    }

    static void otherUserStops(String flow) throws Exception {
        System.out.println("\n  --- " + flow + ": fakeother uses fakelib too, and pkg would remove it ---");
        setUp(flow, "fakeother");
        String before = sh("pkg query %n-%v | sort");
        JSONObject r = runFlow(flow);
        if (r == null) return;
        String label = flow + " other user: ";
        check(label + "the job stops (" + r.optString("status") + ")", "error".equals(r.optString("status")));
        check(label + "no package changed", sh("pkg query %n-%v | sort").equals(before));
        check(label + "fake-other still runs", sh("/usr/local/bin/fake-other; echo $?").trim().equals("0"));
        check(label + "fakeapp protected again as before", flow.equals("unprotected") || locked().contains("fakeapp"));
        // With the packages downloaded, what pkg does. Before 2.9 it planned to remove fakelib and fakeother too, and the
        // panel refused; pkg 2.9.2 holds fakeapp back instead and removes nothing (measured on the VM, 22/11/2026): the
        // plan is empty, and the panel must say why instead of showing nothing.
        boolean heldBack = pkgHoldsFakeappBack();
        JSONObject preview = preview(flow);
        boolean blocked = flow.equals("guided") ? !preview.optBoolean("canProceed") : !preview.optString("blockedReason").isEmpty();
        String why = r.optString("errorMessage");
        if (heldBack) {
            check(label + "pkg holds fakeapp back: the reason for the stop says so, what is in the way and who still needs it",
                    why.contains("fakeapp 1.1") && why.contains("fakelib 1.0") && why.contains("fakeother"));
            JSONArray hb = preview.optJSONObject("plan") == null ? null : preview.getJSONObject("plan").optJSONArray("heldBack");
            check(label + "the card knows pkg holds fakeapp back (" + hb + ")",
                    hb != null && hb.length() == 1 && "fakeapp".equals(hb.getJSONObject(0).optString("name")));
            String shown = flow.equals("guided") ? checkDetail(preview, "plan-held-back") : preview.optString("blockedReason");
            check(label + "and the card says why: fakelib 1.0 is still needed by fakeother",
                    shown.contains("fakelib 1.0") && shown.contains("fakeother"));
        } else {
            check(label + "and the reason for the stop says which removals the panel does not run",
                    why.contains("fakeother 1.0") && why.contains("fakelib 1.0"));
            // With the packages downloaded the card sees the two removals, and says it does not run them.
            JSONArray v = preview.optJSONObject("plan") == null ? null : preview.getJSONObject("plan").optJSONArray("replacements");
            Set<String> never = new TreeSet<>();
            for (int i = 0; v != null && i < v.length(); i++)
                if (!v.getJSONObject(i).optBoolean("safe"))
                    never.add(v.getJSONObject(i).optString("name"));
            check(label + "the card shows fakelib and fakeother, which the panel does not remove (found " + never + ")",
                    never.equals(Set.of("fakelib", "fakeother")));
        }
        check(label + "and it does not let it start", blocked);
    }

    /** pkg's own answer, with the packages downloaded: does it hold fakeapp 1.1 back (pkg 2.9) instead of removing? */
    static boolean pkgHoldsFakeappBack() {
        boolean wasLocked = locked().contains("fakeapp");
        String out = sh("pkg unlock -y fakeapp >/dev/null 2>&1; pkg upgrade -n fakeapp 2>&1");
        if (wasLocked) sh("pkg lock -y fakeapp >/dev/null 2>&1");
        System.out.println("     pkg with the packages downloaded: " + (out.contains("is held back") ? "holds fakeapp back" : "would remove"));
        return out.contains("fakeapp-1.1 is held back to solve the problem");
    }

    /** The text of one check of the guided card, "" if it is not there. */
    static String checkDetail(JSONObject preview, String id) {
        JSONArray ck = preview.optJSONArray("checks");
        for (int i = 0; ck != null && i < ck.length(); i++)
            if (id.equals(ck.getJSONObject(i).optString("id"))) return ck.getJSONObject(i).optString("detail");
        return "";
    }

    /**
     * With the packages downloaded the card sees the two removals and does not let it start; the go
     * given all the same, with the card's real signature, as if somebody bypassed the page: the job
     * refuses. There is no confirmation to send any more. fakeother stays and runs.
     */
    static void otherUserStartedAnyway() throws Exception {
        System.out.println("\n  --- guided: with the packages downloaded, the go given all the same ---");
        setUp("guided", "fakeother");
        // With the packages downloaded, as after the first try; while protected pkg would not download it.
        sh("pkg unlock -y fakeapp; pkg upgrade -F -y fakeapp 2>&1; pkg lock -y fakeapp");
        String before = sh("pkg query %n-%v | sort");
        JSONObject pf = preview("guided");
        check("started all the same: the card does not let it start", !pf.optBoolean("canProceed"));
        JSONObject start = UpdateManager.startGuidedUpdate("fakeapp", pf.optString("signature"));
        String id = start.optString("jobId");
        long deadline = System.currentTimeMillis() + 600_000;
        while (!id.isEmpty() && PackageQueue.holder() != null && System.currentTimeMillis() < deadline) Thread.sleep(1000);
        JSONObject job = id.isEmpty() ? new JSONObject() : UpdateManager.jobStatus(id).getJSONObject("job");
        System.out.println("     outcome: " + job.optString("status") + " " + job.optString("errorMessage"));
        check("started all the same: the job refuses", id.isEmpty() || "error".equals(job.optString("status")));
        check("started all the same: no package changed", sh("pkg query %n-%v | sort").equals(before));
        check("started all the same: fake-other runs", sh("/usr/local/bin/fake-other; echo $?").trim().equals("0"));
    }

    /** fakeplugin uses libfake.so.1 without declaring fakelib: pkg would leave it broken. */
    static void pluginBreaks() throws Exception {
        System.out.println("\n  --- guided: fakeplugin uses libfake.so.1 without declaring it ---");
        setUp("guided", "fakeplugin");
        String before = sh("pkg query %n-%v | sort");
        JSONObject r = runFlow("guided");
        if (r == null) return;
        check("plugin: the job stops (" + r.optString("status") + ")", "error".equals(r.optString("status")));
        check("plugin: no package changed", sh("pkg query %n-%v | sort").equals(before));
        check("plugin: fake-plugin still runs", sh("/usr/local/bin/fake-plugin; echo $?").trim().equals("0"));
        JSONObject pf = preview("guided");
        JSONArray v = pf.optJSONObject("plan") == null ? null : pf.getJSONObject("plan").optJSONArray("replacements");
        JSONObject fl = null;
        for (int i = 0; v != null && i < v.length(); i++) if (v.getJSONObject(i).optString("name").equals("fakelib")) fl = v.getJSONObject(i);
        check("plugin: the card says fakelib is not removed, because fakeplugin uses libfake.so.1",
                fl != null && !fl.optBoolean("safe")
                        && fl.optJSONArray("problems").toString().contains("fakeplugin")
                        && fl.optJSONArray("problems").toString().contains("libfake.so.1"));
        check("plugin: and it does not let it start", !pf.optBoolean("canProceed"));
    }

    /* ===================================================================
     * The bench
     * =================================================================== */

    /** The fake packages of the old catalog, installed; the new catalog, not downloaded yet. */
    static void setUp(String flow, String extra) {
        removeFakes();
        sh("rm -f /var/cache/pkg/fake*");
        sh("pkg add " + WORK + "/repoA/fakeapp-1.0.pkg 2>&1");
        if (extra != null) sh("pkg add " + WORK + "/repoA/" + extra + "-1.0.pkg 2>&1");
        if (!flow.equals("unprotected")) sh("pkg lock -y fakeapp");
        sh("pkg update -f -r " + REPO + " 2>&1");
    }

    /** The preview of the job's card. */
    static JSONObject preview(String flow) {
        return switch (flow) {
            case "guided" -> UpdateManager.packagePreflight("fakeapp");
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
        if (inPlan.isEmpty() || !FAKES.containsAll(inPlan)) {
            check(flow + ": the plan touches only the fake packages (found " + inPlan + ")", false);
            return null;
        }
        if (flow.equals("guided") && !pv.optBoolean("canProceed")) {
            check(flow + ": the card lets it start", false);
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
        if (id.isEmpty()) { check(flow + ": the job starts (" + start + ")", false); return null; }
        long deadline = System.currentTimeMillis() + 600_000;
        while (PackageQueue.holder() != null && System.currentTimeMillis() < deadline) Thread.sleep(1000);
        JSONObject job = UpdateManager.jobStatus(id).getJSONObject("job");
        System.out.println("     outcome: " + job.optString("status")
                + (job.optString("errorMessage").isEmpty() ? "" : "\n     error: " + job.optString("errorMessage")));
        for (String l : job.optString("consoleLog").split("\n")) System.out.println("       | " + l);
        return job;
    }

    static void removeFakes() {
        sh("pkg unlock -y fakeapp fakeother fakeplugin fakelib fakelib0 2>/dev/null; pkg delete -y -f fakeapp fakeother fakeplugin fakelib fakelib0 2>/dev/null");
    }

    /** The packages with real ELF libraries, and nginx serving the new catalog on 8099. */
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
        Path f = Files.createTempFile("replacement-build", ".sh");
        Files.writeString(f, script);
        Shell.Result r = Shell.run(Duration.ofSeconds(300), "sh", f.toString());
        Files.deleteIfExists(f);
        check("fake packages built and new catalog served over http", r.success() && r.output().contains("BUILT"));
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
     * The boot environments the test's jobs created before touching the packages (PackageWayBack,
     * since 06/11/2026): they are removed, as everything else is put back.
     */
    private static void removeWayBacks(String before) {
        for (String n : sh("bectl list -H 2>/dev/null | cut -f1").split("\n"))
            if (n.trim().startsWith(PackageWayBack.PREFIX) && !before.contains(n.trim())) PackageWayBack.destroy(n.trim());
    }
}
