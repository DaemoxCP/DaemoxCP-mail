package org.mail_panel.system;

import org.json.JSONArray;
import org.json.JSONObject;
import org.mail_panel.i18n.I18n;
import org.mail_panel.util.Shell;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * The edges of the package update, with real jobs on fake packages.
 *
 * On 06/11/2026 this test only measured (reperti 146-148): where the update breaks. The owner chose
 * to fix the first four points, and now every measurement checks the right behaviour, and keeps
 * printing what happens:
 *
 *   M1  the way back: a boot environment before every job, removed if nothing changed, the oldest
 *       pruned, and the warning if mail and databases are inside it
 *   M2  the turn holds across processes: a second Java process does not take it
 *   M2b a second start of the jar while the panel updates does not touch the running job
 *   M3  an external pkg (from SSH) holding the lock: the panel's job refuses
 *   M4  the panel killed while pkg installs: at restart it locks again as soon as pkg has
 *       finished, without waiting for the next restart, and leaves the notice
 *   M5  the timeout: a pkg is not killed halfway (it warns and waits); another command stops with
 *       all its children; never an exception in place of the exit code
 *   M6  the periodic report says the packages without protection and the interrupted job
 *   M7  the machine switched off abruptly during pkg upgrade (-Dmeasure=m7, then the m7-after mode)
 *
 * It touches the system: it installs and removes fake packages, creates and removes boot
 * environments, turns off the real repositories for the duration, unlocks and locks again. Only on
 * a test machine, as root, with
 * -De2e.vm=yes:
 *   java -De2e.vm=yes -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.UpdaterRobustnessE2ETest
 * With -Dmeasure=m1,m4 only those. At the end it checks that packages, protections, repositories
 * and boot environments are those of before.
 */
public class UpdaterRobustnessE2ETest {

    static final String PKG = "nginx-robust-probe";
    static final String OTHER = "robust-probe-other";
    static final String REPO_CONF = "/usr/local/etc/pkg/repos/zzz-robust-probe.conf";
    static final Path DIR = Path.of("/var/tmp/um-probe");
    static final Path SLEEP = DIR.resolve("sleep"), STARTED = DIR.resolve("started"), DONE = DIR.resolve("done");

    private static int failures = 0;
    private static Path work;
    private static boolean createdReposDir;
    private static String noticeBefore;

    public static void main(String[] args) throws Exception {
        if (args.length > 0) { child(args); return; }
        if (!"yes".equals(System.getProperty("e2e.vm"))) {
            System.out.println("Without -De2e.vm=yes this test does nothing: it changes packages.");
            return;
        }
        if (!sh("id -u").trim().equals("0")) { System.out.println("Root is needed."); System.exit(2); }
        if ("m7".equals(System.getProperty("measure"))) { m7Before(); return; }

        String packagesBefore = sh("pkg query %n-%v | sort | sha256");
        Set<String> lockedBefore = locked();
        String bootEnvironmentsBefore = bootEnvironments();
        noticeBefore = Files.exists(PackageRecovery.notice) ? Files.readString(PackageRecovery.notice) : null;
        cleanup();
        work = Files.createTempDirectory(Path.of("/var/tmp"), "robust-probe");
        Files.createDirectories(DIR);
        try {
            setUp();
            Set<String> only = new TreeSet<>(List.of(System.getProperty("measure", "all").split(",")));
            java.util.function.Predicate<String> on = m -> only.contains("all") || only.contains(m);
            if (on.test("m1")) m1WayBack(bootEnvironmentsBefore);
            if (on.test("m2")) m2TurnAcrossProcesses();
            if (on.test("m2b")) m2bSecondStartDuringJob();
            if (on.test("m3")) m3ExternalPkgHoldsTheLock();
            if (on.test("m4")) m4PanelKilledDuringPkg();
            if (on.test("m5")) m5Timeout();
            if (on.test("m6")) m6Report();
        } finally {
            cleanup();
            sh("rm -f " + REPO_CONF + "; rm -rf /var/db/pkg/repos/robustprobe " + work + " " + DIR);
            if (createdReposDir) sh("rmdir " + Path.of(REPO_CONF).getParent());
            removeOwnBootEnvironments(bootEnvironmentsBefore);
            restoreNotice();
            UpdateManager.refreshLockTrace();
            check("at the end: the same packages as before", sh("pkg query %n-%v | sort | sha256").equals(packagesBefore));
            check("at the end: the same protected packages", locked().equals(lockedBefore));
            check("at the end: no list of an interrupted job", !PackageQueue.statePresent());
            check("at the end: FreeBSD-ports turned on again",
                    sh("pkg -vv 2>/dev/null | grep -A3 '^  FreeBSD-ports: {' | grep -c 'enabled *: yes'").trim().equals("1"));
            check("at the end: the same boot environments", bootEnvironments().equals(bootEnvironmentsBefore));
        }
        System.out.println(failures == 0 ? "\nALL OK" : "\n" + failures + " CHECKS FAILED");
        if (failures > 0) System.exit(1);
    }

    static void setUp() throws Exception {
        build(PKG, "1.0", false);
        build(PKG, "1.1", true);
        build(OTHER, "1.0", true);
        if (!Files.isDirectory(Path.of(REPO_CONF).getParent())) {
            Files.createDirectories(Path.of(REPO_CONF).getParent());
            createdReposDir = true;
        }
        Path repo = work.resolve("repo");
        sh("mkdir -p " + repo + " && cp " + work.resolve("pkgs/" + PKG + "-1.1.pkg") + " " + work.resolve("pkgs/" + OTHER + "-1.0.pkg")
                + " " + repo + " && pkg repo " + repo + " >/dev/null 2>&1");
        Files.writeString(Path.of(REPO_CONF),
                "FreeBSD-ports: { enabled: no }\nFreeBSD-ports-kmods: { enabled: no }\n"
              + "robustprobe: { url: \"file://" + repo + "\", signature_type: \"none\", enabled: yes }\n");
        sh("pkg update -f -r robustprobe >/dev/null 2>&1");
    }

    // ===================== M1 =====================

    static void m1WayBack(String bootEnvironmentsBefore) throws Exception {
        System.out.println("\n== M1. The way back ==");
        fresh(0);
        JSONObject job = guided();
        if (job == null) return;
        String log = job.optString("consoleLog");
        List<String> created = newOwn(bootEnvironmentsBefore);
        System.out.println("  outcome: " + job.optString("status") + ", version " + sh("pkg query %v " + PKG).trim());
        System.out.println("  new boot environments: " + created);
        for (String l : log.split("\n")) if (l.contains("packages-before-") || l.contains("bectl")) System.out.println("    | " + l);
        check("M1 the job succeeds", "completed".equals(job.optString("status")));
        check("M1 one new boot environment, the guided update's", created.size() == 1 && created.get(0).endsWith("-guided-update"));
        JSONArray envs = UpdateManager.bootEnvironments().optJSONArray("environments");
        boolean labelled = false;
        for (int i = 0; envs != null && i < envs.length(); i++)
            if (!created.isEmpty() && created.get(0).equals(envs.getJSONObject(i).optString("name")))
                labelled = envs.getJSONObject(i).optString("origin").equals(I18n.tr("server.um.bootEnvironments.packagesOrigin"));
        check("M1 the boot environments tab presents it as the way back of the packages", labelled);
        check("M1 the log says how to go back", !created.isEmpty() && log.contains("bectl activate " + created.get(0)));
        List<String> inside = PackageWayBack.dataInside();
        System.out.println("  data inside the boot environment: " + inside);
        check("M1 the log warns when mail or databases are inside the boot environment",
                inside.isEmpty() || log.contains(String.join(", ", inside)));

        // A job that changes no package: the boot environment is not needed and is removed.
        String before = bootEnvironments();
        UpdateManager.Job j = new UpdateManager.Job("measure-m1-noop", "measure");
        UpdateManager.withWayBack(j, "noop-test", () -> j.write("nothing to do")).run();
        String noopLog = j.toJson().optString("consoleLog");
        System.out.println("  a job without changes: " + noopLog.replace("\n", " | "));
        check("M1 a job without changes does not leave its boot environment", bootEnvironments().equals(before)
                && noopLog.contains("packages-before-"));

        // The pruning: the last three are kept, never one in use, and the origin snapshots go away.
        String snapshotsBefore = sh("zfs list -H -t snapshot -o name | sort");
        List<String> old = new ArrayList<>();
        for (int i = 1; i <= 4; i++) {
            String n = "packages-before-2000-01-0" + i + "-000000-prune-test";
            sh("bectl create " + n);
            old.add(n);
        }
        StringBuilder pl = new StringBuilder();
        PackageWayBack.prune(l -> pl.append(l).append(" | "), PackageWayBack.KEEP);
        String now = bootEnvironments();
        System.out.println("  pruning: " + pl);
        // With M1's boot environment (more recent) the last three are: M1, 04, 03.
        check("M1 the pruning removes the oldest and keeps the last three",
                !now.contains(old.get(0)) && !now.contains(old.get(1)) && now.contains(old.get(3)) && now.contains(old.get(2))
                && !created.isEmpty() && now.contains(created.get(0)));
        for (String n : old) if (now.contains(n)) PackageWayBack.destroy(n);
        check("M1 the origin snapshots of the removed boot environments go away", sh("zfs list -H -t snapshot -o name | sort")
                .lines().filter(x -> !snapshotsBefore.contains(x)).filter(x -> !created.isEmpty() && !x.isEmpty()).count() <= 1);
    }

    // ===================== M2 =====================

    static void m2TurnAcrossProcesses() throws Exception {
        System.out.println("\n== M2. The turn, with two processes ==");
        String mine = PackageQueue.take("measure-m2", "measurement M2");
        String other = runChild(60, "take-turn").trim();
        PackageQueue.release("measure-m2");
        String afterRelease = runChild(60, "take-turn").trim();
        System.out.println("  this process: " + (mine == null ? "taken" : mine));
        System.out.println("  a second process, at the same moment: " + other);
        System.out.println("  a second process, after the release: " + afterRelease);
        check("M2 the second process does NOT take the turn while the first holds it", mine == null && other.startsWith("REFUSED"));
        check("M2 and it takes it as soon as the first releases it", afterRelease.startsWith("TAKEN"));
    }

    // ===================== M2b =====================

    static void m2bSecondStartDuringJob() throws Exception {
        System.out.println("\n== M2b. A second start of the jar while the panel updates ==");
        // During pkg upgrade.
        fresh(25);
        JSONObject pf = UpdateManager.packagePreflight(PKG);
        if (!pf.optBoolean("canProceed")) { check("M2b: the preflight lets it start (" + firstProblem(pf) + ")", false); return; }
        JSONObject start = UpdateManager.startGuidedUpdate(PKG, pf.optString("signature"));
        String id = start.optString("jobId");
        if (id.isEmpty() || !waitFor(STARTED, 240)) { check("M2b: the job reaches the install script (" + start + ")", false); return; }
        String second = runChild(180, "restore").trim();
        System.out.println("  the second start during pkg upgrade: " + second.replace("\n", " | "));
        check("M2b during pkg: the second start does not touch the list", PackageQueue.statePresent() && second.contains("another panel process"));
        JSONObject job = waitJob(id);
        System.out.println("  the job: " + job.optString("status") + " " + job.optString("errorMessage"));
        check("M2b during pkg: the job ends well and locks again", "completed".equals(job.optString("status"))
                && sh("pkg query 'locked=%k' " + PKG).trim().equals("locked=1"));

        // In the window between the unlock and pkg upgrade: this process holds the turn, as the job does.
        fresh(0);
        PackageQueue.take("measure-m2b", "measurement M2b");
        PackageQueue.writeState(List.of(PKG));
        sh("pkg unlock -y " + PKG);
        String second2 = runChild(180, "restore").trim();
        System.out.println("  the second start in the window: " + second2.replace("\n", " | "));
        check("M2b in the window: the second start does not lock again and does not delete the list",
                PackageQueue.statePresent() && sh("pkg query 'locked=%k' " + PKG).trim().equals("locked=0"));
        String up = sh("pkg upgrade -y -U " + PKG + " 2>&1; echo rc=$?");
        System.out.println("  the job's pkg upgrade, afterwards: " + up.trim().replace("\n", " | "));
        check("M2b in the window: the job's pkg upgrade works", up.contains("rc=0") && sh("pkg query %v " + PKG).trim().equals("1.1"));
        sh("pkg lock -y " + PKG);
        PackageQueue.deleteState();
        PackageQueue.release("measure-m2b");
        Files.writeString(SLEEP, "0");
        Files.deleteIfExists(PackageRecovery.notice);
    }

    // ===================== M3 =====================

    static void m3ExternalPkgHoldsTheLock() throws Exception {
        System.out.println("\n== M3. An external pkg (from SSH) holds the lock while a panel job starts ==");
        fresh(0);
        Files.writeString(SLEEP, "45");
        Files.deleteIfExists(STARTED);
        Files.deleteIfExists(DONE);
        Process external = new ProcessBuilder("sh", "-c", "pkg install -y " + OTHER + " > " + DIR.resolve("external.log") + " 2>&1")
                .redirectInput(ProcessBuilder.Redirect.from(new java.io.File("/dev/null"))).start();
        if (!waitFor(STARTED, 60)) { check("M3: the external pkg reached its script", false); external.destroy(); return; }
        JSONObject pf = UpdateManager.packagePreflight(PKG);
        System.out.println("  preview of the guided update with the external pkg working: canProceed=" + pf.optBoolean("canProceed"));
        external.waitFor();
        check("M3 the panel's job does not start and touches nothing", !pf.optBoolean("canProceed")
                && sh("pkg query '%v locked=%k' " + PKG).trim().equals("1.0 locked=1") && !PackageQueue.statePresent());
        Files.writeString(SLEEP, "0");
    }

    // ===================== M4 =====================

    static void m4PanelKilledDuringPkg() throws Exception {
        System.out.println("\n== M4. The panel killed while pkg installs ==");
        fresh(40);
        Files.deleteIfExists(PackageRecovery.notice);
        String cp = System.getProperty("java.class.path");
        Process child = new ProcessBuilder("java", "-De2e.vm=yes", "-cp", cp, UpdaterRobustnessE2ETest.class.getName(), "run-guided")
                .redirectErrorStream(true).redirectOutput(DIR.resolve("child.log").toFile())
                .redirectInput(ProcessBuilder.Redirect.from(new java.io.File("/dev/null"))).start();
        if (!waitFor(STARTED, 240)) {
            check("M4: the job reached the install script", false);
            System.out.println(Files.readString(DIR.resolve("child.log")));
            child.destroyForcibly();
            return;
        }
        sh("kill -9 " + child.pid());
        child.waitFor();
        Thread.sleep(2000);
        System.out.println("  after kill -9 of the panel: pkg " + (sh("pgrep -lf 'pkg upgrade' | grep -v pgrep").trim().isEmpty() ? "finished" : "still working")
                + ", " + PKG + " protected: " + (locked().contains(PKG) ? "yes" : "no"));
        // The panel starts again and stays up: the child does the start-up restore and waits.
        String restart = runChild(200, "restore-and-stay", "150").trim();
        System.out.println("  the panel restarted (and still up): " + restart.replace("\n", " | "));
        JSONObject n = PackageRecovery.notice();
        System.out.println("  " + PKG + " at the end: " + sh("pkg query '%v locked=%k' " + PKG).trim()
                + ", list: " + (PackageQueue.statePresent() ? "still there" : "removed"));
        System.out.println("  the notice: " + n);
        check("M4 the restart says pkg is still working and that it retries", restart.contains("retrying every"));
        check("M4 locked again as soon as pkg finished, without another restart",
                sh("pkg query '%v locked=%k' " + PKG).trim().equals("1.1 locked=1") && !PackageQueue.statePresent()
                && restart.contains("PROTECTED AGAIN IN THE BACKGROUND"));
        check("M4 the notice says which job, that pkg was working, and when it was locked again",
                n.optString("description").contains(PKG) && !n.optString("pkgWasRunning").isEmpty() && n.has("relockedUtc"));
        Files.writeString(SLEEP, "0");
        Files.deleteIfExists(PackageRecovery.notice);
    }

    // ===================== M5 =====================

    static void m5Timeout() throws Exception {
        System.out.println("\n== M5. runLogged's timeout ==");
        sh("pkg delete -y " + OTHER + " >/dev/null 2>&1");
        Files.writeString(SLEEP, "40");
        Files.deleteIfExists(STARTED);
        Files.deleteIfExists(DONE);
        UpdateManager.Job job = new UpdateManager.Job("measure-m5", "measure");
        long t0 = System.currentTimeMillis();
        String outcome;
        int code = Integer.MIN_VALUE;
        try { code = UpdateManager.runLogged(job, "pkg install -y " + OTHER + " 2>&1", 10); outcome = "code " + code; }
        catch (Exception e) { outcome = "EXCEPTION " + e; }
        long took = (System.currentTimeMillis() - t0) / 1000;
        String log = job.toJson().optString("consoleLog");
        System.out.println("  pkg install with a 10 s timeout and a 40 s script: back after " + took + " s, " + outcome);
        for (String l : log.split("\n")) if (l.contains("pkg") && (l.contains("minut") || l.contains("TIMEOUT"))) System.out.println("    | " + l);
        check("M5 pkg: it comes back with pkg's exit code, no exception", code == 0);
        check("M5 pkg: not killed, it reaches the end of its script", Files.exists(DONE) && took >= 38
                && sh("pkg check -s " + OTHER + " >/dev/null 2>&1; echo $?").trim().equals("0"));
        check("M5 pkg: the log says it waits, not that it ends it",
                log.contains(I18n.tr("server.um.runLogged.pkgStillRunning", java.util.Map.of("cmd", "pkg", "minutes", "1")).substring(0, 12))
                && !log.contains("TIMEOUT"));
        Files.writeString(SLEEP, "0");

        // A command that is not pkg: when the time is up it stops, with all its children.
        UpdateManager.Job j2 = new UpdateManager.Job("measure-m5b", "measure");
        t0 = System.currentTimeMillis();
        int c2 = Integer.MIN_VALUE;
        String o2;
        try { c2 = UpdateManager.runLogged(j2, "sleep 61 & sleep 62; wait", 3); o2 = "code " + c2; }
        catch (Exception e) { o2 = "EXCEPTION " + e; }
        long took2 = (System.currentTimeMillis() - t0) / 1000;
        String left = sh("pgrep -lf 'sleep 6[12]$'").trim();
        System.out.println("  sleep 61 & sleep 62 with a 3 s timeout: back after " + took2 + " s, " + o2 + ", left: " + (left.isEmpty() ? "none" : left));
        check("M5 other command: stopped when the time is up with 124, without an exception", c2 == UpdateManager.TIMED_OUT && took2 < 20);
        check("M5 other command: no child left alive", left.isEmpty());
        sh("pkill -f 'sleep 6[12]$'");

        // A process let go by the command, outside the tree, that keeps the output open: the
        // timeout holds all the same.
        UpdateManager.Job j3 = new UpdateManager.Job("measure-m5c", "measure");
        t0 = System.currentTimeMillis();
        int c3 = Integer.MIN_VALUE;
        String o3;
        try { c3 = UpdateManager.runLogged(j3, "(sleep 71 &) ; sleep 63", 3); o3 = "code " + c3; }
        catch (Exception e) { o3 = "EXCEPTION " + e; }
        long took3 = (System.currentTimeMillis() - t0) / 1000;
        System.out.println("  (sleep 71 &); sleep 63 with a 3 s timeout: back after " + took3 + " s, " + o3);
        check("M5 a detached process that keeps the output does not get past the timeout", c3 == UpdateManager.TIMED_OUT && took3 < 30);
        // A command that ENDS with a detached process still alive is not a problem: measured on the
        // VM, the JVM closes the pipe by itself when the process exits, with the reading in the main
        // thread as in a separate one. The OUTPUT_GRACE_SECONDS margin stays as a defence, but it has
        // no case that triggers it, and it is not counted here.
        sh("pkill -f 'sleep 7[12]$'");

        // The table: what is never stopped.
        check("M5 the table of the commands not to stop", UpdateManager.mustNotBeKilled("pkg upgrade -y -U 2>&1")
                && UpdateManager.mustNotBeKilled("pkg install -f -y dovecot 2>&1")
                && UpdateManager.mustNotBeKilled("pkg autoremove -y 2>&1")
                && UpdateManager.mustNotBeKilled("freebsd-update install 2>&1")
                && !UpdateManager.mustNotBeKilled("pkg upgrade -F -y -U 2>&1")
                && !UpdateManager.mustNotBeKilled("pkg upgrade -n 2>&1")
                && !UpdateManager.mustNotBeKilled("freebsd-update --not-running-from-cron fetch 2>&1")
                && !UpdateManager.mustNotBeKilled("cp -Rp /var/db/mysql /x"));
    }

    // ===================== M6 =====================

    static void m6Report() throws Exception {
        System.out.println("\n== M6. The report ==");
        fresh(0);
        // An interrupted job with the package still unlocked, and the notice.
        PackageQueue.take("measure-m6", "Guided update of " + PKG);
        PackageQueue.writeState(List.of(PKG));
        PackageQueue.release("measure-m6");
        sh("pkg unlock -y " + PKG);
        PackageRecovery.recordInterruption(PackageQueue.jobRecord(), List.of(PKG), List.of(PKG), "");
        JSONArray toDo = UpdateManager.reportData(false).optJSONArray("toDo");
        List<String> whats = new ArrayList<>();
        for (int i = 0; toDo != null && i < toDo.length(); i++) whats.add(toDo.getJSONObject(i).optInt("urgency") + " " + toDo.getJSONObject(i).optString("what"));
        whats.forEach(w -> System.out.println("    - " + w));
        check("M6 the report says, with urgency 0, the packages still without protection",
                whats.stream().anyMatch(w -> w.startsWith("0 ") && w.contains(PKG) && w.contains("pkg lock -y")));
        check("M6 the report says which job was interrupted and what to check",
                whats.stream().anyMatch(w -> w.startsWith("1 ") && w.contains("Guided update of " + PKG) && w.contains("pkg check -s")));
        JSONObject st = PackageRecovery.status();
        check("M6 the page receives the notice and the packages without protection",
                st.optJSONObject("notice") != null && st.optJSONArray("stillUnprotected") != null
                && st.getJSONArray("stillUnprotected").toList().contains(PKG));
        check("M6 the notice does not close while the packages are without protection", !PackageRecovery.dismiss().optBoolean("success"));
        PackageQueue.deleteState();
        // Without a list, but with a stack package unlocked outside the panel.
        toDo = UpdateManager.reportData(false).optJSONArray("toDo");
        boolean loose = false;
        for (int i = 0; toDo != null && i < toDo.length(); i++) if (toDo.getJSONObject(i).optString("what").contains(PKG)) loose = true;
        check("M6 a stack package unlocked outside the panel is in the report", loose);
        check("M6 the notice closes after checking", PackageRecovery.dismiss().optBoolean("success") && PackageRecovery.notice().isEmpty());
        sh("pkg lock -y " + PKG);
    }

    // ===================== M7 =====================

    /** Where M7 keeps what it needs after the reboot: /var/tmp is outside the boot environments. */
    static final Path M7 = Path.of("/var/tmp/um-probe-m7");

    /**
     * M7, first part: a guided update with the long install script, and the machine switched off
     * abruptly while pkg installs (reboot -nq: no shutdown scripts, no sync, like a power cut).
     * Whoever runs it waits for "M7 IN PKG" and then does the reboot. The second part (after the
     * reboot, and after the panel started again) is the "m7-after" mode.
     */
    static void m7Before() throws Exception {
        Files.createDirectories(M7);
        Files.writeString(M7.resolve("packages-before"), sh("pkg query %n-%v | sort | sha256"));
        Files.writeString(M7.resolve("locked-before"), String.join("\n", locked()));
        Files.writeString(M7.resolve("boot-environments-before"), bootEnvironments());
        cleanup();
        Files.deleteIfExists(PackageRecovery.notice);
        work = Files.createDirectories(M7.resolve("work"));
        Files.createDirectories(DIR);
        build(PKG, "1.0", false);
        build(PKG, "1.1", true);
        Path repo = work.resolve("repo");
        sh("mkdir -p " + repo + " && cp " + work.resolve("pkgs/" + PKG + "-1.1.pkg") + " " + repo + " && pkg repo " + repo + " >/dev/null 2>&1");
        if (!Files.isDirectory(Path.of(REPO_CONF).getParent())) {
            Files.createDirectories(Path.of(REPO_CONF).getParent());
            Files.writeString(M7.resolve("created-repos-dir"), "yes");
        }
        Files.writeString(Path.of(REPO_CONF),
                "FreeBSD-ports: { enabled: no }\nFreeBSD-ports-kmods: { enabled: no }\n"
              + "robustprobe: { url: \"file://" + repo + "\", signature_type: \"none\", enabled: yes }\n");
        sh("pkg update -f -r robustprobe >/dev/null 2>&1");
        fresh(120);
        Thread t = new Thread(() -> {
            try { while (!Files.exists(STARTED)) Thread.sleep(200); System.out.println("M7 IN PKG"); System.out.flush(); }
            catch (InterruptedException ignored) { }
        });
        t.setDaemon(true);
        t.start();
        JSONObject job = guided();
        System.out.println("M7: the job ended before the reboot: " + job);
    }

    /** M7, second part: what the panel found at start, what page and report say, and the cleanup. */
    static void m7After() throws Exception {
        System.out.println("== M7. After an abrupt reboot during pkg upgrade ==");
        JSONObject n = PackageRecovery.notice();
        System.out.println("  the notice the panel left at start: " + n);
        System.out.println("  " + PKG + ": " + sh("pkg query '%v locked=%k' " + PKG + " 2>&1").trim()
                + ", install script reached its end: " + (Files.exists(DONE) ? "yes" : "NO"));
        check("M7 locked again at start, list closed", sh("pkg query 'locked=%k' " + PKG).trim().equals("locked=1") && !PackageQueue.statePresent());
        check("M7 the notice says which job was interrupted, and it is locked again", n.optString("description").contains(PKG) && n.has("relockedUtc"));
        JSONArray toDo = UpdateManager.reportData(false).optJSONArray("toDo");
        boolean inReport = false;
        for (int i = 0; toDo != null && i < toDo.length(); i++)
            if (toDo.getJSONObject(i).optString("what").contains(PKG) && toDo.getJSONObject(i).optString("what").contains("pkg install -f")) inReport = true;
        check("M7 the report says so, with what to do", inReport);
        check("M7 the notice closes after checking", PackageRecovery.dismiss().optBoolean("success"));
        // the cleanup
        cleanup();
        sh("rm -f " + REPO_CONF + "; rm -rf /var/db/pkg/repos/robustprobe " + DIR);
        if (Files.exists(M7.resolve("created-repos-dir"))) sh("rmdir " + Path.of(REPO_CONF).getParent());
        removeOwnBootEnvironments(Files.readString(M7.resolve("boot-environments-before")));
        UpdateManager.refreshLockTrace();
        check("M7 at the end: the same packages as before",
                sh("pkg query %n-%v | sort | sha256").equals(Files.readString(M7.resolve("packages-before"))));
        check("M7 at the end: the same protected packages",
                String.join("\n", locked()).equals(Files.readString(M7.resolve("locked-before"))));
        check("M7 at the end: the same boot environments", bootEnvironments().equals(Files.readString(M7.resolve("boot-environments-before"))));
        sh("rm -rf " + M7);
        System.out.println(failures == 0 ? "\nALL OK" : "\n" + failures + " CHECKS FAILED");
        if (failures > 0) System.exit(1);
    }

    // ===================== the children =====================

    static void child(String[] args) throws Exception {
        switch (args[0]) {
            case "take-turn" -> {
                String r = PackageQueue.take("measure-m2-child", "measurement M2, second process");
                System.out.println(r == null ? "TAKEN" : "REFUSED: " + r);
                if (r == null) PackageQueue.release("measure-m2-child");
            }
            case "run-guided" -> {
                JSONObject job = guided();
                System.out.println("child finished: " + (job == null ? "null" : job.optString("status")));
            }
            case "restore" -> System.out.println(UpdateManager.restoreLocksAfterCrash());
            case "restore-and-stay" -> {
                System.out.println(UpdateManager.restoreLocksAfterCrash());
                long until = System.currentTimeMillis() + Long.parseLong(args[1]) * 1000;
                while (PackageQueue.statePresent() && System.currentTimeMillis() < until) Thread.sleep(1000);
                if (!PackageQueue.statePresent()) System.out.println("PROTECTED AGAIN IN THE BACKGROUND");
            }
            case "m7-after" -> m7After();
            case "be-label" -> {
                // How the tab and the report describe a way back of the packages. It touches no packages
                // nor repositories: it creates a boot environment with the right name, asks
                // bootEnvironments() and removes it.
                String n = "packages-before-2000-01-01-000000-label-test";
                sh("bectl create " + n);
                try {
                    String origin = "", explain = "";
                    JSONArray envs = UpdateManager.bootEnvironments().optJSONArray("environments");
                    for (int i = 0; envs != null && i < envs.length(); i++)
                        if (n.equals(envs.getJSONObject(i).optString("name"))) {
                            origin = envs.getJSONObject(i).optString("origin");
                            explain = envs.getJSONObject(i).optString("explanation");
                        }
                    System.out.println("  " + n + ": " + origin + " / " + explain);
                    check("a way back of the packages presents itself as such",
                            origin.equals(I18n.tr("server.um.bootEnvironments.packagesOrigin"))
                            && explain.equals(I18n.tr("server.um.bootEnvironments.packagesExplain")));
                } finally {
                    PackageWayBack.destroy(n);
                }
                check("and the test boot environment is gone", !bootEnvironments().contains(n));
                if (failures > 0) System.exit(1);
            }
            default -> throw new IllegalArgumentException(args[0]);
        }
    }

    // ===================== tools =====================

    /** nginx-robust-probe 1.0 installed and protected, 1.1 in the catalog, with the script sleeping 'seconds'. */
    static void fresh(int seconds) throws Exception {
        sh("pkg unlock -y " + PKG + " >/dev/null 2>&1; pkg delete -y " + PKG + " >/dev/null 2>&1");
        sh("pkg add " + work.resolve("pkgs/" + PKG + "-1.0.pkg") + " >/dev/null 2>&1");
        sh("pkg lock -y " + PKG);
        Files.writeString(SLEEP, String.valueOf(seconds));
        Files.deleteIfExists(STARTED);
        Files.deleteIfExists(DONE);
    }

    static JSONObject guided() throws Exception {
        JSONObject pf = UpdateManager.packagePreflight(PKG);
        if (!pf.optBoolean("canProceed")) {
            check("the preflight lets it start (" + firstProblem(pf) + ")", false);
            return null;
        }
        JSONObject start = UpdateManager.startGuidedUpdate(PKG, pf.optString("signature"));
        String id = start.optString("jobId");
        if (id.isEmpty()) { System.out.println("  the job does not start: " + start); return start; }
        System.out.println("  job " + id + " started");
        return waitJob(id);
    }

    static JSONObject waitJob(String id) throws Exception {
        long deadline = System.currentTimeMillis() + 900_000;
        while (PackageQueue.holder() != null && System.currentTimeMillis() < deadline) Thread.sleep(1000);
        return UpdateManager.jobStatus(id).getJSONObject("job");
    }

    static String firstProblem(JSONObject pf) {
        String all = pf.toString();
        return all.substring(0, Math.min(400, all.length()));
    }

    /** A fake package: a file with the version, and an install script that can sleep. */
    static void build(String name, String version, boolean slow) throws Exception {
        String share = name.equals(PKG) ? "robust-probe" : OTHER;
        Path root = work.resolve("root-" + name + "-" + version);
        Path d = Files.createDirectories(root.resolve("usr/local/share/" + share));
        Files.writeString(d.resolve("version"), version + "\n");
        String post = slow
                ? "touch " + STARTED + "\necho \"post-install: sleeping $(cat " + SLEEP + " 2>/dev/null || echo 0) s\"\n"
                  + "sleep $(cat " + SLEEP + " 2>/dev/null || echo 0)\necho 'post-install: done'\ntouch " + DONE + "\nexit 0\n"
                : "exit 0\n";
        Path manifest = work.resolve("manifest-" + name + "-" + version);
        Files.writeString(manifest, "name: " + name + "\nversion: \"" + version + "\"\norigin: misc/" + name
                + "\ncomment: \"updater measurement\"\ndesc: \"updater measurement\"\nmaintainer: root@localhost\n"
                + "www: https://localhost/\nprefix: /usr/local\nscripts: {\n  post-install: <<EOD\n" + post + "EOD\n}\n");
        Path plist = work.resolve("plist-" + name + "-" + version);
        Files.writeString(plist, "/usr/local/share/" + share + "/version\n");
        Files.createDirectories(work.resolve("pkgs"));
        String out = sh("pkg create -M " + manifest + " -r " + root + " -p " + plist + " -o " + work.resolve("pkgs") + " 2>&1");
        if (!Files.exists(work.resolve("pkgs/" + name + "-" + version + ".pkg")))
            throw new IllegalStateException("pkg create " + name + " " + version + ": " + out);
    }

    static void cleanup() {
        sh("pkill -f 'pkg (install|upgrade).*robust-probe' ; sleep 1; "
         + "pkg unlock -y " + PKG + " >/dev/null 2>&1; pkg delete -y " + PKG + " " + OTHER + " >/dev/null 2>&1; "
         + "rm -rf /usr/local/share/robust-probe /usr/local/share/" + OTHER + "; true");
        PackageQueue.deleteState();
    }

    /** The notice of an interrupted job as it was before the test (usually: it was not there). */
    static void restoreNotice() throws Exception {
        if (noticeBefore == null) Files.deleteIfExists(PackageRecovery.notice);
        else Files.writeString(PackageRecovery.notice, noticeBefore);
    }

    static String bootEnvironments() {
        return sh("bectl list -H | cut -f1 | sort");
    }

    /** The boot environments of the packages that appeared during the test. */
    static List<String> newOwn(String before) {
        List<String> r = new ArrayList<>();
        for (String n : bootEnvironments().split("\n"))
            if (n.startsWith(PackageWayBack.PREFIX) && !before.contains(n)) r.add(n.trim());
        return r;
    }

    static void removeOwnBootEnvironments(String before) {
        for (String n : newOwn(before)) PackageWayBack.destroy(n);
    }

    static String runChild(int seconds, String... mode) throws Exception {
        String cp = System.getProperty("java.class.path");
        List<String> cmd = new ArrayList<>(List.of("java", "-De2e.vm=yes", "-cp", cp, UpdaterRobustnessE2ETest.class.getName()));
        cmd.addAll(List.of(mode));
        Process p = new ProcessBuilder(cmd).redirectErrorStream(true)
                .redirectInput(ProcessBuilder.Redirect.from(new java.io.File("/dev/null"))).start();
        StringBuilder out = new StringBuilder();
        try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
            String l;
            while ((l = r.readLine()) != null)
                if (!l.startsWith("WARNING") && !l.startsWith("INFO:") && !l.matches("^[A-Z][a-z]{2} \\d{2}, \\d{4} .*")) out.append(l).append('\n');
        }
        p.waitFor(seconds, java.util.concurrent.TimeUnit.SECONDS);
        return out.toString();
    }

    static boolean waitFor(Path f, int seconds) throws Exception {
        for (int i = 0; i < seconds * 2; i++) { if (Files.exists(f)) return true; Thread.sleep(500); }
        return false;
    }

    static Set<String> locked() {
        Set<String> r = new TreeSet<>();
        for (String l : sh("pkg lock -l 2>/dev/null").split("\n"))
            if (!l.trim().isEmpty() && !l.trim().endsWith(":")) r.add(l.trim().replaceAll("-[^-]+$", ""));
        return r;
    }

    static String sh(String cmd) {
        return Shell.runShell(Duration.ofSeconds(600), cmd).output();
    }

    static void check(String name, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + name);
        if (!ok) failures++;
    }
}
