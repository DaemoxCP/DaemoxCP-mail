package org.daemoxcp.mail.system;

import org.json.JSONObject;
import org.daemoxcp.mail.Main;
import org.daemoxcp.mail.database.MailDatabase;
import org.daemoxcp.mail.scripts.FullMailServerScript;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * The package jobs' turn between PROCESSES: two panels, and the panel against the full installation
 * script started by hand.
 *
 * The service (--web) and the on-screen menu are two JVMs, and the install_mail_server.sh script can
 * also be started from a shell. The turn is a lock on PackageQueue.turnLock (fcntl from the panel,
 * lockf(1) from the script). Here a second real process (TurnHolder) holds the turn, and it is
 * checked that this process:
 *   - does not take it, and knows who holds it;
 *   - at start leaves that job's list alone (restoreLocksAfterCrash);
 *   - does not apply the locks rule while the other works, and says so (applyLockPolicy);
 * that, with the other killed by kill -9, the turn is free again and the list left is locked again
 * with the notice naming the interrupted job; that lockf and the panel exclude each other in both
 * directions (reperto 153); and that the turn part of the real script (taken from the text the
 * panel writes, up to the checks on the protected packages, before stopping anything) starts only
 * when it should.
 *
 * List, job record, notice and lock live in a test folder. The restore asks pkg about two packages
 * that do not exist (pkg info -e), so it changes nothing on the machine; it must be run on the VM
 * like the others, as root (the script checks it):
 *   java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.daemoxcp.mail.system.PackageTurnAcrossProcessesTest
 */
public class PackageTurnAcrossProcessesTest {

    private static int failed = 0;
    private static Path d;

    public static void main(String[] args) throws Exception {
        d = Files.createTempDirectory(Path.of("/var/tmp"), "turn-across");
        PackageQueue.list = d.resolve("mail-panel-maintenance-locks");
        PackageQueue.turnLock = d.resolve("package-turn.lock");
        PackageRecovery.notice = d.resolve("package-job-interrupted.json");
        Path list = PackageQueue.list;
        long me = ProcessHandle.current().pid();

        System.out.println("== Another process holds the turn, without a list ==");
        Holder h = Holder.start(list, "test maintenance");
        check("the other process has the turn", h.pid > 0);
        String r = PackageQueue.take("here", "guided update");
        check("here it is not taken", r != null);
        check("and the reason says the other's pid and job",
                r != null && r.contains("pid " + h.pid) && r.contains("test maintenance"));
        check("the refusal does not leave the turn taken in memory", PackageQueue.holder() == null);
        check("not even for the protections", PackageQueue.takeForLocks("here", "protection") != null);
        // The locks rule at start: with the panel's database "present" (not connected: the refusal
        // comes before any question), it must lock nothing now, and say so.
        Main.mailDatabase = new MailDatabase();
        String policy = UpdateManager.applyLockPolicy();
        Main.mailDatabase = null;
        check("the locks rule is not applied while the other works, and it says so",
                policy.contains("not applied") && policy.contains("test maintenance"));
        h.release();
        check("released by the other, here it is taken", PackageQueue.take("here", "guided update") == null);
        check("and the lock says who holds it now", Files.readString(PackageQueue.turnLock).startsWith("pid " + me + ", "));
        PackageQueue.release("here");

        System.out.println("\n== Another process works with the packages unlocked (list on disk) ==");
        h = Holder.start(list, "test reinstallation", "e2e-turn-probe-a", "e2e-turn-probe-b");
        check("the other has the turn and the list", h.pid > 0 && Files.exists(list));
        check("the job record next to the list is the other's",
                PackageQueue.jobRecord().optLong("pid") == h.pid
                && "test reinstallation".equals(PackageQueue.jobRecord().optString("description")));
        String restore = UpdateManager.restoreLocksAfterCrash();
        check("this process's start leaves the list alone", restore.contains("the list is not touched"));
        check("and the list is still the other's",
                Files.readString(list).equals("e2e-turn-probe-a\ne2e-turn-probe-b\n"));
        check("and no notice of an interrupted job", !Files.exists(PackageRecovery.notice));
        check("with the list of a live job, nothing starts here", PackageQueue.take("here", "maintenance") != null);

        System.out.println("\n== The other process dies (kill -9) ==");
        h.kill();
        check("the list stays: it is what survives", Files.exists(list));
        restore = UpdateManager.restoreLocksAfterCrash();
        check("now the start recognises it as interrupted and closes it",
                restore.contains("Interrupted") && !Files.exists(list));
        JSONObject notice = PackageRecovery.notice();
        check("and the notice names the interrupted job", "test reinstallation".equals(notice.optString("description")));
        check("and the turn is free", PackageQueue.take("here", "maintenance") == null);
        PackageQueue.release("here");
        Files.deleteIfExists(PackageRecovery.notice);

        lockfAgainstThePanel();
        scriptTurn();

        for (String f : new String[]{"package-turn.lock", "mail-panel-maintenance-locks",
                "mail-panel-maintenance-locks.job.json", "package-job-interrupted.json", "stop", "turn-part.sh"})
            Files.deleteIfExists(d.resolve(f));
        Files.delete(d);
        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }

    /** lockf(1) (flock) and the panel (fcntl): do they exclude each other? Measured in reperto 153, repeated here. */
    static void lockfAgainstThePanel() throws Exception {
        System.out.println("\n== lockf(1) against the panel ==");
        if (!Files.isExecutable(Path.of("/usr/bin/lockf"))) { check("lockf(1) is there (FreeBSD)", false); return; }
        Path lock = PackageQueue.turnLock, stop = d.resolve("stop");
        Files.writeString(stop, "");
        Process p = new ProcessBuilder("lockf", "-k", "-t", "0", lock.toString(), "sh", "-c",
                "echo \"pid $$, test with lockf\" > " + lock + "; echo HELD; while [ -e " + stop + " ]; do sleep 0.2; done")
                .redirectErrorStream(true).start();
        String first = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8)).readLine();
        check("lockf has the turn", "HELD".equals(first));
        String r = PackageQueue.take("here", "guided update");
        check("with lockf holding it, the panel does not take the turn", r != null);
        check("and it knows who holds it, from what is written there", r != null && r.contains("test with lockf"));
        Files.delete(stop);
        p.waitFor();
        check("lockf -k finished, the lock file stays", Files.exists(lock));
        check("lockf finished, the panel takes it", PackageQueue.take("here", "guided update") == null);
        int rc = sh("lockf -k -s -t 0 " + lock + " true");
        check("with the turn held by the panel, lockf -t 0 exits 75 (already taken)", rc == 75);
        PackageQueue.release("here");
        check("released by the panel, lockf takes it", sh("lockf -k -s -t 0 " + lock + " true") == 0);
        check("with -k the file stays (the panel opens it by name)", Files.exists(lock));
    }

    /**
     * The turn part of the real script: the text of FullMailServerScript up to the checks on the
     * protected packages, with the test folder's lock; in place of the rest, "TURN-OK" and a wait while
     * the stop file is there. It never reaches phase 1, whatever happens.
     */
    static void scriptTurn() throws Exception {
        System.out.println("\n== The turn part of the full installation script ==");
        String full = new FullMailServerScript().getScriptContent();
        // The cut is the opening of the protected-packages check: the comment above it is in the
        // script's own language, the code line is not.
        String cut = "if true; then\n    if ! LOCKED_PACKAGES=";
        int at = full.indexOf(cut);
        check("the script has the protected-packages check after the turn", at > 0 && full.indexOf("PACKAGE_TURN_LOCK=") > 0
                && full.indexOf("PACKAGE_TURN_LOCK=") < at && at < full.indexOf("PHASE 1: CLEANUP"));
        if (at < 0) return;
        Path lock = PackageQueue.turnLock, stop = d.resolve("stop"), part = d.resolve("turn-part.sh");
        String body = full.substring(0, at).replace(PackageQueue.TURN_LOCK_PATH, lock.toString());
        check("and it takes the panel's lock, not another file", !body.equals(full.substring(0, at)));
        Files.writeString(part, body + "\necho TURN-OK\nwhile [ -e " + stop + " ]; do sleep 0.2; done\nexit 0\n");
        long me = ProcessHandle.current().pid();

        // From the menu: the panel (us) holds the turn and tells the script.
        PackageQueue.take("menu", "complete mail server installation");
        Run s = Run.script(part, Map.of("MAIL_PANEL_PACKAGE_TURN", String.valueOf(me)));
        check("from the menu, with the turn held by the panel: the script passes", s.rc == 0 && s.out.contains("TURN-OK"));
        // Started by hand while the panel works.
        s = Run.script(part, Map.of());
        check("by hand, with the turn held by the panel: the script stops before anything", s.rc != 0 && !s.out.contains("TURN-OK"));
        check("and it says who holds it", s.out.contains("another job is working on the packages") && s.out.contains("pid " + me + ","));
        // A pid that is not the parent.
        s = Run.script(part, Map.of("MAIL_PANEL_PACKAGE_TURN", "1"));
        check("with another process's pid: it stops", s.rc != 0 && !s.out.contains("TURN-OK"));
        // The restart under a fake lockf while the panel works: the lock is taken (by the panel), so
        // only the check that the parent is lockf stops it.
        s = Run.script(part, Map.of("MAIL_PANEL_TURN_BY_LOCKF", "1"));
        check("by hand with MAIL_PANEL_TURN_BY_LOCKF, with the turn held by the panel: it stops", s.rc != 0 && !s.out.contains("TURN-OK"));
        PackageQueue.release("menu");
        // The panel says it holds it, but it does not.
        s = Run.script(part, Map.of("MAIL_PANEL_PACKAGE_TURN", String.valueOf(me)));
        check("with the right pid but the turn free: it stops", s.rc != 0 && !s.out.contains("TURN-OK") && s.out.contains("does not hold"));
        // The turn is taken, but by another process: its pid is written inside, not ours.
        Holder h = Holder.start(PackageQueue.list, "test maintenance");
        s = Run.script(part, Map.of("MAIL_PANEL_PACKAGE_TURN", String.valueOf(me)));
        check("with the turn taken by another panel process: it stops", s.rc != 0 && !s.out.contains("TURN-OK"));
        h.release();
        // The restart under a fake lockf: the variable set by hand.
        s = Run.script(part, Map.of("MAIL_PANEL_TURN_BY_LOCKF", "1"));
        check("with MAIL_PANEL_TURN_BY_LOCKF set by hand, without lockf: it stops", s.rc != 0 && !s.out.contains("TURN-OK"));

        // By hand, with the turn free: it restarts itself under lockf and holds it while it works.
        Files.writeString(stop, "");
        Process p = Run.start(part, Map.of());
        StringBuilder out = new StringBuilder();
        BufferedReader rd = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8));
        for (String l; (l = rd.readLine()) != null; ) { out.append(l).append('\n'); if (l.contains("TURN-OK")) break; }
        check("by hand, with the turn free: the script passes", out.toString().contains("TURN-OK"));
        String r = PackageQueue.take("here", "maintenance");
        check("and while it works the panel does not take the turn", r != null);
        check("and it knows it is the script started by hand", r != null && r.contains("install_mail_server.sh started by hand"));
        Run second = Run.script(part, Map.of());
        check("and a second script by hand stops", second.rc != 0 && !second.out.contains("TURN-OK"));
        check("the lock line names the process that works, not lockf",
                Files.readString(lock).startsWith("pid ") && !Files.readString(lock).startsWith("pid " + p.pid() + ","));
        Files.delete(stop);
        rd.transferTo(java.io.Writer.nullWriter());
        int rc = p.waitFor();
        check("the script ends with 0", rc == 0);
        // Before any take: take creates the file if missing, and the check would no longer see
        // anything (it happened: with lockf without -k this check, placed after, stayed green).
        check("the script finished, the lock file is still there (lockf -k)", Files.exists(lock));
        check("the script finished, the panel takes the turn", PackageQueue.take("here", "maintenance") == null);
        PackageQueue.release("here");
    }

    /** A script started as the panel starts it: sh <path> <arguments>, stdin /dev/null. */
    static final class Run {
        int rc;
        String out;

        static final List<String> ARGS = List.of("127.0.0.1", "3306", "mailpanel", "mailserver", "mail.turn.test",
                "webmail.turn.test", "8443", "", "", "");

        static Process start(Path script, Map<String, String> env) throws Exception {
            List<String> cmd = new ArrayList<>(List.of("sh", script.toString()));
            cmd.addAll(ARGS);
            ProcessBuilder pb = new ProcessBuilder(cmd).redirectErrorStream(true)
                    .redirectInput(ProcessBuilder.Redirect.from(new java.io.File("/dev/null")));
            pb.environment().remove("MAIL_PANEL_PACKAGE_TURN");
            pb.environment().remove("MAIL_PANEL_TURN_BY_LOCKF");
            pb.environment().put("MYSQL_PASSWORD", "turn-test");
            pb.environment().put("MYSQL_ROOT_PASSWORD", "turn-test");
            // The script of #91 (the webmail with its own MySQL user) also wants this one, and stops
            // before the turn if it is missing; the old one ignores it. Found on the integration branch.
            pb.environment().put("ROUNDCUBE_DB_PASSWORD", "turn-test");
            pb.environment().putAll(env);
            return pb.start();
        }

        static Run script(Path script, Map<String, String> env) throws Exception {
            Process p = start(script, env);
            Run r = new Run();
            r.out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            r.rc = p.waitFor();
            String last = r.out.strip();
            int nl = last.lastIndexOf('\n');
            System.out.println("    (script " + env + ": rc=" + r.rc + ", " + (nl < 0 ? last : last.substring(nl + 1)) + ")");
            return r;
        }
    }

    private static int sh(String cmd) throws Exception {
        return new ProcessBuilder("sh", "-c", cmd).inheritIO().start().waitFor();
    }

    /** The second process: TurnHolder, with the same classpath. */
    static final class Holder {
        final Process p;
        final long pid;

        private Holder(Process p, long pid) { this.p = p; this.pid = pid; }

        static Holder start(Path list, String description, String... packages) throws Exception {
            String java = ProcessHandle.current().info().command().orElse("java");
            List<String> cmd = new ArrayList<>(List.of(java, "-cp", System.getProperty("java.class.path"),
                    "org.daemoxcp.mail.system.TurnHolder", list.toString(), description));
            cmd.addAll(List.of(packages));
            Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
            BufferedReader out = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8));
            String line = out.readLine();
            System.out.println("    (other process: " + line + ")");
            long pid = line != null && line.startsWith("HELD ") ? Long.parseLong(line.substring(5).trim()) : -1;
            return new Holder(p, pid);
        }

        void release() throws Exception {
            p.getOutputStream().close();
            p.waitFor();
        }

        void kill() throws Exception {
            p.destroyForcibly();   // SIGKILL: no finally, no shutdown hook
            p.waitFor();
        }
    }

    private static void check(String what, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + what);
        if (!ok) failed++;
    }
}
