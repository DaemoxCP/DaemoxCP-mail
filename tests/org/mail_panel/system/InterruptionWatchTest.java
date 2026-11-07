package org.mail_panel.system;

import org.json.JSONObject;
import org.mail_panel.i18n.I18n;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * The running service's guardian (UpdateManager.watchOnce, reperto 166): when it must NOT touch the
 * list of unlocked packages, and the text of the notice of an interrupted reinstallation. No pkg:
 * every case stops before locking again (the case that really locks again is ReinstallJobTest J4,
 * on the clone). List, job record, turn and notice in a temporary folder.
 *
 * Usage: java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.InterruptionWatchTest
 */
public class InterruptionWatchTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static long deadPid() throws Exception {
        Process p = new ProcessBuilder("true").start();
        p.waitFor();
        return p.pid();
    }

    /** Every case starts clean: a list left from the case before makes the turn be refused (take). */
    static void clearList() throws Exception {
        Files.deleteIfExists(PackageQueue.list);
        Files.deleteIfExists(PackageQueue.jobRecordPath());
    }

    static void writeList(long writerPid, boolean expectsRestart, String turnId) throws Exception {
        Files.writeString(PackageQueue.list, "dovecot\nnginx\n");
        Files.writeString(PackageQueue.jobRecordPath(), new JSONObject()
                .put("description", "test").put("turnId", turnId).put("pid", writerPid)
                .put("expectsRestart", expectsRestart).put("startedUtc", "2026-11-06T00:00:00Z").toString());
    }

    public static void main(String[] args) throws Exception {
        I18n.setCurrent("en");
        Path d = Files.createTempDirectory("interruption-watch");
        PackageQueue.list = d.resolve("mail-panel-maintenance-locks");
        PackageQueue.turnLock = d.resolve("package-turn.lock");
        PackageRecovery.notice = d.resolve("package-job-interrupted.json");
        try {
            System.out.println("== No list ==");
            check("nothing to do", UpdateManager.watchOnce().isEmpty());

            System.out.println("\n== The list left on purpose by the JVM update ==");
            clearList();
            writeList(deadPid(), true, "java-update");
            check("it does not touch it (the restart it makes closes it)", UpdateManager.watchOnce().isEmpty() && PackageQueue.statePresent());
            check("and it writes no notice", !Files.exists(PackageRecovery.notice));

            System.out.println("\n== Whoever wrote the list is still working (another process) ==");
            Process alive = new ProcessBuilder("sleep", "60").start();
            clearList();
            writeList(alive.pid(), false, InstallLocks.REINSTALL_TURN_PREFIX + "1");
            check("it does not touch it", UpdateManager.watchOnce().isEmpty() && PackageQueue.statePresent() && !Files.exists(PackageRecovery.notice));
            alive.destroyForcibly();
            alive.waitFor();

            System.out.println("\n== A job of this same process wrote it, still on the turn ==");
            clearList();
            check("this process takes the turn", PackageQueue.take("test-here", "test job") == null);
            writeList(ProcessHandle.current().pid(), false, "test-here");
            check("it does not touch it", UpdateManager.watchOnce().isEmpty() && PackageQueue.statePresent());
            PackageQueue.release("test-here");

            System.out.println("\n== Whoever wrote it is dead, but another process holds the turn ==");
            clearList();     // the other process takes the turn first, and then there is the list, as in a real job
            String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
            Process holder = new ProcessBuilder(java, "-cp", System.getProperty("java.class.path"),
                    "org.mail_panel.system.TurnHolder", PackageQueue.list.toString(), "test turn")
                    .redirectErrorStream(true).start();
            BufferedReader out = new BufferedReader(new InputStreamReader(holder.getInputStream(), StandardCharsets.UTF_8));
            String line;
            boolean held = false;
            while ((line = out.readLine()) != null) { if (line.contains("HELD")) { held = true; break; } }
            check("the other process holds the turn", held);
            writeList(deadPid(), false, InstallLocks.REINSTALL_TURN_PREFIX + "2");
            String r = UpdateManager.watchOnce();
            check("the recovery touches nothing and says why", r.contains("another panel process holds the package turn")
                    && PackageQueue.statePresent() && !Files.exists(PackageRecovery.notice));
            holder.getOutputStream().close();
            holder.waitFor();

            System.out.println("\n== The notice of an interrupted reinstallation ==");
            PackageRecovery.recordInterruption(new JSONObject().put("description", "complete mail server installation")
                    .put("turnId", InstallLocks.REINSTALL_TURN_PREFIX + "3"), List.of("dovecot"), List.of("dovecot"), "");
            JSONObject n = PackageRecovery.notice();
            check("the notice knows it was the reinstallation", n.optBoolean("reinstall"));
            String text = PackageRecovery.text(n.put("wayBack", "reinstall-before-2026-11-06-120000"));
            check("and it says how to go back with its way back", text.contains("bectl activate reinstall-before-2026-11-06-120000"));
            check("and that mail may be stopped", text.contains("mail services may be stopped"));
            check("it no longer says \"at startup\"", !text.contains("at startup"));
            text = PackageRecovery.text(n.put("wayBack", ""));
            check("without a way back it says so", text.contains("no way back"));
            Files.deleteIfExists(PackageRecovery.notice);
            PackageRecovery.recordInterruption(new JSONObject().put("description", "installing nginx")
                    .put("turnId", "install-4"), List.of("nginx"), List.of(), "");
            n = PackageRecovery.notice();
            check("installing a package from the page is not the reinstallation", !n.optBoolean("reinstall")
                    && !PackageRecovery.text(n).contains("complete reinstallation"));
        } finally {
            try (var walk = Files.walk(d)) {
                for (Path q : walk.sorted((x, y) -> y.compareTo(x)).toList()) Files.deleteIfExists(q);
            }
        }
        System.out.println(failed == 0 ? "\nAll checks passed." : "\n" + failed + " checks FAILED.");
        System.exit(failed == 0 ? 0 : 1);
    }
}
