package org.mail_panel.system;

import java.time.Duration;
import org.mail_panel.util.Shell;

/**
 * The standard input of the updater's commands.
 *
 * Every command of the updates area goes through {@code Shell} (the reads: pkg query, pkg lock,
 * service status) or {@code UpdateManager.runLogged} (the long jobs: pkg upgrade, freebsd-update
 * install). With ProcessBuilder's default pipe a child that reads gets neither data nor EOF: it
 * waits until the timeout, which here is 1800 or 3600 seconds, and meanwhile the package turn is
 * taken and every other operation is refused. Measured on the FreeBSD 15.1 VM on 23/10/2026:
 * 8102 ms on an 8 s timeout, exit -1; with /dev/null 3 ms.
 *
 * The checks are written to FAIL without the fix: a wait until the timeout shows both in the
 * outcome (exit -1, timedOut) and in the elapsed time.
 */
public class ChildStdinTest {

    private static int failures = 0;

    /** Timeout of the test commands: long enough for a wait to stand out from work. */
    private static final int TIMEOUT = 8;

    /** Beyond this a trivial command is not slow, it is waiting. */
    private static final long IMMEDIATE_MS = 4000;

    public static void main(String[] args) throws Exception {

        // --- 1. Shell.runShell: a command that reads from stdin ---
        long t = System.currentTimeMillis();
        Shell.Result r = Shell.runShell(Duration.ofSeconds(TIMEOUT), "read x; echo \"read [$x]\"");
        long duration = System.currentTimeMillis() - t;
        check("runShell: the command that reads does not wait (" + duration + " ms)", duration < IMMEDIATE_MS);
        check("runShell: no timeout", !r.timedOut());
        check("runShell: exit 0, not -1", r.exitCode() == 0);
        check("runShell: the command reached its end", r.outputTrim().contains("read []"));

        // --- 2. Shell.run, the form with separate arguments: same code, declared outcome ---
        t = System.currentTimeMillis();
        r = Shell.run(Duration.ofSeconds(TIMEOUT), "sh", "-c", "read x; echo \"read [$x]\"");
        duration = System.currentTimeMillis() - t;
        check("run: the command that reads does not wait (" + duration + " ms)", duration < IMMEDIATE_MS);
        check("run: exit 0 and no timeout", r.exitCode() == 0 && !r.timedOut());

        // --- 3. runLogged, the way of the long jobs ---
        UpdateManager.Job job = new UpdateManager.Job("stdin-test", "test");
        t = System.currentTimeMillis();
        int exitCode = UpdateManager.runLogged(job, "read x; echo \"read [$x]\"", TIMEOUT);
        duration = System.currentTimeMillis() - t;
        String log = job.toJson().optString("consoleLog", "");
        check("runLogged: the command that reads does not wait (" + duration + " ms)", duration < IMMEDIATE_MS);
        check("runLogged: exit 0, not a killed process", exitCode == 0);
        check("runLogged: there is no timeout in the job's log",
             !log.contains("TIMEOUT") && !log.toLowerCase().contains("timeout"));
        check("runLogged: the command's output is in the log", log.contains("read []"));

        // --- 4. A command that does NOT read behaves as before ---
        r = Shell.runShell(Duration.ofSeconds(TIMEOUT), "echo hello; echo failure >&2");
        check("an ordinary command stays ordinary: exit 0",
             r.exitCode() == 0 && !r.timedOut());
        check("an ordinary command stays ordinary: stdout and stderr joined",
             r.outputTrim().contains("hello") && r.outputTrim().contains("failure"));

        // --- 5. EOF does not become a silent yes ---
        // A command that checks the outcome of its read notices and can fail: this check exists
        // so that whoever adds a command that asks something knows that /dev/null removes the
        // wait, it does not turn the prompt into an error. A command that does NOT check goes on
        // with the empty value (case 1: exit 0).
        r = Shell.runShell(Duration.ofSeconds(TIMEOUT), "if read x; then exit 0; else exit 7; fi");
        check("a read whose outcome is checked fails at once instead of waiting",
             r.exitCode() == 7 && !r.timedOut());

        System.out.println(failures == 0 ? "\nALL OK" : "\n" + failures + " CHECKS FAILED");
        if (failures > 0) System.exit(1);
    }

    private static void check(String name, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + name);
        if (!ok) failures++;
    }
}
