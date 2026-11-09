package org.mail_panel.system;

import org.json.JSONObject;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * The job in progress, and the logs of the jobs that never started (reperto 206).
 *
 * On the real server two "Update the packages" pressed during a search were refused, rightly, and the page did not say
 * what was running. Each refused job also left a log with its start and no end, which Diagnostics counted among the
 * jobs "ended without an end". Here:
 *  - a job's log on disk opens with its first line: a job that never writes (refused because the turn is another's)
 *    leaves no file; one that writes has its start, its lines and, at the end, its outcome;
 *  - packageTurn says who holds the turn and since when, and nothing when it is free.
 *
 * Usage (from the project root, after mvn package):
 *   javac -cp target/freebsd-mail-panel-1.0.jar -d tests tests/org/mail_panel/system/RunningJobTest.java
 *   java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.RunningJobTest
 */
public class RunningJobTest {

    private static int failed = 0;

    private static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    private static List<Path> logs(Path dir) throws Exception {
        try (var s = Files.list(dir)) { return s.toList(); }
    }

    public static void main(String[] args) throws Exception {
        Path dir = Files.createTempDirectory("running-job");
        JobJournal.dir = dir;
        try {
            System.out.println("== The log of a job opens with its first line ==");
            UpdateManager.Job refused = new UpdateManager.Job("upd-1", "update");
            check("a job that never writes (refused: the turn is another's) leaves no log", logs(dir).isEmpty());
            UpdateManager.Job real = new UpdateManager.Job("srch-1", "search");
            real.write("[1/3] The package catalog (pkg update)");
            List<Path> after = logs(dir);
            check("one that writes has its log", after.size() == 1 && after.get(0).getFileName().toString().contains("search__srch-1"));
            String text = Files.readString(after.get(0));
            check("  with its start and its line", text.startsWith("=== job srch-1 (search) started ") && text.contains("[1/3] The package catalog"));
            real.status = "completed";
            real.outcome = "Lists updated.";
            real.finish();
            text = Files.readString(after.get(0));
            check("  and at the end its outcome", text.contains("=== end: completed") && text.contains("Lists updated."));
            check("the refused one still has no log", logs(dir).size() == 1 && refused.finishedAt == 0);

            System.out.println("\n== Who holds the turn ==");
            JSONObject free = UpdateManager.packageTurn();
            check("free: nothing running", free.optBoolean("success") && !free.optBoolean("running") && !free.has("who"));
            check("a job takes the turn", PackageQueue.take("srch-2", "check for updates") == null);
            JSONObject busy = UpdateManager.packageTurn();
            check("taken: running, who and since when (" + busy.optString("who") + ")", busy.optBoolean("running")
                    && busy.optString("who").startsWith("check for updates, "));
            check("  no job id to follow when the panel has no such job in its list", !busy.has("jobId"));
            check("the id of the holder", "srch-2".equals(PackageQueue.holderId()));
            PackageQueue.release("srch-2");
            check("released: nothing running again", !UpdateManager.packageTurn().optBoolean("running") && PackageQueue.holderId() == null);
        } finally {
            try (var s = Files.walk(dir)) { s.sorted(java.util.Comparator.reverseOrder()).forEach(p -> p.toFile().delete()); }
        }
        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }
}
