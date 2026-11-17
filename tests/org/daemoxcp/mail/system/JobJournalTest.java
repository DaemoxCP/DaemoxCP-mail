package org.daemoxcp.mail.system;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;
import org.json.JSONArray;
import org.json.JSONObject;
import org.daemoxcp.mail.i18n.I18n;

/**
 * The jobs' log on disk (JobJournal, reperto 196): a log per job that survives a restart of the panel or of the
 * server, read from Diagnostics.
 *
 * In a temporary folder (mailpanel.jobs.dir is set before the class loads): a job writes its start, its lines with
 * the UTC time, its end with status, error and duration, once only; the folder is 0700 and the files 0600; only the
 * newest KEEP stay; the list comes newest first with the type and the status read from the end; a job that never
 * ended says so; reading takes only a well formed name inside the folder (no "..", no absolute path, no other file).
 */
public class JobJournalTest {

    private static int failures = 0;

    public static void main(String[] args) throws Exception {
        I18n.setCurrent("en");
        Path dir = Files.createTempDirectory("job-journal-test").resolve("jobs");
        JobJournal.dir = dir;
        try {
            UpdateManager.Job a = new UpdateManager.Job("osp-1", "os-patch");
            a.write("first line");
            a.write("second line");
            a.status = "completed";
            a.outcome = "Installed: FreeBSD 15.1-RELEASE-p6.";
            a.finish();
            a.finish();
            Path fa = JobJournal.files().get(0);
            String text = Files.readString(fa);
            System.out.println("== one job ==\n" + text.trim().replaceAll("(?m)^", "    "));
            check("the folder exists, only for root (0700)", PosixFilePermissions.toString(Files.getPosixFilePermissions(dir)).equals("rwx------"));
            check("the file only for root (0600)", PosixFilePermissions.toString(Files.getPosixFilePermissions(fa)).equals("rw-------"));
            check("the name: UTC time, type, id", fa.getFileName().toString().matches("[0-9]{8}-[0-9]{6}-os-patch__osp-1\\.log"));
            check("the start line", text.startsWith("=== job osp-1 (os-patch) started 20"));
            check("every line with its UTC time", text.matches("(?s).*\\n20[0-9-]+T[0-9:]+Z first line\\n20[0-9-]+T[0-9:]+Z second line\\n.*"));
            check("the end: status, outcome and duration, once only",
                    text.contains("=== end: completed after ") && text.contains("outcome: Installed: FreeBSD 15.1-RELEASE-p6.")
                    && text.split("=== end:", -1).length == 2);

            UpdateManager.Job b = new UpdateManager.Job("jump-2", "jump");
            b.write("round 1");
            b.status = "error";
            b.errorMessage = "freebsd-update install\nended with code 1";
            b.finish();
            UpdateManager.Job c = new UpdateManager.Job("sys-3", "system");
            c.write("never ends: the panel stops here");

            System.out.println("\n== the list ==");
            JSONArray list = JobJournal.list(10).getJSONArray("journals");
            for (int i = 0; i < list.length(); i++) System.out.println("    " + list.getJSONObject(i));
            check("three logs", list.length() == 3);
            String statuses = "";
            for (int i = 0; i < list.length(); i++) statuses += list.getJSONObject(i).getString("type") + "=" + list.getJSONObject(i).getString("status") + " ";
            check("the type from the name, the status from the end: " + statuses.trim(),
                    statuses.contains("os-patch=completed") && statuses.contains("jump=error") && statuses.contains("system=unfinished"));
            check("the error on one line in the end line", Files.readString(JobJournal.files().stream()
                    .filter(p -> p.toString().contains("jump__")).findFirst().get()).contains("error: freebsd-update install ended with code 1"));

            System.out.println("\n== reading ==");
            String name = fa.getFileName().toString();
            JSONObject r = JobJournal.read(name);
            check("a log by its name", r.optBoolean("success") && r.getString("text").contains("second line"));
            Files.writeString(dir.getParent().resolve("secret.log"), "not a job log");
            for (String bad : List.of("../secret.log", "/etc/passwd", "20261108-214037-x__y.log/../../secret.log", "secret.log",
                    "20261108-214037-..__x.log", "")) {
                JSONObject x = JobJournal.read(bad);
                check("refused: \"" + bad + "\"", !x.optBoolean("success") && !x.optString("text").contains("not a job log"));
            }
            check("a well formed name that does not exist: refused", !JobJournal.read("20000101-000000-x__y.log").optBoolean("success"));

            System.out.println("\n== what is done before the end (reperto 207) ==");
            // On the VM "Update everything" wrote the way back's cleanup AFTER "=== end", and the list, which reads the
            // last line, called it unfinished. The cleanup now runs before the end, outside the job's lock.
            UpdateManager.Job e = new UpdateManager.Job("all-5", "update_everything");
            e.write("step 1 of 1");
            String[] seen = {""};
            e.beforeEnd(() -> {
                Thread t = new Thread(() -> seen[0] = e.toJson().getString("status"));
                t.start();
                try { t.join(5000); } catch (InterruptedException x) { Thread.currentThread().interrupt(); }
                e.write("Way back: older boot environment packages-before-x removed");
            });
            e.status = "completed";
            e.finish();
            e.runBeforeEnd();
            e.finish();
            String te = Files.readString(JobJournal.files().stream().filter(p -> p.toString().contains("update_everything__all-5")).findFirst().get());
            String[] lines = te.trim().split("\n");
            check("the cleanup line before the end, once; the end the last line, once",
                    te.indexOf("Way back") > 0 && te.indexOf("Way back") < te.indexOf("=== end:") && lines[lines.length - 1].contains("=== end: completed")
                    && te.split("Way back", -1).length == 2 && te.split("=== end:", -1).length == 2);
            check("meanwhile the page, asking from another thread, gets an answer: still running (" + seen[0] + ")", seen[0].equals("running"));
            UpdateManager.Job g = new UpdateManager.Job("g-6", "search");
            g.beforeEnd(() -> { throw new IllegalStateException("bectl failed"); });
            g.status = "error";
            g.finish();
            check("a cleanup that throws does not stop the end", Files.readString(JobJournal.files().stream()
                    .filter(p -> p.toString().contains("search__g-6")).findFirst().get()).contains("=== end: error"));
            UpdateManager.Job h = new UpdateManager.Job("h-7", "update_plain");
            h.write("a job that does not write its end");
            h.beforeEnd(() -> h.write("cleanup"));
            h.runBeforeEnd();
            h.markFinished();
            String th = Files.readString(JobJournal.files().stream().filter(p -> p.toString().contains("update_plain__h-7")).findFirst().get());
            check("without its own end: the cleanup when the work returns, the end after it",
                    th.indexOf("cleanup") > 0 && th.indexOf("cleanup") < th.indexOf("=== end:") && th.split("cleanup", -1).length == 2);
            JSONArray after = JobJournal.list(20).getJSONArray("journals");
            boolean listed = false;
            for (int i = 0; i < after.length(); i++)
                if (after.getJSONObject(i).getString("type").equals("update_everything")) listed = after.getJSONObject(i).getString("status").equals("completed");
            check("listed as completed, not as unfinished", listed);

            System.out.println("\n== logs of before, and errors redone well (reperto 212) ==");
            // Before build 554 the way back's cleanup wrote a line AFTER the end: that log ended, and must read so.
            Path old = dir.resolve("20261109-070942-pkg_branch__branch-1.log");
            Files.writeString(old, "=== job branch-1 (pkg_branch) started 2026-11-09T07:09:42Z ===\n2026-11-09T07:09:56Z === end: completed after 14 s ===\n"
                    + "2026-11-09T07:09:56Z Way back: no package changed, so packages-before-x is not needed: removed.\n");
            check("a log of before with a line after its end: completed, not \"without an end\"", "completed".equals(JobJournal.endLine(old).contains("=== end: completed") ? "completed" : "x"));
            JSONArray settled = new JSONArray()
                    .put(new JSONObject().put("type", "update_everything").put("status", "completed"))
                    .put(new JSONObject().put("type", "update_everything").put("status", "error"))
                    .put(new JSONObject().put("type", "update").put("status", "error"))
                    .put(new JSONObject().put("type", "os-patch").put("status", "error"))
                    .put(new JSONObject().put("type", "pkg_branch").put("status", "unfinished"));
            JobJournal.settle(settled);
            check("an error of a package job followed by a package job that ended well: settled (also of another type of the family)",
                    settled.getJSONObject(1).getBoolean("settled") && settled.getJSONObject(2).getBoolean("settled"));
            check("  one of another family (the base system), or with nothing after it: not settled",
                    !settled.getJSONObject(3).getBoolean("settled") && !settled.getJSONObject(4).getBoolean("settled"));
            check("  a job that ended well is never settled", !settled.getJSONObject(0).getBoolean("settled"));
            Files.delete(old);

            System.out.println("\n== only the newest stay ==");
            JobJournal.keep = 4;
            for (int i = 0; i < 6; i++) {
                Files.writeString(dir.resolve("20200101-00000" + i + "-old__" + i + ".log"), "old " + i + "\n");
            }
            new UpdateManager.Job("new-9", "search").finish();
            List<Path> left = JobJournal.files();
            check("4 left after the next job (" + left.size() + ")", left.size() == 4);
            check("  the newest: the new one and the three of today, none of the old ones",
                    left.stream().anyMatch(p -> p.toString().contains("search__new-9"))
                    && left.stream().noneMatch(p -> p.getFileName().toString().startsWith("20200101")));

            System.out.println("\n== a folder that cannot be written ==");
            // A plain file where the folder should be: not creatable, even as root.
            Path blocker = dir.getParent().resolve("a-file");
            Files.writeString(blocker, "");
            JobJournal.dir = blocker.resolve("jobs");
            UpdateManager.Job d = new UpdateManager.Job("x-1", "search");
            d.write("the job goes on");
            d.finish();
            check("the job goes on without its log on disk", d.toJson().getString("consoleLog").contains("the job goes on"));
        } finally {
            new ProcessBuilder("rm", "-rf", dir.getParent().toString()).start().waitFor();
        }
        System.out.println(failures == 0 ? "\nALL OK" : "\n" + failures + " CHECKS FAILED");
        System.exit(failures == 0 ? 0 : 1);
    }

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failures++;
    }
}
