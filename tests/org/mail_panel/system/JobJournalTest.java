package org.mail_panel.system;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;
import org.json.JSONArray;
import org.json.JSONObject;
import org.mail_panel.i18n.I18n;

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
