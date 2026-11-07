package org.mail_panel.system;

import org.json.JSONObject;

/**
 * A job has finished when it has finished, not when it has an outcome.
 *
 * The full maintenance wrote "completed" as soon as pkg upgrade exited with 0, and AFTERWARDS
 * compared with the plan and the inventory, locked the packages again, checked protections and
 * services: five steps that can change the outcome to "error". The page (updPoll) stops asking at
 * the first outcome it sees. Measured on the FreeBSD 15.1 VM on 23/10/2026: a probe stopped at the
 * first "completed" found 14 packages of 39 still to lock again, and the log without the final
 * verification.
 *
 * The checks are written to FAIL without the fix: 3 and 7 reproduce the job that says
 * "completed" and then goes on, and look at what the page would have seen.
 */
public class JobVisibleStatusTest {

    private static int failures = 0;

    public static void main(String[] args) throws Exception {

        // --- 1. The states before an outcome stay as they are ---
        UpdateManager.Job j = new UpdateManager.Job("test-1", "test");
        check("a job just created is \"pending\"", "pending".equals(seenStatus(j)));
        j.status = "running";
        check("a running job is \"running\"", "running".equals(seenStatus(j)));

        // --- 2. "completed" without the end written: the job has not finished ---
        j.status = "completed";
        check("\"completed\" with the job still open shows as \"running\"", "running".equals(seenStatus(j)));
        j.finishedAt = System.currentTimeMillis();
        check("  and it shows as \"completed\" as soon as the end is written", "completed".equals(seenStatus(j)));

        // --- 3. The same for "error" ---
        UpdateManager.Job e = new UpdateManager.Job("test-3", "test");
        e.status = "error";
        e.errorMessage = "something";
        check("\"error\" with the job still open shows as \"running\"", "running".equals(seenStatus(e)));
        e.finishedAt = System.currentTimeMillis();
        check("  and it shows as \"error\" as soon as the end is written", "error".equals(seenStatus(e)));
        check("  with its message", "something".equals(e.toJson().optString("errorMessage")));

        // --- 4. The end written by the floor, when the job forgets it ---
        UpdateManager.Job d = new UpdateManager.Job("test-4", "test");
        UpdateManager.withEndMarked(d, () -> d.status = "completed").run();
        check("a job that gives the outcome without writing the end does not stay \"running\" forever",
             "completed".equals(seenStatus(d)) && d.finishedAt > 0);

        // --- 5. ... even when it exits with an exception ---
        UpdateManager.Job x = new UpdateManager.Job("test-5", "test");
        boolean propagated = false;
        try {
            UpdateManager.withEndMarked(x, () -> { x.status = "error"; throw new IllegalStateException("fault"); }).run();
        } catch (IllegalStateException ex) { propagated = true; }
        check("a job that exits with an exception has the end written", x.finishedAt > 0 && "error".equals(seenStatus(x)));
        check("  and the exception is not swallowed", propagated);

        // --- 6. The floor does not move the end of whoever wrote it ---
        UpdateManager.Job f = new UpdateManager.Job("test-6", "test");
        UpdateManager.withEndMarked(f, () -> { f.status = "completed"; f.finishedAt = 12345L; }).run();
        check("the end written by the job stays", f.finishedAt == 12345L);

        // --- 7. The real shape of the maintenance, looked at as the page looks at it ---
        // The job says "completed", then locks again and verifies, then writes the end. Whoever
        // asks for the state while the job runs must never see an outcome without the final check.
        UpdateManager.Job m = new UpdateManager.Job("test-7", "test");
        Thread work = new Thread(UpdateManager.withEndMarked(m, () -> {
            m.status = "running";
            m.write("pkg upgrade ended with code 0");
            m.status = "completed";
            try {
                for (int i = 1; i <= 5; i++) { Thread.sleep(60); m.write("  locked again " + i + "/5"); }
                Thread.sleep(60);
                m.write("Verification passed");
            } catch (InterruptedException ie) { Thread.currentThread().interrupt(); }
            finally { m.finishedAt = System.currentTimeMillis(); }
        }));
        work.setDaemon(true);
        work.start();
        String firstOutcome = null, logAtFirstOutcome = null;
        long t0 = System.currentTimeMillis();
        while (System.currentTimeMillis() - t0 < 10_000) {
            JSONObject s = m.toJson();
            String st = s.optString("status");
            if ("completed".equals(st) || "error".equals(st)) {
                firstOutcome = st;
                logAtFirstOutcome = s.optString("consoleLog");
                break;
            }
            Thread.sleep(10);
        }
        check("the page sees an outcome (" + firstOutcome + ")", "completed".equals(firstOutcome));
        check("  and when it sees it the relocking is over",
             logAtFirstOutcome != null && logAtFirstOutcome.contains("locked again 5/5"));
        check("  and the final verification is there", logAtFirstOutcome != null && logAtFirstOutcome.contains("Verification passed"));

        // --- 8. The outcome changed in the finally reaches the page ---
        // It is the case that did harm: "completed" in the body, then the relocking fails and the
        // finally changes it to "error". The page, stopped at the first "completed", did not know.
        UpdateManager.Job g = new UpdateManager.Job("test-8", "test");
        Thread failing = new Thread(UpdateManager.withEndMarked(g, () -> {
            g.status = "completed";
            try { Thread.sleep(200); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); }
            g.status = "error";
            g.errorMessage = "protection lost";
            g.finishedAt = System.currentTimeMillis();
        }));
        failing.setDaemon(true);
        failing.start();
        firstOutcome = null;
        t0 = System.currentTimeMillis();
        while (System.currentTimeMillis() - t0 < 10_000) {
            String st = g.toJson().optString("status");
            if ("completed".equals(st) || "error".equals(st)) { firstOutcome = st; break; }
            Thread.sleep(10);
        }
        check("an outcome changed to \"error\" after \"completed\" arrives as \"error\" (" + firstOutcome + ")",
             "error".equals(firstOutcome));

        System.out.println(failures == 0 ? "\nALL OK" : "\n" + failures + " CHECKS FAILED");
        if (failures > 0) System.exit(1);
    }

    /** The state as the page receives it: it is the only one that counts. */
    private static String seenStatus(UpdateManager.Job j) {
        return j.toJson().optString("status");
    }

    private static void check(String name, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + name);
        if (!ok) failures++;
    }
}
