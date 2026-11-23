package org.daemoxcp.mail.system;

import org.json.JSONArray;
import org.json.JSONObject;
import org.daemoxcp.mail.i18n.I18n;
import org.daemoxcp.mail.util.Shell;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.function.BooleanSupplier;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * After a package job that did not get to the end: lock again even when pkg is still
 * working, and SAY SO.
 *
 * Measured on the VM on 2026-11-06 (finding 147):
 *  - the panel killed halfway through an upgrade: pkg goes on and finishes by itself; the panel
 *    restarted while pkg is working fails to lock again ("PROTECTING AGAIN FAILED") and the
 *    package stayed unlocked until the NEXT restart, that is, even for weeks;
 *  - power failing during pkg: at startup the package is locked again, but it shows as
 *    installed with the install script never finished;
 *  - in both cases the only trace was a WARNING line in the log: nothing on the page, nothing
 *    in the periodic report.
 *
 * Here are the two answers: the recovery that retries by itself every RETRY_SECONDS until pkg
 * has finished, and the notice on disk (NOTICE_PATH) that the Updates page and the report
 * show until an administrator says they have checked.
 */
public final class PackageRecovery {

    private PackageRecovery() {}

    private static final Logger LOGGER = Logger.getLogger(PackageRecovery.class.getName());

    /** The notice of an interrupted job: it stays until an administrator closes it. */
    public static final String NOTICE_PATH = "/var/db/daemoxcp-mail/package-job-interrupted.json";

    /** Where the notice lives. It is a variable only so that the tests do not write in /var/db. */
    static Path notice = Path.of(NOTICE_PATH);

    /** How often to retry locking again while pkg is working. */
    static int retrySeconds = 30;

    private static Thread retry;

    /** The pkg working right now ("pid name arguments"), or "" if none. */
    static String pkgRunning() {
        return Shell.runShell(Duration.ofSeconds(15), "pgrep -lfx 'pkg(-static)? .*' 2>/dev/null").outputTrim();
    }

    private static String now() {
        return Instant.now().truncatedTo(ChronoUnit.SECONDS).toString();
    }

    /**
     * Records that a job was interrupted: which one (from the record the job wrote next to its
     * list), with which packages, which ones were still unlocked at startup, and whether pkg was
     * still working. A notice that is already there is not overwritten: it is appended to.
     */
    static void recordInterruption(JSONObject job, List<String> packages, List<String> unlockedAtStart, String pkgNow) {
        JSONObject n = new JSONObject()
                .put("description", job.optString("description", ""))
                .put("startedUtc", job.optString("startedUtc", ""))
                .put("detectedUtc", now())
                .put("packages", new JSONArray(packages))
                .put("unlockedAtStart", new JSONArray(unlockedAtStart))
                .put("pkgWasRunning", pkgNow);
        // The interrupted full reinstallation leaves mail off and the configurations deleted, not
        // just packages to lock again: the notice says so, with its way back (finding 166).
        if (job.optString("turnId", "").startsWith(InstallLocks.REINSTALL_TURN_PREFIX))
            n.put("reinstall", true).put("wayBack", PackageWayBack.newestReinstallWayBack());
        JSONObject old = notice();
        if (!old.isEmpty()) n.put("earlier", old);
        write(n);
        // In the log the job id and the packages, in English: the description is in the panel's language (notice).
        LOGGER.warning("Interrupted package job recorded in " + notice + ": job " + (job.optString("turnId", "").isEmpty()
                ? "of unknown id" : job.optString("turnId")) + ", packages " + packages);
    }

    /**
     * The interrupted job was completed by the panel (InterruptedJobRecovery): the notice says what it did and
     * whether everything adds up. If the notice was not there (a job that had unlocked nothing, and therefore did
     * not leave the list), it creates it from the job's trace.
     */
    static void recordRecovery(JSONObject running, JSONObject recovery) {
        JSONObject n = notice();
        if (n.isEmpty()) {
            List<String> names = new java.util.ArrayList<>();
            JSONArray ch = recovery.optJSONArray("changed");
            for (int i = 0; ch != null && i < ch.length(); i++) names.add(ch.getJSONObject(i).optString("name"));
            n.put("description", running.optString("description", ""))
             .put("startedUtc", running.optString("startedUtc", ""))
             .put("detectedUtc", now())
             .put("packages", new JSONArray(names))
             .put("unlockedAtStart", new JSONArray())
             .put("pkgWasRunning", "");
            if (running.optString("id", "").startsWith(InstallLocks.REINSTALL_TURN_PREFIX))
                n.put("reinstall", true).put("wayBack", PackageWayBack.newestReinstallWayBack());
        }
        write(n.put("recovery", recovery));
    }

    /** The notice states a completed and verified job: something to read, not something to do. */
    static boolean completed(JSONObject n) {
        JSONObject r = n.optJSONObject("recovery");
        return r != null && r.optBoolean("ok");
    }

    /** The packages are locked again: the notice says so, but it stays until someone checks. */
    static void markRelocked() {
        JSONObject n = notice();
        if (n.isEmpty() || n.has("relockedUtc")) return;
        write(n.put("relockedUtc", now()));
    }

    private static void write(JSONObject n) {
        try {
            Files.createDirectories(notice.getParent());
            Path tmp = notice.resolveSibling(notice.getFileName() + ".tmp");
            Files.writeString(tmp, n.toString(2) + "\n", StandardCharsets.UTF_8);
            Files.move(tmp, notice, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Cannot write " + notice, e);
        }
    }

    /**
     * For the periodic report (UpdateManager.reportData): the notice as something to do, or null if
     * there is none. The interrupted reinstallation is the most urgent thing (mail may be off) and
     * has its own title; before, it came out with the urgency and the title of any job (finding 172).
     */
    public static JSONObject reportItem() {
        JSONObject n = notice();
        // Completed and verified by the panel: there is nothing to do (the page shows it anyway).
        if (n.isEmpty() || completed(n)) return null;
        boolean reinstall = n.optBoolean("reinstall");
        return new JSONObject().put("urgency", reinstall ? 0 : 1)
                .put("title", I18n.tr(reinstall ? "mail.report.title.reinstallInterrupted" : "server.recovery.title"))
                .put("what", text(n))
                .put("where", I18n.tr(reinstall ? "mail.report.where.interrupted" : "server.um.x.updatesPage"));
    }

    /** The notice, or an empty object if there is none. */
    public static JSONObject notice() {
        try { return new JSONObject(Files.readString(notice)); }
        catch (Exception e) { return new JSONObject(); }
    }

    /** For the page: the notice and, if the list is still on disk, the packages still unlocked. */
    public static JSONObject status() {
        JSONObject r = new JSONObject().put("success", true);
        JSONObject n = notice();
        r.put("notice", n.isEmpty() ? JSONObject.NULL : n.put("text", text(n)).put("completed", completed(n)));
        if (PackageQueue.statePresent()) {
            r.put("stillUnprotected", new JSONArray(statePackages()));
            r.put("retrying", retry != null && retry.isAlive());
        }
        return r;
    }

    /** The names written in the list of the interrupted job (valid lines, without comments). */
    static List<String> statePackages() {
        try {
            return Files.readAllLines(PackageQueue.list).stream().map(String::trim)
                    .filter(l -> !l.isEmpty() && UpdateManager.isValidName(l)).toList();
        } catch (Exception e) { return List.of(); }
    }

    /**
     * The administrator has checked: the notice is closed. It is not closed while the packages are
     * still unlocked: that is not a notice to file away, it is a job to finish.
     */
    public static JSONObject dismiss() {
        if (PackageQueue.statePresent())
            return new JSONObject().put("success", false).put("error", I18n.tr("server.recovery.cannotDismiss"));
        try {
            Files.deleteIfExists(notice);
            return new JSONObject().put("success", true).put("note", I18n.tr("server.recovery.dismissed"));
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", org.daemoxcp.mail.util.ErrorText.detail("PackageRecovery", e));
        }
    }

    /**
     * Retries locking again every retrySeconds, in a separate thread, until the attempt says it
     * has finished. Only one thread at a time: a second start of the same request does not
     * create another one.
     */
    static synchronized void retryInBackground(BooleanSupplier attempt) {
        if (retry != null && retry.isAlive()) return;
        retry = new Thread(() -> {
            try {
                while (true) {
                    Thread.sleep(retrySeconds * 1000L);
                    if (attempt.getAsBoolean()) return;
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }, "package-relock-retry");
        retry.setDaemon(true);
        retry.start();
    }

    /** What the panel did when completing the job, in one sentence: packages, reinstallations, services. */
    static String actions(JSONObject r) {
        List<String> parts = new java.util.ArrayList<>();
        JSONArray ch = r.optJSONArray("changed");
        if (ch != null && ch.length() > 0) {
            List<String> list = new java.util.ArrayList<>();
            for (int i = 0; i < ch.length(); i++) {
                JSONObject c = ch.getJSONObject(i);
                list.add(c.optString("name") + " " + (c.optString("from").isEmpty() ? "-" : c.optString("from")) + " -> "
                        + (c.optString("to").isEmpty() ? "-" : c.optString("to")));
            }
            parts.add(I18n.tr("server.recovery.actions.changed", Map.of("list", String.join(", ", list))));
        }
        JSONArray re = r.optJSONArray("reinstalled");
        if (re != null && re.length() > 0)
            parts.add(I18n.tr("server.recovery.actions.reinstalled", Map.of("list",
                    String.join(" ", re.toList().stream().map(String::valueOf).toList()))));
        JSONArray sv = r.optJSONArray("services");
        List<String> handled = new java.util.ArrayList<>();
        for (int i = 0; sv != null && i < sv.length(); i++) {
            JSONObject o = sv.getJSONObject(i);
            String key = "server.recovery.actions." + o.optString("action");
            handled.add(I18n.tr(key, Map.of("s", o.optString("name"), "before", o.optString("pidBefore", "?"),
                    "after", o.optString("pidAfter", "?"))));
        }
        parts.add(handled.isEmpty() ? I18n.tr("server.recovery.actions.noServices")
                : I18n.tr("server.recovery.actions.services", Map.of("list", String.join(", ", handled))));
        return String.join(" ", parts);
    }

    /** The notice's text in the request's language, for the page and for the report. */
    static String text(JSONObject n) {
        String what = n.optString("description", "");
        String list = String.join(" ", n.optJSONArray("packages") == null ? List.of()
                : n.getJSONArray("packages").toList().stream().map(String::valueOf).toList());
        String state = !n.optString("relockedUtc").isEmpty()
                ? I18n.tr("server.recovery.relocked", java.util.Map.of("when", n.optString("relockedUtc")))
                : I18n.tr("server.recovery.notYetRelocked");
        String pkg = n.optString("pkgWasRunning", "").isEmpty() ? "" : " " + I18n.tr("server.recovery.pkgWasRunning");
        String reinstall = !n.optBoolean("reinstall") ? ""
                : " " + (n.optString("wayBack", "").isEmpty() ? I18n.tr("server.recovery.reinstallNoWayBack")
                        : I18n.tr("server.recovery.reinstallHint", java.util.Map.of("name", n.optString("wayBack"))));
        JSONObject r = n.optJSONObject("recovery");
        if (r != null && !n.optBoolean("reinstall")) {
            // The panel completed it: we say what it did, and only if something does not add up, what is left.
            Map<String, String> v = new java.util.HashMap<>();
            v.put("what", what.isEmpty() ? I18n.tr("server.recovery.unknownJob") : what);
            v.put("started", n.optString("startedUtc", "?"));
            v.put("detected", n.optString("detectedUtc", "?"));
            v.put("done", r.optString("finishedUtc", "?"));
            v.put("actions", actions(r));
            v.put("problems", String.join(" ", r.optJSONArray("problems") == null ? List.of()
                    : r.getJSONArray("problems").toList().stream().map(String::valueOf).toList()));
            return I18n.tr(r.optBoolean("ok") ? "server.recovery.completedText" : "server.recovery.completedProblemsText", v);
        }
        return I18n.tr("server.recovery.text", java.util.Map.of(
                "what", what.isEmpty() ? I18n.tr("server.recovery.unknownJob") : what,
                "started", n.optString("startedUtc", "?"),
                "detected", n.optString("detectedUtc", "?"),
                "state", state + pkg,
                "list", list.isEmpty() ? "?" : list)) + reinstall;
    }
}
