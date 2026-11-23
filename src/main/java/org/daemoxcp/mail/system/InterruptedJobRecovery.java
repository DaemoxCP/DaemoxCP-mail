package org.daemoxcp.mail.system;

import org.json.JSONArray;
import org.json.JSONObject;
import org.daemoxcp.mail.i18n.I18n;
import org.daemoxcp.mail.util.Shell;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.logging.Logger;

/**
 * A package job that died halfway completes itself: the panel in service checks what the job had changed,
 * puts the services back in service and verifies.
 *
 * <p>Before (finding 152) the panel locked the packages again and left a notice: "the job did not run its final
 * checks, do them by hand: pkg check -s, restart the services, reinstall a package whose script might not have
 * finished". The owner (2026-11-08): the panel has to do them. Now, when it finds the trace of a job
 * (PackageQueue.runningRecord) whose process is gone:
 * <ol>
 *   <li>it waits for pkg to finish and for the packages to be locked again, and takes the package turn: no other
 *       package job in the meantime;</li>
 *   <li>it compares the packages now with those the trace had at the start: what changed is what the job did
 *       before dying;</li>
 *   <li>it checks the files of the changed packages (pkg check -s) and reinstalls those that do not match;</li>
 *   <li>for each service of those packages: if it still runs with the old files (started before the last package
 *       that concerns it) it restarts it, after having it test its configuration, and checks that the pid has
 *       changed; if it was running at the start and is stopped now it starts it again; then its data (redis);</li>
 *   <li>verifies: the services running at the start are running, and the mail lookups answer (Postfix and
 *       Dovecot);</li>
 *   <li>writes in the notice what it did. If everything matches, the notice is still there to be read but is no
 *       longer something to do; if something does not match, it says what and how to fix it.</li>
 * </ol>
 * It does not do this for an interrupted full reinstall (mail may be down with the configurations deleted: there
 * the way back is needed, and the notice states it), nor for an intended restart (the JVM update). A service whose
 * configuration fails the test is not restarted: restarting it would stop it.
 */
public final class InterruptedJobRecovery {

    private static final Logger LOGGER = Logger.getLogger(InterruptedJobRecovery.class.getName());

    private InterruptedJobRecovery() {}

    /** What is needed from the system, kept separate to test the decisions without real pkg or services. */
    interface Machine {
        long now();
        /** Is pkg working right now? */
        boolean pkgRunning();
        /** The packages installed now, name -> version. */
        Map<String, String> inventory();
        /** When each one was installed (seconds since the epoch), for the given names. */
        Map<String, Long> installTimes(Collection<String> names);
        /** The real (rc.d) names of the services a package concerns, itself or whatever depends on it. */
        List<String> servicesOf(String pkg);
        /** Which services are running now (only those present on the system). */
        Map<String, Boolean> servicesState();
        String pid(String service);
        /** When that process started (seconds since the epoch), -1 if unknown. */
        long processStart(String pid);
        /** The service's configuration test, or null if it has none. */
        Shell.Result configTest(String service);
        boolean restart(String service);
        boolean start(String service);
        boolean running(String service);
        /**
         * After the restart: did the service find its data again? null if there is no test, otherwise the reason
         * why not ("" = yes).
         */
        String dataCheck(String service);
        /** The packages among those given whose files do not match (pkg check -s). */
        List<String> checksumFailures(Collection<String> pkgs);
        /** Reinstalls those packages from the same catalogue, removing and putting back the locks: null if it succeeds. */
        String reinstall(List<String> pkgs);
        /** The mail lookups (Postfix and Dovecot): null if they answer, otherwise the reason. */
        String mailLookups();
    }

    /** A service to put back in service, and why. */
    enum Action { RESTART, START, CHECK }

    /** What changed between the start of the job and now: name -> {before, now} ("" = was not there / is gone). */
    static Map<String, String[]> changes(Map<String, String> before, Map<String, String> now) {
        Map<String, String[]> out = new TreeMap<>();
        Set<String> names = new LinkedHashSet<>(before.keySet());
        names.addAll(now.keySet());
        for (String n : names) {
            String b = before.getOrDefault(n, ""), a = now.getOrDefault(n, "");
            if (!b.equals(a)) out.put(n, new String[]{b, a});
        }
        return out;
    }

    /**
     * What to do with a service. RESTART if it is running but with its process started before the last package that
     * concerns it (it still runs with the old files); START if it was running at the start of the job and is stopped
     * now; CHECK if it is running and already started after it (for example after a reboot of the machine); null if it
     * was stopped and still is.
     */
    static Action decide(boolean wasRunning, boolean running, long processStart, long newestChange) {
        if (running) return processStart >= 0 && processStart > newestChange ? Action.CHECK : Action.RESTART;
        return wasRunning ? Action.START : null;
    }

    /**
     * At the start of the watchdog's round (UpdateManager.watchOnce), only in the panel in service. "" if there was
     * nothing to do or if it is too early (pkg is still working, the list is still there, someone else holds the turn).
     */
    static String completeIfInterrupted(Machine m) {
        JSONObject rec = PackageQueue.runningRecord();
        if (rec.isEmpty()) return "";
        long pid = rec.optLong("pid", 0), self = ProcessHandle.current().pid();
        if (pid == self && PackageQueue.holder() != null) return "";           // a job of this process
        if (pid > 0 && pid != self && ProcessHandle.of(pid).map(ProcessHandle::isAlive).orElse(false)) return "";
        if (rec.optBoolean("expectsRestart")) {
            PackageQueue.deleteRunning();
            return "";
        }
        // First the locks (the restore does that) and pkg idle: completing while pkg writes would mean
        // restarting services halfway through an update.
        if (PackageQueue.statePresent() || m.pkgRunning()) return "";
        String refusal = PackageQueue.takeForLocks("interrupted-recovery", I18n.tr("server.recovery.turnComplete"));
        if (refusal != null) return "";
        try {
            // Re-read with the package turn held: another process may already have closed it.
            rec = PackageQueue.runningRecord();
            if (rec.isEmpty()) return "";
            JSONObject outcome = complete(m, rec);
            PackageQueue.deleteRunning();
            return outcome == null ? "" : outcome.optString("summary");
        } finally {
            PackageQueue.release("interrupted-recovery");
        }
    }

    /** The interrupted job, completed and verified. null if it had not changed anything. */
    static JSONObject complete(Machine m, JSONObject rec) {
        String description = rec.optString("description", "");
        boolean reinstallJob = rec.optString("id", "").startsWith(InstallLocks.REINSTALL_TURN_PREFIX);
        JSONObject inv = rec.optJSONObject("inventory");
        JSONObject svc = rec.optJSONObject("services");
        Map<String, String> before = new LinkedHashMap<>();
        if (inv != null) for (String k : inv.keySet()) before.put(k, inv.optString(k));
        Map<String, Boolean> servicesBefore = new LinkedHashMap<>();
        if (svc != null) for (String k : svc.keySet()) servicesBefore.put(k, svc.optBoolean(k));

        Map<String, String> now = m.inventory();
        Map<String, String[]> changed = inv == null ? Map.of() : changes(before, now);
        Map<String, Boolean> servicesNow = m.servicesState();
        boolean fell = false;
        for (Map.Entry<String, Boolean> e : servicesBefore.entrySet())
            if (e.getValue() && !Boolean.TRUE.equals(servicesNow.get(e.getKey()))) fell = true;
        if (changed.isEmpty() && !fell) {
            LOGGER.info("[InterruptedJobRecovery] job " + rec.optString("id", "?") + " stopped before changing anything: nothing to complete");
            return null;
        }

        JSONObject r = new JSONObject().put("startedUtc", iso(m.now()));
        JSONArray changedJson = new JSONArray();
        for (Map.Entry<String, String[]> e : changed.entrySet())
            changedJson.put(new JSONObject().put("name", e.getKey()).put("from", e.getValue()[0]).put("to", e.getValue()[1]));
        r.put("changed", changedJson);
        List<String> problems = new ArrayList<>();
        // The same problems in English, for the log: the logs are in English for everyone (EnglishLogsTest).
        List<String> problemsLog = new ArrayList<>();

        if (reinstallJob) {
            // The full reinstall: no automatic restarts, the notice already states the way back.
            r.put("skipped", "reinstall");
            r.put("ok", false).put("problems", new JSONArray().put(I18n.tr("server.recovery.complete.reinstall")));
            PackageRecovery.recordRecovery(rec, r);
            return r.put("summary", "the interrupted job was the complete reinstallation: nothing restarted automatically");
        }

        // 1. The files of the packages that changed and are still installed; those that do not match are reinstalled.
        List<String> installedChanged = new ArrayList<>();
        for (Map.Entry<String, String[]> e : changed.entrySet()) if (!e.getValue()[1].isEmpty()) installedChanged.add(e.getKey());
        List<String> broken = installedChanged.isEmpty() ? List.of() : m.checksumFailures(installedChanged);
        r.put("checked", new JSONArray(installedChanged));
        if (!broken.isEmpty()) {
            String err = m.reinstall(broken);
            r.put("reinstalled", new JSONArray(broken));
            if (err != null) {
                problem(problems, problemsLog, "server.recovery.complete.reinstallFailed", Map.of("list", String.join(" ", broken), "err", err));
            } else {
                List<String> still = m.checksumFailures(broken);
                if (!still.isEmpty())
                    problem(problems, problemsLog, "server.recovery.complete.stillBroken", Map.of("list", String.join(" ", still)));
            }
        }

        // 2. The services: those of the changed packages, and those running at the start and stopped now.
        Map<String, Long> times = m.installTimes(installedChanged);
        Map<String, Long> newestFor = new LinkedHashMap<>();
        for (String p : installedChanged)
            for (String s : m.servicesOf(p))
                newestFor.merge(s, times.getOrDefault(p, m.now()), Math::max);
        for (Map.Entry<String, Boolean> e : servicesBefore.entrySet())
            if (e.getValue() && !Boolean.TRUE.equals(servicesNow.get(e.getKey()))) newestFor.putIfAbsent(e.getKey(), 0L);
        JSONArray services = new JSONArray();
        for (Map.Entry<String, Long> e : newestFor.entrySet()) {
            String s = e.getKey();
            boolean running = m.running(s);
            String pidBefore = running ? m.pid(s) : "";
            Action a = decide(Boolean.TRUE.equals(servicesBefore.get(s)), running,
                    pidBefore.isEmpty() ? -1 : m.processStart(pidBefore), e.getValue());
            if (a == null) continue;
            JSONObject o = new JSONObject().put("name", s).put("action", a.name().toLowerCase());
            if (a != Action.CHECK) {
                Shell.Result test = m.configTest(s);
                if (test != null && !test.success()) {
                    o.put("ok", false).put("why", problem(problems, problemsLog, "server.recovery.complete.configRefused", Map.of("s", s)));
                    services.put(o);
                    continue;
                }
                boolean done = a == Action.RESTART ? m.restart(s) : m.start(s);
                String pidAfter = m.running(s) ? m.pid(s) : "";
                o.put("pidBefore", pidBefore).put("pidAfter", pidAfter);
                if (!done || pidAfter.isEmpty()) {
                    o.put("ok", false).put("why", problem(problems, problemsLog, "server.recovery.complete.notRunning", Map.of("s", s)));
                    services.put(o);
                    continue;
                }
                if (a == Action.RESTART && !pidBefore.isEmpty() && pidBefore.equals(pidAfter)) {
                    o.put("ok", false).put("why", problem(problems, problemsLog, "server.recovery.complete.samePid", Map.of("s", s, "pid", pidAfter)));
                    services.put(o);
                    continue;
                }
            }
            String data = m.dataCheck(s);
            if (data != null && !data.isEmpty()) {
                o.put("ok", false).put("why", data);
                problems.add(data);
                problemsLog.add(data);
            } else {
                o.put("ok", true);
            }
            services.put(o);
        }
        r.put("services", services);

        // 3. The check: the services running at the start are running, and mail finds the mailboxes.
        Map<String, Boolean> after = m.servicesState();
        for (Map.Entry<String, Boolean> e : servicesBefore.entrySet())
            if (e.getValue() && !Boolean.TRUE.equals(after.get(e.getKey())))
                problem(problems, problemsLog, "server.recovery.complete.notRunning", Map.of("s", e.getKey()));
        String lookups = m.mailLookups();
        if (lookups != null) problem(problems, problemsLog, "server.recovery.complete.lookups", Map.of("why", lookups));

        LinkedHashSet<String> unique = new LinkedHashSet<>(problems);
        r.put("problems", new JSONArray(new ArrayList<>(unique))).put("ok", unique.isEmpty()).put("finishedUtc", iso(m.now()));
        PackageRecovery.recordRecovery(rec, r);
        String summary = description + ": " + changed.size() + " packages changed, " + services.length()
                + " services handled, " + (unique.isEmpty() ? "all verified" : "problems: " + String.join("; ", unique));
        // In the log, the job id and the problems in English; the translated summary goes to the notice.
        String logLine = "job " + rec.optString("id", "?") + ": " + changed.size() + " packages changed, " + services.length()
                + " services handled, " + (unique.isEmpty() ? "all verified"
                : "problems: " + String.join("; ", new LinkedHashSet<>(problemsLog)));
        if (unique.isEmpty()) LOGGER.info("[InterruptedJobRecovery] DONE: " + logLine);
        else LOGGER.warning("[InterruptedJobRecovery] " + logLine);
        return r.put("summary", summary);
    }

    /** A problem: in the language of whoever reads the notice, and in English for the log. Returns the translated text. */
    private static String problem(List<String> problems, List<String> forLog, String key, Map<String, ?> params) {
        String text = I18n.tr(key, params);
        problems.add(text);
        forLog.add(I18n.t("en", key, params));
        return text;
    }

    private static String iso(long epochSeconds) {
        return Instant.ofEpochSecond(epochSeconds).truncatedTo(ChronoUnit.SECONDS).toString();
    }
}
