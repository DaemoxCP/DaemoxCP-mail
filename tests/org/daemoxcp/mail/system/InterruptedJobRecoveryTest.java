package org.daemoxcp.mail.system;

import org.json.JSONArray;
import org.json.JSONObject;
import org.daemoxcp.mail.i18n.I18n;
import org.daemoxcp.mail.util.Shell;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * A package job that died halfway is completed by the panel (InterruptedJobRecovery), with a fake system:
 *
 *  1. the package turn leaves its trace: written when a job takes it, with packages and services as they were, removed
 *     when it is released; the relock (takeForLocks) leaves none;
 *  2. what is changed, and what to do with a service: restart if it still runs on the old files, start if it was on
 *     and fell, only check if it already started after the change, nothing if it was off and still is;
 *  3. the completion: services restarted with their configuration tested first and a new pid, a service that falls
 *     started again, files that do not match reinstalled, the mail lookups checked; every fault (configuration
 *     refused, same pid, not running after, lookups failing, files still broken) said in the notice; a notice created
 *     for a job that had unlocked nothing; the complete reinstallation not touched;
 *  4. when it waits and when it does nothing: a job of a live process, the list still on disk, pkg still working, a
 *     restart by design; otherwise it takes the turn, completes and removes the trace.
 *
 * Usage:
 *   java -cp "tests:target/daemoxcp-mail-1.0.jar" org.daemoxcp.mail.system.InterruptedJobRecoveryTest
 */
public class InterruptedJobRecoveryTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static Shell.Result result(int code, String out) { return new Shell.Result(code, out, false, List.of()); }

    /** A fake machine: packages, services with pids and start times, and the faults to plant. */
    static final class Fake implements InterruptedJobRecovery.Machine {
        long now = 2_000_000;
        boolean pkgRunning;
        Map<String, String> inventory = new TreeMap<>();
        Map<String, Long> installed = new TreeMap<>();
        Map<String, List<String>> servicesOf = new TreeMap<>();
        Map<String, Boolean> running = new TreeMap<>();
        Map<String, Integer> pid = new TreeMap<>();
        Map<String, Long> started = new TreeMap<>();
        java.util.Set<String> configRefused = new java.util.TreeSet<>(), samePid = new java.util.TreeSet<>(),
                cannotStart = new java.util.TreeSet<>(), broken = new java.util.TreeSet<>(), stillBroken = new java.util.TreeSet<>();
        String lookups;
        String reinstallError;
        List<String> restarted = new ArrayList<>(), startedAgain = new ArrayList<>(), reinstalled = new ArrayList<>();
        int pids = 100;

        void service(String name, boolean on, long since) {
            running.put(name, on);
            if (on) { pid.put(name, ++pids); started.put(name, since); }
        }

        @Override public long now() { return now; }
        @Override public boolean pkgRunning() { return pkgRunning; }
        @Override public Map<String, String> inventory() { return new TreeMap<>(inventory); }
        @Override public Map<String, Long> installTimes(Collection<String> names) {
            Map<String, Long> m = new LinkedHashMap<>();
            for (String n : names) if (installed.containsKey(n)) m.put(n, installed.get(n));
            return m;
        }
        @Override public List<String> servicesOf(String pkg) { return servicesOf.getOrDefault(pkg, List.of()); }
        @Override public Map<String, Boolean> servicesState() { return new TreeMap<>(running); }
        @Override public String pid(String service) { return running.getOrDefault(service, false) ? String.valueOf(pid.get(service)) : ""; }
        @Override public long processStart(String p) {
            for (Map.Entry<String, Integer> e : pid.entrySet())
                if (String.valueOf(e.getValue()).equals(p)) return started.getOrDefault(e.getKey(), -1L);
            return -1;
        }
        @Override public Shell.Result configTest(String service) {
            return configRefused.contains(service) ? result(1, "syntax error") : result(0, "");
        }
        @Override public boolean restart(String s) {
            restarted.add(s);
            if (cannotStart.contains(s)) { running.put(s, false); return false; }
            if (!samePid.contains(s)) pid.put(s, ++pids);
            started.put(s, now);
            return true;
        }
        @Override public boolean start(String s) {
            startedAgain.add(s);
            if (cannotStart.contains(s)) return false;
            running.put(s, true);
            pid.put(s, ++pids);
            started.put(s, now);
            return true;
        }
        @Override public boolean running(String s) { return running.getOrDefault(s, false); }
        @Override public String dataCheck(String s) { return null; }
        @Override public List<String> checksumFailures(Collection<String> pkgs) {
            List<String> out = new ArrayList<>();
            for (String p : pkgs) if (broken.contains(p)) out.add(p);
            return out;
        }
        @Override public String reinstall(List<String> pkgs) {
            reinstalled.addAll(pkgs);
            if (reinstallError != null) return reinstallError;
            for (String p : pkgs) if (!stillBroken.contains(p)) broken.remove(p);
            return null;
        }
        @Override public String mailLookups() { return lookups; }
    }

    static Path dir;

    /** A trace of a job of a dead process: the inventory and the services at its start. */
    static JSONObject trace(String id, Map<String, String> inventory, Map<String, Boolean> services) throws Exception {
        Process p = new ProcessBuilder("true").start();
        p.waitFor();
        JSONObject inv = new JSONObject(), svc = new JSONObject();
        inventory.forEach(inv::put);
        services.forEach(svc::put);
        return new JSONObject().put("id", id).put("description", "guided update of nginx-probe")
                .put("startedUtc", "2026-11-08T10:00:00Z").put("startedEpoch", 1_000_000).put("pid", p.pid())
                .put("expectsRestart", false).put("inventory", inv).put("services", svc);
    }

    static void writeTrace(JSONObject t) throws Exception {
        Files.writeString(PackageQueue.running(), t.toString(2));
    }

    static void clean() throws Exception {
        Files.deleteIfExists(PackageQueue.running());
        Files.deleteIfExists(PackageRecovery.notice);
        Files.deleteIfExists(PackageQueue.list);
    }

    /** A machine where the job upgraded nginx-probe 1.0 -> 1.1 (installed at 1_500_000) and nginx runs since 1_200_000. */
    static Fake upgradedNginx() {
        Fake f = new Fake();
        f.inventory.put("nginx-probe", "1.1");
        f.inventory.put("postfix", "3.11");
        f.installed.put("nginx-probe", 1_500_000L);
        f.servicesOf.put("nginx-probe", List.of("nginx"));
        f.service("nginx", true, 1_200_000);
        f.service("postfix", true, 1_200_000);
        f.service("unbound", false, 0);
        return f;
    }

    static Map<String, String> before() { return Map.of("nginx-probe", "1.0", "postfix", "3.11"); }
    static Map<String, Boolean> servicesBefore() { return Map.of("nginx", true, "postfix", true, "unbound", false); }

    public static void main(String[] args) throws Exception {
        dir = Files.createTempDirectory("interrupted-recovery");
        PackageQueue.list = dir.resolve("locks");
        PackageQueue.turnLock = dir.resolve("package-turn.lock");
        PackageRecovery.notice = dir.resolve("interrupted.json");
        I18n.setCurrent("en");

        System.out.println("== 1. The trace of the turn");
        PackageQueue.snapshot = () -> new JSONObject().put("inventory", new JSONObject().put("a", "1"))
                .put("services", new JSONObject().put("nginx", true));
        check("a job takes the turn", PackageQueue.take("job-1", "a test job") == null);
        JSONObject rec = PackageQueue.runningRecord();
        check("its trace is written: who, from which process, packages and services " + rec.keySet(),
                "job-1".equals(rec.optString("id")) && rec.optLong("pid") == ProcessHandle.current().pid()
                        && "1".equals(rec.getJSONObject("inventory").optString("a")) && rec.getJSONObject("services").optBoolean("nginx"));
        check("it sits next to the turn's lock (tests that move the lock move it too)",
                PackageQueue.running().getParent().equals(dir));
        PackageQueue.release("job-1");
        check("released: the trace is gone", !Files.exists(PackageQueue.running()));
        check("the relock takes the turn without leaving a trace",
                PackageQueue.takeForLocks("relock", "relock") == null && !Files.exists(PackageQueue.running()));
        PackageQueue.release("relock");

        System.out.println("== 2. Decisions");
        Map<String, String[]> ch = InterruptedJobRecovery.changes(
                Map.of("a", "1", "b", "1", "c", "1"), Map.of("a", "2", "c", "1", "d", "1"));
        check("changes: upgraded, removed, installed, and the unchanged left out",
                ch.size() == 3 && ch.get("a")[1].equals("2") && ch.get("b")[1].isEmpty() && ch.get("d")[0].isEmpty() && !ch.containsKey("c"));
        check("running on the old files: restart", InterruptedJobRecovery.decide(true, true, 100, 200) == InterruptedJobRecovery.Action.RESTART);
        check("running, start time unknown: restart (the safe side)", InterruptedJobRecovery.decide(true, true, -1, 200) == InterruptedJobRecovery.Action.RESTART);
        check("already started after the change (a reboot): only check", InterruptedJobRecovery.decide(true, true, 300, 200) == InterruptedJobRecovery.Action.CHECK);
        check("on at the start, off now: start", InterruptedJobRecovery.decide(true, false, -1, 200) == InterruptedJobRecovery.Action.START);
        check("off at the start and now: nothing", InterruptedJobRecovery.decide(false, false, -1, 200) == null);

        System.out.println("== 3. The completion");
        clean();
        Fake f = upgradedNginx();
        JSONObject r = InterruptedJobRecovery.complete(f, trace("guid-1", before(), servicesBefore()));
        JSONObject n = PackageRecovery.notice();
        check("nginx, which still ran on the old files, restarted; postfix (not concerned) not touched",
                f.restarted.equals(List.of("nginx")));
        check("verified: ok, nothing to do, and the notice is created for a job that unlocked nothing",
                r.optBoolean("ok") && PackageRecovery.completed(n) && PackageRecovery.reportItem() == null);
        String text = PackageRecovery.text(n);
        check("the notice says what changed and what was done: " + text,
                text.contains("nginx-probe 1.0 -> 1.1") && text.contains("nginx restarted (pid 101 -> ")
                        && text.contains("nothing to do"));
        check("the page shows it as completed", PackageRecovery.status().getJSONObject("notice").optBoolean("completed"));

        clean();
        f = upgradedNginx();
        f.started.put("nginx", 1_600_000L);         // started after the package: the machine rebooted
        r = InterruptedJobRecovery.complete(f, trace("guid-2", before(), servicesBefore()));
        check("a service already on the new files is only checked, not restarted",
                f.restarted.isEmpty() && r.optBoolean("ok") && r.getJSONArray("services").getJSONObject(0).optString("action").equals("check"));

        clean();
        f = upgradedNginx();
        f.configRefused.add("nginx");
        r = InterruptedJobRecovery.complete(f, trace("guid-3", before(), servicesBefore()));
        check("a configuration refused: not restarted (it would stop), and said",
                f.restarted.isEmpty() && !r.optBoolean("ok") && r.getJSONArray("problems").toString().contains("does not accept its configuration")
                        && PackageRecovery.reportItem() != null);

        clean();
        f = upgradedNginx();
        f.samePid.add("nginx");
        r = InterruptedJobRecovery.complete(f, trace("guid-4", before(), servicesBefore()));
        check("the same pid after the restart: said", !r.optBoolean("ok") && r.getJSONArray("problems").toString().contains("same process"));

        clean();
        f = upgradedNginx();
        f.cannotStart.add("nginx");
        r = InterruptedJobRecovery.complete(f, trace("guid-5", before(), servicesBefore()));
        check("a service that does not come back: said", !r.optBoolean("ok") && r.getJSONArray("problems").toString().contains("nginx is not running"));

        clean();
        f = upgradedNginx();
        f.running.put("postfix", false);             // fell during the job
        r = InterruptedJobRecovery.complete(f, trace("guid-6", before(), servicesBefore()));
        check("a service on at the start and off now is started again", f.startedAgain.equals(List.of("postfix")) && r.optBoolean("ok"));
        check("unbound, off at the start, stays off", !f.startedAgain.contains("unbound") && !f.restarted.contains("unbound"));

        clean();
        f = upgradedNginx();
        f.broken.add("nginx-probe");
        r = InterruptedJobRecovery.complete(f, trace("guid-7", before(), servicesBefore()));
        check("files that do not match are reinstalled, then checked again: ok",
                f.reinstalled.equals(List.of("nginx-probe")) && r.optBoolean("ok") && PackageRecovery.text(PackageRecovery.notice()).contains("Reinstalled"));
        clean();
        f = upgradedNginx();
        f.broken.add("nginx-probe");
        f.stillBroken.add("nginx-probe");
        r = InterruptedJobRecovery.complete(f, trace("guid-8", before(), servicesBefore()));
        check("still broken after the reinstallation: said", !r.optBoolean("ok") && r.getJSONArray("problems").toString().contains("still do not match"));

        clean();
        f = upgradedNginx();
        f.lookups = "doveadm auth lookup: exit 75";
        r = InterruptedJobRecovery.complete(f, trace("guid-9", before(), servicesBefore()));
        check("the mail lookups failing: said", !r.optBoolean("ok") && r.getJSONArray("problems").toString().contains("mail lookups"));

        clean();
        f = upgradedNginx();
        r = InterruptedJobRecovery.complete(f, trace(InstallLocks.REINSTALL_TURN_PREFIX + "x", before(), servicesBefore()));
        check("the complete reinstallation: nothing restarted, the notice keeps it as a thing to do",
                f.restarted.isEmpty() && f.startedAgain.isEmpty() && !r.optBoolean("ok") && PackageRecovery.reportItem() != null);

        clean();
        f = upgradedNginx();
        f.inventory.put("nginx-probe", "1.0");
        r = InterruptedJobRecovery.complete(f, trace("guid-10", before(), servicesBefore()));
        check("stopped before changing anything: nothing done, no notice", r == null && f.restarted.isEmpty() && PackageRecovery.notice().isEmpty());

        System.out.println("== 4. When it waits");
        clean();
        writeTrace(trace("guid-11", before(), servicesBefore()).put("pid", ProcessHandle.current().pid()));
        PackageQueue.take("guid-11-live", "a live job of this process");
        f = upgradedNginx();
        check("a job of this process still running: nothing", InterruptedJobRecovery.completeIfInterrupted(f).isEmpty() && f.restarted.isEmpty());
        PackageQueue.release("guid-11-live");

        clean();
        Process live = new ProcessBuilder("sleep", "30").start();
        writeTrace(trace("guid-12", before(), servicesBefore()).put("pid", live.pid()));
        f = upgradedNginx();
        check("a job of another live process: nothing", InterruptedJobRecovery.completeIfInterrupted(f).isEmpty() && Files.exists(PackageQueue.running()));
        live.destroy();

        clean();
        writeTrace(trace("guid-13", before(), servicesBefore()).put("expectsRestart", true));
        f = upgradedNginx();
        check("a restart by design: the trace goes, nothing done",
                InterruptedJobRecovery.completeIfInterrupted(f).isEmpty() && !Files.exists(PackageQueue.running()) && f.restarted.isEmpty());

        clean();
        writeTrace(trace("guid-14", before(), servicesBefore()));
        Files.writeString(PackageQueue.list, "nginx-probe\n");
        f = upgradedNginx();
        check("the list of unlocked packages still on disk: it waits", InterruptedJobRecovery.completeIfInterrupted(f).isEmpty()
                && Files.exists(PackageQueue.running()) && f.restarted.isEmpty());
        Files.delete(PackageQueue.list);
        f.pkgRunning = true;
        check("pkg still working: it waits", InterruptedJobRecovery.completeIfInterrupted(f).isEmpty() && Files.exists(PackageQueue.running()));
        f.pkgRunning = false;
        String done = InterruptedJobRecovery.completeIfInterrupted(f);
        check("then it completes, removes the trace and gives the turn back (" + done + ")",
                done.contains("all verified") && !Files.exists(PackageQueue.running()) && PackageQueue.holder() == null
                        && f.restarted.equals(List.of("nginx")));

        clean();
        System.out.println(failed == 0 ? "ALL OK" : failed + " FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }
}
