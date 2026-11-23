package org.daemoxcp.mail.system;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.daemoxcp.mail.util.Shell;

/**
 * The scheduled restart: until the machine comes back up the panel changes nothing.
 *
 * <p>The owner, on 2026-11-09, while scheduling the restart of the production server: "when I set the schedule
 * for the restart, you must not let me do anything in the panel until it restarts, otherwise unpleasant things
 * could happen". A job started one minute before the shutdown stays half done (a pkg replacing the libraries, a
 * configuration file rewritten without the reload), and nobody sees it until the next restart.
 *
 * <p>How: every request that can change something ({@code Access.changes}) is refused as long as the
 * {@code shutdown} process exists (scheduled from the panel or from SSH: the same process). What remains: reads,
 * cancelling the restart, restarting right away and the restart status ({@link #exempt}). Only the root part knows
 * it: the web part does not see other users' processes ({@code security.bsd.see_other_uids=0}) and asks the root
 * part.
 *
 * <p>The time: the one written by the panel when it schedules it ({@link #AT}, valid only if the process is the
 * same), or derived from the command ({@code shutdown -r +N}: started so many seconds ago, plus N minutes). For the
 * other formats we know there is one, not when.
 */
public final class RestartLock {

    private RestartLock() {}

    private static final Logger LOGGER = Logger.getLogger(RestartLock.class.getName());

    /** Where the panel writes the process and the time of the restart it schedules: "pid milliseconds". */
    static Path AT = Path.of("/var/db/daemoxcp-mail/reboot-at");

    /** The status. known false: it could not be read (pgrep did not answer). at 0: the time is unknown. */
    public record State(boolean scheduled, long at, boolean known) {
        public static final State NONE = new State(false, 0, true);
        public static final State UNKNOWN = new State(false, 0, false);
    }

    /** What remains possible with the scheduled restart, by route: cancelling it, restarting right away, its status. */
    private static final Map<String, Set<String>> EXEMPT = Map.of(
            "/api/updates", Set.of("reboot_cancel", "reboot_now", "reboot_state"));

    public static boolean exempt(String route, String action) {
        // Map.of does not accept null even on lookup: without a route or without an action, no exemption applies.
        if (route == null || action == null) return false;
        Set<String> s = EXEMPT.get(route);
        return s != null && s.contains(action);
    }

    private static volatile State cached;
    private static volatile long cachedAt;
    /** A few seconds: a page that saves three things in a row does not launch three pgrep. */
    private static final long TTL_MS = 3000;

    /** The status now (root only). */
    public static State current() {
        long now = System.currentTimeMillis();
        State c = cached;
        if (c != null && now - cachedAt < TTL_MS) return c;
        State s = read(now);
        cached = s;
        cachedAt = now;
        return s;
    }

    /** After scheduling or cancelling it: the next request reads it again. */
    public static void forget() {
        cachedAt = 0;
    }

    private static State read(long now) {
        Shell.Result r = Shell.run(Duration.ofSeconds(10), "/bin/pgrep", "-x", "shutdown");
        String out = r.output() == null ? "" : r.output().trim();
        // pgrep: 0 found, 1 none; anything else is an error, and "I don't know" does not count as "no restart".
        if (r.exitCode() == 1 && out.isEmpty()) return State.NONE;
        if (!r.success()) return State.UNKNOWN;
        String pid = out.split("\\s+")[0];
        if (!pid.matches("[0-9]{1,7}")) return State.UNKNOWN;
        long at = recordedAt(pid);
        if (at == 0) {
            Shell.Result p = Shell.run(Duration.ofSeconds(10), "/bin/ps", "-o", "etimes=", "-o", "command=", "-p", pid);
            if (p.success() && p.output() != null) at = atFromPs(p.output().trim(), now);
        }
        return new State(true, at, true);
    }

    /** The time written by the panel, if it belongs to this process. */
    private static long recordedAt(String pid) {
        try {
            if (!Files.isRegularFile(AT)) return 0;
            String[] f = Files.readString(AT, StandardCharsets.UTF_8).trim().split("\\s+");
            if (f.length == 2 && f[0].equals(pid) && f[1].matches("[0-9]{1,15}")) return Long.parseLong(f[1]);
        } catch (Exception e) {
            LOGGER.log(Level.FINE, "reboot-at unreadable", e);
        }
        return 0;
    }

    /**
     * From a ps line ("seconds command"): the time for "shutdown -r +N" and "shutdown -r now", 0 for the other
     * formats (an absolute time: we know there is a restart, not when).
     */
    static long atFromPs(String line, long now) {
        String[] f = line.trim().split("\\s+");
        if (f.length < 2 || !f[0].matches("[0-9]{1,10}")) return 0;
        long started = now - Long.parseLong(f[0]) * 1000;
        for (int i = 2; i < f.length; i++) {
            String a = f[i];
            if (a.startsWith("-")) continue;
            if (a.equals("now")) return started;
            if (a.matches("\\+[0-9]{1,5}")) return started + Long.parseLong(a.substring(1)) * 60_000;
            return 0;
        }
        return 0;
    }

    /** The panel has just scheduled it: process and time, to state it correctly on every page. */
    public static void record(String pid, long at) {
        try {
            if (pid == null || !pid.matches("[0-9]{1,7}")) return;
            Files.writeString(AT, pid + " " + at + "\n", StandardCharsets.UTF_8);
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "reboot-at not written: the time of the restart will be read from ps", e);
        }
        forget();
    }

    /** Cancelled: the time no longer counts. */
    public static void cleared() {
        try {
            Files.deleteIfExists(AT);
        } catch (Exception e) {
            LOGGER.log(Level.FINE, "reboot-at not removed", e);
        }
        forget();
    }
}
