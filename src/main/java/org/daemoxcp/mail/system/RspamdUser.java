package org.daemoxcp.mail.system;

import org.daemoxcp.mail.util.Shell;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

/**
 * rspamd entirely with the rspamd user, the main process too.
 *
 * Measured on 2026-11-07 on the production server: "rspamd: main process" runs as root, the workers as rspamd.
 * From the rspamd source (src/rspamd.c, detect_priv; src/libserver/worker_util.c): as root the main process
 * opens the ports, prepares the logs and drops privileges only for the workers with -u/-g; started directly
 * by any user it runs as that user, and -u/-g do not count. Here root is of no use: the ports are
 * 11332-11334 (above 1023), and pid, logs and databases (/var/run/rspamd, /var/log/rspamd, /var/db/rspamd)
 * already belong to rspamd. The port's rc.d script uses rc.subr, which with rspamd_user starts the command
 * as that user (su -m): it is the intended way, without touching the script.
 *
 * It is changed only if the main process runs as root and rspamd_user is not already written. After the
 * restart: all of rspamd's processes are its own, the three ports listen, the controller answers and a
 * real scan gives an action. Otherwise rspamd_user is removed and rspamd restarts as before.
 */
public final class RspamdUser {

    private static final Logger LOGGER = Logger.getLogger(RspamdUser.class.getName());

    static final String RSPAMC = "/usr/local/bin/rspamc";
    static final String USER = "rspamd";
    static final List<String> PORTS = List.of("127.0.0.1:11332", "127.0.0.1:11333", "127.0.0.1:11334");

    /** Any message to have analysed: an action must come back, whatever it is. */
    static final String PROBE = "From: probe@daemoxcp-mail.invalid\nTo: probe@daemoxcp-mail.invalid\nSubject: daemoxcp-mail rspamd probe\n"
            + "Message-ID: <rspamd-probe@daemoxcp-mail.invalid>\n\nThis message only checks that rspamd answers.\n";

    private RspamdUser() {}

    /** The users of the rspamd processes: the main process's line first, if there is one. */
    static List<String[]> processes() {
        List<String[]> out = new ArrayList<>();
        for (String l : Shell.run(Duration.ofSeconds(10), "ps", "-axww", "-o", "user=", "-o", "command=").outputTrim().split("\n")) {
            String[] p = l.trim().split("\\s+", 2);
            if (p.length == 2 && p[1].startsWith("rspamd: ")) out.add(p);
        }
        return out;
    }

    static String mainUser() {
        for (String[] p : processes()) if (p[1].startsWith("rspamd: main process")) return p[0];
        return null;
    }

    public static void ensureAtBoot() {
        try {
            if (!Files.isExecutable(Path.of("/usr/local/bin/rspamd"))) return;
            if (!"root".equals(mainUser())) return;   // off, or already with its own user
            Shell.Result rcUser = Shell.run(Duration.ofSeconds(10), "sysrc", "-n", "rspamd_user");
            if (rcUser.success() && !rcUser.outputTrim().isEmpty()) {
                LOGGER.info("[RspamdUser] rspamd_user is already set to '" + rcUser.outputTrim() + "' but the main process runs"
                        + " as root: left as it is");
                return;
            }
            if (Shell.run(Duration.ofSeconds(10), "id", "-u", USER).exitCode() != 0) return;
            apply();
        } catch (Throwable t) {
            LOGGER.warning("[RspamdUser] ensureAtBoot exception: " + t.getMessage());
        }
    }

    static boolean apply() throws Exception {
        String before = scan();
        if (before == null) {
            LOGGER.warning("[RspamdUser] rspamd does not scan a message before any change: left as it is");
            return false;
        }
        // The order matters. With rspamd_user written, rc.subr also sends the stop signals as that user,
        // and then it cannot stop the main process running as root ("kill: No such process"),
        // and the start finds rspamd "already running". Measured on the VM on 2026-11-07. So: it is stopped
        // with the previous setting, rspamd_user is written, it is started; and to go back the same
        // in reverse.
        if (!stop()) {
            Shell.run(Duration.ofSeconds(120), "service", "rspamd", "start");
            LOGGER.warning("[RspamdUser] NOT_APPLIED: rspamd did not stop within 120 seconds; started again as it was");
            return false;
        }
        Shell.run(Duration.ofSeconds(10), "sysrc", "rspamd_user=" + USER);
        Shell.run(Duration.ofSeconds(120), "service", "rspamd", "start");
        String problem = verify();
        if (problem != null) {
            stop();
            Shell.run(Duration.ofSeconds(10), "sysrc", "-x", "rspamd_user");
            Shell.run(Duration.ofSeconds(120), "service", "rspamd", "start");
            Thread.sleep(3000);
            String again = scan() != null ? "rspamd scans again" : "rspamd DOES NOT SCAN";
            LOGGER.warning("[RspamdUser] ROLLED_BACK: " + problem + "; rspamd_user removed and rspamd restarted (" + again + ")");
            return false;
        }
        LOGGER.info("[RspamdUser] DONE: rspamd runs entirely as " + USER + ", the main process no longer as root"
                + " (rspamd_user in rc.conf); a real scan checked");
        return true;
    }

    /** Stops rspamd with the current setting and waits until the main process is gone. */
    static boolean stop() throws InterruptedException {
        Shell.run(Duration.ofSeconds(120), "service", "rspamd", "stop");
        for (int i = 0; i < 60; i++) {
            if (mainUser() == null) return true;
            Thread.sleep(1000);
        }
        return false;
    }

    /** After the restart: all the processes its own, the ports open, a real scan. */
    static String verify() throws InterruptedException {
        for (int i = 0; i < 30; i++) {
            Thread.sleep(1000);
            List<String[]> ps = processes();
            boolean hasMain = ps.stream().anyMatch(p -> p[1].startsWith("rspamd: main process"));
            boolean allOwn = !ps.isEmpty() && ps.stream().allMatch(p -> USER.equals(p[0]));
            String listening = Shell.run(Duration.ofSeconds(15), "sockstat", "-4l").outputTrim();
            boolean ports = PORTS.stream().allMatch(listening::contains);
            if (hasMain && allOwn && ports && scan() != null) return null;
            if (i == 29) {
                if (!hasMain) return "rspamd is not running after the restart";
                if (!allOwn) return "rspamd processes still as " + ps.stream().map(p -> p[0]).distinct().toList();
                if (!ports) return "rspamd does not listen on " + PORTS;
                return "rspamd does not scan a message after the restart";
            }
        }
        return "unreachable";
    }

    /** A real scan on the normal worker: the action rspamd decides, or null. */
    static String scan() {
        String out = symbols(PROBE);
        if (out == null) return null;
        for (String l : out.split("\n"))
            if (l.trim().startsWith("Action:")) return l.trim().substring(7).trim();
        return null;
    }

    /** What rspamc says about that message, analysed by the normal worker; null if it cannot be asked. */
    static String symbols(String message) {
        try {
            Path f = Files.createTempFile(Path.of("/var/tmp"), "rspamd-probe-", ".eml");
            try {
                Files.writeString(f, message);
                return Shell.runShell(Duration.ofSeconds(60), RSPAMC + " -h 127.0.0.1:11333 symbols < " + f).outputTrim();
            } finally {
                Files.deleteIfExists(f);
            }
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Restarts rspamd with the current setting and waits, up to one minute, for it to analyse a message. For
     * whoever changes its configuration or groups: a process's groups are read only when it starts (RedisSocket,
     * ClamdSocket).
     */
    static boolean restart() throws InterruptedException {
        Shell.run(Duration.ofSeconds(180), "service", "rspamd", "restart");
        for (int i = 0; i < 60; i++) {
            if (scan() != null) return true;
            Thread.sleep(1000);
        }
        return false;
    }

    /** The members of a group, from /etc/group (pw groupshow); empty if the group does not exist. */
    static List<String> members(String group) {
        Shell.Result r = Shell.run(Duration.ofSeconds(10), "pw", "groupshow", group);
        if (!r.success()) return List.of();
        String[] f = r.outputTrim().split(":", -1);
        if (f.length < 4 || f[3].isBlank()) return List.of();
        return List.of(f[3].trim().split(","));
    }

    /** Adds a user to a group or removes it (pw groupmod -m/-d); true if it is now as requested. */
    static boolean setMember(String group, String user, boolean member) {
        Shell.run(Duration.ofSeconds(20), "pw", "groupmod", group, member ? "-m" : "-d", user);
        return members(group).contains(user) == member;
    }
}
