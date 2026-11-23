package org.daemoxcp.mail.system;

import org.daemoxcp.mail.util.Shell;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.logging.Logger;
import java.util.regex.Pattern;

/**
 * syslogd no longer opens port 514 to the network.
 *
 * Measured on 2026-11-07 on the production server and on the VM: syslogd listens over UDP on *:514, IPv4 and IPv6.
 * It is the FreeBSD default (/etc/defaults/rc.conf: syslogd_flags="-s"): with a single -s the messages from outside
 * are discarded, but the port stays open. The manual, syslogd(8): "-s ... If specified twice, no network socket will
 * be opened at all, which also disables logging to remote machines". On the server nothing sends the logs to another
 * machine (in /etc/syslog.conf there is only "#*.* @loghost", commented out) and nothing receives them: with the
 * double -s nothing is lost.
 *
 * It is changed only if the flags are the FreeBSD ones ("-s") and no line of syslog.conf sends the logs elsewhere:
 * whoever chose different ones has their reasons. After syslogd is restarted it checks that no port was left open
 * and that a message written with logger arrives in /var/log/messages; if not, the flags go back to how they were.
 */
public final class SyslogNetwork {

    private static final Logger LOGGER = Logger.getLogger(SyslogNetwork.class.getName());

    static final List<String> CONF_FILES = List.of("/etc/syslog.conf");
    static final List<String> CONF_DIRS = List.of("/etc/syslog.d", "/usr/local/etc/syslog.d");
    static final String MESSAGES = "/var/log/messages";

    /** An active line that sends the logs to another machine: "selector @host". */
    private static final Pattern FORWARD = Pattern.compile("^[^#]*\\s@\\S");

    private SyslogNetwork() {}

    enum Action { NOTHING, APPLY, LEFT_ALONE }

    record Decision(Action action, String reason) {}

    /** Pure function: the current flags (sysrc -n) and the lines of syslog.conf. */
    static Decision decide(String flags, List<String> confLines) {
        String f = flags == null ? "" : flags.trim().replaceAll("\\s+", " ");
        if (f.equals("-ss") || f.matches("(.* )?-s( .*)? -s( .*)?") || f.matches("(.* )?-ss( .*)?"))
            return new Decision(Action.NOTHING, "syslogd already opens no network socket");
        if (!f.equals("-s"))
            return new Decision(Action.LEFT_ALONE, "syslogd_flags is '" + f + "', not FreeBSD's default: left as it is");
        for (String l : confLines)
            if (FORWARD.matcher(l).find())
                return new Decision(Action.LEFT_ALONE, "syslog sends logs to another machine (" + l.trim() + "): left as it is");
        return new Decision(Action.APPLY, "syslogd listens on UDP 514 without needing it");
    }

    static List<String> confLines() throws Exception {
        List<String> out = new ArrayList<>();
        for (String f : CONF_FILES) if (Files.isRegularFile(Path.of(f))) out.addAll(Files.readAllLines(Path.of(f)));
        for (String d : CONF_DIRS) {
            if (!Files.isDirectory(Path.of(d))) continue;
            try (var s = Files.list(Path.of(d))) {
                for (Path p : s.filter(x -> x.toString().endsWith(".conf")).sorted().toList()) out.addAll(Files.readAllLines(p));
            }
        }
        return out;
    }

    public static void ensureAtBoot() {
        try {
            if (Shell.resolve("sysrc") == null) return;
            Shell.Result flags = Shell.run(Duration.ofSeconds(10), "sysrc", "-n", "syslogd_flags");
            if (!flags.success()) return;
            Decision d = decide(flags.outputTrim(), confLines());
            switch (d.action()) {
                case NOTHING -> { return; }
                case LEFT_ALONE -> { LOGGER.info("[SyslogNetwork] " + d.reason()); return; }
                case APPLY -> apply(flags.outputTrim());
            }
        } catch (Throwable t) {
            LOGGER.warning("[SyslogNetwork] ensureAtBoot exception: " + t.getMessage());
        }
    }

    static boolean apply(String oldFlags) throws Exception {
        boolean inRcConf = Shell.run(Duration.ofSeconds(10), "sh", "-c", "grep -q '^[[:space:]]*syslogd_flags=' /etc/rc.conf").success();
        Shell.run(Duration.ofSeconds(10), "sysrc", "syslogd_flags=-ss");
        Shell.run(Duration.ofSeconds(30), "service", "syslogd", "restart");
        String problem = verify();
        if (problem != null) {
            if (inRcConf) Shell.run(Duration.ofSeconds(10), "sysrc", "syslogd_flags=" + oldFlags);
            else Shell.run(Duration.ofSeconds(10), "sysrc", "-x", "syslogd_flags");
            Shell.run(Duration.ofSeconds(30), "service", "syslogd", "restart");
            LOGGER.warning("[SyslogNetwork] ROLLED_BACK: " + problem + "; syslogd_flags back to '" + oldFlags + "'");
            return false;
        }
        LOGGER.info("[SyslogNetwork] DONE: syslogd opens no network socket any more (syslogd_flags=-ss, port 514 closed);"
                + " local logging checked");
        return true;
    }

    /** No syslogd port, and a local message that arrives. */
    static String verify() throws Exception {
        String probe = "daemoxcp-mail syslog probe " + UUID.randomUUID();
        for (int i = 0; i < 10; i++) {
            Thread.sleep(500);
            boolean open = false;
            for (String l : Shell.run(Duration.ofSeconds(15), "sockstat", "-46l").outputTrim().split("\n")) {
                String[] f = l.trim().split("\\s+");
                if (f.length >= 2 && f[1].startsWith("syslogd")) open = true;
            }
            if (open) { if (i == 9) return "syslogd still has a network socket"; continue; }
            Shell.run(Duration.ofSeconds(10), "logger", "-p", "user.notice", "-t", "daemoxcp-mail", probe);
            for (int j = 0; j < 10; j++) {
                Thread.sleep(500);
                if (Shell.run(Duration.ofSeconds(10), "tail", "-n", "200", MESSAGES).output().contains(probe)) return null;
            }
            return "a message written with logger did not reach " + MESSAGES;
        }
        return "syslogd still has a network socket";
    }
}
