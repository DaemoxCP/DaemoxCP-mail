package org.daemoxcp.mail.system;

import org.daemoxcp.mail.util.Shell;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.time.Duration;
import java.util.logging.Logger;
import java.util.regex.Pattern;

/**
 * inet_protocols written explicitly in main.cf, with the value Postfix already uses.
 *
 * The installation script of every postfix upgrade (/usr/local/libexec/postfix/post-install, read on the VM
 * on 2026-11-09) does this: if the default is not ipv4 and main.cf does not set inet_protocols, it writes
 * {@code inet_protocols = ipv4}. On FreeBSD the default is all, so it writes it every time it is missing, and
 * on restart postfix stops listening on IPv6 (finding 42). The panel sees it and does not restart
 * (InstallSideEffects), but the step stops: in the test of "Update all" on the VM (finding 207) the chain
 * stopped at the postfix-mysql step because of this. The full installation did not write the line; the stack
 * one and PostfixScript did.
 *
 * Here the line is written with the current value, the one {@code postconf -h} reads: nothing changes in what
 * Postfix does, so there is no need to reload it, and the script has nothing left to write. A value already
 * written, whatever it is, stays: it is someone's choice (on the production server ipv4, with no IPv6
 * addresses). Afterwards it checks that main.cf says the right value and that {@code postfix check} passes; if
 * not, main.cf goes back to how it was, byte for byte. On the second startup it does nothing.
 */
public final class PostfixInetProtocols {

    private static final Logger LOGGER = Logger.getLogger(PostfixInetProtocols.class.getName());

    static final String POSTCONF = "/usr/local/sbin/postconf";
    static final String POSTFIX = "/usr/local/sbin/postfix";

    /** The values Postfix accepts: all, or ipv4 and ipv6, alone or together. Nothing else goes into main.cf. */
    private static final Pattern VALUE = Pattern.compile("all|ipv4|ipv6|ipv4[ ,]+ipv6|ipv6[ ,]+ipv4");

    private PostfixInetProtocols() {}

    enum Action { NOTHING, WRITE, LEFT_ALONE }

    record Decision(Action action, String value, String reason) {}

    /**
     * Pure function: if Postfix is there, the value written in main.cf ({@code postconf -nh}, empty if absent)
     * and the one in use ({@code postconf -h}).
     */
    static Decision decide(boolean installed, String explicit, String effective) {
        if (!installed) return new Decision(Action.NOTHING, "", "Postfix is not installed");
        String set = explicit == null ? "" : explicit.trim();
        if (!set.isEmpty())
            return new Decision(Action.NOTHING, set, "main.cf already says inet_protocols = " + set);
        String now = effective == null ? "" : effective.trim().replaceAll("\\s+", " ");
        if (!VALUE.matcher(now).matches())
            return new Decision(Action.LEFT_ALONE, "", "inet_protocols in use is '" + now + "', not a value written here: left as it is");
        return new Decision(Action.WRITE, now, "main.cf does not say inet_protocols: the update of postfix would write ipv4");
    }

    public static void ensureAtBoot() {
        try {
            boolean installed = Files.isExecutable(Path.of(POSTCONF));
            String explicit = "", effective = "";
            if (installed) {
                explicit = postconf("-n", "-h", "inet_protocols");
                effective = postconf("-h", "inet_protocols");
            }
            Decision d = decide(installed, explicit, effective);
            switch (d.action()) {
                case NOTHING -> { return; }
                case LEFT_ALONE -> { LOGGER.warning("[PostfixInetProtocols] " + d.reason()); return; }
                case WRITE -> write(d);
            }
        } catch (Throwable t) {
            LOGGER.warning("[PostfixInetProtocols] ensureAtBoot exception: " + t.getMessage());
        }
    }

    private static void write(Decision d) throws Exception {
        Path mainCf = Path.of(postconf("-h", "config_directory"), "main.cf");
        if (!Files.isRegularFile(mainCf)) {
            LOGGER.warning("[PostfixInetProtocols] " + mainCf + " not found: left as it is");
            return;
        }
        byte[] before = Files.readAllBytes(mainCf);
        PosixFileAttributes attrs = Files.readAttributes(mainCf, PosixFileAttributes.class);
        // A check that was already failing before is not this line's fault: it counts only if it used to pass.
        boolean checkedBefore = Shell.run(Duration.ofSeconds(60), POSTFIX, "check").success();
        Shell.Result r = Shell.run(Duration.ofSeconds(30), POSTCONF, "-e", "inet_protocols=" + d.value());
        String problem = !r.success() ? "postconf -e failed (exit " + r.exitCode() + "): " + r.outputTrim() : verify(d.value(), checkedBefore);
        if (problem != null) {
            Files.write(mainCf, before);
            PosixFileAttributeView view = Files.getFileAttributeView(mainCf, PosixFileAttributeView.class);
            view.setOwner(attrs.owner());
            view.setGroup(attrs.group());
            view.setPermissions(attrs.permissions());
            LOGGER.warning("[PostfixInetProtocols] ROLLED_BACK: " + problem + "; main.cf back as it was");
            return;
        }
        LOGGER.info("[PostfixInetProtocols] DONE: inet_protocols = " + d.value() + " written in " + mainCf
                + " (the value already in use: nothing changes, no reload)");
    }

    /** main.cf states the value, the one in use is the same, and the configuration still passes Postfix's check. */
    private static String verify(String value, boolean checkedBefore) {
        String now = postconf("-n", "-h", "inet_protocols").trim().replaceAll("\\s+", " ");
        if (!now.equals(value)) return "main.cf says '" + now + "' instead of '" + value + "'";
        String inUse = postconf("-h", "inet_protocols").trim().replaceAll("\\s+", " ");
        if (!inUse.equals(value)) return "inet_protocols in use is now '" + inUse + "' instead of '" + value + "'";
        Shell.Result check = Shell.run(Duration.ofSeconds(60), POSTFIX, "check");
        if (checkedBefore && !check.success()) return "postfix check failed (exit " + check.exitCode() + "): " + check.outputTrim();
        return null;
    }

    private static String postconf(String... args) {
        String[] cmd = new String[args.length + 1];
        cmd[0] = POSTCONF;
        System.arraycopy(args, 0, cmd, 1, args.length);
        Shell.Result r = Shell.run(Duration.ofSeconds(15), cmd);
        return r.success() ? r.outputTrim() : "";
    }
}
