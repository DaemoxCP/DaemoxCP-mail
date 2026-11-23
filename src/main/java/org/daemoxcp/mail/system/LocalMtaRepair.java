package org.daemoxcp.mail.system;

import org.daemoxcp.mail.scripts.LocalMtaScript;
import org.daemoxcp.mail.util.Shell;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Arrays;
import java.util.Locale;
import java.util.Set;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Postfix as the local MTA on servers installed BEFORE the installer did it.
 *
 * The installer does it since PR #60 (scripts/LocalMtaScript): a server installed before still
 * has no /usr/local/etc/mail/mailer.conf, so system mail (cron, periodic, PHP's mail()) goes
 * out through dma, without DKIM and without TLS. At startup the panel fixes it, as it already does
 * with /etc/aliases (PostfixAliasesManager.ensureAtBoot, which runs before this one and so leaves
 * aliases.db already built).
 *
 * The order is the one measured in the findings (points 66-68), and it matters: if mailer.conf is
 * activated while addresses without a domain become a domain that is not local (myorigin =
 * $mydomain, the server name, with mydestination = localhost), Postfix sends "root" to itself
 * and bounces it, bounce included: system mail disappears. Therefore:
 *  - if myorigin is already local, it is simply activated;
 *  - if it is not but localhost is in mydestination, first myorigin = localhost (with
 *    smtp_generic_maps for outgoing mail, if nobody has set it already), then it is activated;
 *  - if local delivery is off (local_transport = error:, written by the "all" script) or
 *    there is no local domain, it is NOT activated: with dma system mail at least arrives in
 *    /var/mail/root, with Postfix it would bounce. This is said in the log, with the reason.
 * mydestination is never touched: widening it would open the system accounts to the Internet.
 *
 * It can be repeated: with mailer.conf already right it does nothing.
 */
public final class LocalMtaRepair {

    private static final Logger LOGGER = Logger.getLogger(LocalMtaRepair.class.getName());

    static final String POSTFIX_SENDMAIL = "/usr/local/sbin/sendmail";
    static final String MAILER_CONF = "/usr/local/etc/mail/mailer.conf";
    static final String POSTCONF = "/usr/local/sbin/postconf";
    static final String GENERIC_MAPS = "inline:{ @localhost=@$myhostname }";

    private static final Pattern POSTFIX_LINE =
            Pattern.compile("(?m)^sendmail[ \\t]+/usr/local/sbin/sendmail([ \\t]|$)");

    private LocalMtaRepair() {}

    enum Action { NOTHING, ACTIVATE, SET_MYORIGIN_THEN_ACTIVATE, REFUSE }

    record Decision(Action action, String reason) {}

    /**
     * What to do, starting from what is there. Separate from the system so that it can be tested:
     * myorigin and mydestination arrive already expanded (postconf -x).
     */
    static Decision decide(boolean postfixInstalled, String mailerConf,
                           String myorigin, String mydestination, String localTransport) {
        if (!postfixInstalled)
            return new Decision(Action.NOTHING, "Postfix's sendmail is not installed");
        if (mailerConf != null && POSTFIX_LINE.matcher(mailerConf).find())
            return new Decision(Action.NOTHING, "sendmail(8) already hands over to Postfix");
        String transport = localTransport == null ? "" : localTransport.trim();
        if (transport.startsWith("error"))
            return new Decision(Action.REFUSE, "local delivery is switched off (local_transport = "
                    + transport + "): with Postfix, system mail would bounce; left on dma");
        Set<String> local = Arrays.stream((mydestination == null ? "" : mydestination).split("[,\\s]+"))
                .map(s -> s.trim().toLowerCase(Locale.ROOT))
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toSet());
        String origin = myorigin == null ? "" : myorigin.trim().toLowerCase(Locale.ROOT);
        if (!origin.isEmpty() && local.contains(origin))
            return new Decision(Action.ACTIVATE, "myorigin " + origin + " is already local");
        if (local.contains("localhost"))
            return new Decision(Action.SET_MYORIGIN_THEN_ACTIVATE, "myorigin " + origin
                    + " is not in mydestination: it becomes localhost first");
        return new Decision(Action.REFUSE, "no local domain for system mail (mydestination = "
                + (mydestination == null ? "" : mydestination.trim()) + "): left on dma");
    }

    /** At panel startup. It throws no exceptions: it says everything in the log. */
    public static void ensureAtBoot() {
        try {
            boolean installed = Files.isExecutable(Path.of(POSTFIX_SENDMAIL));
            String mailerConf = Files.isRegularFile(Path.of(MAILER_CONF)) ? Files.readString(Path.of(MAILER_CONF)) : null;
            String myorigin = "", mydestination = "", localTransport = "", genericMaps = "";
            if (installed) {
                myorigin = postconf("-x", "-h", "myorigin");
                mydestination = postconf("-x", "-h", "mydestination");
                localTransport = postconf("-x", "-h", "local_transport");
                genericMaps = postconf("-h", "smtp_generic_maps");
            }
            Decision d = decide(installed, mailerConf, myorigin, mydestination, localTransport);
            switch (d.action()) {
                case NOTHING -> {
                    LOGGER.info("[LocalMta] " + d.reason());
                    return;
                }
                case REFUSE -> {
                    LOGGER.warning("[LocalMta] Postfix NOT made the local MTA: " + d.reason());
                    return;
                }
                case SET_MYORIGIN_THEN_ACTIVATE -> {
                    LOGGER.warning("[LocalMta] " + d.reason());
                    if (!run(POSTCONF, "-e", "myorigin=localhost")) return;
                    if (genericMaps.isBlank()) {
                        if (!run(POSTCONF, "-e", "smtp_generic_maps=" + GENERIC_MAPS)) return;
                    } else {
                        LOGGER.warning("[LocalMta] smtp_generic_maps is already set (" + genericMaps
                                + "): left alone, system mail leaving the server may say root@localhost");
                    }
                    if (!run("/usr/local/sbin/postfix", "reload")) return;
                }
                case ACTIVATE -> LOGGER.warning("[LocalMta] sendmail(8) hands over to dma: " + d.reason());
            }
            Shell.Result r = Shell.runShell(Duration.ofSeconds(120), LocalMtaScript.SHELL);
            for (String line : r.outputTrim().split("\n"))
                if (!line.isBlank()) LOGGER.info("[LocalMta] " + line.trim());
            String after = Files.isRegularFile(Path.of(MAILER_CONF)) ? Files.readString(Path.of(MAILER_CONF)) : "";
            if (POSTFIX_LINE.matcher(after).find())
                LOGGER.info("[LocalMta] Postfix is now the local MTA (" + MAILER_CONF + ")");
            else
                LOGGER.warning("[LocalMta] the repair ran (exit " + r.exitCode() + ") but sendmail(8) still does not hand over to Postfix");
        } catch (Throwable t) {
            LOGGER.warning("[LocalMta] ensureAtBoot exception: " + t.getMessage());
        }
    }

    private static String postconf(String... args) {
        String[] cmd = new String[args.length + 1];
        cmd[0] = POSTCONF;
        System.arraycopy(args, 0, cmd, 1, args.length);
        Shell.Result r = Shell.run(Duration.ofSeconds(15), cmd);
        return r.success() ? r.outputTrim() : "";
    }

    private static boolean run(String... cmd) {
        Shell.Result r = Shell.run(Duration.ofSeconds(30), cmd);
        if (!r.success())
            LOGGER.warning("[LocalMta] " + String.join(" ", cmd) + " failed (exit " + r.exitCode() + "): "
                    + r.outputTrim() + " -- stopping, sendmail(8) left on dma");
        return r.success();
    }
}
