package org.daemoxcp.mail.system;

import org.daemoxcp.mail.util.Shell;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.logging.Logger;

/**
 * SMTP authentication (AUTH) only on the submission ports, 587 and 465; not on 25.
 *
 * Measured on the VM on 2026-11-20: main.cf had smtpd_sasl_auth_enable = yes for all ports, so 25, after
 * STARTTLS, offered AUTH to anyone: one more target for whoever tries passwords. Nobody uses it: the webmail
 * sends from tls://127.0.0.1:587, the profiles and the client settings page say 587 or 465, and in the mail
 * log the logins go through postfix/submission. 25 is the port on which the other servers deliver, and it is
 * not needed there. It is the arrangement of the Postfix documentation (SASL_README: authentication on the
 * submission services, with -o smtpd_sasl_auth_enable=yes in master.cf).
 *
 * master.cf already turns it on for 587 (submission) and 465 (smtps): here it is turned off in main.cf, only if
 * both turn it on by themselves, otherwise the clients could no longer send. The installer writes it into
 * main.cf; on the servers installed earlier this boot repair does it: postconf -e, postfix check, reload, and
 * the real test with STARTTLS (25 does not offer AUTH, 587 does). If something does not add up it puts the
 * previous value back and reloads.
 */
public final class PostfixSubmissionAuth {

    private static final Logger LOGGER = Logger.getLogger(PostfixSubmissionAuth.class.getName());

    public static final String SETTING = "smtpd_sasl_auth_enable";

    enum Action { NOTHING, APPLY, MASTER_NOT_READY }

    private PostfixSubmissionAuth() {}

    /** What to do, from the three values: main.cf, submission and smtps in master.cf. Pure function. */
    static Action decide(String main, String submission, String smtps) {
        if ("no".equalsIgnoreCase(trim(main))) return Action.NOTHING;
        if (!"yes".equalsIgnoreCase(trim(submission)) || !"yes".equalsIgnoreCase(trim(smtps))) return Action.MASTER_NOT_READY;
        return Action.APPLY;
    }

    /** The service offers AUTH, from the answer to EHLO after STARTTLS. Pure function. */
    static boolean offersAuth(String ehlo) {
        return ehlo != null && ehlo.matches("(?s).*(^|\\n)250[- ]AUTH[ =].*");
    }

    private static String trim(String s) {
        return s == null ? "" : s.trim();
    }

    public static void ensureAtBoot() {
        try {
            if (!Files.isExecutable(Path.of(PostfixVrfy.POSTCONF))) return;
            String main = Shell.run(Duration.ofSeconds(15), PostfixVrfy.POSTCONF, "-h", SETTING).outputTrim();
            String submission = Shell.run(Duration.ofSeconds(15), PostfixVrfy.POSTCONF, "-Ph", "submission/inet/" + SETTING).outputTrim();
            String smtps = Shell.run(Duration.ofSeconds(15), PostfixVrfy.POSTCONF, "-Ph", "smtps/inet/" + SETTING).outputTrim();
            switch (decide(main, submission, smtps)) {
                case NOTHING -> { return; }
                case MASTER_NOT_READY -> {
                    LOGGER.info("[PostfixSubmissionAuth] AUTH stays on port 25 too: master.cf does not turn it on by itself for"
                            + " both 587 and 465 (submission: " + submission + ", smtps: " + smtps + ")");
                    return;
                }
                case APPLY -> apply(main);
            }
        } catch (Throwable t) {
            LOGGER.warning("[PostfixSubmissionAuth] ensureAtBoot exception: " + t.getMessage());
        }
    }

    static void apply(String before) {
        if (!Shell.run(Duration.ofSeconds(15), "service", "postfix", "status").success()) {
            LOGGER.info("[PostfixSubmissionAuth] Postfix is not running: AUTH left as it is, retrying at the next start");
            return;
        }
        if (!offersAuth(ehlo(587))) {
            LOGGER.warning("[PostfixSubmissionAuth] port 587 does not offer AUTH even now: nothing changed");
            return;
        }
        Shell.Result set = Shell.run(Duration.ofSeconds(30), PostfixVrfy.POSTCONF, "-e", SETTING + "=no");
        Shell.Result check = Shell.run(Duration.ofSeconds(60), "postfix", "check");
        if (!set.success() || !check.success()) {
            putBack(before, false);
            LOGGER.warning("[PostfixSubmissionAuth] ROLLED_BACK: " + (set.success() ? "postfix check: " + check.outputTrim() : set.outputTrim()));
            return;
        }
        Shell.run(Duration.ofSeconds(30), "postfix", "reload");
        String problem = null;
        for (int i = 0; i < 10; i++) {
            try { Thread.sleep(500); } catch (InterruptedException e) { Thread.currentThread().interrupt(); break; }
            boolean on25 = offersAuth(ehlo(25)), on587 = offersAuth(ehlo(587));
            problem = on25 ? "port 25 still offers AUTH" : !on587 ? "port 587 no longer offers AUTH" : null;
            if (problem == null) break;
        }
        if (problem != null) {
            putBack(before, true);
            LOGGER.warning("[PostfixSubmissionAuth] ROLLED_BACK: " + problem + "; " + SETTING + " put back");
            return;
        }
        LOGGER.info("[PostfixSubmissionAuth] DONE: SMTP AUTH only on the sending ports 587 and 465, no longer on port 25,"
                + " where the other mail servers deliver");
    }

    private static void putBack(String before, boolean reload) {
        Shell.run(Duration.ofSeconds(30), PostfixVrfy.POSTCONF, "-e", SETTING + "=" + (before == null || before.isBlank() ? "no" : before));
        if (reload) Shell.run(Duration.ofSeconds(30), "postfix", "reload");
    }

    /** The answer to EHLO after STARTTLS on the given port of this machine (openssl s_client, like a real client). */
    static String ehlo(int port) {
        Shell.Result r = Shell.run(Duration.ofSeconds(30), "sh", "-c",
                "{ sleep 1; printf 'EHLO localhost\\r\\n'; sleep 1; printf 'QUIT\\r\\n'; sleep 1; } | "
                        + "timeout -f 20 openssl s_client -starttls smtp -crlf -quiet -connect 127.0.0.1:" + port + " 2>/dev/null");
        return r.output();
    }
}
