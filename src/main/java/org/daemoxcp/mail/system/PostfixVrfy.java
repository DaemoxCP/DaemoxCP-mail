package org.daemoxcp.mail.system;

import org.daemoxcp.mail.util.Shell;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.logging.Logger;

/**
 * The SMTP VRFY command turned off (disable_vrfy_command = yes).
 *
 * Measured on the VM on 2026-11-20, on port 25 and without authentication: "VRFY existing-mailbox" answered 252,
 * "VRFY nonexistent-mailbox" 550 "User unknown". Anyone could find out which mailboxes exist: it is the account
 * enumeration that rule r6 forbids. Postfix's documentation (postconf(5), disable_vrfy_command): "Disable the
 * SMTP VRFY command. This stops some techniques used to harvest email addresses." No mail client uses it.
 *
 * The rejection at RCPT TO of a recipient that does not exist stays as it is: it is what the documentation
 * recommends (smtpd_reject_unlisted_recipient), because accepting and then bouncing produces backscatter towards
 * forged senders.
 *
 * The installer writes it into main.cf; on the servers installed earlier this boot repair does it: postconf -e,
 * postfix check, reload, and the real test (a VRFY on 25 must receive 502). If something does not add up it puts
 * the previous value back and reloads. On the second startup it does nothing.
 */
public final class PostfixVrfy {

    private static final Logger LOGGER = Logger.getLogger(PostfixVrfy.class.getName());

    public static final String SETTING = "disable_vrfy_command";
    static final String POSTCONF = "/usr/local/sbin/postconf";

    private PostfixVrfy() {}

    /** To do: Postfix's value is not yes (neither the default no, nor anything else). Pure function. */
    static boolean needed(String value) {
        return !"yes".equalsIgnoreCase(value == null ? "" : value.trim());
    }

    /** Postfix's answer to VRFY says that the command is turned off: 502 5.5.1. Pure function. */
    static boolean refused(String reply) {
        return reply != null && reply.startsWith("502");
    }

    public static void ensureAtBoot() {
        try {
            if (!Files.isExecutable(Path.of(POSTCONF))) return;
            Shell.Result now = Shell.run(Duration.ofSeconds(15), POSTCONF, "-h", SETTING);
            if (!now.success() || !needed(now.outputTrim())) return;
            if (!Shell.run(Duration.ofSeconds(15), "service", "postfix", "status").success()) {
                LOGGER.info("[PostfixVrfy] Postfix is not running: VRFY left as it is, retrying at the next start");
                return;
            }
            boolean explicit = Shell.run(Duration.ofSeconds(15), POSTCONF, "-n", SETTING).outputTrim().startsWith(SETTING);
            String before = now.outputTrim();
            Shell.Result set = Shell.run(Duration.ofSeconds(30), POSTCONF, "-e", SETTING + "=yes");
            Shell.Result check = Shell.run(Duration.ofSeconds(60), "postfix", "check");
            if (!set.success() || !check.success()) {
                putBack(explicit, before, false);
                LOGGER.warning("[PostfixVrfy] ROLLED_BACK: " + (set.success() ? "postfix check: " + check.outputTrim() : set.outputTrim()));
                return;
            }
            Shell.run(Duration.ofSeconds(30), "postfix", "reload");
            String reply = probe();
            if (!refused(reply)) {
                putBack(explicit, before, true);
                LOGGER.warning("[PostfixVrfy] ROLLED_BACK: after the reload VRFY on port 25 answered «" + reply + "», not 502");
                return;
            }
            LOGGER.info("[PostfixVrfy] DONE: the SMTP VRFY command is off (" + SETTING + " = yes): nobody can ask port 25 which"
                    + " mailboxes exist");
        } catch (Throwable t) {
            LOGGER.warning("[PostfixVrfy] ensureAtBoot exception: " + t.getMessage());
        }
    }

    private static void putBack(boolean explicit, String before, boolean reload) {
        if (explicit) Shell.run(Duration.ofSeconds(30), POSTCONF, "-e", SETTING + "=" + before);
        else Shell.run(Duration.ofSeconds(30), POSTCONF, "-X", SETTING);
        if (reload) Shell.run(Duration.ofSeconds(30), "postfix", "reload");
    }

    /** A real VRFY on port 25 of this machine, waiting for every answer: the line Postfix answers, or null. */
    static String probe() {
        for (int attempt = 0; attempt < 10; attempt++) {
            try (Socket s = new Socket()) {
                s.connect(new InetSocketAddress("127.0.0.1", 25), 5000);
                s.setSoTimeout(5000);
                BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream(), StandardCharsets.US_ASCII));
                OutputStream out = s.getOutputStream();
                if (!last(in).startsWith("220")) continue;
                out.write("EHLO localhost\r\n".getBytes(StandardCharsets.US_ASCII));
                out.flush();
                last(in);
                out.write("VRFY postmaster\r\n".getBytes(StandardCharsets.US_ASCII));
                out.flush();
                String reply = last(in);
                out.write("QUIT\r\n".getBytes(StandardCharsets.US_ASCII));
                out.flush();
                return reply;
            } catch (Exception e) {
                try { Thread.sleep(500); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); return null; }
            }
        }
        return null;
    }

    /** The last line of an SMTP answer ("250-" lines continue, "250 " ends it). */
    private static String last(BufferedReader in) throws Exception {
        String line;
        while ((line = in.readLine()) != null) {
            if (line.length() < 4 || line.charAt(3) != '-') return line;
        }
        return "";
    }
}
