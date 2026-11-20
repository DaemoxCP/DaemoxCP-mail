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
 * Il comando SMTP VRFY spento (disable_vrfy_command = yes).
 *
 * Misurato sulla VM il 20/11/2026, sulla porta 25 e senza autenticazione: «VRFY casella-che-esiste» rispondeva 252,
 * «VRFY casella-che-non-esiste» 550 «User unknown». Chiunque poteva sapere quali caselle ci sono: e' l'enumerazione
 * degli account che la regola r6 vieta. La documentazione di Postfix (postconf(5), disable_vrfy_command): «Disable the
 * SMTP VRFY command. This stops some techniques used to harvest email addresses.» Nessun client di posta lo usa.
 *
 * Il rifiuto al RCPT TO di un destinatario che non esiste resta com'e': e' quello che la documentazione raccomanda
 * (smtpd_reject_unlisted_recipient), perche' accettare e poi rimandare indietro produce posta di ritorno verso mittenti
 * falsificati.
 *
 * L'installatore lo scrive in main.cf; sui server installati prima lo fa questa riparazione all'avvio: postconf -e,
 * postfix check, reload, e la prova vera (un VRFY sulla 25 deve ricevere 502). Se qualcosa non torna rimette il valore
 * di prima e ricarica. Al secondo avvio non fa niente.
 */
public final class PostfixVrfy {

    private static final Logger LOGGER = Logger.getLogger(PostfixVrfy.class.getName());

    public static final String SETTING = "disable_vrfy_command";
    static final String POSTCONF = "/usr/local/sbin/postconf";

    private PostfixVrfy() {}

    /** Da fare: il valore di Postfix non e' yes (ne' il predefinito no, ne' altro). Funzione pura. */
    static boolean needed(String value) {
        return !"yes".equalsIgnoreCase(value == null ? "" : value.trim());
    }

    /** La risposta di Postfix a VRFY dice che il comando e' spento: 502 5.5.1. Funzione pura. */
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

    /** Un VRFY vero sulla 25 di questa macchina, aspettando ogni risposta: la riga che Postfix risponde, o null. */
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

    /** L'ultima riga di una risposta SMTP (le righe «250-» continuano, «250 » chiude). */
    private static String last(BufferedReader in) throws Exception {
        String line;
        while ((line = in.readLine()) != null) {
            if (line.length() < 4 || line.charAt(3) != '-') return line;
        }
        return "";
    }
}
