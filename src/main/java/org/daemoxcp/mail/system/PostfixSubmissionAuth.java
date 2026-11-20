package org.daemoxcp.mail.system;

import org.daemoxcp.mail.util.Shell;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.logging.Logger;

/**
 * L'autenticazione SMTP (AUTH) solo sulle porte di invio, 587 e 465; non sulla 25.
 *
 * Misurato sulla VM il 20/11/2026: main.cf aveva smtpd_sasl_auth_enable = yes per tutte le porte, quindi la 25, dopo
 * STARTTLS, offriva AUTH a chiunque: un bersaglio in piu' per chi prova le password. Nessuno la usa: la webmail spedisce
 * da tls://127.0.0.1:587, i profili e la pagina delle impostazioni dei client dicono 587 o 465, e nel registro della
 * posta gli accessi passano da postfix/submission. La 25 e' la porta su cui gli altri server consegnano, e li' non
 * serve. E' la disposizione della documentazione di Postfix (SASL_README: l'autenticazione sui servizi di invio,
 * con -o smtpd_sasl_auth_enable=yes in master.cf).
 *
 * master.cf la accende gia' sulla 587 (submission) e sulla 465 (smtps): qui si spegne in main.cf, solo se tutte e due la
 * accendono per conto loro, altrimenti i client non spedirebbero piu'. L'installatore lo scrive in main.cf; sui server
 * installati prima lo fa questa riparazione all'avvio: postconf -e, postfix check, reload, e la prova vera con STARTTLS
 * (la 25 non offre AUTH, la 587 si'). Se qualcosa non torna rimette il valore di prima e ricarica.
 */
public final class PostfixSubmissionAuth {

    private static final Logger LOGGER = Logger.getLogger(PostfixSubmissionAuth.class.getName());

    public static final String SETTING = "smtpd_sasl_auth_enable";

    enum Action { NOTHING, APPLY, MASTER_NOT_READY }

    private PostfixSubmissionAuth() {}

    /** Che cosa fare, dai tre valori: main.cf, submission e smtps in master.cf. Funzione pura. */
    static Action decide(String main, String submission, String smtps) {
        if ("no".equalsIgnoreCase(trim(main))) return Action.NOTHING;
        if (!"yes".equalsIgnoreCase(trim(submission)) || !"yes".equalsIgnoreCase(trim(smtps))) return Action.MASTER_NOT_READY;
        return Action.APPLY;
    }

    /** Il servizio offre AUTH, dalla risposta a EHLO dopo STARTTLS. Funzione pura. */
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

    /** La risposta a EHLO dopo STARTTLS sulla porta data di questa macchina (openssl s_client, come un client vero). */
    static String ehlo(int port) {
        Shell.Result r = Shell.run(Duration.ofSeconds(30), "sh", "-c",
                "{ sleep 1; printf 'EHLO localhost\\r\\n'; sleep 1; printf 'QUIT\\r\\n'; sleep 1; } | "
                        + "timeout -f 20 openssl s_client -starttls smtp -crlf -quiet -connect 127.0.0.1:" + port + " 2>/dev/null");
        return r.output();
    }
}
