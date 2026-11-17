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
 * Postfix come MTA locale sui server installati PRIMA che l'installatore lo facesse.
 *
 * L'installatore lo fa dalla PR #60 (scripts/LocalMtaScript): un server installato prima ha
 * ancora /usr/local/etc/mail/mailer.conf assente, quindi la posta di sistema (cron, periodic,
 * il mail() di PHP) esce da dma, senza DKIM e senza TLS. All'avvio il pannello lo corregge, come
 * gia' fa con /etc/aliases (PostfixAliasesManager.ensureAtBoot, che gira prima di questo e quindi
 * lascia gia' costruito aliases.db).
 *
 * L'ordine e' quello misurato nei reperti (punti 66-68), e conta: se si attiva mailer.conf
 * mentre gli indirizzi senza dominio diventano un dominio che non e' locale (myorigin =
 * $mydomain, il nome del server, con mydestination = localhost), Postfix spedisce "root" a se
 * stesso e lo rimbalza, rimbalzo compreso: la posta di sistema sparisce. Quindi:
 *  - se myorigin e' gia' locale, si attiva e basta;
 *  - se non lo e' ma localhost e' in mydestination, prima myorigin = localhost (con
 *    smtp_generic_maps per la posta che esce, se nessuno l'ha gia' impostato), poi si attiva;
 *  - se la consegna locale e' spenta (local_transport = error:, lo scriveva lo script «all») o
 *    non c'e' nessun dominio locale, NON si attiva: con dma la posta di sistema almeno arriva in
 *    /var/mail/root, con Postfix rimbalzerebbe. Lo si dice nel log, con il motivo.
 * Non si tocca mai mydestination: allargarla aprirebbe gli account di sistema a Internet.
 *
 * Si puo' ripetere: con mailer.conf gia' giusto non fa niente.
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
     * Che cosa fare, a partire da quello che c'e'. Separata dal sistema per poterla provare:
     * myorigin e mydestination arrivano gia' espansi (postconf -x).
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

    /** All'avvio del pannello. Non lancia eccezioni: dice tutto nel log. */
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
