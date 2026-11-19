package org.daemoxcp.mail.system;

import org.daemoxcp.mail.security.PemTls;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * I tre nomi di un server prima dell'installazione dal menu (reperto 244).
 *
 * <p>Un server ha tre nomi, e servono diversi:
 * <ul>
 *   <li>il nome della posta (voce 4, per esempio mail.example.com): MX, PTR, certificato di Postfix e Dovecot. Il suo
 *       record A deve restare «DNS only» in Cloudflare: la posta (25, 465, 587, 993) non passa dal proxy;</li>
 *   <li>il nome della webmail (voce 3, per esempio webmail.example.com, porta 8443) e quello del pannello (voce 2, per
 *       esempio panel.example.com, porta 2096): passano dal proxy di Cloudflare, che inoltra l'HTTPS su 8443 e 2096.</li>
 * </ul>
 * Fino a oggi l'installazione partiva anche col nome della webmail di esempio rimasto quello di fabbrica
 * (webmail.example.com, che passava il controllo dello script) e con un nome uguale a quello della posta, che in
 * Cloudflare non puo' essere insieme dietro il proxy e fuori. Qui i problemi che fermano l'installazione dal menu, e
 * gli avvisi che la lasciano partire (il pannello senza un nome suo si puo' sistemare dopo, con la voce 2).
 */
public final class InstallNames {

    private InstallNames() {}

    /** Il nome della webmail che il pannello scrive alla prima apertura del database. */
    public static final String DEFAULT_WEBMAIL = "webmail.example.com";

    public record Result(List<String> problems, List<String> warnings) {}

    public static Result check(String mailHost, String webmailDomain, String panelHost) {
        List<String> problems = new ArrayList<>(), warnings = new ArrayList<>();
        String mail = lower(mailHost), webmail = lower(webmailDomain), panel = lower(panelHost);

        if (!PemTls.dnsName(mail))
            problems.add(org.daemoxcp.mail.i18n.I18n.tr("console.names.mailNotDomain"));
        if (webmail.isEmpty() || webmail.equals(DEFAULT_WEBMAIL))
            problems.add(org.daemoxcp.mail.i18n.I18n.tr("console.names.webmailFirst"));
        else if (!PemTls.dnsName(webmail))
            problems.add(org.daemoxcp.mail.i18n.I18n.tr("console.names.webmailNotDomain"));
        else if (webmail.equals(mail))
            problems.add(org.daemoxcp.mail.i18n.I18n.tr("console.names.webmailSameAsMail"));

        if (!PemTls.dnsName(panel))
            warnings.add(org.daemoxcp.mail.i18n.I18n.tr("console.names.panelNoName", java.util.Map.of("name", panel.isEmpty() ? org.daemoxcp.mail.i18n.I18n.tr("console.names.empty") : panel)));
        else if (panel.equals(mail))
            problems.add(org.daemoxcp.mail.i18n.I18n.tr("console.names.panelSameAsMail"));
        return new Result(problems, warnings);
    }

    private static String lower(String s) {
        return s == null ? "" : s.trim().toLowerCase(Locale.ROOT);
    }
}
