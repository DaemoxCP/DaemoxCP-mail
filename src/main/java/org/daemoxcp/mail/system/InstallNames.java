package org.daemoxcp.mail.system;

import org.daemoxcp.mail.security.PemTls;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * The three names of a server before the installation from the menu (finding 244).
 *
 * <p>A server has three names, and they serve different purposes:
 * <ul>
 *   <li>the mail name (option 4, for example mail.example.com): MX, PTR, certificate of Postfix and Dovecot. Its
 *       A record must stay "DNS only" in Cloudflare: mail (25, 465, 587, 993) does not go through the proxy;</li>
 *   <li>the webmail name (option 3, for example webmail.example.com, port 8443) and the panel's name (option 2,
 *       for example panel.example.com, port 2096): they go through the Cloudflare proxy, which forwards HTTPS on
 *       8443 and 2096.</li>
 * </ul>
 * Until today the installation started even with the example webmail name left at the factory value
 * (webmail.example.com, which passed the script's check) and with a name equal to the mail one, which in
 * Cloudflare cannot be both behind the proxy and outside it. Here are the problems that stop the installation from
 * the menu, and the warnings that let it start (the panel without a name of its own can be fixed later, with option
 * 2).
 */
public final class InstallNames {

    private InstallNames() {}

    /** The webmail name that the panel writes when the database is first opened. */
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
