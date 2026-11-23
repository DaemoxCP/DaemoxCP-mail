package org.daemoxcp.mail.system;

import org.daemoxcp.mail.i18n.I18n;

import java.time.ZonedDateTime;
import java.util.Map;

/**
 * The emails with a one-time code: panel login, confirmation of a sensitive operation,
 * confirmation of the new login email.
 *
 * Each one says, in the order in which the person opening it needs it: which panel and which
 * server, the code, how long it is valid, from where and when it was requested, and what to do
 * if they did not request it.
 *
 * Three choices:
 *  - the code is NOT in the subject nor in the preview line: phone notifications show them
 *    on the lock screen;
 *  - the IP address of whoever requested it is in the login and in the confirmation, which go
 *    to the administrator's mailbox; it is NOT in the email change, which goes to the NEW
 *    address, that is to whoever was written in the form: sending them the IP of whoever wrote
 *    it would be handing it to a stranger;
 *  - no link: an email that asks you to click to log in is exactly what a fake imitates.
 */
public final class CodeMail {

    private CodeMail() {}

    public enum Kind {
        LOGIN("login", true), STEP_UP("stepUp", true), EMAIL_CHANGE("emailChange", false);

        final String key;
        final boolean showsRequester;
        Kind(String key, boolean showsRequester) { this.key = key; this.showsRequester = showsRequester; }
    }

    public static PanelMail.Message message(Kind kind, String lang, String server, String code,
                                            long minutes, String ip, ZonedDateTime when) {
        String l = I18n.normalize(lang);
        String k = "mail.code." + kind.key + ".";
        String name = server == null || server.isEmpty() ? I18n.t(l, "mail.report.unnamedServer") : server;
        Map<String, Object> v = Map.of("server", name, "minutes", minutes);

        String subject = I18n.t(l, k + "subject", v);
        String title = I18n.t(l, k + "title");
        String intro = I18n.t(l, k + "intro", v);
        String validity = I18n.t(l, k + "validity", v);
        String requested = kind.showsRequester && ip != null && !ip.isBlank()
                ? I18n.t(l, "mail.code.requested", Map.of("ip", ip, "when", PanelMail.longDateTime(l, when)))
                : I18n.t(l, "mail.code.requestedAt", Map.of("when", PanelMail.longDateTime(l, when)));
        String notYou = I18n.t(l, k + "notYou");
        String never = I18n.t(l, "mail.code.neverShare");
        String footer = I18n.t(l, "mail.code.footer", Map.of("server", name));

        StringBuilder t = new StringBuilder();
        t.append(I18n.t(l, "mail.common.product")).append(" - ").append(name).append("\n\n")
         .append(title).append("\n\n")
         .append(PanelMail.wrap(intro, 72, ""))
         .append('\n').append("    ").append(code).append("\n\n")
         .append(PanelMail.wrap(validity, 72, ""))
         .append(PanelMail.wrap(requested, 72, "")).append('\n')
         .append(PanelMail.wrap(notYou, 72, "")).append('\n')
         .append(PanelMail.wrap(never, 72, "")).append('\n')
         .append("-- \n").append(PanelMail.wrap(footer, 72, ""));

        String content = PanelMail.h1(title)
                + PanelMail.p(intro)
                + PanelMail.code(code)
                + PanelMail.p(validity)
                + PanelMail.muted(requested)
                + PanelMail.banner(PanelMail.Tone.LATER, I18n.t(l, "mail.code.notYouTitle"), notYou)
                + PanelMail.muted(never);
        String html = PanelMail.page(l, subject, I18n.t(l, k + "preheader", v), server,
                content, PanelMail.footerLine(footer));
        return new PanelMail.Message(subject, t.toString(), html, l);
    }
}
