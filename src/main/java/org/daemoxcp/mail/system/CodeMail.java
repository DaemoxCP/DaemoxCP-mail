package org.daemoxcp.mail.system;

import org.daemoxcp.mail.i18n.I18n;

import java.time.ZonedDateTime;
import java.util.Map;

/**
 * Le email con un codice monouso: accesso al pannello, conferma di un'operazione delicata,
 * conferma della nuova email di accesso.
 *
 * Ognuna dice, nell'ordine in cui serve a chi la apre: quale pannello e quale server, il codice,
 * per quanto vale, da dove e quando e' stato chiesto, e cosa fare se non l'ha chiesto lui.
 *
 * Tre scelte:
 *  - il codice NON sta nell'oggetto ne' nella riga di anteprima: le notifiche del telefono le
 *    mostrano a schermo bloccato;
 *  - l'indirizzo IP di chi l'ha chiesto c'e' nell'accesso e nella conferma, che vanno alla
 *    casella dell'amministratore; NON c'e' nel cambio dell'email, che va al NUOVO indirizzo, cioe'
 *    a chiunque sia stato scritto nel modulo: mandargli l'IP di chi l'ha scritto sarebbe
 *    consegnarlo a uno sconosciuto;
 *  - nessun collegamento: un'email che chiede di cliccare per entrare e' esattamente quello che
 *    un falso imita.
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
