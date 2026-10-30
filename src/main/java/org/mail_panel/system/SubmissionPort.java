package org.mail_panel.system;

import org.json.JSONObject;
import org.mail_panel.i18n.I18n;
import org.mail_panel.util.Shell;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Rende la porta 465 una vera porta di sottomissione, aggiungendo a master.cf la riga che
 * rifiuta chi non si e' autenticato.
 *
 * Perche' serve, verificato sulle specifiche e non a intuito:
 *  - RFC 8314 §3.3: il servizio "submissions" sulla 465 da' accesso a un Message Submission
 *    Agent secondo RFC 6409, e le regole degli MSA valgono anche per quella porta.
 *  - RFC 6409 §4.3 ("Require Authentication"): l'MSA DEVE rifiutare il comando MAIL se la
 *    sessione non e' stata autenticata.
 *
 * Oggi la voce smtps ha smtpd_sasl_auth_enable=yes, che ABILITA l'autenticazione ma non la
 * RICHIEDE: chi non si autentica viene servito lo stesso, come sulla porta 25. La differenza
 * non si vede finche' qualcuno non se ne accorge.
 *
 * Attenzione all'asimmetria: la stessa riga sulla porta 25 fermerebbe tutta la posta in
 * arrivo, perche' e' li' che i server del mondo consegnano senza autenticarsi. Per questo
 * qui si tocca UNA sola voce, individuata dal primo campo della riga e non cercando la
 * parola "smtps" nel file: quella parola compare anche dentro le opzioni (syslog_name).
 */
public class SubmissionPort {

    public static final String RESTRICTION = "smtpd_client_restrictions=permit_sasl_authenticated,reject";
    private static final String MASTER = "/usr/local/etc/postfix/master.cf";
    private static final String COPY = "/var/db/mailpanel/master.cf-before-465";

    /** I nomi con cui la porta 465 puo' comparire in master.cf. */
    private static final List<String> NAMES = List.of("smtps", "submissions");

    private SubmissionPort() {}

    /* ===================================================================
     * La parte che si puo' provare senza server
     * =================================================================== */

    public enum Outcome { AGGIUNTA, GIA_PRESENTE, VOCE_ASSENTE }

    public static class Change {
        public Outcome outcome;
        public String content;   // il file nuovo, solo quando esito == AGGIUNTA
        public String entry;        // il nome trovato: smtps oppure submissions
        public int line;           // dove comincia la voce, per poterlo dire
        public String already;         // la restrizione gia' presente, quando c'e'
    }

    /**
     * Aggiunge la restrizione alla voce della 465, e a nessun'altra.
     *
     * Il riconoscimento guarda il PRIMO CAMPO di una riga non indentata: in master.cf le
     * righe che cominciano con uno spazio sono opzioni della voce precedente, e una riga che
     * comincia con '#' e' commentata. Cercare la parola "smtps" nel testo prenderebbe anche
     * "-o syslog_name=postfix/smtps", che e' un'opzione, non una voce.
     */
    public static Change addRestriction(String masterCf) {
        Change m = new Change();
        if (masterCf == null) { m.outcome = Outcome.VOCE_ASSENTE; return m; }

        String[] lines = masterCf.split("\n", -1);
        int start = -1;
        for (int i = 0; i < lines.length; i++) {
            String r = lines[i];
            if (r.isEmpty() || Character.isWhitespace(r.charAt(0))) continue;  // opzione
            if (r.startsWith("#")) continue;                                   // commentata
            String first = r.trim().split("\\s+")[0];
            if (NAMES.contains(first)) { start = i; m.entry = first; break; }
        }
        if (start < 0) { m.outcome = Outcome.VOCE_ASSENTE; return m; }
        m.line = start + 1;

        // Le opzioni della voce: le righe indentate che seguono, fino alla prossima voce.
        int end = start + 1;
        while (end < lines.length && !lines[end].isEmpty()
                && Character.isWhitespace(lines[end].charAt(0))) end++;

        // Si accettano ENTRAMBE le forme. Dei due script di installazione del pannello, uno
        // scrive "smtpd_recipient_restrictions=permit_sasl_authenticated,reject" su questa
        // voce e l'altro non scrive niente: cercare solo la forma "client" avrebbe fatto
        // aggiungere una riga ridondante a un server gia' a posto, e avrebbe fatto dire al
        // pannello che la porta era aperta quando non lo era.
        for (int i = start; i < end; i++) {
            String compact = lines[i].replace(" ", "");
            if (compact.contains("smtpd_client_restrictions=")
                    || compact.contains("smtpd_recipient_restrictions=")) {
                m.outcome = Outcome.GIA_PRESENTE;
                m.already = lines[i].trim();
                return m;
            }
        }

        List<String> outside = new ArrayList<>();
        for (int i = 0; i < end; i++) outside.add(lines[i]);
        outside.add("  -o " + RESTRICTION);
        for (int i = end; i < lines.length; i++) outside.add(lines[i]);

        m.outcome = Outcome.AGGIUNTA;
        m.content = String.join("\n", outside);
        return m;
    }

    /* ===================================================================
     * La parte che tocca il server
     * =================================================================== */

    /** Legge lo stato senza cambiare niente. */
    public static JSONObject state() {
        JSONObject r = new JSONObject().put("success", true);
        try {
            Path p = Path.of(MASTER);
            if (!Files.isReadable(p))
                return new JSONObject().put("success", false)
                        .put("error", I18n.tr("server.subm.cannotRead", java.util.Map.of("file", String.valueOf(MASTER))));
            Change m = addRestriction(Files.readString(p));
            r.put("voce", m.entry == null ? JSONObject.NULL : m.entry)
             .put("riga", m.line)
             .put("stato", m.outcome.name())
             .put("restrizione", RESTRICTION);

            // La verifica che non si da' per scontata: se le restrizioni venissero valutate
            // PRIMA dell'autenticazione, la riga rifiuterebbe anche gli utenti legittimi.
            RunResult d = run("postconf", "-h", "smtpd_delay_reject");
            String value = d.output.trim();
            r.put("delayReject", value).put("delayRejectLetto", d.code == 0);
            r.put("sicuro", d.code == 0 && value.equalsIgnoreCase("yes"));

            switch (m.outcome) {
                case GIA_PRESENTE -> r.put("nota", I18n.tr("server.subm.already", java.util.Map.of("svc", String.valueOf(m.entry), "line", String.valueOf(m.already))))
                        .put("gia", m.already);
                case VOCE_ASSENTE -> r.put("nota", I18n.tr("server.subm.noEntry"));
                case AGGIUNTA -> r.put("nota", I18n.tr("server.subm.acceptsUnauth", java.util.Map.of("svc", String.valueOf(m.entry), "line", String.valueOf(m.line))));
            }
            return r;
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", I18n.tr("server.subm.readError", java.util.Map.of("err", String.valueOf(e.getMessage()))));
        }
    }

    /**
     * Applica la modifica. Copia di sicurezza, scrittura, postfix check, reload, e se
     * qualcosa non torna si rimette il file di prima e si ricarica di nuovo.
     */
    public static JSONObject apply() {
        JSONObject r = new JSONObject();
        try {
            JSONObject st = state();
            if (!st.optBoolean("success", false))
                return r.put("success", false).put("error", st.optString("error", I18n.tr("server.subm.stateUnreadable")));

            String state = st.optString("stato", "");
            if ("GIA_PRESENTE".equals(state))
                return r.put("success", true).put("giaFatto", true).put("nota", st.optString("nota"));
            if ("VOCE_ASSENTE".equals(state))
                return r.put("success", false).put("error", st.optString("nota"));

            // Il controllo che vale piu' di tutti: senza delay_reject a "yes" la riga
            // rifiuterebbe anche chi si autentica, perche' verrebbe valutata prima dell'AUTH.
            if (!st.optBoolean("sicuro", false))
                return r.put("success", false)
                        .put("error", st.optBoolean("delayRejectLetto", false)
                                ? I18n.tr("server.subm.delayReject", java.util.Map.of("v", String.valueOf(st.optString("delayReject", "?"))))
                                : I18n.tr("server.subm.delayRejectUnread", java.util.Map.of("v", String.valueOf(st.optString("delayReject", "?")))));

            Path p = Path.of(MASTER);
            String before = Files.readString(p);
            Change m = addRestriction(before);
            if (m.outcome != Outcome.AGGIUNTA)
                return r.put("success", false).put("error", I18n.tr("server.subm.changed", java.util.Map.of("state", String.valueOf(m.outcome.name()))));

            Path copy = Path.of(COPY);
            Files.createDirectories(copy.getParent());
            Files.writeString(copy, before);
            r.put("copia", copy.toString()).put("voce", m.entry).put("riga", m.line);

            Files.writeString(p, m.content);

            RunResult check = run("postfix", "check");
            if (check.code != 0) {
                Files.writeString(p, before);
                return r.put("success", false).put("ripristinato", true)
                        .put("error", I18n.tr("server.subm.checkFailed", java.util.Map.of("out", String.valueOf(check.output.trim()))));
            }

            RunResult reload = run("postfix", "reload");
            if (reload.code != 0) {
                Files.writeString(p, before);
                run("postfix", "reload");
                return r.put("success", false).put("ripristinato", true)
                        .put("error", I18n.tr("server.subm.reloadFailed", java.util.Map.of("out", String.valueOf(reload.output.trim()))));
            }

            // Non basta che i comandi non abbiano protestato: si rilegge e si guarda.
            Change after = addRestriction(Files.readString(p));
            if (after.outcome != Outcome.GIA_PRESENTE)
                return r.put("success", false)
                        .put("error", I18n.tr("server.subm.notPresent", java.util.Map.of("file", String.valueOf(MASTER))));

            RunResult m465 = run("postconf", "-M", m.entry + "/inet");
            r.put("vocePostfix", m465.output.trim());

            return r.put("success", true)
                    .put("nota", I18n.tr("server.subm.done", java.util.Map.of("svc", String.valueOf(m.entry), "copy", String.valueOf(copy))));
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", I18n.tr("server.subm.error", java.util.Map.of("err", String.valueOf(e.getMessage()))));
        }
    }

    private record RunResult(int code, String output) {}

    private static RunResult run(String... cmd) {
        try {
            ProcessBuilder pb = new ProcessBuilder(cmd);
            Shell.applyPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes());
            return new RunResult(p.waitFor(), out);
        } catch (Exception e) {
            return new RunResult(-1, String.valueOf(e.getMessage()));
        }
    }
}
