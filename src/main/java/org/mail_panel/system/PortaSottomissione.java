package org.mail_panel.system;

import org.json.JSONObject;
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
public class PortaSottomissione {

    public static final String RESTRIZIONE = "smtpd_client_restrictions=permit_sasl_authenticated,reject";
    private static final String MASTER = "/usr/local/etc/postfix/master.cf";
    private static final String COPIA = "/var/db/mailpanel/master.cf-prima-della-465";

    /** I nomi con cui la porta 465 puo' comparire in master.cf. */
    private static final List<String> NOMI = List.of("smtps", "submissions");

    private PortaSottomissione() {}

    /* ===================================================================
     * La parte che si puo' provare senza server
     * =================================================================== */

    public enum Esito { AGGIUNTA, GIA_PRESENTE, VOCE_ASSENTE }

    public static class Modifica {
        public Esito esito;
        public String contenuto;   // il file nuovo, solo quando esito == AGGIUNTA
        public String voce;        // il nome trovato: smtps oppure submissions
        public int riga;           // dove comincia la voce, per poterlo dire
        public String gia;         // la restrizione gia' presente, quando c'e'
    }

    /**
     * Aggiunge la restrizione alla voce della 465, e a nessun'altra.
     *
     * Il riconoscimento guarda il PRIMO CAMPO di una riga non indentata: in master.cf le
     * righe che cominciano con uno spazio sono opzioni della voce precedente, e una riga che
     * comincia con '#' e' commentata. Cercare la parola "smtps" nel testo prenderebbe anche
     * "-o syslog_name=postfix/smtps", che e' un'opzione, non una voce.
     */
    public static Modifica aggiungiRestrizione(String masterCf) {
        Modifica m = new Modifica();
        if (masterCf == null) { m.esito = Esito.VOCE_ASSENTE; return m; }

        String[] righe = masterCf.split("\n", -1);
        int inizio = -1;
        for (int i = 0; i < righe.length; i++) {
            String r = righe[i];
            if (r.isEmpty() || Character.isWhitespace(r.charAt(0))) continue;  // opzione
            if (r.startsWith("#")) continue;                                   // commentata
            String primo = r.trim().split("\\s+")[0];
            if (NOMI.contains(primo)) { inizio = i; m.voce = primo; break; }
        }
        if (inizio < 0) { m.esito = Esito.VOCE_ASSENTE; return m; }
        m.riga = inizio + 1;

        // Le opzioni della voce: le righe indentate che seguono, fino alla prossima voce.
        int fine = inizio + 1;
        while (fine < righe.length && !righe[fine].isEmpty()
                && Character.isWhitespace(righe[fine].charAt(0))) fine++;

        // Si accettano ENTRAMBE le forme. Dei due script di installazione del pannello, uno
        // scrive "smtpd_recipient_restrictions=permit_sasl_authenticated,reject" su questa
        // voce e l'altro non scrive niente: cercare solo la forma "client" avrebbe fatto
        // aggiungere una riga ridondante a un server gia' a posto, e avrebbe fatto dire al
        // pannello che la porta era aperta quando non lo era.
        for (int i = inizio; i < fine; i++) {
            String compatta = righe[i].replace(" ", "");
            if (compatta.contains("smtpd_client_restrictions=")
                    || compatta.contains("smtpd_recipient_restrictions=")) {
                m.esito = Esito.GIA_PRESENTE;
                m.gia = righe[i].trim();
                return m;
            }
        }

        List<String> fuori = new ArrayList<>();
        for (int i = 0; i < fine; i++) fuori.add(righe[i]);
        fuori.add("  -o " + RESTRIZIONE);
        for (int i = fine; i < righe.length; i++) fuori.add(righe[i]);

        m.esito = Esito.AGGIUNTA;
        m.contenuto = String.join("\n", fuori);
        return m;
    }

    /* ===================================================================
     * La parte che tocca il server
     * =================================================================== */

    /** Legge lo stato senza cambiare niente. */
    public static JSONObject stato() {
        JSONObject r = new JSONObject().put("success", true);
        try {
            Path p = Path.of(MASTER);
            if (!Files.isReadable(p))
                return new JSONObject().put("success", false)
                        .put("error", "Non riesco a leggere " + MASTER + ".");
            Modifica m = aggiungiRestrizione(Files.readString(p));
            r.put("voce", m.voce == null ? JSONObject.NULL : m.voce)
             .put("riga", m.riga)
             .put("stato", m.esito.name())
             .put("restrizione", RESTRIZIONE);

            // La verifica che non si da' per scontata: se le restrizioni venissero valutate
            // PRIMA dell'autenticazione, la riga rifiuterebbe anche gli utenti legittimi.
            Ris d = esegui("postconf", "-h", "smtpd_delay_reject");
            String valore = d.uscita.trim();
            r.put("delayReject", valore).put("delayRejectLetto", d.codice == 0);
            r.put("sicuro", d.codice == 0 && valore.equalsIgnoreCase("yes"));

            switch (m.esito) {
                case GIA_PRESENTE -> r.put("nota", "La voce " + m.voce + " richiede gia' l'autenticazione: "
                        + "non c'e' niente da aggiungere. La riga che lo fa e': " + m.gia)
                        .put("gia", m.gia);
                case VOCE_ASSENTE -> r.put("nota", "In master.cf non c'e' una voce smtps o submissions "
                        + "attiva: la porta 465 non e' in ascolto, quindi non c'e' nulla da irrigidire.");
                case AGGIUNTA -> r.put("nota", "La voce " + m.voce + " (riga " + m.riga + ") accetta anche "
                        + "chi non si autentica. RFC 6409 §4.3 dice che un MSA deve rifiutarlo, e RFC 8314 "
                        + "§3.3 dice che la 465 e' un MSA.");
            }
            return r;
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", "errore in lettura: " + e.getMessage());
        }
    }

    /**
     * Applica la modifica. Copia di sicurezza, scrittura, postfix check, reload, e se
     * qualcosa non torna si rimette il file di prima e si ricarica di nuovo.
     */
    public static JSONObject applica() {
        JSONObject r = new JSONObject();
        try {
            JSONObject st = stato();
            if (!st.optBoolean("success", false))
                return r.put("success", false).put("error", st.optString("error", "stato non leggibile"));

            String stato = st.optString("stato", "");
            if ("GIA_PRESENTE".equals(stato))
                return r.put("success", true).put("giaFatto", true).put("nota", st.optString("nota"));
            if ("VOCE_ASSENTE".equals(stato))
                return r.put("success", false).put("error", st.optString("nota"));

            // Il controllo che vale piu' di tutti: senza delay_reject a "yes" la riga
            // rifiuterebbe anche chi si autentica, perche' verrebbe valutata prima dell'AUTH.
            if (!st.optBoolean("sicuro", false))
                return r.put("success", false)
                        .put("error", "Non applico: smtpd_delay_reject risulta \"" + st.optString("delayReject", "?")
                                + "\" invece di \"yes\"" + (st.optBoolean("delayRejectLetto", false) ? ""
                                : " (e non sono nemmeno riuscito a leggerlo)")
                                + ". Con quel valore le restrizioni sul client vengono valutate PRIMA "
                                + "dell'autenticazione, quindi la riga rifiuterebbe anche gli utenti "
                                + "legittimi: la posta in uscita si fermerebbe.");

            Path p = Path.of(MASTER);
            String prima = Files.readString(p);
            Modifica m = aggiungiRestrizione(prima);
            if (m.esito != Esito.AGGIUNTA)
                return r.put("success", false).put("error", "Rileggendo il file la situazione e' cambiata: "
                        + m.esito.name() + ". Non tocco niente, riprova.");

            Path copia = Path.of(COPIA);
            Files.createDirectories(copia.getParent());
            Files.writeString(copia, prima);
            r.put("copia", copia.toString()).put("voce", m.voce).put("riga", m.riga);

            Files.writeString(p, m.contenuto);

            Ris check = esegui("postfix", "check");
            if (check.codice != 0) {
                Files.writeString(p, prima);
                return r.put("success", false).put("ripristinato", true)
                        .put("error", "postfix check ha protestato, quindi ho rimesso il file di prima e "
                                + "NON ho ricaricato niente. Detto da Postfix: " + check.uscita.trim());
            }

            Ris reload = esegui("postfix", "reload");
            if (reload.codice != 0) {
                Files.writeString(p, prima);
                esegui("postfix", "reload");
                return r.put("success", false).put("ripristinato", true)
                        .put("error", "Il reload e' fallito: ho rimesso il file di prima e ricaricato. "
                                + "Detto da Postfix: " + reload.uscita.trim());
            }

            // Non basta che i comandi non abbiano protestato: si rilegge e si guarda.
            Modifica dopo = aggiungiRestrizione(Files.readString(p));
            if (dopo.esito != Esito.GIA_PRESENTE)
                return r.put("success", false)
                        .put("error", "Ho scritto e ricaricato, ma rileggendo master.cf la restrizione non "
                                + "risulta presente. Guarda " + MASTER + " prima di riprovare.");

            Ris m465 = esegui("postconf", "-M", m.voce + "/inet");
            r.put("vocePostfix", m465.uscita.trim());

            return r.put("success", true)
                    .put("nota", "Fatto: la voce " + m.voce + " ora rifiuta chi non si autentica, come "
                            + "chiedono RFC 6409 §4.3 e RFC 8314 §3.3. La porta 25 non e' stata toccata: "
                            + "li' le connessioni non autenticate devono continuare a passare, altrimenti "
                            + "non arriverebbe piu' posta dall'esterno. Copia di sicurezza in " + copia + ".");
        } catch (Exception e) {
            return new JSONObject().put("success", false).put("error", "errore: " + e.getMessage());
        }
    }

    private record Ris(int codice, String uscita) {}

    private static Ris esegui(String... cmd) {
        try {
            ProcessBuilder pb = new ProcessBuilder(cmd);
            Shell.applicaPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes());
            return new Ris(p.waitFor(), out);
        } catch (Exception e) {
            return new Ris(-1, String.valueOf(e.getMessage()));
        }
    }
}
