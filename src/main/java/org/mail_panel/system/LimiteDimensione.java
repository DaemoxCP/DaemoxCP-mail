package org.mail_panel.system;

import org.json.JSONObject;
import org.mail_panel.util.Shell;

/**
 * La dimensione massima di un messaggio, cioe' il parametro Postfix message_size_limit.
 *
 * Il campo "dimensione massima" esisteva gia' nella pagina dei limiti di invio, ma non era
 * collegato a niente: il valore si scriveva e non succedeva nulla. Qui viene collegato al
 * parametro vero, con la stessa disciplina usata altrove: si legge il valore attuale, si
 * scrive, si valida con "postfix check", e se la validazione fallisce si rimette quello di
 * prima senza ricaricare.
 *
 * Il valore in Postfix e' in BYTE, nell'interfaccia in megabyte: la conversione sta qui, in
 * un posto solo, invece che sparsa fra pagina e server dove due arrotondamenti diversi
 * finirebbero per mostrare un numero e salvarne un altro.
 */
public class LimiteDimensione {

    private LimiteDimensione() {}

    public static final int MEGA = 1024 * 1024;

    /** Megabyte -> byte. */
    public static long aByte(int mb) { return (long) mb * MEGA; }

    /** Byte -> megabyte, arrotondato per difetto ma mai a zero se c'e' un limite. */
    public static int aMega(long byteTotali) {
        if (byteTotali <= 0) return 0;
        int mb = (int) (byteTotali / MEGA);
        return mb == 0 ? 1 : mb;
    }

    /** Il valore attuale in megabyte, o -1 se non si riesce a leggerlo. */
    public static int leggiMega() {
        Ris r = esegui("postconf", "-h", "message_size_limit");
        if (r.codice != 0) return -1;
        try {
            return aMega(Long.parseLong(r.uscita.trim()));
        } catch (Exception e) {
            return -1;
        }
    }

    /**
     * Imposta il limite. Restituisce sempre un esito leggibile, mai un'eccezione muta.
     */
    public static JSONObject imposta(int mb) {
        JSONObject r = new JSONObject().put("megabyte", mb);
        if (mb < 1 || mb > 1024)
            return r.put("success", false)
                    .put("error", "Un limite di " + mb + " MB non ha senso: sono ammessi valori da 1 a 1024. "
                            + "Zero vorrebbe dire \"nessun limite\", che in Postfix si scrive diversamente e "
                            + "non e' quello che questo campo fa.");

        int prima = leggiMega();
        if (prima < 0)
            return r.put("success", false)
                    .put("error", "Non riesco a leggere il valore attuale di message_size_limit: non cambio "
                            + "niente. Senza sapere da dove si parte non saprei nemmeno come tornare indietro.");
        r.put("prima", prima);
        if (prima == mb)
            return r.put("success", true).put("invariato", true)
                    .put("nota", "Il limite era gia' " + mb + " MB: non ho toccato niente.");

        Ris set = esegui("postconf", "-e", "message_size_limit=" + aByte(mb));
        if (set.codice != 0)
            return r.put("success", false)
                    .put("error", "postconf ha rifiutato: " + set.uscita.trim());

        Ris check = esegui("postfix", "check");
        if (check.codice != 0) {
            esegui("postconf", "-e", "message_size_limit=" + aByte(prima));
            return r.put("success", false).put("ripristinato", true)
                    .put("error", "postfix check ha protestato, quindi ho rimesso " + prima + " MB e NON ho "
                            + "ricaricato niente. Detto da Postfix: " + check.uscita.trim());
        }

        Ris reload = esegui("postfix", "reload");
        if (reload.codice != 0) {
            esegui("postconf", "-e", "message_size_limit=" + aByte(prima));
            esegui("postfix", "reload");
            return r.put("success", false).put("ripristinato", true)
                    .put("error", "Il reload e' fallito: ho rimesso " + prima + " MB. Detto da Postfix: "
                            + reload.uscita.trim());
        }

        // Non basta che i comandi non abbiano protestato: si rilegge.
        int dopo = leggiMega();
        r.put("dopo", dopo);
        if (dopo != mb)
            return r.put("success", false)
                    .put("error", "Ho scritto " + mb + " MB e ricaricato, ma rileggendo Postfix riporta "
                            + dopo + " MB. Guarda main.cf prima di riprovare.");

        return r.put("success", true)
                .put("nota", "Dimensione massima dei messaggi portata da " + prima + " a " + mb
                        + " MB. Vale sia per la posta in arrivo sia per quella in uscita.");
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
