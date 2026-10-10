package org.mail_panel.system;

import org.json.JSONObject;
import org.mail_panel.i18n.I18n;
import org.mail_panel.util.Shell;

import java.util.Map;

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
 *
 * Le note e gli errori sono per chi usa il pannello: nella lingua della richiesta (server.size.*).
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
                    .put("error", I18n.tr("server.size.outOfRange", Map.of("mb", mb)));

        int prima = leggiMega();
        if (prima < 0)
            return r.put("success", false)
                    .put("error", I18n.tr("server.size.unreadable"));
        r.put("prima", prima);
        if (prima == mb)
            return r.put("success", true).put("invariato", true)
                    .put("nota", I18n.tr("server.size.unchanged", Map.of("mb", mb)));

        Ris set = esegui("postconf", "-e", "message_size_limit=" + aByte(mb));
        if (set.codice != 0)
            return r.put("success", false)
                    .put("error", I18n.tr("server.size.postconfRefused", Map.of("output", set.uscita.trim())));

        Ris check = esegui("postfix", "check");
        if (check.codice != 0) {
            esegui("postconf", "-e", "message_size_limit=" + aByte(prima));
            return r.put("success", false).put("ripristinato", true)
                    .put("error", I18n.tr("server.size.checkFailed", Map.of("before", prima, "output", check.uscita.trim())));
        }

        Ris reload = esegui("postfix", "reload");
        if (reload.codice != 0) {
            esegui("postconf", "-e", "message_size_limit=" + aByte(prima));
            esegui("postfix", "reload");
            return r.put("success", false).put("ripristinato", true)
                    .put("error", I18n.tr("server.size.reloadFailed", Map.of("before", prima, "output", reload.uscita.trim())));
        }

        // Non basta che i comandi non abbiano protestato: si rilegge.
        int dopo = leggiMega();
        r.put("dopo", dopo);
        if (dopo != mb)
            return r.put("success", false)
                    .put("error", I18n.tr("server.size.readBackDiffers", Map.of("mb", mb, "after", dopo)));

        return r.put("success", true)
                .put("nota", I18n.tr("server.size.changed", Map.of("before", prima, "mb", mb)));
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
