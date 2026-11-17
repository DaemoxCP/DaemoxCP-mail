package org.daemoxcp.mail.system;

import org.json.JSONObject;
import org.daemoxcp.mail.i18n.I18n;
import org.daemoxcp.mail.util.Shell;

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
public class MessageSizeLimit {

    private MessageSizeLimit() {}

    public static final int MEGA = 1024 * 1024;

    /** Megabyte -> byte. */
    public static long toBytes(int mb) { return (long) mb * MEGA; }

    /** Byte -> megabyte, arrotondato per difetto ma mai a zero se c'e' un limite. */
    public static int aMega(long totalBytes) {
        if (totalBytes <= 0) return 0;
        int mb = (int) (totalBytes / MEGA);
        return mb == 0 ? 1 : mb;
    }

    /** Il valore attuale in megabyte, o -1 se non si riesce a leggerlo. */
    public static int readMegabytes() {
        RunResult r = run("postconf", "-h", "message_size_limit");
        if (r.code != 0) return -1;
        try {
            return aMega(Long.parseLong(r.output.trim()));
        } catch (Exception e) {
            return -1;
        }
    }

    /**
     * Imposta il limite. Restituisce sempre un esito leggibile, mai un'eccezione muta.
     */
    public static JSONObject set(int mb) {
        JSONObject r = new JSONObject().put("megabytes", mb);
        if (mb < 1 || mb > 1024)
            return r.put("success", false)
                    .put("error", I18n.tr("server.size.outOfRange", Map.of("mb", mb)));

        int before = readMegabytes();
        if (before < 0)
            return r.put("success", false)
                    .put("error", I18n.tr("server.size.unreadable"));
        r.put("before", before);
        if (before == mb)
            return r.put("success", true).put("unchanged", true)
                    .put("note", I18n.tr("server.size.unchanged", Map.of("mb", mb)));

        RunResult set = run("postconf", "-e", "message_size_limit=" + toBytes(mb));
        if (set.code != 0)
            return r.put("success", false)
                    .put("error", I18n.tr("server.size.postconfRefused", Map.of("output", set.output.trim())));

        RunResult check = run("postfix", "check");
        if (check.code != 0) {
            run("postconf", "-e", "message_size_limit=" + toBytes(before));
            return r.put("success", false).put("restored", true)
                    .put("error", I18n.tr("server.size.checkFailed", Map.of("before", before, "output", check.output.trim())));
        }

        RunResult reload = run("postfix", "reload");
        if (reload.code != 0) {
            run("postconf", "-e", "message_size_limit=" + toBytes(before));
            run("postfix", "reload");
            return r.put("success", false).put("restored", true)
                    .put("error", I18n.tr("server.size.reloadFailed", Map.of("before", before, "output", reload.output.trim())));
        }

        // Non basta che i comandi non abbiano protestato: si rilegge.
        int after = readMegabytes();
        r.put("after", after);
        if (after != mb)
            return r.put("success", false)
                    .put("error", I18n.tr("server.size.readBackDiffers", Map.of("mb", mb, "after", after)));

        return r.put("success", true)
                .put("note", I18n.tr("server.size.changed", Map.of("before", before, "mb", mb)));
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
