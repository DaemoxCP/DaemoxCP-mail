package org.mail_panel.system;

import org.json.JSONArray;
import org.json.JSONObject;
import org.mail_panel.database.MailDatabase;

import java.util.ArrayList;
import java.util.List;

/**
 * I pezzi nati dall'unificazione delle due sequenze: il filtro per dominio e la traduzione
 * dell'esito nelle righe della pagina DNS.
 */
public class MtaStsSequenceTest {

    static int failed = 0;
    static void require(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FALLITO ") + what);
        if (!ok) failed++;
    }

    static MailDatabase.Domain dom(String name) {
        MailDatabase.Domain d = new MailDatabase.Domain();
        d.domain = name;
        return d;
    }

    public static void main(String[] a) {
        List<MailDatabase.Domain> allItems = new ArrayList<>();
        for (String s : new String[]{"domain-d.test", "domain-b.test", "domain-a.test"}) allItems.add(dom(s));

        System.out.println("\n== filtra(): il filtro per dominio ==");
        require("null vuol dire tutti", MtaStsSetup.filter(allItems, null).size() == 3);
        require("un nome preciso ne lascia uno", MtaStsSetup.filter(allItems, "domain-d.test").size() == 1);
        require("le maiuscole non contano",
                MtaStsSetup.filter(allItems, "DoMaIn-D.TeSt").size() == 1);
        // Se il confronto fosse "contiene", "ake.net" pescherebbe domain-d.test e la sequenza
        // lavorerebbe su un dominio che nessuno ha chiesto.
        require("il confronto e' esatto, non 'contiene'",
                MtaStsSetup.filter(allItems, "ake.net").isEmpty());
        require("un dominio che non esiste da lista VUOTA (e' la guardia del falso successo)",
                MtaStsSetup.filter(allItems, "nonesiste.invalid").isEmpty());
        require("una lista nulla non fa esplodere niente",
                MtaStsSetup.filter(null, "x.it").isEmpty());

        System.out.println("\n== comeVoci(): l'esito tradotto per la pagina DNS ==");
        JSONObject outcome = new JSONObject()
            .put("success", true)
            .put("steps", new JSONArray()
                .put(new JSONObject().put("key", "include").put("title", "Riga di include")
                        .put("ok", true).put("messageText", "era gia' a posto"))
                .put(new JSONObject().put("key", "cname").put("title", "CNAME mta-sts")
                        .put("detail", new JSONArray()
                            .put(new JSONObject().put("domain", "domain-d.test").put("ok", true)
                                    .put("messageText", "Record CNAME creato"))))
                .put(new JSONObject().put("key", "txt").put("title", "Prova e record TXT")
                        .put("detail", new JSONArray()
                            .put(new JSONObject().put("domain", "a.it").put("ok", true).put("messageText", "ok"))
                            .put(new JSONObject().put("domain", "b.it").put("ok", false)
                                    .put("messageText", "la politica non risponde ancora")))));

        JSONArray v = MtaStsSetup.asEntries(outcome);
        require("tre passi diventano tre righe", v.length() == 3);
        require("il passo semplice conserva titolo ed esito",
                v.getJSONObject(0).getString("title").equals("Riga di include")
                && v.getJSONObject(0).getBoolean("ok"));
        require("un passo per dominio tutto riuscito e' verde", v.getJSONObject(1).getBoolean("ok"));
        require("il dominio compare nel messaggio",
                v.getJSONObject(1).getString("messageText").contains("domain-d.test"));
        // La riga rossa e' l'unica che spiega: se una sola fallisce, il passo NON e' verde.
        require("basta una riga fallita perche' il passo non sia verde",
                !v.getJSONObject(2).getBoolean("ok"));
        require("nel messaggio ci sono ENTRAMBE le righe, non solo la prima",
                v.getJSONObject(2).getString("messageText").contains("a.it")
                && v.getJSONObject(2).getString("messageText").contains("b.it"));

        System.out.println("\n== comeVoci(): una sequenza interrotta non sparisce ==");
        JSONObject broken = new JSONObject().put("success", false)
            .put("error", "Senza la 443 configurata la politica non puo' rispondere: mi fermo.")
            .put("steps", new JSONArray()
                .put(new JSONObject().put("title", "Riga di include").put("ok", true)
                        .put("messageText", "done")));
        JSONArray vr = MtaStsSetup.asEntries(broken);
        require("i passi gia' fatti restano", vr.length() == 2);
        // Un elenco di passi riusciti che si interrompe senza dire perche' somiglia a un successo.
        require("in fondo c'e' la riga rossa che dice perche' si e' fermata",
                !vr.getJSONObject(1).getBoolean("ok")
                && vr.getJSONObject(1).getString("messageText").contains("443"));

        System.out.println("\n== comeVoci(): un passo per dominio VUOTO non e' un successo ==");
        JSONArray vv = MtaStsSetup.asEntries(new JSONObject().put("success", true)
            .put("steps", new JSONArray().put(new JSONObject().put("title", "CNAME")
                    .put("detail", new JSONArray()))));
        require("nessuna riga esaminata non puo' valere verde", !vv.getJSONObject(0).getBoolean("ok"));

        System.out.println("\n" + (failed == 0 ? "TUTTO VERDE" : failed + " CONTROLLI FALLITI"));
        if (failed > 0) System.exit(1);
    }
}
