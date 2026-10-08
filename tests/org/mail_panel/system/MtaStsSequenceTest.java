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

    static int falliti = 0;
    static void esigi(String cosa, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FALLITO ") + cosa);
        if (!ok) falliti++;
    }

    static MailDatabase.Domain dom(String nome) {
        MailDatabase.Domain d = new MailDatabase.Domain();
        d.domain = nome;
        return d;
    }

    public static void main(String[] a) {
        List<MailDatabase.Domain> tutti = new ArrayList<>();
        for (String s : new String[]{"domain-d.test", "domain-b.test", "domain-a.test"}) tutti.add(dom(s));

        System.out.println("\n== filtra(): il filtro per dominio ==");
        esigi("null vuol dire tutti", AttivaMtaSts.filtra(tutti, null).size() == 3);
        esigi("un nome preciso ne lascia uno", AttivaMtaSts.filtra(tutti, "domain-d.test").size() == 1);
        esigi("le maiuscole non contano",
                AttivaMtaSts.filtra(tutti, "DoMaIn-D.TeSt").size() == 1);
        // Se il confronto fosse "contiene", "ake.net" pescherebbe domain-d.test e la sequenza
        // lavorerebbe su un dominio che nessuno ha chiesto.
        esigi("il confronto e' esatto, non 'contiene'",
                AttivaMtaSts.filtra(tutti, "ake.net").isEmpty());
        esigi("un dominio che non esiste da lista VUOTA (e' la guardia del falso successo)",
                AttivaMtaSts.filtra(tutti, "nonesiste.invalid").isEmpty());
        esigi("una lista nulla non fa esplodere niente",
                AttivaMtaSts.filtra(null, "x.it").isEmpty());

        System.out.println("\n== comeVoci(): l'esito tradotto per la pagina DNS ==");
        JSONObject esito = new JSONObject()
            .put("success", true)
            .put("passi", new JSONArray()
                .put(new JSONObject().put("chiave", "include").put("titolo", "Riga di include")
                        .put("ok", true).put("messaggio", "era gia' a posto"))
                .put(new JSONObject().put("chiave", "cname").put("titolo", "CNAME mta-sts")
                        .put("dettaglio", new JSONArray()
                            .put(new JSONObject().put("dominio", "domain-d.test").put("ok", true)
                                    .put("messaggio", "Record CNAME creato"))))
                .put(new JSONObject().put("chiave", "txt").put("titolo", "Prova e record TXT")
                        .put("dettaglio", new JSONArray()
                            .put(new JSONObject().put("dominio", "a.it").put("ok", true).put("messaggio", "ok"))
                            .put(new JSONObject().put("dominio", "b.it").put("ok", false)
                                    .put("messaggio", "la politica non risponde ancora")))));

        JSONArray v = AttivaMtaSts.comeVoci(esito);
        esigi("tre passi diventano tre righe", v.length() == 3);
        esigi("il passo semplice conserva titolo ed esito",
                v.getJSONObject(0).getString("titolo").equals("Riga di include")
                && v.getJSONObject(0).getBoolean("ok"));
        esigi("un passo per dominio tutto riuscito e' verde", v.getJSONObject(1).getBoolean("ok"));
        esigi("il dominio compare nel messaggio",
                v.getJSONObject(1).getString("messaggio").contains("domain-d.test"));
        // La riga rossa e' l'unica che spiega: se una sola fallisce, il passo NON e' verde.
        esigi("basta una riga fallita perche' il passo non sia verde",
                !v.getJSONObject(2).getBoolean("ok"));
        esigi("nel messaggio ci sono ENTRAMBE le righe, non solo la prima",
                v.getJSONObject(2).getString("messaggio").contains("a.it")
                && v.getJSONObject(2).getString("messaggio").contains("b.it"));

        System.out.println("\n== comeVoci(): una sequenza interrotta non sparisce ==");
        JSONObject rotto = new JSONObject().put("success", false)
            .put("error", "Senza la 443 configurata la politica non puo' rispondere: mi fermo.")
            .put("passi", new JSONArray()
                .put(new JSONObject().put("titolo", "Riga di include").put("ok", true)
                        .put("messaggio", "fatto")));
        JSONArray vr = AttivaMtaSts.comeVoci(rotto);
        esigi("i passi gia' fatti restano", vr.length() == 2);
        // Un elenco di passi riusciti che si interrompe senza dire perche' somiglia a un successo.
        esigi("in fondo c'e' la riga rossa che dice perche' si e' fermata",
                !vr.getJSONObject(1).getBoolean("ok")
                && vr.getJSONObject(1).getString("messaggio").contains("443"));

        System.out.println("\n== comeVoci(): un passo per dominio VUOTO non e' un successo ==");
        JSONArray vv = AttivaMtaSts.comeVoci(new JSONObject().put("success", true)
            .put("passi", new JSONArray().put(new JSONObject().put("titolo", "CNAME")
                    .put("dettaglio", new JSONArray()))));
        esigi("nessuna riga esaminata non puo' valere verde", !vv.getJSONObject(0).getBoolean("ok"));

        System.out.println("\n" + (falliti == 0 ? "TUTTO VERDE" : falliti + " CONTROLLI FALLITI"));
        if (falliti > 0) System.exit(1);
    }
}
