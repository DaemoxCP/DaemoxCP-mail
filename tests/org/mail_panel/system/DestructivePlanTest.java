package org.mail_panel.system;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Il pannello non esegue piani che RIMUOVONO o RETROCEDONO pacchetti.
 *
 * E' una regola del pannello, non un fatto di pkg: un aggiornamento che toglie un pacchetto
 * da un server di posta, o che ne riporta indietro la versione, va deciso da una persona che
 * sa chi lo usa.
 *
 * Stava scritta in un punto solo — la scheda di un pacchetto protetto — e mancava negli altri
 * due lavori che eseguono un piano. Misurato sulla VM FreeBSD 15.1 il 23/10/2026, sulla
 * stessa macchina e sullo stesso pacchetto:
 *
 *   aggiornamento guidato di postfix-mysql -> «[block] Il piano rimuove pacchetti:
 *                                             pkg rimuoverebbe lmdb 1.0.2,1»
 *   manutenzione completa                  -> runnable=true, impedimenti [], e nel piano
 *                                             «rimuove lmdb 1.0.2,1»
 *
 * Due risposte opposte alla stessa domanda, e quella permissiva stava sul pulsante che si
 * preme per aggiornare tutto.
 *
 * Qui si prova la regola, che adesso e' una sola funzione. Che i tre lavori la chiedano
 * davvero si vede sulla macchina: la manutenzione completa, su quella VM, si ferma.
 */
public class DestructivePlanTest {

    private static int falliti = 0;

    public static void main(String[] args) {

        // ===== Il caso misurato: il piano della manutenzione su quella macchina =====
        JSONObject vero = piano(
                cambio("installa", "lmdb0", "", "0.9.35"),
                cambio("aggiorna", "postfix-mysql", "3.11.7_1,1", "3.11.7_3,1"),
                cambio("rimuove", "lmdb", "1.0.2,1", ""));
        String motivo = UpdateManager.motivoPianoDistruttivo(vero);
        vero("il piano misurato sulla VM non si esegue", motivo != null);
        vero("  e il motivo nomina il pacchetto e la versione",
             motivo != null && motivo.contains("lmdb 1.0.2,1"));
        JSONObject d = UpdateManager.cambiamentiDistruttivi(vero);
        vero("  una rimozione, nessuna retrocessione",
             d.getJSONArray("removes").length() == 1 && d.getJSONArray("downgrades").isEmpty());
        vero("  e l'installazione e l'aggiornamento non c'entrano",
             !d.getJSONArray("removes").toString().contains("lmdb0")
             && !d.getJSONArray("removes").toString().contains("postfix-mysql"));

        // ===== Una retrocessione =====
        JSONObject retro = piano(cambio("retrocede", "redis", "8.10.2", "8.9.0"));
        String m2 = UpdateManager.motivoPianoDistruttivo(retro);
        vero("una retrocessione non si esegue", m2 != null);
        vero("  e il motivo dice da quale versione a quale",
             m2 != null && m2.contains("8.10.2") && m2.contains("8.9.0"));

        // ===== Tutte e due insieme: si dicono entrambe =====
        String m3 = UpdateManager.motivoPianoDistruttivo(piano(
                cambio("rimuove", "lmdb", "1.0.2,1", ""),
                cambio("retrocede", "redis", "8.10.2", "8.9.0")));
        vero("rimozione e retrocessione insieme: il motivo le dice entrambe",
             m3 != null && m3.contains("lmdb") && m3.contains("redis"));

        // ===== Un piano che non tocca niente in quel modo: si esegue =====
        vero("aggiornamenti, installazioni e reinstallazioni non fermano niente",
             UpdateManager.motivoPianoDistruttivo(piano(
                 cambio("aggiorna", "nginx", "1.30.5_2,3", "1.30.6,3"),
                 cambio("installa", "lmdb0", "", "0.9.35"),
                 cambio("reinstalla", "cyrus-sasl", "2.1.28_5", "2.1.28_5"))) == null);

        // ===== Piani vuoti o assenti: nessun motivo inventato =====
        vero("un piano senza cambiamenti non si ferma",
             UpdateManager.motivoPianoDistruttivo(piano()) == null);
        vero("un piano senza la chiave 'changes' non si ferma",
             UpdateManager.motivoPianoDistruttivo(new JSONObject()) == null);
        vero("e nemmeno un piano nullo",
             UpdateManager.motivoPianoDistruttivo(null) == null);
        vero("su un piano nullo l'elenco e' vuoto, non nullo",
             UpdateManager.cambiamentiDistruttivi(null).getJSONArray("removes").isEmpty());

        // ===== Molte rimozioni: si nominano tutte, non solo la prima =====
        String m4 = UpdateManager.motivoPianoDistruttivo(piano(
                cambio("rimuove", "lmdb", "1.0.2,1", ""),
                cambio("rimuove", "tinycdb", "0.81", ""),
                cambio("rimuove", "libtlsrpt", "0.5.1", "")));
        vero("tre rimozioni, tutte nominate",
             m4 != null && m4.contains("lmdb") && m4.contains("tinycdb") && m4.contains("libtlsrpt"));

        System.out.println(falliti == 0 ? "\nTUTTO OK" : "\n" + falliti + " PROVE FALLITE");
        if (falliti > 0) System.exit(1);
    }

    private static JSONObject cambio(String tipo, String nome, String da, String a) {
        return new JSONObject().put("tipo", tipo).put("nome", nome).put("da", da).put("a", a);
    }

    private static JSONObject piano(JSONObject... cambi) {
        JSONArray c = new JSONArray();
        for (JSONObject x : cambi) c.put(x);
        return new JSONObject().put("changes", c).put("measured", true).put("runnable", true);
    }

    private static void vero(String nome, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + nome);
        if (!ok) falliti++;
    }
}
