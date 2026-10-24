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

    private static int failures = 0;

    public static void main(String[] args) {

        // ===== Il caso misurato: il piano della manutenzione su quella macchina =====
        JSONObject real = plan(
                change("installa", "lmdb0", "", "0.9.35"),
                change("aggiorna", "postfix-mysql", "3.11.7_1,1", "3.11.7_3,1"),
                change("rimuove", "lmdb", "1.0.2,1", ""));
        String reason = UpdateManager.destructivePlanReason(real);
        check("il piano misurato sulla VM non si esegue", reason != null);
        check("  e il motivo nomina il pacchetto e la versione",
             reason != null && reason.contains("lmdb 1.0.2,1"));
        JSONObject d = UpdateManager.destructiveChanges(real);
        check("  una rimozione, nessuna retrocessione",
             d.getJSONArray("removes").length() == 1 && d.getJSONArray("downgrades").isEmpty());
        check("  e l'installazione e l'aggiornamento non c'entrano",
             !d.getJSONArray("removes").toString().contains("lmdb0")
             && !d.getJSONArray("removes").toString().contains("postfix-mysql"));

        // ===== Una retrocessione =====
        JSONObject downgrade = plan(change("retrocede", "redis", "8.10.2", "8.9.0"));
        String m2 = UpdateManager.destructivePlanReason(downgrade);
        check("una retrocessione non si esegue", m2 != null);
        check("  e il motivo dice da quale versione a quale",
             m2 != null && m2.contains("8.10.2") && m2.contains("8.9.0"));

        // ===== Tutte e due insieme: si dicono entrambe =====
        String m3 = UpdateManager.destructivePlanReason(plan(
                change("rimuove", "lmdb", "1.0.2,1", ""),
                change("retrocede", "redis", "8.10.2", "8.9.0")));
        check("rimozione e retrocessione insieme: il motivo le dice entrambe",
             m3 != null && m3.contains("lmdb") && m3.contains("redis"));

        // ===== Un piano che non tocca niente in quel modo: si esegue =====
        check("aggiornamenti, installazioni e reinstallazioni non fermano niente",
             UpdateManager.destructivePlanReason(plan(
                 change("aggiorna", "nginx", "1.30.5_2,3", "1.30.6,3"),
                 change("installa", "lmdb0", "", "0.9.35"),
                 change("reinstalla", "cyrus-sasl", "2.1.28_5", "2.1.28_5"))) == null);

        // ===== Piani vuoti o assenti: nessun motivo inventato =====
        check("un piano senza cambiamenti non si ferma",
             UpdateManager.destructivePlanReason(plan()) == null);
        check("un piano senza la chiave 'changes' non si ferma",
             UpdateManager.destructivePlanReason(new JSONObject()) == null);
        check("e nemmeno un piano nullo",
             UpdateManager.destructivePlanReason(null) == null);
        check("su un piano nullo l'elenco e' vuoto, non nullo",
             UpdateManager.destructiveChanges(null).getJSONArray("removes").isEmpty());

        // ===== Molte rimozioni: si nominano tutte, non solo la prima =====
        String m4 = UpdateManager.destructivePlanReason(plan(
                change("rimuove", "lmdb", "1.0.2,1", ""),
                change("rimuove", "tinycdb", "0.81", ""),
                change("rimuove", "libtlsrpt", "0.5.1", "")));
        check("tre rimozioni, tutte nominate",
             m4 != null && m4.contains("lmdb") && m4.contains("tinycdb") && m4.contains("libtlsrpt"));

        System.out.println(failures == 0 ? "\nTUTTO OK" : "\n" + failures + " PROVE FALLITE");
        if (failures > 0) System.exit(1);
    }

    private static JSONObject change(String type, String name, String from, String a) {
        return new JSONObject().put("tipo", type).put("nome", name).put("da", from).put("a", a);
    }

    private static JSONObject plan(JSONObject... changeList) {
        JSONArray c = new JSONArray();
        for (JSONObject x : changeList) c.put(x);
        return new JSONObject().put("changes", c).put("measured", true).put("runnable", true);
    }

    private static void check(String name, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + name);
        if (!ok) failures++;
    }
}
