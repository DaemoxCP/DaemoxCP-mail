package org.mail_panel.system;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Il piano dipende da cio' che e' nella cache di pkg, quindi va riletto dopo lo scaricamento.
 *
 * Misurato sulla VM FreeBSD 15.1 il 23/10/2026, due volte sullo stesso pacchetto e sullo
 * stesso catalogo, a due minuti di distanza:
 *
 *   senza i file in /var/cache/pkg -> 3 cambi (installa lmdb0, installa mysql97-client,
 *                                     aggiorna postfix-mysql)
 *   con i file in /var/cache/pkg   -> 4 cambi, gli stessi piu' "rimuove lmdb 1.0.2,1"
 *
 * Il controllo di integrita' di pkg vede i conflitti sui file solo quando i pacchetti sono
 * scaricati. E il pannello RIFIUTA i piani che rimuovono pacchetti: quel rifiuto veniva
 * scavalcato ogni volta che i pacchetti non erano ancora scaricati, cioe' al primo tentativo.
 *
 * Qui si prova il confronto fra due piani: dev'essere insensibile a cio' che cambia per
 * forza fra la scheda e l'esecuzione (le protezioni da togliere) e sensibile a cio' che
 * conta (i cambiamenti).
 */
public class PlanAfterFetchTest {

    private static int falliti = 0;

    public static void main(String[] args) {

        // Il piano approvato: postfix-mysql era protetto, quindi andava sbloccato.
        JSONObject approvato = new JSONObject()
                .put("measured", true)
                .put("unlockedPackages", new JSONArray().put("postfix-mysql"))
                .put("changes", new JSONArray()
                        .put(cambio("installa", "lmdb0", "", "0.9.35"))
                        .put(cambio("installa", "mysql97-client", "", "9.7.2"))
                        .put(cambio("aggiorna", "postfix-mysql", "3.11.7_1,1", "3.11.7_3,1")));

        // Lo stesso piano ricalcolato DOPO lo sblocco vero: niente piu' da sbloccare, e i
        // cambiamenti arrivano in un altro ordine perche' li elenca un'altra simulazione.
        JSONObject dopoSblocco = new JSONObject()
                .put("measured", true)
                .put("unlockedPackages", new JSONArray())
                .put("changes", new JSONArray()
                        .put(cambio("aggiorna", "postfix-mysql", "3.11.7_1,1", "3.11.7_3,1"))
                        .put(cambio("installa", "mysql97-client", "", "9.7.2"))
                        .put(cambio("installa", "lmdb0", "", "0.9.35")));

        // Il piano con la rimozione che compare solo dopo lo scaricamento.
        JSONObject cresciuto = new JSONObject()
                .put("measured", true)
                .put("unlockedPackages", new JSONArray())
                .put("changes", new JSONArray()
                        .put(cambio("installa", "lmdb0", "", "0.9.35"))
                        .put(cambio("installa", "mysql97-client", "", "9.7.2"))
                        .put(cambio("aggiorna", "postfix-mysql", "3.11.7_1,1", "3.11.7_3,1"))
                        .put(cambio("rimuove", "lmdb", "1.0.2,1", "")));

        String fApprovato = PackagePlan.firmaDeiCambi(approvato);
        String fDopo = PackagePlan.firmaDeiCambi(dopoSblocco);
        String fCresciuto = PackagePlan.firmaDeiCambi(cresciuto);

        vero("lo sblocco gia' avvenuto non cambia la firma dei cambiamenti", fApprovato.equals(fDopo));
        vero("e nemmeno l'ordine in cui la simulazione li elenca", fApprovato.equals(fDopo));
        vero("una rimozione in piu' la cambia", !fApprovato.equals(fCresciuto));
        vero("la firma e' 16 cifre esadecimali", fApprovato.matches("[0-9a-f]{16}"));

        // La firma INTERA, invece, cambierebbe per il solo sblocco: e' il motivo per cui ne
        // serve una sui soli cambiamenti. Se un giorno qualcuno confrontasse quella, il
        // lavoro si fermerebbe sempre, e per il motivo sbagliato.
        vero("la firma intera cambia per il solo sblocco, e non andrebbe usata qui",
             !PackagePlan.signature(approvato).equals(PackagePlan.signature(dopoSblocco)));

        // Una versione di arrivo diversa e' un piano diverso.
        JSONObject altraVersione = new JSONObject()
                .put("measured", true).put("unlockedPackages", new JSONArray())
                .put("changes", new JSONArray()
                        .put(cambio("installa", "lmdb0", "", "0.9.35"))
                        .put(cambio("installa", "mysql97-client", "", "9.7.2"))
                        .put(cambio("aggiorna", "postfix-mysql", "3.11.7_1,1", "3.11.8,1")));
        vero("una versione di arrivo diversa cambia la firma",
             !fApprovato.equals(PackagePlan.firmaDeiCambi(altraVersione)));

        // Un pacchetto in meno nel piano e' un piano diverso: il controllo guarda in
        // entrambe le direzioni, non solo le aggiunte.
        JSONObject ridotto = new JSONObject()
                .put("measured", true).put("unlockedPackages", new JSONArray())
                .put("changes", new JSONArray()
                        .put(cambio("aggiorna", "postfix-mysql", "3.11.7_1,1", "3.11.7_3,1")));
        vero("un cambiamento in meno cambia la firma", !fApprovato.equals(PackagePlan.firmaDeiCambi(ridotto)));

        // Piani vuoti: nessuna eccezione, e due vuoti si somigliano.
        vero("un piano senza cambiamenti ha una firma stabile",
             PackagePlan.firmaDeiCambi(new JSONObject()).equals(
                     PackagePlan.firmaDeiCambi(new JSONObject().put("changes", new JSONArray()))));

        // Le righe da mostrare: una per cambiamento, leggibili, in ordine stabile.
        java.util.List<String> righe = PackagePlan.cambiInRighe(cresciuto);
        vero("le righe da mostrare sono una per cambiamento", righe.size() == 4);
        vero("  e nominano il pacchetto e le versioni",
             righe.toString().contains("postfix-mysql 3.11.7_1,1 -> 3.11.7_3,1"));
        vero("  la rimozione compare con la versione che c'e' adesso",
             righe.toString().contains("lmdb 1.0.2,1"));
        vero("  e l'ordine non dipende da quello della simulazione",
             righe.equals(PackagePlan.cambiInRighe(riordina(cresciuto))));

        // ===== I tre lavori sui pacchetti chiedono TUTTI la firma =====
        //
        // Era l'invariante che mancava: l'aggiornamento dei non protetti partiva senza, cioe'
        // eseguiva un "pkg upgrade -y" che nessuno aveva approvato riga per riga. Il controllo
        // avviene prima di prendere il turno e prima di toccare pkg, quindi si prova qui.
        for (String firma : new String[]{"", "   ", "abc", "ZZZZZZZZZZZZZZZZ", "0123456789abcde",
                                         "0123456789abcdef0", "0123456789ABCDEF"}) {
            vero("l'aggiornamento dei non protetti rifiuta la firma \"" + firma + "\"",
                 !UpdateManager.startUnlockedPackagesUpdate(firma).optBoolean("success"));
            vero("  la manutenzione rifiuta la stessa",
                 !UpdateManager.startMaintenance(firma).optBoolean("success"));
            vero("  e l'aggiornamento guidato pure",
                 !UpdateManager.startGuidedUpdate("nginx", firma).optBoolean("success"));
        }
        vero("e senza firma del tutto (null) non parte niente",
             !UpdateManager.startUnlockedPackagesUpdate(null).optBoolean("success")
             && !UpdateManager.startMaintenance(null).optBoolean("success")
             && !UpdateManager.startGuidedUpdate("nginx", null).optBoolean("success"));

        System.out.println(falliti == 0 ? "\nTUTTO OK" : "\n" + falliti + " PROVE FALLITE");
        if (falliti > 0) System.exit(1);
    }

    private static JSONObject cambio(String tipo, String nome, String da, String a) {
        return new JSONObject().put("tipo", tipo).put("nome", nome).put("da", da).put("a", a);
    }

    /** Lo stesso piano con i cambiamenti all'incontrario. */
    private static JSONObject riordina(JSONObject piano) {
        JSONArray c = piano.getJSONArray("changes"), r = new JSONArray();
        for (int i = c.length() - 1; i >= 0; i--) r.put(c.get(i));
        return new JSONObject(piano.toString()).put("changes", r);
    }

    private static void vero(String nome, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + nome);
        if (!ok) falliti++;
    }
}
