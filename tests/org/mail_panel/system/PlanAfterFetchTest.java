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

    private static int failures = 0;

    public static void main(String[] args) {

        // Il piano approvato: postfix-mysql era protetto, quindi andava sbloccato.
        JSONObject approved = new JSONObject()
                .put("measured", true)
                .put("unlockedPackages", new JSONArray().put("postfix-mysql"))
                .put("changes", new JSONArray()
                        .put(change("installa", "lmdb0", "", "0.9.35"))
                        .put(change("installa", "mysql97-client", "", "9.7.2"))
                        .put(change("aggiorna", "postfix-mysql", "3.11.7_1,1", "3.11.7_3,1")));

        // Lo stesso piano ricalcolato DOPO lo sblocco vero: niente piu' da sbloccare, e i
        // cambiamenti arrivano in un altro ordine perche' li elenca un'altra simulazione.
        JSONObject afterUnlock = new JSONObject()
                .put("measured", true)
                .put("unlockedPackages", new JSONArray())
                .put("changes", new JSONArray()
                        .put(change("aggiorna", "postfix-mysql", "3.11.7_1,1", "3.11.7_3,1"))
                        .put(change("installa", "mysql97-client", "", "9.7.2"))
                        .put(change("installa", "lmdb0", "", "0.9.35")));

        // Il piano con la rimozione che compare solo dopo lo scaricamento.
        JSONObject grown = new JSONObject()
                .put("measured", true)
                .put("unlockedPackages", new JSONArray())
                .put("changes", new JSONArray()
                        .put(change("installa", "lmdb0", "", "0.9.35"))
                        .put(change("installa", "mysql97-client", "", "9.7.2"))
                        .put(change("aggiorna", "postfix-mysql", "3.11.7_1,1", "3.11.7_3,1"))
                        .put(change("rimuove", "lmdb", "1.0.2,1", "")));

        String approvedSignature = PackagePlan.changesSignature(approved);
        String afterSignature = PackagePlan.changesSignature(afterUnlock);
        String grownSignature = PackagePlan.changesSignature(grown);

        check("lo sblocco gia' avvenuto non cambia la firma dei cambiamenti", approvedSignature.equals(afterSignature));
        check("e nemmeno l'ordine in cui la simulazione li elenca", approvedSignature.equals(afterSignature));
        check("una rimozione in piu' la cambia", !approvedSignature.equals(grownSignature));
        check("la firma e' 16 cifre esadecimali", approvedSignature.matches("[0-9a-f]{16}"));

        // La firma INTERA, invece, cambierebbe per il solo sblocco: e' il motivo per cui ne
        // serve una sui soli cambiamenti. Se un giorno qualcuno confrontasse quella, il
        // lavoro si fermerebbe sempre, e per il motivo sbagliato.
        check("la firma intera cambia per il solo sblocco, e non andrebbe usata qui",
             !PackagePlan.signature(approved).equals(PackagePlan.signature(afterUnlock)));

        // Una versione di arrivo diversa e' un piano diverso.
        JSONObject otherVersion = new JSONObject()
                .put("measured", true).put("unlockedPackages", new JSONArray())
                .put("changes", new JSONArray()
                        .put(change("installa", "lmdb0", "", "0.9.35"))
                        .put(change("installa", "mysql97-client", "", "9.7.2"))
                        .put(change("aggiorna", "postfix-mysql", "3.11.7_1,1", "3.11.8,1")));
        check("una versione di arrivo diversa cambia la firma",
             !approvedSignature.equals(PackagePlan.changesSignature(otherVersion)));

        // Un pacchetto in meno nel piano e' un piano diverso: il controllo guarda in
        // entrambe le direzioni, non solo le aggiunte.
        JSONObject reduced = new JSONObject()
                .put("measured", true).put("unlockedPackages", new JSONArray())
                .put("changes", new JSONArray()
                        .put(change("aggiorna", "postfix-mysql", "3.11.7_1,1", "3.11.7_3,1")));
        check("un cambiamento in meno cambia la firma", !approvedSignature.equals(PackagePlan.changesSignature(reduced)));

        // Piani vuoti: nessuna eccezione, e due vuoti si somigliano.
        check("un piano senza cambiamenti ha una firma stabile",
             PackagePlan.changesSignature(new JSONObject()).equals(
                     PackagePlan.changesSignature(new JSONObject().put("changes", new JSONArray()))));

        // Le righe da mostrare: una per cambiamento, leggibili, in ordine stabile.
        java.util.List<String> lines = PackagePlan.changesInLines(grown);
        check("le righe da mostrare sono una per cambiamento", lines.size() == 4);
        check("  e nominano il pacchetto e le versioni",
             lines.toString().contains("postfix-mysql 3.11.7_1,1 -> 3.11.7_3,1"));
        check("  la rimozione compare con la versione che c'e' adesso",
             lines.toString().contains("lmdb 1.0.2,1"));
        check("  e l'ordine non dipende da quello della simulazione",
             lines.equals(PackagePlan.changesInLines(reorder(grown))));

        // ===== I tre lavori sui pacchetti chiedono TUTTI la firma =====
        //
        // Era l'invariante che mancava: l'aggiornamento dei non protetti partiva senza, cioe'
        // eseguiva un "pkg upgrade -y" che nessuno aveva approvato riga per riga. Il controllo
        // avviene prima di prendere il turno e prima di toccare pkg, quindi si prova qui.
        for (String signature : new String[]{"", "   ", "abc", "ZZZZZZZZZZZZZZZZ", "0123456789abcde",
                                         "0123456789abcdef0", "0123456789ABCDEF"}) {
            check("l'aggiornamento dei non protetti rifiuta la firma \"" + signature + "\"",
                 !UpdateManager.startUnlockedPackagesUpdate(signature).optBoolean("success"));
            check("  la manutenzione rifiuta la stessa",
                 !UpdateManager.startMaintenance(signature).optBoolean("success"));
            check("  e l'aggiornamento guidato pure",
                 !UpdateManager.startGuidedUpdate("nginx", signature).optBoolean("success"));
        }
        check("e senza firma del tutto (null) non parte niente",
             !UpdateManager.startUnlockedPackagesUpdate(null).optBoolean("success")
             && !UpdateManager.startMaintenance(null).optBoolean("success")
             && !UpdateManager.startGuidedUpdate("nginx", null).optBoolean("success"));

        System.out.println(failures == 0 ? "\nTUTTO OK" : "\n" + failures + " PROVE FALLITE");
        if (failures > 0) System.exit(1);
    }

    private static JSONObject change(String type, String name, String from, String a) {
        return new JSONObject().put("tipo", type).put("nome", name).put("da", from).put("a", a);
    }

    /** Lo stesso piano con i cambiamenti all'incontrario. */
    private static JSONObject reorder(JSONObject plan) {
        JSONArray c = plan.getJSONArray("changes"), r = new JSONArray();
        for (int i = c.length() - 1; i >= 0; i--) r.put(c.get(i));
        return new JSONObject(plan.toString()).put("changes", r);
    }

    private static void check(String name, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + name);
        if (!ok) failures++;
    }
}
