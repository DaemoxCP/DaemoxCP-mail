package org.mail_panel.system;

import java.util.Map;
import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Cio' che e' cambiato senza essere nel piano firmato.
 *
 * Il confronto atteso/trovato di {@code verifyOutcome} scorre le righe del PIANO: vede un
 * pacchetto del piano che non e' arrivato dove doveva, e NON puo' vedere un pacchetto
 * cambiato che nel piano non c'era. Il 18 ottobre 2026, sulla VM, e' successo davvero: il
 * piano firmato 465385a9d669def8 aveva dieci cambi e nessuna rimozione, pkg ha trovato un
 * conflitto durante l'esecuzione (lmdb0 contro lmdb su /usr/local/bin/mdb_copy), ha rifatto
 * il calcolo e ha RIMOSSO lmdb. La verifica ha controllato i suoi dieci, li ha trovati tutti
 * "ok" e ha concluso "verifica superata".
 *
 * Qui si prova il confronto con l'inventario, che guarda dall'altra direzione. Il primo caso
 * e' quel reperto, con i suoi dati.
 *
 * Le righe di inventario sono quelle vere di {@code pkg query '%n\t%v\t%k'}, lette dal
 * parser vero: una prova su mappe costruite a mano salterebbe proprio il punto dove un
 * difetto di chiavi o di formato si nasconde.
 */
public class PlanDivergenceTest {

    private static int failures = 0, skipped = 0;

    public static void main(String[] args) {

        // ===== 1. Il reperto 14, con i suoi dati =====
        // Prima: lmdb installato. Il piano: installa lmdb0, aggiorna nginx, reinstalla
        // cyrus-sasl. Nessuna rimozione. Dopo: lmdb non c'e' piu'.
        Map<String, String> before = PackagePlan.versionsOnly(PackagePlan.installed(
                "lmdb\t1.0.2,1\t0\n"
              + "nginx\t1.30.5_1,3\t1\n"
              + "cyrus-sasl\t2.1.28_5\t0\n"));
        Map<String, String> after = PackagePlan.versionsOnly(PackagePlan.installed(
                "lmdb0\t0.9.35\t0\n"
              + "nginx\t1.30.5_4,3\t1\n"
              + "cyrus-sasl\t2.1.28_5\t0\n"));
        JSONObject plan = plan(
                change("installa", "lmdb0", "", "0.9.35"),
                change("aggiorna", "nginx", "1.30.5_1,3", "1.30.5_4,3"),
                change("reinstalla", "cyrus-sasl", "2.1.28_5", "2.1.28_5"));

        JSONArray d = PackagePlan.divergences(before, after, plan);
        check("il reperto 14: la rimozione fuori dal piano viene vista", d.length() == 1);
        if (d.length() == 1) {
            JSONObject x = d.getJSONObject(0);
            check("  e' lmdb", "lmdb".equals(x.optString("name")));
            check("  ed e' stato rimosso", "removed".equals(x.optString("happened")));
            check("  con la versione che c'era", "1.0.2,1".equals(x.optString("from")));
            check("  e il motivo e' che nel piano non c'era", !x.optString("why").isEmpty());
            check("  la riga da mostrare nomina il pacchetto",
                 PackagePlan.divergenceInLine(x).contains("lmdb"));
        }
        check("l'installazione prevista e l'aggiornamento previsto non sono divergenze",
             d.length() == 1);

        // ===== 2. Tutto come previsto: nessuna divergenza =====
        check("piano rispettato alla lettera: nessuna divergenza",
             PackagePlan.divergences(
                 PackagePlan.versionsOnly(PackagePlan.installed("nginx\t1.30.5_1,3\t1\nredis\t8.10.2\t1\n")),
                 PackagePlan.versionsOnly(PackagePlan.installed("nginx\t1.30.6,3\t1\nredis\t8.10.2\t1\n")),
                 plan(change("aggiorna", "nginx", "1.30.5_1,3", "1.30.6,3"))).isEmpty());

        // ===== 3. Un pacchetto installato che nel piano non c'era =====
        JSONArray inst = PackagePlan.divergences(
                PackagePlan.versionsOnly(PackagePlan.installed("nginx\t1.30.6,3\t1\n")),
                PackagePlan.versionsOnly(PackagePlan.installed("nginx\t1.30.6,3\t1\nlibzip\t1.12.1\t0\n")),
                plan());
        check("un'installazione fuori dal piano viene vista",
             inst.length() == 1 && "installed".equals(field(inst, "happened"))
             && "libzip".equals(field(inst, "name")));
        check("  e dice a quale versione", "1.12.1".equals(field(inst, "to")));

        // ===== 4. Nel piano c'era, ma e' finito a una versione DIVERSA =====
        JSONArray other = PackagePlan.divergences(
                PackagePlan.versionsOnly(PackagePlan.installed("nginx\t1.30.5_1,3\t1\n")),
                PackagePlan.versionsOnly(PackagePlan.installed("nginx\t1.31.0,3\t1\n")),
                plan(change("aggiorna", "nginx", "1.30.5_1,3", "1.30.6,3")));
        check("una versione di arrivo diversa da quella approvata viene vista", other.length() == 1);
        check("  e il motivo dice che cosa diceva il piano", field(other, "why").contains("1.30.6,3"));

        // ===== 5. Una rimozione PREVISTA non e' una divergenza =====
        check("una rimozione prevista non e' una divergenza",
             PackagePlan.divergences(
                 PackagePlan.versionsOnly(PackagePlan.installed("lmdb\t1.0.2,1\t0\n")),
                 PackagePlan.versionsOnly(PackagePlan.installed("")),
                 plan(change("rimuove", "lmdb", "1.0.2,1", ""))).isEmpty());

        // ===== 6. Una reinstallazione non lascia traccia nell'inventario =====
        // Stessa versione prima e dopo: da qui non si vede, e non si DEVE vedere. Che la
        // reinstallazione sia avvenuta lo controlla verifyOutcome, che confronta le versioni
        // del piano. I due controlli sono complementari: questo guarda cio' che e' cambiato
        // senza permesso, quello cio' che era promesso e non e' avvenuto.
        check("una reinstallazione non produce divergenze",
             PackagePlan.divergences(
                 PackagePlan.versionsOnly(PackagePlan.installed("cyrus-sasl\t2.1.28_5\t0\n")),
                 PackagePlan.versionsOnly(PackagePlan.installed("cyrus-sasl\t2.1.28_5\t0\n")),
                 plan(change("reinstalla", "cyrus-sasl", "2.1.28_5", "2.1.28_5"))).isEmpty());

        // ===== 7. Un aggiornamento promesso e non avvenuto NON e' una divergenza =====
        // Non e' una dimenticanza: nell'inventario non e' cambiato niente, e quel caso lo
        // prende verifyOutcome ("atteso 1.30.6,3, trovato 1.30.5_1,3"). Se un giorno
        // qualcuno lo facesse comparire anche qui, lo stesso guasto verrebbe detto due volte
        // con due nomi diversi.
        check("un aggiornamento promesso e non avvenuto non compare qui (lo prende verificaEsito)",
             PackagePlan.divergences(
                 PackagePlan.versionsOnly(PackagePlan.installed("nginx\t1.30.5_1,3\t1\n")),
                 PackagePlan.versionsOnly(PackagePlan.installed("nginx\t1.30.5_1,3\t1\n")),
                 plan(change("aggiorna", "nginx", "1.30.5_1,3", "1.30.6,3"))).isEmpty());

        // ===== 8. Una retrocessione prevista, e il pkg che aggiorna se stesso =====
        check("una retrocessione prevista non e' una divergenza",
             PackagePlan.divergences(
                 PackagePlan.versionsOnly(PackagePlan.installed("redis\t8.10.2\t1\n")),
                 PackagePlan.versionsOnly(PackagePlan.installed("redis\t8.9.0\t1\n")),
                 plan(change("retrocede", "redis", "8.10.2", "8.9.0"))).isEmpty());
        check("il pkg che aggiorna se stesso, se il piano lo dichiara, non e' una divergenza",
             PackagePlan.divergences(
                 PackagePlan.versionsOnly(PackagePlan.installed("pkg\t2.1.0\t0\n")),
                 PackagePlan.versionsOnly(PackagePlan.installed("pkg\t2.2.0\t0\n")),
                 plan(change("aggiorna", "pkg", "2.1.0", "2.2.0"))).isEmpty());
        check("e se il piano NON lo dichiara, si', e' una divergenza",
             PackagePlan.divergences(
                 PackagePlan.versionsOnly(PackagePlan.installed("pkg\t2.1.0\t0\n")),
                 PackagePlan.versionsOnly(PackagePlan.installed("pkg\t2.2.0\t0\n")),
                 plan()).length() == 1);

        // ===== 9. Nessun piano misurabile: non si inventa un verdetto =====
        check("con un piano senza cambi, ogni cambiamento e' fuori dal piano",
             PackagePlan.divergences(
                 PackagePlan.versionsOnly(PackagePlan.installed("nginx\t1.30.5_1,3\t1\n")),
                 PackagePlan.versionsOnly(PackagePlan.installed("nginx\t1.30.6,3\t1\n")),
                 new JSONObject()).length() == 1);
        check("inventari identici e piano vuoto: niente da dire",
             PackagePlan.divergences(Map.of("nginx", "1.30.6,3"), Map.of("nginx", "1.30.6,3"),
                 new JSONObject()).isEmpty());

        // ===== 10. Il contratto con pkg vero =====
        if (!hasPkg()) {
            skip("l'inventario vero di pkg: pkg non c'e' su questa macchina");
        } else {
            Map<String, String> inventory = PackagePlan.versionsOnly(PackagePlan.installed());
            check("l'inventario vero non e' vuoto", !inventory.isEmpty());
            boolean sensibleVersions = true;
            for (Map.Entry<String, String> e : inventory.entrySet())
                if (e.getValue() == null || e.getValue().isEmpty()) sensibleVersions = false;
            check("e ogni pacchetto ha una versione", sensibleVersions);
            // Due inventari di fila, senza aver toccato niente: zero divergenze. Se questo
            // fallisse, il confronto darebbe falsi allarmi a ogni aggiornamento.
            check("due inventari di fila non producono divergenze",
                 PackagePlan.divergences(inventory, PackagePlan.versionsOnly(PackagePlan.installed()),
                         new JSONObject()).isEmpty());
        }

        System.out.println();
        if (skipped > 0) System.out.println(skipped + " PROVE SALTATE (lo dicono sopra)");
        System.out.println(failures == 0 ? "TUTTO OK" : failures + " PROVE FALLITE");
        if (failures > 0) System.exit(1);
    }

    /** Un campo della prima divergenza, o stringa vuota se non ce n'e' nessuna: una prova
     *  che fallisce deve dire TUTTO quello che non va, non fermarsi alla prima mancanza. */
    private static String field(JSONArray d, String key) {
        return d.length() == 0 ? "" : d.getJSONObject(0).optString(key);
    }

    private static JSONObject change(String type, String name, String from, String a) {
        return new JSONObject().put("tipo", type).put("nome", name).put("da", from).put("a", a);
    }

    private static JSONObject plan(JSONObject... changeList) {
        JSONArray c = new JSONArray();
        for (JSONObject x : changeList) c.put(x);
        return new JSONObject().put("changes", c).put("measured", true);
    }

    private static boolean hasPkg() {
        return org.mail_panel.util.Shell.runShell(java.time.Duration.ofSeconds(15),
                "pkg -N >/dev/null 2>&1").success();
    }

    private static void check(String name, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + name);
        if (!ok) failures++;
    }

    private static void skip(String name) {
        System.out.println("  --   SALTATA: " + name);
        skipped++;
    }
}
