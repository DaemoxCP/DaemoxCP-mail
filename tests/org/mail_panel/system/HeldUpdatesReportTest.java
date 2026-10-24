package org.mail_panel.system;

import java.util.LinkedHashMap;
import java.util.Map;
import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Il rapporto periodico e gli aggiornamenti che il blocco trattiene.
 *
 * La riga "con aggiornamento: N" del rapporto leggeva le versioni da due chiavi che le righe
 * di packagesStatus non hanno mai avuto ("current" e "available"): valeva SEMPRE zero.
 * Misurato sulla VM FreeBSD 15.1 il 23/10/2026 — rapporto 0, mentre packagesOverview nello
 * stesso istante contava 2 aggiornamenti dello stack (nginx e postfix-mysql, entrambi
 * bloccati) e 5 in tutto. Il rapporto e' l'unico canale che raggiunge chi non apre la pagina,
 * quindi quella riga muta e' il modo in cui un pacchetto bloccato resta indietro per sempre.
 *
 * Tre strati, perche' un difetto di chiavi non lo prende nessuno dei tre da solo:
 *  1. la logica, su righe costruite a mano — compreso il caso delle chiavi vecchie;
 *  2. il contratto: le chiavi che packagesStatus mette DAVVERO sono quelle che il conto legge;
 *  3. l'accordo con lockedUpdates, che calcola la stessa cosa per un'altra strada.
 *
 * Gli strati 2 e 3 hanno bisogno di pkg: senza, si saltano DICENDOLO, perche' una prova che
 * si salta in silenzio conta come verde senza aver provato niente.
 */
public class HeldUpdatesReportTest {

    private static int failures = 0, skipped = 0;

    public static void main(String[] args) {

        // ===== 1. La logica =====
        JSONArray lines = new JSONArray()
                // come le mette packagesStatus(): name, role, version, locked, installed
                .put(line("nginx", "1.30.5_2,3", true))
                .put(line("postfix-mysql", "3.11.7_1,1", true))
                .put(line("dovecot", "2.3.21.1_3", true))     // nessun aggiornamento
                .put(line("redis", "8.10.2", false))          // non protetto, con aggiornamento
                .put(line("clamav", "1.5.4_1,1", false));     // non protetto, senza
        Map<String, String> catalog = new LinkedHashMap<>();
        catalog.put("nginx", "1.30.6,3");
        catalog.put("postfix-mysql", "3.11.7_3,1");
        catalog.put("redis", "8.11.0");
        catalog.put("libzip", "1.12.1");                     // non e' dello stack: non c'entra

        JSONObject c = UpdateManager.countUpdates(lines, catalog);
        check("conta i pacchetti dello stack", c.getInt("totals") == 5);
        check("conta i protetti", c.getInt("protectedNames") == 3);
        check("conta gli aggiornamenti disponibili", c.getInt("withUpdate") == 3);
        check("conta quanti di quelli il blocco trattiene", c.getInt("heldBack") == 2);
        String list = c.getJSONArray("toUpdate").toString();
        check("l'elenco dice da quale versione a quale", list.contains("nginx 1.30.5_2,3 -> 1.30.6,3"));
        check("l'elenco segna i trattenuti", list.contains("nginx 1.30.5_2,3 -> 1.30.6,3 ("));
        check("e non segna chi non e' protetto", list.contains("redis 8.10.2 -> 8.11.0\"")
                || list.contains("redis 8.10.2 -> 8.11.0,"));

        // Stessa versione nel catalogo: non e' un aggiornamento.
        JSONObject same = UpdateManager.countUpdates(
                new JSONArray().put(line("redis", "8.10.2", false)), Map.of("redis", "8.10.2"));
        check("la stessa versione non e' un aggiornamento", same.getInt("withUpdate") == 0);

        // Catalogo vuoto (pkg version non ha risposto): zero, e zero protetti trattenuti.
        JSONObject empty = UpdateManager.countUpdates(lines, Map.of());
        check("senza catalogo non si inventa niente",
             empty.getInt("withUpdate") == 0 && empty.getInt("heldBack") == 0);
        check("ma i pacchetti si contano comunque", empty.getInt("totals") == 5);

        // Il difetto, come caso di prova: una riga con le chiavi SBAGLIATE non conta niente.
        // Serve a dire perche' lo strato 2 esiste: qui dentro il conto e' giusto e il
        // risultato e' zero lo stesso.
        JSONArray oldKeys = new JSONArray().put(new JSONObject()
                .put("name", "nginx").put("current", "1.30.5_2,3").put("available", "1.30.6,3")
                .put("locked", true));
        JSONObject old = UpdateManager.countUpdates(oldKeys, catalog);
        check("una riga senza la chiave 'version' non puo' dire la versione installata",
             old.getJSONArray("toUpdate").getString(0).startsWith("nginx  -> "));

        // ===== 2. Il contratto con packagesStatus =====
        if (!hasPkg()) {
            skip("le chiavi vere di packagesStatus: pkg non c'e' su questa macchina");
            skip("l'accordo fra il rapporto e lockedUpdates: pkg non c'e' su questa macchina");
        } else {
            JSONObject st = UpdateManager.packagesStatus();
            JSONArray real = st.optJSONArray("packages");
            if (real == null || real.length() == 0) {
                skip("le chiavi vere di packagesStatus: nessun pacchetto dello stack installato");
                skip("l'accordo fra il rapporto e lockedUpdates: nessun pacchetto dello stack");
            } else {
                JSONObject r0 = real.getJSONObject(0);
                check("packagesStatus mette 'name'", r0.has("name"));
                check("packagesStatus mette 'version', la chiave che il conto legge", r0.has("version"));
                check("packagesStatus mette 'locked'", r0.has("locked"));
                check("packagesStatus NON mette 'available': chi la legge conta zero",
                     !r0.has("available"));

                // ===== 3. L'accordo con l'altra strada =====
                JSONArray heldBackElsewhere = UpdateManager.lockedUpdates();
                JSONObject report = UpdateManager.reportData(false);
                int fromReport = report.optInt("heldBackPackages", -1);
                if (heldBackElsewhere.length() == 0) {
                    skip("l'accordo fra il rapporto e lockedUpdates: su questa macchina nessun"
                        + " pacchetto protetto ha un aggiornamento, non c'e' niente da misurare");
                } else {
                    check("il rapporto conta i trattenuti come lockedUpdates ("
                         + fromReport + " contro " + heldBackElsewhere.length() + ")",
                         fromReport == heldBackElsewhere.length());
                    check("e allora la riga 'con aggiornamento' non puo' essere zero",
                         report.optInt("packagesWithUpdate", 0) >= heldBackElsewhere.length());
                    boolean said = false;
                    JSONArray toDo = report.optJSONArray("daFare");
                    for (int i = 0; toDo != null && i < toDo.length(); i++)
                        if (toDo.getJSONObject(i).optString("what").contains("pkg upgrade")) said = true;
                    check("fra le cose da fare c'e' scritto che pkg upgrade li salta", said);
                }
            }
        }

        System.out.println();
        if (skipped > 0) System.out.println(skipped + " PROVE SALTATE (lo dicono sopra)");
        System.out.println(failures == 0 ? "TUTTO OK" : failures + " PROVE FALLITE");
        if (failures > 0) System.exit(1);
    }

    /** Una riga come la mette packagesStatus(). */
    private static JSONObject line(String name, String version, boolean isProtected) {
        return new JSONObject().put("name", name).put("role", "prova")
                .put("version", version).put("locked", isProtected).put("installed", true);
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
