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

    private static int falliti = 0, saltati = 0;

    public static void main(String[] args) {

        // ===== 1. La logica =====
        JSONArray righe = new JSONArray()
                // come le mette packagesStatus(): name, role, version, locked, installed
                .put(riga("nginx", "1.30.5_2,3", true))
                .put(riga("postfix-mysql", "3.11.7_1,1", true))
                .put(riga("dovecot", "2.3.21.1_3", true))     // nessun aggiornamento
                .put(riga("redis", "8.10.2", false))          // non protetto, con aggiornamento
                .put(riga("clamav", "1.5.4_1,1", false));     // non protetto, senza
        Map<String, String> catalogo = new LinkedHashMap<>();
        catalogo.put("nginx", "1.30.6,3");
        catalogo.put("postfix-mysql", "3.11.7_3,1");
        catalogo.put("redis", "8.11.0");
        catalogo.put("libzip", "1.12.1");                     // non e' dello stack: non c'entra

        JSONObject c = UpdateManager.contaAggiornamenti(righe, catalogo);
        vero("conta i pacchetti dello stack", c.getInt("totali") == 5);
        vero("conta i protetti", c.getInt("protetti") == 3);
        vero("conta gli aggiornamenti disponibili", c.getInt("conAggiornamento") == 3);
        vero("conta quanti di quelli il blocco trattiene", c.getInt("trattenuti") == 2);
        String elenco = c.getJSONArray("daAggiornare").toString();
        vero("l'elenco dice da quale versione a quale", elenco.contains("nginx 1.30.5_2,3 -> 1.30.6,3"));
        vero("l'elenco segna i trattenuti", elenco.contains("nginx 1.30.5_2,3 -> 1.30.6,3 ("));
        vero("e non segna chi non e' protetto", elenco.contains("redis 8.10.2 -> 8.11.0\"")
                || elenco.contains("redis 8.10.2 -> 8.11.0,"));

        // Stessa versione nel catalogo: non e' un aggiornamento.
        JSONObject uguale = UpdateManager.contaAggiornamenti(
                new JSONArray().put(riga("redis", "8.10.2", false)), Map.of("redis", "8.10.2"));
        vero("la stessa versione non e' un aggiornamento", uguale.getInt("conAggiornamento") == 0);

        // Catalogo vuoto (pkg version non ha risposto): zero, e zero protetti trattenuti.
        JSONObject vuoto = UpdateManager.contaAggiornamenti(righe, Map.of());
        vero("senza catalogo non si inventa niente",
             vuoto.getInt("conAggiornamento") == 0 && vuoto.getInt("trattenuti") == 0);
        vero("ma i pacchetti si contano comunque", vuoto.getInt("totali") == 5);

        // Il difetto, come caso di prova: una riga con le chiavi SBAGLIATE non conta niente.
        // Serve a dire perche' lo strato 2 esiste: qui dentro il conto e' giusto e il
        // risultato e' zero lo stesso.
        JSONArray chiaviVecchie = new JSONArray().put(new JSONObject()
                .put("name", "nginx").put("current", "1.30.5_2,3").put("available", "1.30.6,3")
                .put("locked", true));
        JSONObject vecchie = UpdateManager.contaAggiornamenti(chiaviVecchie, catalogo);
        vero("una riga senza la chiave 'version' non puo' dire la versione installata",
             vecchie.getJSONArray("daAggiornare").getString(0).startsWith("nginx  -> "));

        // ===== 2. Il contratto con packagesStatus =====
        if (!cEPkg()) {
            salta("le chiavi vere di packagesStatus: pkg non c'e' su questa macchina");
            salta("l'accordo fra il rapporto e lockedUpdates: pkg non c'e' su questa macchina");
        } else {
            JSONObject st = UpdateManager.packagesStatus();
            JSONArray vere = st.optJSONArray("packages");
            if (vere == null || vere.length() == 0) {
                salta("le chiavi vere di packagesStatus: nessun pacchetto dello stack installato");
                salta("l'accordo fra il rapporto e lockedUpdates: nessun pacchetto dello stack");
            } else {
                JSONObject r0 = vere.getJSONObject(0);
                vero("packagesStatus mette 'name'", r0.has("name"));
                vero("packagesStatus mette 'version', la chiave che il conto legge", r0.has("version"));
                vero("packagesStatus mette 'locked'", r0.has("locked"));
                vero("packagesStatus NON mette 'available': chi la legge conta zero",
                     !r0.has("available"));

                // ===== 3. L'accordo con l'altra strada =====
                JSONArray trattenutiAltrove = UpdateManager.lockedUpdates();
                JSONObject rapporto = UpdateManager.reportData(false);
                int dalRapporto = rapporto.optInt("pacchettiTrattenuti", -1);
                if (trattenutiAltrove.length() == 0) {
                    salta("l'accordo fra il rapporto e lockedUpdates: su questa macchina nessun"
                        + " pacchetto protetto ha un aggiornamento, non c'e' niente da misurare");
                } else {
                    vero("il rapporto conta i trattenuti come lockedUpdates ("
                         + dalRapporto + " contro " + trattenutiAltrove.length() + ")",
                         dalRapporto == trattenutiAltrove.length());
                    vero("e allora la riga 'con aggiornamento' non puo' essere zero",
                         rapporto.optInt("pacchettiConAggiornamento", 0) >= trattenutiAltrove.length());
                    boolean detto = false;
                    JSONArray daFare = rapporto.optJSONArray("daFare");
                    for (int i = 0; daFare != null && i < daFare.length(); i++)
                        if (daFare.getJSONObject(i).optString("cosa").contains("pkg upgrade")) detto = true;
                    vero("fra le cose da fare c'e' scritto che pkg upgrade li salta", detto);
                }
            }
        }

        System.out.println();
        if (saltati > 0) System.out.println(saltati + " PROVE SALTATE (lo dicono sopra)");
        System.out.println(falliti == 0 ? "TUTTO OK" : falliti + " PROVE FALLITE");
        if (falliti > 0) System.exit(1);
    }

    /** Una riga come la mette packagesStatus(). */
    private static JSONObject riga(String nome, String versione, boolean protetto) {
        return new JSONObject().put("name", nome).put("role", "prova")
                .put("version", versione).put("locked", protetto).put("installed", true);
    }

    private static boolean cEPkg() {
        return org.mail_panel.util.Shell.runShell(java.time.Duration.ofSeconds(15),
                "pkg -N >/dev/null 2>&1").success();
    }

    private static void vero(String nome, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + nome);
        if (!ok) falliti++;
    }

    private static void salta(String nome) {
        System.out.println("  --   SALTATA: " + nome);
        saltati++;
    }
}
