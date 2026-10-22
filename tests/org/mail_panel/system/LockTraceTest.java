package org.mail_panel.system;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.json.JSONObject;

/**
 * La traccia dei blocchi sulla macchina: perche' quei pacchetti sono bloccati, e come si
 * liberano se il pannello non c'e' piu'.
 *
 * Il blocco non scade e nessuno lo toglie allo spegnimento: e' la regola, ed e' giusta
 * finche' il pannello c'e'. Se il pannello viene disinstallato, o semplicemente non riparte,
 * quei pacchetti restano bloccati per sempre — e un pacchetto bloccato non riceve nemmeno le
 * correzioni di sicurezza.
 *
 * Misurato sulla VM FreeBSD 15.1 il 23/10/2026, con 40 pacchetti bloccati dal pannello:
 * `pkg upgrade` nomina i bloccati in una riga di passaggio, NON li mette nel riepilogo e
 * termina con uscita ZERO. Dal sistema non si capiva ne' chi li avesse bloccati, ne' perche',
 * ne' come liberarli: `pkg lock -l` elenca i nomi e basta.
 *
 * Qui si prova che la spiegazione c'e', che dice le cose che servono, e che non resta
 * indietro rispetto allo stato vero.
 */
public class LockTraceTest {

    private static int falliti = 0, saltati = 0;

    public static void main(String[] args) throws Exception {

        // ===== 1. Il testo della nota dice tutto quello che serve =====
        String nota = UpdateManager.notaDeiBlocchi(
                List.of("dovecot", "nginx", "postfix-mysql"), "2026-10-23T01:00:00Z");
        vero("la nota elenca i pacchetti bloccati",
             nota.contains("dovecot") && nota.contains("nginx") && nota.contains("postfix-mysql"));
        vero("dice quando e' stata scritta, in UTC", nota.contains("2026-10-23T01:00:00Z")
                && nota.contains("UTC"));
        vero("dice il comando esatto che li libera", nota.contains(UpdateManager.COMANDO_SBLOCCO));
        vero("dice che un pacchetto bloccato non riceve le correzioni di sicurezza",
             nota.toLowerCase().contains("sicurezza"));
        vero("dice che pkg upgrade li salta uscendo con codice 0",
             nota.contains("codice 0") || nota.contains("code 0"));
        vero("rimanda al pannello per aggiornarli", nota.contains("Aggiornamenti"));
        vero("dice come si libera uno solo", nota.contains("pkg unlock -y"));
        vero("e dove si legge lo stato vero", nota.contains("pkg lock -l"));
        vero("avvisa di non modificarla a mano", nota.toLowerCase().contains("non modificare"));

        // Una nota senza pacchetti non deve sembrare un elenco vuoto per sbaglio.
        vero("con nessun pacchetto bloccato lo dice",
             UpdateManager.notaDeiBlocchi(List.of(), "2026-10-23T01:00:00Z").contains("nessun pacchetto"));

        // ===== 2. La scrittura: atomica, e non resta indietro =====
        Path d = Files.createTempDirectory("prova-nota-blocchi");
        Path f = d.resolve("locked-packages.txt");
        Path originale = UpdateManager.notaBlocchi;
        UpdateManager.notaBlocchi = f;
        try {
            if (!cEPkg()) {
                salta("la scrittura della nota: pkg non c'e' su questa macchina");
            } else {
                UpdateManager.scriviNotaDeiBlocchi();
                // Quanti pacchetti DELLO STACK sono bloccati: e' il conto che fa
                // packagesStatus, cioe' esattamente quello che la nota deve elencare.
                JSONObject stato = UpdateManager.packagesStatus();
                int quantiBloccati = stato.optInt("lockedCount");
                java.util.List<String> bloccatiVeri = new java.util.ArrayList<>();
                org.json.JSONArray righe = stato.getJSONArray("packages");
                for (int i = 0; i < righe.length(); i++)
                    if (righe.getJSONObject(i).optBoolean("locked"))
                        bloccatiVeri.add(righe.getJSONObject(i).getString("name"));
                if (quantiBloccati == 0) {
                    vero("senza pacchetti bloccati la nota non esiste", !Files.exists(f));
                    salta("il contenuto della nota: su questa macchina non c'e' nessun blocco");
                } else {
                    vero("la nota viene scritta", Files.exists(f));
                    String scritta = Files.exists(f) ? Files.readString(f) : "";
                    final String testo = scritta;
                    vero("e contiene i pacchetti bloccati davvero ("
                         + bloccatiVeri.size() + ")", bloccatiVeri.stream().allMatch(testo::contains));
                    vero("e il comando per liberarli", scritta.contains(UpdateManager.COMANDO_SBLOCCO));
                    vero("nessun file temporaneo rimasto indietro",
                         !Files.exists(f.resolveSibling(f.getFileName() + ".tmp")));
                }
            }
        } finally {
            UpdateManager.notaBlocchi = originale;
            try { Files.deleteIfExists(f); Files.deleteIfExists(d); } catch (Exception ignored) { }
        }

        // ===== 3. L'avviso dove si toglie il pannello di mezzo =====
        if (!cEPkg()) {
            salta("l'avviso sui blocchi che restano: pkg non c'e' su questa macchina");
            salta("l'avviso nella rimozione dell'avvio automatico: pkg non c'e'");
        } else {
            String avviso = UpdateManager.avvisoBlocchiRimasti();
            int quanti = UpdateManager.packagesStatus().optInt("lockedCount");
            if (quanti == 0) {
                vero("senza blocchi non si avvisa di niente", avviso.isEmpty());
                salta("il contenuto dell'avviso: su questa macchina non c'e' nessun blocco");
            } else {
                vero("l'avviso c'e' quando ci sono blocchi", !avviso.isEmpty());
                vero("  dice quanti sono", avviso.contains(String.valueOf(quanti)));
                vero("  dice il comando che li libera", avviso.contains(UpdateManager.COMANDO_SBLOCCO));
                vero("  e dove sta scritto il perche'", avviso.contains(UpdateManager.LOCK_NOTE));

                // La rimozione dell'avvio automatico lo ripete: e' il momento in cui la
                // domanda "e i blocchi?" si pone da se'. In sola lettura (esegui = false).
                JSONObject rc = UpdateManager.removePanelRcScript(false);
                vero("la rimozione dell'avvio automatico avvisa dei blocchi",
                     rc.optString("nota").contains(UpdateManager.COMANDO_SBLOCCO)
                     || rc.optString("locksStay").contains(UpdateManager.COMANDO_SBLOCCO));
                vero("  e non ha eseguito niente", !rc.optBoolean("eseguito", false));
            }
        }

        // ===== 4. Il cartello nel database di pkg =====
        // Una riga di comando si prova eseguendola: il valore contiene spazi, un percorso e
        // un trattino, e in questo progetto un apice dentro un testo e' gia' passato intatto
        // attraverso un here-document per rompere piu' in la'.
        vero("un nome non conforme non produce nessun comando",
             UpdateManager.comandoAnnotazione("ngi nx; rm -rf /") == null);
        String cmd = UpdateManager.comandoAnnotazione("nginx");
        vero("il comando nomina la chiave e il pacchetto",
             cmd != null && cmd.contains(UpdateManager.CHIAVE_ANNOTAZIONE) && cmd.contains(" nginx "));
        vero("  e rimanda alla nota e al comando di sblocco",
             cmd != null && cmd.contains(UpdateManager.LOCK_NOTE) && cmd.contains(UpdateManager.COMANDO_SBLOCCO));

        if (!cEPkg()) {
            salta("l'annotazione su pkg vero: pkg non c'e' su questa macchina");
        } else {
            String suQuale = primoInstallato();
            if (suQuale == null) {
                salta("l'annotazione su pkg vero: nessun pacchetto installato");
            } else {
                boolean eseguito = org.mail_panel.util.Shell.runShell(java.time.Duration.ofSeconds(30),
                        UpdateManager.comandoAnnotazione(suQuale)).success();
                String letta = org.mail_panel.util.Shell.runShell(java.time.Duration.ofSeconds(30),
                        "pkg info -A " + suQuale).output();
                // Si rimette com'era, qualunque sia l'esito.
                org.mail_panel.util.Shell.runShell(java.time.Duration.ofSeconds(30),
                        "pkg annotate -y -D " + suQuale + " " + UpdateManager.CHIAVE_ANNOTAZIONE);
                vero("il comando di annotazione viene eseguito da pkg su " + suQuale, eseguito);
                vero("  e pkg info -A la mostra", letta.contains(UpdateManager.CHIAVE_ANNOTAZIONE));
                vero("  col rimando alla nota", letta.contains(UpdateManager.LOCK_NOTE));
                String dopo = org.mail_panel.util.Shell.runShell(java.time.Duration.ofSeconds(30),
                        "pkg info -A " + suQuale).output();
                vero("  e si puo' togliere, quindi la prova non lascia tracce",
                     !dopo.contains(UpdateManager.CHIAVE_ANNOTAZIONE));
            }
        }

        System.out.println();
        if (saltati > 0) System.out.println(saltati + " PROVE SALTATE (lo dicono sopra)");
        System.out.println(falliti == 0 ? "TUTTO OK" : falliti + " PROVE FALLITE");
        if (falliti > 0) System.exit(1);
    }

    /** Un pacchetto installato qualunque, su cui provare l'annotazione. */
    private static String primoInstallato() {
        for (String n : PackagePlan.installati().keySet()) return n;
        return null;
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
