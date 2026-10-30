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

    private static int failures = 0, skipped = 0;

    public static void main(String[] args) throws Exception {

        // ===== 1. Il testo della nota dice tutto quello che serve =====
        String note = UpdateManager.lockNoteText(
                List.of("dovecot", "nginx", "postfix-mysql"), "2026-10-23T01:00:00Z");
        check("la nota elenca i pacchetti bloccati",
             note.contains("dovecot") && note.contains("nginx") && note.contains("postfix-mysql"));
        check("dice quando e' stata scritta, in UTC", note.contains("2026-10-23T01:00:00Z")
                && note.contains("UTC"));
        check("dice il comando esatto che li libera", note.contains(UpdateManager.UNLOCK_ALL_COMMAND));
        check("dice che un pacchetto bloccato non riceve le correzioni di sicurezza",
             note.toLowerCase().contains("sicurezza"));
        check("dice che pkg upgrade li salta uscendo con codice 0",
             note.contains("codice 0") || note.contains("code 0"));
        check("rimanda al pannello per aggiornarli", note.contains("Aggiornamenti"));
        check("dice come si libera uno solo", note.contains("pkg unlock -y"));
        check("e dove si legge lo stato vero", note.contains("pkg lock -l"));
        check("avvisa di non modificarla a mano", note.toLowerCase().contains("non modificare"));

        // Una nota senza pacchetti non deve sembrare un elenco vuoto per sbaglio.
        check("con nessun pacchetto bloccato lo dice",
             UpdateManager.lockNoteText(List.of(), "2026-10-23T01:00:00Z").contains("nessun pacchetto"));

        // ===== 2. La scrittura: atomica, e non resta indietro =====
        Path d = Files.createTempDirectory("prova-nota-blocchi");
        Path f = d.resolve("locked-packages.txt");
        Path original = UpdateManager.lockNotePath;
        UpdateManager.lockNotePath = f;
        try {
            if (!hasPkg()) {
                skip("la scrittura della nota: pkg non c'e' su questa macchina");
            } else {
                UpdateManager.writeLockNote();
                // Quanti pacchetti DELLO STACK sono bloccati: e' il conto che fa
                // packagesStatus, cioe' esattamente quello che la nota deve elencare.
                JSONObject state = UpdateManager.packagesStatus();
                int lockedCount = state.optInt("lockedCount");
                java.util.List<String> reallyLocked = new java.util.ArrayList<>();
                org.json.JSONArray lines = state.getJSONArray("packages");
                for (int i = 0; i < lines.length(); i++)
                    if (lines.getJSONObject(i).optBoolean("locked"))
                        reallyLocked.add(lines.getJSONObject(i).getString("name"));
                if (lockedCount == 0) {
                    check("senza pacchetti bloccati la nota non esiste", !Files.exists(f));
                    skip("il contenuto della nota: su questa macchina non c'e' nessun blocco");
                } else {
                    check("la nota viene scritta", Files.exists(f));
                    String written = Files.exists(f) ? Files.readString(f) : "";
                    final String text = written;
                    check("e contiene i pacchetti bloccati davvero ("
                         + reallyLocked.size() + ")", reallyLocked.stream().allMatch(text::contains));
                    check("e il comando per liberarli", written.contains(UpdateManager.UNLOCK_ALL_COMMAND));
                    check("nessun file temporaneo rimasto indietro",
                         !Files.exists(f.resolveSibling(f.getFileName() + ".tmp")));
                }
            }
        } finally {
            UpdateManager.lockNotePath = original;
            try { Files.deleteIfExists(f); Files.deleteIfExists(d); } catch (Exception ignored) { }
        }

        // ===== 3. L'avviso dove si toglie il pannello di mezzo =====
        if (!hasPkg()) {
            skip("l'avviso sui blocchi che restano: pkg non c'e' su questa macchina");
            skip("l'avviso nella rimozione dell'avvio automatico: pkg non c'e'");
        } else {
            String warning = UpdateManager.locksStayWarning();
            int howMany = UpdateManager.packagesStatus().optInt("lockedCount");
            if (howMany == 0) {
                check("senza blocchi non si avvisa di niente", warning.isEmpty());
                skip("il contenuto dell'avviso: su questa macchina non c'e' nessun blocco");
            } else {
                check("l'avviso c'e' quando ci sono blocchi", !warning.isEmpty());
                check("  dice quanti sono", warning.contains(String.valueOf(howMany)));
                check("  dice il comando che li libera", warning.contains(UpdateManager.UNLOCK_ALL_COMMAND));
                check("  e dove sta scritto il perche'", warning.contains(UpdateManager.LOCK_NOTE));

                // La rimozione dell'avvio automatico lo ripete: e' il momento in cui la
                // domanda "e i blocchi?" si pone da se'. In sola lettura (esegui = false).
                JSONObject rc = UpdateManager.removePanelRcScript(false);
                check("la rimozione dell'avvio automatico avvisa dei blocchi",
                     rc.optString("note").contains(UpdateManager.UNLOCK_ALL_COMMAND)
                     || rc.optString("locksStay").contains(UpdateManager.UNLOCK_ALL_COMMAND));
                check("  e non ha eseguito niente", !rc.optBoolean("executed", false));
            }
        }

        // ===== 4. Il cartello nel database di pkg =====
        // Una riga di comando si prova eseguendola: il valore contiene spazi, un percorso e
        // un trattino, e in questo progetto un apice dentro un testo e' gia' passato intatto
        // attraverso un here-document per rompere piu' in la'.
        check("un nome non conforme non produce nessun comando",
             UpdateManager.markCommand("ngi nx; rm -rf /") == null);
        String cmd = UpdateManager.markCommand("nginx");
        check("il comando nomina la chiave e il pacchetto",
             cmd != null && cmd.contains(UpdateManager.MARK_KEY) && cmd.contains(" nginx "));
        check("  e rimanda alla nota e al comando di sblocco",
             cmd != null && cmd.contains(UpdateManager.LOCK_NOTE) && cmd.contains(UpdateManager.UNLOCK_ALL_COMMAND));

        if (!hasPkg()) {
            skip("l'annotazione su pkg vero: pkg non c'e' su questa macchina");
        } else {
            String target = firstInstalled();
            if (target == null) {
                skip("l'annotazione su pkg vero: nessun pacchetto installato");
            } else {
                boolean executed = org.mail_panel.util.Shell.runShell(java.time.Duration.ofSeconds(30),
                        UpdateManager.markCommand(target)).success();
                String readBack = org.mail_panel.util.Shell.runShell(java.time.Duration.ofSeconds(30),
                        "pkg info -A " + target).output();
                // Si rimette com'era, qualunque sia l'esito.
                org.mail_panel.util.Shell.runShell(java.time.Duration.ofSeconds(30),
                        "pkg annotate -y -D " + target + " " + UpdateManager.MARK_KEY);
                check("il comando di annotazione viene eseguito da pkg su " + target, executed);
                check("  e pkg info -A la mostra", readBack.contains(UpdateManager.MARK_KEY));
                check("  col rimando alla nota", readBack.contains(UpdateManager.LOCK_NOTE));
                String after = org.mail_panel.util.Shell.runShell(java.time.Duration.ofSeconds(30),
                        "pkg info -A " + target).output();
                check("  e si puo' togliere, quindi la prova non lascia tracce",
                     !after.contains(UpdateManager.MARK_KEY));
            }
        }

        System.out.println();
        if (skipped > 0) System.out.println(skipped + " PROVE SALTATE (lo dicono sopra)");
        System.out.println(failures == 0 ? "TUTTO OK" : failures + " PROVE FALLITE");
        if (failures > 0) System.exit(1);
    }

    /** Un pacchetto installato qualunque, su cui provare l'annotazione. */
    private static String firstInstalled() {
        for (String n : PackagePlan.installed().keySet()) return n;
        return null;
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
