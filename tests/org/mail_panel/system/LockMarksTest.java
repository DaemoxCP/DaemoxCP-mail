package org.mail_panel.system;

import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import org.mail_panel.util.Shell;

/**
 * Il cartello "bloccato dal pannello" deve stare su ogni pacchetto che il pannello tiene
 * bloccato, e solo su quelli.
 *
 * Prima si annotava solo il pacchetto bloccato all'avvio. Misurato sulla VM FreeBSD 15.1 il
 * 24/10/2026: reinstallare un pacchetto (quindi anche aggiornarlo) cancella le sue
 * annotazioni — annotato nginx, reinstallato nginx 1.30.6,3 dalla cache, annotazione sparita —
 * e nessuna riprotezione le riscriveva. Su 39 pacchetti protetti l'annotazione stava su uno.
 *
 * Le prove 1-3 sono pure. La 4 lavora su pkg vero, se c'e', e rimette i cartelli esattamente
 * come li ha trovati, qualunque sia l'esito.
 */
public class LockMarksTest {

    private static int failures = 0;

    public static void main(String[] args) {

        // --- 1. Chi porta il cartello, da un'uscita di pkg query -a '%n %At' ---
        String output = String.join("\n",
                "alsa-lib FreeBSD_version",
                "nginx cpe",
                "nginx repository",
                "redis mail_panel_lock",
                "redis cpe",
                "postfix-mysql mail_panel_lock",
                "pkg: warning: qualcosa su stderr",
                "rm;-rf mail_panel_lock",
                "");
        Set<String> marked = UpdateManager.markedIn(output);
        check("dall'uscita di pkg: redis e postfix-mysql", marked.equals(Set.of("redis", "postfix-mysql")));
        check("  una riga di stderr non e' un pacchetto", !marked.contains("pkg:"));
        check("  un nome che non passa il filtro non entra", marked.stream().noneMatch(n -> n.contains(";")));
        check("uscita vuota: nessun cartello", UpdateManager.markedIn("").isEmpty());

        // --- 1-bis. Il testo del cartello, da pkg query -a '%n %At %Av' ---
        // Sui server installati prima il valore e' quello italiano: non serve riconoscerlo, basta
        // che non sia quello di adesso. Il pannello lo riscrive, solo sui pacchetti ancora bloccati.
        String withValues = String.join("\n",
                "nginx repository FreeBSD",
                "redis " + UpdateManager.MARK_KEY + " " + UpdateManager.MARK_VALUE,
                "postfix-mysql " + UpdateManager.MARK_KEY + " un testo di prima: vedi la nota",
                "dovecot " + UpdateManager.MARK_KEY,
                "lmdb " + UpdateManager.MARK_KEY + " un testo di prima",
                "");
        check("con i valori si leggono gli stessi cartelli",
             UpdateManager.markedIn(withValues).equals(Set.of("redis", "postfix-mysql", "dovecot", "lmdb")));
        check("  e quelli col testo di prima (o senza testo): postfix-mysql, dovecot, lmdb",
             UpdateManager.staleMarksIn(withValues).equals(Set.of("postfix-mysql", "dovecot", "lmdb")));
        List<String> rw = UpdateManager.lockMarkCommands(Set.of("redis", "postfix-mysql", "dovecot"),
                UpdateManager.markedIn(withValues), UpdateManager.staleMarksIn(withValues));
        check("si riscrivono postfix-mysql e dovecot, bloccati; lmdb, non piu' bloccato, si toglie (" + rw + ")",
             rw.size() == 3 && rw.contains(UpdateManager.rewriteMarkCommand("postfix-mysql"))
                     && rw.contains(UpdateManager.rewriteMarkCommand("dovecot")) && rw.contains(UpdateManager.removeMarkCommand("lmdb")));
        check("il valore e' in inglese e rimanda alla nota e al comando di sblocco",
             UpdateManager.MARK_VALUE.startsWith("locked by the mail panel")
                     && UpdateManager.MARK_VALUE.contains(UpdateManager.LOCK_NOTE) && UpdateManager.MARK_VALUE.contains(UpdateManager.UNLOCK_ALL_COMMAND));
        check("il comando che riscrive usa -M con lo stesso valore di quello che mette",
             ("pkg annotate -y -M nginx " + UpdateManager.MARK_KEY + " '" + UpdateManager.MARK_VALUE + "'").equals(UpdateManager.rewriteMarkCommand("nginx"))
                     && UpdateManager.markCommand("nginx").endsWith(" '" + UpdateManager.MARK_VALUE + "'")
                     && UpdateManager.rewriteMarkCommand("x; rm -rf /") == null);

        // --- 2. I comandi per portare i cartelli dove servono ---
        List<String> c = UpdateManager.lockMarkCommands(
                Set.of("nginx", "redis", "dovecot"), Set.of("redis", "lmdb"));
        check("tre comandi: due da mettere, uno da togliere (" + c.size() + ")", c.size() == 3);
        check("  mette il cartello su dovecot", c.stream().anyMatch(x -> x.contains(" -A dovecot ")));
        check("  e su nginx", c.stream().anyMatch(x -> x.contains(" -A nginx ")));
        check("  non tocca redis, che ce l'ha", c.stream().noneMatch(x -> x.contains(" redis ")));
        check("  toglie quello di lmdb, che non e' piu' bloccato",
             c.contains(UpdateManager.removeMarkCommand("lmdb")));
        check("  e il comando che toglie nomina la chiave e il pacchetto",
             "pkg annotate -y -D lmdb mail_panel_lock".equals(UpdateManager.removeMarkCommand("lmdb")));
        check("tutto in pari: nessun comando",
             UpdateManager.lockMarkCommands(Set.of("nginx"), Set.of("nginx")).isEmpty());
        check("un nome che non passa il filtro non produce nessun comando",
             UpdateManager.lockMarkCommands(Set.of("ngi nx; rm -rf /"), Set.of()).isEmpty()
             && UpdateManager.removeMarkCommand("x; rm -rf /") == null);

        // --- 3. La macchina della misura: 39 bloccati, il cartello su uno ---
        Set<String> thirtyNine = new TreeSet<>();
        for (int i = 0; i < 38; i++) thirtyNine.add("package" + i);
        thirtyNine.add("redis");
        check("39 bloccati e un cartello solo: 38 da mettere, niente da togliere",
             UpdateManager.lockMarkCommands(thirtyNine, Set.of("redis")).size() == 38);

        // --- 4. Su pkg vero ---
        if (!Shell.runShell(Duration.ofSeconds(10), "command -v pkg").success()) {
            System.out.println("  --   pkg vero: pkg non c'e' su questa macchina, salto");
        } else {
            onRealPkg();
        }

        System.out.println(failures == 0 ? "\nTUTTO OK" : "\n" + failures + " PROVE FALLITE");
        if (failures > 0) System.exit(1);
    }

    private static void onRealPkg() {
        Set<String> markedBefore = markedNow();
        Set<String> locked = panelLocked();
        if (locked.isEmpty()) {
            System.out.println("  --   pkg vero: nessun pacchetto dello stack bloccato, salto");
            return;
        }
        String one = locked.iterator().next();
        String free = firstUnlocked();
        try {
            UpdateManager.syncLockMarks();
            check("pkg vero: dopo la sincronizzazione il cartello sta su tutti e soli i "
                 + locked.size() + " bloccati", markedNow().equals(locked));

            // Il cartello perso da un aggiornamento, e uno rimasto su un pacchetto sbloccato
            sh("pkg annotate -y -D " + one + " " + UpdateManager.MARK_KEY);
            if (free != null) sh(UpdateManager.markCommand(free));
            int[] done = UpdateManager.syncLockMarks();
            check("  il cartello tolto a " + one + " torna", markedNow().contains(one));
            if (free != null) {
                check("  quello messo su " + free + ", che non e' bloccato, se ne va",
                     !markedNow().contains(free));
                check("  e la sincronizzazione lo conta: 1 messo, 1 tolto (" + done[0] + ", " + done[1] + ")",
                     done[0] == 1 && done[1] == 1);
            }
            check("  e una seconda volta non c'e' niente da fare",
                 java.util.Arrays.equals(UpdateManager.syncLockMarks(), new int[]{0, 0, 0}));

            // Il cartello col testo di prima, come lo lascia un server installato prima.
            sh("pkg annotate -y -M " + one + " " + UpdateManager.MARK_KEY + " 'un testo di prima'");
            int[] again = UpdateManager.syncLockMarks();
            check("  il cartello di " + one + " col testo di prima si riscrive (" + again[2] + "), e dice quello di adesso",
                 again[2] == 1 && sh("pkg annotate -S " + one + " " + UpdateManager.MARK_KEY).contains(UpdateManager.MARK_VALUE));
        } finally {
            // Come li ho trovati, cartello per cartello.
            Set<String> now = markedNow();
            for (String n : now) if (!markedBefore.contains(n)) sh("pkg annotate -y -D " + n + " " + UpdateManager.MARK_KEY);
            for (String n : markedBefore) if (!now.contains(n)) sh(UpdateManager.markCommand(n));
        }
        check("  e la prova lascia i cartelli come li ha trovati", markedNow().equals(markedBefore));
    }

    private static Set<String> markedNow() {
        return UpdateManager.markedIn(sh("pkg query -a '%n %At'"));
    }

    /** La stessa regola della nota: lo stack di posta, bloccato adesso. */
    private static Set<String> panelLocked() {
        Set<String> r = new TreeSet<>();
        for (String line : sh("sed -n '/^[a-z]/p' " + UpdateManager.LOCK_NOTE + " 2>/dev/null").split("\n")) {
            if (!line.isBlank()) r.add(line.trim());
        }
        // La nota e' quella dell'ultimo avvio: si tiene solo cio' che e' bloccato davvero adesso.
        r.retainAll(UpdateManager.lockedNames(sh("pkg lock -l")));
        return r;
    }

    private static String firstUnlocked() {
        String r = sh("pkg query -a '%k %n' | awk '$1 == 0 {print $2; exit}'").trim();
        return r.isEmpty() ? null : r;
    }

    private static String sh(String cmd) {
        return Shell.runShell(Duration.ofSeconds(60), cmd).outputTrim();
    }

    private static void check(String name, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + name);
        if (!ok) failures++;
    }
}
