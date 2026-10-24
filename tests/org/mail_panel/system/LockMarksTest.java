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

    private static int falliti = 0;

    public static void main(String[] args) {

        // --- 1. Chi porta il cartello, da un'uscita di pkg query -a '%n %At' ---
        String uscita = String.join("\n",
                "alsa-lib FreeBSD_version",
                "nginx cpe",
                "nginx repository",
                "redis mail_panel_lock",
                "redis cpe",
                "postfix-mysql mail_panel_lock",
                "pkg: warning: qualcosa su stderr",
                "rm;-rf mail_panel_lock",
                "");
        Set<String> annotati = UpdateManager.markedIn(uscita);
        vero("dall'uscita di pkg: redis e postfix-mysql", annotati.equals(Set.of("redis", "postfix-mysql")));
        vero("  una riga di stderr non e' un pacchetto", !annotati.contains("pkg:"));
        vero("  un nome che non passa il filtro non entra", annotati.stream().noneMatch(n -> n.contains(";")));
        vero("uscita vuota: nessun cartello", UpdateManager.markedIn("").isEmpty());

        // --- 2. I comandi per portare i cartelli dove servono ---
        List<String> c = UpdateManager.lockMarkCommands(
                Set.of("nginx", "redis", "dovecot"), Set.of("redis", "lmdb"));
        vero("tre comandi: due da mettere, uno da togliere (" + c.size() + ")", c.size() == 3);
        vero("  mette il cartello su dovecot", c.stream().anyMatch(x -> x.contains(" -A dovecot ")));
        vero("  e su nginx", c.stream().anyMatch(x -> x.contains(" -A nginx ")));
        vero("  non tocca redis, che ce l'ha", c.stream().noneMatch(x -> x.contains(" redis ")));
        vero("  toglie quello di lmdb, che non e' piu' bloccato",
             c.contains(UpdateManager.removeMarkCommand("lmdb")));
        vero("  e il comando che toglie nomina la chiave e il pacchetto",
             "pkg annotate -y -D lmdb mail_panel_lock".equals(UpdateManager.removeMarkCommand("lmdb")));
        vero("tutto in pari: nessun comando",
             UpdateManager.lockMarkCommands(Set.of("nginx"), Set.of("nginx")).isEmpty());
        vero("un nome che non passa il filtro non produce nessun comando",
             UpdateManager.lockMarkCommands(Set.of("ngi nx; rm -rf /"), Set.of()).isEmpty()
             && UpdateManager.removeMarkCommand("x; rm -rf /") == null);

        // --- 3. La macchina della misura: 39 bloccati, il cartello su uno ---
        Set<String> trentanove = new TreeSet<>();
        for (int i = 0; i < 38; i++) trentanove.add("pacchetto" + i);
        trentanove.add("redis");
        vero("39 bloccati e un cartello solo: 38 da mettere, niente da togliere",
             UpdateManager.lockMarkCommands(trentanove, Set.of("redis")).size() == 38);

        // --- 4. Su pkg vero ---
        if (!Shell.runShell(Duration.ofSeconds(10), "command -v pkg").success()) {
            System.out.println("  --   pkg vero: pkg non c'e' su questa macchina, salto");
        } else {
            sulVero();
        }

        System.out.println(falliti == 0 ? "\nTUTTO OK" : "\n" + falliti + " PROVE FALLITE");
        if (falliti > 0) System.exit(1);
    }

    private static void sulVero() {
        Set<String> primaAnnotati = annotatiOra();
        Set<String> bloccati = bloccatiDelPannello();
        if (bloccati.isEmpty()) {
            System.out.println("  --   pkg vero: nessun pacchetto dello stack bloccato, salto");
            return;
        }
        String uno = bloccati.iterator().next();
        String libero = primoNonBloccato();
        try {
            UpdateManager.syncLockMarks();
            vero("pkg vero: dopo la sincronizzazione il cartello sta su tutti e soli i "
                 + bloccati.size() + " bloccati", annotatiOra().equals(bloccati));

            // Il cartello perso da un aggiornamento, e uno rimasto su un pacchetto sbloccato
            sh("pkg annotate -y -D " + uno + " " + UpdateManager.CHIAVE_ANNOTAZIONE);
            if (libero != null) sh(UpdateManager.comandoAnnotazione(libero));
            int[] fatti = UpdateManager.syncLockMarks();
            vero("  il cartello tolto a " + uno + " torna", annotatiOra().contains(uno));
            if (libero != null) {
                vero("  quello messo su " + libero + ", che non e' bloccato, se ne va",
                     !annotatiOra().contains(libero));
                vero("  e la sincronizzazione lo conta: 1 messo, 1 tolto (" + fatti[0] + ", " + fatti[1] + ")",
                     fatti[0] == 1 && fatti[1] == 1);
            }
            vero("  e una seconda volta non c'e' niente da fare",
                 java.util.Arrays.equals(UpdateManager.syncLockMarks(), new int[]{0, 0}));
        } finally {
            // Come li ho trovati, cartello per cartello.
            Set<String> ora = annotatiOra();
            for (String n : ora) if (!primaAnnotati.contains(n)) sh("pkg annotate -y -D " + n + " " + UpdateManager.CHIAVE_ANNOTAZIONE);
            for (String n : primaAnnotati) if (!ora.contains(n)) sh(UpdateManager.comandoAnnotazione(n));
        }
        vero("  e la prova lascia i cartelli come li ha trovati", annotatiOra().equals(primaAnnotati));
    }

    private static Set<String> annotatiOra() {
        return UpdateManager.markedIn(sh("pkg query -a '%n %At'"));
    }

    /** La stessa regola della nota: lo stack di posta, bloccato adesso. */
    private static Set<String> bloccatiDelPannello() {
        Set<String> r = new TreeSet<>();
        for (String riga : sh("sed -n '/^[a-z]/p' " + UpdateManager.LOCK_NOTE + " 2>/dev/null").split("\n")) {
            if (!riga.isBlank()) r.add(riga.trim());
        }
        // La nota e' quella dell'ultimo avvio: si tiene solo cio' che e' bloccato davvero adesso.
        r.retainAll(UpdateManager.insiemeProtetti(sh("pkg lock -l")));
        return r;
    }

    private static String primoNonBloccato() {
        String r = sh("pkg query -a '%k %n' | awk '$1 == 0 {print $2; exit}'").trim();
        return r.isEmpty() ? null : r;
    }

    private static String sh(String cmd) {
        return Shell.runShell(Duration.ofSeconds(60), cmd).outputTrim();
    }

    private static void vero(String nome, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + nome);
        if (!ok) falliti++;
    }
}
