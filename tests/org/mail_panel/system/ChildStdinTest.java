package org.mail_panel.system;

import java.time.Duration;
import org.mail_panel.util.Shell;

/**
 * Lo standard input dei comandi dell'updater.
 *
 * Ogni comando dell'area aggiornamenti passa da {@code Shell} (le letture: pkg query, pkg
 * lock, service status) o da {@code UpdateManager.eseguiConLog} (i lavori lunghi: pkg
 * upgrade, freebsd-update install). Con la pipe predefinita di ProcessBuilder il figlio che
 * legge non riceve ne' dati ne' EOF: resta fermo fino al timeout, che qui vale 1800 o 3600
 * secondi, e nel frattempo il turno dei pacchetti e' preso e ogni altra operazione viene
 * rifiutata. Misurato sulla VM FreeBSD 15.1 il 23/10/2026: 8102 ms su un timeout di 8s,
 * exit -1; con /dev/null 3 ms.
 *
 * Le prove sono scritte per FALLIRE senza la correzione: un'attesa fino al timeout si vede
 * sia nell'esito (exit -1, timedOut) sia nel tempo trascorso.
 */
public class ChildStdinTest {

    private static int falliti = 0;

    /** Timeout dei comandi di prova: abbastanza lungo perche' l'attesa si distingua dal lavoro. */
    private static final int TIMEOUT = 8;

    /** Oltre questo un comando banale non e' lento, sta aspettando. */
    private static final long SUBITO_MS = 4000;

    public static void main(String[] args) throws Exception {

        // --- 1. Shell.runShell: un comando che legge da stdin ---
        long t = System.currentTimeMillis();
        Shell.Result r = Shell.runShell(Duration.ofSeconds(TIMEOUT), "read x; echo \"letto [$x]\"");
        long durata = System.currentTimeMillis() - t;
        vero("runShell: il comando che legge non aspetta (" + durata + " ms)", durata < SUBITO_MS);
        vero("runShell: nessun timeout", !r.timedOut());
        vero("runShell: uscita 0, non -1", r.exitCode() == 0);
        vero("runShell: il comando e' arrivato in fondo", r.outputTrim().contains("letto []"));

        // --- 2. Shell.run, la forma con argomenti separati: stesso codice, esito dichiarato ---
        t = System.currentTimeMillis();
        r = Shell.run(Duration.ofSeconds(TIMEOUT), "sh", "-c", "read x; echo \"letto [$x]\"");
        durata = System.currentTimeMillis() - t;
        vero("run: il comando che legge non aspetta (" + durata + " ms)", durata < SUBITO_MS);
        vero("run: uscita 0 e nessun timeout", r.exitCode() == 0 && !r.timedOut());

        // --- 3. eseguiConLog, la via dei lavori lunghi ---
        UpdateManager.Job job = new UpdateManager.Job("prova-stdin", "prova");
        t = System.currentTimeMillis();
        int codice = UpdateManager.eseguiConLog(job, "read x; echo \"letto [$x]\"", TIMEOUT);
        durata = System.currentTimeMillis() - t;
        String log = job.toJson().optString("consoleLog", "");
        vero("eseguiConLog: il comando che legge non aspetta (" + durata + " ms)", durata < SUBITO_MS);
        vero("eseguiConLog: uscita 0, non un processo ucciso", codice == 0);
        vero("eseguiConLog: nel log del lavoro non c'e' nessun timeout",
             !log.contains("TIMEOUT") && !log.toLowerCase().contains("timeout"));
        vero("eseguiConLog: l'output del comando e' nel log", log.contains("letto []"));

        // --- 4. Un comando che NON legge si comporta come prima ---
        r = Shell.runShell(Duration.ofSeconds(TIMEOUT), "echo ciao; echo errore >&2");
        vero("un comando normale resta normale: uscita 0",
             r.exitCode() == 0 && !r.timedOut());
        vero("un comando normale resta normale: stdout e stderr uniti",
             r.outputTrim().contains("ciao") && r.outputTrim().contains("errore"));

        // --- 5. EOF non diventa un si' silenzioso ---
        // Chi controlla l'esito della lettura se ne accorge e puo' fallire: questa prova
        // esiste perche' chi aggiunge un comando che chiede qualcosa sappia che /dev/null
        // toglie l'attesa, non trasforma il prompt in un errore. Un comando che NON
        // controlla prosegue con il valore vuoto (caso 1: uscita 0).
        r = Shell.runShell(Duration.ofSeconds(TIMEOUT), "if read x; then exit 0; else exit 7; fi");
        vero("una lettura con esito controllato fallisce subito invece di aspettare",
             r.exitCode() == 7 && !r.timedOut());

        System.out.println(falliti == 0 ? "\nTUTTO OK" : "\n" + falliti + " PROVE FALLITE");
        if (falliti > 0) System.exit(1);
    }

    private static void vero(String nome, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + nome);
        if (!ok) falliti++;
    }
}
