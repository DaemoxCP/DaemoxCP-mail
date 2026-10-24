package org.mail_panel.util;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Helper centralizzato per l'esecuzione di comandi shell.
 *
 * Sostituisce decine di pattern ripetuti:
 *   ProcessBuilder pb = new ProcessBuilder("sh", "-c", cmd);
 *   pb.redirectErrorStream(true);
 *   Process p = pb.start();
 *   String out = new String(p.getInputStream().readAllBytes(), UTF_8);
 *   p.waitFor(N, TimeUnit.SECONDS);
 *
 * Uso tipico:
 *
 *   var r = Shell.run(Duration.ofSeconds(30),
 *                     "/usr/sbin/service", "fail2ban", "restart");
 *   if (r.success()) {
 *       LOGGER.info("OK: " + r.output());
 *   } else {
 *       LOGGER.warning("FAIL exit=" + r.exitCode() + " out=" + r.output());
 *   }
 *
 *   // Per comandi che voglio passare a sh -c (es. con redirect, pipe, ecc):
 *   var r = Shell.runShell(Duration.ofSeconds(10),
 *                          "fail2ban-client status | grep Active");
 *
 * Caratteristiche:
 *  - Timeout SEMPRE rispettato (kill del processo se eccede)
 *  - stdout + stderr unificati nell'output (redirectErrorStream)
 *  - Charset UTF-8 esplicito (niente sorprese di encoding)
 *  - Mai NullPointerException — output e' sempre stringa non-null
 *  - timedOut flag separato per distinguere fallimenti da timeout
 *
 * SECURITY: usa {@link #run(Duration, String...)} con argomenti separati
 * quando possibile. Solo {@link #runShell(Duration, String)} accetta una
 * stringa unica che viene passata a {@code sh -c} — pericoloso se contiene
 * input non sanitizzato dall'utente (shell injection).
 */
public final class Shell {

    private static final Logger LOGGER = Logger.getLogger(Shell.class.getName());

    /** Default timeout se non specificato. */
    public static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(30);

    private Shell() {} // no instances

    /**
     * Risultato di un'esecuzione comando.
     *
     * @param exitCode  codice di uscita del processo, -1 se timeout, -2 se IOException
     * @param output    stdout + stderr combinati (sempre non-null, anche se vuoto)
     * @param timedOut  true se il processo e' stato killato per superamento timeout
     * @param command   il comando eseguito (utile per logging)
     */
    public record Result(int exitCode, String output, boolean timedOut, List<String> command) {
        /** true se exitCode == 0 E non c'e' stato timeout. */
        public boolean success() { return exitCode == 0 && !timedOut; }

        /** Output trimmato (rimuove whitespace iniziale/finale). */
        public String outputTrim() { return output == null ? "" : output.trim(); }

        /** Stringa human-readable per log. */
        @Override
        public String toString() {
            return "Shell.Result{exit=" + exitCode + (timedOut ? ",TIMEOUT" : "")
                + ",cmd=" + command + ",out=" + outputTrim() + "}";
        }
    }

    /**
     * Esegue un comando con argomenti separati (NO shell, no injection).
     *
     * @param timeout durata massima di esecuzione; se superata il processo viene killato
     * @param cmd     comando + argomenti separati, es: {@code "/usr/sbin/service", "fail2ban", "restart"}
     */
    public static Result run(Duration timeout, String... cmd) {
        return runInternal(timeout, Arrays.asList(cmd));
    }

    /**
     * Esegue un comando con argomenti separati con timeout di default (30s).
     */
    public static Result run(String... cmd) {
        return run(DEFAULT_TIMEOUT, cmd);
    }

    /**
     * Esegue una stringa di comando via {@code sh -c}.
     * USA SOLO con comandi statici o input gia' sanitizzato — rischio shell injection.
     *
     * @param timeout durata massima
     * @param shellCommand stringa che verra' passata a {@code sh -c "..."}
     */
    public static Result runShell(Duration timeout, String shellCommand) {
        return runInternal(timeout, List.of("sh", "-c", shellCommand));
    }

    /** Esegue via sh -c con timeout di default (30s). */
    public static Result runShell(String shellCommand) {
        return runShell(DEFAULT_TIMEOUT, shellCommand);
    }

    /**
     * Il PATH con cui vengono lanciati i processi figli.
     *
     * Il pannello ereditava e basta il PATH di chi lo aveva avviato. Da riga di comando va
     * bene; avviato da rc.d puo' essere molto piu' corto, e allora un comando che sta in
     * /usr/local/bin — mysqldump, mysql, doveadm, postmap, rspamadm, fail2ban-client —
     * semplicemente "non esiste". Il guasto si presenta lontano da qui, sotto forma di
     * "mysqldump non e' installato", che manda a cercare un pacchetto che c'e'.
     *
     * Le cartelle standard vengono AGGIUNTE IN CODA a quelle ereditate: cosi' non si cambia
     * quale binario vince per i comandi che gia' si risolvevano, e si aggiunge soltanto cio'
     * che mancava. L'ordine e' quello del PATH predefinito di FreeBSD in login.conf.
     */
    private static final String PATH_COMPLETO = costruisciPath();

    private static String costruisciPath() {
        String ereditato = System.getenv("PATH");
        java.util.LinkedHashSet<String> parti = new java.util.LinkedHashSet<>();
        if (ereditato != null)
            for (String d : ereditato.split(":")) if (!d.isBlank()) parti.add(d);
        for (String d : new String[]{"/sbin", "/bin", "/usr/sbin", "/usr/bin",
                                     "/usr/local/sbin", "/usr/local/bin"})
            parti.add(d);
        return String.join(":", parti);
    }

    /**
     * Applica lo stesso PATH a un ProcessBuilder costruito altrove.
     *
     * Serve perche' non tutto passa da qui: i comandi lunghi che scrivono il log mentre
     * arrivano, e quelli che devono ricevere una password via ambiente (MYSQL_PWD), si
     * costruiscono il ProcessBuilder da soli. Senza questa chiamata ereditano il PATH del
     * pannello e possono non trovare programmi che ci sono: e' successo con mysqldump,
     * dove --print-defaults funzionava (passava da Shell) e il dump vero no.
     */
    public static void applicaPath(ProcessBuilder pb) {
        if (pb == null) return;
        pb.environment().put("PATH", PATH_COMPLETO);
        java.util.List<String> cmd = pb.command();
        if (cmd == null || cmd.isEmpty()) return;
        String prog = cmd.get(0);
        if (prog == null || prog.isEmpty() || prog.indexOf('/') >= 0) return;   // gia' assoluto
        String assoluto = risolvi(prog);
        if (assoluto != null) cmd.set(0, assoluto);
    }

    /**
     * Il percorso assoluto di un programma, cercato nelle stesse cartelle del PATH completo.
     * Restituisce null se non esiste da nessuna parte: in quel caso il nome resta com'era e
     * l'errore che ne segue e' quello giusto, cioe' "il programma non c'e'" davvero.
     */
    public static String risolvi(String prog) {
        if (prog == null || prog.isEmpty() || prog.indexOf('/') >= 0) return prog;
        for (String d : PATH_COMPLETO.split(":")) {
            if (d.isBlank()) continue;
            java.io.File f = new java.io.File(d, prog);
            if (f.isFile() && f.canExecute()) return f.getAbsolutePath();
        }
        return null;
    }

    /** Il PATH che il pannello usa davvero per i sottoprocessi. */
    public static String pathCompleto() { return PATH_COMPLETO; }

    /** Il PATH ereditato da chi ha avviato il pannello, prima dell'integrazione. */
    public static String pathEreditato() {
        String e = System.getenv("PATH");
        return e == null ? "" : e;
    }

    /**
     * Lo standard input di ogni figlio: /dev/null, cioe' EOF immediato.
     *
     * Senza questa riga ProcessBuilder gli da' la sua pipe predefinita, che la JVM tiene
     * aperta in scrittura e non scrive mai: chi legge non prende ne' dati ne' EOF e resta
     * fermo fino al timeout. Misurato sulla VM FreeBSD 15.1 il 23/10/2026: un `read x`
     * passato a runShell con timeout 8s torna dopo 8102 ms, exit -1, timedOut true; lo
     * stesso comando con </dev/null torna in 3 ms. Nei lavori dell'updater i timeout
     * valgono 1800 o 3600 secondi, quindi quell'attesa e' mezz'ora o un'ora in cui il
     * turno dei pacchetti resta preso e ogni altra operazione viene rifiutata.
     *
     * Nessuno puo' rispondere a quel prompt: il figlio non eredita il terminale, prende
     * una pipe sua, e quello che l'operatore digita arriva allo stdin del PANNELLO. Quindi
     * l'attesa non e' un'attesa, e' un blocco.
     *
     * EOF non e' un errore: un comando che legge senza controllare l'esito della lettura
     * prosegue con un valore vuoto invece di fermarsi. Questo toglie l'attesa, non
     * trasforma un prompt in un errore — chi aggiunge un comando che chiede qualcosa deve
     * controllare l'esito della lettura.
     */
    private static final java.io.File NO_STDIN = new java.io.File("/dev/null");

    private static Result runInternal(Duration timeout, List<String> cmd) {
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.environment().put("PATH", PATH_COMPLETO);
        pb.redirectInput(ProcessBuilder.Redirect.from(NO_STDIN));
        pb.redirectErrorStream(true);
        Process p = null;
        try {
            p = pb.start();
            // FIX critico: il pipe buffer del kernel e' tipicamente 64KB.
            // Se NON leggiamo lo stdout in parallelo, processi che producono >64KB
            // di output (es. pfctl -T show su 100k+ entries) si bloccano e waitFor()
            // attende fino al timeout. Risolviamo leggendo lo stdout in un thread separato.
            final Process pFinal = p;
            java.util.concurrent.CompletableFuture<String> outputFuture =
                java.util.concurrent.CompletableFuture.supplyAsync(() -> readOutput(pFinal),
                    java.util.concurrent.CompletableFuture.delayedExecutor(0,
                        TimeUnit.MILLISECONDS,
                        java.util.concurrent.Executors.newVirtualThreadPerTaskExecutor()));

            boolean finished = p.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS);
            if (!finished) {
                p.destroyForcibly();
                // Aspetta un attimo che il kill arrivi a destinazione
                p.waitFor(2, TimeUnit.SECONDS);
                String partial = "";
                try { partial = outputFuture.get(2, TimeUnit.SECONDS); } catch (Exception ignored) {}
                LOGGER.log(Level.WARNING, "Shell timeout after {0}ms: {1}",
                    new Object[]{timeout.toMillis(), cmd});
                return new Result(-1, partial, true, cmd);
            }
            // Process finito — recupera l'output (gia' letto in parallelo)
            String out = "";
            try { out = outputFuture.get(5, TimeUnit.SECONDS); } catch (Exception ignored) {}
            return new Result(p.exitValue(), out, false, cmd);
        } catch (IOException e) {
            LOGGER.log(Level.WARNING, "Shell IOException: " + cmd, e);
            return new Result(-2, "IOException: " + e.getMessage(), false, cmd);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            if (p != null) p.destroyForcibly();
            return new Result(-3, "Interrupted: " + e.getMessage(), false, cmd);
        }
    }

    private static String readOutput(Process p) {
        try {
            byte[] bytes = p.getInputStream().readAllBytes();
            return new String(bytes, StandardCharsets.UTF_8);
        } catch (IOException e) {
            return "";
        }
    }
}
