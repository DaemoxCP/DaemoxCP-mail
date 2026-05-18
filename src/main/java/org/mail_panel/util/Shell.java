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

    private static Result runInternal(Duration timeout, List<String> cmd) {
        ProcessBuilder pb = new ProcessBuilder(cmd);
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
