package org.daemoxcp.mail.util;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Centralized helper for running shell commands.
 *
 * Replaces dozens of repeated patterns:
 *   ProcessBuilder pb = new ProcessBuilder("sh", "-c", cmd);
 *   pb.redirectErrorStream(true);
 *   Process p = pb.start();
 *   String out = new String(p.getInputStream().readAllBytes(), UTF_8);
 *   p.waitFor(N, TimeUnit.SECONDS);
 *
 * Typical usage:
 *
 *   var r = Shell.run(Duration.ofSeconds(30),
 *                     "/usr/sbin/service", "fail2ban", "restart");
 *   if (r.success()) {
 *       LOGGER.info("OK: " + r.output());
 *   } else {
 *       LOGGER.warning("FAIL exit=" + r.exitCode() + " out=" + r.output());
 *   }
 *
 *   // For commands I want to pass to sh -c (e.g. with redirects, pipes, etc.):
 *   var r = Shell.runShell(Duration.ofSeconds(10),
 *                          "fail2ban-client status | grep Active");
 *
 * Features:
 *  - Timeout ALWAYS honoured (the process is killed if it exceeds it)
 *  - stdout + stderr unified in the output (redirectErrorStream)
 *  - Explicit UTF-8 charset (no encoding surprises)
 *  - Never a NullPointerException -- output is always a non-null string
 *  - Separate timedOut flag to tell failures apart from timeouts
 *
 * SECURITY: use {@link #run(Duration, String...)} with separate arguments
 * when possible. Only {@link #runShell(Duration, String)} accepts a
 * single string that is passed to {@code sh -c} -- dangerous if it contains
 * unsanitized user input (shell injection).
 */
public final class Shell {

    private static final Logger LOGGER = Logger.getLogger(Shell.class.getName());

    /**
     * The web part of the separated panel: no system commands, except
     * the few it needs that change nothing. The operating system would deny it anything that needs root
     * anyway; here a command the web part must not run is stopped earlier, and the log says which one, so
     * an operation forgotten in the web part shows up instead of failing silently.
     */
    private static volatile boolean webPart;

    /** The programs the web part runs: dig (blacklists), sendmail (the access codes), the server name. */
    static final java.util.Set<String> WEB_PART_PROGRAMS = java.util.Set.of("dig", "drill", "host", "sendmail", "postconf", "hostname");
    /** The shell lines the web part runs (PanelMail, the name in the sender). */
    static final java.util.Set<String> WEB_PART_SHELL = java.util.Set.of("postconf -h myhostname 2>/dev/null", "hostname");

    /** To be called at the start of the web part, before serving requests. There is no going back. */
    public static void webPartOnly() {
        webPart = true;
    }

    /** Stops if the web part asks for a command that is not its own. */
    static void allowed(List<String> cmd) {
        if (!webPart || cmd == null || cmd.isEmpty()) return;
        String prog = cmd.get(0);
        boolean ok;
        if (cmd.size() >= 3 && (prog.equals("sh") || prog.equals("/bin/sh")) && cmd.get(1).equals("-c"))
            ok = WEB_PART_SHELL.contains(cmd.get(2));
        else
            ok = WEB_PART_PROGRAMS.contains(prog.substring(prog.lastIndexOf('/') + 1));
        if (ok) return;
        LOGGER.warning("[WebPart] refused to run " + prog + (cmd.size() > 1 ? " " + cmd.get(1) : "")
                + ": the web part runs no system command");
        throw new SecurityException("the web part runs no system command: " + prog);
    }

    /** Default timeout if not specified. */
    public static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(30);

    private Shell() {} // no instances

    /**
     * Result of a command execution.
     *
     * @param exitCode  exit code of the process, -1 on timeout, -2 on IOException
     * @param output    stdout + stderr combined (always non-null, even if empty)
     * @param timedOut  true if the process was killed for exceeding the timeout
     * @param command   the command executed (useful for logging)
     */
    public record Result(int exitCode, String output, boolean timedOut, List<String> command) {
        /** true if exitCode == 0 AND there was no timeout. */
        public boolean success() { return exitCode == 0 && !timedOut; }

        /** Trimmed output (removes leading/trailing whitespace). */
        public String outputTrim() { return output == null ? "" : output.trim(); }

        /** Human-readable string for logs. */
        @Override
        public String toString() {
            return "Shell.Result{exit=" + exitCode + (timedOut ? ",TIMEOUT" : "")
                + ",cmd=" + command + ",out=" + outputTrim() + "}";
        }
    }

    /**
     * Runs a command with separate arguments (NO shell, no injection).
     *
     * @param timeout maximum execution time; if exceeded the process is killed
     * @param cmd     command + separate arguments, e.g.: {@code "/usr/sbin/service", "fail2ban", "restart"}
     */
    public static Result run(Duration timeout, String... cmd) {
        return runInternal(timeout, Arrays.asList(cmd));
    }

    /**
     * Runs a command with separate arguments, with the default timeout (30s).
     */
    public static Result run(String... cmd) {
        return run(DEFAULT_TIMEOUT, cmd);
    }

    /**
     * Like {@link #run(Duration, String...)}, but with a text on the command's standard input, then
     * EOF. For secrets that a command can read from there (doveadm pw, doveadm auth test): among the
     * arguments anyone could see them with ps, and a timeout would write them to the log with the command.
     */
    public static Result runWithInput(Duration timeout, String input, String... cmd) {
        return runInternal(timeout, Arrays.asList(cmd), input == null ? "" : input);
    }

    /**
     * Runs a command string via {@code sh -c}.
     * USE ONLY with static commands or already sanitized input -- shell injection risk.
     *
     * @param timeout maximum duration
     * @param shellCommand string that will be passed to {@code sh -c "..."}
     */
    public static Result runShell(Duration timeout, String shellCommand) {
        return runInternal(timeout, List.of("sh", "-c", shellCommand));
    }

    /** Runs via sh -c with the default timeout (30s). */
    public static Result runShell(String shellCommand) {
        return runShell(DEFAULT_TIMEOUT, shellCommand);
    }

    /**
     * The PATH with which child processes are launched.
     *
     * The panel simply inherited the PATH of whoever had started it. From the command line that is
     * fine; started from rc.d it can be much shorter, and then a command that lives in
     * /usr/local/bin -- mysqldump, mysql, doveadm, postmap, rspamadm, fail2ban-client --
     * simply "does not exist". The failure shows up far from here, in the form of
     * "mysqldump is not installed", which sends you looking for a package that is there.
     *
     * The standard folders are APPENDED to the inherited ones: that way we do not change
     * which binary wins for the commands that already resolved, and we only add what
     * was missing. The order is that of the FreeBSD default PATH in login.conf.
     */
    private static final String FULL_PATH = buildPath();

    private static String buildPath() {
        String inherited = System.getenv("PATH");
        java.util.LinkedHashSet<String> parts = new java.util.LinkedHashSet<>();
        if (inherited != null)
            for (String d : inherited.split(":")) if (!d.isBlank()) parts.add(d);
        for (String d : new String[]{"/sbin", "/bin", "/usr/sbin", "/usr/bin",
                                     "/usr/local/sbin", "/usr/local/bin"})
            parts.add(d);
        return String.join(":", parts);
    }

    /**
     * Applies the same PATH to a ProcessBuilder built elsewhere.
     *
     * It is needed because not everything goes through here: the long commands that write the log as
     * output arrives, and those that must receive a password via the environment (MYSQL_PWD), build
     * their own ProcessBuilder. Without this call they inherit the PATH of the
     * panel and may not find programs that are there: it happened with mysqldump,
     * where --print-defaults worked (it went through Shell) and the real dump did not.
     */
    public static void applyPath(ProcessBuilder pb) {
        if (pb == null) return;
        allowed(pb.command());
        pb.environment().put("PATH", FULL_PATH);
        java.util.List<String> cmd = pb.command();
        if (cmd == null || cmd.isEmpty()) return;
        String prog = cmd.get(0);
        if (prog == null || prog.isEmpty() || prog.indexOf('/') >= 0) return;   // already absolute
        String absolute = resolve(prog);
        if (absolute != null) cmd.set(0, absolute);
    }

    /**
     * The absolute path of a program, searched in the same folders as the complete PATH.
     * Returns null if it exists nowhere: in that case the name stays as it was and
     * the error that follows is the right one, that is, "the program is not there" for real.
     */
    public static String resolve(String prog) {
        if (prog == null || prog.isEmpty() || prog.indexOf('/') >= 0) return prog;
        for (String d : FULL_PATH.split(":")) {
            if (d.isBlank()) continue;
            java.io.File f = new java.io.File(d, prog);
            if (f.isFile() && f.canExecute()) return f.getAbsolutePath();
        }
        return null;
    }

    /** The PATH the panel really uses for subprocesses. */
    public static String fullPath() { return FULL_PATH; }

    /** The PATH inherited from whoever started the panel, before the missing folders are added. */
    public static String inheritedPath() {
        String e = System.getenv("PATH");
        return e == null ? "" : e;
    }

    /**
     * The standard input of every child: /dev/null, that is, immediate EOF.
     *
     * Without this line ProcessBuilder gives it its default pipe, which the JVM keeps
     * open for writing and never writes to: whoever reads gets neither data nor EOF and stays
     * stuck until the timeout. Measured on the FreeBSD 15.1 VM on 2026-10-23: a `read x`
     * passed to runShell with an 8s timeout returns after 8102 ms, exit -1, timedOut true; the
     * same command with </dev/null returns in 3 ms. In the updater jobs the timeouts
     * are 1800 or 3600 seconds, so that wait is half an hour or an hour in which the
     * package turn stays taken and every other operation is refused.
     *
     * Nobody can answer that prompt: the child does not inherit the terminal, it gets
     * its own pipe, and what the operator types goes to the PANEL's stdin. So
     * the wait is not a wait, it is a hang.
     *
     * EOF is not an error: a command that reads without checking the result of the read
     * carries on with an empty value instead of stopping. This removes the wait, it does not
     * turn a prompt into an error -- whoever adds a command that asks for something must
     * check the result of the read.
     */
    private static final java.io.File NO_STDIN = new java.io.File("/dev/null");

    private static Result runInternal(Duration timeout, List<String> cmd) {
        return runInternal(timeout, cmd, null);
    }

    /** input null: the standard input is /dev/null (see NO_STDIN); otherwise that text, then EOF. */
    private static Result runInternal(Duration timeout, List<String> cmd, String input) {
        // applyPath and not just the PATH in the environment: Java looks for the program to launch with the
        // panel's PATH, not with the child's. Started from rc.d without /usr/local, the panel
        // did not find nginx, doveadm, postmap... even though the child's PATH had them. On the production
        // server on 2026-11-07 three first-boot migrations got stuck on "Cannot run
        // program nginx" (finding 181).
        ProcessBuilder pb = new ProcessBuilder(new java.util.ArrayList<>(cmd));
        applyPath(pb);
        pb.redirectInput(input == null ? ProcessBuilder.Redirect.from(NO_STDIN) : ProcessBuilder.Redirect.PIPE);
        pb.redirectErrorStream(true);
        Process p = null;
        try {
            p = pb.start();
            if (input != null) {
                // A few bytes: they fit in the pipe buffer and the write does not wait for the child.
                // A child that exits without reading closes the pipe: that is not the writer's error.
                try (java.io.OutputStream in = p.getOutputStream()) {
                    in.write(input.getBytes(StandardCharsets.UTF_8));
                } catch (IOException closedByChild) {
                    // the outcome is given by the exit code
                }
            }
            // Critical FIX: the kernel pipe buffer is typically 64KB.
            // If we do NOT read stdout in parallel, processes that produce >64KB
            // of output (e.g. pfctl -T show on 100k+ entries) block and waitFor()
            // waits until the timeout. We solve it by reading stdout in a separate thread.
            final Process pFinal = p;
            java.util.concurrent.CompletableFuture<String> outputFuture =
                java.util.concurrent.CompletableFuture.supplyAsync(() -> readOutput(pFinal),
                    java.util.concurrent.CompletableFuture.delayedExecutor(0,
                        TimeUnit.MILLISECONDS,
                        java.util.concurrent.Executors.newVirtualThreadPerTaskExecutor()));

            boolean finished = p.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS);
            if (!finished) {
                p.destroyForcibly();
                // Wait a moment for the kill to reach its target
                p.waitFor(2, TimeUnit.SECONDS);
                String partial = "";
                try { partial = outputFuture.get(2, TimeUnit.SECONDS); } catch (Exception ignored) {}
                LOGGER.log(Level.WARNING, "Shell timeout after {0}ms: {1}",
                    new Object[]{timeout.toMillis(), cmd});
                return new Result(-1, partial, true, cmd);
            }
            // Process finished -- fetch the output (already read in parallel)
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
