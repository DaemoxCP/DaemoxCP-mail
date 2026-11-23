package org.daemoxcp.mail.system;

import org.daemoxcp.mail.i18n.I18n;

import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

/**
 * The full reinstallation from the menu runs detached from the menu: a process of its own, in a session of
 * its own (daemon(8)), that writes to a log; the menu just follows it.
 *
 * <p>Why it exists: measured on the FreeBSD 15.1 VM on 2026-11-06 (finding 163). The script ran as a child
 * of the menu's JVM, in the same process group.
 * <ul>
 *   <li>ssh closed during phase 2 (the terminal receives SIGHUP): menu, script and pkg died together.
 *       Mail off, Postfix configurations already deleted, the 39 packages unlocked with the list on
 *       disk, and the running service did not notice until its next startup.</li>
 *   <li>The menu's JVM killed with kill -9: the orphaned script went on for ~16 seconds (installing
 *       Roundcube and PHP) and died at the first line written to the pipe that nobody read any more, at
 *       a random point.</li>
 * </ul>
 * Now the menu launches {@code Main --reinstall <name> <outcome file>} with daemon(8): new session, no
 * terminal, the output in a file. If the menu dies (ssh dropped, Ctrl-C, kill) the job goes on, locks
 * the packages again, decides the password and the way back, and writes the outcome. When the menu is
 * reopened during a reinstallation, it follows the one in progress instead of starting another.
 *
 * <p>The log lives in /var/log/daemoxcp-mail, outside the boot environment: it stays even after going
 * back with the way back, which is exactly when it needs to be read.
 */
public final class ReinstallJob {

    private static final Logger LOGGER = Logger.getLogger(ReinstallJob.class.getName());

    private ReinstallJob() {}

    /** The log folder. The tests move it with -Ddaemoxcp.mail.reinstall.dir. */
    static Path dir = Path.of(System.getProperty("daemoxcp.mail.reinstall.dir", "/var/log/daemoxcp-mail"));

    /** daemon(8) from the FreeBSD base system. */
    static String daemon = "/usr/sbin/daemon";

    /** How many past reinstallations are kept (log and outcome). */
    static final int KEEP = 10;

    private static final DateTimeFormatter STAMP =
            DateTimeFormatter.ofPattern("yyyy-MM-dd-HHmmss").withZone(ZoneOffset.UTC);

    /** A reinstallation: the log, the pid file (from daemon -p) and the outcome file. */
    public record Run(Path log, Path pid, Path exit) {
        static Run named(String base) {
            return new Run(dir.resolve(base + ".log"), dir.resolve(base + ".pid"), dir.resolve(base + ".exit"));
        }
    }

    /** An acceptable mail server name: letters, digits, hyphens and dots, like a DNS name. */
    public static boolean validHostname(String h) {
        return h != null && h.length() <= 253
                && h.matches("[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*");
    }

    /**
     * From the menu option: launches the detached reinstallation (or finds the one in progress) and follows
     * its log until the end. True if it succeeded. Without daemon(8) (not FreeBSD) it does it here, as
     * before, and says so.
     */
    public static boolean runFromMenu(String host, PrintStream out) {
        I18n.setCurrent("en");     // the console is in English
        try {
            Run running = running();
            if (running != null) {
                out.println(I18n.tr("server.reinstall.job.alreadyRunning",
                        Map.of("pid", String.valueOf(pidOf(running)), "log", String.valueOf(running.log()))));
                out.flush();
                return follow(running, out);
            }
            if (!validHostname(host)) {
                out.println(I18n.tr("server.reinstall.job.badHostname", Map.of("host", String.valueOf(host))));
                return false;
            }
            if (!new File(daemon).canExecute()) {
                out.println(I18n.tr("server.reinstall.job.inProcess", Map.of("daemon", daemon)));
                out.flush();
                I18n.clearCurrent();
                // The script of the running jar, as Main --reinstall does (InstallScripts, finding 169).
                new org.daemoxcp.mail.scripts.FullMailServerScript().write_file();
                return org.daemoxcp.mail.Main.runInstallation(host);
            }
            Run r;
            try {
                r = launch(host);
            } catch (IOException | RuntimeException e) {
                out.println(I18n.tr("server.reinstall.job.cannotStart", Map.of("err", String.valueOf(e.getMessage()))));
                return false;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
            out.println(I18n.tr("server.reinstall.job.started",
                    Map.of("pid", String.valueOf(pidOf(r)), "log", String.valueOf(r.log()))));
            out.flush();
            return follow(r, out);
        } finally {
            I18n.clearCurrent();
        }
    }

    /** Launches the job with daemon(8) and waits until it has written its pid. */
    static Run launch(String host) throws IOException, InterruptedException {
        Files.createDirectories(dir);
        setPermissions(dir, "rwx------");
        prune();
        Run r = Run.named("reinstall-" + STAMP.format(Instant.now()));
        if (Files.exists(r.log())) throw new IOException("a reinstallation started in this same second: " + r.log());
        Files.createFile(r.log());
        setPermissions(r.log(), "rw-------");

        // --enable-native-access: with -cp the Enable-Native-Access entry of the jar manifest does not apply
        // (only -jar reads it), and Java 25 wrote four WARNINGs about the System.load of the SQLite driver at
        // the top of the reinstallation log, so also on the menu screen (test from a clean server on 2026-11-18).
        List<String> cmd = new ArrayList<>(List.of(daemon, "-f", "-o", r.log().toString(),
                "-p", r.pid().toString(), "-t", "daemoxcp-mail-reinstall", java(), "--enable-native-access=ALL-UNNAMED"));
        // The panel's settings (secrets folder, log folder) apply to it too.
        for (String k : System.getProperties().stringPropertyNames())
            if (k.startsWith("daemoxcp.mail.")) cmd.add("-D" + k + "=" + System.getProperty(k));
        cmd.addAll(List.of("-cp", System.getProperty("java.class.path"), "org.daemoxcp.mail.Main",
                "--reinstall", host, r.exit().toString()));
        ProcessBuilder pb = new ProcessBuilder(cmd).directory(new File(System.getProperty("user.dir")));
        org.daemoxcp.mail.util.Shell.applyPath(pb);
        pb.redirectInput(ProcessBuilder.Redirect.from(new File("/dev/null")));
        pb.redirectErrorStream(true);
        pb.redirectOutput(ProcessBuilder.Redirect.DISCARD);
        int rc = pb.start().waitFor();
        if (rc != 0) throw new IOException(daemon + " exited " + rc);
        for (int i = 0; i < 150 && pidOf(r) <= 0; i++) Thread.sleep(100);
        if (pidOf(r) <= 0 && !Files.exists(r.exit())) throw new IOException("the reinstallation did not start: " + r.log());
        LOGGER.info("Complete reinstallation started detached, pid " + pidOf(r) + ", log " + r.log());
        return r;
    }

    /**
     * Follows the log from the start until the outcome. True if the outcome is 0. If the job disappears
     * without an outcome (killed), it says so and returns false.
     */
    static boolean follow(Run r, PrintStream out) {
        long offset = 0;
        try {
            while (true) {
                offset = copyNew(r.log(), offset, out);
                if (Files.exists(r.exit())) {
                    copyNew(r.log(), offset, out);
                    return "0".equals(Files.readString(r.exit(), StandardCharsets.UTF_8).trim());
                }
                if (!alive(r)) {
                    Thread.sleep(500);
                    offset = copyNew(r.log(), offset, out);
                    if (Files.exists(r.exit()))
                        return "0".equals(Files.readString(r.exit(), StandardCharsets.UTF_8).trim());
                    out.println(I18n.tr("server.reinstall.job.stopped", Map.of("log", String.valueOf(r.log()))));
                    out.flush();
                    return false;
                }
                Thread.sleep(500);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        } catch (IOException e) {
            out.println(I18n.tr("server.reinstall.job.cannotFollow", Map.of("log", String.valueOf(r.log()), "err", String.valueOf(e.getMessage()))));
            return false;
        }
    }

    private static long copyNew(Path log, long offset, PrintStream out) throws IOException {
        if (!Files.exists(log)) return offset;
        try (RandomAccessFile f = new RandomAccessFile(log.toFile(), "r")) {
            long len = f.length();
            if (len <= offset) return offset;
            f.seek(offset);
            byte[] b = new byte[(int) Math.min(len - offset, 1 << 20)];
            f.readFully(b);
            out.write(b, 0, b.length);
            out.flush();
            return offset + b.length;
        }
    }

    /** The pid written by daemon -p (which removes it when the job ends); 0 if there is none. */
    static long pidOf(Run r) {
        try {
            String s = Files.readString(r.pid(), StandardCharsets.UTF_8).trim();
            return s.matches("[0-9]{1,10}") ? Long.parseLong(s) : 0;
        } catch (IOException e) {
            return 0;
        }
    }

    /** Alive: the pid is there, the process is there, and it is a reinstallation of the panel. */
    static boolean alive(Run r) {
        long pid = pidOf(r);
        if (pid <= 0) return false;
        return ProcessHandle.of(pid).filter(ProcessHandle::isAlive)
                .map(h -> h.info().commandLine().map(c -> c.contains("--reinstall")).orElse(true))
                .orElse(false);
    }

    /** The reinstallation in progress now, if there is one (the most recent). */
    static Run running() {
        try (var files = Files.list(dir)) {
            List<String> bases = files.map(p -> p.getFileName().toString())
                    .filter(n -> n.matches("reinstall-[0-9-]+\\.pid"))
                    .map(n -> n.substring(0, n.length() - ".pid".length()))
                    .sorted(java.util.Comparator.reverseOrder()).toList();
            for (String b : bases) {
                Run r = Run.named(b);
                if (!Files.exists(r.exit()) && alive(r)) return r;
            }
        } catch (IOException e) {
            // no folder: no reinstallation in progress
        }
        return null;
    }

    /**
     * The log of the last reinstallation that failed AFTER starting to change the system (that reached
     * phase 1): killed without an outcome, or outcome 1. "" if the last one went well, stopped before
     * changing anything, is still in progress, or there is none.
     */
    public static String lastFailedAfterChanges() {
        try (var files = Files.list(dir)) {
            String latest = files.map(p -> p.getFileName().toString())
                    .filter(n -> n.matches("reinstall-[0-9-]+\\.log"))
                    .map(n -> n.substring(0, n.length() - ".log".length()))
                    .sorted(java.util.Comparator.reverseOrder()).findFirst().orElse(null);
            if (latest == null) return "";
            Run r = Run.named(latest);
            if (alive(r)) return "";
            String exit = Files.exists(r.exit()) ? Files.readString(r.exit(), StandardCharsets.UTF_8).trim() : "";
            if ("0".equals(exit)) return "";
            String log = Files.readString(r.log(), StandardCharsets.UTF_8);
            return log.contains("[PHASE 1/10]") ? r.log().toString() : "";
        } catch (IOException e) {
            return "";
        }
    }

    /** At the end of the detached job (Main --reinstall): the outcome, written all or nothing. */
    public static void writeExit(Path exit, boolean ok) {
        try {
            Path tmp = exit.resolveSibling(exit.getFileName() + ".tmp");
            Files.writeString(tmp, ok ? "0\n" : "1\n", StandardCharsets.UTF_8);
            setPermissions(tmp, "rw-------");
            try {
                Files.move(tmp, exit, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(tmp, exit, StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException e) {
            LOGGER.warning("Cannot write the reinstallation result " + exit + ": " + e.getMessage());
        }
    }

    /** The last KEEP finished reinstallations are kept; never the files of one in progress. */
    static void prune() {
        try (var files = Files.list(dir)) {
            List<String> bases = files.map(p -> p.getFileName().toString())
                    .filter(n -> n.matches("reinstall-[0-9-]+\\.log"))
                    .map(n -> n.substring(0, n.length() - ".log".length()))
                    .sorted().toList();
            for (int i = 0; i < bases.size() - KEEP; i++) {
                Run r = Run.named(bases.get(i));
                if (alive(r)) continue;
                Files.deleteIfExists(r.log());
                Files.deleteIfExists(r.exit());
                Files.deleteIfExists(r.pid());
            }
        } catch (IOException e) {
            LOGGER.warning("Cannot prune the old reinstallation logs: " + e.getMessage());
        }
    }

    private static String java() {
        return ProcessHandle.current().info().command()
                .orElse(Path.of(System.getProperty("java.home"), "bin", "java").toString());
    }

    private static void setPermissions(Path p, String perms) {
        try {
            Files.setPosixFilePermissions(p, PosixFilePermissions.fromString(perms));
        } catch (IOException | UnsupportedOperationException ignored) {
            // file system without POSIX permissions
        }
    }
}
