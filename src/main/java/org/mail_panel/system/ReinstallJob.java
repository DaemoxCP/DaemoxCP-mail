package org.mail_panel.system;

import org.mail_panel.i18n.I18n;

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
 * La reinstallazione completa dal menu gira staccata dal menu: un processo suo, in una sessione sua
 * (daemon(8)), che scrive in un registro; il menu lo segue e basta.
 *
 * <p>Perche' esiste: misurato sulla VM FreeBSD 15.1 il 06/11/2026 (reperto 163). Lo script girava
 * come figlio della JVM del menu, nel suo stesso gruppo di processi.
 * <ul>
 *   <li>Chiuso l'ssh durante la fase 2 (il terminale riceve SIGHUP): morti insieme menu, script e
 *       pkg. Posta spenta, configurazioni di Postfix gia' cancellate, i 39 pacchetti sbloccati con
 *       l'elenco su disco, e il servizio acceso non se ne accorgeva fino al suo prossimo avvio.</li>
 *   <li>La JVM del menu uccisa con kill -9: lo script orfano andava avanti ~16 secondi (installava
 *       Roundcube e PHP) e moriva alla prima riga scritta sul tubo che nessuno leggeva piu', in un
 *       punto a caso.</li>
 * </ul>
 * Adesso il menu lancia {@code Main --reinstall <nome> <file d'esito>} con daemon(8): sessione
 * nuova, nessun terminale, l'uscita in un file. Se il menu muore (ssh caduto, Ctrl-C, kill) il
 * lavoro va avanti, riprotegge i pacchetti, decide la password e la via di ritorno, e scrive
 * l'esito. Riaprendo il menu durante una reinstallazione, il menu segue quella in corso invece di
 * partirne un'altra.
 *
 * <p>Il registro sta in /var/log/mailpanel, fuori dal boot environment: resta anche dopo essere
 * tornati indietro con la via di ritorno, che e' proprio quando serve leggerlo.
 */
public final class ReinstallJob {

    private static final Logger LOGGER = Logger.getLogger(ReinstallJob.class.getName());

    private ReinstallJob() {}

    /** La cartella dei registri. Le prove la spostano con -Dmailpanel.reinstall.dir. */
    static Path dir = Path.of(System.getProperty("mailpanel.reinstall.dir", "/var/log/mailpanel"));

    /** daemon(8) della base di FreeBSD. */
    static String daemon = "/usr/sbin/daemon";

    /** Quante reinstallazioni passate si tengono (registro ed esito). */
    static final int KEEP = 10;

    private static final DateTimeFormatter STAMP =
            DateTimeFormatter.ofPattern("yyyy-MM-dd-HHmmss").withZone(ZoneOffset.UTC);

    /** Una reinstallazione: il registro, il file col pid (di daemon -p) e quello dell'esito. */
    public record Run(Path log, Path pid, Path exit) {
        static Run named(String base) {
            return new Run(dir.resolve(base + ".log"), dir.resolve(base + ".pid"), dir.resolve(base + ".exit"));
        }
    }

    /** Un nome di server di posta accettabile: lettere, cifre, trattini e punti, come un nome DNS. */
    public static boolean validHostname(String h) {
        return h != null && h.length() <= 253
                && h.matches("[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*");
    }

    /**
     * Dalla voce del menu: lancia la reinstallazione staccata (o ritrova quella in corso) e ne segue
     * il registro fino alla fine. Vero se e' riuscita. Senza daemon(8) (non FreeBSD) la fa qui, come
     * prima, e lo dice.
     */
    public static boolean runFromMenu(String host, PrintStream out) {
        I18n.setCurrent("en");     // la console e' in inglese
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
                return org.mail_panel.Main.runInstallation(host);
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

    /** Lancia il lavoro con daemon(8) e aspetta che abbia scritto il suo pid. */
    static Run launch(String host) throws IOException, InterruptedException {
        Files.createDirectories(dir);
        setPermissions(dir, "rwx------");
        prune();
        Run r = Run.named("reinstall-" + STAMP.format(Instant.now()));
        if (Files.exists(r.log())) throw new IOException("a reinstallation started in this same second: " + r.log());
        Files.createFile(r.log());
        setPermissions(r.log(), "rw-------");

        List<String> cmd = new ArrayList<>(List.of(daemon, "-f", "-o", r.log().toString(),
                "-p", r.pid().toString(), "-t", "mailpanel-reinstall", java()));
        // Le impostazioni del pannello (cartella dei segreti, dei registri) valgono anche per lui.
        for (String k : System.getProperties().stringPropertyNames())
            if (k.startsWith("mailpanel.")) cmd.add("-D" + k + "=" + System.getProperty(k));
        cmd.addAll(List.of("-cp", System.getProperty("java.class.path"), "org.mail_panel.Main",
                "--reinstall", host, r.exit().toString()));
        ProcessBuilder pb = new ProcessBuilder(cmd).directory(new File(System.getProperty("user.dir")));
        org.mail_panel.util.Shell.applyPath(pb);
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
     * Segue il registro dall'inizio fino all'esito. Vero se l'esito e' 0. Se il lavoro sparisce
     * senza esito (ucciso), lo dice e torna falso.
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

    /** Il pid scritto da daemon -p (che lo toglie quando il lavoro finisce); 0 se non c'e'. */
    static long pidOf(Run r) {
        try {
            String s = Files.readString(r.pid(), StandardCharsets.UTF_8).trim();
            return s.matches("[0-9]{1,10}") ? Long.parseLong(s) : 0;
        } catch (IOException e) {
            return 0;
        }
    }

    /** Vivo: il pid c'e', il processo c'e', ed e' una reinstallazione del pannello. */
    static boolean alive(Run r) {
        long pid = pidOf(r);
        if (pid <= 0) return false;
        return ProcessHandle.of(pid).filter(ProcessHandle::isAlive)
                .map(h -> h.info().commandLine().map(c -> c.contains("--reinstall")).orElse(true))
                .orElse(false);
    }

    /** La reinstallazione in corso adesso, se ce n'e' una (la piu' recente). */
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
            // nessuna cartella: nessuna reinstallazione in corso
        }
        return null;
    }

    /** Alla fine del lavoro staccato (Main --reinstall): l'esito, scritto tutto o niente. */
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

    /** Si tengono le ultime KEEP reinstallazioni finite; mai i file di una in corso. */
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
            // file system senza permessi POSIX
        }
    }
}
