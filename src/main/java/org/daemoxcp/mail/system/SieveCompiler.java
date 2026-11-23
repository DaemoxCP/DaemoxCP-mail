package org.daemoxcp.mail.system;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipalLookupService;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Pigeonhole's sievec without root (finding 218).
 *
 * <p>The panel's Sieve rules are in /var/mail/sieve/domain/name/.dovecot.sieve, owned by root on purpose (finding
 * 214): Dovecot, which delivers as vmail, reads them and cannot rewrite them. For the same reason it cannot save
 * their compiled file beside them, and without a compiled file it recompiles them for every message: the
 * Pigeonhole documentation (2.3 and 2.4) says that "before" scripts are precompiled by the administrator with
 * sievec. Until 2026-11-10 the panel launched sievec as root, and root parsed a text made of what an
 * administrator writes in the filters and in the automatic reply, which with the separated panel comes from
 * MySQL, where the web part also writes. sievec does not need root (the manual: "performed manually by an
 * authorized user"): root was needed only because the compiled file ends up in a root folder.
 *
 * <p>Now:
 * <ul>
 *   <li>sievec runs as the sievec user (PanelUser: no password, shell or home, a group of its own with nobody
 *       else in it), with an empty environment and a minimal configuration passed with -c. Dovecot's one contains
 *       secrets and no ordinary user reads it (measured: doveconf stops on auth-sql.conf.ext). The minimal one has
 *       only the two version lines that 2.4 requires, taken from dovecot.conf; for 2.3 it is empty. The extensions
 *       stay Pigeonhole's default ones, which are also those of the panel's configuration (in 2.3 its
 *       sieve_extensions line adds with + only extensions that are already default, in 2.4 it is not there).
 *       Measured on the VM: the compiled file is identical byte for byte to root's one with the real
 *       configuration, on 2.3.21 and on 2.4.5 (the latter in a clone of the boot environment, with the panel's 2.4
 *       configuration). In 2.4 -c /dev/null and the lines given with -o are not enough ("dovecot_storage_version
 *       setting must be set"): they are needed in the file; and doveconf, run by an ordinary user, writes a
 *       temporary file of its own in /tmp;</li>
 *   <li>not vmail: whoever delivers could then lay hands on the compiled file root installs, and so rewrite
 *       the panel's rules, exactly what finding 214 takes away from it;</li>
 *   <li>sievec compiles the script at its real path, because the compiled file carries it written inside
 *       ("location", and 2.4 compares it), and saves it in a folder of its own inside a root work folder that
 *       it cannot change;</li>
 *   <li>root does not open the compiled file: sievec itself reads it with cat, so a link to a file that sievec
 *       cannot read does not become a compiled file readable by everyone. Root writes it beside the script with
 *       the owner, group and permissions of the script, as root's sievec gave them when saving beside the
 *       script, and puts it in place with a rename, without following links and only if nobody else can change
 *       the folders from / to the script (RootOnlyPath, finding 221). The compiled file is created after the
 *       script, so it is newer, as Pigeonhole wants (it compares the times to the nanosecond, and if they are
 *       equal it recompiles);</li>
 *   <li>if the user cannot be obtained, if sievec does not read the script, or if it says 0 but the compiled
 *       file is not there (sievec exits 0 even when it fails to save it: measured), the compiled file is not
 *       installed: Dovecot recompiles at every delivery, slow but correct. Never root in its place.</li>
 * </ul>
 */
public final class SieveCompiler {

    private static final Logger LOGGER = Logger.getLogger(SieveCompiler.class.getName());

    /** The user and the group sievec runs as. */
    public static final String USER = "sievec";
    static final PanelUser COMPILER_USER = new PanelUser(USER, Product.NAME + " Sieve compiler");

    static final String CHROOT = "/usr/sbin/chroot";
    static final String CAT = "/bin/cat";
    static final String FIND = "/usr/bin/find";
    static final List<String> SIEVEC_PLACES = List.of("/usr/local/bin/sievec", "/usr/bin/sievec", "/usr/local/libexec/dovecot/sievec");
    static final Path DOVECOT_CONF = Path.of("/usr/local/etc/dovecot/dovecot.conf");
    /**
     * Where the work folder is created: /tmp, not java.io.tmpdir. sievec must be able to pass through it, and a
     * java.io.tmpdir moved with daemoxcp_mail_opts to a closed folder would stop every compilation without saying
     * why.
     */
    static final Path WORK_BASE = Path.of("/tmp");

    /**
     * In the work folder: the minimal configuration, the script to validate, sievec's folder and its compiled
     * file.
     */
    static final String CONF = "dovecot.conf";
    static final String TEXT = "script.sieve";
    static final String OUT = "out";
    static final String BINARY = "compiled.svbin";

    static final Duration TIMEOUT = Duration.ofSeconds(60);
    /** A bigger compiled file does not belong to the panel's rules (Pigeonhole rejects scripts over 1 MB). */
    static final int MAX_BINARY = 16 << 20;
    static final int MAX_TEXT = 64 << 10;

    private SieveCompiler() {}

    /**
     * COMPILED: done. REFUSED: the script has errors (sievec reports them line by line). NOT_COMPILED: it could
     * not be done.
     */
    /** UNCHANGED: compiled, and it was already equal to the one beside the script (SieveBinaries, finding 241). */
    public enum Status { COMPILED, UNCHANGED, REFUSED, NOT_COMPILED }

    /** The result, with sievec's text or the reason. */
    public record Outcome(Status status, String message) {
        public boolean refused() { return status == Status.REFUSED; }
    }

    private static Outcome notCompiled(String why) {
        return new Outcome(Status.NOT_COMPILED, why);
    }

    /** Where sievec is, or null if Pigeonhole is not installed. */
    public static String sievec() {
        for (String p : SIEVEC_PLACES) if (Files.isExecutable(Path.of(p))) return p;
        return null;
    }

    // ===================== Compiling and validating =====================

    /**
     * Compiles the script at its path and installs the compiled file beside it (name.sieve -> name.svbin), as
     * root's sievec would do, but with sievec running as {@link #USER}.
     */
    public static Outcome compile(Path script) {
        return compile(script, false, List.of());
    }

    /**
     * Like {@link #compile(Path)}, with sievec options before the script: for scripts that use extensions that
     * sievec does not load by itself, like the IMAPSieve ones (-P sieve_imapsieve -P sieve_extprograms
     * -x "+vnd.dovecot.pipe +imapsieve": SpamLearning). The options are panel constants, never text that comes
     * from outside.
     */
    public static Outcome compile(Path script, List<String> options) {
        return compile(script, false, options);
    }

    /** Like {@link #refresh(Path)}, with the options of {@link #compile(Path, List)}. */
    public static Outcome refresh(Path script, List<String> options) {
        return compile(script, true, options);
    }

    /**
     * Like {@link #compile(Path)}, but the compiled file beside the script is replaced only if it differs from
     * what the installed sievec makes now: UNCHANGED if it was already that (finding 241). The compiled file is
     * deterministic.
     */
    public static Outcome refresh(Path script) {
        return compile(script, true, List.of());
    }

    private static Outcome compile(Path script, boolean onlyIfDifferent, List<String> options) {
        String sievec = sievec();
        if (sievec == null) return notCompiled("sievec is not installed");
        Path s = script.toAbsolutePath().normalize();
        Path binary = binaryFor(s);
        if (binary == null) return notCompiled(s + " is not a .sieve script");
        PosixFileAttributes like;
        try {
            like = Files.readAttributes(s, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        } catch (IOException e) {
            return notCompiled("cannot read " + s + ": " + e.getMessage());
        }
        if (!like.isRegularFile()) return notCompiled(s + " is not a regular file");
        String folder = org.daemoxcp.mail.security.RootOnlyPath.problem(s.getParent());
        if (folder != null) return notCompiled(folder);
        String user = ensureUser();
        if (user != null) return notCompiled(user);

        Path work = null;
        try {
            work = workDir();
            Path compiled = work.resolve(OUT).resolve(BINARY);
            List<String> cmd = new ArrayList<>(List.of(sievec, "-c", work.resolve(CONF).toString()));
            cmd.addAll(options);
            cmd.addAll(List.of(s.toString(), compiled.toString()));
            Run c = run(asCompiler(cmd.toArray(new String[0])), MAX_TEXT, true);
            if (c.timedOut()) return notCompiled("sievec did not finish in " + TIMEOUT.toSeconds() + " s");
            if (c.exit() != 0) return failed(c.text());
            Run cat = run(asCompiler(CAT, compiled.toString()), MAX_BINARY, false);
            if (cat.exit() != 0 || cat.out().length == 0)
                return notCompiled("sievec saved no binary" + (c.text().isBlank() ? "" : ": " + c.text().strip()));
            // The folder belongs only to root (RootOnlyPath, above): root reads the existing compiled file without
            // following links.
            if (onlyIfDifferent && Files.isRegularFile(binary, LinkOption.NOFOLLOW_LINKS)
                    && Files.size(binary) == cat.out().length && java.util.Arrays.equals(Files.readAllBytes(binary), cat.out()))
                return new Outcome(Status.UNCHANGED, "");
            install(binary, cat.out(), like);
            return new Outcome(Status.COMPILED, c.text().strip());
        } catch (IOException e) {
            return notCompiled("compiling " + s + " failed: " + e.getMessage());
        } finally {
            if (work != null) cleanUp(work);
        }
    }

    /**
     * Checks a Sieve text without installing anything: sievec, as {@link #USER}, compiles it and throws away
     * the result.
     */
    public static Outcome validate(String text) {
        String sievec = sievec();
        if (sievec == null) return notCompiled("sievec is not installed");
        String user = ensureUser();
        if (user != null) return notCompiled(user);
        Path work = null;
        try {
            work = workDir();
            Path s = work.resolve(TEXT);
            Files.writeString(s, text, StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
            Files.setPosixFilePermissions(s, PosixFilePermissions.fromString("rw-r--r--"));
            // -d: instead of the compiled file, its dump; to /dev/null, that is nothing on disk.
            Run c = run(asCompiler(sievec, "-c", work.resolve(CONF).toString(), "-d", s.toString(), "/dev/null"), MAX_TEXT, true);
            if (c.timedOut()) return notCompiled("sievec did not finish in " + TIMEOUT.toSeconds() + " s");
            return c.exit() == 0 ? new Outcome(Status.COMPILED, c.text().strip()) : failed(c.text());
        } catch (IOException e) {
            return notCompiled("validating failed: " + e.getMessage());
        } finally {
            if (work != null) cleanUp(work);
        }
    }

    /**
     * An error at a line of the script ("name: line 2: error: ...") is a rejection; everything else is an
     * impediment.
     */
    private static final Pattern SCRIPT_ERROR = Pattern.compile(": line \\d+: error: ");

    static Outcome failed(String text) {
        String t = text.strip();
        return new Outcome(SCRIPT_ERROR.matcher(t).find() ? Status.REFUSED : Status.NOT_COMPILED, t.isEmpty() ? "sievec failed" : t);
    }

    // ===================== The pieces =====================

    /** name.sieve -> name.svbin in the same folder, as Pigeonhole looks for it; null if it is not a .sieve. Pure. */
    static Path binaryFor(Path script) {
        Path name = script.getFileName();
        if (name == null || script.getParent() == null) return null;
        String n = name.toString();
        if (!n.endsWith(".sieve") || n.length() == ".sieve".length()) return null;
        return script.resolveSibling(n.substring(0, n.length() - ".sieve".length()) + ".svbin");
    }

    /** The sievec user, created if missing; null if it exists and is the panel's one, otherwise the reason. */
    static String ensureUser() {
        PanelUser.Ensured e = COMPILER_USER.ensure();
        if (e.problem() != null) {
            LOGGER.warning("[SieveCompiler] Sieve scripts not precompiled (Dovecot compiles them at each delivery): " + e.problem());
            return e.problem();
        }
        if (e.created()) LOGGER.info("[SieveCompiler] DONE: user and group " + USER + " created (no password, no shell, home "
                + PanelUser.HOME + "): the panel's Sieve rules are compiled with it, not as root");
        return null;
    }

    /**
     * The minimal sievec configuration: for 2.4 the two version lines of dovecot.conf (2.4 does not start without
     * them, and they must be the first ones), for 2.3 nothing. Only digits and dots: anything else does not pass.
     * Pure.
     */
    static String minimalConfig(String dovecotConf) {
        if (dovecotConf == null) return "";
        String config = version(dovecotConf, "dovecot_config_version");
        if (config == null) return "";
        String storage = version(dovecotConf, "dovecot_storage_version");
        return "dovecot_config_version = " + config + "\n" + (storage == null ? "" : "dovecot_storage_version = " + storage + "\n");
    }

    private static String version(String conf, String key) {
        Matcher m = Pattern.compile("(?m)^[ \\t]*" + key + "[ \\t]*=[ \\t]*([0-9]{1,4}(?:\\.[0-9]{1,4}){1,3})[ \\t]*$").matcher(conf);
        return m.find() ? m.group(1) : null;
    }

    /**
     * The work folder: owned by root, 0711 (sievec passes through it but cannot list or change it), with the
     * minimal configuration owned by root 0644 and sievec's out folder, 0700, where it saves the compiled file.
     */
    static Path workDir() throws IOException {
        Path work = Files.createTempDirectory(WORK_BASE, "sievec-");
        boolean ready = false;
        try {
            Files.setPosixFilePermissions(work, PosixFilePermissions.fromString("rwx--x--x"));
            String conf = "";
            try {
                if (Files.isRegularFile(DOVECOT_CONF)) conf = minimalConfig(Files.readString(DOVECOT_CONF, StandardCharsets.UTF_8));
            } catch (IOException e) {
                LOGGER.warning("[SieveCompiler] cannot read " + DOVECOT_CONF + ": " + e.getMessage());
            }
            Path c = work.resolve(CONF);
            Files.writeString(c, conf, StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
            Files.setPosixFilePermissions(c, PosixFilePermissions.fromString("rw-r--r--"));
            Path out = Files.createDirectory(work.resolve(OUT), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
            PosixFileAttributeView v = Files.getFileAttributeView(out, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
            UserPrincipalLookupService names = out.getFileSystem().getUserPrincipalLookupService();
            v.setOwner(names.lookupPrincipalByName(USER));
            v.setGroup(names.lookupPrincipalByGroupName(USER));
            ready = true;
            return work;
        } finally {
            if (!ready) cleanUp(work);
        }
    }

    /**
     * The compiled file beside the script, with the owner, group and permissions of the script: a new file and
     * then a rename onto the real name, so that whoever delivers sees all or nothing, never following a link and
     * only if nobody else can change the folders from / down to there (RootOnlyPath, finding 221; before, only the
     * script's folder was checked).
     */
    static void install(Path binary, byte[] bytes, PosixFileAttributes like) throws IOException {
        org.daemoxcp.mail.security.RootOnlyPath.replace(binary.getParent(), binary.getFileName().toString(), bytes,
                like.owner(), like.group(), like.permissions());
    }

    /**
     * Remove the work folder. What is in sievec's folder is removed by sievec itself (find -delete does not
     * follow links): root does not descend into a folder that another user controls. Then root removes the empty
     * folder and its files; if sievec left something there, the folder stays and that is reported.
     */
    static void cleanUp(Path work) {
        Path out = work.resolve(OUT);
        try {
            if (Files.isDirectory(out, LinkOption.NOFOLLOW_LINKS)) {
                run(asCompiler(FIND, out.toString(), "-mindepth", "1", "-delete"), MAX_TEXT, true);
                Files.deleteIfExists(out);
            }
            Files.deleteIfExists(work.resolve(CONF));
            Files.deleteIfExists(work.resolve(TEXT));
            Files.deleteIfExists(work);
        } catch (IOException e) {
            LOGGER.warning("[SieveCompiler] left " + work + ": " + e.getMessage());
        }
    }

    /**
     * A command as sievec: chroot(8) with root /, without shell or PAM, and only the sievec group (-G: without
     * it, the command would keep root's additional groups, wheel and operator; measured for daemoxcp_mail on
     * 2026-11-07). Pure.
     */
    static List<String> asCompiler(String... cmd) {
        List<String> c = new ArrayList<>(List.of(CHROOT, "-u", USER, "-g", USER, "-G", USER, "/"));
        c.addAll(List.of(cmd));
        return c;
    }

    /** sievec's environment: nothing of root's, only this. */
    static final Map<String, String> ENVIRONMENT = Map.of("PATH", "/usr/bin:/bin:/usr/local/bin", "HOME", PanelUser.HOME,
            "USER", USER, "LOGNAME", USER);

    /** How a command went: exit code, what it wrote (up to a limit), whether the time ran out. */
    record Run(int exit, byte[] out, boolean timedOut) {
        String text() { return new String(out, StandardCharsets.UTF_8); }
    }

    /**
     * Launches the command with sievec's environment and standard input closed. With merge the error goes
     * together with the output (text for the administrator); without it, the output is the bytes of the compiled
     * file and the error is thrown away. Beyond limit bytes the output counts as failed.
     */
    static Run run(List<String> cmd, int limit, boolean merge) throws IOException {
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.environment().clear();
        pb.environment().putAll(ENVIRONMENT);
        pb.redirectInput(ProcessBuilder.Redirect.from(new File("/dev/null")));
        if (merge) pb.redirectErrorStream(true);
        else pb.redirectError(ProcessBuilder.Redirect.DISCARD);
        Process p = pb.start();
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        boolean[] tooMuch = {false};
        Thread reader = Thread.ofVirtual().start(() -> {
            try (InputStream in = p.getInputStream()) {
                byte[] b = new byte[8192];
                for (int n; (n = in.read(b)) > 0; ) {
                    if (buf.size() + n > limit) { tooMuch[0] = true; continue; }
                    buf.write(b, 0, n);
                }
            } catch (IOException ignored) {
                // the process has finished or has been stopped
            }
        });
        try {
            if (!p.waitFor(TIMEOUT.toMillis(), TimeUnit.MILLISECONDS)) {
                p.destroyForcibly();
                p.waitFor(5, TimeUnit.SECONDS);
                reader.join(Duration.ofSeconds(5));
                return new Run(-1, buf.toByteArray(), true);
            }
            reader.join(Duration.ofSeconds(5));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            p.destroyForcibly();
            return new Run(-1, buf.toByteArray(), true);
        }
        return new Run(tooMuch[0] ? -2 : p.exitValue(), buf.toByteArray(), false);
    }
}
