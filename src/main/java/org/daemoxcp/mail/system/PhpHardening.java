package org.daemoxcp.mail.system;

import org.daemoxcp.mail.util.Shell;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;
import java.util.regex.Pattern;

/**
 * PHP as the installer writes it, on the servers installed earlier too (finding 238).
 *
 * <p>The php84 package does not install a php.ini: there are only the samples php.ini-production and
 * php.ini-development. The production server had been installed before the installer wrote it, and, measured
 * read-only on 2026-11-16, PHP was running on the values compiled in: "Loaded Configuration File => (none)",
 * expose_php On (the PHP version in every webmail response, "X-Powered-By: PHP/8.4..."), display_errors on the
 * output, sessions in /tmp, no time zone. Here, if it is missing, {@link #INI} is written, the same text as the
 * installer's (which takes it from here), with the sessions folder, the error log and its rotation.
 *
 * <p>In addition, two lines that the PHP guide recommends for a production server:
 * session.upload_progress.enabled = Off (Roundcube does not use it, and it writes into the session file a name
 * chosen by whoever uploads) and, in the Roundcube pool, security.limit_extensions = .php: the php-fpm default is
 * ".php .phar", and the webmail runs only .php.
 *
 * <p>Afterwards: php-fpm -t, the reload, and the webmail login page answering on every nginx site that serves it;
 * if php.ini was missing, with no X-Powered-By any more (the proof that php-fpm really reads the file). An error
 * puts everything back as it was. A php.ini that exists is not touched: it belongs to the installer or to the
 * administrator; the pool is touched only if the panel wrote it.
 */
public final class PhpHardening {

    private static final Logger LOGGER = Logger.getLogger(PhpHardening.class.getName());

    private PhpHardening() {}

    public static final Path PHP_INI = Path.of("/usr/local/etc/php.ini");
    static final Path POOL = Path.of(RoundcubeUser.FPM_DIR, RoundcubeUser.POOL + ".conf");
    static final Path ROTATION = Path.of(RoundcubeUser.NEWSYSLOG_DIR, "php-errors.conf");

    /** The panel's php.ini: the installer writes it from here, and the repair takes it from here. */
    public static final String INI = """
            [PHP]
            engine = On
            short_open_tag = Off
            output_buffering = 4096
            zend.enable_gc = On
            zend.exception_ignore_args = On
            ; r19: neither PHP's version in the headers nor an error in front of whoever passes by.
            expose_php = Off
            display_errors = Off
            display_startup_errors = Off
            log_errors = On
            error_log = /var/log/php_errors.log
            error_reporting = E_ALL & ~E_DEPRECATED
            ignore_repeated_errors = Off
            max_execution_time = 300
            max_input_time = 300
            memory_limit = 256M
            variables_order = "GPCS"
            request_order = "GP"
            register_argc_argv = Off
            auto_globals_jit = On
            default_mimetype = "text/html"
            default_charset = "UTF-8"
            enable_dl = Off
            file_uploads = On
            upload_max_filesize = 50M
            post_max_size = 56M
            max_file_uploads = 20
            allow_url_fopen = On
            allow_url_include = Off
            default_socket_timeout = 60

            [Date]
            ; UTC, not the administrator's time zone: what is stored is always UTC, and the
            ; conversion is done by whoever shows it (r13). Roundcube converts to the user's zone itself.
            ; Without this line PHP has no time zone and says so at every date function.
            date.timezone = UTC

            [Session]
            session.save_handler = files
            ; NOT /tmp, which is the default: there Roundcube's session files would be
            ; readable by any local user. The script creates this folder, 700 and owned by roundcube.
            session.save_path = "/var/db/daemoxcp-mail/php_sessions"
            session.use_strict_mode = 1
            ; No upload progress in the session: Roundcube does not use it, and it is data chosen by whoever
            ; uploads, written into the session file (finding 238).
            session.upload_progress.enabled = Off
            session.use_cookies = 1
            session.use_only_cookies = 1
            session.cookie_lifetime = 0
            session.cookie_path = /
            session.cookie_httponly = 1
            session.cookie_secure = 1
            session.cookie_samesite = "Lax"
            session.gc_probability = 1
            session.gc_divisor = 1000
            session.gc_maxlifetime = 3600
            session.cache_limiter = nocache
            session.sid_length = 32

            [opcache]
            opcache.enable = 1
            opcache.enable_cli = 0
            opcache.memory_consumption = 128
            opcache.interned_strings_buffer = 8
            opcache.max_accelerated_files = 10000
            opcache.revalidate_freq = 2
            opcache.validate_timestamps = 1
            """;

    static final String LIMIT_COMMENT = "; Only .php: php-fpm's default is \".php .phar\" (finding 238).\n";
    public static final String LIMIT = "security.limit_extensions = .php\n";
    private static final Pattern HAS_LIMIT = Pattern.compile("(?m)^\\s*security\\.limit_extensions\\s*=");

    static boolean hasLimit(String pool) {
        return HAS_LIMIT.matcher(pool).find();
    }

    /** The pool with the line at the end (there is only one section, [roundcube]). Pure. */
    static String withLimit(String pool) {
        return pool + (pool.endsWith("\n") ? "" : "\n") + LIMIT_COMMENT + LIMIT;
    }

    /** An nginx site that serves the webmail. */
    record Site(String name, String port) {}

    /** What is needed, so that it can be tested without PHP, php-fpm and nginx. */
    interface Services {
        /** The file, or null if it is not there. */
        String read(Path file) throws IOException;
        /** A new file, root:wheel 0644. */
        void create(Path file, String text) throws IOException;
        /** In place of the file, with the previous owner and permissions. */
        void write(Path file, String text) throws IOException;
        void delete(Path file) throws IOException;
        /** The sessions folder and the error log, if missing, owned by the Roundcube user. */
        void prepare() throws IOException;
        boolean fpmTest();
        void fpmReload();
        List<Site> sites();
        /** Headers and page of the webmail, or null if it does not answer with the login page. */
        String webmail(Site site);
        /** A pause between one check and the next (in the test it does not wait). */
        void pause();
    }

    public enum Outcome { NOTHING, DONE, LEFT, ROLLED_BACK, INCOMPLETE }

    public record Result(Outcome outcome, String detail) {}

    static boolean poweredBy(String page) {
        return Pattern.compile("(?im)^x-powered-by:").matcher(page).find();
    }

    /** The switchover, pure with respect to {@link Services}. */
    static Result run(Services sv, Path ini, Path pool, Path rotation, int waitSeconds) {
        String i, p, rot;
        try {
            i = sv.read(ini);
            p = sv.read(pool);
            rot = sv.read(rotation);
        } catch (IOException e) {
            return new Result(Outcome.LEFT, "php.ini or the pool cannot be read: " + e.getClass().getSimpleName());
        }
        boolean needIni = i == null;
        boolean needPool = p != null && PanelMarker.writtenByPanel(p) && !hasLimit(p);
        if (!needIni && !needPool) return new Result(Outcome.NOTHING, "");
        List<Site> sites = sv.sites();
        if (sites.isEmpty()) return new Result(Outcome.LEFT, "no nginx site serves the webmail: nothing changed");
        for (Site s : sites)
            if (sv.webmail(s) == null)
                return new Result(Outcome.LEFT, "the webmail does not answer now on " + s.name() + ":" + s.port() + ": nothing changed");

        boolean rotationNew = false, poolWritten = false;
        try {
            if (needIni) {
                sv.prepare();
                sv.create(ini, INI);
                if (rot == null) {
                    rotationNew = true;
                    sv.create(rotation, "# PHP's error log (written by " + Product.NAME + ", finding 238)\n"
                            + RoundcubeUser.phpErrorsRotationLine() + "\n");
                }
            }
            if (needPool) {
                poolWritten = true;
                sv.write(pool, withLimit(p));
            }
        } catch (IOException e) {
            return back(sv, needIni, ini, pool, poolWritten ? p : null, rotationNew ? rotation : null, "a file could not be written: "
                    + e.getClass().getSimpleName());
        }
        if (!sv.fpmTest()) return back(sv, needIni, ini, pool, needPool ? p : null, rotationNew ? rotation : null, "php-fpm -t refuses it");
        sv.fpmReload();
        String why = null;
        for (int t = 0; t <= waitSeconds; t++) {
            why = null;
            for (Site s : sites) {
                String page = sv.webmail(s);
                if (page == null) why = "the webmail does not answer on " + s.name() + ":" + s.port() + " after the reload";
                else if (needIni && poweredBy(page)) why = "php-fpm still sends X-Powered-By: it did not read " + ini;
                if (why != null) break;
            }
            if (why == null) break;
            sv.pause();
        }
        if (why != null) return back(sv, needIni, ini, pool, needPool ? p : null, rotationNew ? rotation : null, why);
        List<String> done = new ArrayList<>();
        if (needIni) done.add(ini + " written (it was missing: PHP ran on its built-in defaults), X-Powered-By gone");
        if (needPool) done.add("security.limit_extensions = .php in the pool " + RoundcubeUser.POOL);
        return new Result(Outcome.DONE, String.join("; ", done) + "; the webmail answers");
    }

    private static Result back(Services sv, boolean createdIni, Path ini, Path pool, String poolBefore, Path rotation, String why) {
        boolean ok = true;
        try {
            if (createdIni) sv.delete(ini);
            if (rotation != null) sv.delete(rotation);
            if (poolBefore != null) sv.write(pool, poolBefore);
        } catch (IOException e) {
            ok = false;
        }
        sv.fpmReload();
        return new Result(ok ? Outcome.ROLLED_BACK : Outcome.INCOMPLETE,
                why + (ok ? ": everything as it was" : "; and putting the files back failed"));
    }

    // ===================== The production server =====================

    static Services real() {
        return new Services() {
            @Override public String read(Path file) throws IOException {
                return Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS) ? Files.readString(file, StandardCharsets.UTF_8) : null;
            }
            @Override public void create(Path file, String text) throws IOException {
                RoundcubeDbUser.write(file, text, new RoundcubeDbUser.FileState(file, text, "root", "wheel",
                        PosixFilePermissions.fromString("rw-r--r--")));
            }
            @Override public void write(Path file, String text) throws IOException {
                RoundcubeDbUser.write(file, text, RoundcubeDbUser.FileState.of(file, Files.readString(file, StandardCharsets.UTF_8)));
            }
            @Override public void delete(Path file) throws IOException {
                Files.deleteIfExists(file);
            }
            @Override public void prepare() throws IOException {
                String owner = RoundcubeUser.runtimeUser() + ":" + RoundcubeUser.runtimeGroup();
                Path sessions = Path.of(RoundcubeUser.SESSIONS_DIR), log = Path.of(RoundcubeUser.PHP_ERRORS_LOG);
                if (!Files.isDirectory(sessions, LinkOption.NOFOLLOW_LINKS)) {
                    Files.createDirectories(sessions);
                    Shell.run(Duration.ofSeconds(10), "chmod", "700", sessions.toString());
                    Shell.run(Duration.ofSeconds(10), "chown", owner, sessions.toString());
                }
                if (!Files.exists(log, LinkOption.NOFOLLOW_LINKS)) {
                    Files.createFile(log, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-r-----")));
                    // The permissions asked of createFile go through the panel's umask (077 when
                    // upgrade-panel.sh starts it): on the production server the log was created 0600,
                    // and RoundcubeUser was putting it right.
                    Shell.run(Duration.ofSeconds(10), "chmod", "640", log.toString());
                    Shell.run(Duration.ofSeconds(10), "chown", owner, log.toString());
                }
            }
            @Override public boolean fpmTest() {
                return Shell.run(Duration.ofSeconds(30), "php-fpm", "-t").success();
            }
            @Override public void fpmReload() {
                Shell.run(Duration.ofSeconds(60), "service", "php_fpm", "onereload");
            }
            @Override public List<Site> sites() {
                Shell.Result r = Shell.run(Duration.ofSeconds(20), "nginx", "-T");
                if (!r.success()) return List.of();
                List<Site> out = new ArrayList<>();
                for (RoundcubeDbUser.Site s : RoundcubeDbUser.webmailSites(r.output(), Path.of(RoundcubeUser.ROUNDCUBE_DIR)))
                    out.add(new Site(s.name(), s.port()));
                return out;
            }
            @Override public String webmail(Site s) {
                if (!s.name().matches("[A-Za-z0-9.-]+") || !s.port().matches("[0-9]+")) return null;
                Shell.Result r = Shell.run(Duration.ofSeconds(20), "curl", "-sk", "-i", "-m", "15", "--resolve",
                        s.name() + ":" + s.port() + ":127.0.0.1", "https://" + s.name() + ":" + s.port() + "/");
                return r.success() && r.output().contains("rcmloginuser") ? r.output() : null;
            }
            @Override public void pause() {
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        };
    }

    /** At root part startup, before RoundcubeUser (which re-applies the owners of the folder and of the log). */
    public static void ensureAtBoot() {
        try {
            if (!Files.isDirectory(Path.of(RoundcubeUser.ROUNDCUBE_DIR))) return;
            Result r = run(real(), PHP_INI, POOL, ROTATION, 30);
            switch (r.outcome()) {
                case NOTHING -> { }
                case DONE -> LOGGER.info("[PhpHardening] DONE: " + r.detail());
                case LEFT -> LOGGER.info("[PhpHardening] left as it is: " + r.detail());
                default -> LOGGER.warning("[PhpHardening] " + r.outcome() + ": " + r.detail());
            }
        } catch (Throwable t) {
            LOGGER.warning("[PhpHardening] failed: " + t.getClass().getName());
        }
    }
}
