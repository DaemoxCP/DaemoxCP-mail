package org.daemoxcp.mail.system;

import org.json.JSONArray;
import org.daemoxcp.mail.i18n.I18n;
import org.json.JSONObject;
import org.daemoxcp.mail.util.Shell;

import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The versions of the mail server's software, read from the server on every request: the Version column
 * of "Mail services" and the "Other software" table on the Home page.
 *
 * Each program is asked for what it is, and as close as possible to what is running:
 *  - MySQL with SELECT VERSION() on the panel's connection: the running server answers;
 *  - ClamAV by asking the clamd daemon for VERSION on its socket: the engine and signatures it uses now;
 *  - Java from the panel's own process, the kernel with freebsd-version -r;
 *  - the others from their own binary (postconf -h mail_version, dovecot --version, nginx -v...).
 *
 * The package is found with "pkg which" on the binary, not by name: the panel installs
 * postfix-mysql and dovecot-mysql, and "pkg query %v postfix" on those servers finds nothing (the
 * same stumble is described in DovecotConfig).
 *
 * Is the previous version still running? For MySQL, ClamAV and Java the answer of the process is
 * compared with the installed package; for the kernel, freebsd-version -k with -r. For the other
 * daemons the start time of the process (from its pidfile) is compared with the installation time of
 * the package (pkg query %t): if it started before, it is running the previous code. When one of the
 * two times is missing nothing is said: no indication is better than a wrong one. For the same reason
 * PHP-FPM is not checked this way: its reload relaunches the new binary in the same process, which
 * keeps its start time, and after a reload the warning would be false.
 */
public final class SoftwareVersions {

    private SoftwareVersions() {}

    /** The system to query: the real one of the server, or a fake one in tests. */
    public interface SystemAccess {
        /** Command output (stdout and stderr) even if it exits with an error; null if it fails to start or times out. */
        String run(String... argv);
        boolean exists(String path);
        /** A small file, or null if it is missing or too large. */
        String read(String path);
        /** The answer of clamd to VERSION on its socket, or null if it does not answer. */
        String askClamd2();
        /** SELECT VERSION() on the panel's connection, or null. */
        String mysqlVersion();
        /** When the process started, or null if there is no process or it is not known. */
        Instant startup(long pid);
        /** Runtime.version() of the Java that runs the panel. */
        String javaVersion();
        /** java.home of the Java that runs the panel. */
        String javaFolder();
        Instant now();
        ZoneId zone();
    }

    /** ClamAV signatures older than this are a warning: the same threshold as the ClamAV check (Security). */
    static final int SIGNATURE_DAYS = 7;
    static final String PKG = "/usr/local/sbin/pkg";
    static final String SOCKET_CLAMD = "/var/run/clamav/clamd.sock";
    static final String CLAMD = "/usr/local/sbin/clamd";
    static final String MYSQLD = "/usr/local/libexec/mysqld";
    static final String ROUNDCUBE = "/usr/local/www/roundcube";
    static final String FREEBSD_VERSION = "/bin/freebsd-version";
    static final String OPENSSL_BASE = "/usr/bin/openssl";
    static final String OPENSSL_PKG = "/usr/local/bin/openssl";

    /** A version: printable characters only, without spaces, as the programs and pkg write them. */
    private static final Pattern VALID_VERSION = Pattern.compile("[0-9A-Za-z.+_,:~-]{1,40}");
    private static final Pattern VALID_PATH = Pattern.compile("/[0-9A-Za-z._/+-]{1,200}");
    private static final String V = "(\\d[0-9A-Za-z.+_~-]*)";
    private static final DateTimeFormatter DATE_TIME = DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm");
    /** Always with the seconds: toString() omits them when they are zero, and the page cuts them by position. */
    private static final DateTimeFormatter INSTANT = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ssXXX");

    /**
     * A program read from its binary: where it is, how it is asked for its version (null: only from the
     * package), how the version is recognised in the answer and, for daemons, where it writes its pid.
     */
    record Entry(String key, String name, String role, String binary, String[] command, Pattern version, String pidfile) {}

    private static Pattern line(String re) { return Pattern.compile(re, Pattern.MULTILINE); }

    static final Entry POSTFIX = new Entry("postfix", "Postfix", "server.ver.role.postfix", "/usr/local/sbin/postconf",
            new String[]{"/usr/local/sbin/postconf", "-h", "mail_version"}, line("^" + V), "/var/spool/postfix/pid/master.pid");
    static final Entry DOVECOT = new Entry("dovecot", "Dovecot", "server.ver.role.dovecot", "/usr/local/sbin/dovecot",
            new String[]{"/usr/local/sbin/dovecot", "--version"}, line("^" + V), "/var/run/dovecot/master.pid");
    static final Entry RSPAMD = new Entry("rspamd", "Rspamd", "server.ver.role.rspamd", "/usr/local/bin/rspamd",
            new String[]{"/usr/local/bin/rspamd", "--version"}, line("[Vv]ersion\\s+" + V), "/var/run/rspamd/rspamd.pid");
    static final Entry REDIS = new Entry("redis", "Redis", "server.ver.role.redis", "/usr/local/bin/redis-server",
            new String[]{"/usr/local/bin/redis-server", "--version"}, line("\\bv=" + V), "/var/run/redis/redis.pid");
    static final Entry NGINX = new Entry("nginx", "nginx", "server.ver.role.nginx",
            "/usr/local/sbin/nginx", new String[]{"/usr/local/sbin/nginx", "-v"}, line("nginx/" + V), "/var/run/nginx.pid");
    static final Entry PHP = new Entry("php", "PHP-FPM", "server.ver.role.php", "/usr/local/sbin/php-fpm",
            new String[]{"/usr/local/sbin/php-fpm", "-v"}, line("^PHP " + V), null);
    static final Entry PIGEONHOLE = new Entry("pigeonhole", "Pigeonhole", "server.ver.role.pigeonhole",
            "/usr/local/bin/sievec", null, null, null);
    static final Entry FAIL2BAN = new Entry("fail2ban", "fail2ban", "server.ver.role.fail2ban",
            "/usr/local/bin/fail2ban-client", null, null, "/var/run/fail2ban/fail2ban.pid");
    static final Entry UNBOUND = new Entry("unbound", "Unbound", "server.ver.role.unbound",
            "/usr/local/sbin/unbound", new String[]{"/usr/local/sbin/unbound", "-V"}, line("^Version " + V), null);
    /** The base system one is present on every FreeBSD: it is shown only if it runs (that is what the pidfile is for). */
    static final Entry LOCAL_UNBOUND = new Entry("local_unbound", "server.ver.name.localUnbound", "server.ver.role.unbound",
            "/usr/sbin/local-unbound", new String[]{"/usr/sbin/local-unbound", "-V"}, line("^Version " + V), null);
    static final String PIDFILE_LOCAL_UNBOUND = "/var/run/local_unbound.pid";

    /** The versions of everything: "services" for the Mail services rows, "other" for the rest. */
    public static JSONObject read(SystemAccess s) {
        String javaBin = javaBin(s);
        List<String> binaries = new ArrayList<>();
        for (String b : new String[]{POSTFIX.binary(), DOVECOT.binary(), RSPAMD.binary(), REDIS.binary(), CLAMD, MYSQLD,
                ROUNDCUBE + "/index.php", NGINX.binary(), PHP.binary(), PIGEONHOLE.binary(), FAIL2BAN.binary(),
                UNBOUND.binary(), LOCAL_UNBOUND.binary(), OPENSSL_PKG, javaBin}) {
            if (b != null && s.exists(b)) binaries.add(b);
        }
        // Who owns each binary and when it was installed: two calls to pkg for all of them.
        Map<String, String> packageOf = new HashMap<>();
        Map<String, Long> installedOn = new HashMap<>();
        if (s.exists(PKG) && !binaries.isEmpty()) {
            List<String> argv = new ArrayList<>(List.of(PKG, "which"));
            argv.addAll(binaries);
            packageOf = owners(s.run(argv.toArray(String[]::new)));
            installedOn = installs(s.run(PKG, "query", "%n %t"));
        }
        Reading l = new Reading(s, packageOf, installedOn);

        JSONObject services = new JSONObject()
                .put("postfix", l.fromBinary(POSTFIX))
                .put("dovecot", l.fromBinary(DOVECOT))
                .put("mysql", l.mysql())
                .put("rspamd", l.fromBinary(RSPAMD))
                .put("redis", l.fromBinary(REDIS))
                .put("clamav", l.clamav())
                .put("roundcube", l.roundcube());

        JSONArray other = new JSONArray();
        other.put(l.freebsd());
        other.put(l.openssl(OPENSSL_BASE, "openssl", "OpenSSL", "server.ver.role.openssl"));
        if (s.exists(OPENSSL_PKG))
            other.put(l.openssl(OPENSSL_PKG, "openssl_pkg", "server.ver.name.opensslPkg", "server.ver.role.opensslPkg"));
        other.put(l.fromBinary(NGINX));
        other.put(l.fromBinary(PHP));
        other.put(l.fromBinary(PIGEONHOLE));
        other.put(l.java(javaBin));
        if (s.exists(FAIL2BAN.binary())) other.put(l.fromBinary(FAIL2BAN));
        if (s.exists(UNBOUND.binary())) other.put(l.fromBinary(UNBOUND));
        if (s.exists(LOCAL_UNBOUND.binary()) && l.alive(PIDFILE_LOCAL_UNBOUND)) other.put(l.fromBinary(LOCAL_UNBOUND));

        return new JSONObject().put("success", true).put("services", services).put("other", other)
                .put("readAt", s.now().atZone(s.zone()).format(INSTANT));
    }

    /** The binary of the Java that runs the panel, if its path is one of those expected. */
    private static String javaBin(SystemAccess s) {
        String home = s.javaFolder();
        if (home == null || !VALID_PATH.matcher(home).matches() || home.contains("..")) return null;
        return home + "/bin/java";
    }

    /** What one request reads: the system, and what pkg said about the packages. */
    private record Reading(SystemAccess s, Map<String, String> packageOf, Map<String, Long> installedOn) {

        String pkgName(String binary) { return binary == null ? "" : packageOf.getOrDefault(binary, ""); }

        /** Version from the binary, or from the package if the binary does not answer; for daemons, the start time. */
        JSONObject fromBinary(Entry v) {
            JSONObject r = entry(v.key(), v.name(), v.role());
            if (!s.exists(v.binary())) return r;
            r.put("installed", true);
            String pkg = pkgName(v.binary());
            if (!pkg.isEmpty()) r.put("pkgName", pkg);
            String ver = v.command() == null ? null : extract(v.version(), s.run(v.command()));
            if (ver != null) r.put("version", ver).put("source", String.join(" ", v.command()));
            else if (!pkg.isEmpty()) r.put("version", upstream(pkg)).put("source", "pkg which " + v.binary());
            if (v.pidfile() != null && !pkg.isEmpty()) startupAndInstall(r, v.pidfile(), name(pkg), I18n.tr(v.name()));
            return r;
        }

        /** The process started before its package was installed: it is running the previous version. */
        void startupAndInstall(JSONObject r, String pidfile, String packageName, String who) {
            Long pid = pid(s.read(pidfile));
            Instant startup = pid == null ? null : s.startup(pid);
            Long installed = installedOn.get(packageName);
            if (startup == null || installed == null) return;
            if (startup.getEpochSecond() < installed) {
                r.put("restart", true).put("restartNote", I18n.tr("server.ver.startedBefore", java.util.Map.of("who", String.valueOf(who), "start", String.valueOf(data(startup)), "inst", String.valueOf(data(Instant.ofEpochSecond(installed))))));
            }
        }

        boolean alive(String pidfile) {
            Long pid = pid(s.read(pidfile));
            return pid != null && s.startup(pid) != null;
        }

        /** The process answers with a version different from the package's: it must be restarted. */
        void compare(JSONObject r, String running, String installed, String who, String remedy) {
            String a = numbers(running), b = numbers(installed);
            if (a.isEmpty() || b.isEmpty() || a.equals(b)) return;
            r.put("restart", true).put("installedVersion", installed)
             .put("restartNote", I18n.tr("server.ver.runningVsInstalled", java.util.Map.of("who", String.valueOf(who), "run", String.valueOf(running), "inst", String.valueOf(installed), "fix", String.valueOf(remedy))));
        }

        JSONObject mysql() {
            JSONObject r = entry("mysql", "MySQL", "server.ver.role.mysql");
            String pkg = pkgName(MYSQLD);
            String alive = validate(s.mysqlVersion());
            if (alive == null && !s.exists(MYSQLD)) return r;
            r.put("installed", true);
            if (!pkg.isEmpty()) r.put("pkgName", pkg);
            if (alive != null) {
                r.put("version", alive).put("source", I18n.tr("server.ver.srcMysql")).put("running", true);
                if (!pkg.isEmpty()) compare(r, alive, upstream(pkg), "MySQL", I18n.tr("server.ver.fixMysql"));
                return r;
            }
            String ver = extract(line("\\bVer\\s+" + V), s.run(MYSQLD, "--version"));
            if (ver != null) r.put("version", ver).put("source", MYSQLD + " --version");
            else if (!pkg.isEmpty()) r.put("version", upstream(pkg)).put("source", "pkg which " + MYSQLD);
            return r.put("warning", I18n.tr("server.ver.mysqlDown"));
        }

        JSONObject clamav() {
            JSONObject r = entry("clamav", "ClamAV", "server.ver.role.clamav");
            if (!s.exists(CLAMD)) return r;
            r.put("installed", true);
            String pkg = pkgName(CLAMD);
            if (!pkg.isEmpty()) r.put("pkgName", pkg);
            Clamd c = clamd(s.askClamd2(), s.zone());
            boolean fromDaemon = c != null;
            if (!fromDaemon) c = clamd(s.run(CLAMD, "--version"), s.zone());
            if (c == null) {
                if (!pkg.isEmpty()) r.put("version", upstream(pkg)).put("source", "pkg which " + CLAMD);
                return r;
            }
            r.put("version", c.engine()).put("source", fromDaemon ? I18n.tr("server.ver.srcClamd", java.util.Map.of("sock", String.valueOf(SOCKET_CLAMD))) : CLAMD + " --version");
            if (fromDaemon) r.put("running", true);
            if (c.signatures() != null) {
                r.put("signatures", c.signatures());
                r.put("detail", c.del() != null
                        ? I18n.tr("server.ver.sigsOf", java.util.Map.of("n", String.valueOf(c.signatures()), "date", String.valueOf(data(c.del()))))
                        : I18n.tr("server.ver.sigs", java.util.Map.of("n", String.valueOf(c.signatures()))));
                if (c.del() != null) {
                    long days = ChronoUnit.DAYS.between(c.del(), s.now());
                    if (days > SIGNATURE_DAYS)
                        r.put("warning", I18n.tr("server.ver.sigsOld", java.util.Map.of("d", String.valueOf(days))));
                }
            }
            if (fromDaemon && !pkg.isEmpty())
                compare(r, c.engine(), upstream(pkg), "clamd", I18n.tr("server.ver.fixClamav"));
            return r;
        }

        JSONObject roundcube() {
            JSONObject r = entry("roundcube", "Roundcube", "server.ver.role.roundcube");
            String index = ROUNDCUBE + "/index.php";
            if (!s.exists(index)) return r;
            r.put("installed", true);
            String pkg = pkgName(index);
            if (!pkg.isEmpty()) r.put("pkgName", pkg);
            String ver = extract(Pattern.compile("RCMAIL_VERSION'\\s*,\\s*'" + V + "'"), s.read(ROUNDCUBE + "/program/include/iniset.php"));
            if (ver != null) r.put("version", ver).put("source", "RCMAIL_VERSION in " + ROUNDCUBE + "/program/include/iniset.php");
            else if (!pkg.isEmpty()) r.put("version", upstream(pkg)).put("source", "pkg which " + index);
            return r;
        }

        JSONObject java(String javaBin) {
            JSONObject r = entry("java", "Java", "server.ver.role.java").put("installed", true);
            String ver = validate(s.javaVersion());
            if (ver == null) return r;
            r.put("version", ver).put("source", I18n.tr("server.ver.srcJava")).put("running", true);
            String pkg = pkgName(javaBin);
            if (!pkg.isEmpty()) {
                r.put("pkgName", pkg);
                compare(r, ver, upstream(pkg), I18n.tr("server.ver.panelJava"), I18n.tr("server.ver.fixPanel"));
            }
            return r;
        }

        JSONObject freebsd() {
            JSONObject r = entry("freebsd", "FreeBSD", "server.ver.role.freebsd");
            if (!s.exists(FREEBSD_VERSION)) return r;
            String userland = validate(before(s.run(FREEBSD_VERSION, "-u")));
            if (userland == null) return r;
            String running = validate(before(s.run(FREEBSD_VERSION, "-r")));
            String installed = validate(before(s.run(FREEBSD_VERSION, "-k")));
            r.put("installed", true).put("version", userland).put("source", "freebsd-version -u");
            // Kernel and userland can have different patch levels for good reasons (a fix that
            // touches only one or the other): it is reported, but it is not a problem.
            if (running != null && !running.equals(userland)) r.put("detail", I18n.tr("server.ver.kernelRunning", java.util.Map.of("v", String.valueOf(running))));
            // The Handbook: an installed kernel different from the running one means a reboot is missing.
            if (installed != null && running != null && !installed.equals(running)) {
                r.put("restart", true).put("installedVersion", installed).put("restartNote", I18n.tr("server.ver.kernelReboot", java.util.Map.of("inst", String.valueOf(installed), "run", String.valueOf(running))));
            }
            return r;
        }

        JSONObject openssl(String binary, String key, String name, String role) {
            JSONObject r = entry(key, name, role);
            if (!s.exists(binary)) return r;
            r.put("installed", true);
            String pkg = pkgName(binary);
            if (!pkg.isEmpty()) r.put("pkgName", pkg);
            String out = s.run(binary, "version");
            Matcher m = Pattern.compile("^(?:OpenSSL|LibreSSL)\\s+" + V + "(?:\\s+(\\d{1,2} [A-Z][a-z]{2} \\d{4}))?", Pattern.MULTILINE)
                    .matcher(out == null ? "" : out);
            if (m.find() && validate(m.group(1)) != null) {
                r.put("version", m.group(1)).put("source", binary + " version");
                if (m.group(2) != null) {
                    try {
                        LocalDate d = LocalDate.parse(m.group(2), DateTimeFormatter.ofPattern("d MMM yyyy", Locale.ENGLISH));
                        r.put("detail", I18n.tr("server.ver.released", java.util.Map.of("date", String.valueOf(d.format(DateTimeFormatter.ofPattern("dd/MM/yyyy"))))));
                    } catch (Exception ignored) { /* the date is an extra */ }
                }
            } else if (!pkg.isEmpty()) {
                r.put("version", upstream(pkg)).put("source", "pkg which " + binary);
            }
            return r;
        }

        String data(Instant i) { return i.atZone(s.zone()).format(DATE_TIME); }
    }

    private static JSONObject entry(String key, String name, String role) {
        return new JSONObject().put("key", key).put("name", I18n.tr(name)).put("role", I18n.tr(role)).put("installed", false);
    }

    /** The first group of the pattern in the output, if it is a version; otherwise null. */
    static String extract(Pattern template, String output) {
        if (output == null) return null;
        Matcher m = template.matcher(output);
        return m.find() ? validate(m.group(1)) : null;
    }

    static String validate(String v) {
        if (v == null) return null;
        String t = v.strip();
        return VALID_VERSION.matcher(t).matches() ? t : null;
    }

    private static String before(String output) {
        if (output == null) return null;
        String t = output.strip();
        int a = t.indexOf('\n');
        return a < 0 ? t : t.substring(0, a).strip();
    }

    /**
     * "pkg which": "/usr/local/sbin/postconf was installed by package postfix-mysql-3.10.4,1".
     * Files that no package owns ("was not found in the database") do not appear.
     */
    static Map<String, String> owners(String output) {
        Map<String, String> m = new HashMap<>();
        if (output == null) return m;
        Matcher r = Pattern.compile("^(/\\S+) was installed by package (\\S+)$", Pattern.MULTILINE).matcher(output);
        while (r.find()) {
            String nv = r.group(2);
            int dash = nv.lastIndexOf('-');
            if (dash > 0 && validate(nv.substring(dash + 1)) != null && nv.matches("[0-9A-Za-z.+_,:~-]{1,100}"))
                m.put(r.group(1), nv);
        }
        return m;
    }

    /** "pkg query '%n %t'": package name and installation time (seconds since 1970). */
    static Map<String, Long> installs(String output) {
        Map<String, Long> m = new HashMap<>();
        if (output == null) return m;
        Matcher r = Pattern.compile("^([0-9A-Za-z.+_-]{1,100}) (\\d{1,12})$", Pattern.MULTILINE).matcher(output);
        while (r.find()) m.put(r.group(1), Long.parseLong(r.group(2)));
        return m;
    }

    /** The name of a package from "name-version": the version is after the last hyphen. */
    static String name(String versionName) {
        int t = versionName.lastIndexOf('-');
        return t > 0 ? versionName.substring(0, t) : versionName;
    }

    /**
     * The version of the program from that of the package, without the port revision and the epoch:
     * "postfix-mysql-3.10.4,1" -> "3.10.4", "dovecot-mysql-2.3.21.1_8" -> "2.3.21.1".
     */
    static String upstream(String versionName) {
        int t = versionName.lastIndexOf('-');
        String v = t >= 0 ? versionName.substring(t + 1) : versionName;
        return v.replaceFirst(",\\d+$", "").replaceFirst("_\\d+$", "");
    }

    /** The leading numeric part, for comparing: "8.0.43-debug" -> "8.0.43", "25.0.1+8-LTS" -> "25.0.1". */
    static String numbers(String v) {
        if (v == null) return "";
        Matcher m = Pattern.compile("^\\d+(?:\\.\\d+)*").matcher(v.strip());
        return m.find() ? m.group() : "";
    }

    /** The pid written in a pidfile (Postfix right-aligns it with spaces). */
    static Long pid(String content) {
        if (content == null) return null;
        String t = content.strip();
        if (!t.matches("\\d{1,10}")) return null;
        long p = Long.parseLong(t);
        return p > 1 ? p : null;
    }

    /** The answer of clamd: engine, number of signatures and their date (null if they are missing). */
    record Clamd(String engine, String signatures, Instant del) {}

    /**
     * "ClamAV 1.4.3/27780/Thu Oct  2 08:24:28 2026": the date is the one from ctime(), in the local time
     * of the server, that is the same zone as the JVM that reads it here.
     */
    static Clamd clamd(String answer, ZoneId zone) {
        if (answer == null) return null;
        Matcher m = Pattern.compile("ClamAV " + V + "(?:/(\\d{1,9})/([A-Za-z]{3} [A-Za-z]{3} +\\d{1,2} \\d{2}:\\d{2}:\\d{2} \\d{4}))?")
                .matcher(answer);
        if (!m.find()) return null;
        String engine = validate(m.group(1));
        if (engine == null) return null;
        Instant del = null;
        if (m.group(3) != null) {
            try {
                del = LocalDateTime.parse(m.group(3).replaceAll(" +", " "),
                        DateTimeFormatter.ofPattern("EEE MMM d HH:mm:ss yyyy", Locale.ENGLISH)).atZone(zone).toInstant();
            } catch (Exception ignored) { /* without a date only the number is shown */ }
        }
        return new Clamd(engine, m.group(2), del);
    }

    // ===== The real system =====

    /** The server: commands with Shell (separate arguments, no shell), files, the socket of clamd. */
    public static SystemAccess real(Supplier<String> mysqlVersion) {
        return new SystemAccess() {
            public String run(String... argv) {
                Shell.Result r = Shell.run(Duration.ofSeconds(10), argv);
                if (r.timedOut() || r.exitCode() < 0) return null;
                String out = r.output();
                return out.length() > 65536 ? out.substring(0, 65536) : out;
            }
            public boolean exists(String path) { return Files.exists(Path.of(path)); }
            public String read(String path) {
                try {
                    Path p = Path.of(path);
                    if (!Files.isRegularFile(p) || Files.size(p) > 262144) return null;
                    return new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
                } catch (Exception e) {
                    return null;
                }
            }
            public String askClamd2() { return askClamd(Path.of(SOCKET_CLAMD)); }
            public String mysqlVersion() {
                try { return mysqlVersion.get(); } catch (Exception e) { return null; }
            }
            public Instant startup(long pid) {
                return ProcessHandle.of(pid).flatMap(p -> p.info().startInstant()).orElse(null);
            }
            public String javaVersion() { return Runtime.version().toString(); }
            public String javaFolder() { return System.getProperty("java.home"); }
            public Instant now() { return Instant.now(); }
            public ZoneId zone() { return ZoneId.systemDefault(); }
        };
    }

    /**
     * Asks clamd for VERSION ("z": command and answer terminated by a zero byte). At most three
     * seconds: a read blocked on a clamd that does not answer would stop the request forever, and
     * closing the socket (on leaving the try) is what unblocks it.
     */
    static String askClamd(Path socket) {
        if (!Files.exists(socket)) return null;
        try (ExecutorService es = Executors.newVirtualThreadPerTaskExecutor();
             SocketChannel ch = SocketChannel.open(StandardProtocolFamily.UNIX)) {
            Future<String> f = es.submit(() -> {
                ch.connect(UnixDomainSocketAddress.of(socket));
                ch.write(ByteBuffer.wrap("zVERSION\0".getBytes(StandardCharsets.US_ASCII)));
                ByteBuffer b = ByteBuffer.allocate(512);
                while (b.hasRemaining() && ch.read(b) > 0) {
                    if (b.position() > 0 && b.get(b.position() - 1) == 0) break;
                }
                String t = new String(b.array(), 0, b.position(), StandardCharsets.US_ASCII);
                int zero = t.indexOf('\0');
                return (zero >= 0 ? t.substring(0, zero) : t).strip();
            });
            String r = f.get(3, TimeUnit.SECONDS);
            return r.isEmpty() ? null : r;
        } catch (Exception e) {
            return null;
        }
    }
}
