package org.daemoxcp.mail.system;

import org.daemoxcp.mail.util.Shell;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * php-fpm's master process as roundcube, not root (2026-11-23).
 *
 * <p>The master runs no pages: it reads the configuration, makes the pools' sockets and starts their processes. It
 * needs root only to start each pool as a different user. On the mail server there is one pool, Roundcube's, already
 * running as roundcube: the master can be roundcube too, and PHP-FPM supports it (a master that is not root runs
 * every pool as its own user, and ignores "user" and "group"). What it removes: in 2021 a pool process could write
 * into the master's memory and become root through it (CVE-2021-21703, PHP-FPM); with the master as roundcube, the
 * same flaw would give roundcube what roundcube already has.
 *
 * <p>What a master that is not root needs, all done here and checked before and after:
 * <ul>
 *   <li>its socket and pidfile in a folder of its own, {@link RoundcubeUser#FPM_RUN_DIR} (roundcube, group
 *       {@link RoundcubeUser#SOCKET_GROUP}, 0750): FreeBSD's cleanvar empties /var/run at boot but keeps its folders;
 *   <li>the socket's group, {@link RoundcubeUser#SOCKET_GROUP}, with roundcube (which makes the socket and may give
 *       it only one of its own groups) and nginx's www, nobody else: www in roundcube's group would read the
 *       webmail's configuration;
 *   <li>the pool file readable by roundcube (root:roundcube 0640): the master reads it;
 *   <li>its log to syslog: /var/log/php-fpm.log is root's;
 *   <li>the pidfile: the package's rc script always reads /var/run/php-fpm.pid, so that name becomes a link to the
 *       pidfile roundcube writes (cleanvar deletes files and sockets in /var/run, not links); rc.subr believes the
 *       pid only if it is a php-fpm process;
 *   <li>php_fpm_user="roundcube" in rc.conf: rc.subr starts php-fpm as that user (su).
 * </ul>
 * A php-fpm with other pools (added by hand: their users need a master as root) is left as it is, and said.
 * On any failure everything goes back as it was, php-fpm as root included, and the next start tries again.
 */
public final class PhpFpmMaster {

    private static final Logger LOGGER = Logger.getLogger(PhpFpmMaster.class.getName());

    /** Where the master writes its pid, in its own folder. */
    public static final String PID_FILE = RoundcubeUser.FPM_RUN_DIR + "/php-fpm.pid";
    /** The pidfile the package's rc script (rc.d/php_fpm) reads, fixed in the script. */
    static final String RC_PIDFILE = "/var/run/php-fpm.pid";
    static final String FPM_CONF = "/usr/local/etc/php-fpm.conf";

    private PhpFpmMaster() {}

    enum Outcome { NOTHING, OTHER_POOLS, NOT_OURS, DONE, ROLLED_BACK }

    record Report(Outcome outcome, String detail) {}

    /** Where the files are: fixed on the server, temporary folders in the test. */
    record Places(Path fpmConf, Path fpmDir, Path runDir, Path rcPidfile, Path roundcubeDir) {
        static Places real() {
            return new Places(Path.of(FPM_CONF), Path.of(RoundcubeUser.FPM_DIR), Path.of(RoundcubeUser.FPM_RUN_DIR),
                    Path.of(RC_PIDFILE), Path.of(RoundcubeUser.ROUNDCUBE_DIR));
        }
        Path pool() { return fpmDir.resolve(RoundcubeUser.POOL + ".conf"); }
        Path pid() { return runDir.resolve("php-fpm.pid"); }
    }

    /** What is needed from the system, kept apart to test the decisions without it. */
    interface Services {
        /** The value of a variable of rc.conf, or "" if it is not set. */
        String rcConf(String name);
        /** Sets a variable of rc.conf; a null value removes it. */
        boolean setRcConf(String name, String value);
        boolean ensureSocketGroupAndDir();
        /** root:roundcube 0640, so that the master, as roundcube, reads it. */
        boolean poolFileReadable(Path pool);
        /** The user the php-fpm master runs as, or null if it does not run. */
        String masterUser();
        Map<String, Set<String>> poolUsers();
        Shell.Result phpFpmTest();
        Shell.Result phpFpmStop();
        Shell.Result phpFpmStart();
        String nginxDump();
        Shell.Result nginxTest();
        Shell.Result nginxReload();
        boolean webmailAnswers(String name, String port);
        void pause();
    }

    public static void ensureAtBoot() {
        try {
            Report r = migrate(Places.real(), new RealServices());
            if (r.outcome() == Outcome.NOTHING) return;
            String line = "[PhpFpmMaster] " + r.outcome() + ": " + r.detail();
            if (r.outcome() == Outcome.DONE) LOGGER.info(line);
            else LOGGER.warning(line);
        } catch (Throwable t) {
            LOGGER.warning("[PhpFpmMaster] failed: " + t);
        }
    }

    // ===================== the files =====================

    private static final Pattern GLOBAL_KEY = Pattern.compile("^\\s*;?\\s*(pid|error_log)\\s*=.*$");

    /**
     * php-fpm.conf with, in [global], the pid in roundcube's folder and the log to syslog. The two keys are replaced
     * where they are (commented or not) or added right after [global]; everything else stays as it is. Pure.
     */
    static String globalSettings(String conf, String pidFile) {
        List<String> out = new ArrayList<>();
        boolean inGlobal = false, pidDone = false, logDone = false;
        int globalAt = -1;
        for (String line : conf.split("\n", -1)) {
            String t = line.trim();
            if (t.startsWith("[") && t.endsWith("]")) {
                inGlobal = t.equals("[global]");
                if (inGlobal) globalAt = out.size();
                out.add(line);
                continue;
            }
            Matcher m = GLOBAL_KEY.matcher(line);
            if (inGlobal && m.matches()) {
                if (m.group(1).equals("pid") && !pidDone) { out.add("pid = " + pidFile); pidDone = true; continue; }
                if (m.group(1).equals("error_log") && !logDone) { out.add("error_log = syslog"); logDone = true; continue; }
                if (!t.startsWith(";")) continue;
            }
            out.add(line);
        }
        if (globalAt < 0) {
            out.add(0, "[global]");
            globalAt = 0;
        }
        int at = globalAt + 1;
        if (!logDone) out.add(at, "error_log = syslog");
        if (!pidDone) out.add(at, "pid = " + pidFile);
        return String.join("\n", out);
    }

    /** True if php-fpm.conf already has both settings, uncommented, in [global]. Pure. */
    static boolean globalDone(String conf, String pidFile) {
        boolean inGlobal = false, pid = false, log = false;
        for (String line : conf.split("\n")) {
            String t = line.trim();
            if (t.startsWith("[") && t.endsWith("]")) { inGlobal = t.equals("[global]"); continue; }
            if (!inGlobal || t.startsWith(";")) continue;
            if (t.matches("pid\\s*=\\s*" + Pattern.quote(pidFile))) pid = true;
            if (t.matches("error_log\\s*=\\s*syslog")) log = true;
        }
        return pid && log;
    }

    /** The pools other than Roundcube's in the php-fpm.d files: their names, empty if there are none. */
    static List<String> otherPools(Map<String, String> files) {
        List<String> out = new ArrayList<>();
        for (String content : files.values())
            for (RoundcubeUser.Pool p : RoundcubeUser.pools(content))
                if (!p.name().equals(RoundcubeUser.POOL) && !p.name().equals("global")) out.add(p.name());
        return out;
    }

    /** The pm.* lines of the current Roundcube pool, carried over into the new one. Pure. */
    static String pmLines(String pool) {
        StringBuilder b = new StringBuilder();
        for (RoundcubeUser.Pool p : RoundcubeUser.pools(pool))
            if (p.name().equals(RoundcubeUser.POOL))
                for (String l : p.lines()) if (l.startsWith("pm")) b.append(l).append('\n');
        return b.toString();
    }

    // ===================== the boot migration =====================

    static Report migrate(Places at, Services sv) throws IOException {
        Path pool = at.pool();
        if (!Files.isRegularFile(pool, LinkOption.NOFOLLOW_LINKS) || !Files.isRegularFile(at.fpmConf(), LinkOption.NOFOLLOW_LINKS))
            return new Report(Outcome.NOTHING, "");
        String poolBefore = Files.readString(pool, StandardCharsets.UTF_8);
        if (!PanelMarker.writtenByPanel(poolBefore))
            return new Report(Outcome.NOT_OURS, pool + " was not written by the panel: php-fpm left as it is");
        Map<String, String> files = new java.util.TreeMap<>();
        try (var s = Files.newDirectoryStream(at.fpmDir(), "*.conf")) {
            for (Path f : s) if (Files.isRegularFile(f, LinkOption.NOFOLLOW_LINKS)) files.put(f.getFileName().toString(), Files.readString(f));
        }
        List<String> others = otherPools(files);
        if (!others.isEmpty())
            return new Report(Outcome.OTHER_POOLS, "php-fpm has other pools (" + String.join(", ", others)
                    + "): their users need the master as root, so it stays root");

        String confBefore = Files.readString(at.fpmConf(), StandardCharsets.UTF_8);
        String poolAfter = RoundcubeUser.poolConf(pmLines(poolBefore));
        boolean linkOk = Files.isSymbolicLink(at.rcPidfile())
                && Files.readSymbolicLink(at.rcPidfile()).equals(at.pid());
        if (RoundcubeUser.USER.equals(sv.rcConf("php_fpm_user")) && RoundcubeUser.USER.equals(sv.masterUser())
                && poolBefore.equals(poolAfter) && globalDone(confBefore, at.pid().toString()) && linkOk) {
            sv.ensureSocketGroupAndDir();
            sv.poolFileReadable(pool);
            return new Report(Outcome.NOTHING, "");
        }

        // The nginx files that pass to the socket of the master as root, moved to the new one.
        List<RoundcubeUser.FileEdit> edits = new ArrayList<>();
        String dump = sv.nginxDump();
        if (dump == null) return new Report(Outcome.NOTHING, "nginx does not answer: php-fpm left as it is, tried again at the next start");
        for (Map.Entry<Path, String> f : RoundcubeUser.configFiles(dump).entrySet()) {
            if (!Files.isRegularFile(f.getKey(), LinkOption.NOFOLLOW_LINKS)) continue;
            String before = Files.readString(f.getKey(), StandardCharsets.UTF_8);
            String after = RoundcubeUser.repointed(before, "unix:" + RoundcubeUser.ROOT_MASTER_SOCKET);
            if (!after.equals(before)) edits.add(new RoundcubeUser.FileEdit(f.getKey(), before, after));
        }
        edits.add(new RoundcubeUser.FileEdit(at.fpmConf(), confBefore, globalSettings(confBefore, at.pid().toString())));
        edits.add(new RoundcubeUser.FileEdit(pool, poolBefore, poolAfter));
        String userBefore = sv.rcConf("php_fpm_user");
        Path pidBefore = Files.isSymbolicLink(at.rcPidfile()) ? Files.readSymbolicLink(at.rcPidfile()) : null;

        if (!sv.ensureSocketGroupAndDir())
            return new Report(Outcome.NOTHING, "the group " + RoundcubeUser.SOCKET_GROUP + " or the folder " + at.runDir()
                    + " could not be made: php-fpm left as it is");
        for (RoundcubeUser.FileEdit e : edits) e.apply();
        sv.poolFileReadable(pool);
        Shell.Result t = sv.phpFpmTest();
        if (!t.success()) return back(at, sv, edits, userBefore, pidBefore, false, "php-fpm -t refused the new configuration: " + t.outputTrim());
        Shell.Result n = sv.nginxTest();
        if (!n.success()) return back(at, sv, edits, userBefore, pidBefore, false, "nginx -t refused the new socket: " + n.outputTrim());

        // The master's user changes only with a stop and a start: the webmail is off for those seconds.
        sv.phpFpmStop();
        Files.deleteIfExists(at.rcPidfile());
        Files.createSymbolicLink(at.rcPidfile(), at.pid());
        if (!sv.setRcConf("php_fpm_user", RoundcubeUser.USER))
            return back(at, sv, edits, userBefore, pidBefore, true, "php_fpm_user could not be set in rc.conf");
        Shell.Result st = sv.phpFpmStart();
        if (!st.success()) return back(at, sv, edits, userBefore, pidBefore, true, "php-fpm did not start as " + RoundcubeUser.USER + ": " + st.outputTrim());
        sv.nginxReload();

        String why = null;
        for (int i = 0; i < 20; i++) {
            why = check(at, sv);
            if (why == null) break;
            sv.pause();
        }
        if (why != null) return back(at, sv, edits, userBefore, pidBefore, true, why);
        return new Report(Outcome.DONE, "php-fpm's master runs as " + RoundcubeUser.USER + ", not root; socket "
                + RoundcubeUser.SOCKET + " (group " + RoundcubeUser.SOCKET_GROUP + "), log to syslog, pidfile " + at.pid());
    }

    /** After the start: master and pool as roundcube, and the webmail answers. Null if all is right. */
    static String check(Places at, Services sv) {
        String master = sv.masterUser();
        if (!RoundcubeUser.USER.equals(master)) return "the php-fpm master runs as " + master + ", not " + RoundcubeUser.USER;
        Map<String, Set<String>> users = sv.poolUsers();
        if (!Map.of(RoundcubeUser.POOL, Set.of(RoundcubeUser.USER)).equals(users))
            return "the pools run as " + users + " instead of " + RoundcubeUser.POOL + "=[" + RoundcubeUser.USER + "] alone";
        for (RoundcubeUser.Site s : RoundcubeUser.sitesPassingTo(RoundcubeUser.configFiles(sv.nginxDump()),
                "unix:" + RoundcubeUser.SOCKET, at.roundcubeDir()))
            if (s.roundcube() && !sv.webmailAnswers(s.name(), s.port()))
                return "the webmail does not answer on " + s.name() + ":" + s.port() + " with the new socket";
        return null;
    }

    /**
     * Everything back as it was: the files; and, if php-fpm was already stopped to change its user ({@code switched}),
     * rc.conf, the pidfile, php-fpm started again as before and nginx reloaded. Before the switch php-fpm and nginx
     * never saw the new files: only the files go back.
     */
    private static Report back(Places at, Services sv, List<RoundcubeUser.FileEdit> edits, String userBefore, Path pidBefore,
                               boolean switched, String why) {
        List<String> problems = new ArrayList<>();
        if (switched) sv.phpFpmStop();
        for (RoundcubeUser.FileEdit e : edits) {
            try { e.undo(); } catch (IOException x) { problems.add(e.path() + ": " + x.getMessage()); }
        }
        if (!switched)
            return new Report(Outcome.ROLLED_BACK, why + "; the files put back, php-fpm and nginx never used them"
                    + (problems.isEmpty() ? "" : " except: " + String.join("; ", problems)));
        if (!sv.setRcConf("php_fpm_user", userBefore == null || userBefore.isEmpty() ? null : userBefore))
            problems.add("php_fpm_user in rc.conf");
        try {
            Files.deleteIfExists(at.rcPidfile());
            if (pidBefore != null) Files.createSymbolicLink(at.rcPidfile(), pidBefore);
        } catch (IOException x) {
            problems.add(at.rcPidfile() + ": " + x.getMessage());
        }
        Shell.Result s = sv.phpFpmStart();
        if (!s.success()) problems.add("php-fpm start: " + s.outputTrim());
        Shell.Result n = sv.nginxReload();
        if (!n.success()) problems.add("nginx reload: " + n.outputTrim());
        return new Report(Outcome.ROLLED_BACK, why + "; everything put back as it was"
                + (problems.isEmpty() ? "" : " except: " + String.join("; ", problems)));
    }

    /** The socket's group with exactly roundcube and www, and php-fpm's folder (roundcube, that group, 0750). */
    public static boolean ensureSocketGroupAndDir() {
        Duration d = Duration.ofSeconds(20);
        String g = RoundcubeUser.SOCKET_GROUP;
        if (!Shell.run(d, "pw", "groupshow", g).success() && !Shell.run(d, "pw", "groupadd", g).success()) return false;
        if (!Shell.run(d, "pw", "groupmod", g, "-M", RoundcubeUser.USER + "," + RoundcubeUser.WEB_GROUP).success()) return false;
        Path dir = Path.of(RoundcubeUser.FPM_RUN_DIR);
        try {
            if (Files.isSymbolicLink(dir) || (Files.exists(dir, LinkOption.NOFOLLOW_LINKS) && !Files.isDirectory(dir, LinkOption.NOFOLLOW_LINKS)))
                Files.delete(dir);
        } catch (IOException e) {
            return false;
        }
        return Shell.run(d, "install", "-d", "-o", RoundcubeUser.USER, "-g", g, "-m", "750", dir.toString()).success();
    }

    private static final class RealServices implements Services {
        private static final Duration SHORT = Duration.ofSeconds(30);

        @Override public String rcConf(String name) {
            Shell.Result r = Shell.run(SHORT, "sysrc", "-n", "-q", name);
            return r.success() ? r.outputTrim() : "";
        }
        @Override public boolean setRcConf(String name, String value) {
            return value == null ? Shell.run(SHORT, "sysrc", "-x", name).success() || rcConf(name).isEmpty()
                    : Shell.run(SHORT, "sysrc", name + "=" + value).success();
        }
        @Override public boolean ensureSocketGroupAndDir() { return PhpFpmMaster.ensureSocketGroupAndDir(); }
        @Override public boolean poolFileReadable(Path pool) {
            return Shell.run(SHORT, "chown", "root:" + RoundcubeUser.GROUP, pool.toString()).success()
                    && Shell.run(SHORT, "chmod", "640", pool.toString()).success();
        }
        @Override public String masterUser() {
            for (String l : Shell.run(SHORT, "ps", "-axww", "-o", "user=", "-o", "command=").output().split("\n")) {
                String[] f = l.trim().split("\\s+", 2);
                if (f.length == 2 && f[1].startsWith("php-fpm: master process")) return f[0];
            }
            return null;
        }
        @Override public Map<String, Set<String>> poolUsers() {
            return ServiceUsers.poolUsers(Shell.run(SHORT, "ps", "-axww", "-o", "user=", "-o", "pid=", "-o", "ppid=",
                    "-o", "command=").output());
        }
        @Override public Shell.Result phpFpmTest() { return Shell.run(SHORT, "php-fpm", "-t"); }
        // "one": they work even if php_fpm_enable is not YES in rc.conf.
        @Override public Shell.Result phpFpmStop() { return Shell.run(SHORT, "service", "php_fpm", "onestop"); }
        @Override public Shell.Result phpFpmStart() { return Shell.run(SHORT, "service", "php_fpm", "onestart"); }
        @Override public String nginxDump() {
            if (Shell.resolve("nginx") == null) return null;
            Shell.Result r = Shell.run(SHORT, "nginx", "-T");
            return r.success() ? r.output() : null;
        }
        @Override public Shell.Result nginxTest() { return Shell.run(SHORT, "nginx", "-t"); }
        @Override public Shell.Result nginxReload() { return Shell.run(SHORT, "service", "nginx", "onereload"); }
        @Override public boolean webmailAnswers(String name, String port) {
            if (!name.matches("[A-Za-z0-9.-]+") || !port.matches("[0-9]+")) return false;
            Shell.Result r = Shell.run(SHORT, "curl", "-sk", "-m", "15", "--resolve", name + ":" + port + ":127.0.0.1",
                    "https://" + name + ":" + port + "/");
            return r.success() && r.output().contains("rcmloginuser");
        }
        @Override public void pause() {
            try { Thread.sleep(500); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
        }
    }
}
