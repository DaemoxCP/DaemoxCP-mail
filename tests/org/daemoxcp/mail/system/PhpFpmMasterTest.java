package org.daemoxcp.mail.system;

import org.daemoxcp.mail.util.Shell;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * php-fpm's master process as roundcube, not root (PhpFpmMaster, 2026-11-23).
 *  1. php-fpm.conf: the pid in roundcube's folder and the log to syslog, replacing the package's lines (commented or
 *     not) or adding them after [global]; the rest untouched; twice the same.
 *  2. The pool: the socket in php-fpm's own folder, its group with roundcube and www alone; the pm.* lines carried
 *     over; other pools are found (a master as root stays right for them).
 *  3. The migration with fake services in a temporary folder: done in the right order (stop, the rc pidfile as a
 *     link, php_fpm_user, start, nginx moved to the new socket); a refused configuration puts everything back and
 *     leaves php-fpm as root; a pool that is not the panel's or other pools: nothing touched; already done: nothing.
 * Pure Java, no system call: it runs anywhere, the VM included.
 *   java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.PhpFpmMasterTest
 */
public class PhpFpmMasterTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static final String PACKAGE_CONF = """
            ;;;;;;;;;;;;;;;;;;;;;
            ; FPM Configuration ;
            ;;;;;;;;;;;;;;;;;;;;;

            [global]
            ; Pid file
            ; Note: the default prefix is /var
            ; Default Value: none
            pid = run/php-fpm.pid

            ; Error log file
            ;error_log = log/php-fpm.log

            ;syslog.facility = daemon
            include=/usr/local/etc/php-fpm.d/*.conf
            """;

    public static void main(String[] a) throws Exception {
        String pid = "/var/run/php-fpm/php-fpm.pid";

        System.out.println("== 1. php-fpm.conf ==");
        String after = PhpFpmMaster.globalSettings(PACKAGE_CONF, pid);
        check("the pid in roundcube's folder, the package's line replaced", after.contains("\npid = " + pid + "\n")
                && !after.contains("pid = run/php-fpm.pid"));
        check("the log to syslog, in place of the commented line", after.contains("\nerror_log = syslog\n")
                && !after.contains(";error_log = log/php-fpm.log"));
        check("everything else as it was", after.contains("include=/usr/local/etc/php-fpm.d/*.conf")
                && after.contains(";syslog.facility = daemon") && after.contains("; Default Value: none"));
        check("a second time, the same", PhpFpmMaster.globalSettings(after, pid).equals(after));
        check("done is recognised, the package's file is not", PhpFpmMaster.globalDone(after, pid) && !PhpFpmMaster.globalDone(PACKAGE_CONF, pid));
        String bare = PhpFpmMaster.globalSettings("[global]\ninclude=x\n", pid);
        check("keys missing: added right after [global]", bare.startsWith("[global]\npid = " + pid + "\nerror_log = syslog\ninclude=x"));

        System.out.println("\n== 2. The pool ==");
        String pool = RoundcubeUser.poolConf(null);
        check("the socket in php-fpm's own folder", pool.contains("listen = /var/run/php-fpm/roundcube.sock\n"));
        check("  owned by roundcube, its group roundcube_fpm, 0660", pool.contains("listen.owner = roundcube\n")
                && pool.contains("listen.group = roundcube_fpm\n") && pool.contains("listen.mode = 0660\n"));
        check("user and group kept: if the master ever ran as root again, the pool would still not", pool.contains("user = roundcube\n")
                && pool.contains("group = roundcube\n"));
        String old = oldPool("pm = static\npm.max_children = 7\n");
        check("the pm lines carried over", PhpFpmMaster.pmLines(old).equals("pm = static\npm.max_children = 7\n"));
        check("Roundcube's pool alone: no other pool", PhpFpmMaster.otherPools(Map.of("roundcube.conf", pool,
                "www.conf", RoundcubeUser.wwwPlaceholder())).isEmpty());
        check("another pool is found", PhpFpmMaster.otherPools(Map.of("roundcube.conf", pool, "site.conf", "[site]\nuser = site\n"))
                .equals(List.of("site")));
        check("the install script makes the group with roundcube and www, and the folder", RoundcubeUser.shellPool()
                .contains("pw groupmod roundcube_fpm -M roundcube,www") && RoundcubeUser.shellPool()
                .contains("install -d -o roundcube -g roundcube_fpm -m 750 /var/run/php-fpm"));

        System.out.println("\n== 3. The migration ==");
        Path tmp = Files.createTempDirectory("php-fpm-master");
        try {
            Fake ok = new Fake(tmp.resolve("ok"), false);
            PhpFpmMaster.Report r = PhpFpmMaster.migrate(ok.at, ok);
            check("done (" + r.detail() + ")", r.outcome() == PhpFpmMaster.Outcome.DONE);
            check("  stop before the link, php_fpm_user before the start", ok.calls.indexOf("stop") >= 0
                    && ok.calls.indexOf("rc php_fpm_user=roundcube") > ok.calls.indexOf("stop")
                    && ok.calls.indexOf("start") > ok.calls.indexOf("rc php_fpm_user=roundcube"));
            check("  the rc pidfile is a link to roundcube's pidfile", Files.isSymbolicLink(ok.at.rcPidfile())
                    && Files.readSymbolicLink(ok.at.rcPidfile()).equals(ok.at.pid()));
            check("  php-fpm.conf with the new pid and syslog", PhpFpmMaster.globalDone(Files.readString(ok.at.fpmConf()), ok.at.pid().toString()));
            check("  the pool on the new socket, pm lines kept", Files.readString(ok.at.pool()).contains("listen = " + RoundcubeUser.SOCKET)
                    && Files.readString(ok.at.pool()).contains("pm.max_children = 7"));
            check("  nginx moved to the new socket", Files.readString(ok.nginx).contains("fastcgi_pass unix:" + RoundcubeUser.SOCKET + ";")
                    && !Files.readString(ok.nginx).contains(RoundcubeUser.ROOT_MASTER_SOCKET));
            check("  the pool file made readable by roundcube", ok.calls.contains("readable"));
            PhpFpmMaster.Report again = PhpFpmMaster.migrate(ok.at, ok);
            check("a second start: nothing to do", again.outcome() == PhpFpmMaster.Outcome.NOTHING);

            Fake bad = new Fake(tmp.resolve("bad"), true);
            String confBefore = Files.readString(bad.at.fpmConf()), poolBefore = Files.readString(bad.at.pool()),
                    nginxBefore = Files.readString(bad.nginx);
            r = PhpFpmMaster.migrate(bad.at, bad);
            check("php-fpm -t refuses: rolled back (" + r.detail() + ")", r.outcome() == PhpFpmMaster.Outcome.ROLLED_BACK);
            check("  the files as they were", Files.readString(bad.at.fpmConf()).equals(confBefore)
                    && Files.readString(bad.at.pool()).equals(poolBefore) && Files.readString(bad.nginx).equals(nginxBefore));
            check("  refused before the switch: php-fpm never stopped, php_fpm_user never set, still root",
                    !bad.calls.contains("stop") && bad.rc.get("php_fpm_user") == null && "root".equals(bad.masterUser()));

            Fake late = new Fake(tmp.resolve("late"), false);
            late.startFailsAs = "roundcube";
            r = PhpFpmMaster.migrate(late.at, late);
            check("php-fpm does not start as roundcube: rolled back (" + r.detail() + ")", r.outcome() == PhpFpmMaster.Outcome.ROLLED_BACK);
            check("  php_fpm_user removed, the rc pidfile no longer a link, php-fpm started again as root",
                    late.rc.get("php_fpm_user") == null && !Files.isSymbolicLink(late.at.rcPidfile()) && "root".equals(late.masterUser()));
            check("  the files as they were", Files.readString(late.at.fpmConf()).equals(PACKAGE_CONF)
                    && Files.readString(late.nginx).contains(RoundcubeUser.ROOT_MASTER_SOCKET));

            Fake theirs = new Fake(tmp.resolve("theirs"), false);
            Files.writeString(theirs.at.pool(), "[roundcube]\nuser = roundcube\nlisten = /tmp/x.sock\n");
            r = PhpFpmMaster.migrate(theirs.at, theirs);
            check("a pool not written by the panel: nothing touched", r.outcome() == PhpFpmMaster.Outcome.NOT_OURS && theirs.calls.isEmpty());

            Fake others = new Fake(tmp.resolve("others"), false);
            Files.writeString(others.at.fpmDir().resolve("site.conf"), "[site]\nuser = site\nlisten = /var/run/site.sock\n");
            r = PhpFpmMaster.migrate(others.at, others);
            check("another pool: the master stays root, said (" + r.detail() + ")", r.outcome() == PhpFpmMaster.Outcome.OTHER_POOLS
                    && others.calls.isEmpty());
        } finally {
            try (var w = Files.walk(tmp)) { w.sorted(java.util.Comparator.reverseOrder()).forEach(p -> p.toFile().delete()); }
        }

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }

    /** A pool as 1.0.1 wrote it: the panel's mark, the socket in /var/run, group www. */
    static String oldPool(String pm) {
        return RoundcubeUser.poolConf(pm).replace(RoundcubeUser.SOCKET, RoundcubeUser.ROOT_MASTER_SOCKET)
                .replace("listen.group = " + RoundcubeUser.SOCKET_GROUP, "listen.group = www");
    }

    /** The system as the migration sees it, in a temporary folder: files real, services faked. */
    static final class Fake implements PhpFpmMaster.Services {
        final PhpFpmMaster.Places at;
        final Path nginx;
        final List<String> calls = new ArrayList<>();
        final Map<String, String> rc = new java.util.HashMap<>(Map.of("php_fpm_enable", "YES"));
        final boolean refuse;
        boolean running = true;
        String runningAs = "root";
        /** The start fails when php-fpm would run as this user (a planted failure). */
        String startFailsAs = null;

        Fake(Path dir, boolean refuse) throws Exception {
            this.refuse = refuse;
            Files.createDirectories(dir.resolve("etc/php-fpm.d"));
            Files.createDirectories(dir.resolve("run/php-fpm"));
            Files.createDirectories(dir.resolve("www/roundcube"));
            at = new PhpFpmMaster.Places(dir.resolve("etc/php-fpm.conf"), dir.resolve("etc/php-fpm.d"), dir.resolve("run/php-fpm"),
                    dir.resolve("run/php-fpm.pid"), dir.resolve("www/roundcube"));
            Files.writeString(at.fpmConf(), PACKAGE_CONF);
            Files.writeString(at.pool(), oldPool("pm = static\npm.max_children = 7\n"));
            Files.writeString(at.fpmDir().resolve("www.conf"), RoundcubeUser.wwwPlaceholder());
            Files.writeString(at.rcPidfile(), "123\n");
            nginx = dir.resolve("etc/roundcube-nginx.conf");
            Files.writeString(nginx, "server {\n    listen 8443 ssl;\n    server_name webmail.example.com;\n    root " + at.roundcubeDir()
                    + ";\n    location ~ \\.php$ {\n        fastcgi_pass unix:" + RoundcubeUser.ROOT_MASTER_SOCKET + ";\n    }\n}\n");
        }

        private static Shell.Result ok() { return new Shell.Result(0, "ok", false, List.of()); }
        private static Shell.Result fail(String why) { return new Shell.Result(1, why, false, List.of()); }

        @Override public String rcConf(String name) { return rc.getOrDefault(name, ""); }
        @Override public boolean setRcConf(String name, String value) {
            calls.add("rc " + name + "=" + value);
            if (value == null) rc.remove(name); else rc.put(name, value);
            return true;
        }
        @Override public boolean ensureSocketGroupAndDir() { calls.add("group"); return true; }
        @Override public boolean poolFileReadable(Path pool) { calls.add("readable"); return true; }
        @Override public String masterUser() { return running ? runningAs : null; }
        @Override public Map<String, Set<String>> poolUsers() { return Map.of("roundcube", Set.of("roundcube")); }
        @Override public Shell.Result phpFpmTest() { calls.add("test"); return refuse ? fail("planted: invalid configuration") : ok(); }
        @Override public Shell.Result phpFpmStop() { calls.add("stop"); running = false; return ok(); }
        @Override public Shell.Result phpFpmStart() {
            calls.add("start");
            String as = rc.getOrDefault("php_fpm_user", "root");
            if (as.equals(startFailsAs)) { running = false; return fail("planted: php-fpm did not start as " + as); }
            running = true;
            runningAs = as;
            return ok();
        }
        @Override public String nginxDump() {
            try { return "# configuration file " + nginx + ":\n" + Files.readString(nginx); }
            catch (Exception e) { return null; }
        }
        @Override public Shell.Result nginxTest() { calls.add("nginx -t"); return ok(); }
        @Override public Shell.Result nginxReload() { calls.add("nginx reload"); return ok(); }
        @Override public boolean webmailAnswers(String name, String port) { return "webmail.example.com".equals(name) && "8443".equals(port); }
        @Override public void pause() { }
    }
}
