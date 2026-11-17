package org.daemoxcp.mail.system;

import org.json.JSONArray;
import org.json.JSONObject;

import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * The software versions in the Home (SoftwareVersions).
 *
 * A fake system answers with the REAL outputs of the programs on FreeBSD (postconf, dovecot,
 * rspamd, redis-server, nginx, php-fpm, openssl, freebsd-version, clamd, mysqld, pkg which,
 * pkg query): it is checked that every version is recognised, that the package is found from the
 * binary even when it is called postfix-mysql, and that "needs a restart" appears when and only when
 * it is known (a process started before the package was installed, or answering with another
 * version). Then the crooked cases: clamd not answering, old signatures, MySQL unreachable, programs
 * answering something else, text that is not a version. Finally the real clamd socket, with a fake
 * daemon that answers and one that stays silent (the read must give up in three seconds).
 *
 * The panel's texts are read in English (I18n.setCurrent): outside a request it writes Italian.
 *
 * Uso: java -cp "tests:target/daemoxcp-mail-1.0.jar" org.daemoxcp.mail.system.SoftwareVersionsTest
 * With a test MySQL it also reads the version from the real server (reads only):
 *   -Dmysql.port=33062 -Dmysql.user=daemoxcp_mail -Dmysql.password=... -Dmysql.database=daemoxcp_mail_test
 */
public class SoftwareVersionsTest {

    static int failed = 0;

    static void real(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static final ZoneId ROME = ZoneId.of("Europe/Rome");

    /** A fake server: files that exist, command outputs, pidfiles and start times. */
    static class FakeSystem implements SoftwareVersions.SystemAccess {
        final Set<String> file = new HashSet<>();
        final Map<String, String> outputs = new HashMap<>();
        final Map<String, String> contents = new HashMap<>();
        final Map<Long, Instant> processes = new HashMap<>();
        final java.util.List<String> launched = new java.util.ArrayList<>();
        String clamd, mysql, java = "25.0.1+8-1", javaFolder = "/usr/local/openjdk25";
        Instant now = Instant.parse("2026-10-03T12:00:00Z");

        public String run(String... argv) {
            String k = String.join(" ", argv);
            launched.add(k);
            if (k.startsWith(SoftwareVersions.PKG + " which ")) return outputs.get("pkg which");
            return outputs.get(k);
        }
        public boolean exists(String p) { return file.contains(p); }
        public String read(String p) { return contents.get(p); }
        public String askClamd2() { return clamd; }
        public String mysqlVersion() { return mysql; }
        public Instant startup(long pid) { return processes.get(pid); }
        public String javaVersion() { return java; }
        public String javaFolder() { return javaFolder; }
        public Instant now() { return now; }
        public ZoneId zone() { return ROME; }
    }

    static long epoch(String iso) { return Instant.parse(iso).getEpochSecond(); }

    /** A complete mail server as the panel installs it, with a few services to restart. */
    static FakeSystem complete() {
        FakeSystem f = new FakeSystem();
        f.file.addAll(Arrays.asList(SoftwareVersions.PKG, "/usr/local/sbin/postconf", "/usr/local/sbin/dovecot",
                "/usr/local/bin/rspamd", "/usr/local/bin/redis-server", SoftwareVersions.CLAMD, SoftwareVersions.MYSQLD,
                "/usr/local/www/roundcube/index.php", "/usr/local/sbin/nginx", "/usr/local/sbin/php-fpm", "/usr/local/bin/sievec",
                "/usr/local/bin/fail2ban-client", "/usr/sbin/local-unbound", SoftwareVersions.OPENSSL_BASE,
                SoftwareVersions.FREEBSD_VERSION, "/usr/local/openjdk25/bin/java"));
        // pkg which: a file no package owns (local-unbound belongs to the base system).
        f.outputs.put("pkg which", String.join("\n",
                "/usr/local/sbin/postconf was installed by package postfix-mysql-3.10.4,1",
                "/usr/local/sbin/dovecot was installed by package dovecot-mysql-2.3.21.1_8",
                "/usr/local/bin/rspamd was installed by package rspamd-3.12.1",
                "/usr/local/bin/redis-server was installed by package redis-7.4.2",
                "/usr/local/sbin/clamd was installed by package clamav-1.4.3,1",
                "/usr/local/libexec/mysqld was installed by package mysql80-server-8.0.43",
                "/usr/local/www/roundcube/index.php was installed by package roundcube-php84-1.6.11,1",
                "/usr/local/sbin/nginx was installed by package nginx-1.28.0_3,3",
                "/usr/local/sbin/php-fpm was installed by package php84-8.4.13",
                "/usr/local/bin/sievec was installed by package dovecot-pigeonhole-0.5.21.1_1",
                "/usr/local/bin/fail2ban-client was installed by package py311-fail2ban-1.1.0_3",
                "/usr/sbin/local-unbound was not found in the database",
                "/usr/local/openjdk25/bin/java was installed by package openjdk25-25.0.1+8.1", ""));
        f.outputs.put(SoftwareVersions.PKG + " query %n %t", String.join("\n",
                "postfix-mysql " + epoch("2026-10-02T07:00:00Z"),
                "dovecot-mysql " + epoch("2026-09-20T07:00:00Z"),
                "rspamd " + epoch("2026-09-20T07:00:00Z"),
                "redis " + epoch("2026-09-20T07:00:00Z"),
                "py311-fail2ban " + epoch("2026-09-01T07:00:00Z"),
                "php84 " + epoch("2026-10-02T07:00:00Z"), ""));
        f.outputs.put("/usr/local/sbin/postconf -h mail_version", "3.10.4\n");
        f.outputs.put("/usr/local/sbin/dovecot --version", "2.3.21.1 (d492236fa0)\n");
        f.outputs.put("/usr/local/bin/rspamd --version", "Rspamd daemon version 3.12.1\n\nCPU architecture amd64; features: avx2, avx, sse2, sse3, ssse3, sse4.1, sse4.2, rdrand\n"
                + "Hyperscan enabled: TRUE\nJemalloc enabled: FALSE\nLuaJIT enabled: TRUE (LuaJIT version: LuaJIT 2.1.1736781742)\n");
        f.outputs.put("/usr/local/bin/redis-server --version", "Redis server v=7.4.2 sha=00000000:0 malloc=libc bits=64 build=7b2f3e4c3d2a1b0c\n");
        f.outputs.put("/usr/local/sbin/nginx -v", "nginx version: nginx/1.28.0\n");
        f.outputs.put("/usr/local/sbin/php-fpm -v", "PHP 8.4.13 (fpm-fcgi) (built: Sep 25 2025 01:23:45)\nCopyright (c) The PHP Group\nZend Engine v4.4.13, Copyright (c) Zend Technologies\n");
        f.outputs.put("/usr/sbin/local-unbound -V", "Version 1.22.0\n\nConfigure line: --with-ssl=/usr --with-libexpat=/usr\nLinked libs: libevent 2.1.12-stable (it uses kqueue), OpenSSL 3.5.1 1 Jul 2025\n");
        f.outputs.put(SoftwareVersions.OPENSSL_BASE + " version", "OpenSSL 3.5.1 1 Jul 2025\n");
        f.outputs.put(SoftwareVersions.FREEBSD_VERSION + " -u", "15.0-RELEASE-p3\n");
        f.outputs.put(SoftwareVersions.FREEBSD_VERSION + " -r", "15.0-RELEASE-p2\n");
        f.outputs.put(SoftwareVersions.FREEBSD_VERSION + " -k", "15.0-RELEASE-p3\n");
        f.contents.put("/usr/local/www/roundcube/program/include/iniset.php",
                "<?php\n\n// application constants\ndefine('RCMAIL_VERSION', '1.6.11');\ndefine('RCMAIL_START', microtime(true));\n");
        // Postfix: started before the 02/10 upgrade. Dovecot: after the last installation.
        // Rspamd: no pidfile. Redis: pidfile of a process that is no longer there. PHP-FPM: started
        // before its package, but for it the start time says nothing (reload).
        f.contents.put("/var/spool/postfix/pid/master.pid", "        812\n");
        f.processes.put(812L, Instant.parse("2026-09-28T06:15:00Z"));
        f.contents.put("/var/run/dovecot/master.pid", "901\n");
        f.processes.put(901L, Instant.parse("2026-09-21T08:00:00Z"));
        f.contents.put("/var/run/redis/redis.pid", "1203\n");
        f.contents.put("/var/run/php-fpm.pid", "1300\n");
        f.processes.put(1300L, Instant.parse("2026-09-01T08:00:00Z"));
        f.contents.put("/var/run/fail2ban/fail2ban.pid", "1400\n");
        f.processes.put(1400L, Instant.parse("2026-09-02T08:00:00Z"));
        f.contents.put(SoftwareVersions.PIDFILE_LOCAL_UNBOUND, "700\n");
        f.processes.put(700L, Instant.parse("2026-09-01T05:00:00Z"));
        f.clamd = "ClamAV 1.4.3/27780/Fri Oct  2 08:24:28 2026";
        f.mysql = "8.0.42";
        return f;
    }

    static JSONObject other(JSONObject r, String key) {
        JSONArray a = r.getJSONArray("other");
        for (int i = 0; i < a.length(); i++) if (a.getJSONObject(i).getString("key").equals(key)) return a.getJSONObject(i);
        return null;
    }

    public static void main(String[] args) throws Exception {
        org.daemoxcp.mail.i18n.I18n.setCurrent("en");
        System.out.println("\n== The pieces: packages, versions, pids, clamd ==");
        real("program version from the package: postfix-mysql-3.10.4,1 -> 3.10.4",
                SoftwareVersions.upstream("postfix-mysql-3.10.4,1").equals("3.10.4"));
        real("without the port revision: dovecot-mysql-2.3.21.1_8 -> 2.3.21.1",
                SoftwareVersions.upstream("dovecot-mysql-2.3.21.1_8").equals("2.3.21.1"));
        real("revision and epoch together: roundcube-php84-1.6.11_1,1 -> 1.6.11",
                SoftwareVersions.upstream("roundcube-php84-1.6.11_1,1").equals("1.6.11"));
        real("name with dashes: roundcube-php84-1.6.11,1 -> roundcube-php84",
                SoftwareVersions.name("roundcube-php84-1.6.11,1").equals("roundcube-php84"));
        real("numeric part to compare: 8.0.43-debug -> 8.0.43, 25.0.1+8-LTS -> 25.0.1",
                SoftwareVersions.numbers("8.0.43-debug").equals("8.0.43") && SoftwareVersions.numbers("25.0.1+8-LTS").equals("25.0.1")
                && SoftwareVersions.numbers("abc").isEmpty());
        real("Postfix's pidfile (right-aligned): 812", Long.valueOf(812).equals(SoftwareVersions.pid("        812\n")));
        real("invalid pidfiles: text, 1 (init), 0, eleven digits",
                SoftwareVersions.pid("abc") == null && SoftwareVersions.pid("1") == null && SoftwareVersions.pid("0") == null
                && SoftwareVersions.pid("12345678901") == null && SoftwareVersions.pid(null) == null);
        SoftwareVersions.Clamd c = SoftwareVersions.clamd("ClamAV 1.4.3/27780/Fri Oct  2 08:24:28 2026", ROME);
        real("clamd: engine, signatures and date (one-digit day, two spaces)", c != null && c.engine().equals("1.4.3")
                && c.signatures().equals("27780") && c.del().equals(Instant.parse("2026-10-02T06:24:28Z")));
        c = SoftwareVersions.clamd("ClamAV 1.4.3/27791/Mon Oct 12 18:01:02 2026", ROME);
        real("clamd: two-digit day", c != null && c.del().equals(Instant.parse("2026-10-12T16:01:02Z")));
        c = SoftwareVersions.clamd("ClamAV 1.0.9", ROME);
        real("clamd without signatures loaded: only the engine", c != null && c.engine().equals("1.0.9") && c.signatures() == null && c.del() == null);
        real("an answer that is not clamd's: nothing", SoftwareVersions.clamd("ERROR: unknown command", ROME) == null);
        Map<String, String> p = SoftwareVersions.owners("/a/b was installed by package one-1.0\n/c was not found in the database\n"
                + "/d was installed by package two two-1.0\n/e was installed by package <script>-1\n");
        real("pkg which: only the valid lines (" + p + ")", p.size() == 1 && "one-1.0".equals(p.get("/a/b")));
        Map<String, Long> t = SoftwareVersions.installs("rspamd 1790000000\nbroken\nnginx abc\n");
        real("pkg query %n %t: name and seconds", t.size() == 1 && t.get("rspamd") == 1790000000L);
        real("a version is not accepted if it has spaces or symbols", SoftwareVersions.validate("1.2 3") == null
                && SoftwareVersions.validate("<b>1</b>") == null && SoftwareVersions.validate("3.10.4").equals("3.10.4"));

        System.out.println("\n== Complete server, with something to restart ==");
        FakeSystem f = complete();
        JSONObject r = SoftwareVersions.read(f);
        JSONObject s = r.getJSONObject("services");
        real("readAt with the seconds even when they are zero, in the server's time: " + r.getString("readAt"),
                r.getString("readAt").equals("2026-10-03T14:00:00+02:00"));
        long pkgCalls = f.launched.stream().filter(x -> x.startsWith(SoftwareVersions.PKG)).count();
        real("pkg is called twice in all (which and query), not once per program: " + pkgCalls, pkgCalls == 2);
        JSONObject pf = s.getJSONObject("postfix");
        real("Postfix: 3.10.4 from postconf, package postfix-mysql (not \"postfix\")", pf.getString("version").equals("3.10.4")
                && pf.getString("pkgName").equals("postfix-mysql-3.10.4,1") && pf.getString("source").contains("mail_version"));
        real("Postfix started on 28/09, package installed on 02/10: needs a restart, with the two dates: " + pf.optString("restartNote"),
                pf.optBoolean("restart") && pf.getString("restartNote").contains("28/09/2026 08:15")
                && pf.getString("restartNote").contains("02/10/2026 09:00"));
        JSONObject dv = s.getJSONObject("dovecot");
        real("Dovecot: 2.3.21.1, started after the installation: nothing to restart", dv.getString("version").equals("2.3.21.1")
                && !dv.optBoolean("restart") && dv.getString("pkgName").equals("dovecot-mysql-2.3.21.1_8"));
        JSONObject my = s.getJSONObject("mysql");
        real("MySQL: the running version (8.0.42), not the package's", my.getString("version").equals("8.0.42")
                && my.optBoolean("running") && my.getString("source").startsWith("SELECT VERSION()"));
        real("MySQL: the package is 8.0.43, so it needs a restart: " + my.optString("restartNote"), my.optBoolean("restart")
                && my.getString("installedVersion").equals("8.0.43") && my.getString("restartNote").contains("restart MySQL"));
        JSONObject rs = s.getJSONObject("rspamd");
        real("Rspamd: 3.12.1; without a pidfile nothing is said about the restart", rs.getString("version").equals("3.12.1") && !rs.has("restart"));
        JSONObject rd = s.getJSONObject("redis");
        real("Redis: 7.4.2; pidfile of a process no longer there: nothing about the restart", rd.getString("version").equals("7.4.2") && !rd.has("restart"));
        JSONObject cl = s.getJSONObject("clamav");
        real("ClamAV: from the daemon, engine 1.4.3, signatures 27780 of 02/10/2026 08:24: " + cl.optString("detail"),
                cl.getString("version").equals("1.4.3") && cl.optBoolean("running")
                && cl.getString("detail").equals("signatures 27780 of 02/10/2026 08:24") && !cl.has("warning") && !cl.has("restart"));
        JSONObject rc = s.getJSONObject("roundcube");
        real("Roundcube: 1.6.11 from RCMAIL_VERSION, package roundcube-php84", rc.getString("version").equals("1.6.11")
                && rc.getString("source").contains("RCMAIL_VERSION") && rc.getString("pkgName").equals("roundcube-php84-1.6.11,1"));

        JSONObject fb = other(r, "freebsd");
        real("FreeBSD: userland 15.0-RELEASE-p3, running kernel p2 but p3 installed: server reboot",
                fb.getString("version").equals("15.0-RELEASE-p3") && fb.getString("detail").equals("running kernel 15.0-RELEASE-p2")
                && fb.optBoolean("restart") && fb.getString("restartNote").contains("the server needs a reboot"));
        JSONObject os = other(r, "openssl");
        real("base system OpenSSL: 3.5.1, released on 01/07/2025", os.getString("version").equals("3.5.1")
                && os.getString("detail").equals("released on 01/07/2025"));
        real("no package OpenSSL, no package Unbound: they do not appear", other(r, "openssl_pkg") == null && other(r, "unbound") == null);
        real("nginx 1.28.0", other(r, "nginx").getString("version").equals("1.28.0"));
        JSONObject php = other(r, "php");
        real("PHP-FPM 8.4.13; started before the package but for it the time does not count (reload): nothing about the restart",
                php.getString("version").equals("8.4.13") && !php.has("restart"));
        JSONObject ph = other(r, "pigeonhole");
        real("Pigeonhole from the package: 0.5.21.1", ph.getString("version").equals("0.5.21.1") && ph.getString("source").startsWith("pkg which"));
        JSONObject jv = other(r, "java");
        real("the panel's Java: 25.0.1+8-1 running, the same as the openjdk25 package", jv.getString("version").equals("25.0.1+8-1")
                && jv.optBoolean("running") && jv.getString("pkgName").equals("openjdk25-25.0.1+8.1") && !jv.has("restart"));
        JSONObject f2b = other(r, "fail2ban");
        real("fail2ban from the package: 1.1.0, started after the installation", f2b != null && f2b.getString("version").equals("1.1.0") && !f2b.has("restart"));
        JSONObject lu = other(r, "local_unbound");
        real("the base system's Unbound, because it runs: 1.22.0, without a package", lu != null && lu.getString("version").equals("1.22.0") && !lu.has("pkgName"));
        boolean noHtml = !r.toString().contains("<");
        real("no HTML in the answer", noHtml);

        System.out.println("\n== Freshly installed server: nothing ==");
        FakeSystem empty = new FakeSystem();
        empty.javaFolder = "/usr/local/openjdk25";
        r = SoftwareVersions.read(empty);
        s = r.getJSONObject("services");
        boolean allAbsent = true;
        for (String k : s.keySet()) allAbsent &= !s.getJSONObject(k).getBoolean("installed");
        real("all seven services are there, as not installed: " + s.keySet(), s.length() == 7 && allAbsent);
        real("without pkg, pkg is not called", empty.launched.stream().noneMatch(x -> x.startsWith(SoftwareVersions.PKG)));
        real("Java is always there (it is what runs the panel)", other(r, "java").getBoolean("installed"));
        real("fail2ban and Unbound not installed: they do not appear", other(r, "fail2ban") == null && other(r, "local_unbound") == null);

        System.out.println("\n== Crooked cases ==");
        FakeSystem st = complete();
        st.clamd = null;
        st.outputs.put(SoftwareVersions.CLAMD + " --version", "ClamAV 1.4.3/27700/Mon Sep 14 08:00:00 2026\n");
        st.mysql = null;
        st.outputs.put(SoftwareVersions.MYSQLD + " --version", "/usr/local/libexec/mysqld  Ver 8.0.43 for FreeBSD15.0 on amd64 (Source distribution)\n");
        st.outputs.put("/usr/local/sbin/postconf -h mail_version", "postconf: fatal: open /usr/local/etc/postfix/main.cf: No such file or directory\n");
        st.outputs.put("/usr/local/sbin/dovecot --version", "<script>alert(1)</script>\n");
        st.outputs.put("pkg which", st.outputs.get("pkg which").replace("openjdk25-25.0.1+8.1", "openjdk25-25.0.2+10.1"));
        st.contents.put("/usr/local/www/roundcube/program/include/iniset.php", "<?php // without the constant\n");
        r = SoftwareVersions.read(st);
        s = r.getJSONObject("services");
        cl = s.getJSONObject("clamav");
        real("clamd not answering: version from the binary, not \"running\"", cl.getString("version").equals("1.4.3")
                && !cl.has("running") && cl.getString("source").endsWith("--version"));
        real("signatures of 14/09 (19 days): warning — " + cl.optString("warning"), cl.optString("warning").contains("19 days"));
        real("and without a daemon it is not compared with the package", !cl.has("restart"));
        my = s.getJSONObject("mysql");
        real("MySQL not answering: version from mysqld --version, with the warning that it is not the running one",
                my.getString("version").equals("8.0.43") && !my.has("running") && my.optString("warning").contains("does not answer"));
        pf = s.getJSONObject("postfix");
        real("postconf answers with an error: version from the package (3.10.4)", pf.getString("version").equals("3.10.4")
                && pf.getString("source").startsWith("pkg which"));
        dv = s.getJSONObject("dovecot");
        real("an answer that is not a version does not pass: the package is used", dv.getString("version").equals("2.3.21.1")
                && !r.toString().contains("script"));
        real("iniset.php without the constant: Roundcube from the package", s.getJSONObject("roundcube").getString("version").equals("1.6.11"));
        jv = other(r, "java");
        real("Java updated (package 25.0.2) but the panel runs on 25.0.1: restart the panel — " + jv.optString("restartNote"),
                jv.optBoolean("restart") && jv.getString("restartNote").contains("restart the panel"));
        FakeSystem odd = complete();
        odd.javaFolder = "/usr/local/openjdk25/../../etc";
        r = SoftwareVersions.read(odd);
        real("java.home with \"..\": pkg is not asked", odd.launched.stream().noneMatch(x -> x.contains("..")));

        System.out.println("\n== The real clamd socket ==");
        Path folder = Files.createTempDirectory("clamd-test");
        Path sock = folder.resolve("clamd.sock");
        real("no socket: nothing, at once", SoftwareVersions.askClamd(sock) == null);
        try (ServerSocketChannel srv = ServerSocketChannel.open(StandardProtocolFamily.UNIX)) {
            srv.bind(UnixDomainSocketAddress.of(sock));
            Thread daemon = Thread.ofVirtual().start(() -> {
                try (SocketChannel ch = srv.accept()) {
                    ByteBuffer b = ByteBuffer.allocate(64);
                    ch.read(b);
                    String asked = new String(b.array(), 0, b.position(), StandardCharsets.US_ASCII);
                    String answer = asked.equals("zVERSION\0") ? "ClamAV 1.4.3/27780/Fri Oct  2 08:24:28 2026\0" : "ERROR\0";
                    ch.write(ByteBuffer.wrap(answer.getBytes(StandardCharsets.US_ASCII)));
                } catch (Exception ignored) { }
            });
            String answer = SoftwareVersions.askClamd(sock);
            daemon.join();
            real("clamd answers zVERSION: " + answer, "ClamAV 1.4.3/27780/Fri Oct  2 08:24:28 2026".equals(answer));

            Thread silent = Thread.ofVirtual().start(() -> {
                try (SocketChannel ch = srv.accept()) {
                    Thread.sleep(6000);
                } catch (Exception ignored) { }
            });
            long t0 = System.nanoTime();
            String nothing = SoftwareVersions.askClamd(sock);
            long ms = (System.nanoTime() - t0) / 1_000_000;
            real("silent clamd: it gives up in about three seconds (" + ms + " ms) and says nothing", nothing == null && ms >= 2900 && ms < 4500);
            silent.interrupt();
        } finally {
            Files.deleteIfExists(sock);
            Files.deleteIfExists(folder);
        }

        System.out.println("\n== The real system, as far as it can be here ==");
        SoftwareVersions.SystemAccess system = SoftwareVersions.real(() -> "8.0.46");
        real("a command that does not exist: null", system.run("/does-not-exist/really", "-v") == null);
        real("a command that exits with an error: its output is there all the same", system.run("sh", "-c", "echo version; exit 3").contains("version"));
        real("this process's start time can be read", system.startup(ProcessHandle.current().pid()) != null);
        real("a pid that is not there: null", system.startup(999_999_999L) == null);
        real("this process's Java: " + system.javaVersion(), system.javaVersion().equals(Runtime.version().toString()));
        real("MySQL from the function given to the panel: " + system.mysqlVersion(), "8.0.46".equals(system.mysqlVersion()));

        // The whole path, on a real MySQL: MailDatabase.serverVersion() and the MySQL row that comes
        // out of it, with real() running this machine's real commands. Reads only.
        String port = System.getProperty("mysql.port");
        if (port == null) {
            System.out.println("\n== MySQL not given (-Dmysql.port=...): the version from the real server is skipped ==");
        } else {
            System.out.println("\n== Real MySQL on port " + port + " ==");
            org.daemoxcp.mail.database.MailDatabase db = new org.daemoxcp.mail.database.MailDatabase();
            db.setCredentials(System.getProperty("mysql.user", "daemoxcp_mail"), System.getProperty("mysql.password", ""));
            db.setConnection("127.0.0.1", Integer.parseInt(port), System.getProperty("mysql.database", "daemoxcp_mail_test"));
            real("connection", db.connect());
            String v = db.serverVersion();
            real("serverVersion(): " + v, v != null && SoftwareVersions.numbers(v).matches("\\d+\\.\\d+\\.\\d+"));
            JSONObject everything = SoftwareVersions.read(SoftwareVersions.real(db::serverVersion));
            JSONObject line = everything.getJSONObject("services").getJSONObject("mysql");
            real("the MySQL row shows it running: " + line.optString("version"), v != null && v.equals(line.optString("version"))
                    && line.optBoolean("running") && line.getBoolean("installed"));
            real("and the panel's Java is there: " + other(everything, "java").optString("version"), other(everything, "java").optBoolean("running"));
            db.close();
        }

        System.out.println("\n" + (failed == 0 ? "ALL GREEN" : failed + " CHECKS FAILED"));
        System.exit(failed == 0 ? 0 : 1);
    }
}
