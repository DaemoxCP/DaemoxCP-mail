package org.mail_panel.system;

import org.mail_panel.scripts.FullMailServerScript;
import org.mail_panel.scripts.FullMailStackScript;
import org.mail_panel.scripts.RoundcubeScript;
import org.mail_panel.util.Shell;

import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Stream;

/**
 * Roundcube from the www pool (nginx's user) to the roundcube pool (RoundcubeUser.migrate), in a
 * temporary folder with real files, owners and permissions, and with a fake php-fpm, nginx and
 * webmail. The fake php-fpm, reloaded, runs the pools it finds in the files, like the real one.
 *
 * <p>For every step that can go wrong there is a planted fault, and the test wants the migration to
 * go back leaving EVERY file as it was: content, owner, group and permissions, compared with a photo
 * taken before. Then the refusals (a www.conf that is not the panel's, a pool also serving another
 * site, a webmail that already does not answer), the links put inside logs by whoever had taken www
 * (not followed), the second time (it does nothing) and the drifts (a Roundcube upgrade that puts
 * logs back to www, the PHP package that copies
 * www.conf.default again).
 *
 * <p>It touches real owners: it must be run as root on the FreeBSD VM, where www and wheel exist,
 * and it creates the roundcube user if missing (like the real migration).
 *   java -cp "tests:&lt;dir&gt;/freebsd-mail-panel-1.0.jar" org.mail_panel.system.RoundcubeUserTest
 */
public class RoundcubeUserTest {

    static int failed = 0;
    static final PrintStream OUT = System.out;

    static void check(String what, boolean ok) {
        OUT.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    /** The www.conf FullMailServerScript wrote before this version. */
    static final String PANEL_WWW = """
            [www]
            user = www
            group = www
            listen = /var/run/php-fpm.sock
            listen.owner = www
            listen.group = www
            listen.mode = 0660
            pm = dynamic
            pm.max_children = 10
            pm.start_servers = 3
            pm.min_spare_servers = 2
            pm.max_spare_servers = 5
            """;
    static final String WWW_DEFAULT = "; php84's sample\n[www]\nuser = www\ngroup = www\nlisten = 127.0.0.1:9000\npm = dynamic\npm.max_children = 5\n";
    static final String ROTATION_SAMPLE = """
            # logfilename                 [owner:group] mode count size when  flags [/pid_file] [sig_num]
            /usr/local/www/roundcube/logs/errors.log    www:www       644  10    1000 *     XCBN
            /usr/local/www/roundcube/logs/sendmail.log  www:www       644  10    1000 *     XCBN
            """;
    static final String PHP_ROTATION = "# PHP error log (written by the mail panel's installation)\n"
            + "/var/log/php_errors.log    www:www    640    7    1024    *    JC\n";

    /** nginx.conf as regenerateNginxRoundcubeConfig writes it, with the given webmail root. */
    static String nginx(Path rc, String pass, String extraServer) {
        return """
                worker_processes auto;
                http {
                    include mime.types;
                    upstream other { server 127.0.0.1:9001; }
                    # Default server: reject requests on non-matching hostnames
                    server {
                        listen 8443 ssl default_server;
                        server_name _;
                        return 444;
                    }
                    # Roundcube webmail: responds ONLY to the configured domain
                    server {
                        listen 8443 ssl;
                        server_name webmail.test.local;
                        root %s/public_html;
                        index index.php;
                        location / { try_files $uri $uri/ /index.php?$args; }
                        location ~ \\.php {
                            include fastcgi_params;
                            fastcgi_split_path_info ^(.+\\.php)(/.+)$;
                            fastcgi_pass %s;
                        }
                        location ~ /\\. { deny all; }
                    }
                %s}
                """.formatted(rc, pass, extraServer);
    }

    /** A mail server in miniature: the webmail's files with the old owners. */
    static final class Bench {
        final Path root, fpm, rc, sessions, phpErrors, newsyslog, sample, ssoKey, backup, nginxConf, outside;
        final RoundcubeUser.Places at;

        Bench() throws Exception {
            root = Files.createTempDirectory(Path.of("/var/tmp"), "rcuser-");
            fpm = Files.createDirectories(root.resolve("php-fpm.d"));
            rc = root.resolve("roundcube");
            sessions = root.resolve("php_sessions");
            phpErrors = root.resolve("php_errors.log");
            newsyslog = Files.createDirectories(root.resolve("newsyslog.conf.d"));
            sample = root.resolve("roundcube-newsyslog.sample");
            ssoKey = root.resolve("roundcube_sso.key");
            backup = root.resolve("backup");
            nginxConf = root.resolve("nginx.conf");
            outside = root.resolve("outside-secret");
            at = new RoundcubeUser.Places(fpm, rc, sessions, phpErrors, newsyslog, sample, ssoKey, backup);

            write(fpm.resolve("www.conf"), PANEL_WWW, "root", "wheel", "rw-r--r--");
            write(fpm.resolve("www.conf.default"), WWW_DEFAULT, "root", "wheel", "rw-r--r--");
            dir(rc, "root", "wheel", "rwxr-xr-x");
            dir(rc.resolve("public_html"), "root", "wheel", "rwxr-xr-x");
            dir(rc.resolve("config"), "root", "wheel", "rwxr-xr-x");
            write(rc.resolve("config/config.inc.php"), "<?php $config['des_key'] = 'x';\n", "root", "www", "rw-r-----");
            dir(rc.resolve("plugins"), "root", "wheel", "rwxr-xr-x");
            dir(rc.resolve("plugins/mailpanel_sso"), "www", "www", "rwxr-xr-x");
            write(rc.resolve("plugins/mailpanel_sso/mailpanel_sso.php"), "<?php // code\n", "www", "www", "rw-r--r--");
            write(rc.resolve("plugins/mailpanel_sso/config.inc.php"), "<?php // secret\n", "www", "www", "rw-------");
            dir(rc.resolve("temp"), "www", "www", "rwxr-xr-x");
            write(rc.resolve("temp/upload.tmp"), "attachment\n", "www", "www", "rw-r--r--");
            dir(rc.resolve("logs"), "www", "www", "rwxr-xr-x");
            write(rc.resolve("logs/errors.log"), "", "www", "www", "rw-r--r--");
            write(rc.resolve("logs/userlogins.log"), "[x] Successful login\n", "www", "www", "rw-r-----");
            // A link put by whoever had taken www: root must not follow it.
            write(outside, "root's\n", "root", "wheel", "rw-------");
            Files.createSymbolicLink(rc.resolve("logs/evil"), outside);
            dir(sessions, "www", "www", "rwx------");
            write(sessions.resolve("sess_abc"), "x", "www", "www", "rw-------");
            write(phpErrors, "", "www", "www", "rw-r-----");
            write(newsyslog.resolve("php-errors.conf"), PHP_ROTATION.replace("/var/log/php_errors.log", phpErrors.toString()), "root", "wheel", "rw-r--r--");
            String rot = ROTATION_SAMPLE.replace("/usr/local/www/roundcube", rc.toString());
            write(sample, rot, "root", "wheel", "rw-r--r--");
            write(newsyslog.resolve("roundcube.conf"), rot, "root", "wheel", "rw-r--r--");
            write(ssoKey, "0123456789abcdef0123456789abcdef", "root", "www", "rw-r-----");
            write(nginxConf, nginx(rc, "unix:/var/run/php-fpm.sock", ""), "root", "wheel", "rw-r--r--");
        }

        void clean() throws Exception {
            Shell.run("chflags", "-R", "noschg", root.toString());
            try (Stream<Path> s = Files.walk(root)) {
                for (Path p : s.sorted(java.util.Comparator.reverseOrder()).toList()) Files.deleteIfExists(p);
            }
        }
    }

    static void write(Path p, String content, String user, String group, String mode) throws Exception {
        Files.writeString(p, content, StandardCharsets.UTF_8);
        own(p, user, group, mode);
    }

    static void dir(Path p, String user, String group, String mode) throws Exception {
        Files.createDirectories(p);
        own(p, user, group, mode);
    }

    static void own(Path p, String user, String group, String mode) throws Exception {
        var names = p.getFileSystem().getUserPrincipalLookupService();
        Files.setOwner(p, names.lookupPrincipalByName(user));
        Files.getFileAttributeView(p, java.nio.file.attribute.PosixFileAttributeView.class).setGroup(names.lookupPrincipalByGroupName(group));
        Files.setPosixFilePermissions(p, PosixFilePermissions.fromString(mode));
    }

    static String owner(Path p) throws Exception {
        PosixFileAttributes a = Files.readAttributes(p, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        return a.owner().getName() + ":" + a.group().getName() + " " + PosixFilePermissions.toString(a.permissions());
    }

    /** Every file under the folder: content (hash), owner, group, permissions. */
    static Map<String, String> photo(Path root) throws Exception {
        Map<String, String> m = new TreeMap<>();
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        try (Stream<Path> s = Files.walk(root)) {
            for (Path p : s.toList()) {
                if (p.startsWith(root.resolve("backup"))) continue;
                String what = Files.isSymbolicLink(p) ? "link->" + Files.readSymbolicLink(p)
                        : Files.isDirectory(p, LinkOption.NOFOLLOW_LINKS) ? "dir"
                        : HexFormat.of().formatHex(sha.digest(Files.readAllBytes(p)));
                m.put(root.relativize(p).toString(), what + " " + owner(p));
            }
        }
        return m;
    }

    /** Fake php-fpm, nginx and webmail. The reloaded php-fpm runs the pools written in the files. */
    static final class Fake implements RoundcubeUser.Services {
        final Bench b;
        boolean dumpNull, fpmTestFails, nginxTestFails, fpmReloadFails, nginxReloadFails, nginxNeverReloads, fpmKeepsOldPools;
        boolean answersBefore = true, answersAfter = true;
        int fpmTests, fpmReloads, nginxTests, nginxReloads;
        Map<String, Set<String>> running;
        Fake(Bench b) { this.b = b; running = poolsInFiles(); }

        Map<String, Set<String>> poolsInFiles() {
            Map<String, Set<String>> m = new TreeMap<>();
            try (Stream<Path> s = Files.list(b.fpm)) {
                for (Path f : s.filter(x -> x.toString().endsWith(".conf")).toList())
                    for (RoundcubeUser.Pool p : RoundcubeUser.pools(Files.readString(f)))
                        m.put(p.name(), Set.of(p.get("user")));
            } catch (Exception e) { throw new RuntimeException(e); }
            return m;
        }

        @Override public String nginxDump() {
            if (dumpNull) return null;
            try { return "# configuration file " + b.nginxConf + ":\n" + Files.readString(b.nginxConf); }
            catch (Exception e) { return null; }
        }
        @Override public Shell.Result nginxTest() { nginxTests++; return r(!nginxTestFails, "nginx: [emerg] planted"); }
        @Override public Shell.Result nginxReload() {
            nginxReloads++;
            return r(!(nginxNeverReloads || nginxReloadFails && nginxReloads == 1), "planted reload failure");
        }
        @Override public Shell.Result phpFpmTest() { fpmTests++; return r(!fpmTestFails, "ERROR: planted"); }
        @Override public Shell.Result phpFpmReload() {
            fpmReloads++;
            if (fpmReloadFails && fpmReloads == 1) return r(false, "planted reload failure");
            if (!fpmKeepsOldPools) running = poolsInFiles();
            return r(true, "");
        }
        @Override public boolean ensureUser() { return Shell.run("pw", "usershow", RoundcubeUser.USER).success()
                || (Shell.run("pw", "groupadd", RoundcubeUser.GROUP).exitCode() >= 0
                    && Shell.run("pw", "useradd", RoundcubeUser.USER, "-g", RoundcubeUser.GROUP, "-d", "/nonexistent", "-s", "/usr/sbin/nologin").success()); }
        @Override public Map<String, Set<String>> poolUsers() { return running; }
        @Override public boolean webmailAnswers(String name, String port) {
            boolean switched;
            try { switched = Files.readString(b.nginxConf).contains(RoundcubeUser.SOCKET); } catch (Exception e) { return false; }
            return switched ? answersAfter : answersBefore;
        }
        @Override public void pause() {}

        static Shell.Result r(boolean ok, String out) { return new Shell.Result(ok ? 0 : 1, ok ? "" : out, false, List.of()); }
    }

    /** A planted fault: the migration goes back and leaves every file as it was. */
    static void plantedFault(String what, java.util.function.Consumer<Fake> plant, int fpmReloadsAfter, int nginxReloadsAfter) throws Exception {
        OUT.println("\n-- planted fault: " + what);
        Bench b = new Bench();
        try {
            Map<String, String> before = photo(b.root);
            Fake f = new Fake(b);
            plant.accept(f);
            RoundcubeUser.Report r = RoundcubeUser.migrate(b.at, f);
            OUT.println("     " + r.outcome() + ": " + r.detail());
            check("it goes back (ROLLED_BACK)", r.outcome() == RoundcubeUser.Outcome.ROLLED_BACK);
            check("and it does not say EXCEPT", !r.detail().contains("EXCEPT"));
            Map<String, String> after = photo(b.root);
            check("every file as it was: content, owner, permissions", before.equals(after));
            if (!before.equals(after))
                for (String k : after.keySet()) if (!after.get(k).equals(before.get(k))) OUT.println("       different: " + k + " " + before.get(k) + " -> " + after.get(k));
            check("php-fpm reloaded " + fpmReloadsAfter + " times (also to go back)", f.fpmReloads == fpmReloadsAfter);
            check("nginx reloaded " + nginxReloadsAfter + " times", f.nginxReloads == nginxReloadsAfter);
        } finally { b.clean(); }
    }

    /** A refusal: nothing changes. */
    static void refusal(String what, RoundcubeUser.Outcome expected, ThrowingConsumer<Bench> prepare, java.util.function.Consumer<Fake> plant) throws Exception {
        OUT.println("\n-- refusal: " + what);
        Bench b = new Bench();
        try {
            prepare.accept(b);
            Map<String, String> before = photo(b.root);
            Fake f = new Fake(b);
            plant.accept(f);
            RoundcubeUser.Report r = RoundcubeUser.migrate(b.at, f);
            OUT.println("     " + r.outcome() + ": " + r.detail());
            check("outcome " + expected, r.outcome() == expected);
            check("no file changed", before.equals(photo(b.root)));
            check("no reload", f.fpmReloads + f.nginxReloads == 0);
        } finally { b.clean(); }
    }

    interface ThrowingConsumer<T> { void accept(T t) throws Exception; }

    public static void main(String[] args) throws Exception {
        if (!"root".equals(System.getProperty("user.name")) || !System.getProperty("os.name").contains("FreeBSD")) {
            OUT.println("This test changes real owners: it must be run as root on the FreeBSD VM.");
            System.exit(2);
        }

        OUT.println("== The pieces");
        List<RoundcubeUser.Pool> pools = RoundcubeUser.pools("; c\n[www]\nuser = www\nlisten = /var/run/php-fpm.sock\n[b]\nuser=x\n");
        check("two pools read, with the values", pools.size() == 2 && "www".equals(pools.get(0).get("user")) && "x".equals(pools.get(1).get("user")));
        check("a path becomes unix: for nginx", "unix:/a.sock".equals(RoundcubeUser.nginxForm("/a.sock"))
                && "127.0.0.1:9000".equals(RoundcubeUser.nginxForm("127.0.0.1:9000")));
        Map<Path, String> files = RoundcubeUser.configFiles("# configuration file /a.conf:\none\n# configuration file /b.conf:\ntwo\n");
        check("nginx -T split into its files", files.size() == 2 && files.get(Path.of("/b.conf")).trim().equals("two"));
        check("a # inside quotes is not a comment", RoundcubeUser.withoutComments("a \"x#y\"; # gone\nb").equals("a \"x#y\"; \nb"));
        String two = nginx(Path.of("/rc"), "unix:/var/run/php-fpm.sock", "    server { listen 80; # fastcgi_pass unix:/var/run/php-fpm.sock;\n    }\n");
        List<String> blocks = RoundcubeUser.serverBlocks(RoundcubeUser.withoutComments(two));
        check("three server blocks, not the upstream (" + blocks.size() + ")", blocks.size() == 3);
        List<RoundcubeUser.Site> sites = RoundcubeUser.sitesPassingTo(Map.of(Path.of("/n"), two), "unix:/var/run/php-fpm.sock", Path.of("/rc"));
        check("a single site passes to the pool (the comment in the other does not count)", sites.size() == 1 && sites.get(0).roundcube());
        check("the site's name and port", sites.size() == 1 && "webmail.test.local".equals(sites.get(0).name()) && "8443".equals(sites.get(0).port()));
        check("fastcgi_pass moved to the new socket", RoundcubeUser.repointed(two, "unix:/var/run/php-fpm.sock")
                .contains("fastcgi_pass unix:" + RoundcubeUser.SOCKET + ";"));
        String pool = RoundcubeUser.poolConf("pm = static\npm.max_children = 4\n");
        List<RoundcubeUser.Pool> pp = RoundcubeUser.pools(pool);
        check("the new pool: roundcube, its own socket, nginx in the group, pm carried over",
                pp.size() == 1 && "roundcube".equals(pp.get(0).get("user")) && RoundcubeUser.SOCKET.equals(pp.get(0).get("listen"))
                && "www".equals(pp.get(0).get("listen.group")) && "static".equals(pp.get(0).get("pm")));
        check("the www.conf placeholder has no pool, and no '#'", RoundcubeUser.pools(RoundcubeUser.wwwPlaceholder()).isEmpty()
                && RoundcubeUser.wwwPlaceholder().lines().allMatch(l -> l.startsWith(";")));

        OUT.println("\n== The installation scripts are born with the roundcube pool");
        Map<String, String> scripts = new LinkedHashMap<>();
        scripts.put("FullMailServerScript", new FullMailServerScript().getScriptContent());
        scripts.put("RoundcubeScript", new RoundcubeScript().getScriptContent());
        scripts.put("FullMailStackScript", new FullMailStackScript().getScriptContent());
        for (Map.Entry<String, String> e : scripts.entrySet()) {
            String s = e.getValue();
            check(e.getKey() + ": it writes the roundcube pool and the placeholder", s.contains(RoundcubeUser.poolConf(null)) && s.contains(RoundcubeUser.wwwPlaceholder()));
            check(e.getKey() + ": no 'user = www', no 'chown -R www:www'", !s.contains("user = www") && !s.contains("chown -R www:www"));
            check(e.getKey() + ": nginx passes to roundcube's socket", s.contains("fastcgi_pass unix:" + RoundcubeUser.SOCKET + ";")
                    && !s.contains("fastcgi_pass unix:/var/run/php-fpm.sock;") && !s.contains("fastcgi_pass 127.0.0.1:9000;"));
            check(e.getKey() + ": config.inc.php as root:roundcube", s.contains("chown root:roundcube /usr/local/www/roundcube/config/config.inc.php"));
        }
        check("FullMailServerScript: the PHP errors rotation is roundcube's",
                scripts.get("FullMailServerScript").contains(RoundcubeUser.phpErrorsRotationLine()));
        check("FullMailServerScript: the SSO key is no longer www's", !scripts.get("FullMailServerScript").contains("chown root:www"));

        OUT.println("\n== The migration that succeeds");
        Bench b = new Bench();
        try {
            Fake f = new Fake(b);
            RoundcubeUser.Report r = RoundcubeUser.migrate(b.at, f);
            OUT.println("     " + r.outcome() + ": " + r.detail());
            check("DONE", r.outcome() == RoundcubeUser.Outcome.DONE);
            check("the roundcube pool with the old pm values", Files.readString(b.fpm.resolve("roundcube.conf")).equals(RoundcubeUser.poolConf(
                    "pm = dynamic\npm.max_children = 10\npm.start_servers = 3\npm.min_spare_servers = 2\npm.max_spare_servers = 5\n")));
            check("www.conf without a pool", Files.readString(b.fpm.resolve("www.conf")).equals(RoundcubeUser.wwwPlaceholder()));
            check("nginx passes to the new socket", Files.readString(b.nginxConf).contains("fastcgi_pass unix:" + RoundcubeUser.SOCKET + ";"));
            check("php-fpm runs roundcube as roundcube, and nothing else", f.running.equals(Map.of("roundcube", Set.of("roundcube"))));
            check("php-fpm -t and nginx -t asked", f.fpmTests == 1 && f.nginxTests == 1);
            check("config.inc.php root:roundcube 640", owner(b.rc.resolve("config/config.inc.php")).equals("root:roundcube rw-r-----"));
            check("SSO plugin: code owned by root", owner(b.rc.resolve("plugins/mailpanel_sso")).equals("root:wheel rwxr-xr-x")
                    && owner(b.rc.resolve("plugins/mailpanel_sso/mailpanel_sso.php")).equals("root:wheel rw-r--r--"));
            check("SSO plugin: configuration root:roundcube 640", owner(b.rc.resolve("plugins/mailpanel_sso/config.inc.php")).equals("root:roundcube rw-r-----"));
            check("roundcube's temp 700, and its content", owner(b.rc.resolve("temp")).equals("roundcube:roundcube rwx------")
                    && owner(b.rc.resolve("temp/upload.tmp")).startsWith("roundcube:roundcube rw-r-----"));
            check("roundcube's logs 750, with the logs", owner(b.rc.resolve("logs")).equals("roundcube:roundcube rwxr-x---")
                    && owner(b.rc.resolve("logs/userlogins.log")).equals("roundcube:roundcube rw-r-----"));
            check("the link in logs was not followed: the file outside stays root's", owner(b.outside).equals("root:wheel rw-------"));
            check("roundcube's sessions", owner(b.sessions).equals("roundcube:roundcube rwx------") && owner(b.sessions.resolve("sess_abc")).startsWith("roundcube:roundcube"));
            check("roundcube's PHP error log", owner(b.phpErrors).equals("roundcube:roundcube rw-r-----"));
            check("the SSO key only root's", owner(b.ssoKey).equals("root:wheel rw-------"));
            check("PHP errors rotation: roundcube:roundcube", Files.readString(b.newsyslog.resolve("php-errors.conf")).contains(" roundcube:roundcube "));
            check("Roundcube's rotation rewritten with the right owner", Files.readString(b.newsyslog.resolve("roundcube.conf"))
                    .contains(b.rc + "/logs/errors.log    roundcube:roundcube"));
            check("the old copies in the backup folder", Files.isDirectory(b.backup));

            OUT.println("\n-- the second time");
            Map<String, String> photo = photo(b.root);
            int reloads = f.fpmReloads + f.nginxReloads;
            r = RoundcubeUser.migrate(b.at, f);
            check("NOTHING (" + r.outcome() + ")", r.outcome() == RoundcubeUser.Outcome.NOTHING);
            check("no file changed, no reload", photo.equals(photo(b.root)) && reloads == f.fpmReloads + f.nginxReloads);

            OUT.println("\n-- a Roundcube upgrade puts temp and logs back to www:www (the package's post-install)");
            own(b.rc.resolve("temp"), "www", "www", "rwxr-xr-x");
            own(b.rc.resolve("logs"), "www", "www", "rwxr-xr-x");
            r = RoundcubeUser.migrate(b.at, f);
            OUT.println("     " + r.outcome() + ": " + r.detail());
            check("REPAIRED", r.outcome() == RoundcubeUser.Outcome.REPAIRED);
            check("temp and logs back to roundcube", owner(b.rc.resolve("temp")).equals("roundcube:roundcube rwx------")
                    && owner(b.rc.resolve("logs")).equals("roundcube:roundcube rwxr-x---"));
            check("without reloading anything", reloads == f.fpmReloads + f.nginxReloads);

            OUT.println("\n-- the PHP package copies www.conf.default again (somebody had removed the placeholder)");
            Files.writeString(b.fpm.resolve("www.conf"), WWW_DEFAULT);
            f.running = f.poolsInFiles();
            r = RoundcubeUser.migrate(b.at, f);
            OUT.println("     " + r.outcome() + ": " + r.detail());
            check("REPAIRED, with the placeholder again", r.outcome() == RoundcubeUser.Outcome.REPAIRED
                    && Files.readString(b.fpm.resolve("www.conf")).equals(RoundcubeUser.wwwPlaceholder()));
            check("php-fpm reloaded: no www pool any more", !f.running.containsKey("www"));

            OUT.println("\n-- a www.conf with a pool written by somebody");
            Files.writeString(b.fpm.resolve("www.conf"), "[www]\nuser = www\nlisten = 127.0.0.1:9100\n");
            r = RoundcubeUser.migrate(b.at, f);
            OUT.println("     " + r.outcome() + ": " + r.detail());
            check("NOT_OURS, and the file stays theirs", r.outcome() == RoundcubeUser.Outcome.NOT_OURS
                    && Files.readString(b.fpm.resolve("www.conf")).contains("9100"));
        } finally { b.clean(); }

        OUT.println("\n== The planted faults: every failed step puts everything back");
        plantedFault("php-fpm -t refuses the new pool", f -> f.fpmTestFails = true, 0, 0);
        plantedFault("nginx -t refuses the new socket", f -> f.nginxTestFails = true, 0, 0);
        plantedFault("the php-fpm reload fails", f -> f.fpmReloadFails = true, 2, 0);
        plantedFault("php-fpm keeps running the www pool", f -> f.fpmKeepsOldPools = true, 2, 0);
        plantedFault("the nginx reload fails", f -> f.nginxReloadFails = true, 2, 2);
        plantedFault("the webmail does not answer after the switch", f -> f.answersAfter = false, 2, 2);

        OUT.println("\n-- planted fault: nginx does not reload even when going back");
        Bench n = new Bench();
        try {
            Fake f = new Fake(n);
            f.nginxNeverReloads = true;
            RoundcubeUser.Report r = RoundcubeUser.migrate(n.at, f);
            OUT.println("     " + r.outcome() + ": " + r.detail());
            check("ROLLED_BACK, and it says so: EXCEPT nginx reload", r.outcome() == RoundcubeUser.Outcome.ROLLED_BACK
                    && r.detail().contains("EXCEPT: nginx reload"));
        } finally { n.clean(); }

        OUT.println("\n-- planted fault: a file that cannot be changed (chflags schg) halfway");
        Bench s = new Bench();
        try {
            Map<String, String> before = photo(s.root);
            check("chflags schg planted", Shell.run("chflags", "schg", s.phpErrors.toString()).success());
            Fake f = new Fake(s);
            RoundcubeUser.Report r = RoundcubeUser.migrate(s.at, f);
            OUT.println("     " + r.outcome() + ": " + r.detail());
            check("ROLLED_BACK", r.outcome() == RoundcubeUser.Outcome.ROLLED_BACK);
            Shell.run("chflags", "noschg", s.phpErrors.toString());
            check("every file as it was", before.equals(photo(s.root)));
        } finally { s.clean(); }

        OUT.println("\n== The refusals: nothing changes");
        refusal("www.conf with two pools", RoundcubeUser.Outcome.NOT_OURS,
                bb -> Files.writeString(bb.fpm.resolve("www.conf"), PANEL_WWW + "[other]\nuser = nobody\nlisten = /tmp/o.sock\n"), f -> {});
        refusal("the www pool does not run as www", RoundcubeUser.Outcome.NOT_OURS,
                bb -> Files.writeString(bb.fpm.resolve("www.conf"), PANEL_WWW.replace("user = www", "user = nobody")), f -> {});
        refusal("the www pool also serves another site", RoundcubeUser.Outcome.OTHER_SITES,
                bb -> Files.writeString(bb.nginxConf, nginx(bb.rc, "unix:/var/run/php-fpm.sock",
                        "    server { listen 8444; server_name blog.local; root /usr/local/www/blog;\n        location ~ \\.php { fastcgi_pass unix:/var/run/php-fpm.sock; }\n    }\n")), f -> {});
        refusal("nginx does not pass the webmail to the www pool", RoundcubeUser.Outcome.NOT_SERVED,
                bb -> Files.writeString(bb.nginxConf, nginx(bb.rc, "127.0.0.1:9000", "")), f -> {});
        refusal("the webmail already does not answer", RoundcubeUser.Outcome.NOT_ANSWERING, bb -> {}, f -> f.answersBefore = false);
        refusal("nginx -T does not answer", RoundcubeUser.Outcome.NGINX_UNREADABLE, bb -> {}, f -> f.dumpNull = true);
        refusal("Roundcube is not there", RoundcubeUser.Outcome.NOTHING, bb -> {
            try (Stream<Path> st = Files.walk(bb.rc)) {
                for (Path p : st.sorted(java.util.Comparator.reverseOrder()).toList()) Files.delete(p);
            }
        }, f -> {});

        OUT.println();
        OUT.println(failed == 0 ? "ALL OK" : "FAILED: " + failed);
        if (failed > 0) System.exit(1);
    }
}
