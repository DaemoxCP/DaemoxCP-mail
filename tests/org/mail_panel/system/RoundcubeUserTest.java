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
 * Roundcube dal pool www (l'utente di nginx) al pool roundcube (RoundcubeUser.migrate), in una
 * cartella temporanea con file, proprietari e permessi veri, e con php-fpm, nginx e la webmail
 * finti. Il php-fpm finto, ricaricato, fa girare i pool che trova nei file, come quello vero.
 *
 * <p>Per ogni passo che puo' andare male c'e' un guasto piantato, e la prova vuole che la
 * migrazione torni indietro lasciando OGNI file com'era: contenuto, proprietario, gruppo e
 * permessi, confrontati con una fotografia presa prima. Poi i rifiuti (un www.conf non del
 * pannello, un pool che serve anche un altro sito, una webmail che gia' non risponde), i link
 * messi dentro logs da chi aveva preso www (non si seguono), la seconda volta (non fa niente) e le
 * derive (un aggiornamento di Roundcube che rimette logs a www, il pacchetto di PHP che ricopia
 * www.conf.default).
 *
 * <p>Tocca proprietari veri: va lanciata da root sulla VM FreeBSD, dove esistono www e wheel, e
 * crea l'utente roundcube se manca (come la migrazione vera).
 *   java -cp "tests:&lt;dir&gt;/freebsd-mail-panel-1.0.jar" org.mail_panel.system.RoundcubeUserTest
 */
public class RoundcubeUserTest {

    static int failed = 0;
    static final PrintStream OUT = System.out;

    static void check(String what, boolean ok) {
        OUT.println((ok ? "  OK   " : "  FALLITO ") + what);
        if (!ok) failed++;
    }

    /** Il www.conf che scriveva FullMailServerScript prima di questa versione. */
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
    static final String WWW_DEFAULT = "; il campione di php84\n[www]\nuser = www\ngroup = www\nlisten = 127.0.0.1:9000\npm = dynamic\npm.max_children = 5\n";
    static final String ROTATION_SAMPLE = """
            # logfilename                 [owner:group] mode count size when  flags [/pid_file] [sig_num]
            /usr/local/www/roundcube/logs/errors.log    www:www       644  10    1000 *     XCBN
            /usr/local/www/roundcube/logs/sendmail.log  www:www       644  10    1000 *     XCBN
            """;
    static final String PHP_ROTATION = "# Registro degli errori di PHP (scritto dall'installazione del pannello mail)\n"
            + "/var/log/php_errors.log    www:www    640    7    1024    *    JC\n";

    /** nginx.conf come lo scrive regenerateNginxRoundcubeConfig, con la radice della webmail data. */
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
                        server_name webmail.prova.local;
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

    /** Un server di posta in miniatura: i file della webmail coi proprietari di prima. */
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
            write(rc.resolve("plugins/mailpanel_sso/mailpanel_sso.php"), "<?php // codice\n", "www", "www", "rw-r--r--");
            write(rc.resolve("plugins/mailpanel_sso/config.inc.php"), "<?php // segreto\n", "www", "www", "rw-------");
            dir(rc.resolve("temp"), "www", "www", "rwxr-xr-x");
            write(rc.resolve("temp/upload.tmp"), "allegato\n", "www", "www", "rw-r--r--");
            dir(rc.resolve("logs"), "www", "www", "rwxr-xr-x");
            write(rc.resolve("logs/errors.log"), "", "www", "www", "rw-r--r--");
            write(rc.resolve("logs/userlogins.log"), "[x] Successful login\n", "www", "www", "rw-r-----");
            // Un link messo da chi aveva preso www: root non deve seguirlo.
            write(outside, "di root\n", "root", "wheel", "rw-------");
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

    /** Ogni file sotto la cartella: contenuto (hash), proprietario, gruppo, permessi. */
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

    /** php-fpm, nginx e la webmail finti. Il php-fpm ricaricato fa girare i pool scritti nei file. */
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

    /** Un guasto piantato: la migrazione torna indietro e lascia ogni file com'era. */
    static void plantedFault(String what, java.util.function.Consumer<Fake> plant, int fpmReloadsAfter, int nginxReloadsAfter) throws Exception {
        OUT.println("\n-- guasto piantato: " + what);
        Bench b = new Bench();
        try {
            Map<String, String> before = photo(b.root);
            Fake f = new Fake(b);
            plant.accept(f);
            RoundcubeUser.Report r = RoundcubeUser.migrate(b.at, f);
            OUT.println("     " + r.outcome() + ": " + r.detail());
            check("torna indietro (ROLLED_BACK)", r.outcome() == RoundcubeUser.Outcome.ROLLED_BACK);
            check("e non dice EXCEPT", !r.detail().contains("EXCEPT"));
            Map<String, String> after = photo(b.root);
            check("ogni file com'era: contenuto, proprietario, permessi", before.equals(after));
            if (!before.equals(after))
                for (String k : after.keySet()) if (!after.get(k).equals(before.get(k))) OUT.println("       diverso: " + k + " " + before.get(k) + " -> " + after.get(k));
            check("php-fpm ricaricato " + fpmReloadsAfter + " volte (anche per tornare indietro)", f.fpmReloads == fpmReloadsAfter);
            check("nginx ricaricato " + nginxReloadsAfter + " volte", f.nginxReloads == nginxReloadsAfter);
        } finally { b.clean(); }
    }

    /** Un rifiuto: niente cambia. */
    static void refusal(String what, RoundcubeUser.Outcome expected, ThrowingConsumer<Bench> prepare, java.util.function.Consumer<Fake> plant) throws Exception {
        OUT.println("\n-- rifiuto: " + what);
        Bench b = new Bench();
        try {
            prepare.accept(b);
            Map<String, String> before = photo(b.root);
            Fake f = new Fake(b);
            plant.accept(f);
            RoundcubeUser.Report r = RoundcubeUser.migrate(b.at, f);
            OUT.println("     " + r.outcome() + ": " + r.detail());
            check("esito " + expected, r.outcome() == expected);
            check("nessun file cambiato", before.equals(photo(b.root)));
            check("nessun ricaricamento", f.fpmReloads + f.nginxReloads == 0);
        } finally { b.clean(); }
    }

    interface ThrowingConsumer<T> { void accept(T t) throws Exception; }

    public static void main(String[] args) throws Exception {
        if (!"root".equals(System.getProperty("user.name")) || !System.getProperty("os.name").contains("FreeBSD")) {
            OUT.println("Questa prova cambia proprietari veri: va lanciata da root sulla VM FreeBSD.");
            System.exit(2);
        }

        OUT.println("== I pezzi");
        List<RoundcubeUser.Pool> pools = RoundcubeUser.pools("; c\n[www]\nuser = www\nlisten = /var/run/php-fpm.sock\n[b]\nuser=x\n");
        check("due pool letti, coi valori", pools.size() == 2 && "www".equals(pools.get(0).get("user")) && "x".equals(pools.get(1).get("user")));
        check("un percorso diventa unix: per nginx", "unix:/a.sock".equals(RoundcubeUser.nginxForm("/a.sock"))
                && "127.0.0.1:9000".equals(RoundcubeUser.nginxForm("127.0.0.1:9000")));
        Map<Path, String> files = RoundcubeUser.configFiles("# configuration file /a.conf:\nuno\n# configuration file /b.conf:\ndue\n");
        check("nginx -T diviso nei suoi file", files.size() == 2 && files.get(Path.of("/b.conf")).trim().equals("due"));
        check("un # fra virgolette non e' un commento", RoundcubeUser.withoutComments("a \"x#y\"; # via\nb").equals("a \"x#y\"; \nb"));
        String two = nginx(Path.of("/rc"), "unix:/var/run/php-fpm.sock", "    server { listen 80; # fastcgi_pass unix:/var/run/php-fpm.sock;\n    }\n");
        List<String> blocks = RoundcubeUser.serverBlocks(RoundcubeUser.withoutComments(two));
        check("tre blocchi server, non l'upstream (" + blocks.size() + ")", blocks.size() == 3);
        List<RoundcubeUser.Site> sites = RoundcubeUser.sitesPassingTo(Map.of(Path.of("/n"), two), "unix:/var/run/php-fpm.sock", Path.of("/rc"));
        check("un solo sito passa al pool (il commento nell'altro non conta)", sites.size() == 1 && sites.get(0).roundcube());
        check("nome e porta del sito", sites.size() == 1 && "webmail.prova.local".equals(sites.get(0).name()) && "8443".equals(sites.get(0).port()));
        check("fastcgi_pass spostato sul socket nuovo", RoundcubeUser.repointed(two, "unix:/var/run/php-fpm.sock")
                .contains("fastcgi_pass unix:" + RoundcubeUser.SOCKET + ";"));
        String pool = RoundcubeUser.poolConf("pm = static\npm.max_children = 4\n");
        List<RoundcubeUser.Pool> pp = RoundcubeUser.pools(pool);
        check("il pool nuovo: roundcube, socket suo, nginx nel gruppo, pm portati",
                pp.size() == 1 && "roundcube".equals(pp.get(0).get("user")) && RoundcubeUser.SOCKET.equals(pp.get(0).get("listen"))
                && "www".equals(pp.get(0).get("listen.group")) && "static".equals(pp.get(0).get("pm")));
        check("il segnaposto di www.conf non ha pool, e nessun '#'", RoundcubeUser.pools(RoundcubeUser.wwwPlaceholder()).isEmpty()
                && RoundcubeUser.wwwPlaceholder().lines().allMatch(l -> l.startsWith(";")));

        OUT.println("\n== Gli script d'installazione nascono col pool roundcube");
        Map<String, String> scripts = new LinkedHashMap<>();
        scripts.put("FullMailServerScript", new FullMailServerScript().getScriptContent());
        scripts.put("RoundcubeScript", new RoundcubeScript().getScriptContent());
        scripts.put("FullMailStackScript", new FullMailStackScript().getScriptContent());
        for (Map.Entry<String, String> e : scripts.entrySet()) {
            String s = e.getValue();
            check(e.getKey() + ": scrive il pool roundcube e il segnaposto", s.contains(RoundcubeUser.poolConf(null)) && s.contains(RoundcubeUser.wwwPlaceholder()));
            check(e.getKey() + ": nessun 'user = www', nessun 'chown -R www:www'", !s.contains("user = www") && !s.contains("chown -R www:www"));
            check(e.getKey() + ": nginx passa al socket di roundcube", s.contains("fastcgi_pass unix:" + RoundcubeUser.SOCKET + ";")
                    && !s.contains("fastcgi_pass unix:/var/run/php-fpm.sock;") && !s.contains("fastcgi_pass 127.0.0.1:9000;"));
            check(e.getKey() + ": config.inc.php a root:roundcube", s.contains("chown root:roundcube /usr/local/www/roundcube/config/config.inc.php"));
        }
        check("FullMailServerScript: la rotazione degli errori di PHP e' di roundcube",
                scripts.get("FullMailServerScript").contains(RoundcubeUser.phpErrorsRotationLine()));
        check("FullMailServerScript: la chiave SSO non e' piu' di www", !scripts.get("FullMailServerScript").contains("chown root:www"));

        OUT.println("\n== La migrazione che riesce");
        Bench b = new Bench();
        try {
            Fake f = new Fake(b);
            RoundcubeUser.Report r = RoundcubeUser.migrate(b.at, f);
            OUT.println("     " + r.outcome() + ": " + r.detail());
            check("DONE", r.outcome() == RoundcubeUser.Outcome.DONE);
            check("il pool roundcube coi pm di prima", Files.readString(b.fpm.resolve("roundcube.conf")).equals(RoundcubeUser.poolConf(
                    "pm = dynamic\npm.max_children = 10\npm.start_servers = 3\npm.min_spare_servers = 2\npm.max_spare_servers = 5\n")));
            check("www.conf senza pool", Files.readString(b.fpm.resolve("www.conf")).equals(RoundcubeUser.wwwPlaceholder()));
            check("nginx passa al socket nuovo", Files.readString(b.nginxConf).contains("fastcgi_pass unix:" + RoundcubeUser.SOCKET + ";"));
            check("php-fpm fa girare roundcube come roundcube, e nient'altro", f.running.equals(Map.of("roundcube", Set.of("roundcube"))));
            check("php-fpm -t e nginx -t chiesti", f.fpmTests == 1 && f.nginxTests == 1);
            check("config.inc.php root:roundcube 640", owner(b.rc.resolve("config/config.inc.php")).equals("root:roundcube rw-r-----"));
            check("plugin SSO: codice di root", owner(b.rc.resolve("plugins/mailpanel_sso")).equals("root:wheel rwxr-xr-x")
                    && owner(b.rc.resolve("plugins/mailpanel_sso/mailpanel_sso.php")).equals("root:wheel rw-r--r--"));
            check("plugin SSO: configurazione root:roundcube 640", owner(b.rc.resolve("plugins/mailpanel_sso/config.inc.php")).equals("root:roundcube rw-r-----"));
            check("temp di roundcube 700, e il suo contenuto", owner(b.rc.resolve("temp")).equals("roundcube:roundcube rwx------")
                    && owner(b.rc.resolve("temp/upload.tmp")).startsWith("roundcube:roundcube rw-r-----"));
            check("logs di roundcube 750, coi log", owner(b.rc.resolve("logs")).equals("roundcube:roundcube rwxr-x---")
                    && owner(b.rc.resolve("logs/userlogins.log")).equals("roundcube:roundcube rw-r-----"));
            check("il link in logs non e' stato seguito: il file fuori resta di root", owner(b.outside).equals("root:wheel rw-------"));
            check("sessioni di roundcube", owner(b.sessions).equals("roundcube:roundcube rwx------") && owner(b.sessions.resolve("sess_abc")).startsWith("roundcube:roundcube"));
            check("registro degli errori di PHP di roundcube", owner(b.phpErrors).equals("roundcube:roundcube rw-r-----"));
            check("la chiave SSO solo di root", owner(b.ssoKey).equals("root:wheel rw-------"));
            check("rotazione degli errori di PHP: roundcube:roundcube", Files.readString(b.newsyslog.resolve("php-errors.conf")).contains(" roundcube:roundcube "));
            check("rotazione di Roundcube riscritta col proprietario giusto", Files.readString(b.newsyslog.resolve("roundcube.conf"))
                    .contains(b.rc + "/logs/errors.log    roundcube:roundcube"));
            check("le copie di prima nella cartella di backup", Files.isDirectory(b.backup));

            OUT.println("\n-- la seconda volta");
            Map<String, String> photo = photo(b.root);
            int reloads = f.fpmReloads + f.nginxReloads;
            r = RoundcubeUser.migrate(b.at, f);
            check("NOTHING (" + r.outcome() + ")", r.outcome() == RoundcubeUser.Outcome.NOTHING);
            check("nessun file cambiato, nessun ricaricamento", photo.equals(photo(b.root)) && reloads == f.fpmReloads + f.nginxReloads);

            OUT.println("\n-- un aggiornamento di Roundcube rimette temp e logs a www:www (il post-install del pacchetto)");
            own(b.rc.resolve("temp"), "www", "www", "rwxr-xr-x");
            own(b.rc.resolve("logs"), "www", "www", "rwxr-xr-x");
            r = RoundcubeUser.migrate(b.at, f);
            OUT.println("     " + r.outcome() + ": " + r.detail());
            check("REPAIRED", r.outcome() == RoundcubeUser.Outcome.REPAIRED);
            check("temp e logs tornati a roundcube", owner(b.rc.resolve("temp")).equals("roundcube:roundcube rwx------")
                    && owner(b.rc.resolve("logs")).equals("roundcube:roundcube rwxr-x---"));
            check("senza ricaricare niente", reloads == f.fpmReloads + f.nginxReloads);

            OUT.println("\n-- il pacchetto di PHP ricopia www.conf.default (qualcuno aveva tolto il segnaposto)");
            Files.writeString(b.fpm.resolve("www.conf"), WWW_DEFAULT);
            f.running = f.poolsInFiles();
            r = RoundcubeUser.migrate(b.at, f);
            OUT.println("     " + r.outcome() + ": " + r.detail());
            check("REPAIRED, col segnaposto di nuovo", r.outcome() == RoundcubeUser.Outcome.REPAIRED
                    && Files.readString(b.fpm.resolve("www.conf")).equals(RoundcubeUser.wwwPlaceholder()));
            check("php-fpm ricaricato: niente piu' pool www", !f.running.containsKey("www"));

            OUT.println("\n-- un www.conf con un pool scritto da qualcuno");
            Files.writeString(b.fpm.resolve("www.conf"), "[www]\nuser = www\nlisten = 127.0.0.1:9100\n");
            r = RoundcubeUser.migrate(b.at, f);
            OUT.println("     " + r.outcome() + ": " + r.detail());
            check("NOT_OURS, e il file resta suo", r.outcome() == RoundcubeUser.Outcome.NOT_OURS
                    && Files.readString(b.fpm.resolve("www.conf")).contains("9100"));
        } finally { b.clean(); }

        OUT.println("\n== I guasti piantati: ogni passo fallito rimette tutto");
        plantedFault("php-fpm -t rifiuta il pool nuovo", f -> f.fpmTestFails = true, 0, 0);
        plantedFault("nginx -t rifiuta il socket nuovo", f -> f.nginxTestFails = true, 0, 0);
        plantedFault("il reload di php-fpm fallisce", f -> f.fpmReloadFails = true, 2, 0);
        plantedFault("php-fpm continua a far girare il pool www", f -> f.fpmKeepsOldPools = true, 2, 0);
        plantedFault("il reload di nginx fallisce", f -> f.nginxReloadFails = true, 2, 2);
        plantedFault("la webmail non risponde dopo lo scambio", f -> f.answersAfter = false, 2, 2);

        OUT.println("\n-- guasto piantato: nginx non si ricarica nemmeno tornando indietro");
        Bench n = new Bench();
        try {
            Fake f = new Fake(n);
            f.nginxNeverReloads = true;
            RoundcubeUser.Report r = RoundcubeUser.migrate(n.at, f);
            OUT.println("     " + r.outcome() + ": " + r.detail());
            check("ROLLED_BACK, e lo dice: EXCEPT nginx reload", r.outcome() == RoundcubeUser.Outcome.ROLLED_BACK
                    && r.detail().contains("EXCEPT: nginx reload"));
        } finally { n.clean(); }

        OUT.println("\n-- guasto piantato: un file che non si puo' cambiare (chflags schg) a meta' strada");
        Bench s = new Bench();
        try {
            Map<String, String> before = photo(s.root);
            check("chflags schg piantato", Shell.run("chflags", "schg", s.phpErrors.toString()).success());
            Fake f = new Fake(s);
            RoundcubeUser.Report r = RoundcubeUser.migrate(s.at, f);
            OUT.println("     " + r.outcome() + ": " + r.detail());
            check("ROLLED_BACK", r.outcome() == RoundcubeUser.Outcome.ROLLED_BACK);
            Shell.run("chflags", "noschg", s.phpErrors.toString());
            check("ogni file com'era", before.equals(photo(s.root)));
        } finally { s.clean(); }

        OUT.println("\n== I rifiuti: niente cambia");
        refusal("www.conf con due pool", RoundcubeUser.Outcome.NOT_OURS,
                bb -> Files.writeString(bb.fpm.resolve("www.conf"), PANEL_WWW + "[other]\nuser = nobody\nlisten = /tmp/o.sock\n"), f -> {});
        refusal("il pool www non gira come www", RoundcubeUser.Outcome.NOT_OURS,
                bb -> Files.writeString(bb.fpm.resolve("www.conf"), PANEL_WWW.replace("user = www", "user = nobody")), f -> {});
        refusal("il pool www serve anche un altro sito", RoundcubeUser.Outcome.OTHER_SITES,
                bb -> Files.writeString(bb.nginxConf, nginx(bb.rc, "unix:/var/run/php-fpm.sock",
                        "    server { listen 8444; server_name blog.local; root /usr/local/www/blog;\n        location ~ \\.php { fastcgi_pass unix:/var/run/php-fpm.sock; }\n    }\n")), f -> {});
        refusal("nginx non passa la webmail al pool www", RoundcubeUser.Outcome.NOT_SERVED,
                bb -> Files.writeString(bb.nginxConf, nginx(bb.rc, "127.0.0.1:9000", "")), f -> {});
        refusal("la webmail gia' non risponde", RoundcubeUser.Outcome.NOT_ANSWERING, bb -> {}, f -> f.answersBefore = false);
        refusal("nginx -T non risponde", RoundcubeUser.Outcome.NGINX_UNREADABLE, bb -> {}, f -> f.dumpNull = true);
        refusal("Roundcube non c'e'", RoundcubeUser.Outcome.NOTHING, bb -> {
            try (Stream<Path> st = Files.walk(bb.rc)) {
                for (Path p : st.sorted(java.util.Comparator.reverseOrder()).toList()) Files.delete(p);
            }
        }, f -> {});

        OUT.println();
        OUT.println(failed == 0 ? "TUTTO OK" : "FALLITE: " + failed);
        if (failed > 0) System.exit(1);
    }
}
