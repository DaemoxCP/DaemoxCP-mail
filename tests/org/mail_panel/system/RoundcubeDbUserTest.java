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
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * La webmail dall'utente MySQL del pannello al suo (RoundcubeDbUser.migrate), con config.inc.php
 * vero in una cartella temporanea (contenuto, proprietario, gruppo, permessi) e MySQL, php-fpm,
 * nginx e la webmail finti. Il MySQL finto esegue le istruzioni che la migrazione gli manda -- e si
 * ferma su una che non conosce --; la webmail finta entra in MySQL col db_dsnw che php-fpm ha
 * caricato all'ultimo reload, come quella vera con opcache.
 *
 * <p>Per ogni controllo c'e' un guasto piantato che solo lui vede, e la prova vuole che la
 * migrazione torni indietro lasciando TUTTO com'era: config.inc.php byte per byte con proprietario,
 * gruppo e permessi, gli account MySQL con password e privilegi, la webmail che risponde. Poi i
 * rifiuti (un altro utente, un altro server, un account roundcube che c'e' gia', un'altra
 * configurazione che entra come il pannello, una webmail che gia' non risponde), la seconda volta
 * (non fa niente, e non chiede nemmeno a root), il caso degli script vecchi (roundcube con la
 * password del pannello) e quello di un avvio fermato prima della revoca.
 *
 * <p>Cambia proprietari veri: va lanciata da root sulla VM FreeBSD, dove esistono www e wheel.
 *   java -cp "tests:&lt;dir&gt;/freebsd-mail-panel-1.0.jar" org.mail_panel.system.RoundcubeDbUserTest
 */
public class RoundcubeDbUserTest {

    static int failed = 0;
    static final PrintStream OUT = System.out;

    static void check(String what, boolean ok) {
        OUT.println((ok ? "  OK   " : "  FALLITO ") + what);
        if (!ok) failed++;
    }

    static final String PANEL_PASS = "PanelPass0123456789abcde";
    static final String SECRET = "RoundcubeSecret01234567x";

    /** config.inc.php come lo scriveva FullMailServerScript, col blocco del plugin password in fondo. */
    static String config(String user, String password) {
        return "<?php\n"
             + "$config['db_dsnw'] = 'mysql://" + user + ":" + password + "@127.0.0.1/roundcubemail';\n"
             + "$config['imap_host'] = 'ssl://127.0.0.1:993';\n"
             + "$config['des_key'] = 'abcdefghijklmnopqrstuvwx';\n"
             + "$config['plugins'] = array('mailpanel_sso', 'archive', 'zipdownload');\n"
             + "\n// BEGIN mail-panel: webmail password changes (rewritten by the panel at startup)\n"
             + "$config['password_driver'] = 'httpapi';\n"
             + "// END mail-panel: webmail password changes\n";
    }

    // ===================== MySQL finto =====================

    /** Un account: la password, i database su cui ha tutto, e il SELECT su tutto (un privilegio globale). */
    static final class Account {
        String password;
        Set<String> dbs = new TreeSet<>();
        boolean globalSelect;
        Account(String password, String... dbs) { this.password = password; this.dbs.addAll(List.of(dbs)); }
        Account copy() { Account a = new Account(password); a.dbs.addAll(dbs); a.globalSelect = globalSelect; return a; }
        @Override public String toString() { return password + dbs + (globalSelect ? "+SELECT*.*" : ""); }
    }

    static final class Fake implements RoundcubeDbUser.Services {
        final Path config;
        final Map<String, Account> accounts = new TreeMap<>();   // "utente@host"
        final Set<String> sessions = new HashSet<>();
        final List<String> rootLog = new ArrayList<>();
        final List<String> unknown = new ArrayList<>();
        long rcConnections = 0;
        int sessionCounter = 0;
        int realLogins = 0;
        boolean performanceSchema = true;
        String loaded;                       // la configurazione che php-fpm ha caricato
        String secret = SECRET;
        // i guasti
        boolean rootDown, createRefused, roundcubeLocked, reloadFails, reloadIgnored, roundcubeCannotWriteSessions,
                ssoBroken, ssoBreaksForRoundcube, pluginUsesPanel, revokeFails, nginxDown, noSites, webmailDown;

        Fake(Path config) throws Exception {
            this.config = config;
            accounts.put("mailpanel@localhost", new Account(PANEL_PASS, "mailserver", "roundcubemail"));
            accounts.put("mailpanel@127.0.0.1", new Account(PANEL_PASS, "mailserver", "roundcubemail"));
            reload();
        }

        void reload() throws Exception { loaded = Files.readString(config); }

        static Shell.Result r(boolean ok, String out) { return new Shell.Result(ok ? 0 : 1, out, false, List.of()); }

        @Override public String secret() { return secret; }
        @Override public String panelUser() { return "mailpanel"; }
        @Override public String panelPassword() { return PANEL_PASS; }

        boolean canUse(String user, String password, String host, String db) {
            Account a = accounts.get(user + "@" + host);
            if (a == null || !a.password.equals(password)) return false;
            if (USER.equals(user) && roundcubeLocked) return false;      // init_connect che roundcube non passa
            return a.dbs.contains(db) || a.globalSelect;
        }
        static final String USER = RoundcubeDbUser.USER;

        @Override public Shell.Result as(String user, String password, String host, String db, String sql) {
            boolean ok = canUse(user, password, host, db);
            if (ok && USER.equals(user)) rcConnections++;
            return r(ok, ok ? "1" : "ERROR 1045 (28000): Access denied for user '" + user + "'");
        }

        @Override public Shell.Result root(String sql) {
            rootLog.add(sql);
            if (rootDown) return r(false, "ERROR 2002 (HY000): Can't connect to local MySQL server");
            StringBuilder out = new StringBuilder();
            for (String line : sql.split("\n")) {
                String st = line.trim();
                if (st.endsWith(";")) st = st.substring(0, st.length() - 1).trim();
                if (st.isEmpty()) continue;
                String res = exec(st);
                if (res == null) return r(false, "ERROR 1396 (HY000): Operation failed: " + st);
                out.append(res);
            }
            return r(true, out.toString());
        }

        String account(String u, String h) { return u + "@" + h; }

        /** Le istruzioni che la migrazione usa, e solo quelle: il resto e' un errore della prova. */
        String exec(String st) {
            Matcher m;
            if (st.equals("SELECT 1")) return "1\n";
            if ((m = Pattern.compile("SELECT COUNT\\(\\*\\) FROM mysql\\.user WHERE user = '(\\w+)' AND host = '([^']+)'").matcher(st)).matches())
                return (accounts.containsKey(account(m.group(1), m.group(2))) ? "1" : "0") + "\n";
            if (st.equals("SET SESSION print_identified_with_as_hex = ON")) return "";
            if ((m = Pattern.compile("SHOW CREATE USER '(\\w+)'@'([^']+)'").matcher(st)).matches()) {
                Account a = accounts.get(account(m.group(1), m.group(2)));
                if (a == null) return null;
                return "CREATE USER `" + m.group(1) + "`@`" + m.group(2) + "` IDENTIFIED WITH 'caching_sha2_password' AS 0x"
                        + HexFormat.of().withUpperCase().formatHex(a.password.getBytes(StandardCharsets.UTF_8))
                        + " REQUIRE NONE PASSWORD EXPIRE DEFAULT ACCOUNT UNLOCK\n";
            }
            if ((m = Pattern.compile("SHOW GRANTS FOR '(\\w+)'@'([^']+)'").matcher(st)).matches()) {
                Account a = accounts.get(account(m.group(1), m.group(2)));
                if (a == null) return null;
                String to = " TO `" + m.group(1) + "`@`" + m.group(2) + "`\n";
                StringBuilder b = new StringBuilder(a.globalSelect ? "GRANT SELECT ON *.*" + to : "GRANT USAGE ON *.*" + to);
                for (String db : a.dbs) b.append("GRANT ALL PRIVILEGES ON `").append(db).append("`.*").append(to);
                return b.toString();
            }
            if ((m = Pattern.compile("SELECT host FROM mysql\\.user WHERE user = '(\\w+)' ORDER BY host").matcher(st)).matches()) {
                StringBuilder b = new StringBuilder();
                for (String k : accounts.keySet()) if (k.startsWith(m.group(1) + "@")) b.append(k.substring(k.indexOf('@') + 1)).append('\n');
                return b.toString();
            }
            if ((m = Pattern.compile("CREATE USER IF NOT EXISTS '(\\w+)'@'([^']+)' IDENTIFIED BY '([^']*)'").matcher(st)).matches()) {
                if (createRefused) return null;      // validate_password: la politica rifiuta una password di sole lettere e cifre
                accounts.putIfAbsent(account(m.group(1), m.group(2)), new Account(m.group(3)));
                return "";
            }
            if ((m = Pattern.compile("ALTER USER '(\\w+)'@'([^']+)' IDENTIFIED BY '([^']*)'").matcher(st)).matches()) {
                Account a = accounts.get(account(m.group(1), m.group(2)));
                if (a == null || createRefused) return null;
                a.password = m.group(3);
                return "";
            }
            if ((m = Pattern.compile("GRANT ALL PRIVILEGES ON `?(\\w+)`?\\.\\* TO [`']([\\w]+)[`']@[`']([^`']+)[`']").matcher(st)).matches()) {
                Account a = accounts.get(account(m.group(2), m.group(3)));
                if (a == null) return null;
                a.dbs.add(m.group(1));
                return "";
            }
            if ((m = Pattern.compile("GRANT (USAGE|SELECT) ON \\*\\.\\* TO `(\\w+)`@`([^`]+)`").matcher(st)).matches()) {
                Account a = accounts.get(account(m.group(2), m.group(3)));
                if (a == null) return null;
                if (m.group(1).equals("SELECT")) a.globalSelect = true;
                return "";
            }
            if ((m = Pattern.compile("REVOKE IF EXISTS ALL PRIVILEGES ON `(\\w+)`\\.\\* FROM '(\\w+)'@'([^']+)' IGNORE UNKNOWN USER").matcher(st)).matches()) {
                if (revokeFails) return null;
                Account a = accounts.get(account(m.group(2), m.group(3)));
                if (a != null) a.dbs.remove(m.group(1));
                return "";
            }
            if ((m = Pattern.compile("DROP USER IF EXISTS '(\\w+)'@'([^']+)'").matcher(st)).matches()) {
                accounts.remove(account(m.group(1), m.group(2)));
                return "";
            }
            if ((m = Pattern.compile("CREATE USER `(\\w+)`@`([^`]+)` IDENTIFIED WITH 'caching_sha2_password' AS 0x([0-9A-F]+) .*").matcher(st)).matches()) {
                if (accounts.containsKey(account(m.group(1), m.group(2)))) return null;
                accounts.put(account(m.group(1), m.group(2)),
                        new Account(new String(HexFormat.of().parseHex(m.group(3)), StandardCharsets.UTF_8)));
                return "";
            }
            if ((m = Pattern.compile("SELECT COUNT\\(\\*\\) FROM `(\\w+)`\\.session WHERE sess_id = '(\\w+)'").matcher(st)).matches())
                return (sessions.contains(m.group(2)) ? "1" : "0") + "\n";
            if (st.startsWith("SELECT IF(@@performance_schema, (SELECT COALESCE(SUM(TOTAL_CONNECTIONS), 0) FROM performance_schema.accounts WHERE USER = 'roundcube'), -1)"))
                return (performanceSchema ? rcConnections : -1) + "\n";
            unknown.add(st);
            return null;
        }

        // ===================== la webmail finta =====================

        /** La webmail entra in MySQL col db_dsnw che php-fpm ha caricato; un plugin, se c'e', come il pannello. */
        boolean webmailDb() {
            if (webmailDown) return false;
            RoundcubeDbUser.Dsn d = RoundcubeDbUser.activeDsn(loaded);
            if (d == null) return false;
            boolean ok = canUse(d.user(), d.password(), d.accountHost(), d.db());
            if (ok && USER.equals(d.user())) rcConnections++;
            if (ok && pluginUsesPanel) ok = canUse("mailpanel", PANEL_PASS, "127.0.0.1", d.db());
            return ok;
        }

        @Override public Shell.Result phpFpmReload() {
            if (reloadFails) { reloadFails = false; return r(false, "php_fpm: reload failed"); }   // una volta: il ritorno indietro ricarica
            try { if (!reloadIgnored) reload(); } catch (Exception e) { return r(false, e.toString()); }
            return r(true, "");
        }

        @Override public List<RoundcubeDbUser.Site> webmailSites() {
            if (nginxDown) return null;
            return noSites ? List.of() : List.of(new RoundcubeDbUser.Site("webmail.example.test", "8443"));
        }

        @Override public RoundcubeDbUser.Page loginPage(RoundcubeDbUser.Site s) {
            if (!webmailDb()) return new RoundcubeDbUser.Page(false, null);
            String id = "abcdef" + (++sessionCounter) + "0123";
            RoundcubeDbUser.Dsn d = RoundcubeDbUser.activeDsn(loaded);
            if (!(roundcubeCannotWriteSessions && USER.equals(d.user()))) sessions.add(id);   // un trigger sulla tabella session
            return new RoundcubeDbUser.Page(true, id);
        }

        @Override public String realLogin(RoundcubeDbUser.Site s, String db) {
            realLogins++;
            if (ssoBroken) return "the SSO login as mailbox #1 did not open the mailbox";
            if (!webmailDb()) return "the webmail does not answer";
            if (ssoBreaksForRoundcube && USER.equals(RoundcubeDbUser.activeDsn(loaded).user()))
                return "the SSO login as mailbox #1 did not open the mailbox";
            return null;
        }

        @Override public void pause() {}

        /** Tutto quello che la migrazione puo' toccare, per confrontarlo prima e dopo. */
        String state() throws Exception {
            PosixFileAttributes a = Files.readAttributes(config, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            return Files.readString(config) + "|" + a.owner().getName() + ":" + a.group().getName() + " "
                    + PosixFilePermissions.toString(a.permissions()) + "|" + new TreeMap<>(accounts) + "|loaded=" + loaded.equals(Files.readString(config));
        }

        Map<String, Account> accountsCopy() {
            Map<String, Account> c = new TreeMap<>();
            accounts.forEach((k, v) -> c.put(k, v.copy()));
            return c;
        }
    }

    // ===================== la cartella della prova =====================

    static Path root;

    static Fake bench(String name, String configText, String owner, String group, String perms) throws Exception {
        Path rc = root.resolve(name);
        Files.createDirectories(rc.resolve("config"));
        Files.createDirectories(rc.resolve("plugins/mailpanel_sso"));
        Files.writeString(rc.resolve("plugins/mailpanel_sso/config.inc.php"),
                "<?php\n$config['mailpanel_sso_secret'] = 'c2VjcmV0';\n");
        Path cfg = rc.resolve("config/config.inc.php");
        Files.writeString(cfg, configText);
        Shell.run("chown", owner + ":" + group, cfg.toString());
        Files.setPosixFilePermissions(cfg, PosixFilePermissions.fromString(perms));
        return new Fake(cfg);
    }

    static RoundcubeDbUser.Report run(Fake f) throws Exception {
        return RoundcubeDbUser.migrate(new RoundcubeDbUser.Places(f.config.getParent().getParent()), f);
    }

    /** Nessuna istruzione che cambia account o privilegi (SHOW CREATE USER e SHOW GRANTS leggono soltanto). */
    static boolean noWrites(Fake f) {
        for (String s : f.rootLog)
            for (String l : s.split("\n"))
                if (l.trim().matches("(?i)(CREATE USER|ALTER USER|GRANT|REVOKE|DROP USER)\\b.*")) return false;
        return true;
    }

    static String attrs(Path p) throws Exception {
        PosixFileAttributes a = Files.readAttributes(p, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        return a.owner().getName() + ":" + a.group().getName() + " " + PosixFilePermissions.toString(a.permissions());
    }

    public static void main(String[] args) throws Exception {
        root = Files.createTempDirectory("roundcube-db-user-test");

        OUT.println("== db_dsnw: quale riga conta, e cosa cambia");
        {
            String c = "<?php\n// $config['db_dsnw'] = 'mysql://old:x@127.0.0.1/old';\n"
                     + "$config['db_dsnw'] = 'mysql://first:p1@127.0.0.1/roundcubemail';\n"
                     + "#$config['db_dsnw'] = 'mysql://hash:p2@127.0.0.1/x';\n"
                     + "  $config[\"db_dsnw\"] = \"mysql://mailpanel:p3@127.0.0.1:3306/roundcubemail\"; // l'ultima vince\n"
                     + " * $config['db_dsnw'] = 'mysql://doc:p4@127.0.0.1/doc';\n";
            RoundcubeDbUser.Dsn d = RoundcubeDbUser.activeDsn(c);
            check("vince l'ultima assegnazione attiva, non le commentate", d != null && d.user().equals("mailpanel")
                    && d.password().equals("p3") && d.host().equals("127.0.0.1:3306") && d.db().equals("roundcubemail"));
            check("l'host dell'account e' senza porta", d != null && d.accountHost().equals("127.0.0.1"));
            String w = RoundcubeDbUser.withCredentials(c, d, "roundcube", "NEW");
            String[] a = c.split("\n", -1), b = w.split("\n", -1);
            int diff = 0;
            for (int i = 0; i < a.length; i++) if (!a[i].equals(b[i])) diff++;
            check("cambia solo la riga attiva, solo utente e password",
                    diff == 1 && b[4].equals("  $config[\"db_dsnw\"] = \"mysql://roundcube:NEW@127.0.0.1:3306/roundcubemail\"; // l'ultima vince"));
            check("nessun db_dsnw: null", RoundcubeDbUser.activeDsn("<?php\n// $config['db_dsnw'] = 'mysql://a:b@c/d';\n") == null);
        }

        OUT.println("== i siti della webmail, da nginx -T");
        {
            String dump = "# configuration file /usr/local/etc/nginx/nginx.conf:\nhttp {\n"
                    + "  server { listen 80 default_server; server_name _; return 444; }\n"
                    + "  server { listen 8443 ssl; listen [::]:8443 ssl; server_name webmail.example.test;\n"
                    + "    root /usr/local/www/roundcube/public_html; location ~ \\.php$ { fastcgi_pass unix:/var/run/php-fpm-roundcube.sock; } }\n"
                    + "  # server { listen 9443 ssl; server_name old.example.test; root /usr/local/www/roundcube; }\n"
                    + "}\n# configuration file /usr/local/etc/nginx/conf.d/mailpanel-public.conf:\n"
                    + "server { listen 443 ssl; server_name mta-sts.example.test; root /var/db/mailpanel/public; }\n";
            List<RoundcubeDbUser.Site> s = RoundcubeDbUser.webmailSites(dump, Path.of("/usr/local/www/roundcube"));
            check("un sito solo: la webmail sulla 8443, non i commentati ne' gli altri",
                    s.size() == 1 && s.get(0).name().equals("webmail.example.test") && s.get(0).port().equals("8443"));
        }

        OUT.println("== gli script d'installazione");
        {
            Map<String, String> scripts = new LinkedHashMap<>();
            scripts.put("FullMailServerScript", new FullMailServerScript().getScriptContent());
            scripts.put("RoundcubeScript", new RoundcubeScript().getScriptContent());
            scripts.put("FullMailStackScript", new FullMailStackScript().getScriptContent());
            Pattern dsn = Pattern.compile("db_dsnw'\\] = 'mysql://([^:]+):([^@]+)@127\\.0\\.0\\.1/roundcubemail'");
            for (Map.Entry<String, String> e : scripts.entrySet()) {
                String s = e.getValue(), n = e.getKey();
                Matcher m = dsn.matcher(s);
                check(n + ": la webmail entra come roundcube con la sua password",
                        m.find() && m.group(1).equals("roundcube") && m.group(2).matches("\\$\\{?ROUNDCUBE_DB_PASSWORD\\}?") && !m.find());
                check(n + ": crea l'account roundcube coi privilegi sul solo roundcubemail",
                        s.contains("CREATE USER IF NOT EXISTS 'roundcube'@'127.0.0.1' IDENTIFIED BY '")
                        && s.contains("ALTER USER 'roundcube'@'127.0.0.1' IDENTIFIED BY '")
                        && s.contains("GRANT ALL PRIVILEGES ON roundcubemail.* TO 'roundcube'@'127.0.0.1';"));
                check(n + ": toglie roundcubemail all'utente del pannello", s.contains("REVOKE IF EXISTS ALL PRIVILEGES ON roundcubemail.* FROM '"));
                check(n + ": nessuna GRANT su roundcubemail ad altri", !Pattern.compile("GRANT [^;]*ON roundcubemail\\.\\* TO '(?!roundcube')").matcher(s).find());
                check(n + ": senza ROUNDCUBE_DB_PASSWORD si ferma", s.contains("ROUNDCUBE_DB_PASSWORD not in the environment"));
                check(n + ": nessuna password sulla riga di comando di mysql", !Pattern.compile("mysql [^\\n]*-p\"?\\$").matcher(s).find());
                check(n + ": niente IDENTIFIED BY dentro una GRANT (MySQL 8 lo rifiuta)", !Pattern.compile("GRANT [^;\\n]*IDENTIFIED BY").matcher(s).find());
                Path f = root.resolve(n + ".sh");
                Files.writeString(f, s);
                Shell.Result r = Shell.run("sh", "-n", f.toString());
                check(n + ": sh -n lo accetta" + (r.success() ? "" : " (" + r.outputTrim() + ")"), r.success());
            }
            check("RoundcubeScript non legge piu' /usr/local/etc/mail/mysql_password",
                    !scripts.get("RoundcubeScript").contains("$(cat /usr/local/etc/mail/mysql_password)"));
            check("FullMailServerScript: l'utente del pannello non e' piu' nella configurazione della webmail",
                    !scripts.get("FullMailServerScript").contains("mysql://$MYSQL_USER"));
        }

        OUT.println("== la migrazione riuscita, coi permessi di prima (www:wheel 644)");
        {
            Fake f = bench("ok", config("mailpanel", PANEL_PASS), "www", "wheel", "rw-r--r--");
            String before = Files.readString(f.config);
            long c0 = f.rcConnections;
            RoundcubeDbUser.Report r = run(f);
            String after = Files.readString(f.config);
            check("DONE: " + r.detail(), r.outcome() == RoundcubeDbUser.Outcome.DONE);
            check("db_dsnw usa roundcube con la password del file dei segreti",
                    after.equals(before.replace("mysql://mailpanel:" + PANEL_PASS + "@", "mysql://roundcube:" + SECRET + "@")));
            check("proprietario e gruppo di prima, niente lettura per gli altri", attrs(f.config).equals("www:wheel rw-r-----"));
            check("l'account roundcube ha solo roundcubemail", f.accounts.get("roundcube@127.0.0.1") != null
                    && f.accounts.get("roundcube@127.0.0.1").password.equals(SECRET)
                    && f.accounts.get("roundcube@127.0.0.1").dbs.equals(Set.of("roundcubemail")));
            check("il pannello ha solo mailserver, da tutti e due gli host",
                    f.accounts.get("mailpanel@localhost").dbs.equals(Set.of("mailserver"))
                    && f.accounts.get("mailpanel@127.0.0.1").dbs.equals(Set.of("mailserver")));
            check("php-fpm ha caricato la configurazione nuova, e la webmail risponde", f.loaded.equals(after) && f.webmailDb());
            check("MySQL ha visto entrare roundcube", f.rcConnections > c0);
            check("verificata anche con un accesso vero", r.detail().contains("real login through the panel's SSO") && f.realLogins >= 3);
            check("nessuna istruzione sconosciuta", f.unknown.isEmpty());
            check("nessun file temporaneo rimasto", !Files.exists(f.config.resolveSibling("config.inc.php.mailpanel.tmp")));

            f.rootLog.clear();
            String st = f.state();
            RoundcubeDbUser.Report again = run(f);
            check("la seconda volta non fa niente", again.outcome() == RoundcubeDbUser.Outcome.NOTHING && f.state().equals(st));
            check("e non chiede niente a root", f.rootLog.isEmpty());
        }

        OUT.println("== senza accesso vero (l'SSO non entra gia' prima) e senza performance_schema");
        {
            Fake f = bench("nosso", config("mailpanel", PANEL_PASS), "root", "www", "rw-r-----");
            f.ssoBroken = true;
            f.performanceSchema = false;
            RoundcubeDbUser.Report r = run(f);
            check("DONE, e lo dice: " + r.detail(), r.outcome() == RoundcubeDbUser.Outcome.DONE
                    && r.detail().contains("without a real login: the SSO login as mailbox #1 did not open the mailbox"));
            check("root:www 640 resta root:www 640", attrs(f.config).equals("root:www rw-r-----"));
        }

        OUT.println("== un guasto per ogni controllo: si torna indietro, e tutto e' com'era");
        String[][] faults = {
            {"createRefused", "l'account non si crea (validate_password)", "cannot create the MySQL account"},
            {"roundcubeLocked", "roundcube non entra (init_connect)", "roundcube cannot read roundcubemail"},
            {"reloadFails", "il reload di php-fpm fallisce", "php-fpm reload failed"},
            {"reloadIgnored", "php-fpm tiene la configurazione di prima (opcache)", "php-fpm still runs the old configuration"},
            {"roundcubeCannotWriteSessions", "la sessione di roundcube non arriva nel database", "is not in the database roundcubemail after the switch"},
            {"ssoBreaksForRoundcube", "l'accesso vero non riesce dopo il cambio", "the real login failed"},
            {"pluginUsesPanel", "un plugin entra come il pannello: si vede dopo la revoca", "once mailpanel lost roundcubemail"},
            {"revokeFails", "la revoca fallisce", "cannot take roundcubemail away from mailpanel"},
        };
        for (String[] fault : faults) {
            Fake f = bench("fault-" + fault[0], config("mailpanel", PANEL_PASS), "www", "wheel", "rw-r--r--");
            String st = f.state();
            Map<String, Account> acc = f.accountsCopy();
            f.getClass().getDeclaredField(fault[0]).setBoolean(f, true);
            RoundcubeDbUser.Report r = run(f);
            f.getClass().getDeclaredField(fault[0]).setBoolean(f, false);
            check(fault[1] + ": ROLLED_BACK (" + r.detail() + ")", r.outcome() == RoundcubeDbUser.Outcome.ROLLED_BACK
                    && r.detail().contains(fault[2]) && r.detail().endsWith("everything put back"));
            check(fault[1] + ": config.inc.php, account e privilegi come prima",
                    f.state().equals(st) && acc.toString().equals(f.accounts.toString()));
            check(fault[1] + ": la webmail risponde col pannello", f.webmailDb() && !f.accounts.containsKey("roundcube@127.0.0.1"));
            check(fault[1] + ": nessuna istruzione sconosciuta", f.unknown.isEmpty());
        }
        {
            // Senza performance_schema il php-fpm che tiene la configurazione vecchia lo vede la verifica dopo la revoca.
            Fake f = bench("stale-nops", config("mailpanel", PANEL_PASS), "root", "www", "rw-r-----");
            String st = f.state();
            f.reloadIgnored = true;
            f.performanceSchema = false;
            RoundcubeDbUser.Report r = run(f);
            f.reloadIgnored = false;
            check("opcache senza performance_schema: lo vede la verifica dopo la revoca (" + r.detail() + ")",
                    r.outcome() == RoundcubeDbUser.Outcome.ROLLED_BACK && r.detail().contains("once mailpanel lost roundcubemail")
                    && f.state().equals(st));
        }

        OUT.println("== i rifiuti: non cambia niente");
        Object[][] refusals = {
            {"un altro utente", config("someone", "x1"), "NOT_OURS", "neither the panel's"},
            {"un altro server", config("mailpanel", PANEL_PASS).replace("127.0.0.1/roundcubemail", "db.example.test/roundcubemail"), "NOT_OURS", "not to the panel's MySQL"},
            {"un altro motore", config("mailpanel", PANEL_PASS).replace("'mysql://", "'pgsql://"), "NOT_OURS", "not to the panel's MySQL"},
            {"nessun db_dsnw", "<?php\n$config['imap_host'] = 'x';\n", "NOT_OURS", "no active db_dsnw"},
            {"db_dsnr come il pannello", config("mailpanel", PANEL_PASS) + "$config['db_dsnr'] = 'mysql://mailpanel:" + PANEL_PASS + "@127.0.0.1/roundcubemail';\n",
                    "NOT_OURS", "config.inc.php line 10"},
        };
        for (Object[] c : refusals) {
            Fake f = bench("refuse-" + ((String) c[0]).replace(' ', '-'), (String) c[1], "root", "www", "rw-r-----");
            String st = f.state();
            RoundcubeDbUser.Report r = run(f);
            check(c[0] + ": " + c[2] + " (" + r.detail() + ")", r.outcome().name().equals(c[2]) && r.detail().contains((String) c[3])
                    && f.state().equals(st) && noWrites(f));
        }
        {
            Fake f = bench("refuse-plugin", config("mailpanel", PANEL_PASS), "root", "www", "rw-r-----");
            Path pc = f.config.getParent().getParent().resolve("plugins/password");
            Files.createDirectories(pc);
            Files.writeString(pc.resolve("config.inc.php"), "<?php\n// $config['password_db_dsn'] = 'mysql://mailpanel:x@127.0.0.1/mailserver';\n"
                    + "$config['password_db_dsn'] = 'mysql://mailpanel:" + PANEL_PASS + "@127.0.0.1/mailserver';\n");
            RoundcubeDbUser.Report r = run(f);
            check("un plugin che entra come il pannello: NOT_OURS col file e la riga (" + r.detail() + ")",
                    r.outcome() == RoundcubeDbUser.Outcome.NOT_OURS && r.detail().contains("plugins/password/config.inc.php line 3") && noWrites(f));
        }
        {
            Fake f = bench("commented-other", config("mailpanel", PANEL_PASS) + "// $config['db_dsnr'] = 'mysql://mailpanel:x@127.0.0.1/roundcubemail';\n",
                    "root", "www", "rw-r-----");
            check("una riga commentata non ferma niente", run(f).outcome() == RoundcubeDbUser.Outcome.DONE);
        }
        {
            Fake f = bench("refuse-existing", config("mailpanel", PANEL_PASS), "root", "www", "rw-r-----");
            f.accounts.put("roundcube@127.0.0.1", new Account("SomethingElse12345678", "roundcubemail"));
            String st = f.state();
            RoundcubeDbUser.Report r = run(f);
            check("un account roundcube che la webmail non usa: NOT_OURS (" + r.detail() + ")",
                    r.outcome() == RoundcubeDbUser.Outcome.NOT_OURS && r.detail().contains("already exists") && f.state().equals(st) && noWrites(f));
        }
        {
            Fake f = bench("refuse-beyond", config("roundcube", "OldPassword123456789"), "root", "www", "rw-r-----");
            f.accounts.put("roundcube@127.0.0.1", new Account("OldPassword123456789", "roundcubemail", "mailserver"));
            String st = f.state();
            RoundcubeDbUser.Report r = run(f);
            check("un account roundcube con altri privilegi: NOT_OURS (" + r.detail() + ")",
                    r.outcome() == RoundcubeDbUser.Outcome.NOT_OURS && r.detail().contains("privileges beyond roundcubemail")
                    && r.detail().contains("`mailserver`") && f.state().equals(st) && noWrites(f));
        }
        Object[][] blocked = {
            {"webmailDown", "una webmail che gia' non risponde", "NOT_ANSWERING"},
            {"rootDown", "root di MySQL non entra", "NO_ROOT"},
            {"nginxDown", "nginx -T non risponde", "NOT_SERVED"},
            {"noSites", "nessun sito serve la webmail", "NOT_SERVED"},
        };
        for (Object[] c : blocked) {
            Fake f = bench("blocked-" + c[0], config("mailpanel", PANEL_PASS), "root", "www", "rw-r-----");
            String st = f.state();
            f.getClass().getDeclaredField((String) c[0]).setBoolean(f, true);
            RoundcubeDbUser.Report r = run(f);
            f.getClass().getDeclaredField((String) c[0]).setBoolean(f, false);
            check(c[1] + ": " + c[2] + " (" + r.detail() + ")", r.outcome().name().equals(c[2]) && f.state().equals(st) && noWrites(f));
        }
        {
            Fake f = bench("bad-secret", config("mailpanel", PANEL_PASS), "root", "www", "rw-r-----");
            f.secret = "with'quote@and/slash000";
            RoundcubeDbUser.Report r = run(f);
            check("una password nel file dei segreti che il pannello non genera: NOT_OURS",
                    r.outcome() == RoundcubeDbUser.Outcome.NOT_OURS && noWrites(f) && f.rootLog.isEmpty());
        }

        OUT.println("== gli script di prima: roundcube con la password del pannello");
        {
            Fake f = bench("shared", config("roundcube", PANEL_PASS), "root", "www", "rw-r-----");
            f.accounts.put("roundcube@127.0.0.1", new Account(PANEL_PASS, "roundcubemail"));
            f.accounts.get("mailpanel@localhost").dbs.remove("roundcubemail");
            f.accounts.get("mailpanel@127.0.0.1").dbs.remove("roundcubemail");
            String st = f.state();
            f.reloadFails = true;
            RoundcubeDbUser.Report r = run(f);
            f.reloadFails = false;
            check("con un guasto torna la password di prima, e la webmail entra (" + r.detail() + ")",
                    r.outcome() == RoundcubeDbUser.Outcome.ROLLED_BACK && f.state().equals(st)
                    && f.accounts.get("roundcube@127.0.0.1").password.equals(PANEL_PASS) && f.webmailDb());
            r = run(f);
            check("senza guasto la password cambia: DONE (" + r.detail() + ")", r.outcome() == RoundcubeDbUser.Outcome.DONE
                    && f.accounts.get("roundcube@127.0.0.1").password.equals(SECRET) && f.webmailDb()
                    && Files.readString(f.config).contains("mysql://roundcube:" + SECRET + "@"));
        }

        OUT.println("== un avvio fermato prima della revoca");
        {
            Fake f = bench("half", config("roundcube", SECRET), "root", "www", "rw-r-----");
            f.accounts.put("roundcube@127.0.0.1", new Account(SECRET, "roundcubemail"));
            Map<String, Account> acc = f.accountsCopy();
            f.pluginUsesPanel = true;
            RoundcubeDbUser.Report r = run(f);
            f.pluginUsesPanel = false;
            check("se dopo la revoca la webmail non va, i privilegi tornano (" + r.detail() + ")",
                    r.outcome() == RoundcubeDbUser.Outcome.ROLLED_BACK && acc.toString().equals(f.accounts.toString()));
            r = run(f);
            check("FINISHED: il pannello perde roundcubemail (" + r.detail() + ")", r.outcome() == RoundcubeDbUser.Outcome.FINISHED
                    && f.accounts.get("mailpanel@localhost").dbs.equals(Set.of("mailserver")) && f.webmailDb());
            check("poi non fa piu' niente", run(f).outcome() == RoundcubeDbUser.Outcome.NOTHING);
        }

        OUT.println("== il pannello legge ancora per un privilegio globale: lo dice");
        {
            Fake f = bench("global", config("mailpanel", PANEL_PASS), "root", "www", "rw-r-----");
            f.accounts.get("mailpanel@localhost").globalSelect = true;
            f.accounts.get("mailpanel@127.0.0.1").globalSelect = true;
            RoundcubeDbUser.Report r = run(f);
            check("PARTIAL, col privilegio (" + r.detail() + ")", r.outcome() == RoundcubeDbUser.Outcome.PARTIAL
                    && r.detail().contains("GRANT SELECT ON *.*") && f.accounts.get("roundcube@127.0.0.1") != null);
        }

        Shell.run("rm", "-rf", root.toString());
        OUT.println(failed == 0 ? "\nTUTTO OK" : "\nFALLITI: " + failed);
        System.exit(failed == 0 ? 0 : 1);
    }
}
