package org.mail_panel.system;

import org.mail_panel.database.SqlCatalog;
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
 * The webmail moved from the panel's MySQL user to its own (RoundcubeDbUser.migrate), with a real
 * config.inc.php in a temporary folder (content, owner, group, permissions) and fake MySQL, php-fpm,
 * nginx and webmail. The fake MySQL answers the catalog statements the migration sends it, with their
 * parameters -- and stops on one it does not know, or on one that needs the webmail's database without it --;
 * the fake webmail enters MySQL with the db_dsnw php-fpm loaded at the last reload, like the real one with
 * opcache. The same statements against a real MySQL: RoundcubeDbUserMysqlTest.
 *
 * <p>For every check there is a planted fault that only that check sees, and the test wants the
 * migration to go back leaving EVERYTHING as it was: config.inc.php byte for byte with owner, group
 * and permissions, the MySQL accounts with passwords and privileges, the webmail answering. Then the
 * refusals (another user, another server, a roundcube account that already exists, another
 * configuration that enters as the panel, a webmail that already does not answer), the second time
 * (it does nothing, and does not even ask root), the case of the old scripts (roundcube with the
 * panel's password) and that of a start stopped before the revoke.
 *
 * <p>It changes real owners: it must be run as root on the FreeBSD VM, where www and wheel exist.
 *   java -cp "tests:&lt;dir&gt;/freebsd-mail-panel-1.0.jar" org.mail_panel.system.RoundcubeDbUserTest
 */
public class RoundcubeDbUserTest {

    static int failed = 0;
    static final PrintStream OUT = System.out;

    static void check(String what, boolean ok) {
        OUT.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static final String PANEL_PASS = "PanelPass0123456789abcde";
    static final String SECRET = "RoundcubeSecret01234567x";

    /** config.inc.php as FullMailServerScript wrote it, with the password plugin's block at the end. */
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

    // ===================== Fake MySQL =====================

    /** An account: the password, the databases it has everything on, and SELECT on everything (a global privilege). */
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
        final Map<String, Account> accounts = new TreeMap<>();   // "user@host"
        final Set<String> sessions = new HashSet<>();
        final List<String> rootLog = new ArrayList<>();
        final List<String> unknown = new ArrayList<>();
        long rcConnections = 0;
        int sessionCounter = 0;
        int realLogins = 0;
        boolean performanceSchema = true;
        String loaded;                       // the configuration php-fpm loaded
        String secret = SECRET;
        // the faults
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
            if (USER.equals(user) && roundcubeLocked) return false;      // an init_connect roundcube does not pass
            return a.dbs.contains(db) || a.globalSelect;
        }
        static final String USER = RoundcubeDbUser.USER;

        @Override public Shell.Result as(String user, String password, String host, String db, String sql, Object... params) {
            if (!sql.equals(SqlCatalog.MYSQL_ROOT_PING) && !sql.equals(SqlCatalog.RC_SESSIONS_READABLE)) {
                unknown.add(sql);
                return r(false, "ERROR: not a statement the migration sends as " + user);
            }
            boolean ok = canUse(user, password, host, db);
            if (ok && USER.equals(user)) rcConnections++;
            return r(ok, ok ? "1" : "ERROR 1045 (28000): Access denied for user '" + user + "'");
        }

        @Override public Shell.Result root(String db, String sql, Object... params) {
            rootLog.add(sql + " " + java.util.Arrays.toString(params));
            if (rootDown) return r(false, "ERROR 2002 (HY000): Can't connect to local MySQL server");
            String res = exec(db, sql, params);
            if (res == null) return r(false, "ERROR 1396 (HY000): Operation failed: " + sql);
            return r(true, res);
        }

        String account(String u, String h) { return u + "@" + h; }

        /**
         * The catalog statements the migration uses, and only those: anything else is a mistake of the test. The ones
         * with "ON *" or a table of the webmail need its database, as in MySQL (1046 No database selected).
         */
        String exec(String db, String st, Object[] p) {
            if (st.equals(SqlCatalog.MYSQL_ROOT_PING)) return "1\n";
            if (st.equals(SqlCatalog.RC_ACCOUNT_EXISTS))
                return (accounts.containsKey(account(USER, (String) p[0])) ? "1" : "0") + "\n";
            if (st.equals(SqlCatalog.RC_SHOW_GRANTS)) {
                Account a = accounts.get(account((String) p[0], (String) p[1]));
                if (a == null) return null;
                String to = " TO `" + p[0] + "`@`" + p[1] + "`\n";
                StringBuilder b = new StringBuilder(a.globalSelect ? "GRANT SELECT ON *.*" + to : "GRANT USAGE ON *.*" + to);
                for (String d : a.dbs) b.append("GRANT ALL PRIVILEGES ON `").append(d).append("`.*").append(to);
                return b.toString();
            }
            if (st.equals(SqlCatalog.RC_PANEL_HOSTS)) {
                StringBuilder b = new StringBuilder();
                for (String k : accounts.keySet()) if (k.startsWith(p[0] + "@")) b.append(k.substring(k.indexOf('@') + 1)).append('\n');
                return b.toString();
            }
            if (st.equals(SqlCatalog.RC_CREATE_USER)) {
                if (createRefused) return null;      // validate_password: the policy refuses a password of letters and digits only
                accounts.putIfAbsent(account(USER, (String) p[0]), new Account((String) p[1]));
                return "";
            }
            if (st.equals(SqlCatalog.RC_SET_PASSWORD)) {
                Account a = accounts.get(account(USER, (String) p[0]));
                if (a == null || createRefused) return null;
                a.password = (String) p[1];
                return "";
            }
            if (st.equals(SqlCatalog.RC_GRANT_DATABASE) || st.equals(SqlCatalog.RC_GRANT_PANEL)) {
                if (db == null) return null;
                Account a = st.equals(SqlCatalog.RC_GRANT_DATABASE) ? accounts.get(account(USER, (String) p[0]))
                        : accounts.get(account((String) p[0], (String) p[1]));
                if (a == null) return null;
                a.dbs.add(db);
                return "";
            }
            if (st.equals(SqlCatalog.RC_REVOKE_PANEL)) {
                if (db == null || revokeFails) return null;
                Account a = accounts.get(account((String) p[0], (String) p[1]));
                if (a != null) a.dbs.remove(db);
                return "";
            }
            if (st.equals(SqlCatalog.RC_DROP_USER)) {
                accounts.remove(account(USER, (String) p[0]));
                return "";
            }
            if (st.equals(SqlCatalog.RC_SESSION_EXISTS)) {
                if (db == null) return null;
                return (sessions.contains((String) p[0]) ? "1" : "0") + "\n";
            }
            if (st.equals(SqlCatalog.RC_CONNECTIONS)) return (performanceSchema ? rcConnections : -1) + "\n";
            unknown.add(st);
            return null;
        }

        // ===================== The fake webmail =====================

        /** The webmail enters MySQL with the db_dsnw php-fpm loaded; a plugin, if there is one, as the panel. */
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
            // Like the real php-fpm -t, on several lines; only once: the way back reloads
            if (reloadFails) { reloadFails = false; return r(false, "Performing sanity check on php-fpm configuration:\n"
                    + "ERROR: failed to load configuration file '/usr/local/etc/php-fpm.conf'\nERROR: FPM initialization failed"); }
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
            if (!(roundcubeCannotWriteSessions && USER.equals(d.user()))) sessions.add(id);   // a trigger on the session table
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

        /** Everything the migration can touch, to compare it before and after. */
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

    // ===================== The test folder =====================

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

    /** No statement that changes accounts or privileges (SHOW GRANTS only reads). */
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

        OUT.println("== db_dsnw: which line counts, and what changes");
        {
            String c = "<?php\n// $config['db_dsnw'] = 'mysql://old:x@127.0.0.1/old';\n"
                     + "$config['db_dsnw'] = 'mysql://first:p1@127.0.0.1/roundcubemail';\n"
                     + "#$config['db_dsnw'] = 'mysql://hash:p2@127.0.0.1/x';\n"
                     + "  $config[\"db_dsnw\"] = \"mysql://mailpanel:p3@127.0.0.1:3306/roundcubemail\"; // the last one wins\n"
                     + " * $config['db_dsnw'] = 'mysql://doc:p4@127.0.0.1/doc';\n";
            RoundcubeDbUser.Dsn d = RoundcubeDbUser.activeDsn(c);
            check("the last active assignment wins, not the commented ones", d != null && d.user().equals("mailpanel")
                    && d.password().equals("p3") && d.host().equals("127.0.0.1:3306") && d.db().equals("roundcubemail"));
            check("the account's host is without the port", d != null && d.accountHost().equals("127.0.0.1"));
            String w = RoundcubeDbUser.withCredentials(c, d, "roundcube", "NEW");
            String[] a = c.split("\n", -1), b = w.split("\n", -1);
            int diff = 0;
            for (int i = 0; i < a.length; i++) if (!a[i].equals(b[i])) diff++;
            check("only the active line changes, only user and password",
                    diff == 1 && b[4].equals("  $config[\"db_dsnw\"] = \"mysql://roundcube:NEW@127.0.0.1:3306/roundcubemail\"; // the last one wins"));
            check("no db_dsnw: null", RoundcubeDbUser.activeDsn("<?php\n// $config['db_dsnw'] = 'mysql://a:b@c/d';\n") == null);
        }

        OUT.println("== the webmail's sites, from nginx -T");
        {
            String dump = "# configuration file /usr/local/etc/nginx/nginx.conf:\nhttp {\n"
                    + "  server { listen 80 default_server; server_name _; return 444; }\n"
                    + "  server { listen 8443 ssl; listen [::]:8443 ssl; server_name webmail.example.test;\n"
                    + "    root /usr/local/www/roundcube/public_html; location ~ \\.php$ { fastcgi_pass unix:/var/run/php-fpm-roundcube.sock; } }\n"
                    + "  # server { listen 9443 ssl; server_name old.example.test; root /usr/local/www/roundcube; }\n"
                    + "}\n# configuration file /usr/local/etc/nginx/conf.d/mailpanel-public.conf:\n"
                    + "server { listen 443 ssl; server_name mta-sts.example.test; root /var/db/mailpanel/public; }\n";
            List<RoundcubeDbUser.Site> s = RoundcubeDbUser.webmailSites(dump, Path.of("/usr/local/www/roundcube"));
            check("one site only: the webmail on 8443, not the commented ones nor the others",
                    s.size() == 1 && s.get(0).name().equals("webmail.example.test") && s.get(0).port().equals("8443"));
        }

        OUT.println("== the installation scripts");
        {
            Map<String, String> scripts = new LinkedHashMap<>();
            scripts.put("FullMailServerScript", new FullMailServerScript().getScriptContent());
            scripts.put("RoundcubeScript", new RoundcubeScript().getScriptContent());
            scripts.put("FullMailStackScript", new FullMailStackScript().getScriptContent());
            Pattern dsn = Pattern.compile("db_dsnw'\\] = 'mysql://([^:]+):([^@]+)@127\\.0\\.0\\.1/roundcubemail'");
            for (Map.Entry<String, String> e : scripts.entrySet()) {
                String s = e.getValue(), n = e.getKey();
                Matcher m = dsn.matcher(s);
                check(n + ": the webmail enters as roundcube with its own password",
                        m.find() && m.group(1).equals("roundcube") && m.group(2).matches("\\$\\{?ROUNDCUBE_DB_PASSWORD\\}?") && !m.find());
                check(n + ": it creates the roundcube account with privileges on roundcubemail only",
                        s.contains("CREATE USER IF NOT EXISTS 'roundcube'@'127.0.0.1' IDENTIFIED BY '")
                        && s.contains("ALTER USER 'roundcube'@'127.0.0.1' IDENTIFIED BY '")
                        && s.contains("GRANT ALL PRIVILEGES ON roundcubemail.* TO 'roundcube'@'127.0.0.1';"));
                check(n + ": it takes roundcubemail away from the panel's user", s.contains("REVOKE IF EXISTS ALL PRIVILEGES ON roundcubemail.* FROM '"));
                check(n + ": no GRANT on roundcubemail to others", !Pattern.compile("GRANT [^;]*ON roundcubemail\\.\\* TO '(?!roundcube')").matcher(s).find());
                check(n + ": without ROUNDCUBE_DB_PASSWORD it stops", s.contains("ROUNDCUBE_DB_PASSWORD not in the environment"));
                check(n + ": no password on mysql's command line", !Pattern.compile("mysql [^\\n]*-p\"?\\$").matcher(s).find());
                check(n + ": no IDENTIFIED BY inside a GRANT (MySQL 8 refuses it)", !Pattern.compile("GRANT [^;\\n]*IDENTIFIED BY").matcher(s).find());
                Path f = root.resolve(n + ".sh");
                Files.writeString(f, s);
                Shell.Result r = Shell.run("sh", "-n", f.toString());
                check(n + ": sh -n accepts it" + (r.success() ? "" : " (" + r.outputTrim() + ")"), r.success());
            }
            check("RoundcubeScript no longer reads /usr/local/etc/mail/mysql_password",
                    !scripts.get("RoundcubeScript").contains("$(cat /usr/local/etc/mail/mysql_password)"));
            check("FullMailServerScript: the panel's user is no longer in the webmail's configuration",
                    !scripts.get("FullMailServerScript").contains("mysql://$MYSQL_USER"));
        }

        OUT.println("== the migration that succeeds, with the permissions of before (www:wheel 644)");
        {
            Fake f = bench("ok", config("mailpanel", PANEL_PASS), "www", "wheel", "rw-r--r--");
            String before = Files.readString(f.config);
            long c0 = f.rcConnections;
            RoundcubeDbUser.Report r = run(f);
            String after = Files.readString(f.config);
            check("DONE: " + r.detail(), r.outcome() == RoundcubeDbUser.Outcome.DONE);
            check("db_dsnw uses roundcube with the password from the secrets file",
                    after.equals(before.replace("mysql://mailpanel:" + PANEL_PASS + "@", "mysql://roundcube:" + SECRET + "@")));
            check("owner and group of before, no read for others", attrs(f.config).equals("www:wheel rw-r-----"));
            check("the roundcube account has roundcubemail only", f.accounts.get("roundcube@127.0.0.1") != null
                    && f.accounts.get("roundcube@127.0.0.1").password.equals(SECRET)
                    && f.accounts.get("roundcube@127.0.0.1").dbs.equals(Set.of("roundcubemail")));
            check("the panel has mailserver only, from both hosts",
                    f.accounts.get("mailpanel@localhost").dbs.equals(Set.of("mailserver"))
                    && f.accounts.get("mailpanel@127.0.0.1").dbs.equals(Set.of("mailserver")));
            check("php-fpm loaded the new configuration, and the webmail answers", f.loaded.equals(after) && f.webmailDb());
            check("MySQL saw roundcube come in", f.rcConnections > c0);
            check("also verified with a real login", r.detail().contains("real login through the panel's SSO") && f.realLogins >= 3);
            check("no unknown statement", f.unknown.isEmpty());
            check("no temporary file left", !Files.exists(f.config.resolveSibling("config.inc.php.mailpanel.tmp")));

            f.rootLog.clear();
            String st = f.state();
            RoundcubeDbUser.Report again = run(f);
            check("the second time it does nothing", again.outcome() == RoundcubeDbUser.Outcome.NOTHING && f.state().equals(st));
            check("and asks root nothing", f.rootLog.isEmpty());
        }

        OUT.println("== without a real login (the SSO already does not get in before) and without performance_schema");
        {
            Fake f = bench("nosso", config("mailpanel", PANEL_PASS), "root", "www", "rw-r-----");
            f.ssoBroken = true;
            f.performanceSchema = false;
            RoundcubeDbUser.Report r = run(f);
            check("DONE, and it says so: " + r.detail(), r.outcome() == RoundcubeDbUser.Outcome.DONE
                    && r.detail().contains("without a real login: the SSO login as mailbox #1 did not open the mailbox"));
            check("root:www 640 stays root:www 640", attrs(f.config).equals("root:www rw-r-----"));
        }

        OUT.println("== one fault for each check: it goes back, and everything is as it was");
        String[][] faults = {
            {"createRefused", "the account is not created (validate_password)", "cannot create the MySQL account"},
            {"roundcubeLocked", "roundcube does not get in (init_connect)", "roundcube cannot read roundcubemail"},
            {"reloadFails", "the php-fpm reload fails", "php-fpm reload failed"},
            {"reloadIgnored", "php-fpm keeps the configuration of before (opcache)", "php-fpm still runs the old configuration"},
            {"roundcubeCannotWriteSessions", "roundcube's session does not reach the database", "is not in the database roundcubemail after the switch"},
            {"ssoBreaksForRoundcube", "the real login fails after the switch", "the real login failed"},
            {"pluginUsesPanel", "a plugin enters as the panel: it shows after the revoke", "once mailpanel lost roundcubemail"},
            {"revokeFails", "the revoke fails", "cannot take roundcubemail away from mailpanel"},
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
            check(fault[1] + ": config.inc.php, accounts and privileges as before",
                    f.state().equals(st) && acc.toString().equals(f.accounts.toString()));
            check(fault[1] + ": the webmail answers with the panel", f.webmailDb() && !f.accounts.containsKey("roundcube@127.0.0.1"));
            check(fault[1] + ": no unknown statement", f.unknown.isEmpty());
            check(fault[1] + ": the message fits on one log line", !r.detail().contains("\n"));
        }
        {
            // Without performance_schema, the php-fpm that keeps the old configuration is seen by the check after the revoke.
            Fake f = bench("stale-nops", config("mailpanel", PANEL_PASS), "root", "www", "rw-r-----");
            String st = f.state();
            f.reloadIgnored = true;
            f.performanceSchema = false;
            RoundcubeDbUser.Report r = run(f);
            f.reloadIgnored = false;
            check("opcache without performance_schema: the check after the revoke sees it (" + r.detail() + ")",
                    r.outcome() == RoundcubeDbUser.Outcome.ROLLED_BACK && r.detail().contains("once mailpanel lost roundcubemail")
                    && f.state().equals(st));
        }

        OUT.println("== the refusals: nothing changes");
        Object[][] refusals = {
            {"another user", config("someone", "x1"), "NOT_OURS", "neither the panel's"},
            {"another server", config("mailpanel", PANEL_PASS).replace("127.0.0.1/roundcubemail", "db.example.test/roundcubemail"), "NOT_OURS", "not to the panel's MySQL"},
            {"another engine", config("mailpanel", PANEL_PASS).replace("'mysql://", "'pgsql://"), "NOT_OURS", "not to the panel's MySQL"},
            {"no db_dsnw", "<?php\n$config['imap_host'] = 'x';\n", "NOT_OURS", "no active db_dsnw"},
            {"db_dsnr as the panel", config("mailpanel", PANEL_PASS) + "$config['db_dsnr'] = 'mysql://mailpanel:" + PANEL_PASS + "@127.0.0.1/roundcubemail';\n",
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
            check("a plugin that enters as the panel: NOT_OURS with the file and the line (" + r.detail() + ")",
                    r.outcome() == RoundcubeDbUser.Outcome.NOT_OURS && r.detail().contains("plugins/password/config.inc.php line 3") && noWrites(f));
        }
        {
            Fake f = bench("commented-other", config("mailpanel", PANEL_PASS) + "// $config['db_dsnr'] = 'mysql://mailpanel:x@127.0.0.1/roundcubemail';\n",
                    "root", "www", "rw-r-----");
            check("a commented line stops nothing", run(f).outcome() == RoundcubeDbUser.Outcome.DONE);
        }
        {
            Fake f = bench("refuse-existing", config("mailpanel", PANEL_PASS), "root", "www", "rw-r-----");
            f.accounts.put("roundcube@127.0.0.1", new Account("SomethingElse12345678", "roundcubemail"));
            String st = f.state();
            RoundcubeDbUser.Report r = run(f);
            check("a roundcube account the webmail does not use: NOT_OURS (" + r.detail() + ")",
                    r.outcome() == RoundcubeDbUser.Outcome.NOT_OURS && r.detail().contains("already exists") && f.state().equals(st) && noWrites(f));
        }
        {
            Fake f = bench("refuse-beyond", config("roundcube", "OldPassword123456789"), "root", "www", "rw-r-----");
            f.accounts.put("roundcube@127.0.0.1", new Account("OldPassword123456789", "roundcubemail", "mailserver"));
            String st = f.state();
            RoundcubeDbUser.Report r = run(f);
            check("a roundcube account with other privileges: NOT_OURS (" + r.detail() + ")",
                    r.outcome() == RoundcubeDbUser.Outcome.NOT_OURS && r.detail().contains("privileges beyond roundcubemail")
                    && r.detail().contains("`mailserver`") && f.state().equals(st) && noWrites(f));
        }
        Object[][] blocked = {
            {"webmailDown", "a webmail that already does not answer", "NOT_ANSWERING"},
            {"rootDown", "MySQL's root does not get in", "NO_ROOT"},
            {"nginxDown", "nginx -T does not answer", "NOT_SERVED"},
            {"noSites", "no site serves the webmail", "NOT_SERVED"},
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
            check("a password in the secrets file that the panel does not generate: NOT_OURS",
                    r.outcome() == RoundcubeDbUser.Outcome.NOT_OURS && noWrites(f) && f.rootLog.isEmpty());
        }

        OUT.println("== the scripts of before: roundcube with the panel's password");
        {
            Fake f = bench("shared", config("roundcube", PANEL_PASS), "root", "www", "rw-r-----");
            f.accounts.put("roundcube@127.0.0.1", new Account(PANEL_PASS, "roundcubemail"));
            f.accounts.get("mailpanel@localhost").dbs.remove("roundcubemail");
            f.accounts.get("mailpanel@127.0.0.1").dbs.remove("roundcubemail");
            String st = f.state();
            f.reloadFails = true;
            RoundcubeDbUser.Report r = run(f);
            f.reloadFails = false;
            check("with a fault the password of before comes back, and the webmail gets in (" + r.detail() + ")",
                    r.outcome() == RoundcubeDbUser.Outcome.ROLLED_BACK && f.state().equals(st)
                    && f.accounts.get("roundcube@127.0.0.1").password.equals(PANEL_PASS) && f.webmailDb());
            r = run(f);
            check("without a fault the password changes: DONE (" + r.detail() + ")", r.outcome() == RoundcubeDbUser.Outcome.DONE
                    && f.accounts.get("roundcube@127.0.0.1").password.equals(SECRET) && f.webmailDb()
                    && Files.readString(f.config).contains("mysql://roundcube:" + SECRET + "@"));
        }

        OUT.println("== a start stopped before the revoke");
        {
            Fake f = bench("half", config("roundcube", SECRET), "root", "www", "rw-r-----");
            f.accounts.put("roundcube@127.0.0.1", new Account(SECRET, "roundcubemail"));
            Map<String, Account> acc = f.accountsCopy();
            f.pluginUsesPanel = true;
            RoundcubeDbUser.Report r = run(f);
            f.pluginUsesPanel = false;
            check("if the webmail does not work after the revoke, the privileges come back (" + r.detail() + ")",
                    r.outcome() == RoundcubeDbUser.Outcome.ROLLED_BACK && acc.toString().equals(f.accounts.toString()));
            r = run(f);
            check("FINISHED: the panel loses roundcubemail (" + r.detail() + ")", r.outcome() == RoundcubeDbUser.Outcome.FINISHED
                    && f.accounts.get("mailpanel@localhost").dbs.equals(Set.of("mailserver")) && f.webmailDb());
            check("then it does nothing any more", run(f).outcome() == RoundcubeDbUser.Outcome.NOTHING);
        }

        OUT.println("== the panel still reads through a global privilege: it says so");
        {
            Fake f = bench("global", config("mailpanel", PANEL_PASS), "root", "www", "rw-r-----");
            f.accounts.get("mailpanel@localhost").globalSelect = true;
            f.accounts.get("mailpanel@127.0.0.1").globalSelect = true;
            RoundcubeDbUser.Report r = run(f);
            check("PARTIAL, with the privilege (" + r.detail() + ")", r.outcome() == RoundcubeDbUser.Outcome.PARTIAL
                    && r.detail().contains("GRANT SELECT ON *.*") && f.accounts.get("roundcube@127.0.0.1") != null);
        }

        Shell.run("rm", "-rf", root.toString());
        OUT.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }
}
