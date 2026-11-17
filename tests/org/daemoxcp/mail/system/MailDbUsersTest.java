package org.daemoxcp.mail.system;

import org.daemoxcp.mail.scripts.DovecotConfig;
import org.daemoxcp.mail.scripts.FullMailServerScript;
import org.daemoxcp.mail.scripts.FullMailStackScript;
import org.daemoxcp.mail.util.Shell;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Postfix and Dovecot with their own MySQL users (MailDbUsers), the part without MySQL:
 *
 *  1. the connection read from the files exactly as the installers write them (both installers' Postfix maps,
 *     Dovecot 2.3's dovecot-sql.conf and 2.4's auth-sql.conf.ext), and rewritten changing only user and password;
 *     files the panel did not write (another host, another database, another user, quotes, twice the same
 *     setting, a continuation line) are not read as the panel's;
 *  2. the switch with fake services, in a temporary folder: the files get the new user and keep their mode; a
 *     second run touches nothing; postmap failing after the change, a Postfix reload failing, Dovecot's lookup
 *     failing, MySQL not seeing Dovecot's new user, doveconf refusing, all put the files back byte for byte;
 *     a map that already fails, Dovecot not running and a file of someone else are left alone.
 *
 * Usage:
 *   java -cp "tests:target/daemoxcp-mail-1.0.jar" org.daemoxcp.mail.system.MailDbUsersTest
 */
public class MailDbUsersTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    /** The body of the here-document that writes that file, as the script has it. */
    static String heredoc(String script, String file) {
        Matcher m = Pattern.compile("(?m)^\\s*cat > \"?" + Pattern.quote(file) + "\"? *<< *'?([A-Z_]+)'?\\s*$").matcher(script);
        if (!m.find()) return null;
        String tag = m.group(1);
        String[] lines = script.substring(m.end()).split("\n", -1);
        StringBuilder b = new StringBuilder();
        // lines[0] e' il resto della riga di cat.
        for (int i = 1; i < lines.length; i++) {
            if (lines[i].trim().equals(tag)) return b.toString();
            b.append(lines[i]).append("\n");
        }
        return null;
    }

    static final String PANEL = "mailpanel", DB = "mailserver", PANEL_PW = "PanelPasswordPanelPassword123456";
    static final String POSTFIX_PW = "PostfixPostfixPostfixPostfix0001", DOVECOT_PW = "DovecotDovecotDovecotDovecot0001";

    /** Fake Postfix, Dovecot and MySQL: answers set by each case, calls counted. */
    static final class Fake implements MailDbUsers.Services {
        boolean postfixRunning = true, dovecotRunning = true;
        Shell.Result postfixReload = ok(""), dovecotReload = ok(""), doveconf = ok("");
        /** What postmap answers: before the change, and after it. */
        Shell.Result postmapBefore = new Shell.Result(1, "", false, List.of()), postmapAfter = new Shell.Result(1, "", false, List.of());
        int lookupBefore = 67, lookupAfter = 67, connections = 1;
        int postmaps, postfixReloads, dovecotReloads, lookups;
        Path postfixDir;

        static Shell.Result ok(String out) { return new Shell.Result(0, out, false, List.of()); }

        boolean anyPostfixChanged() {
            try {
                for (String n : MailDbUsers.POSTFIX_MAPS) {
                    Path f = postfixDir.resolve(n);
                    if (Files.exists(f) && Files.readString(f).contains("user = " + MailDbUsers.POSTFIX_USER)) return true;
                }
            } catch (Exception e) { throw new RuntimeException(e); }
            return false;
        }

        @Override public boolean postfixRunning() { return postfixRunning; }
        @Override public Shell.Result postfixReload() { postfixReloads++; return postfixReload; }
        @Override public Shell.Result postmap(String key, Path map) {
            postmaps++;
            if (!MailDbUsers.PROBE.equals(key)) wrongKeys++;
            return anyPostfixChanged() ? postmapAfter : postmapBefore;
        }
        @Override public boolean dovecotRunning() { return dovecotRunning; }
        @Override public Shell.Result doveconfCheck() { return doveconf; }
        @Override public Shell.Result dovecotReload() { dovecotReloads++; return dovecotReload; }
        @Override public int dovecotLookup() { lookups++; return dovecotReloads == 0 ? lookupBefore : lookupAfter; }
        @Override public int connections(String user) { return MailDbUsers.DOVECOT_USER.equals(user) ? connections : -1; }
        @Override public void pause() { }
    }

    static String dovecot23, dovecot24;
    /** postmap asked for something else than the probe key. */
    static int wrongKeys = 0;

    /** A fresh server: the three maps and the Dovecot files as the installer writes them, with the panel's user. */
    static MailDbUsers.Places server(boolean dovecot24Format) throws Exception {
        Path root = Files.createTempDirectory("mail-db-users");
        Path pf = Files.createDirectories(root.resolve("postfix")), dc = Files.createDirectories(root.resolve("dovecot/conf.d"));
        String script = new FullMailServerScript().getScriptContent();
        for (String n : MailDbUsers.POSTFIX_MAPS) {
            String text = heredoc(script, "/usr/local/etc/postfix/" + n).replace("$MYSQL_USER", PANEL)
                    .replace("$MYSQL_PASSWORD", PANEL_PW).replace("$MYSQL_DATABASE", DB);
            Files.writeString(pf.resolve(n), text);
            Files.setPosixFilePermissions(pf.resolve(n), PosixFilePermissions.fromString("rw-r-----"));
        }
        Path d = root.resolve("dovecot");
        if (dovecot24Format) {
            Files.writeString(d.resolve("conf.d/auth-sql.conf.ext"), dovecot24);
        } else {
            Files.writeString(d.resolve("dovecot-sql.conf"), dovecot23);
            Files.setPosixFilePermissions(d.resolve("dovecot-sql.conf"), PosixFilePermissions.fromString("rw-------"));
            // Nella 2.3 il file della passdb c'e', senza la connessione.
            Files.writeString(d.resolve("conf.d/auth-sql.conf.ext"), "passdb {\n  driver = sql\n  args = /usr/local/etc/dovecot/dovecot-sql.conf\n}\n");
        }
        Files.setPosixFilePermissions(d.resolve("conf.d/auth-sql.conf.ext"), PosixFilePermissions.fromString("rw-------"));
        return new MailDbUsers.Places(pf, d);
    }

    /** Every file of the server: name and content, to compare before and after. */
    static List<String> snapshot(MailDbUsers.Places at) throws Exception {
        List<String> out = new ArrayList<>();
        for (Path dir : List.of(at.postfixDir(), at.dovecotDir(), at.dovecotDir().resolve("conf.d"))) {
            try (var s = Files.list(dir)) {
                for (Path f : s.sorted().toList()) {
                    if (!Files.isRegularFile(f)) continue;
                    out.add(f.getFileName() + " " + PosixFilePermissions.toString(Files.getPosixFilePermissions(f)) + "\n"
                            + Files.readString(f));
                }
            }
        }
        return out;
    }

    static MailDbUsers.Report run(MailDbUsers.Places at, Fake f) throws Exception {
        f.postfixDir = at.postfixDir();
        return MailDbUsers.switchFiles(at, f, PANEL, DB, POSTFIX_PW, DOVECOT_PW);
    }

    public static void main(String[] args) throws Exception {
        String fragment = DovecotConfig.fromPanelConfig().scriptFragment();
        dovecot23 = heredoc(fragment, "$DOVECOT_ETC/dovecot-sql.conf");
        check("the Dovecot 2.3 file is found in the installer", dovecot23 != null);
        dovecot23 = dovecot23.replace("${DB_NAME}", DB).replace("${DB_USER}", PANEL).replace("${DB_PASS}", PANEL_PW);
        for (DovecotConfig.FileConf c : DovecotConfig.file24())
            if (c.path().equals("conf.d/auth-sql.conf.ext"))
                dovecot24 = c.content().replace("${DB_NAME}", DB).replace("${DB_USER}", PANEL).replace("${DB_PASS}", PANEL_PW);
        check("the Dovecot 2.4 file is found in the installer", dovecot24 != null);

        System.out.println("== 1. The connection in the files, as the installers write them");
        String script = new FullMailServerScript().getScriptContent();
        for (String n : MailDbUsers.POSTFIX_MAPS) {
            String text = heredoc(script, "/usr/local/etc/postfix/" + n).replace("$MYSQL_USER", PANEL)
                    .replace("$MYSQL_PASSWORD", PANEL_PW).replace("$MYSQL_DATABASE", DB);
            MailDbUsers.Login l = MailDbUsers.postfixLogin(text);
            check(n + " (full installer): user, password, host and database read",
                    l != null && PANEL.equals(l.user()) && PANEL_PW.equals(l.password()) && "127.0.0.1".equals(l.host()) && DB.equals(l.db()));
            String after = MailDbUsers.withCredentials(text, l, MailDbUsers.POSTFIX_USER, POSTFIX_PW);
            check(n + ": rewritten with only user and password changed",
                    after.equals(text.replace("user = " + PANEL, "user = " + MailDbUsers.POSTFIX_USER).replace(PANEL_PW, POSTFIX_PW)));
            MailDbUsers.Login again = MailDbUsers.postfixLogin(after);
            check(n + ": read again, the new user and password", again != null
                    && MailDbUsers.POSTFIX_USER.equals(again.user()) && POSTFIX_PW.equals(again.password()));
        }
        String stack = new FullMailStackScript().getScriptContent();
        for (String n : MailDbUsers.POSTFIX_MAPS) {
            String body = heredoc(stack, "/usr/local/etc/postfix/" + n);
            MailDbUsers.Login l = body == null ? null : MailDbUsers.postfixLogin(body.replace("${MAILSERVER_PASS}", PANEL_PW));
            check(n + " (stack installer, database mailpanel): read", l != null && "mailpanel".equals(l.user()) && "mailpanel".equals(l.db()));
        }
        MailDbUsers.Login d23 = MailDbUsers.dovecot23Login(dovecot23);
        check("dovecot-sql.conf (2.3): user, password, host and database read from connect", d23 != null
                && PANEL.equals(d23.user()) && PANEL_PW.equals(d23.password()) && "127.0.0.1".equals(d23.host()) && DB.equals(d23.db()));
        String d23after = MailDbUsers.withCredentials(dovecot23, d23, MailDbUsers.DOVECOT_USER, DOVECOT_PW);
        check("dovecot-sql.conf: both on the same line, rewritten with nothing else changed",
                d23after.equals(dovecot23.replace("user=" + PANEL, "user=" + MailDbUsers.DOVECOT_USER).replace(PANEL_PW, DOVECOT_PW)));
        MailDbUsers.Login d24 = MailDbUsers.dovecot24Login(dovecot24);
        check("auth-sql.conf.ext (2.4): the mysql block read", d24 != null && PANEL.equals(d24.user())
                && PANEL_PW.equals(d24.password()) && "127.0.0.1".equals(d24.host()) && DB.equals(d24.db()));
        String d24after = MailDbUsers.withCredentials(dovecot24, d24, MailDbUsers.DOVECOT_USER, DOVECOT_PW);
        check("auth-sql.conf.ext: rewritten with nothing else changed",
                d24after.equals(dovecot24.replace("user = " + PANEL, "user = " + MailDbUsers.DOVECOT_USER).replace(PANEL_PW, DOVECOT_PW)));
        check("the 2.3 auth-sql.conf.ext has no connection block",
                !MailDbUsers.hasDovecot24Block("passdb {\n  driver = sql\n  args = /usr/local/etc/dovecot/dovecot-sql.conf\n}\n"));

        String map = heredoc(script, "/usr/local/etc/postfix/mysql-virtual-domains.cf").replace("$MYSQL_USER", PANEL)
                .replace("$MYSQL_PASSWORD", PANEL_PW).replace("$MYSQL_DATABASE", DB);
        check("a map with the user twice is not read as the panel's", MailDbUsers.postfixLogin(map + "user = other\n") == null);
        check("a map whose password continues on the next line is not read as the panel's",
                MailDbUsers.postfixLogin(map.replace("password = " + PANEL_PW, "password = " + PANEL_PW + "\n  more")) == null);
        check("a map without the password is not read", MailDbUsers.postfixLogin(map.replace("password = " + PANEL_PW + "\n", "")) == null);
        check("a commented user line does not count",
                MailDbUsers.postfixLogin("# user = old\n" + map) != null);
        check("a connect line with quotes is not read",
                MailDbUsers.dovecot23Login(dovecot23.replace("password=" + PANEL_PW, "password=\"" + PANEL_PW + "\"")) == null);
        check("two connect lines are not read", MailDbUsers.dovecot23Login(dovecot23 + "connect = host=other\n") == null);
        check("two mysql blocks are not read", MailDbUsers.dovecot24Login(dovecot24 + "mysql other {\n  user = x\n  password = y\n  dbname = z\n}\n") == null);

        System.out.println("== 2. The switch, with fake services");
        MailDbUsers.Places at = server(false);
        List<String> before = snapshot(at);
        Fake f = new Fake();
        MailDbUsers.Report r = run(at, f);
        check("both services switched: " + r.done(), r.done().size() == 2 && r.left().isEmpty() && r.rolledBack().isEmpty());
        for (String n : MailDbUsers.POSTFIX_MAPS) {
            MailDbUsers.Login l = MailDbUsers.postfixLogin(Files.readString(at.postfixDir().resolve(n)));
            check(n + " now enters as " + MailDbUsers.POSTFIX_USER + " with its password, and the panel's is gone",
                    l != null && MailDbUsers.POSTFIX_USER.equals(l.user()) && POSTFIX_PW.equals(l.password())
                            && !Files.readString(at.postfixDir().resolve(n)).contains(PANEL_PW));
            check(n + " keeps rw-r-----", "rw-r-----".equals(PosixFilePermissions.toString(Files.getPosixFilePermissions(at.postfixDir().resolve(n)))));
        }
        MailDbUsers.Login dl = MailDbUsers.dovecot23Login(Files.readString(at.dovecotSql()));
        check("dovecot-sql.conf now enters as " + MailDbUsers.DOVECOT_USER, dl != null && MailDbUsers.DOVECOT_USER.equals(dl.user())
                && DOVECOT_PW.equals(dl.password()));
        check("dovecot-sql.conf keeps rw-------", "rw-------".equals(PosixFilePermissions.toString(Files.getPosixFilePermissions(at.dovecotSql()))));
        check("the 2.3 auth-sql.conf.ext is untouched", snapshot(at).stream().anyMatch(s -> s.startsWith("auth-sql.conf.ext"))
                && before.stream().filter(s -> s.startsWith("auth-sql.conf.ext")).toList()
                .equals(snapshot(at).stream().filter(s -> s.startsWith("auth-sql.conf.ext")).toList()));
        check("each map probed before and after (6), Postfix and Dovecot reloaded once each",
                f.postmaps == 6 && f.postfixReloads == 1 && f.dovecotReloads == 1);
        check("no temporary file left next to the maps", snapshot(at).size() == before.size());

        List<String> switched = snapshot(at);
        Fake second = new Fake();
        r = run(at, second);
        check("second run: nothing to do, nothing probed, nothing reloaded",
                r.done().isEmpty() && r.left().isEmpty() && r.rolledBack().isEmpty() && second.postmaps == 0
                        && second.postfixReloads == 0 && second.dovecotReloads == 0 && second.lookups == 0);
        check("second run: the files are identical", snapshot(at).equals(switched));

        // Le prove che devono fallire: ognuna rimette i file byte per byte.
        record Case(String what, java.util.function.Consumer<Fake> breakIt, String service) {}
        List<Case> cases = List.of(
                new Case("postmap answers an error after the change", x -> x.postmapAfter = new Shell.Result(1,
                        "postmap: fatal: table mysql:/x: query error: Application error", false, List.of()), "Postfix"),
                new Case("postmap finds the probe (it must find nothing)", x -> x.postmapAfter = Fake.ok("x/y/"), "Postfix"),
                new Case("the Postfix reload fails", x -> x.postfixReload = new Shell.Result(1, "fatal", false, List.of()), "Postfix"),
                new Case("Dovecot's lookup fails after the reload", x -> x.lookupAfter = 75, "Dovecot"),
                new Case("MySQL does not see Dovecot's new user", x -> x.connections = 0, "Dovecot"),
                new Case("doveconf refuses the file", x -> x.doveconf = new Shell.Result(89, "doveconf: Fatal", false, List.of()), "Dovecot"),
                new Case("the Dovecot reload fails", x -> x.dovecotReload = new Shell.Result(1, "failed", false, List.of()), "Dovecot"));
        for (Case c : cases) {
            MailDbUsers.Places p = server(false);
            List<String> was = snapshot(p);
            Fake x = new Fake();
            c.breakIt().accept(x);
            r = run(p, x);
            List<String> now = snapshot(p);
            List<String> mine = new ArrayList<>(), mineWas = new ArrayList<>();
            for (int i = 0; i < now.size(); i++) {
                boolean postfixFile = now.get(i).startsWith("mysql-virtual-");
                if (postfixFile == c.service().equals("Postfix")) { mine.add(now.get(i)); mineWas.add(was.get(i)); }
            }
            check(c.what() + ": rolled back (" + String.join(" | ", r.rolledBack()) + ")",
                    r.rolledBack().size() == 1 && r.rolledBack().get(0).startsWith(c.service()));
            check(c.what() + ": the " + c.service() + " files are back byte for byte, with their mode", mine.equals(mineWas));
            check(c.what() + ": the other service still switched", r.done().size() == 1 && !r.done().get(0).startsWith(c.service()));
        }

        MailDbUsers.Places p = server(false);
        List<String> was = snapshot(p);
        Fake x = new Fake();
        x.postmapBefore = new Shell.Result(1, "postmap: warning: connect to mysql server 127.0.0.1: Access denied", false, List.of());
        x.dovecotRunning = false;
        r = run(p, x);
        check("a map that fails already, and Dovecot not running: both left as they are (" + String.join(" | ", r.left()) + ")",
                r.left().size() == 2 && r.done().isEmpty() && r.rolledBack().isEmpty() && snapshot(p).equals(was)
                        && x.postfixReloads == 0 && x.dovecotReloads == 0);

        p = server(false);
        x = new Fake();
        x.lookupBefore = 75;
        was = snapshot(p);
        r = run(p, x);
        check("Dovecot's authentication failing already: its file left as it is",
                r.left().size() == 1 && r.left().get(0).startsWith("Dovecot") && snapshot(p).stream().filter(s -> s.startsWith("dovecot-sql"))
                        .toList().equals(was.stream().filter(s -> s.startsWith("dovecot-sql")).toList()));

        p = server(false);
        Path domains = p.postfixDir().resolve("mysql-virtual-domains.cf");
        Files.writeString(domains, Files.readString(domains).replace("user = " + PANEL, "user = someone_else"));
        Path aliases = p.postfixDir().resolve("mysql-virtual-aliases.cf");
        Files.writeString(aliases, Files.readString(aliases).replace("hosts = 127.0.0.1", "hosts = db.example.org"));
        String domainsWas = Files.readString(domains), aliasesWas = Files.readString(aliases);
        x = new Fake();
        r = run(p, x);
        check("a map with another user and one with another host are left alone, the third switched ("
                        + String.join(" | ", r.left()) + ")",
                r.left().size() == 2 && Files.readString(domains).equals(domainsWas) && Files.readString(aliases).equals(aliasesWas)
                        && Files.readString(p.postfixDir().resolve("mysql-virtual-mailboxes.cf")).contains("user = " + MailDbUsers.POSTFIX_USER));

        p = server(true);
        x = new Fake();
        r = run(p, x);
        MailDbUsers.Login l24 = MailDbUsers.dovecot24Login(Files.readString(p.dovecotAuthSql()));
        check("Dovecot 2.4: the mysql block now enters as " + MailDbUsers.DOVECOT_USER, r.rolledBack().isEmpty()
                && l24 != null && MailDbUsers.DOVECOT_USER.equals(l24.user()) && DOVECOT_PW.equals(l24.password()));

        p = server(false);
        Files.writeString(p.dovecotSql(), Files.readString(p.dovecotSql()).replace("user=" + PANEL, "user=" + MailDbUsers.DOVECOT_USER)
                .replace(PANEL_PW, "AnOldPasswordAnOldPasswordAnOld1"));
        x = new Fake();
        r = run(p, x);
        MailDbUsers.Login stale = MailDbUsers.dovecot23Login(Files.readString(p.dovecotSql()));
        check("Dovecot's own user with a password that is no longer the one in the secrets: rewritten",
                stale != null && DOVECOT_PW.equals(stale.password()) && x.dovecotReloads == 1);

        p = server(false);
        Files.delete(p.dovecotSql());
        Files.createSymbolicLink(p.dovecotSql(), p.postfixDir().resolve("mysql-virtual-domains.cf"));
        x = new Fake();
        r = run(p, x);
        check("a symbolic link in place of dovecot-sql.conf is not followed",
                r.left().stream().anyMatch(s -> s.contains("not a regular file")) && Files.isSymbolicLink(p.dovecotSql()));

        check("postmap always asked for the probe key, never a real address", wrongKeys == 0);
        System.out.println(failed == 0 ? "ALL OK" : failed + " FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }
}
