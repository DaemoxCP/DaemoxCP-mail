package org.daemoxcp.mail.database;

import org.daemoxcp.mail.Main;
import org.daemoxcp.mail.security.AuthStore;
import org.daemoxcp.mail.security.PanelSecrets;
import org.daemoxcp.mail.webserver.WebSessions;

import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Properties;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

/**
 * The web part's MySQL user and its procedures, on the test MySQL,
 * as its root:
 *
 *  1. the migration (WebDbAccess): the two users, the procedures with their owner and comment, the role
 *     permissions, the secrets (the web's password in its file, the panel user's moved to root's); a second run
 *     changes and logs nothing; a dropped procedure, an extra privilege, a changed password, an unlocked owner
 *     are put back;
 *  2. the web user by itself (its own JDBC connection, like anyone who took the web part): no table, no
 *     helper procedure, no DDL; the public procedures answer; the others need a live session (not expired,
 *     not idle, administrator active) whose role has the permission; the settings it reads are a closed list;
 *  3. the web part's connection (MailDatabase with the procedures, CatalogGuard.openRoutines), used like the
 *     handlers use it: the same answers as the panel user's connection, generated keys, rows touched,
 *     transactions; the DKIM private keys and the password hashes stay in the database; a viewer and an
 *     operator stop where their role stops; the session check and its last activity through the procedures;
 *  4. the guard on that connection: SQLite statements, other texts, prepareCall and batches refused.
 *
 * Usage (on the VM, with the test MySQL of tests/README.md, as root):
 *   java -Dmysql.port=33062 -Dmysql.user=mailpanel -Dmysql.password=... -Dmysql.database=mailpanel_test \
 *        -cp "tests:target/daemoxcp-mail-1.0.jar" org.daemoxcp.mail.database.WebRoutinesTest
 */
public class WebRoutinesTest {

    static int failed = 0;
    static final String UA = "web-routines-test";

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    interface SqlAction { void run() throws Exception; }

    /** The SQLSTATE (or the vendor code) of what the action threw, or "" if it did not throw. */
    static String refusal(SqlAction a) {
        try {
            a.run();
            return "";
        } catch (SQLException e) {
            return e.getSQLState() + "/" + e.getErrorCode();
        } catch (Exception e) {
            return e.getClass().getSimpleName();
        }
    }

    static String port, database;

    static Connection as(String user, String password) throws SQLException {
        return DriverManager.getConnection("jdbc:mysql://127.0.0.1:" + port + "/" + database
                + "?useSSL=true&requireSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC", user, password);
    }

    static List<String> rows(Connection c, String sql, Object... params) throws SQLException {
        List<String> out = new ArrayList<>();
        try (PreparedStatement p = c.prepareStatement(sql)) {
            for (int i = 0; i < params.length; i++) p.setObject(i + 1, params[i]);
            try (ResultSet r = p.executeQuery()) {
                int n = r.getMetaData().getColumnCount();
                while (r.next()) {
                    StringBuilder b = new StringBuilder();
                    for (int i = 1; i <= n; i++) b.append(i > 1 ? "|" : "").append(r.getString(i));
                    out.add(b.toString());
                }
            }
        }
        return out;
    }

    static void exec(Connection c, String sql, Object... params) throws SQLException {
        try (PreparedStatement p = c.prepareStatement(sql)) {
            for (int i = 0; i < params.length; i++) p.setObject(i + 1, params[i]);
            p.execute();
        }
    }

    static Properties file(Path dir, String name) throws Exception {
        Properties p = new Properties();
        Path f = dir.resolve(name);
        if (Files.exists(f)) try (Reader r = Files.newBufferedReader(f)) { p.load(r); }
        return p;
    }

    /** The WebDbAccess log lines of one run. */
    static final List<String> LOG = new ArrayList<>();

    static String ensure(MailDatabase db) {
        LOG.clear();
        return WebDbAccess.ensure(db, "");
    }

    static boolean logged(String what) {
        return LOG.stream().anyMatch(l -> l.contains(what));
    }

    public static void main(String[] args) throws Exception {
        port = System.getProperty("mysql.port");
        database = System.getProperty("mysql.database", "mailpanel_test");
        if (port == null) {
            System.out.println("No MySQL given (-Dmysql.port=...): this test needs the test MySQL, and its root.");
            System.exit(1);
        }
        Path dir = Files.createTempDirectory("web-routines");
        System.setProperty("daemoxcp.mail.secrets.dir", dir.toString());
        System.setProperty("daemoxcp.mail.vault.key", dir.resolve("master.key").toString());
        Logger.getLogger(WebDbAccess.class.getName()).addHandler(new Handler() {
            @Override public void publish(LogRecord r) { LOG.add(r.getMessage()); }
            @Override public void flush() { }
            @Override public void close() { }
        });

        MailDatabase db = new MailDatabase();
        db.setCredentials(System.getProperty("mysql.user", "mailpanel"), System.getProperty("mysql.password", ""));
        db.setConnection("127.0.0.1", Integer.parseInt(port), database);
        check("connected to MySQL as the panel user", db.connect());
        Main.mailDatabase = db;
        Main.mysqlAvailable = true;
        db.createSchema();
        AuthStore.migrate();
        PanelSecrets.setText(PanelSecrets.MYSQL_PASSWORD, System.getProperty("mysql.password", ""));

        Connection root = as("root", "");
        // The database as the installer creates it (FullMailServerScript): utf8mb4_unicode_ci, while the tables say
        // only utf8mb4 and get utf8mb4_0900_ai_ci. A procedure's parameters take the database's collation: on the
        // VM, compared with a column, MySQL refused the mix ("Illegal mix of collations"). The test MySQL's own
        // default would have hidden it.
        exec(root, "ALTER DATABASE " + database + " CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
        // A clean start: none of the users and procedures of an earlier run.
        exec(root, "DROP USER IF EXISTS 'mailpanel_web'@'localhost', 'mailpanel_web'@'127.0.0.1', 'mailpanel_routines'@'localhost'");
        for (WebDbAccess.Definition d : WebDbAccess.definitions()) exec(root, d.drop());
        exec(root, "DELETE FROM domains WHERE domain LIKE 'wr-%'");
        exec(root, "DELETE FROM audit_log WHERE action = 'WR_TEST'");

        System.out.println("== 1. The migration ==");
        String r = ensure(db);
        check("it says the web part can use its own user (" + r + ")", r == null);
        check("  and logs what it did (" + LOG + ")", logged("DONE") && logged("all 38 procedures") && logged("user mailpanel_web"));
        check("mailpanel_routines exists and is locked",
                rows(root, "SELECT account_locked FROM mysql.user WHERE user = 'mailpanel_routines' AND host = 'localhost'").equals(List.of("Y")));
        check("mailpanel_web exists with both names, not locked", rows(root,
                "SELECT host, account_locked FROM mysql.user WHERE user = 'mailpanel_web' ORDER BY host").equals(List.of("127.0.0.1|N", "localhost|N")));
        List<String> procs = rows(root, "SELECT routine_name, definer, security_type, routine_comment LIKE 'mailpanel %' FROM information_schema.routines"
                + " WHERE routine_schema = DATABASE() AND routine_type = 'PROCEDURE'");
        check("38 procedures (" + procs.size() + "), every one of mailpanel_routines, SQL SECURITY DEFINER, with its comment",
                procs.size() == 38 && procs.stream().allMatch(p -> p.endsWith("|mailpanel_routines@localhost|DEFINER|1")));
        check("the web user has EXECUTE on the 37 procedures of the web and nothing else (" + rows(root,
                "SELECT COUNT(*) FROM mysql.procs_priv WHERE user = 'mailpanel_web'") + ")",
                rows(root, "SELECT COUNT(*) FROM mysql.procs_priv WHERE user = 'mailpanel_web' AND proc_priv = 'Execute' AND routine_name <> 'web_session_admin'").equals(List.of("74"))
                && rows(root, "SELECT COUNT(*) FROM mysql.procs_priv WHERE user = 'mailpanel_web'").equals(List.of("74"))
                && rows(root, "SHOW GRANTS FOR 'mailpanel_web'@'127.0.0.1'").stream().noneMatch(g -> g.contains("ON *.*") && !g.startsWith("GRANT USAGE")));
        int expected = 0;
        for (String role : AuthStore.ROLES) expected += AuthStore.permissionsOf(role).size();
        check("the role permissions are the Java ones (" + expected + " rows)",
                rows(root, "SELECT COUNT(*) FROM panel_role_permissions").equals(List.of(String.valueOf(expected)))
                && rows(root, "SELECT permission FROM panel_role_permissions WHERE role = 'viewer' AND permission = 'domains.manage'").isEmpty());
        Properties web = file(dir, "panel-secrets.properties"), rootFile = file(dir, "root-secrets.properties");
        check("the web part's password is in its secrets file, the panel user's is not any more",
                !web.getProperty("mysql_web_password", "").isEmpty() && !web.containsKey("mysql_password"));
        check("  the panel user's password is in root's file, and the panel (as root) still reads it",
                System.getProperty("mysql.password", "").equals(rootFile.getProperty("mysql_password"))
                && System.getProperty("mysql.password", "").equals(PanelSecrets.text(PanelSecrets.MYSQL_PASSWORD)));
        String webPassword = PanelSecrets.text(PanelSecrets.MYSQL_WEB_PASSWORD);

        r = ensure(db);
        check("a second run changes nothing and logs nothing (" + r + ", " + LOG + ")", r == null && LOG.isEmpty());

        exec(root, "DROP PROCEDURE list_domains");
        r = ensure(db);
        check("a dropped procedure is created again, with its EXECUTE (" + LOG + ")", r == null && logged("procedures list_domains")
                && rows(root, "SELECT COUNT(*) FROM mysql.procs_priv WHERE user = 'mailpanel_web' AND routine_name = 'list_domains'").equals(List.of("2")));
        exec(root, "GRANT SELECT ON domains TO 'mailpanel_web'@'127.0.0.1'");
        r = ensure(db);
        check("a table privilege given by hand is taken away, and the procedures stay (" + LOG + ")", r == null
                && logged("every other privilege of mailpanel_web revoked")
                && rows(root, "SELECT COUNT(*) FROM information_schema.table_privileges WHERE grantee LIKE '%mailpanel_web%'").equals(List.of("0"))
                && rows(root, "SELECT COUNT(*) FROM mysql.procs_priv WHERE user = 'mailpanel_web'").equals(List.of("74")));
        // A procedure the web part had before the asymmetric vault (the copy of a password), granted to it.
        exec(root, "CREATE DEFINER = 'mailpanel_routines'@'localhost' PROCEDURE get_mailbox_password_hash(IN p_session CHAR(64), IN p_id INT)"
                + " SQL SECURITY DEFINER SELECT password FROM mailboxes WHERE id = p_id");
        exec(root, "GRANT EXECUTE ON PROCEDURE get_mailbox_password_hash TO 'mailpanel_web'@'localhost', 'mailpanel_web'@'127.0.0.1'");
        r = ensure(db);
        check("a procedure the web part no longer has is removed, and its EXECUTE with it (" + LOG + ")", r == null
                && logged("removed: get_mailbox_password_hash")
                && rows(root, "SELECT COUNT(*) FROM information_schema.routines WHERE routine_schema = DATABASE() AND routine_name = 'get_mailbox_password_hash'").equals(List.of("0"))
                && rows(root, "SELECT COUNT(*) FROM mysql.procs_priv WHERE user = 'mailpanel_web'").equals(List.of("74")));
        exec(root, "ALTER USER 'mailpanel_web'@'127.0.0.1' IDENTIFIED BY 'someone-else-1234'");
        r = ensure(db);
        check("a password changed by someone else is set back to the one in the web's file (" + r + ", " + LOG + ")",
                r == null && logged("mailpanel_web password set") && webPassword.equals(PanelSecrets.text(PanelSecrets.MYSQL_WEB_PASSWORD)));
        exec(root, "ALTER USER 'mailpanel_routines'@'localhost' ACCOUNT UNLOCK");
        r = ensure(db);
        check("an unlocked owner is locked again (" + r + ", " + LOG + ")", r == null && logged("mailpanel_routines locked again")
                && rows(root, "SELECT account_locked FROM mysql.user WHERE user = 'mailpanel_routines'").equals(List.of("Y")));

        // Administrators and sessions, written as the root part writes them.
        long boss = admin("wr-boss", "superadmin"), vera = admin("wr-vera", "viewer"), otto = admin("wr-otto", "operator");
        String bossToken = Main.sessions.create(boss, UA, "127.0.0.1"), veraToken = Main.sessions.create(vera, UA, "127.0.0.1");
        String ottoToken = Main.sessions.create(otto, UA, "127.0.0.1");
        String bossHash = WebSessions.tokenHash(bossToken), veraHash = WebSessions.tokenHash(veraToken), ottoHash = WebSessions.tokenHash(ottoToken);
        db.setSetting("mail_hostname", "mail.wr-test.example");
        db.setSetting("cloudflare_api_token", "wr-secret-token");

        System.out.println("\n== 2. The web user by itself ==");
        try (Connection w = as("mailpanel_web", webPassword)) {
            check("SELECT on a table: refused (" + refusal(() -> rows(w, "SELECT * FROM panel_admin")) + ")",
                    refusal(() -> rows(w, "SELECT * FROM panel_admin")).endsWith("/1142"));
            check("INSERT of a session: refused", refusal(() -> exec(w, "INSERT INTO panel_sessions (token_hash) VALUES ('x')")).endsWith("/1142"));
            check("UPDATE of an administrator's role: refused", refusal(() -> exec(w, "UPDATE panel_admin SET role = 'superadmin'")).endsWith("/1142"));
            check("the helper procedure: refused (" + refusal(() -> exec(w, "CALL web_session_admin(?, '', @a)", bossHash)) + ")",
                    refusal(() -> exec(w, "CALL web_session_admin(?, '', @a)", bossHash)).endsWith("/1370"));
            check("CREATE PROCEDURE: refused", !refusal(() -> exec(w, "CREATE PROCEDURE wr_evil() SELECT 1")).isEmpty());
            check("the public procedures answer without a session: has_admin, list_domain_names",
                    rows(w, "CALL has_admin(NULL)").equals(List.of("1")) && refusal(() -> rows(w, "CALL list_domain_names(NULL)")).isEmpty());
            check("get_setting gives the settings the web reads", rows(w, "CALL get_setting(NULL, 'mail_hostname')").equals(List.of("mail.wr-test.example")));
            check("  and nothing else: not the Cloudflare token", rows(w, "CALL get_setting(NULL, 'cloudflare_api_token')").isEmpty());
            check("list_domains without a session: refused by the database (" + refusal(() -> rows(w, "CALL list_domains(NULL)")) + ")",
                    refusal(() -> rows(w, "CALL list_domains(NULL)")).startsWith("45000"));
            check("  with a made-up session: refused", refusal(() -> rows(w, "CALL list_domains(?)", "ab".repeat(32))).startsWith("45000"));
            check("  with a live one: answers", refusal(() -> rows(w, "CALL list_domains(?)", bossHash)).isEmpty());
            check("get_session_admin gives the session's administrator", rows(w, "CALL get_session_admin(?, ?)", bossHash, boss).size() == 1);
            check("  and nobody else's (another id: nothing)", rows(w, "CALL get_session_admin(?, ?)", bossHash, vera).isEmpty());
            check("check_session finds a live session by its hash", rows(w, "CALL check_session(NULL, ?, NULL, NULL)", bossHash).size() == 1);
            exec(TestSql(), "UPDATE panel_sessions SET last_seen_at = UTC_TIMESTAMP() - INTERVAL 31 MINUTE WHERE token_hash = ?", ottoHash);
            check("an idle session (31 minutes): refused, and check_session does not find it, whatever time is passed",
                    refusal(() -> rows(w, "CALL list_domains(?)", ottoHash)).startsWith("45000")
                    && rows(w, "CALL check_session(NULL, ?, '2000-01-01 00:00:00', '2000-01-01 00:00:00')", ottoHash).isEmpty());
            exec(TestSql(), "UPDATE panel_sessions SET last_seen_at = UTC_TIMESTAMP(), expires_at = UTC_TIMESTAMP() - INTERVAL 1 SECOND WHERE token_hash = ?", ottoHash);
            check("an expired session: refused", refusal(() -> rows(w, "CALL list_domains(?)", ottoHash)).startsWith("45000"));
            exec(TestSql(), "UPDATE panel_sessions SET expires_at = UTC_TIMESTAMP() + INTERVAL 1 HOUR WHERE token_hash = ?", ottoHash);
            exec(TestSql(), "UPDATE panel_admin SET active = FALSE WHERE id = ?", otto);
            check("an inactive administrator's session: refused", refusal(() -> rows(w, "CALL list_domains(?)", ottoHash)).startsWith("45000"));
            exec(TestSql(), "UPDATE panel_admin SET active = TRUE WHERE id = ?", otto);
            check("the viewer may list but not add a domain",
                    refusal(() -> rows(w, "CALL list_domains(?)", veraHash)).isEmpty()
                    && refusal(() -> rows(w, "CALL add_domain(?, 'wr-no.example', 'x')", veraHash)).startsWith("45000")
                    && rows(TestSql(), "SELECT id FROM domains WHERE domain = 'wr-no.example'").isEmpty());
            check("no procedure gives a password copy or hash, not even to the superadmin (Show password is the root part's)",
                    !refusal(() -> rows(w, "CALL get_mailbox_vault_copy(?, 1)", bossHash)).isEmpty()
                    && !refusal(() -> rows(w, "CALL get_mailbox_password_hash(?, 1)", bossHash)).isEmpty());
            check("a language other than it or en: refused", refusal(() -> rows(w, "CALL set_admin_language(?, 'xx', 'wr-boss')", bossHash)).startsWith("45000"));
            check("a theme of someone else: nothing changes",
                    rows(w, "CALL set_admin_theme(?, 'dark', 'wr-vera')", bossHash).equals(List.of("0")));
        }

        System.out.println("\n== 3. The web part's connection ==");
        MailDatabase webDb = new MailDatabase();
        webDb.setConnection("127.0.0.1", Integer.parseInt(port), database);
        webDb.useRoutines(WebDbAccess.WEB_USER, () -> PanelSecrets.text(PanelSecrets.MYSQL_WEB_PASSWORD));
        check("the web part connects as mailpanel_web, through the procedures", webDb.connect() && webDb.usesRoutines()
                && WebDbAccess.WEB_USER.equals(webDb.getConnection().getMetaData().getUserName().replaceAll("@.*", "")));
        CatalogGuard.forgetSession();
        check("without a session: is there an administrator, the domain names", webDb.hasAdminUser()
                && refusal(webDb::getDomainNames).isEmpty());
        check("  but not the domains (" + refusal(webDb::getDomains) + ")", refusal(webDb::getDomains).startsWith("45000"));
        webDb.logAuditEvent("WR_TEST", "127.0.0.1", "web routines test", null);
        check("  an audit line without a session", rows(TestSql(), "SELECT COUNT(*) FROM audit_log WHERE action = 'WR_TEST'").equals(List.of("1")));

        CatalogGuard.useSession(bossHash);
        String domain = "wr-" + System.nanoTime() + ".example";
        int did = webDb.addDomain(domain, "web routines");
        check("the superadmin adds a domain, and gets its new id (" + did + ")", did > 0
                && rows(TestSql(), "SELECT domain FROM domains WHERE id = ?", did).equals(List.of(domain)));
        exec(TestSql(), "UPDATE domains SET dkim_selector = 'wr', dkim_private_key = 'PRIVATE-KEY-OF-THE-TEST', dkim_public_key = 'PUBLIC' WHERE id = ?", did);
        MailDatabase.Domain viaWeb = webDb.getDomains().stream().filter(d -> d.id == did).findFirst().orElse(null);
        MailDatabase.Domain viaPanel = db.getDomains().stream().filter(d -> d.id == did).findFirst().orElse(null);
        check("the domain through the web: has DKIM, the public key, never the private one",
                viaWeb != null && viaWeb.hasDkim && "PUBLIC".equals(viaWeb.dkimPublicKey) && viaWeb.dkimPrivateKey == null);
        check("  the same fields as through the panel user's connection, save the private key",
                viaPanel != null && viaPanel.dkimPrivateKey != null && viaPanel.hasDkim == viaWeb.hasDkim
                && viaPanel.mailboxCount == viaWeb.mailboxCount && viaPanel.aliasCount == viaWeb.aliasCount
                && java.util.Objects.equals(viaPanel.description, viaWeb.description) && viaPanel.active == viaWeb.active);
        check("  by name too", webDb.getDomainByName(domain) != null && webDb.getDomainByName(domain).hasDkim);
        check("  and its name among the public names", webDb.getDomainNames().contains(domain));
        int mid = webDb.addMailbox(did, "probe@" + domain, "Wr-Test-Password-2026x", "Probe", 10);
        MailDatabase.Mailbox box = webDb.getMailbox(mid);
        check("a mailbox, with its id, and read back like the panel reads it", mid > 0 && box != null
                && box.email.equals("probe@" + domain) && box.domainName.equals(domain) && box.quotaMb == 10
                && db.getMailbox(mid).name.equals(box.name));
        check("  in the lists (all, of the domain), and by address", webDb.getAllMailboxes().stream().anyMatch(m -> m.id == mid)
                && webDb.getMailboxes(did).size() == 1 && webDb.getMailboxByEmail("probe@" + domain) != null);
        check("  the copy is there, in the asymmetric vault's format, and the root part reads it",
                webDb.mailboxHasEncryptedPassword(mid) && org.daemoxcp.mail.security.PasswordVault.isCurrentFormat(db.getMailboxPasswordEncrypted(mid))
                && db.mailboxPasswordMatches(mid, "Wr-Test-Password-2026x")
                && "Wr-Test-Password-2026x".equals(org.daemoxcp.mail.security.PasswordVault.getInstance().decrypt(db.getMailboxPasswordEncrypted(mid))));
        check("  the web part's connection reads neither the copy nor the hash (" + refusal(() -> webDb.getMailboxPasswordEncrypted(mid)) + ")",
                refusal(() -> webDb.getMailboxPasswordEncrypted(mid)).startsWith("42000")
                && refusal(() -> webDb.mailboxPasswordMatches(mid, "Wr-Test-Password-2026x")).startsWith("42000"));
        check("an update with the same values says the same as the panel user's connection (rows found, not changed)",
                webDb.updateMailbox(mid, "Probe", 10, true, true) == db.updateMailbox(mid, "Probe", 10, true, true));
        check("  and a real one is written", webDb.updateMailbox(mid, "Probe Two", 20, true, true) && db.getMailbox(mid).quotaMb == 20);
        check("a new password: hash and copy", webDb.updateMailboxPassword(mid, "Wr-Other-Password-2026y")
                && db.mailboxPasswordMatches(mid, "Wr-Other-Password-2026y"));
        check("a webmail sign-in token", webDb.createAutoLoginToken(mid) != null
                && rows(TestSql(), "SELECT COUNT(*) FROM roundcube_tokens WHERE mailbox_id = ?", mid).equals(List.of("1")));
        check("aliases, auto-responder, forwarding, filters, statistics, training: answered",
                refusal(() -> webDb.getAliasesBySource("probe@" + domain)).isEmpty() && refusal(() -> webDb.getAliasesByDestination("x@" + domain)).isEmpty()
                && webDb.getAutoResponder(mid) == null && webDb.getForwardingRules(mid).isEmpty() && webDb.getSieveFilters(mid).isEmpty()
                && refusal(() -> webDb.getEmailStatistics(7)).isEmpty() && webDb.getTrainingCount("spam", 7) == 0);
        check("own theme and language", webDb.setAdminTheme("wr-boss", "dark") && "dark".equals(webDb.getAdminTheme("wr-boss"))
                && webDb.setAdminLanguage("wr-boss", "en") && "en".equals(webDb.getAdminLanguage("wr-boss")));
        exec(TestSql(), "UPDATE panel_admin SET theme = 'light' WHERE id = ?", vera);
        check("  not someone else's: read as unset, not written", "auto".equals(webDb.getAdminTheme("wr-vera"))
                && !webDb.setAdminTheme("wr-vera", "dark") && rows(TestSql(), "SELECT theme FROM panel_admin WHERE id = ?", vera).equals(List.of("light")));
        int second = webDb.addMailbox(did, "second@" + domain, "Wr-Test-Password-2026z", "Second", 10);
        webDb.transformMailboxToAlias(second, did, "second@" + domain, List.of("probe@" + domain));
        check("a mailbox becomes an alias, in one transaction of four procedures", webDb.getMailbox(second) == null
                && webDb.getAliasesBySource("second@" + domain).size() == 1);

        CatalogGuard.useSession(veraHash);
        check("the viewer through the web: lists, but adding a domain or deleting a mailbox is refused",
                refusal(webDb::getDomains).isEmpty() && refusal(() -> webDb.addDomain("wr-v.example", "x")).startsWith("45000")
                && refusal(() -> webDb.deleteMailbox(mid)).startsWith("45000") && db.getMailbox(mid) != null);
        CatalogGuard.useSession(ottoHash);
        check("the operator: mailboxes yes, domains no", refusal(() -> webDb.addDomain("wr-o.example", "x")).startsWith("45000")
                && refusal(() -> webDb.updateMailbox(mid, "By Otto", 20, true, true)).isEmpty());

        CatalogGuard.useSession(bossHash);
        check("the superadmin removes the mailbox and the domain", webDb.deleteMailbox(mid) && webDb.deleteDomain(did)
                && rows(TestSql(), "SELECT COUNT(*) FROM domains WHERE id = ?", did).equals(List.of("0")));

        // The session check of every request, with the web's connection (AuthStore.connection is the web's).
        CatalogGuard.forgetSession();
        java.util.function.Supplier<Connection> before = AuthStore.connection;
        AuthStore.connection = webDb::getConnection;
        try {
            exec(TestSql(), "UPDATE panel_sessions SET last_seen_at = UTC_TIMESTAMP() - INTERVAL 5 MINUTE WHERE token_hash = ?", bossHash);
            Optional<WebSessions.Current> s = Main.sessions.check(bossToken, UA);
            check("WebSessions.check through the procedures: the session and its administrator", s.isPresent()
                    && s.get().admin().id() == boss && "superadmin".equals(s.get().admin().role()));
            check("  its last activity touched through the procedure",
                    rows(TestSql(), "SELECT last_seen_at > UTC_TIMESTAMP() - INTERVAL 1 MINUTE FROM panel_sessions WHERE token_hash = ?", bossHash).equals(List.of("1")));
            check("  and from now on the procedures get that session", refusal(webDb::getDomains).isEmpty());
            check("a wrong token: no session, and the procedures get none", Main.sessions.check("x".repeat(43), UA).isEmpty()
                    && refusal(webDb::getDomains).startsWith("45000"));
        } finally {
            AuthStore.connection = before;
        }

        System.out.println("\n== 4. The guard of the web part's connection ==");
        Connection c = webDb.getConnection();
        check("a SQLite statement: no procedure, refused", refusal(() -> c.prepareStatement(SqlCatalog.CONFIG_GET_DATA_CONFIG)).startsWith("42000"));
        check("a text outside the catalog: refused", refusal(() -> c.prepareStatement("SELECT * FROM panel_admin")).startsWith("42000"));
        check("prepareCall and nativeSQL: refused", !refusal(() -> c.prepareCall(SqlCatalog.WEB_CALL_HAS_ADMIN)).isEmpty()
                && !refusal(() -> c.nativeSQL(SqlCatalog.MAIL_HAS_ADMIN_USER)).isEmpty());
        check("a batch: refused", refusal(() -> {
            try (PreparedStatement p = c.prepareStatement(SqlCatalog.MAIL_DELETE_MAILBOX)) { p.setInt(1, 1); p.addBatch(); }
        }).startsWith("0A000"));
        check("another text on a prepared statement: refused", !refusal(() -> {
            try (PreparedStatement p = c.prepareStatement(SqlCatalog.MAIL_GET_MAILBOX)) { p.execute("DROP TABLE domains"); }
        }).isEmpty() && rows(TestSql(), "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'domains'").equals(List.of("1")));

        // Back as it was for the other tests: no web user, the panel user's password in the web's file.
        exec(root, "DROP USER IF EXISTS 'mailpanel_web'@'localhost', 'mailpanel_web'@'127.0.0.1'");
        root.close();
        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }

    static Connection TestSql() throws SQLException {
        return org.daemoxcp.mail.TestSql.mysql();
    }

    static long admin(String name, String role) {
        AuthStore.Created c = AuthStore.createAdmin(name, null, role);
        long id = c.id() > 0 ? c.id() : AuthStore.adminByUsername(name).orElseThrow().id();
        AuthStore.setRole(id, role);
        return id;
    }
}
