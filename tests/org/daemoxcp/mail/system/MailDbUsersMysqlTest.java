package org.daemoxcp.mail.system;

import org.daemoxcp.mail.database.MailDatabase;
import org.daemoxcp.mail.util.Shell;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

/**
 * Postfix's and Dovecot's own MySQL users (MailDbUsers), on the test MySQL, as its root:
 *
 *  1. the users: both host names, only their columns (Postfix: domains, mailboxes without the password, aliases;
 *     Dovecot: address, hash, state and quota of the mailboxes), their passwords; a second run changes and logs nothing;
 *  2. each user by itself, over its own JDBC connection like the service would: the lookups of its files answer
 *     with the right rows; what it must not read MySQL refuses (the password column, the other tables, any write);
 *  3. put back: an extra privilege (a whole table, a global one) is taken away with everything else and the
 *     columns given again; a missing column is given again; a changed password is set again; the check after the
 *     users fails when Postfix can read the password column;
 *  4. the whole migration with fake services: the files switched, and the user and password written in them
 *     really enter MySQL and run the lookup; with MySQL refusing a step the files stay as they were.
 *
 * Usage (on the VM, with the test MySQL of tests/README.md, as root):
 *   java -Dmysql.port=33062 -Dmysql.user=daemoxcp_mail -Dmysql.password=... -Dmysql.database=daemoxcp_mail_test \
 *        -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.MailDbUsersMysqlTest
 */
public class MailDbUsersMysqlTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    static String port, database, url;
    static final String POSTFIX_PW = "PostfixTestPasswordPostfixTest01", DOVECOT_PW = "DovecotTestPasswordDovecotTest01";
    static final List<String> LOG = new ArrayList<>();

    static Connection as(String user, String password) throws SQLException {
        return DriverManager.getConnection(url, user, password);
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

    /** The MySQL error code of what the statement threw, 0 if it did not throw. */
    static int refusal(Connection c, String sql, Object... params) {
        try {
            if (sql.trim().toUpperCase().startsWith("SELECT")) rows(c, sql, params);
            else exec(c, sql, params);
            return 0;
        } catch (SQLException e) {
            return e.getErrorCode();
        }
    }

    static List<String> prepare() throws SQLException {
        List<String> done = new ArrayList<>();
        MailDbUsers.prepareUsers(url, "", POSTFIX_PW, DOVECOT_PW, done);
        return done;
    }

    /** Services that answer like a Postfix and a Dovecot that work. */
    static final class Working implements MailDbUsers.Services {
        @Override public boolean postfixRunning() { return true; }
        @Override public Shell.Result postfixReload() { return new Shell.Result(0, "", false, List.of()); }
        @Override public Shell.Result postmap(String key, Path map) { return new Shell.Result(1, "", false, List.of()); }
        @Override public boolean dovecotRunning() { return true; }
        @Override public Shell.Result doveconfCheck() { return new Shell.Result(0, "", false, List.of()); }
        @Override public Shell.Result dovecotReload() { return new Shell.Result(0, "", false, List.of()); }
        @Override public int dovecotLookup() { return 67; }
        @Override public int connections(String user) { return 1; }
        @Override public void pause() { }
    }

    static void dropUsers(Connection root) throws SQLException {
        for (String u : List.of(MailDbUsers.POSTFIX_USER, MailDbUsers.DOVECOT_USER))
            exec(root, "DROP USER IF EXISTS '" + u + "'@'localhost', '" + u + "'@'127.0.0.1'");
    }

    public static void main(String[] args) throws Exception {
        port = System.getProperty("mysql.port");
        database = System.getProperty("mysql.database", "daemoxcp_mail_test");
        if (port == null) {
            System.out.println("No MySQL given (-Dmysql.port=...): this test needs the test MySQL, and its root.");
            System.exit(1);
        }
        url = "jdbc:mysql://127.0.0.1:" + port + "/" + database
                + "?useSSL=true&requireSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC";
        Path dir = Files.createTempDirectory("mail-db-users");
        System.setProperty("daemoxcp.mail.secrets.dir", dir.toString());
        Logger.getLogger(MailDbUsers.class.getName()).addHandler(new Handler() {
            @Override public void publish(LogRecord r) { LOG.add(r.getMessage()); }
            @Override public void flush() { }
            @Override public void close() { }
        });

        // Le tabelle come le crea il pannello (domains, mailboxes con receive_enabled, aliases).
        MailDatabase db = new MailDatabase();
        db.setCredentials(System.getProperty("mysql.user", "daemoxcp_mail"), System.getProperty("mysql.password", ""));
        db.setConnection("127.0.0.1", Integer.parseInt(port), database);
        check("connected to MySQL as the panel user", db.connect());
        db.createSchema();
        db.ensureColumnUpgrades();

        try (Connection root = as("root", "")) {
            dropUsers(root);
            exec(root, "INSERT INTO domains (domain, active) VALUES ('mdu-alpha.test', 1), ('mdu-off.test', 0)");
            List<String> cols = rows(root, "SELECT column_name FROM information_schema.columns WHERE table_schema = ? AND table_name = 'mailboxes'", database);
            check("mailboxes has receive_enabled", cols.stream().anyMatch(c -> c.equalsIgnoreCase("receive_enabled")));
            exec(root, "INSERT INTO mailboxes (email, password, domain_id, active, receive_enabled) "
                    + "SELECT 'ann@mdu-alpha.test', '{BLF-CRYPT}$2y$05$abcdefghijklmnopqrstuuJ5kZ8m3m3m3m3m3m3m3m3m3m3m3m3m', id, 1, 1 FROM domains WHERE domain = 'mdu-alpha.test'");
            exec(root, "INSERT INTO mailboxes (email, password, domain_id, active, receive_enabled) "
                    + "SELECT 'bob@mdu-alpha.test', '{BLF-CRYPT}$2y$05$abcdefghijklmnopqrstuuJ5kZ8m3m3m3m3m3m3m3m3m3m3m3m3m', id, 1, 0 FROM domains WHERE domain = 'mdu-alpha.test'");
            exec(root, "INSERT INTO aliases (source, destination, domain_id, active) "
                    + "SELECT 'info@mdu-alpha.test', 'ann@mdu-alpha.test', id, 1 FROM domains WHERE domain = 'mdu-alpha.test'");
        }

        System.out.println("== 1. The users and their columns");
        List<String> done = prepare();
        check("first run: both users created (" + String.join("; ", done) + ")",
                done.contains("MySQL user " + MailDbUsers.POSTFIX_USER) && done.contains("MySQL user " + MailDbUsers.DOVECOT_USER));
        try (Connection root = as("root", "")) {
            List<String> users = rows(root, "SELECT user, host, account_locked FROM mysql.user WHERE user LIKE 'daemoxcp_mail\\_%' AND user IN (?, ?) ORDER BY user, host",
                    MailDbUsers.DOVECOT_USER, MailDbUsers.POSTFIX_USER);
            check("both users with both host names: " + users, users.equals(List.of(
                    MailDbUsers.DOVECOT_USER + "|127.0.0.1|N", MailDbUsers.DOVECOT_USER + "|localhost|N",
                    MailDbUsers.POSTFIX_USER + "|127.0.0.1|N", MailDbUsers.POSTFIX_USER + "|localhost|N")));
            List<String> columns = rows(root, "SELECT grantee, table_name, column_name, privilege_type FROM information_schema.column_privileges "
                    + "WHERE grantee IN (?, ?) ORDER BY table_name, column_name, grantee",
                    "'" + MailDbUsers.POSTFIX_USER + "'@'127.0.0.1'", "'" + MailDbUsers.POSTFIX_USER + "'@'localhost'");
            List<String> names = new ArrayList<>();
            for (String c : columns) { String[] p = c.split("\\|"); if (p[0].endsWith("'localhost'")) names.add(p[1] + "." + p[2] + " " + p[3]); }
            check("Postfix: SELECT on exactly its columns, never the password: " + names, names.equals(List.of(
                    "aliases.active SELECT", "aliases.destination SELECT", "aliases.source SELECT",
                    "domains.active SELECT", "domains.domain SELECT",
                    "mailboxes.active SELECT", "mailboxes.email SELECT", "mailboxes.receive_enabled SELECT"))
                    && columns.size() == 16);
            columns = rows(root, "SELECT grantee, table_name, column_name, privilege_type FROM information_schema.column_privileges "
                    + "WHERE grantee = ? ORDER BY table_name, column_name", "'" + MailDbUsers.DOVECOT_USER + "'@'localhost'");
            check("Dovecot: SELECT on email, password, active, quota_mb of mailboxes, and nothing else: " + columns, columns.equals(List.of(
                    "'" + MailDbUsers.DOVECOT_USER + "'@'localhost'|mailboxes|active|SELECT",
                    "'" + MailDbUsers.DOVECOT_USER + "'@'localhost'|mailboxes|email|SELECT",
                    "'" + MailDbUsers.DOVECOT_USER + "'@'localhost'|mailboxes|password|SELECT",
                    "'" + MailDbUsers.DOVECOT_USER + "'@'localhost'|mailboxes|quota_mb|SELECT")));
            for (String u : List.of(MailDbUsers.POSTFIX_USER, MailDbUsers.DOVECOT_USER)) {
                List<String> other = rows(root, "SELECT privilege_type FROM information_schema.table_privileges WHERE grantee LIKE ? "
                        + "UNION ALL SELECT privilege_type FROM information_schema.schema_privileges WHERE grantee LIKE ? "
                        + "UNION ALL SELECT privilege_type FROM information_schema.user_privileges WHERE grantee LIKE ? AND privilege_type <> 'USAGE'",
                        "'" + u + "'@%", "'" + u + "'@%", "'" + u + "'@%");
                check(u + ": no table, database or global privilege (a column grant is not a table grant): " + other, other.isEmpty());
            }
        }
        LOG.clear();
        done = prepare();
        check("second run: nothing changed (" + String.join("; ", done) + ")", done.isEmpty());
        check("the users check passes", MailDbUsers.verifyUsers(url, POSTFIX_PW, DOVECOT_PW) == null);

        System.out.println("== 2. Each user by itself");
        try (Connection pf = as(MailDbUsers.POSTFIX_USER, POSTFIX_PW)) {
            check("Postfix: the domain lookup finds an active domain",
                    rows(pf, "SELECT domain FROM domains WHERE domain='mdu-alpha.test' AND active=1").equals(List.of("mdu-alpha.test")));
            check("Postfix: an inactive domain is not found",
                    rows(pf, "SELECT domain FROM domains WHERE domain='mdu-off.test' AND active=1").isEmpty());
            check("Postfix: the mailbox lookup of its map gives domain/local/",
                    rows(pf, "SELECT CONCAT(SUBSTRING_INDEX(email,'@',-1),'/',SUBSTRING_INDEX(email,'@',1),'/') FROM mailboxes WHERE email='ann@mdu-alpha.test' AND active=1 AND receive_enabled=1")
                            .equals(List.of("mdu-alpha.test/ann/")));
            check("Postfix: a mailbox that does not receive is not found",
                    rows(pf, "SELECT CONCAT(SUBSTRING_INDEX(email,'@',-1),'/',SUBSTRING_INDEX(email,'@',1),'/') FROM mailboxes WHERE email='bob@mdu-alpha.test' AND active=1 AND receive_enabled=1").isEmpty());
            check("Postfix: the alias lookup gives its destination",
                    rows(pf, "SELECT destination FROM aliases WHERE source='info@mdu-alpha.test' AND active=1").equals(List.of("ann@mdu-alpha.test")));
            // The map that makes a catch-all safe (MailboxAddressMap): its own query, with Postfix's %s filled in.
            String own = org.daemoxcp.mail.scripts.PostfixMaps.MAILBOX_ADDRESSES_QUERY;
            check("Postfix: the mailbox addresses lookup gives a mailbox that receives itself",
                    rows(pf, own.replace("%s", "ann@mdu-alpha.test")).equals(List.of("ann@mdu-alpha.test")));
            check("Postfix: and not one that does not receive (its mail must not count as a mailbox's)",
                    rows(pf, own.replace("%s", "bob@mdu-alpha.test")).isEmpty());
            check("Postfix: the password column refused (1143)", refusal(pf, "SELECT password FROM mailboxes WHERE email='ann@mdu-alpha.test'") == 1143);
            check("Postfix: SELECT * on mailboxes refused (1143)", refusal(pf, "SELECT * FROM mailboxes") == 1143);
            check("Postfix: the administrators refused (1142)", refusal(pf, "SELECT * FROM panel_admin") == 1142);
            check("Postfix: the vault copies refused (1143, they are in mailboxes)", refusal(pf, "SELECT password_encrypted FROM mailboxes") == 1143);
            check("Postfix: the DKIM private keys refused (1143, they are in domains)", refusal(pf, "SELECT dkim_private_key FROM domains") == 1143);
            check("Postfix: writing a domain refused (1142)", refusal(pf, "UPDATE domains SET active = 0 WHERE domain = 'mdu-alpha.test'") == 1142);
            check("Postfix: adding an alias refused (1142)", refusal(pf, "INSERT INTO aliases (source, destination, domain_id, active) VALUES ('x@mdu-alpha.test', 'evil@example.org', 1, 1)") == 1142);
        }
        try (Connection dc = as(MailDbUsers.DOVECOT_USER, DOVECOT_PW)) {
            List<String> r = rows(dc, "SELECT email as user, password FROM mailboxes WHERE email='ann@mdu-alpha.test' AND active=1");
            check("Dovecot: its password_query finds the mailbox and its hash", r.size() == 1 && r.get(0).startsWith("ann@mdu-alpha.test|{BLF-CRYPT}"));
            check("Dovecot: the aliases refused (1142)", refusal(dc, "SELECT destination FROM aliases") == 1142);
            check("Dovecot: the domains refused (1142)", refusal(dc, "SELECT domain FROM domains") == 1142);
            check("Dovecot: another column of mailboxes refused (1143)", refusal(dc, "SELECT receive_enabled FROM mailboxes") == 1143);
            // The quota userdb (DovecotQuota): its own query, with Dovecot's %{user} filled in.
            String quota = org.daemoxcp.mail.scripts.DovecotConfig.QUOTA_USERDB.lines().filter(l -> l.trim().startsWith("query = "))
                    .findFirst().orElse("").trim().substring("query = ".length());
            check("Dovecot: the quota lookup gives a mailbox's limit in MB (" + rows(dc, quota.replace("%{user}", "ann@mdu-alpha.test")) + ")",
                    rows(dc, quota.replace("%{user}", "ann@mdu-alpha.test")).size() == 1
                            && rows(dc, quota.replace("%{user}", "ann@mdu-alpha.test")).get(0).endsWith("M"));
            check("Dovecot: changing a password refused (1142)", refusal(dc, "UPDATE mailboxes SET password = 'x' WHERE email = 'ann@mdu-alpha.test'") == 1142);
        }

        System.out.println("== 3. Put back");
        try (Connection root = as("root", "")) {
            // A tutti e due i nomi: MySQL risolve 127.0.0.1 in localhost, e chi si collega in TCP entra come @localhost.
            exec(root, "GRANT SELECT ON mailboxes TO '" + MailDbUsers.POSTFIX_USER + "'@'127.0.0.1', '" + MailDbUsers.POSTFIX_USER + "'@'localhost'");
        }
        String why = MailDbUsers.verifyUsers(url, POSTFIX_PW, DOVECOT_PW);
        check("the users check fails while Postfix can read the password column: " + why, why != null && why.contains("must not read"));
        done = prepare();
        check("a whole-table SELECT given to Postfix: everything taken away and the columns given again (" + String.join("; ", done) + ")",
                done.contains("every other privilege of " + MailDbUsers.POSTFIX_USER + " revoked"));
        try (Connection pf = as(MailDbUsers.POSTFIX_USER, POSTFIX_PW)) {
            check("  and the password column is refused again", refusal(pf, "SELECT password FROM mailboxes") == 1143);
            check("  and its lookups answer again", rows(pf, "SELECT domain FROM domains WHERE domain='mdu-alpha.test' AND active=1").size() == 1);
        }
        try (Connection root = as("root", "")) {
            exec(root, "GRANT PROCESS ON *.* TO '" + MailDbUsers.DOVECOT_USER + "'@'localhost'");
        }
        done = prepare();
        check("a global privilege given to Dovecot: taken away (" + String.join("; ", done) + ")",
                done.contains("every other privilege of " + MailDbUsers.DOVECOT_USER + " revoked"));
        try (Connection root = as("root", "")) {
            check("  PROCESS is gone", rows(root, "SELECT privilege_type FROM information_schema.user_privileges WHERE grantee = ? AND privilege_type <> 'USAGE'",
                    "'" + MailDbUsers.DOVECOT_USER + "'@'localhost'").isEmpty());
            exec(root, "REVOKE SELECT (receive_enabled) ON mailboxes FROM '" + MailDbUsers.POSTFIX_USER + "'@'localhost'");
        }
        done = prepare();
        check("a column taken from Postfix: given again (" + String.join("; ", done) + ")",
                done.stream().anyMatch(d -> d.startsWith("columns given again to " + MailDbUsers.POSTFIX_USER + ": mailboxes")));
        try (Connection pf = as(MailDbUsers.POSTFIX_USER, POSTFIX_PW)) {
            check("  and MySQL really lets Postfix read it again (it needs the privileges reloaded)",
                    refusal(pf, "SELECT receive_enabled FROM mailboxes") == 0);
        }
        try (Connection root = as("root", "")) {
            exec(root, "ALTER USER '" + MailDbUsers.DOVECOT_USER + "'@'127.0.0.1' IDENTIFIED BY 'SomethingElse12345', '"
                    + MailDbUsers.DOVECOT_USER + "'@'localhost' IDENTIFIED BY 'SomethingElse12345'");
        }
        done = prepare();
        check("a changed password: set again (" + String.join("; ", done) + ")", done.contains(MailDbUsers.DOVECOT_USER + " password set"));
        try (Connection dc = as(MailDbUsers.DOVECOT_USER, DOVECOT_PW)) {
            check("  and Dovecot enters with the password of the secrets file", dc.isValid(5));
        }
        done = prepare();
        check("after all that, a run with nothing to do: nothing (" + String.join("; ", done) + ")", done.isEmpty());

        System.out.println("== 4. The whole migration, files included");
        Path root = Files.createTempDirectory("mail-db-users-files");
        Path pfDir = Files.createDirectories(root.resolve("postfix")), dcDir = Files.createDirectories(root.resolve("dovecot/conf.d"));
        String map = "user = daemoxcp_mail\npassword = PanelPw\nhosts = 127.0.0.1\ndbname = " + database
                + "\nquery = SELECT domain FROM domains WHERE domain='%s' AND active=1\n";
        Files.writeString(pfDir.resolve("mysql-virtual-domains.cf"), map);
        Files.writeString(dcDir.resolve("..").normalize().resolve("dovecot-sql.conf"), "driver = mysql\nconnect = host=127.0.0.1 dbname="
                + database + " user=daemoxcp_mail password=PanelPw\ndefault_pass_scheme = BLF-CRYPT\n"
                + "password_query = SELECT email as user, password FROM mailboxes WHERE email='%u' AND active=1\n");
        MailDbUsers.Places at = new MailDbUsers.Places(pfDir, root.resolve("dovecot"));
        String outcome = MailDbUsers.ensure(at, new Working(), url, "", "daemoxcp_mail", database, POSTFIX_PW, DOVECOT_PW);
        check("the migration: nothing left behind (" + outcome + ")", outcome == null);
        check("  and logged as DONE", LOG.stream().anyMatch(l -> l.startsWith("[MailDbUsers] DONE:") && l.contains("Postfix enters MySQL as")));
        MailDbUsers.Login pl = MailDbUsers.postfixLogin(Files.readString(pfDir.resolve("mysql-virtual-domains.cf")));
        try (Connection c = as(pl.user(), pl.password())) {
            check("the user and password written in the Postfix map enter MySQL and run its lookup",
                    MailDbUsers.POSTFIX_USER.equals(pl.user()) && rows(c, "SELECT domain FROM domains WHERE domain='mdu-alpha.test' AND active=1").size() == 1);
        }
        MailDbUsers.Login dl = MailDbUsers.dovecot23Login(Files.readString(at.dovecotSql()));
        try (Connection c = as(dl.user(), dl.password())) {
            check("the user and password written in dovecot-sql.conf enter MySQL and run the password_query",
                    MailDbUsers.DOVECOT_USER.equals(dl.user())
                            && rows(c, "SELECT email as user, password FROM mailboxes WHERE email='ann@mdu-alpha.test' AND active=1").size() == 1);
        }

        Files.writeString(pfDir.resolve("mysql-virtual-domains.cf"), map);
        String wasMap = Files.readString(pfDir.resolve("mysql-virtual-domains.cf"));
        outcome = MailDbUsers.ensure(at, new Working(), url, "wrong-root-password", "daemoxcp_mail", database, POSTFIX_PW, DOVECOT_PW);
        check("MySQL root refused: the reason given (" + outcome + ")", outcome != null && outcome.startsWith("MySQL refused a step"));
        check("  and the map is as it was", Files.readString(pfDir.resolve("mysql-virtual-domains.cf")).equals(wasMap));

        try (Connection c = as("root", "")) {
            dropUsers(c);
        }
        System.out.println(failed == 0 ? "ALL OK" : failed + " FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }
}
