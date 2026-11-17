package org.daemoxcp.mail.database;

import org.daemoxcp.mail.TestSql;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

/**
 * The reset of the panel's database (MailDatabase.dropAllTables, which Main uses in the reset).
 *
 * The old reset deleted the tables one at a time and of an error it wrote only a warning: MySQL
 * does not delete a table another one points to with a foreign key, and so mailboxes, domains and
 * panel_admin stayed with their data (plus the tables the list did not have), while Main wrote
 * "Database reset completed!". Here, on a real MySQL: the old reset redone, to see what it left;
 * the new one, with a row in every panel table, which leaves nothing and does not touch other
 * people's tables; every table the schema creates is in its list; a reset on the already empty
 * database; one MySQL must refuse (another people's table points to domains), which deletes nothing
 * and says so. Without MySQL it only tests that without a connection the reset does not start. The
 * MySQL is given like this:
 *   -Dmysql.port=33062 -Dmysql.user=mailpanel -Dmysql.password=... -Dmysql.database=mailpanel_test
 */
public class ResetDatabaseTest {

    static int failed = 0;

    static void real(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    public static void main(String[] a) throws Exception {
        System.out.println("\n== Without a connection to MySQL the reset does not start ==");
        try {
            new MailDatabase().dropAllTables();
            real("an exception", false);
        } catch (SQLException e) {
            real("an exception: " + e.getMessage(), e.getMessage().contains("Not connected"));
        }

        String port = System.getProperty("mysql.port");
        if (port == null) {
            System.out.println("\n== MySQL not given (-Dmysql.port=...): the database part is skipped ==");
        } else {
            database(port);
        }
        System.out.println("\n" + (failed == 0 ? "ALL GREEN" : failed + " CHECKS FAILED"));
        if (failed > 0) System.exit(1);
    }

    static void database(String port) throws Exception {
        MailDatabase db = new MailDatabase();
        db.setCredentials(System.getProperty("mysql.user", "mailpanel"), System.getProperty("mysql.password", ""));
        db.setConnection("127.0.0.1", Integer.parseInt(port), System.getProperty("mysql.database", "mailpanel_test"));
        if (!db.connect()) { real("connection to MySQL", false); return; }
        Connection c = TestSql.mysql();
        try (Statement st = c.createStatement(); ResultSet r = st.executeQuery("SELECT VERSION()")) {
            r.next();
            System.out.println("\n  MySQL " + r.getString(1));
        }

        System.out.println("\n== Every table the panel creates is in the reset's list ==");
        empty(c);
        schema(db);
        List<String> create = tables(c);
        int n = create.size();
        List<String> outside = create.stream().filter(t -> !MailDatabase.PANEL_TABLES.contains(t)).toList();
        real("createSchema and the migrations create " + n + " tables, all in the list"
                + (outside.isEmpty() ? "" : " (missing: " + outside + ")"), outside.isEmpty() && n >= 17);

        System.out.println("\n== The old reset, redone: what it left ==");
        populate(c);
        List<String> warnings = oldReset(c);
        real("MySQL refused three DROPs, and only warnings were left: " + warnings,
                warnings.equals(List.of("mailboxes", "domains", "panel_admin")));
        List<String> left = tables(c);
        real("left: " + left, new HashSet<>(left).equals(new HashSet<>(List.of("admin_passkeys",
                "cloudflare_accounts", "dkim_rotation_history", "domains", "mailboxes", "panel_admin", "panel_sessions",
                "login_code_email", "login_code_console", "stepup_code", "email_change_code"))));
        db.createSchema();
        real("and after \"Database reset completed!\" the old domain, mailbox and administrator were still there",
                lines(c, "domains") == 1 && lines(c, "mailboxes") == 1 && lines(c, "panel_admin") == 1
                        && lines(c, "admin_passkeys") == 1);
        List<String> via = db.dropAllTables();
        real("the new reset, on the old one's leftovers: nothing is left (" + via.size() + " tables deleted)",
                tables(c).isEmpty() && via.size() == n);

        System.out.println("\n== The new reset: a row in every table, another people's table next to them ==");
        schema(db);
        populate(c);
        try (Statement st = c.createStatement()) {
            // The tables of old panel versions, linked to each other as back then.
            st.execute("CREATE TABLE virtual_domains (id INT PRIMARY KEY) ENGINE=InnoDB");
            st.execute("CREATE TABLE virtual_users (id INT PRIMARY KEY, domain_id INT NOT NULL, "
                    + "FOREIGN KEY (domain_id) REFERENCES virtual_domains(id)) ENGINE=InnoDB");
            st.execute("CREATE TABLE virtual_aliases (id INT PRIMARY KEY, domain_id INT NOT NULL, "
                    + "FOREIGN KEY (domain_id) REFERENCES virtual_domains(id)) ENGINE=InnoDB");
            st.execute("INSERT INTO virtual_domains VALUES (1)");
            st.execute("INSERT INTO virtual_users VALUES (1, 1)");
            st.execute("INSERT INTO virtual_aliases VALUES (1, 1)");
            // A table that is not the panel's: the reset must not touch it.
            st.execute("CREATE TABLE foreign_test (id INT PRIMARY KEY, note VARCHAR(40) NOT NULL) ENGINE=InnoDB");
        }
        insert(c, "INSERT INTO foreign_test (id, note) VALUES (?, ?)", 1, "not the panel's");
        List<String> before = tables(c);
        before.remove("foreign_test");
        List<String> empty = before.stream().filter(t -> lines(c, t) == 0).toList();
        real("a row in each of the " + before.size() + " panel tables" + (empty.isEmpty() ? "" : " (empty: " + empty + ")"),
                empty.isEmpty() && before.size() == n + 3);
        List<String> deleted = db.dropAllTables();
        real("it returns the tables it deleted: " + deleted.size(), new HashSet<>(deleted).equals(new HashSet<>(before)));
        real("no panel table is left, not even the virtual_* ones: " + tables(c), tables(c).equals(List.of("foreign_test")));
        real("the other people's table stays, with its row", lines(c, "foreign_test") == 1);
        db.createSchema();
        List<String> full = tables(c).stream().filter(t -> !t.equals("foreign_test") && lines(c, t) > 0).toList();
        real("recreated by createSchema, the tables are empty: no old data" + (full.isEmpty() ? "" : " (full: " + full + ")"),
                full.isEmpty() && tables(c).size() == n + 1);

        System.out.println("\n== The reset on the already empty database ==");
        real("with the tables empty: it deletes them all", db.dropAllTables().size() == n && tables(c).equals(List.of("foreign_test")));
        List<String> nothing = db.dropAllTables();
        real("without tables: no error, no table deleted", nothing.isEmpty() && tables(c).equals(List.of("foreign_test")));

        System.out.println("\n== Another people's table points to domains: MySQL refuses, and nothing is deleted ==");
        schema(db);
        int domain = populate(c);
        try (Statement st = c.createStatement()) {
            st.execute("CREATE TABLE foreign_child (id INT PRIMARY KEY, domain_id INT NOT NULL, "
                    + "FOREIGN KEY (domain_id) REFERENCES domains(id)) ENGINE=InnoDB");
        }
        insert(c, "INSERT INTO foreign_child (id, domain_id) VALUES (?, ?)", 1, domain);
        try {
            db.dropAllTables();
            real("an exception", false);
        } catch (SQLException e) {
            String m = e.getMessage();
            System.out.println("  " + m);
            real("an exception that says why and what is left", m.startsWith("Reset failed")
                    && m.contains("foreign_child") && m.contains("still present: admin_passkeys, aliases"));
        }
        real("everything as it was: the " + n + " tables, with their data", tables(c).size() == n + 2
                && lines(c, "domains") == 1 && lines(c, "mailboxes") == 1 && lines(c, "admin_passkeys") == 1);
        try (Statement st = c.createStatement()) {
            st.execute("DROP TABLE foreign_child");
        }
        db.dropAllTables();
        real("with the table pointing to domains removed, the reset passes", tables(c).equals(List.of("foreign_test")));

        try (Statement st = c.createStatement()) {
            st.execute("DROP TABLE foreign_test");
        }
        db.close();
    }

    /** The schema as the panel prepares it: createSchema and the migrations SSLMailServer runs at start. */
    static void schema(MailDatabase db) throws SQLException {
        db.createSchema();
        db.ensurePasswordlessSchema();
        db.ensureMailboxReceiveEnabledColumn();
        db.ensureMailboxPasswordVaultColumns();
        db.ensureThemeColumn();
        db.ensureDkimRotationColumns();
        db.ensureCloudflareAccountsSchema();
        db.ensureDkimRotationHistoryTable();
    }

    /** A row in every panel table, linked as in real use. Returns the domain's id. */
    static int populate(Connection c) throws SQLException {
        int domain = insert(c, "INSERT INTO domains (domain) VALUES (?)", "example.test");
        int mailbox = insert(c, "INSERT INTO mailboxes (domain_id, email, password) VALUES (?, ?, ?)",
                domain, "mail@example.test", "x");
        int admin = insert(c, "INSERT INTO panel_admin (username) VALUES (?)", "administrator");
        insert(c, "INSERT INTO panel_sessions (token_hash, admin_id, ua_hash, created_at, last_seen_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
                "a".repeat(64), admin, "b".repeat(64), "2030-01-01 00:00:00", "2030-01-01 00:00:00", "2030-01-01 12:00:00");
        for (String t : List.of("login_code_email", "login_code_console", "stepup_code"))
            insert(c, "INSERT INTO " + t + " (admin_id, code_hash, created_at, expires_at) VALUES (?, ?, ?, ?)",
                    admin, "c".repeat(64), "2030-01-01 00:00:00", "2030-01-01 00:10:00");
        insert(c, "INSERT INTO email_change_code (admin_id, code_hash, target_enc, target_index, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
                admin, "c".repeat(64), "v1:x", "d".repeat(64), "2030-01-01 00:00:00", "2030-01-01 00:15:00");
        insert(c, "INSERT INTO admin_passkeys (admin_id, credential_id, public_key_cose) VALUES (?, ?, ?)",
                admin, new byte[] {1, 2, 3}, new byte[] {4, 5, 6});
        insert(c, "INSERT INTO rspamd_training (message_id, trained_as, trained_by) VALUES (?, ?, ?)",
                "<1@example.test>", "spam", admin);
        insert(c, "INSERT INTO roundcube_tokens (token, mailbox_id, expires_at) VALUES (?, ?, ?)",
                "t".repeat(64), mailbox, "2030-01-01 00:00:00");
        insert(c, "INSERT INTO auto_responders (mailbox_id, body) VALUES (?, ?)", mailbox, "On holiday.");
        insert(c, "INSERT INTO sieve_filters (mailbox_id, name, conditions, actions) VALUES (?, ?, ?, ?)",
                mailbox, "filter", "[]", "[]");
        insert(c, "INSERT INTO forwarding_rules (mailbox_id, destination) VALUES (?, ?)", mailbox, "other@example.test");
        insert(c, "INSERT INTO email_statistics (stat_date, mailbox_id, domain_id) VALUES (?, ?, ?)",
                "2026-10-03", mailbox, domain);
        insert(c, "INSERT INTO aliases (domain_id, source, destination) VALUES (?, ?, ?)",
                domain, "info@example.test", "mail@example.test");
        insert(c, "INSERT INTO dkim_rotation_history (domain_id, domain, event_type) VALUES (?, ?, ?)",
                domain, "example.test", "key_generated");
        insert(c, "INSERT INTO cloudflare_accounts (label, api_token) VALUES (?, ?)", "test", "x");
        insert(c, "INSERT INTO audit_log (action, ip_address) VALUES (?, ?)", "TEST", "192.0.2.1");
        insert(c, "INSERT INTO rate_limits (target_type, target_id) VALUES (?, ?)", "domain", domain);
        insert(c, "INSERT INTO panel_settings (setting_key, setting_value) VALUES (?, ?)", "test", "1");
        insert(c, "INSERT INTO installed_components (component_name) VALUES (?)", "postfix");
        return domain;
    }

    /** The old reset, as it was: one table at a time, and of an error only a warning. */
    static List<String> oldReset(Connection c) throws SQLException {
        String[] tables = {
            "audit_log", "rspamd_training", "email_statistics", "roundcube_tokens", "aliases", "mailboxes",
            "domains", "virtual_aliases", "virtual_users", "virtual_domains", "rate_limits", "forwarding_rules",
            "sieve_filters", "auto_responders", "panel_settings", "panel_admin", "installed_components"
        };
        List<String> warnings = new ArrayList<>();
        try (Statement st = c.createStatement()) {
            for (String t : tables) {
                try {
                    st.executeUpdate("DROP TABLE IF EXISTS " + t);
                } catch (SQLException e) {
                    warnings.add(t);
                }
            }
        }
        return warnings;
    }

    /** The empty test database, without going through the code under test. */
    static void empty(Connection c) throws SQLException {
        try (Statement st = c.createStatement()) {
            st.execute("SET FOREIGN_KEY_CHECKS=0");
            try {
                for (String t : tables(c)) st.execute("DROP TABLE `" + t.replace("`", "") + "`");
            } finally {
                st.execute("SET FOREIGN_KEY_CHECKS=1");
            }
        }
    }

    static List<String> tables(Connection c) throws SQLException {
        List<String> t = new ArrayList<>();
        try (PreparedStatement ps = c.prepareStatement(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE() ORDER BY table_name");
             ResultSet r = ps.executeQuery()) {
            while (r.next()) t.add(r.getString(1));
        }
        return t;
    }

    static int lines(Connection c, String table) {
        try (Statement st = c.createStatement();
             ResultSet r = st.executeQuery("SELECT COUNT(*) FROM `" + table.replace("`", "") + "`")) {
            r.next();
            return r.getInt(1);
        } catch (SQLException e) {
            return -1;
        }
    }

    static int insert(Connection c, String sql, Object... parameters) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            for (int k = 0; k < parameters.length; k++) ps.setObject(k + 1, parameters[k]);
            ps.executeUpdate();
            try (ResultSet r = ps.getGeneratedKeys()) {
                return r.next() ? r.getInt(1) : -1;
            }
        }
    }
}
