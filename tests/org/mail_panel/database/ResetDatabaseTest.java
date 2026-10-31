package org.mail_panel.database;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

/**
 * Il reset del database del pannello (MailDatabase.dropAllTables, che Main usa nel reset).
 *
 * Il vecchio reset cancellava le tabelle una alla volta e di un errore scriveva solo un avviso:
 * MySQL non cancella una tabella a cui un'altra punta con una chiave esterna, e cosi' restavano
 * mailboxes, domains e panel_admin con i loro dati (piu' le tabelle che l'elenco non aveva),
 * mentre Main scriveva "Database reset completed!". Qui, su un MySQL vero: il vecchio reset
 * rifatto, per vedere che cosa lasciava; il nuovo, con una riga in ogni tabella del pannello, che
 * non lascia niente e non tocca le tabelle d'altri; ogni tabella che lo schema crea e' nel suo
 * elenco; un reset sul database gia' vuoto; uno che MySQL deve rifiutare (una tabella d'altri
 * punta a domains), che non cancella niente e lo dice. Senza MySQL si prova solo che senza
 * collegamento il reset non parte. Il MySQL si indica cosi':
 *   -Dmysql.port=33062 -Dmysql.user=mailpanel -Dmysql.password=... -Dmysql.database=mailpanel_prova
 */
public class ResetDatabaseTest {

    static int failed = 0;

    static void real(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FALLITO ") + what);
        if (!ok) failed++;
    }

    public static void main(String[] a) throws Exception {
        System.out.println("\n== Senza collegamento a MySQL il reset non parte ==");
        try {
            new MailDatabase().dropAllTables();
            real("un'eccezione", false);
        } catch (SQLException e) {
            real("un'eccezione: " + e.getMessage(), e.getMessage().contains("Not connected"));
        }

        String port = System.getProperty("mysql.port");
        if (port == null) {
            System.out.println("\n== MySQL non indicato (-Dmysql.port=...): salto la parte sul database ==");
        } else {
            database(port);
        }
        System.out.println("\n" + (failed == 0 ? "TUTTO VERDE" : failed + " CONTROLLI FALLITI"));
        if (failed > 0) System.exit(1);
    }

    static void database(String port) throws Exception {
        MailDatabase db = new MailDatabase();
        db.setCredentials(System.getProperty("mysql.user", "mailpanel"), System.getProperty("mysql.password", ""));
        db.setConnection("127.0.0.1", Integer.parseInt(port), System.getProperty("mysql.database", "mailpanel_prova"));
        if (!db.connect()) { real("connessione a MySQL", false); return; }
        Connection c = db.getConnection();
        try (Statement st = c.createStatement(); ResultSet r = st.executeQuery("SELECT VERSION()")) {
            r.next();
            System.out.println("\n  MySQL " + r.getString(1));
        }

        System.out.println("\n== Ogni tabella che il pannello crea e' nell'elenco del reset ==");
        empty(c);
        schema(db);
        List<String> create = tables(c);
        int n = create.size();
        List<String> outside = create.stream().filter(t -> !MailDatabase.PANEL_TABLES.contains(t)).toList();
        real("createSchema e le migrazioni creano " + n + " tabelle, tutte nell'elenco"
                + (outside.isEmpty() ? "" : " (mancano: " + outside + ")"), outside.isEmpty() && n >= 17);

        System.out.println("\n== Il vecchio reset, rifatto: che cosa lasciava ==");
        populate(c);
        List<String> warnings = oldReset(c);
        real("MySQL rifiutava tre DROP, e restavano solo warnings: " + warnings,
                warnings.equals(List.of("mailboxes", "domains", "panel_admin")));
        List<String> left = tables(c);
        real("restavano " + left, new HashSet<>(left).equals(new HashSet<>(List.of("admin_passkeys",
                "cloudflare_accounts", "dkim_rotation_history", "domains", "mailboxes", "panel_admin", "panel_sessions",
                "login_code_email", "login_code_console", "stepup_code", "email_change_code"))));
        db.createSchema();
        real("e dopo \"Database reset completed!\" c'erano ancora il dominio, la casella e l'amministratore di prima",
                lines(c, "domains") == 1 && lines(c, "mailboxes") == 1 && lines(c, "panel_admin") == 1
                        && lines(c, "admin_passkeys") == 1);
        List<String> via = db.dropAllTables();
        real("il reset nuovo, sui resti del vecchio: non resta niente (" + via.size() + " tabelle cancellate)",
                tables(c).isEmpty() && via.size() == n);

        System.out.println("\n== Il reset nuovo: una riga in ogni tabella, una tabella d'altri accanto ==");
        schema(db);
        populate(c);
        try (Statement st = c.createStatement()) {
            // Le tabelle di versioni vecchie del pannello, legate fra loro come allora.
            st.execute("CREATE TABLE virtual_domains (id INT PRIMARY KEY) ENGINE=InnoDB");
            st.execute("CREATE TABLE virtual_users (id INT PRIMARY KEY, domain_id INT NOT NULL, "
                    + "FOREIGN KEY (domain_id) REFERENCES virtual_domains(id)) ENGINE=InnoDB");
            st.execute("CREATE TABLE virtual_aliases (id INT PRIMARY KEY, domain_id INT NOT NULL, "
                    + "FOREIGN KEY (domain_id) REFERENCES virtual_domains(id)) ENGINE=InnoDB");
            st.execute("INSERT INTO virtual_domains VALUES (1)");
            st.execute("INSERT INTO virtual_users VALUES (1, 1)");
            st.execute("INSERT INTO virtual_aliases VALUES (1, 1)");
            // Una tabella che non e' del pannello: il reset non la deve toccare.
            st.execute("CREATE TABLE foreign_test (id INT PRIMARY KEY, note VARCHAR(40) NOT NULL) ENGINE=InnoDB");
        }
        insert(c, "INSERT INTO foreign_test (id, note) VALUES (?, ?)", 1, "non e' del pannello");
        List<String> before = tables(c);
        before.remove("foreign_test");
        List<String> empty = before.stream().filter(t -> lines(c, t) == 0).toList();
        real("una riga in ognuna delle " + before.size() + " tabelle del pannello" + (empty.isEmpty() ? "" : " (vuote: " + empty + ")"),
                empty.isEmpty() && before.size() == n + 3);
        List<String> deleted = db.dropAllTables();
        real("restituisce le tabelle che ha cancellato: " + deleted.size(), new HashSet<>(deleted).equals(new HashSet<>(before)));
        real("non resta nessuna tabella del pannello, nemmeno le virtual_*: " + tables(c), tables(c).equals(List.of("foreign_test")));
        real("la tabella d'altri resta, con la sua riga", lines(c, "foreign_test") == 1);
        db.createSchema();
        List<String> full = tables(c).stream().filter(t -> !t.equals("foreign_test") && lines(c, t) > 0).toList();
        real("ricreate da createSchema, le tabelle sono vuote: nessun dato di prima" + (full.isEmpty() ? "" : " (piene: " + full + ")"),
                full.isEmpty() && tables(c).size() == n + 1);

        System.out.println("\n== Il reset sul database gia' vuoto ==");
        real("con le tabelle vuote: le cancella tutte", db.dropAllTables().size() == n && tables(c).equals(List.of("foreign_test")));
        List<String> nothing = db.dropAllTables();
        real("senza tabelle: nessun errore, nessuna tabella cancellata", nothing.isEmpty() && tables(c).equals(List.of("foreign_test")));

        System.out.println("\n== Una tabella d'altri punta a domains: MySQL rifiuta, e non si cancella niente ==");
        schema(db);
        int domain = populate(c);
        try (Statement st = c.createStatement()) {
            st.execute("CREATE TABLE foreign_child (id INT PRIMARY KEY, domain_id INT NOT NULL, "
                    + "FOREIGN KEY (domain_id) REFERENCES domains(id)) ENGINE=InnoDB");
        }
        insert(c, "INSERT INTO foreign_child (id, domain_id) VALUES (?, ?)", 1, domain);
        try {
            db.dropAllTables();
            real("un'eccezione", false);
        } catch (SQLException e) {
            String m = e.getMessage();
            System.out.println("  " + m);
            real("un'eccezione che dice perche' e che cosa resta", m.startsWith("Reset failed")
                    && m.contains("foreign_child") && m.contains("still present: admin_passkeys, aliases"));
        }
        real("tutto com'era: le " + n + " tabelle, con i loro dati", tables(c).size() == n + 2
                && lines(c, "domains") == 1 && lines(c, "mailboxes") == 1 && lines(c, "admin_passkeys") == 1);
        try (Statement st = c.createStatement()) {
            st.execute("DROP TABLE foreign_child");
        }
        db.dropAllTables();
        real("tolta la tabella che puntava a domains, il reset passa", tables(c).equals(List.of("foreign_test")));

        try (Statement st = c.createStatement()) {
            st.execute("DROP TABLE foreign_test");
        }
        db.close();
    }

    /** Lo schema come lo prepara il pannello: createSchema e le migrazioni che SSLMailServer fa all'avvio. */
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

    /** Una riga in ogni tabella del pannello, legate come nell'uso vero. Restituisce l'id del dominio. */
    static int populate(Connection c) throws SQLException {
        int domain = insert(c, "INSERT INTO domains (domain) VALUES (?)", "esempio.test");
        int mailbox = insert(c, "INSERT INTO mailboxes (domain_id, email, password) VALUES (?, ?, ?)",
                domain, "posta@esempio.test", "x");
        int admin = insert(c, "INSERT INTO panel_admin (username) VALUES (?)", "amministratore");
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
                "<1@esempio.test>", "spam", admin);
        insert(c, "INSERT INTO roundcube_tokens (token, mailbox_id, expires_at) VALUES (?, ?, ?)",
                "t".repeat(64), mailbox, "2030-01-01 00:00:00");
        insert(c, "INSERT INTO auto_responders (mailbox_id, body) VALUES (?, ?)", mailbox, "Sono in ferie.");
        insert(c, "INSERT INTO sieve_filters (mailbox_id, name, conditions, actions) VALUES (?, ?, ?, ?)",
                mailbox, "filtro", "[]", "[]");
        insert(c, "INSERT INTO forwarding_rules (mailbox_id, destination) VALUES (?, ?)", mailbox, "altro@esempio.test");
        insert(c, "INSERT INTO email_statistics (stat_date, mailbox_id, domain_id) VALUES (?, ?, ?)",
                "2026-10-03", mailbox, domain);
        insert(c, "INSERT INTO aliases (domain_id, source, destination) VALUES (?, ?, ?)",
                domain, "info@esempio.test", "posta@esempio.test");
        insert(c, "INSERT INTO dkim_rotation_history (domain_id, domain, event_type) VALUES (?, ?, ?)",
                domain, "esempio.test", "key_generated");
        insert(c, "INSERT INTO cloudflare_accounts (label, api_token) VALUES (?, ?)", "prova", "x");
        insert(c, "INSERT INTO audit_log (action, ip_address) VALUES (?, ?)", "PROVA", "192.0.2.1");
        insert(c, "INSERT INTO rate_limits (target_type, target_id) VALUES (?, ?)", "domain", domain);
        insert(c, "INSERT INTO panel_settings (setting_key, setting_value) VALUES (?, ?)", "prova", "1");
        insert(c, "INSERT INTO installed_components (component_name) VALUES (?)", "postfix");
        return domain;
    }

    /** Il reset di prima, com'era: una tabella alla volta, e di un errore solo un avviso. */
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

    /** Il database di prova vuoto, senza passare dal codice che si prova. */
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
